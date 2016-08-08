#include <linux/bitops.h>
#include <asm/io.h>
#include <common.h>
#include <errno.h>
#include <dm.h>
#include <dm/platform_data/i2c_bcm283x.h>
#include <i2c.h>

#define BSC_I2C1_BASE 0x3f804000

#define BCM2835_I2C_C           0x0
#define BCM2835_I2C_S           0x4
#define BCM2835_I2C_DLEN        0x8
#define BCM2835_I2C_A           0xc
#define BCM2835_I2C_FIFO        0x10
#define BCM2835_I2C_DIV         0x14
#define BCM2835_I2C_DEL         0x18
#define BCM2835_I2C_CLKT        0x1c

#define BCM2835_I2C_C_READ      BIT(0)
#define BCM2835_I2C_C_CLEAR     BIT(4) /* bits 4 and 5 both clear */
#define BCM2835_I2C_C_ST        BIT(7)
#define BCM2835_I2C_C_INTD      BIT(8)
#define BCM2835_I2C_C_INTT      BIT(9)
#define BCM2835_I2C_C_INTR      BIT(10)
#define BCM2835_I2C_C_I2CEN     BIT(15)

#define BCM2835_I2C_S_TA        BIT(0)
#define BCM2835_I2C_S_DONE      BIT(1)
#define BCM2835_I2C_S_TXW       BIT(2)
#define BCM2835_I2C_S_RXR       BIT(3)
#define BCM2835_I2C_S_TXD       BIT(4)
#define BCM2835_I2C_S_RXD       BIT(5)
#define BCM2835_I2C_S_TXE       BIT(6)
#define BCM2835_I2C_S_RXF       BIT(7)
#define BCM2835_I2C_S_ERR       BIT(8)
#define BCM2835_I2C_S_CLKT      BIT(9)
#define BCM2835_I2C_S_LEN       BIT(10) /* Fake bit for SW error reporting */

#define BCM2835_I2C_BITMSK_S    0x03FF

#define BCM2835_I2C_CDIV_MIN    0x0002
#define BCM2835_I2C_CDIV_MAX    0xFFFE

#define BCM2835_I2C_TIMEOUT_us 100000

struct bcm2835_i2c_regs {
	u32 c;
	u32 s;
	u32 dlen;
	u32 a;
	u32 fifo;
	u32 div;
	u32 del;
	u32 clkt;
};

struct bcm2835_i2c_priv {
	struct bcm2835_i2c_regs *regs;
	int index;
	u32 base;
	u32 clk;
};

static u32 bcm2835_i2c_readl(u32 base, u32 offset)
{
	return readl(base + offset);
}

static void bcm2835_i2c_writel(u32 base, u32 offset, u32 val)
{
	writel(val, base + offset);
}

static int bcm2835_i2c_read_fifo(u32 base, struct i2c_msg *msg)
{
	int i;
	u32 s, l;
	debug("RX[%d]: ", msg->len);
	for (i=0; i<msg->len; ++i) {
	    s = bcm2835_i2c_readl(base, BCM2835_I2C_S);
	    if (!(s & BCM2835_I2C_S_RXD))
		break;
	    l = bcm2835_i2c_readl(base, BCM2835_I2C_FIFO);
	    msg->buf[i] = (u8)l;
	    debug("0x%02x ", l);
	}
	debug("\n");
	return 0;
}

static u32 check_completion(u32 base, struct i2c_msg *msg)
{
    u32 err, clr;
    u32 s = bcm2835_i2c_readl(base, BCM2835_I2C_S);
    err  = s & (BCM2835_I2C_S_CLKT | BCM2835_I2C_S_ERR);
    clr = BCM2835_I2C_S_ERR | BCM2835_I2C_S_CLKT | BCM2835_I2C_S_DONE;
    bcm2835_i2c_writel(base, BCM2835_I2C_S, clr); /* clear */

    if (s & BCM2835_I2C_S_TA) {
	return 0;
    }
    if (s & BCM2835_I2C_S_RXD) {
	bcm2835_i2c_read_fifo(base, msg);
	return s;
    }
    if (s & BCM2835_I2C_S_DONE) {
	return s;
    }
    if (err) {
	return s;
    }

    return 0;
}

/*
static void bcm2835_i2c_drain_fifo(u32 base)
{
	u32 s;
	s = bcm2835_i2c_readl(base, BCM2835_I2C_S);
	while(s & BCM2835_I2C_S_RXD) {
	    bcm2835_i2c_readl(base, BCM2835_I2C_FIFO);
	    udelay(10);
	    s = bcm2835_i2c_readl(base, BCM2835_I2C_S);
	}
}
*/

static void bcm2835_i2c_fill_txfifo(u32 base, struct i2c_msg *msg)
{
	u32 s;
	int i;
	debug("TX[%d]: ", msg->len);
	for (i=0; i<msg->len; ++i) {
	    s = bcm2835_i2c_readl(base, BCM2835_I2C_S);
	    if(0 == (s & BCM2835_I2C_S_TXD)) {
		break;
	    }
	    bcm2835_i2c_writel(base, BCM2835_I2C_FIFO, msg->buf[i]);
	    debug("0x%02x ", msg->buf[i]);
	}
	debug("\n");
}

static int bcm2835_i2c_xfer_msg(u32 base, struct i2c_msg *msg)
{
	u32 c, r = 0;
	unsigned long time_left = BCM2835_I2C_TIMEOUT_us;

	bcm2835_i2c_writel(base, BCM2835_I2C_C, BCM2835_I2C_C_CLEAR);
	c = 0;
	if (msg->flags & I2C_M_RD) {
		c = BCM2835_I2C_C_READ;
	} else {
		c = 0;
		bcm2835_i2c_fill_txfifo(base, msg);
	}
	c |= BCM2835_I2C_C_ST | BCM2835_I2C_C_I2CEN;
	bcm2835_i2c_writel(base, BCM2835_I2C_A, msg->addr);
	bcm2835_i2c_writel(base, BCM2835_I2C_DLEN, msg->len);
	bcm2835_i2c_writel(base, BCM2835_I2C_C, c);

	while(time_left > 0) {
		udelay(10);
		time_left -= 10;
		r = check_completion(base, msg);
		if (r) {
			break;
		}
	}
	bcm2835_i2c_writel(base, BCM2835_I2C_C, BCM2835_I2C_C_CLEAR);
	if (time_left == 0) {
	    debug("i2c transfer timed out\n");
	    return -1;
	}
	if (r & (BCM2835_I2C_S_ERR | BCM2835_I2C_S_CLKT)) {
	    debug("i2c status error: 0x%x\n", r);
	    return -1;
	}

	return 0;
}

static int bcm2835_i2c_xfer(struct udevice *bus, struct i2c_msg *msg, int nmsgs)
{
	int i;
	int ret = 0;
	struct bcm2835_i2c_priv * priv = dev_get_priv(bus);
	debug("xfer[%d]\n", nmsgs);
	for (i=0; i<nmsgs; ++i) {
		ret = bcm2835_i2c_xfer_msg(priv->base, &msg[i]);
		if (ret)
			break;
	}
	return ret < 0 ? -1 : 0;
}

static int bcm2835_i2c_read(struct udevice *dev, uint chip, uint addr, int olen, u8 *buf, int blen)
{
	struct i2c_msg msg[2];
	unsigned char msgbuf0[64];
	int r;

	msg[0].addr = chip;
	msg[0].flags = 0;
	msg[0].len = 1;
	msg[0].buf = msgbuf0;
	msgbuf0[0] = (unsigned char)addr;

	msg[1].addr = chip;
	msg[1].flags = I2C_M_RD;
	msg[1].buf = buf;
	msg[1].len = blen;

	r = bcm2835_i2c_xfer(dev, msg, 2);
	if (r < 0) {
		return -EIO;
	}
	return 0;
}

static int bcm2835_i2c_probe_chip(struct udevice *dev, uint chip, uint chip_flags)
{
	int ret;
	u32 tmp = 0;

	ret = bcm2835_i2c_read(dev, chip, 0, 1, (uchar *)&tmp, 1);

	return ret;
}

static int bcm2835_i2c_set_bus_speed(struct udevice *dev, unsigned int speed_hz)
{
	u32 cdiv;
	struct bcm2835_i2c_priv * priv = dev_get_priv(dev);
	priv->base = BSC_I2C1_BASE;
	priv->clk = speed_hz;
	cdiv = (u32)(250000000 / speed_hz);
	bcm2835_i2c_writel(priv->base, BCM2835_I2C_DIV, cdiv);

	return 0;
}

static int i2c_rpi_bind(struct udevice *dev)
{
	dev->req_seq = 1;
	device_set_name(dev, "i2c1");

	return 0;
}

static void rpi_overlay_i2c_on(void)
{
	u32 gpfsel0 = 0;
	gpfsel0 = bcm2835_i2c_readl(0x3f200000, 0);
	gpfsel0 |= (4<<9) + (4<<6);	/* 4 is function 0 */
	bcm2835_i2c_writel(0x3f200000, 0, gpfsel0);
	debug("GPFSEL0: 0x%x\n", bcm2835_i2c_readl(0x3f200000, 0));
}

static int rpi_i2c_probe(struct udevice *dev)
{
	struct bcm283x_i2c_platdata *plat = dev_get_platdata(dev);
	struct bcm2835_i2c_priv * priv = dev_get_priv(dev);

	priv->regs = (struct bcm2835_i2c_regs *)plat->base;

	rpi_overlay_i2c_on();

	return 0;
}

static const struct dm_i2c_ops i2c_rpi_ops = {
	.xfer		= bcm2835_i2c_xfer,
	.probe_chip	= bcm2835_i2c_probe_chip,
	.set_bus_speed	= bcm2835_i2c_set_bus_speed,
};

static const struct udevice_id i2c_rpi_ids[] = {
	{ .compatible = "bcm2835-i2c" },
	{ }
};

U_BOOT_DRIVER(i2c_rpi) = {
	.name	= "i2c_bcm283x",
	.id	= UCLASS_I2C,
	.of_match = i2c_rpi_ids,
	.bind   = i2c_rpi_bind,
	.probe   = rpi_i2c_probe,
	.priv_auto_alloc_size = sizeof(struct bcm2835_i2c_priv),
	.ops	= &i2c_rpi_ops,
	.platdata_auto_alloc_size = sizeof(struct bcm283x_i2c_platdata),
	.per_child_auto_alloc_size = sizeof(struct dm_i2c_chip),
};
