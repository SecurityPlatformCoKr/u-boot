#ifndef __i2c_bcm283x_h
#define __i2c_bcm283x_h

/*
 *Information about a i2c port
 *
 * @base: Register base address
 */
struct bcm283x_i2c_platdata {
	unsigned long base;
	unsigned long clock;
};

#endif
