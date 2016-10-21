/*
 * libsboot - U-Boot Trusted/Secured Boot implementation.
 * Author: Teddy Reed <teddy@prosauce.org>
 *
 * Sboot depends on libtlcl, a lite TSS based on tlcl from the Chromium Project's vboot.
 * The functions defined in libsboot are implemented in U-boot and optionally in SPL.
 */

#include <common.h>
#include <u-boot/sha1.h>

#include <sboot.h>
#include <tpm.h>
#include <environment.h>

#define	TPM_BASE						0
#define	TPM_INVALID_POSTINIT			(TPM_BASE+38)

/* May turn off physical presence, may allow for a trusted boot instead of secure. */
__attribute__((unused))
uint8_t sboot_finish(void);

extern char *console_buffer;

#ifndef CONFIG_SBOOT_DISABLE_CONSOLE_EXTEND
/* If SBOOT is extending console commands then it has two options for
 * measurement, as it must consider measuring the act of sealing measurement:
 *   1. Check for the SBOOT seal command, and skip measurement.
 *   2. Always measure the SBOOT seal command before booting.
 * Finally, to preserve automatic booting, the default boot command (and legacy variants)
 * should not be measured.
 */
const char 		*console_measure_exceptions[] = {
	"sboot seal", "boot", "bootd"
};
#endif

uint8_t sboot_init(void)
{
	uint32_t tpm_result;

	static int sboot_inited = 0;
	if (sboot_inited)
	    return 0;
	sboot_inited = 1;

//	TSS_BOOL disabled, deactivated, nvlocked;
	uint8_t pcrCheck[20], pcrDefault[20];
//	uint32_t permissions;

	puts("Sboot initializing SRTM\n");

	tpm_init();
	tpm_result = tpm_startup(TPM_ST_CLEAR);
	if (tpm_result < 0) {
	    goto error;
	}
	tpm_self_test_full();
//	tpm_nv_define_space(TPM_NV_INDEX_LOCK, 0, 0);

	/* Check PCR values, they should be 0, else they will need to be reset.
	 * A reset can occur via operator authentication or a physical reset.
	 */
	memset(pcrDefault, 0x0, 20);
	tpm_result = tpm_pcr_read(SBOOT_PCR_UBOOT, (void *) pcrCheck, 20);
	if (tpm_result != TPM_SUCCESS || memcmp(pcrCheck, pcrDefault, 20) != 0) {
		debug("sboot: UBOOT PCR is unreadable or extended.\n");
		tpm_result = SBOOT_TPM_ERROR;
		goto error;
	}
	tpm_result = tpm_pcr_read(SBOOT_PCR_CHIPSET_CONFIG, (void *) pcrCheck, 20);
	if (tpm_result != TPM_SUCCESS || memcmp(pcrCheck, pcrDefault, 20) != 0) {
		debug("sboot: CHIPSET CONFIG PCR is unreadable or extended.\n");
		tpm_result = SBOOT_TPM_ERROR;
		goto error;
	}
	tpm_result = tpm_pcr_read(SBOOT_PCR_UBOOT_ENVIRONMENT, (void *) pcrCheck, 20);
	if (tpm_result != TPM_SUCCESS || memcmp(pcrCheck, pcrDefault, 20) != 0) {
		debug("sboot: UBOOT ENVIRONMENT PCR is unreadable or extended.\n");
		tpm_result = SBOOT_TPM_ERROR;
		goto error;
	}
	tpm_result = tpm_pcr_read(SBOOT_PCR_UBOOT_CONSOLE, (void *) pcrCheck, 20);
	if (tpm_result != TPM_SUCCESS || memcmp(pcrCheck, pcrDefault, 20) != 0) {
		debug("sboot: UBOOT CONSOLE PCR is unreadable or extended.\n");
		tpm_result = SBOOT_TPM_ERROR;
		goto error;
	}
	tpm_result = tpm_pcr_read(SBOOT_PCR_KERNEL, (void *) pcrCheck, 20);
	if (tpm_result != TPM_SUCCESS || memcmp(pcrCheck, pcrDefault, 20) != 0) {
		debug("sboot: KERNEL PCR is unreadable or extended.\n");
		tpm_result = SBOOT_TPM_ERROR;
		goto error;
	}

error:
	if (tpm_result != TPM_SUCCESS) {
		puts("sboot: Failed to initialize TPM\n");
		return SBOOT_TPM_ERROR;
	}

	return SBOOT_SUCCESS;
}

#ifndef CONFIG_SBOOT_DISABLE_CONSOLE_EXTEND
__attribute__((unused))
uint8_t sboot_extend_console(const char *buffer, uint32_t max_size)
{
	uint32_t size;
	uint8_t i = 0;

	uint8_t digest[20], out_digest[20];
	sha1_context ctx;

	sboot_init();
	/* sboot will extend the console up to the max_size given to the command.
	 * It is possible that input validation did not happen on buffer, thus
	 * max_size is an explicit parameter to the memory compare.
	 *
	 * max_size is not used by default, as it is possible the memory
	 * space after the null-terminated buffer was NOT scrubbed.
	 */
	size = (strlen(buffer) < max_size) ? strlen(buffer) : max_size;

	/* Do not seal if command buffer is a measurement exception */
	for (i = 0; i < sizeof(console_measure_exceptions) / sizeof(char *); ++i) {
		if (strlen(console_measure_exceptions[i]) == size &&
			memcmp(console_measure_exceptions[i], console_buffer, size) == 0) {
			return SBOOT_DATA_ERROR;
		}
	}

	debug("sboot: Extending console with \"%s\" (size=%d).\n", buffer, size);

	sha1_starts(&ctx); /* could be 1 function, sha1_csum */
	sha1_update(&ctx, (const unsigned char*) buffer, size);
	sha1_finish(&ctx, digest);

	return tpm_extend(SBOOT_PCR_UBOOT_CONSOLE, digest, out_digest);
}
#endif

#ifndef CONFIG_SBOOT_DISABLE_ENV_EXTEND
__attribute__((unused))
uint8_t sboot_extend_environment(const char *buffer, uint32_t size)
{
	uint8_t digest[20], out_digest[20];
	sha1_context ctx;

	sboot_init();
	debug("sboot: Extending env with \"%s\" (size=%d).\n", buffer, size);

	sha1_starts(&ctx); /* could be 1 function, sha1_csum */
	sha1_update(&ctx, (const unsigned char*) buffer, size);
	sha1_finish(&ctx, digest);

	return tpm_extend(SBOOT_PCR_UBOOT_ENVIRONMENT, digest, out_digest);
}

uint8_t sboot_export_extend_environment(void)
{
	env_t env_new;
	int ret;

	if (0 != (ret = env_export(&env_new)))
	    return ret;
    
	return sboot_extend_environment((const char *)env_new.data, ENV_SIZE);
}
#endif

__attribute__((unused))
uint8_t sboot_extend_os(const uint8_t* start, uint32_t size)
{
	/* uint32_t i; */
	uint8_t digest[20], out_digest[20];
	sha1_context ctx;

	if (size == 0)
		return SBOOT_SUCCESS;

	sboot_init();
	debug("sboot: Extending OS (addr=%x, size=%d)\n", (uint32_t) start, size);

	sha1_starts(&ctx);
	sha1_update(&ctx, start, size);
	sha1_finish(&ctx, digest);

	return tpm_extend(SBOOT_PCR_KERNEL, digest, out_digest);
}

__attribute__((unused))
uint8_t sboot_finish(void)
{
#if 0
	/* Remove PP, thus locking READ/WRITE to NVRAM. */
	debug("sboot: finished; locking PCRs and Physical Presence.\n");
//	sboot_lock_pcrs();
	TlclLockPhysicalPresence();
#endif

	return SBOOT_SUCCESS;
}
