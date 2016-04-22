#ifdef _KERNEL
#include <linux/module.h>
#include <linux/kernel.h>
#include <linux/init.h>
#else
#define __exit
#define __init
#endif

#include <sys/crypto/common.h>
#include <sys/crypto/api.h>
#include <sys/crypto/impl.h>
#include <sys/crypto/sched_impl.h>
#include <sys/modhash_impl.h>
#include <sys/crypto/icp.h>

void __exit
icp_exit(void)
{
	sha2_mod_fini();
	aes_mod_fini();
	kcf_sched_destroy();
	kcf_prov_tab_destroy();
	kcf_destroy_mech_tabs();
	mod_hash_fini();
}

/* roughly equivalent to kcf.c: _init() */
int __init
icp_init(void)
{
	/* initialize the mod hash module */
	mod_hash_init();

	/* initialize the mechanisms tables supported out-of-the-box */
	kcf_init_mech_tabs();

	/* initialize the providers tables */
	kcf_prov_tab_init();

	/*
	 * Initialize scheduling structures. Note that this does NOT
	 * start any threads since it might not be safe to do so.
	 */
	kcf_sched_init();

	/* initialize algorithms */
	aes_mod_init();
	sha2_mod_init();

	return (0);
}

#if defined(_KERNEL) && defined(HAVE_SPL)
module_init(icp_init);
module_exit(icp_exit);
MODULE_LICENSE("CDDL");
#endif
