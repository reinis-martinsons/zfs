/*
 * CDDL HEADER START
 *
 * The contents of this file are subject to the terms of the
 * Common Development and Distribution License, Version 1.0 only
 * (the "License").  You may not use this file except in compliance
 * with the License.
 *
 * You can obtain a copy of the license at usr/src/OPENSOLARIS.LICENSE
 * or http://www.opensolaris.org/os/licensing.
 * See the License for the specific language governing permissions
 * and limitations under the License.
 *
 * When distributing Covered Code, include this CDDL HEADER in each
 * file and include the License file at usr/src/OPENSOLARIS.LICENSE.
 * If applicable, add the following below this CDDL HEADER, with the
 * fields enclosed by brackets "[]" replaced with your own identifying
 * information: Portions Copyright [yyyy] [name of copyright owner]
 *
 * CDDL HEADER END
 */

/*
 * Copyright (c) 2016, Datto, Inc. All rights reserved.
 */

#ifdef _KERNEL
#include <linux/module.h>
#include <linux/kernel.h>
#include <linux/init.h>
#else
#define	__exit
#define	__init
#endif

#include <sys/crypto/common.h>
#include <sys/crypto/api.h>
#include <sys/crypto/impl.h>
#include <sys/crypto/sched_impl.h>
#include <sys/modhash_impl.h>
#include <sys/crypto/icp.h>

void __exit
icp_fini(void)
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
module_exit(icp_fini);
module_init(icp_init);
MODULE_LICENSE("CDDL");
#endif
