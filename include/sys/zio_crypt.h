/*
 * CDDL HEADER START
 *
 * The contents of this file are subject to the terms of the
 * Common Development and Distribution License (the "License").
 * You may not use this file except in compliance with the License.
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

#ifndef	_SYS_ZIO_CRYPT_H
#define	_SYS_ZIO_CRYPT_H

#include <sys/zio.h>
#include <sys/refcount.h>
#include <sys/crypto/api.h>

#define CRYPT_KEY_MAX_LEN 32

/*
 * Table of supported crypto algorithms, modes and keylengths.
 */
typedef struct zio_crypt_info {
	crypto_mech_name_t	ci_mechname;
	size_t			ci_keylen;
	size_t			ci_ivlen;
	size_t			ci_maclen;
	size_t			ci_zil_maclen;
	char			*ci_name;
} zio_crypt_info_t;

extern zio_crypt_info_t zio_crypt_table[ZIO_CRYPT_FUNCTIONS];

/*
 * physical representation of a wrapped key in the DSL Keychain
 */
typedef struct dsl_crypto_key_phys {
	uint64_t dk_crypt_alg; //encryption algorithm (see zio_encrypt enum)
	uint8_t dk_iv[13]; //iv / nonce for unwrapping the key
	uint8_t dk_padding[3];
	uint8_t dk_keybuf[48]; //wrapped key data
} dsl_crypto_key_phys_t;

/*
 * in memory representation of an unwrapped key that is loaded into memory
 */
typedef struct zio_crypt_key {
	enum zio_encrypt ck_crypt; //encryption algorithm
	crypto_key_t ck_key; //illumos crypto api key representation
	crypto_ctx_template_t ck_ctx_tmpl; //private data for illumos crypto api
	refcount_t ck_refcnt; //refcount 
} zio_crypt_key_t;

/*
 * in memory representation of an entry in the DSL Keychain
 */
typedef struct dsl_dir_keychain_entry {
	list_node_t ke_link; //link into the keychain
	uint64_t ke_txgid; //first txg id that this key should be applied to
	zio_crypt_key_t ke_key; //the actual key that this entry represents 
} dsl_dir_keychain_entry_t;

/*
 * in memory representation of a DSL keychain
 */
typedef struct dsl_dir_keychain {
	krwlock_t kc_lock; //lock for protecting entry manipulations
	list_node_t kc_entries; //list of keychain entries
	zio_crypt_key_t kc_wkey; //wrapping key for all entries
	refcount_t kc_refcnt; //refcount
} dsl_dir_keychain_t;

int zio_crypt_key_from_props(nvlist_t *, zio_crypt_key_t **);

#endif
