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

#ifndef	_SYS_DSL_KEYCHAIN_H
#define	_SYS_DSL_KEYCHAIN_H

#include <sys/dmu_tx.h>
#include <sys/dmu.h>
#include <sys/zio_crypt.h>

//physical representation of a wrapped key in the DSL Keychain
typedef struct dsl_crypto_key_phys {
	uint64_t dk_crypt_alg; //encryption algorithm (see zio_encrypt enum)
	uint8_t dk_iv[13]; //iv / nonce for unwrapping the key
	uint8_t dk_padding[3];
	uint8_t dk_keybuf[48]; //wrapped key data
} dsl_crypto_key_phys_t;

//in memory representation of an entry in the DSL Keychain
typedef struct dsl_keychain_entry {
	list_node_t ke_link; //link into the keychain
	uint64_t ke_txgid; //first txg id that this key should be applied to
	zio_crypt_key_t *ke_key; //the actual key that this entry represents 
} dsl_keychain_entry_t;

//in memory representation of a DSL keychain
typedef struct dsl_keychain {
	krwlock_t kc_lock; //lock for protecting entry manipulations
	list_t kc_entries; //list of keychain entries
	zio_crypt_key_t *kc_wkey; //wrapping key for all entries
	uint64_t kc_obj; //keychain object id
} dsl_keychain_t;

void dsl_keychain_free(dsl_keychain_t *kc);
int dsl_keychain_create(zio_crypt_key_t *wkey, uint64_t kcobj, dsl_keychain_t **kc_out);
int dsl_keychain_add_key(dsl_keychain_t *kc, dmu_tx_t *tx);
int dsl_keychain_rewrap(dsl_keychain_t *kc, zio_crypt_key_t *wkey, dmu_tx_t *tx);
int dsl_keychain_clone_sync(dsl_keychain_t *kc, uint64_t new_kcobj, dmu_tx_t *tx, dsl_keychain_t **kc_out);
int dsl_keychain_open(objset_t *mos, uint64_t kcobj, zio_crypt_key_t *wkey, dsl_keychain_t **kc_out);

#endif