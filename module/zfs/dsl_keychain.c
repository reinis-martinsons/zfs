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

#include <sys/dsl_keychain.h>
#include <sys/dsl_pool.h>
#include <sys/zap.h>

//macros for defining encryption parameter lengths
#define ZIO_CRYPT_WRAPKEY_IVLEN 13
#define WRAPPING_MAC_LEN 16
#define WRAPPED_KEYDATA_LEN(keylen) ((keylen) + ZIO_CRYPT_WRAPKEY_IVLEN + WRAPPING_MAC_LEN)

int zio_crypt_key_wrap(zio_crypt_key_t *wkey, uint8_t *keydata, uint8_t *ivdata, dsl_crypto_key_phys_t *dckp){
	int ret;
	uint64_t crypt = wkey->zk_crypt;
	
	ASSERT(crypt < ZIO_CRYPT_FUNCTIONS);
	ASSERT(wkey->zk_key->ck_format == CRYPTO_KEY_RAW);

	//copy the crypt and iv data into the dsl_crypto_key_phys_t
	dckp->dk_crypt_alg = crypt;
	bcopy(ivdata, dckp->dk_iv, ZIO_CRYPT_WRAPKEY_IVLEN);
	bzero(dckp->dk_padding, sizeof(dckp->dk_padding));
	
	//encrypt the key and store the result in dckp->keybuf
	ret = zio_encrypt(wkey, ivdata, ZIO_CRYPT_WRAPKEY_IVLEN, WRAPPING_MAC_LEN, keydata, dckp->dk_keybuf, zio_crypt_table[crypt].ci_keylen);
	if(ret) goto error;
	
	return 0;
error:
	return ret;
}

int zio_crypt_key_unwrap(zio_crypt_key_t *wkey, dsl_crypto_key_phys_t *dckp, uint8_t *keydata){
	int ret;
	uint64_t crypt = wkey->zk_crypt;
	
	ASSERT(crypt < ZIO_CRYPT_FUNCTIONS);
	ASSERT(wkey->zk_key->ck_format == CRYPTO_KEY_RAW);

	//encrypt the key and store the result in dckp->keybuf
	ret = zio_decrypt(wkey, dckp->dk_iv, ZIO_CRYPT_WRAPKEY_IVLEN, WRAPPING_MAC_LEN, keydata, dckp->dk_keybuf, zio_crypt_table[crypt].ci_keylen);
	if(ret) goto error;
	
	return 0;
error:
	return ret;
}

void dsl_dir_keychain_free(dsl_dir_keychain_t *kc){
	dsl_dir_keychain_entry_t *kce;
	
	//release each encryption key from the keychain
	while((kce = list_head(&kc->kc_entries)) != NULL){
		zio_crypt_key_rele(kce->ke_key, kc);
		kmem_free(kce, sizeof(dsl_dir_keychain_entry_t));
	}
	
	//free the keychain entries list, wrapping key, and lock
	rw_destroy(&kc->kc_lock);
	list_destroy(&kc->kc_entries);
	if(kc->kc_wkey) zio_crypt_key_rele(kc->kc_wkey, kc);
	
	//free the keychain
	kmem_free(kc, sizeof(dsl_dir_keychain_t));
}

int dsl_dir_keychain_create(zio_crypt_key_t *wkey, uint64_t kcobj, dsl_dir_keychain_t **kc_out){
	int ret;
	dsl_dir_keychain_t *kc;
	
	//allocate the keychain struct
	kc = kmem_alloc(sizeof(dsl_dir_keychain_t), KM_SLEEP);
	if(!kc){
		ret = ENOMEM;
		goto error;
	}
	
	//initialize members
	kc->kc_obj = kcobj;
	rw_init(&kc->kc_lock, NULL, RW_DEFAULT, NULL);
	list_create(&kc->kc_entries, sizeof(dsl_dir_keychain_entry_t), offsetof(dsl_dir_keychain_t, kc_entries));
	
	//add the wrapping key to the keychain
	zio_crypt_key_hold(wkey, kc);
	kc->kc_wkey = wkey;
	
	*kc_out = kc;
	return 0;
	
error:
	*kc_out = NULL;
	return ret;
}

void dsl_dir_keychain_entry_free(dsl_dir_keychain_entry_t *kce){
	if(kce->ke_key) zio_crypt_key_rele(kce->ke_key, kce);
	kmem_free(kce, sizeof(dsl_dir_keychain_entry_t));
}	

int dsl_dir_keychain_entry_generate(uint64_t crypt, uint64_t txgid, dsl_dir_keychain_entry_t **kce_out){
	int ret;
	dsl_dir_keychain_entry_t *kce = NULL;
	uint64_t keydata_len = zio_crypt_table[crypt].ci_keylen;
	uint8_t rnddata[keydata_len];
	
	*kce_out = NULL;
	
	//allocate the keychain entry
	kce = kmem_zalloc(sizeof(dsl_dir_keychain_entry_t), KM_SLEEP);
	if(!kce){
		ret = ENOMEM;
		goto error;
	}
	
	//fill our buffer with random data
	ret = random_get_bytes(rnddata, keydata_len);
	if(ret) goto error;
	
	//create the key from the random data
	ret = zio_crypt_key_create(crypt, rnddata, kce, &kce->ke_key);
	if(ret) goto error;
	
	//set the txgid
	kce->ke_txgid = txgid;
	
	*kce_out = kce;
	return 0;
	
error:
	if(kce) dsl_dir_keychain_entry_free(kce);

	*kce_out = NULL;
	return ret;
}

int dsl_dir_keychain_add_key(dsl_dir_keychain_t *kc, dmu_tx_t *tx){
	int ret;
	uint64_t crypt = kc->kc_wkey->zk_crypt;
	dsl_dir_keychain_entry_t *kce = NULL;
	uint8_t ivdata[ZIO_CRYPT_WRAPKEY_IVLEN];
	dsl_crypto_key_phys_t key_phys;
	
	//generate the keychain entry with the same encryption type as the wrapping key
	ret = dsl_dir_keychain_entry_generate(crypt, tx->tx_txg, &kce);
	if(ret) goto error;
	
	//add the entry to the keychain
	rw_enter(&kc->kc_lock, RW_WRITER);
	list_insert_tail(&kc->kc_entries, kce);
	rw_exit(&kc->kc_lock);
	
	//zero out the phsyical key struct
	bzero(&key_phys, sizeof(dsl_crypto_key_phys_t));
	
	//initialize the physical key struct with a crypt and iv
	key_phys.dk_crypt_alg = crypt;
	
	ret = random_get_bytes(ivdata, ZIO_CRYPT_WRAPKEY_IVLEN);
	if(ret) goto error;
	
	//wrap the key and store the result in key_phys
	ret = zio_crypt_key_wrap(kc->kc_wkey, kce->ke_key->zk_key.ck_data, ivdata, &key_phys);
	if(ret) goto error;
	
	//add the wrapped key entry to the zap
	VERIFY0(zap_add_uint64(tx->tx_pool->dp_meta_objset, kc->kc_obj, &tx->tx_txg, 1, 1, sizeof(dsl_crypto_key_phys_t), &key_phys, tx));
	
	return 0;
	
error:
	if(kce) dsl_dir_keychain_entry_free(kce);

	return ret;
}

int dsl_dir_keychain_rewrap(dsl_dir_keychain_t *kc, zio_crypt_key_t *wkey, dmu_tx_t *tx){
	int ret;
	uint64_t crypt = kc->kc_wkey->zk_crypt;
	dsl_dir_keychain_entry_t *kce;
	uint8_t ivdata[ZIO_CRYPT_WRAPKEY_IVLEN];
	dsl_crypto_key_phys_t key_phys;
	
	//zero out the phsyical key struct
	bzero(&key_phys, sizeof(dsl_crypto_key_phys_t));
	
	//most of this function only reads the keychain, but we do need to change the wkey under the same lock
	rw_enter(&kc->kc_lock, RW_WRITER);
	
	//iterate through the list of encryption keys
	for(kce = list_head(&kc->kc_entries); kce; kce = list_next(&kc->kc_entries, kce)){
		//initialize the physical key struct with a crypt and iv
		key_phys.dk_crypt_alg = crypt;
		
		ret = random_get_bytes(ivdata, ZIO_CRYPT_WRAPKEY_IVLEN);
		if(ret) goto error;
		
		//wrap the key
		ret = zio_crypt_key_wrap(wkey, kce->ke_key->zk_key.ck_data, ivdata, &key_phys);
		if(ret) goto error;
		
		//add the wrapped key entry to the zap
		VERIFY0(zap_update_uint64(tx->tx_pool->dp_meta_objset, kc->kc_obj, &tx->tx_txg, 1, 1, sizeof(dsl_crypto_key_phys_t), &key_phys, tx));
	}
	
	//release the old wrapping key and add the new one to the keychain
	zio_crypt_key_rele(kc->kc_wkey, kc);
	zio_crypt_key_hold(wkey, kc);
	kc->kc_wkey = wkey;
	
	//unlock the keychain
	rw_exit(&kc->kc_lock);
	return 0;
	
error:
	rw_exit(&kc->kc_lock);
	return ret;
}

int dsl_dir_keychain_lookup_key(dsl_dir_keychain_t *kc, uint64_t txgid, zio_crypt_key_t **key_out){
	dsl_dir_keychain_entry_t *kce;
	
	//lock the keychain for reading
	rw_enter(&kc->kc_lock, RW_READER);
	
	//iterate backwards through the list of key entries
	for(kce = list_tail(&kc->kc_entries); kce; kce = list_prev(&kc->kc_entries, kce)){
		
		//return the first key with a txgid lower than or equal to our target value
		if(kce->ke_txgid <= txgid){
			rw_exit(&kc->kc_lock);
			*key_out = kce->ke_key;
			return 0;
		}
	}
	
	//key not found
	rw_exit(&kc->kc_lock);
	*key_out = NULL;
	return ENOENT;
}

int dsl_dir_clone_sync(dsl_dir_keychain_t *kc, uint64_t new_kcobj, dmu_tx_t *tx, dsl_dir_keychain_t **kc_out){
	int ret;
	uint64_t crypt = kc->kc_wkey->zk_crypt;
	dsl_dir_keychain_t *new_kc = NULL;
	dsl_dir_keychain_entry_t *kce, *new_kce;
	uint8_t ivdata[ZIO_CRYPT_WRAPKEY_IVLEN];
	dsl_crypto_key_phys_t key_phys;
	
	//zero out the phsyical key struct
	bzero(&key_phys, sizeof(dsl_crypto_key_phys_t));
	
	//create the new keychain for the clone
	ret = dsl_dir_keychain_create(kc->kc_wkey, new_kcobj, &new_kc);
	if(ret) goto error;
	
	//lock the original keychain for reading
	rw_enter(&kc->kc_lock, RW_READER);
	
	//iterate through the list of encryption keys
	for(kce = list_head(&kc->kc_entries); kce; kce = list_next(&kc->kc_entries, kce)){
		//allocate the keychain entry
		new_kce = kmem_zalloc(sizeof(dsl_dir_keychain_entry_t), KM_SLEEP);
		if(!new_kce){
			ret = ENOMEM;
			goto error_unlock;
		}
		
		//assign the txgid and key to the keychain entry
		new_kce->ke_txgid = kce->ke_txgid;
		new_kce->ke_key = kce->ke_key;
		zio_crypt_key_hold(new_kce->ke_key, new_kc);
		
		//add the key entry to the entries list
		list_insert_tail(&new_kc->kc_entries, new_kce);
		
		//initialize the physical key struct with a crypt and iv
		key_phys.dk_crypt_alg = crypt;
		
		ret = random_get_bytes(ivdata, ZIO_CRYPT_WRAPKEY_IVLEN);
		if(ret) goto error_unlock;
		
		//wrap the key
		ret = zio_crypt_key_wrap(new_kc->kc_wkey, new_kce->ke_key->zk_key.ck_data, ivdata, &key_phys);
		goto error_unlock;
		
		//add the wrapped key entry to the zap
		VERIFY0(zap_update_uint64(tx->tx_pool->dp_meta_objset, new_kc->kc_obj, &tx->tx_txg, 1, 1, sizeof(dsl_crypto_key_phys_t), &key_phys, tx));
	}
	
	rw_exit(&kc->kc_lock);
	
	*kc_out = new_kc;
	return 0;
	
error_unlock:
	rw_exit(&kc->kc_lock);
error:
	if(new_kc) dsl_dir_keychain_free(new_kc);
	
	*kc_out = NULL;
	return ret;
}

int dsl_dir_keychain_load(objset_t *mos, uint64_t kcobj, zio_crypt_key_t *wkey, dsl_dir_keychain_t **kc_out){
	int ret;
	dsl_dir_keychain_t *kc;
	zap_cursor_t zc;
	zap_attribute_t za;
	uint64_t txgid;
	dsl_crypto_key_phys_t dckp;
	uint64_t crypt = wkey->zk_crypt;
	uint_t keylen = zio_crypt_table[crypt].ci_keylen;
	uint8_t keydata[keylen + WRAPPING_MAC_LEN];
	dsl_dir_keychain_entry_t *kce;
	
	//allocate and initialize the keychain struct
	ret = dsl_dir_keychain_create(wkey, kcobj, &kc);
	if(ret) goto error;
	
	//iterate all entries in the on-disk keychain
	for(zap_cursor_init(&zc, mos, kcobj); zap_cursor_retrieve(&zc, &za) == 0; zap_cursor_advance(&zc)) {
		//fetch the txg key of the keychain entry
		txgid = ((uint64_t)*za.za_name);
		
		//lookup the dsl_crypto_key_phys_t value of the key
		ret = zap_lookup_uint64(mos, kcobj, &txgid, 1, 1, sizeof(dsl_crypto_key_phys_t), &dckp);
		if(ret) goto error;
		
		//check to make sure we are using the correct unwrapping mechanism (should match wrapping key)
		if(crypt != dckp.dk_crypt_alg) return EINVAL;
		
		//unwrap the key, will return error if wkey is incorrect by checking the MAC
		ret = zio_crypt_key_unwrap(wkey, &dckp, keydata);
		if(ret) goto error;
		
		//allocate the keychain entry
		kce = kmem_zalloc(sizeof(dsl_dir_keychain_entry_t), KM_SLEEP);
		if(!kce){
			ret = ENOMEM;
			goto error;
		}
		
		//create the key from keydata
		ret = zio_crypt_key_create(crypt, keydata, kce, &kce->ke_key);
		if(ret) goto error;
		
		//set the txgid and add the entry to the keychain
		kce->ke_txgid = txgid;
		list_insert_tail(&kc->kc_entries, kce);
	}
	//release the zap crusor
	zap_cursor_fini(&zc);
	
	//unwrapped all keys sucessfully. add the wrapping key to the keychain
	zio_crypt_key_hold(wkey, kc);
	kc->kc_wkey = wkey;
	
	*kc_out = kc;
	return 0;
	
error:
	if(kc) dsl_dir_keychain_free(kc);

	*kc_out = NULL;
	return ret;
}
