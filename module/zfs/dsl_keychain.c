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
#include <sys/dsl_dir.h>

//macros for defining encryption parameter lengths
#define MAX_KEY_LEN 32
#define ZIO_CRYPT_WRAPKEY_IVLEN 13
#define WRAPPING_MAC_LEN 16
#define WRAPPED_KEYDATA_LEN(keylen) ((keylen) + ZIO_CRYPT_WRAPKEY_IVLEN + WRAPPING_MAC_LEN)

static int zio_crypt_key_wrap(zio_crypt_key_t *wkey, uint8_t *keydata, uint8_t *ivdata, dsl_crypto_key_phys_t *dckp){
	int ret;
	uint64_t crypt = wkey->zk_crypt;
	
	ASSERT(crypt < ZIO_CRYPT_FUNCTIONS);
	ASSERT(wkey->zk_key->ck_format == CRYPTO_KEY_RAW);

	//copy the crypt and iv data into the dsl_crypto_key_phys_t
	dckp->dk_crypt_alg = crypt;
	bcopy(ivdata, dckp->dk_iv, ZIO_CRYPT_WRAPKEY_IVLEN);
	bzero(dckp->dk_padding, sizeof(dckp->dk_padding));
	bzero(dckp->dk_keybuf, sizeof(dckp->dk_keybuf));
	
	//encrypt the key and store the result in dckp->keybuf
	ret = zio_encrypt(wkey, ivdata, ZIO_CRYPT_WRAPKEY_IVLEN, WRAPPING_MAC_LEN, keydata, dckp->dk_keybuf, zio_crypt_table[crypt].ci_keylen);
	if(ret) goto error;
	
	return 0;
error:
	LOG_ERROR(ret, "");
	return ret;
}

static int zio_crypt_key_unwrap(zio_crypt_key_t *wkey, dsl_crypto_key_phys_t *dckp, uint8_t *keydata){
	int ret;
	uint64_t crypt = wkey->zk_crypt;
	
	ASSERT(crypt < ZIO_CRYPT_FUNCTIONS);
	ASSERT(wkey->zk_key->ck_format == CRYPTO_KEY_RAW);

	//encrypt the key and store the result in dckp->keybuf
	ret = zio_decrypt(wkey, dckp->dk_iv, ZIO_CRYPT_WRAPKEY_IVLEN, WRAPPING_MAC_LEN, keydata, dckp->dk_keybuf, zio_crypt_table[crypt].ci_keylen);
	if(ret) goto error;
	
	return 0;
error:
	LOG_ERROR(ret, "");
	return ret;
}

static void dsl_keychain_entry_free(dsl_keychain_entry_t *kce){
	if(kce->ke_key) zio_crypt_key_rele(kce->ke_key, kce);
	kmem_free(kce, sizeof(dsl_keychain_entry_t));
}	

static int dsl_keychain_entry_generate(uint64_t crypt, uint64_t txgid, dsl_keychain_entry_t **kce_out){
	int ret;
	dsl_keychain_entry_t *kce = NULL;
	uint64_t keydata_len = zio_crypt_table[crypt].ci_keylen;
	uint8_t rnddata[keydata_len];
	
	//allocate the keychain entry
	kce = kmem_zalloc(sizeof(dsl_keychain_entry_t), KM_SLEEP);
	if(!kce){
		ret = SET_ERROR(ENOMEM);
		goto error;
	}
	list_link_init(&kce->ke_link);
	
	//set the txgid
	kce->ke_txgid = txgid;
	
	//fill our buffer with random data
	ret = random_get_bytes(rnddata, keydata_len);
	if(ret) goto error;
	
	//create the key from the random data
	ret = zio_crypt_key_create(crypt, rnddata, kce, &kce->ke_key);
	if(ret) goto error;
	
	PRINT_ZKEY(kce->ke_key, "created key");
	
	*kce_out = kce;
	return 0;
	
error:
	LOG_ERROR(ret, "");
	if(kce) dsl_keychain_entry_free(kce);

	*kce_out = NULL;
	return ret;
}

void dsl_keychain_free(dsl_keychain_t *kc){
	dsl_keychain_entry_t *kce;
	
	//release each encryption key from the keychain
	while((kce = list_head(&kc->kc_entries)) != NULL){
		LOG_DEBUG("freeing encryption key entry %p", kce);
		PRINT_ZKEY(kce->ke_key, "");
		list_remove(&kc->kc_entries, kce);
		dsl_keychain_entry_free(kce);
	}
	
	LOG_DEBUG("done freeing key entries");
	
	//free the keychain entries list, wrapping key, and lock
	rw_destroy(&kc->kc_lock);
	list_destroy(&kc->kc_entries);
	refcount_destroy(&kc->kc_refcnt);
	
	LOG_DEBUG("freeing wrapping key");
	if(kc->kc_wkey) zio_crypt_key_rele(kc->kc_wkey, kc);
	
	//free the keychain
	kmem_free(kc, sizeof(dsl_keychain_t));
}

int dsl_keychain_alloc(dsl_keychain_t **kc_out){
	int ret;
	dsl_keychain_t *kc;
	
	//allocate the keychain struct
	kc = kmem_alloc(sizeof(dsl_keychain_t), KM_SLEEP);
	if(!kc){
		ret = SET_ERROR(ENOMEM);
		goto error;
	}
	
	//initialize members
	kc->kc_obj = 0;
	kc->kc_wkey = NULL;
	rw_init(&kc->kc_lock, NULL, RW_DEFAULT, NULL);
	list_create(&kc->kc_entries, sizeof(dsl_keychain_entry_t), offsetof(dsl_keychain_entry_t, ke_link));
	refcount_create(&kc->kc_refcnt);
	
	*kc_out = kc;
	return 0;
	
error:
	LOG_ERROR(ret, "");
	*kc_out = NULL;
	return ret;
}

int dsl_keychain_rewrap(dsl_keychain_t *kc, zio_crypt_key_t *wkey, dmu_tx_t *tx){
	int ret;
	dsl_keychain_entry_t *kce;
	uint8_t ivdata[ZIO_CRYPT_WRAPKEY_IVLEN];
	dsl_crypto_key_phys_t key_phys;
	
	//most of this function only reads the keychain, but we do need to change the wkey under the same lock
	rw_enter(&kc->kc_lock, RW_WRITER);
	
	//iterate through the list of encryption keys
	for(kce = list_head(&kc->kc_entries); kce; kce = list_next(&kc->kc_entries, kce)){		
		//generate an iv
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
	LOG_ERROR(ret, "");
	rw_exit(&kc->kc_lock);
	return ret;
}

int dsl_keychain_lookup_key(dsl_keychain_t *kc, uint64_t txgid, zio_crypt_key_t **key_out){
	dsl_keychain_entry_t *kce;
	
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
	return SET_ERROR(ENOENT);
}

int dsl_keychain_add_key(dsl_keychain_t *kc, dmu_tx_t *tx){
	int ret;
	uint64_t crypt = kc->kc_wkey->zk_crypt;
	dsl_keychain_entry_t *kce = NULL;
	uint8_t ivdata[ZIO_CRYPT_WRAPKEY_IVLEN];
	dsl_crypto_key_phys_t key_phys;
	
	//generate the keychain entry with the same encryption type as the wrapping key
	ret = dsl_keychain_entry_generate(crypt, tx->tx_txg, &kce);
	if(ret) goto error;
	
	//generate an iv
	ret = random_get_bytes(ivdata, ZIO_CRYPT_WRAPKEY_IVLEN);
	if(ret) goto error;
	
	//wrap the key and store the result in key_phys
	ret = zio_crypt_key_wrap(kc->kc_wkey, kce->ke_key->zk_key.ck_data, ivdata, &key_phys);
	if(ret) goto error;
	
	//add the wrapped key entry to the zap
	VERIFY0(zap_add_uint64(tx->tx_pool->dp_meta_objset, kc->kc_obj, &tx->tx_txg, 1, 1, sizeof(dsl_crypto_key_phys_t), &key_phys, tx));
	
	//add the entry to the keychain
	rw_enter(&kc->kc_lock, RW_WRITER);
	list_insert_tail(&kc->kc_entries, kce);
	rw_exit(&kc->kc_lock);
	
	return 0;
	
error:
	LOG_ERROR(ret, "");
	if(kce) dsl_keychain_entry_free(kce);

	return ret;
}

int dsl_keychain_create_sync(zio_crypt_key_t *wkey, dmu_tx_t *tx, dsl_keychain_t **kc_out){
	int ret;
	dsl_keychain_t *kc = NULL;
	
	//create the new keychain for the clone
	ret = dsl_keychain_alloc(&kc);
	if(ret) goto error;
	
	//add the wrapping key
	zio_crypt_key_hold(wkey, kc);
	kc->kc_wkey = wkey;
	
	//create the DSL Keychain object
	kc->kc_obj = zap_create_flags(tx->tx_pool->dp_meta_objset, 0, ZAP_FLAG_UINT64_KEY, DMU_OT_DSL_KEYCHAIN, 0, 0, DMU_OT_NONE, 0, tx);
	
	//add a key to the keychain
	ret = dsl_keychain_add_key(kc, tx);
	if(ret) goto error;
	
	*kc_out = kc;
	return 0;
	
error:
	LOG_ERROR(ret, "");
	if(kc) dsl_keychain_free(kc);

	*kc_out = NULL;
	return ret;
}

int dsl_keychain_clone_sync(dsl_keychain_t *kc, dmu_tx_t *tx, dsl_keychain_t **kc_out){
	int ret;
	dsl_keychain_t *new_kc = NULL;
	dsl_keychain_entry_t *kce, *new_kce;
	uint8_t ivdata[ZIO_CRYPT_WRAPKEY_IVLEN];
	dsl_crypto_key_phys_t key_phys;
	
	//create the new keychain for the clone
	ret = dsl_keychain_alloc(&new_kc);
	if(ret) goto error;
	
	//add the wrapping key
	zio_crypt_key_hold(kc->kc_wkey, new_kc);
	new_kc->kc_wkey = kc->kc_wkey;
	
	//create the DSL Keychain object
	new_kc->kc_obj = zap_create_flags(tx->tx_pool->dp_meta_objset, 0, ZAP_FLAG_UINT64_KEY, DMU_OT_DSL_KEYCHAIN, 0, 0, DMU_OT_NONE, 0, tx);
	
	//lock the original keychain for reading
	rw_enter(&kc->kc_lock, RW_READER);
	
	//iterate through the list of encryption keys
	for(kce = list_head(&kc->kc_entries); kce; kce = list_next(&kc->kc_entries, kce)){
		//allocate the keychain entry
		new_kce = kmem_zalloc(sizeof(dsl_keychain_entry_t), KM_SLEEP);
		if(!new_kce){
			ret = SET_ERROR(ENOMEM);
			goto error_unlock;
		}
		list_link_init(&new_kce->ke_link);
		
		//assign the txgid and key to the keychain entry
		new_kce->ke_txgid = kce->ke_txgid;
		zio_crypt_key_hold(kce->ke_key, new_kc);
		new_kce->ke_key = kce->ke_key;
		
		//add the key entry to the entries list
		list_insert_tail(&new_kc->kc_entries, new_kce);
		
		//generate an iv
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
	LOG_ERROR(ret, "");
	if(new_kc) dsl_keychain_free(new_kc);
	
	*kc_out = NULL;
	return ret;
}

int dsl_keychain_open(objset_t *mos, uint64_t kcobj, uint8_t *wkeydata, uint_t wkeydata_len, dsl_keychain_t **kc_out){
	int ret, need_crypt = 1;
	zap_cursor_t zc;
	zap_attribute_t za;
	uint64_t txgid;
	dsl_crypto_key_phys_t dckp;
	uint64_t crypt;
	uint8_t keydata[MAX_KEY_LEN + WRAPPING_MAC_LEN];
	dsl_keychain_entry_t *kce = NULL;
	dsl_keychain_t *kc = NULL;
	zio_crypt_key_t *wkey = NULL;
	
	//allocate and initialize the keychain struct
	ret = dsl_keychain_alloc(&kc);
	if(ret) return ret;
	
	//iterate all entries in the on-disk keychain
	for(zap_cursor_init(&zc, mos, kcobj); zap_cursor_retrieve(&zc, &za) == 0; zap_cursor_advance(&zc)) {
		//fetch the txg key of the keychain entry
		txgid = ((uint64_t)*za.za_name);
		
		//lookup the dsl_crypto_key_phys_t value of the key
		ret = zap_lookup_uint64(mos, kcobj, &txgid, 1, 1, sizeof(dsl_crypto_key_phys_t), &dckp);
		if(ret) goto error;
		
		if(need_crypt){
			//if this is the first iteration, we need to get crypt from dckp so we can create the wrapping key
			crypt = dckp.dk_crypt_alg;
			
			ASSERT(zio_crypt_table[crypt].ci_keylen == wkeydata_len);
			
			ret = zio_crypt_key_create(crypt, wkeydata, kc, &kc->kc_wkey);
			if(ret) goto error;
			
			need_crypt = 0;
		}else if(dckp.dk_crypt_alg != crypt){
			//all other entries' crypt should match the first
			ret = SET_ERROR(EINVAL);
			goto error;
		}
		
		//unwrap the key, will return error if wkey is incorrect by checking the MAC
		ret = zio_crypt_key_unwrap(wkey, &dckp, keydata);
		if(ret) goto error;
		
		//allocate the keychain entry
		kce = kmem_zalloc(sizeof(dsl_keychain_entry_t), KM_SLEEP);
		if(!kce){
			ret = SET_ERROR(ENOMEM);
			goto error;
		}
		list_link_init(&kce->ke_link);
		
		//create the key from keydata
		ret = zio_crypt_key_create(crypt, keydata, kce, &kce->ke_key);
		if(ret) goto error;
		
		//set the txgid and add the entry to the keychain
		kce->ke_txgid = txgid;
		list_insert_tail(&kc->kc_entries, kce);
		
		//on error, this will be cleaned up by dsl_keychain_free(), make sure it isn't freed twice
		kce = NULL;
	}
	//release the zap crusor
	zap_cursor_fini(&zc);
	
	*kc_out = kc;
	return 0;
	
error:
	LOG_ERROR(ret, "");
	zap_cursor_fini(&zc);
	if(kce) dsl_keychain_entry_free(kce); //will clean up kce->ke_key too, if it exists
	if(kc) dsl_keychain_free(kc); //will clean up wkey too, if it exists

	*kc_out = NULL;
	return ret;
}

int spa_keychain_entry_compare(const void *a, const void *b){
	const dsl_keychain_t *kca = a;
	const dsl_keychain_t *kcb = b;
	
	if(kca->kc_obj < kcb->kc_obj) return -1;
	if(kca->kc_obj > kcb->kc_obj) return 1;
	return 0;
}

int spa_keychain_lookup(spa_t *spa, uint64_t kcobj, dsl_keychain_t **kc_out){
	dsl_keychain_t search_kc;
	dsl_keychain_t *found_kc;
	
	//init the search keychain
	search_kc.kc_obj = kcobj;
	
	//lookup the keychain under the spa's keychain lock
	rw_enter(&spa->spa_loaded_keys_lock, RW_READER);
	found_kc = avl_find(&spa->spa_loaded_keys, &search_kc, NULL);
	rw_exit(&spa->spa_loaded_keys_lock);
	
	*kc_out = found_kc;
	return (found_kc) ? 0 : SET_ERROR(ENOENT);
}

int spa_keychain_insert(spa_t *spa, dsl_keychain_t *kc){
	int ret = 0;
	avl_index_t where;
	
	rw_enter(&spa->spa_loaded_keys_lock, RW_WRITER);
	
	//add the keychain to the avl tree, return an error if one already exists for that kcobj
	if(avl_find(&spa->spa_loaded_keys, kc, &where) != NULL){
		ret = SET_ERROR(EEXIST);
		goto out;
	}
	avl_insert(&spa->spa_loaded_keys, kc, where);
	
out:
	rw_exit(&spa->spa_loaded_keys_lock);
	return ret;
}

int spa_keychain_load(spa_t *spa, uint64_t kcobj, uint8_t *wkeydata, uint_t wkeydata_len){
	int ret;
	dsl_keychain_t *kc;
	
	//load the keychain from disk
	ret = dsl_keychain_open(spa_get_dsl(spa)->dp_meta_objset, kcobj, wkeydata, wkeydata_len, &kc);
	if(ret) return ret;
	
	//add the keychain to the spa
	ret = spa_keychain_insert(spa, kc);
	if(ret) goto error;
	
	return 0;
	
error:
	LOG_ERROR(ret, "");
	dsl_keychain_free(kc);
	return ret;
}

int spa_keychain_unload(spa_t *spa, uint64_t kcobj){
	int ret;
	dsl_keychain_t search_kc;
	dsl_keychain_t *found_kc;
	
	//init the search keychain
	search_kc.kc_obj = kcobj;
	
	rw_enter(&spa->spa_loaded_keys_lock, RW_READER);
	
	//lookup the keychain, check for unloading errors
	found_kc = avl_find(&spa->spa_loaded_keys, &search_kc, NULL);
	if(found_kc == NULL){
		ret = SET_ERROR(ENOENT);
		goto error;
	}else if(!refcount_is_zero(&found_kc->kc_refcnt)){
		ret = SET_ERROR(EBUSY);
		goto error;
	}
	
	//remove the keychain from the tree
	avl_remove(&spa->spa_loaded_keys, found_kc);
	
	rw_exit(&spa->spa_loaded_keys_lock);
	
	return 0;
	
error:
	LOG_ERROR(ret, "");
	rw_exit(&spa->spa_loaded_keys_lock);
	return ret;
}
