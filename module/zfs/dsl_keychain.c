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
#include <sys/dsl_prop.h>
#include <sys/spa_impl.h>

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

/* 
 * Keychain will not be unloaded on refcount hitting zero, but it will become unloadable.
 * References given out via the spa_lookup_keychain_* functions should all be within the
 * context of an owned dataset. When a dataset is disowned spa_keychain_remove_index()
 * will be called, which will release a reference to the keychain
 */
static void dsl_keychain_hold(dsl_keychain_t *kc, void *tag){
	(void)refcount_add(&kc->kc_refcnt, tag);
	LOG_DEBUG("keychain hold : refcount = %d", (int)refcount_count(&kc->kc_refcnt));
}

static void dsl_keychain_rele(dsl_keychain_t *kc, void *tag){
	(void)refcount_remove(&kc->kc_refcnt, tag);
	LOG_DEBUG("keychain rele : refcount = %d", (int)refcount_count(&kc->kc_refcnt));
}

typedef struct dsl_keychain_rewrap_args {
	const char *dkra_dsname;
	zio_crypt_key_t *dkra_wkey;
} dsl_keychain_rewrap_args_t;

static int dsl_keychain_add_key_rewrap_check_impl(const char *dsname, dmu_tx_t *tx){
	int ret;
	dsl_dir_t *dd = NULL;
	dsl_keychain_t *kc = NULL;
	dsl_pool_t *dp = dmu_tx_pool(tx);
	
	//check that the keychain object exists and is loaded
	ret = dsl_dir_hold(dp, dsname, FTAG, &dd, NULL);
	if(ret) return ret;
	
	if(dsl_dir_phys(dd)->dd_keychain_obj == 0){
		ret = SET_ERROR(EINVAL);
		goto error;
	}
	
	ret = spa_keystore_lookup(dp->dp_spa, dsl_dir_phys(dd)->dd_keychain_obj, &kc);
	if(ret) goto error;
	
	dsl_dir_rele(dd, FTAG);
	
	return 0;
	
error:
	dsl_dir_rele(dd, FTAG);
	return ret;
}

static int dsl_keychain_rewrap_check(void *arg, dmu_tx_t *tx){
	dsl_keychain_rewrap_args_t *dkra = arg;
	return dsl_keychain_add_key_rewrap_check_impl(dkra->dkra_dsname, tx);
}

static int dsl_keychain_rewrap_impl(dsl_keychain_t *kc, zio_crypt_key_t *wkey, dmu_tx_t *tx){
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
		VERIFY0(zap_update_uint64(tx->tx_pool->dp_meta_objset, kc->kc_obj, &kce->ke_txgid, 1, 1, sizeof(dsl_crypto_key_phys_t), &key_phys, tx));
		
		LOG_DEBUG("rewrapped key %lu", (unsigned long)kce->ke_txgid);
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

static void dsl_keychain_rewrap_sync(void *arg, dmu_tx_t *tx){
	dsl_keychain_rewrap_args_t *dkra = arg;
	zio_crypt_key_t *wkey = dkra->dkra_wkey;
	const char *dsname = dkra->dkra_dsname;
	dsl_pool_t *dp = dmu_tx_pool(tx);
	dsl_dir_t *dd;
	dsl_keychain_t *kc;
	
	//find the keychain
	VERIFY0(dsl_dir_hold(dp, dsname, FTAG, &dd, NULL));
	VERIFY0(spa_keystore_lookup(dp->dp_spa, dsl_dir_phys(dd)->dd_keychain_obj, &kc));
	
	//rewrap the keychain
	VERIFY0(dsl_keychain_rewrap_impl(kc, wkey, tx));
	
	LOG_DEBUG("rewrapped keychain sucessfully");
	
	dsl_dir_rele(dd, FTAG);
}

static int dsl_keychain_rewrap(const char *dsname, uint64_t crypt, uint8_t *wkeydata){
	int ret;
	uint64_t num_keys;
	dsl_pool_t *dp = NULL;
	dsl_dir_t *dd = NULL;
	zio_crypt_key_t *wkey = NULL;
	dsl_keychain_rewrap_args_t dkra;
	
	//create the key from the raw data
	ret = zio_crypt_key_create(crypt, wkeydata, FTAG, &wkey);
	if(ret) return ret;
	
	//get the number of entries we are going to change
	ret = dsl_pool_hold(dsname, FTAG, &dp);
	if(ret) goto error;
	
	ret = dsl_dir_hold(dp, dsname, FTAG, &dd, NULL);
	if(ret) goto error;
	
	if(dsl_dir_phys(dd)->dd_keychain_obj == 0){
		ret = SET_ERROR(EINVAL);
		goto error;
	}
	
	ret = zap_count(dp->dp_meta_objset, dsl_dir_phys(dd)->dd_keychain_obj, &num_keys);
	if(ret) goto error;
	
	dsl_dir_rele(dd, FTAG);
	dsl_pool_rele(dp, FTAG);
	
	//fill the arg struct
	dkra.dkra_dsname = dsname;
	dkra.dkra_wkey = wkey;
	
	//rewrap the key in syncing context
	ret = dsl_sync_task(dsname, dsl_keychain_rewrap_check, dsl_keychain_rewrap_sync, &dkra, num_keys, ZFS_SPACE_CHECK_NORMAL);
	
	zio_crypt_key_rele(wkey, FTAG);
	
	return ret;
	
error:
	if(dd) dsl_dir_rele(dd, FTAG);
	if(dp) dsl_pool_rele(dp, FTAG);
	if(wkey) zio_crypt_key_rele(wkey, FTAG);
	
	return ret;
}

int dsl_keychain_rewrap_nvlist(const char *dsname, nvlist_t *props){
	int ret;
	uint64_t crypt;
	boolean_t have_salt = B_FALSE;
	uint8_t *wkeydata = NULL;
	uint_t wkeydata_len;
	nvpair_t *elem = NULL;
	char *propname;
	zfs_prop_t prop;
	
	//get the crypt value from the dataset
	ret = dsl_prop_get_integer(dsname, zfs_prop_to_name(ZFS_PROP_ENCRYPTION), &crypt, NULL);
	if(ret) return SET_ERROR(EINVAL);
	
	//get all the required properties for rewrapping
	while((elem = nvlist_next_nvpair(props, elem)) != NULL){
		propname = nvpair_name(elem);
		prop = zfs_name_to_prop(propname);
		
		if(prop == ZPROP_INVAL){
			if(!strcmp(propname, "wkeydata")){
				ret = nvpair_value_uint8_array(elem, &wkeydata, &wkeydata_len);
				if(ret) goto error;
			}else{
				ret = SET_ERROR(EINVAL);
				goto error;
			}
			continue;
		}
		
		switch(prop){
		case ZFS_PROP_SALT:
			have_salt = B_TRUE;
			break;
		case ZFS_PROP_KEYSOURCE:
			break;
		default:
			ret = SET_ERROR(EINVAL);
			goto error;
		}
	}
	
	//must have wkeydata and salt to change keys
	if(!wkeydata || !have_salt){
		ret = SET_ERROR(EINVAL);
		goto error;
	}
	
	//rewrap the keychain
	ret = dsl_keychain_rewrap(dsname, crypt, wkeydata);
	if(ret) goto error;
	
	//delete the wkeydata from props
	bzero(wkeydata, wkeydata_len);
	VERIFY0(nvlist_remove_all(props, "wkeydata"));
	
	return 0;
	
error:
	return ret;
}

static int dsl_keychain_add_key_check(void *arg, dmu_tx_t *tx){
	char *dsname = arg;
	return dsl_keychain_add_key_rewrap_check_impl(dsname, tx);
}

static int dsl_keychain_add_key_impl(dsl_keychain_t *kc, dmu_tx_t *tx){
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
	
	rw_enter(&kc->kc_lock, RW_WRITER);
	
	//add the wrapped key entry to the zap
	VERIFY0(zap_add_uint64(tx->tx_pool->dp_meta_objset, kc->kc_obj, &tx->tx_txg, 1, 1, sizeof(dsl_crypto_key_phys_t), &key_phys, tx));
	
	//add the entry to the keychain
	list_insert_tail(&kc->kc_entries, kce);
	
	rw_exit(&kc->kc_lock);
	
	return 0;
	
error:
	LOG_ERROR(ret, "");
	if(kce) dsl_keychain_entry_free(kce);

	return ret;
}

static void dsl_keychain_add_key_sync(void *arg, dmu_tx_t *tx){
	dsl_dir_t *dd;
	dsl_keychain_t *kc;
	dsl_pool_t *dp = dmu_tx_pool(tx);
	char *dsname = arg;
	dsl_keychain_entry_t *kce;
	
	//find the keychain
	VERIFY0(dsl_dir_hold(dp, dsname, FTAG, &dd, NULL));
	VERIFY0(spa_keystore_lookup(dp->dp_spa, dsl_dir_phys(dd)->dd_keychain_obj, &kc));
	
	//generate and add a key
	VERIFY0(dsl_keychain_add_key_impl(kc, tx));
	
	LOG_DEBUG("added keychain entry sucessfully");
	for(kce = list_head(&kc->kc_entries); kce; kce = list_next(&kc->kc_entries, kce)){
		LOG_DEBUG("kce %lu", (unsigned long)kce->ke_txgid);
	}
	
	dsl_dir_rele(dd, FTAG);
}

int dsl_keychain_add_key(const char *dsname){
	return (dsl_sync_task(dsname, dsl_keychain_add_key_check, dsl_keychain_add_key_sync, (void *)dsname, 1, ZFS_SPACE_CHECK_NORMAL));
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

void dsl_keychain_destroy(uint64_t kcobj, dmu_tx_t *tx){
	//destroy the keychain object
	VERIFY0(zap_destroy(tx->tx_pool->dp_meta_objset, kcobj, tx));
	
	//decrement the feature count
	spa_feature_decr(tx->tx_pool->dp_spa, SPA_FEATURE_ENCRYPTION, tx);
}

int dsl_keychain_create_sync(zio_crypt_key_t *wkey, dmu_tx_t *tx, uint64_t *kcobj_out){
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
	ret = dsl_keychain_add_key_impl(kc, tx);
	if(ret) goto error;
	
	//increment the encryption feature count
	spa_feature_incr(tx->tx_pool->dp_spa, SPA_FEATURE_ENCRYPTION, tx);
	
	//add the keychain to the spa keystore so the user doesn't have to later
	ret = spa_keystore_insert(tx->tx_pool->dp_spa, kc);
	if(ret) goto error;
	
	*kcobj_out = kc->kc_obj;
	return 0;
	
error:
	LOG_ERROR(ret, "");
	if(kc) dsl_keychain_free(kc);

	*kcobj_out = 0;
	return ret;
}

int dsl_keychain_clone_sync(uint64_t orig_kcobj, dmu_tx_t *tx, uint64_t *kcobj_out){
	int ret;
	dsl_keychain_t *kc = NULL, *new_kc = NULL;
	dsl_keychain_entry_t *kce, *new_kce;
	uint8_t ivdata[ZIO_CRYPT_WRAPKEY_IVLEN];
	dsl_crypto_key_phys_t key_phys;
	
	//lookup the old keychain from the keystore
	ret = spa_keystore_lookup(tx->tx_pool->dp_spa, orig_kcobj, &kc);
	if(ret) return ret;
	
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
	
	//increment the encryption feature count
	spa_feature_incr(tx->tx_pool->dp_spa, SPA_FEATURE_ENCRYPTION, tx);
	
	//add the keychain to the spa keystore so the user doesn't have to later
	ret = spa_keystore_insert(tx->tx_pool->dp_spa, new_kc);
	if(ret) goto error;
	
	*kcobj_out = new_kc->kc_obj;
	return 0;
	
error_unlock:
	rw_exit(&kc->kc_lock);
error:
	LOG_ERROR(ret, "");
	if(new_kc) dsl_keychain_free(new_kc);
	
	*kcobj_out = 0;
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
	dsl_keychain_entry_t *kce = NULL, *cur_kce = NULL;
	dsl_keychain_t *kc = NULL;
	
	LOG_DEBUG("dsl_keychain_open()");
	
	//allocate and initialize the keychain struct
	ret = dsl_keychain_alloc(&kc);
	if(ret) return ret;
	
	kc->kc_obj = kcobj;
	
	//iterate all entries in the on-disk keychain
	for(zap_cursor_init(&zc, mos, kcobj); zap_cursor_retrieve(&zc, &za) == 0; zap_cursor_advance(&zc)) {
		//fetch the txg key of the keychain entry
		txgid = ((uint64_t)*za.za_name);
		
		//lookup the dsl_crypto_key_phys_t value of the key
		ret = zap_lookup_uint64(mos, kcobj, &txgid, 1, 1, sizeof(dsl_crypto_key_phys_t), &dckp);
		if(ret) goto error;
		
		LOG_DEBUG("found keychain dckp");
		
		if(need_crypt){
			//if this is the first iteration, we need to get crypt from dckp so we can create the wrapping key
			crypt = dckp.dk_crypt_alg;
			
			ASSERT(zio_crypt_table[crypt].ci_keylen == wkeydata_len);
			
			ret = zio_crypt_key_create(crypt, wkeydata, kc, &kc->kc_wkey);
			if(ret) goto error;
			
			PRINT_ZKEY(kc->kc_wkey, "created wrapping key");
			
			need_crypt = 0;
		}else if(dckp.dk_crypt_alg != crypt){
			//all other entries' crypt should match the first
			ret = SET_ERROR(EINVAL);
			goto error;
		}
		
		LOG_DEBUG("attempting to unwrap the key");
		
		//unwrap the key, will return error if wkey is incorrect by checking the MAC
		ret = zio_crypt_key_unwrap(kc->kc_wkey, &dckp, keydata);
		if(ret){
			ret = SET_ERROR(EINVAL);
			goto error;
		}
		
		LOG_DEBUG("unwraped the key");
		
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
		
		LOG_DEBUG("created keychain entry");
		
		//set the txgid
		kce->ke_txgid = txgid;
		
		//the zap does not store keys in order, we must add them in order
		for(cur_kce = list_head(&kc->kc_entries); cur_kce; cur_kce = list_next(&kc->kc_entries, cur_kce)){
			if(cur_kce->ke_txgid > kce->ke_txgid) break;
		}
		list_insert_before(&kc->kc_entries, cur_kce, kce);
		
		LOG_DEBUG("added keychain entry to keychain");
		
		//on error, this will be cleaned up by dsl_keychain_free(), make sure it isn't freed twice
		kce = NULL;
	}
	//release the zap crusor
	zap_cursor_fini(&zc);
	
	LOG_DEBUG("opened keychain successfully");
	
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

zfs_keystatus_t dsl_keychain_keystatus(dsl_dataset_t *ds){
	int ret;
	uint64_t kcobj = dsl_dir_phys(ds->ds_dir)->dd_keychain_obj;
	dsl_keychain_t *kc;
	
	if(kcobj == 0) return ZFS_KEYSTATUS_NONE;
	
	ret = spa_keystore_lookup(ds->ds_dir->dd_pool->dp_spa, kcobj, &kc);
	if(ret) return ZFS_KEYSTATUS_UNAVAILABLE;
	
	LOG_DEBUG("current key refcount = %d", (int)refcount_count(&kc->kc_refcnt));
	
	return ZFS_KEYSTATUS_AVAILABLE;
}

static int spa_keychain_compare(const void *a, const void *b){
	const dsl_keychain_t *kca = a;
	const dsl_keychain_t *kcb = b;
	
	if(kca->kc_obj < kcb->kc_obj) return -1;
	if(kca->kc_obj > kcb->kc_obj) return 1;
	return 0;
}

static int spa_keychain_index_compare(const void *a, const void *b){
	const dsl_keychain_record_t *kra = a;
	const dsl_keychain_record_t *krb = b;
	
	if(kra->kr_dsobj < krb->kr_dsobj) return -1;
	if(kra->kr_dsobj > krb->kr_dsobj) return 1;
	return 0;
}

void spa_keystore_init(spa_keystore_t *sk){
	rw_init(&sk->sk_lock, NULL, RW_DEFAULT, NULL);
	avl_create(&sk->sk_keychains, spa_keychain_compare, sizeof (dsl_keychain_t), offsetof(dsl_keychain_t, kc_avl_link));
	avl_create(&sk->sk_keychain_index, spa_keychain_index_compare, sizeof (dsl_keychain_record_t), offsetof(dsl_keychain_record_t, kr_avl_link));
}

void spa_keystore_fini(spa_keystore_t *sk){
	avl_destroy(&sk->sk_keychain_index);
	avl_destroy(&sk->sk_keychains);
	rw_destroy(&sk->sk_lock);
}

int spa_keystore_lookup(spa_t *spa, uint64_t kcobj, dsl_keychain_t **kc_out){
	int ret;
	dsl_keychain_t search_kc;
	dsl_keychain_t *found_kc;
	
	//init the search keychain
	search_kc.kc_obj = kcobj;
	
	//lookup the keychain under the spa's keychain lock
	rw_enter(&spa->spa_keystore.sk_lock, RW_READER);
	
	found_kc = avl_find(&spa->spa_keystore.sk_keychains, &search_kc, NULL);
	if(!found_kc){
		ret = SET_ERROR(ENOENT);
		goto error;
	}
	
	rw_exit(&spa->spa_keystore.sk_lock);
	
	*kc_out = found_kc;
	return 0;
	
error:
	LOG_ERROR(ret, "");
	rw_exit(&spa->spa_keystore.sk_lock);
	*kc_out = NULL;
	return ret;
}

int spa_keystore_insert(spa_t *spa, dsl_keychain_t *kc){
	int ret = 0;
	avl_index_t where;
	
	rw_enter(&spa->spa_keystore.sk_lock, RW_WRITER);
	
	//add the keychain to the avl tree, return an error if one already exists for that kcobj
	if(avl_find(&spa->spa_keystore.sk_keychains, kc, &where) != NULL){
		ret = SET_ERROR(EEXIST);
		goto out;
	}
	avl_insert(&spa->spa_keystore.sk_keychains, kc, where);
	
out:
	rw_exit(&spa->spa_keystore.sk_lock);
	return ret;
}

int spa_keystore_load(spa_t *spa, uint64_t kcobj, uint8_t *wkeydata, uint_t wkeydata_len){
	int ret;
	dsl_keychain_t *kc;
	
	LOG_DEBUG("loading key %lu", (unsigned long)kcobj);
	
	//load the keychain from disk
	ret = dsl_keychain_open(spa_get_dsl(spa)->dp_meta_objset, kcobj, wkeydata, wkeydata_len, &kc);
	if(ret) return ret;
	
	//add the keychain to the spa
	ret = spa_keystore_insert(spa, kc);
	if(ret) goto error;
	
	LOG_DEBUG("loaded key sucessfully");
	
	return 0;
	
error:
	LOG_ERROR(ret, "");
	dsl_keychain_free(kc);
	return ret;
}

int spa_keystore_unload(spa_t *spa, uint64_t kcobj){
	int ret;
	dsl_keychain_t search_kc;
	dsl_keychain_t *found_kc;
	
	LOG_DEBUG("unloading key %lu", (unsigned long)kcobj);
	
	//init the search keychain
	search_kc.kc_obj = kcobj;
	
	rw_enter(&spa->spa_keystore.sk_lock, RW_READER);
	
	//lookup the keychain, check for unloading errors
	found_kc = avl_find(&spa->spa_keystore.sk_keychains, &search_kc, NULL);
	if(found_kc == NULL){
		ret = SET_ERROR(ENOENT);
		goto error;
	}else if(!refcount_is_zero(&found_kc->kc_refcnt)){
		LOG_DEBUG("keychain busy: %d", (int)refcount_count(&found_kc->kc_refcnt));
		ret = SET_ERROR(EBUSY);
		goto error;
	}
	
	//remove the keychain from the tree
	avl_remove(&spa->spa_keystore.sk_keychains, found_kc);
	
	rw_exit(&spa->spa_keystore.sk_lock);
	
	LOG_DEBUG("unloaded key sucessfully");
	
	return 0;
	
error:
	LOG_ERROR(ret, "");
	rw_exit(&spa->spa_keystore.sk_lock);
	return ret;
}

/* The spa keystore index provides a means for the zio layer to lookup keys by objset id */
int spa_keystore_lookup_index(spa_t *spa, uint64_t dsobj, dsl_keychain_t **kc_out){
	int ret;
	dsl_keychain_record_t search_kr;
	dsl_keychain_record_t *found_kr;
	
	LOG_DEBUG("looking up index %d", (int)dsobj);
	
	//init the search keychain record
	search_kr.kr_dsobj = dsobj;
	
	rw_enter(&spa->spa_keystore.sk_lock, RW_READER);
	
	//lookup the keychain under the spa's keychain lock
	found_kr = avl_find(&spa->spa_keystore.sk_keychain_index, &search_kr, NULL);
	if(!found_kr){
		ret = SET_ERROR(ENOENT);
		goto error;
	}
	
	rw_exit(&spa->spa_keystore.sk_lock);
	
	*kc_out = found_kr->kr_keychain;
	return 0;
	
error:
	LOG_ERROR(ret, "");
	rw_exit(&spa->spa_keystore.sk_lock);
	*kc_out = NULL;
	return ret;
}

static int spa_keystore_insert_index(spa_t *spa, uint64_t dsobj, dsl_keychain_t *kc){
	int ret = 0;
	avl_index_t where;
	dsl_keychain_record_t *kr = NULL;
	
	LOG_DEBUG("inserting index %d -> %d", (int)dsobj, (int)kc->kc_obj);
	
	//allocate the keychain record
	kr = kmem_alloc(sizeof(dsl_keychain_record_t), KM_SLEEP);
	if(!kr) return SET_ERROR(ENOMEM);
	
	//populate the record
	dsl_keychain_hold(kc, kr);
	kr->kr_keychain = kc;
	kr->kr_dsobj = dsobj;
	
	rw_enter(&spa->spa_keystore.sk_lock, RW_WRITER);
	
	//add the keychain record to the avl tree, return an error if one already exists for that kcobj
	if(avl_find(&spa->spa_keystore.sk_keychain_index, kr, &where) != NULL){
		ret = SET_ERROR(EEXIST);
		goto error;
	}
	avl_insert(&spa->spa_keystore.sk_keychain_index, kr, where);
	
	rw_exit(&spa->spa_keystore.sk_lock);
	return 0;
	
error:
	LOG_ERROR(ret, "");
	rw_exit(&spa->spa_keystore.sk_lock);
	kmem_free(kr, sizeof(dsl_keychain_record_t));
	dsl_keychain_rele(kc, kr);
	
	return ret;
}

int spa_keystore_create_index(spa_t *spa, uint64_t dsobj, uint64_t kcobj){
	int ret;
	dsl_keychain_t *kc;
	
	LOG_DEBUG("creating index");
	
	ret = spa_keystore_lookup(spa, kcobj, &kc);
	if(ret) return ret;
	
	LOG_DEBUG("found keychain for indexing");
	
	return (spa_keystore_insert_index(spa, dsobj, kc));
}

int spa_keystore_remove_index(spa_t *spa, uint64_t dsobj){
	int ret;
	dsl_keychain_record_t search_kr;
	dsl_keychain_record_t *found_kr;
	
	LOG_DEBUG("removing key index %lu", (unsigned long)dsobj);
	
	//init the search keychain record
	search_kr.kr_dsobj = dsobj;
	
	rw_enter(&spa->spa_keystore.sk_lock, RW_READER);
	
	//lookup the keychain record
	found_kr = avl_find(&spa->spa_keystore.sk_keychain_index, &search_kr, NULL);
	if(found_kr == NULL){
		ret = SET_ERROR(ENOENT);
		goto error;
	}
	
	//remove the keychain record from the tree
	avl_remove(&spa->spa_keystore.sk_keychain_index, found_kr);
	
	rw_exit(&spa->spa_keystore.sk_lock);
	
	dsl_keychain_rele(found_kr->kr_keychain, found_kr);
	kmem_free(found_kr, sizeof(dsl_keychain_record_t));
	LOG_DEBUG("removed key index sucessfully");
	
	return 0;
	
error:
	LOG_ERROR(ret, "");
	rw_exit(&spa->spa_keystore.sk_lock);
	return ret;
}
