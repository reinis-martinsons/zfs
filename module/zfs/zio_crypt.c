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

#include <sys/zio_crypt.h>
#include <sys/fs/zfs.h>

void zio_crypt_key_hold(zio_crypt_key_t *key, void *tag){
	refcount_add(&key->zk_refcnt, tag);
}

void zio_crypt_key_rele(zio_crypt_key_t *key, void *tag){
	if(!refcount_remove(&key->zk_refcnt, tag)){
		bzero(key->zk_key.ck_data, BITS_TO_BYTES(key->zk_key.ck_length));
		kmem_free(key->zk_key.ck_data, BITS_TO_BYTES(key->zk_key.ck_length));
		crypto_destroy_ctx_template(key->zk_ctx_tmpl);
		kmem_free(key, sizeof(zio_crypt_key_t));
	}
}

int zio_crypt_key_create(uint64_t crypt, uint8_t *keydata, void *tag, zio_crypt_key_t **key_out){
	int ret;
	zio_crypt_key_t *key = NULL;
	crypto_mechanism_t mech;
	uint64_t keydata_len;
	
	ASSERT(crypt < ZIO_CRYPT_FUNCTIONS);
	
	*key_out = NULL;
	
	//get the key length from the crypt table (the buffer should be at least this size)
	keydata_len = zio_crypt_table[crypt].ci_keylen;
	
	//allocate the key
	key = kmem_zalloc(sizeof(zio_crypt_key_t), KM_SLEEP);
	if(!key){
		ret = ENOMEM;
		goto error;
	}
	
	//allocate the key data's new buffer
	key->zk_key.ck_data = kmem_alloc(keydata_len, KM_SLEEP);
	if(!key->zk_key.ck_data){
		ret = ENOMEM;
		goto error;
	}
	
	//set values for the key
	key->zk_crypt = crypt;
	key->zk_key.ck_format = CRYPTO_KEY_RAW;
	key->zk_key.ck_length = BYTES_TO_BITS(keydata_len);
	
	//copy the data
	bcopy(keydata, key->zk_key.ck_data, keydata_len);
	
	//create the key's context template
	mech.cm_type = crypto_mech2id(zio_crypt_table[crypt].ci_mechname);
	ret = crypto_create_ctx_template(&mech, &key->zk_key, &key->zk_ctx_tmpl, KM_SLEEP);
	if(ret != CRYPTO_SUCCESS){
		ret = EIO;
		key->zk_ctx_tmpl = NULL;
		goto error;
	}
	
	//initialize the refount
	refcount_create(&key->zk_refcnt);
	refcount_add(&key->zk_refcnt, tag);
	
	*key_out = key;
	return 0;
	
error:
	LOG_ERROR(ret, "");
	if(key->zk_key.ck_data) kmem_free(key->zk_key.ck_data, keydata_len);
	if(key) kmem_free(key, sizeof(zio_crypt_key_t));
	
	*key_out = NULL;
	return ret;
}

int zio_crypt_wkey_create_nvlist(nvlist_t *props, void *tag, zio_crypt_key_t **key_out){
	int ret;
	zio_crypt_key_t *key = NULL;
	boolean_t crypt_exists = B_TRUE, keydata_exists = B_TRUE, keysource_exists = B_TRUE; 
	uint64_t crypt;
	uint8_t *wkeydata;
	uint_t wkeydata_len;
	char *keysource;
	uint64_t salt;
	
	*key_out = NULL;
	
	//get relevent properties from the nvlist
	ret = nvlist_lookup_uint64(props, zfs_prop_to_name(ZFS_PROP_ENCRYPTION), &crypt);
	if(ret) crypt_exists = B_FALSE;
	
	ret = nvlist_lookup_string(props, zfs_prop_to_name(ZFS_PROP_KEYSOURCE), &keysource);
	if(ret) keysource_exists = B_FALSE;
	
	ret = nvlist_lookup_uint8_array(props, "wkeydata", &wkeydata, &wkeydata_len);
	if(ret) keydata_exists = B_FALSE;
	
	//no encryption properties is valid, results in a NULL keychain
	if(!crypt_exists && !keydata_exists && !keysource_exists) return 0;
	
	//all 3 properties must be present or not
	if(!(crypt_exists && keydata_exists && keysource_exists)) return EINVAL;
	
	//keysource should be of format passphrase for salt to exist
	if(!strncmp(keysource, "passphrase", 10) && nvlist_lookup_uint64(props, zfs_prop_to_name(ZFS_PROP_SALT), &salt) != 0) return EINVAL;
	
	//wkeydata len must match the desired encryption algorithm
	if(zio_crypt_table[crypt].ci_keylen != wkeydata_len) return EINVAL;
	
	//create the wrapping key now that we have parsed and verified the parameters
	ret = zio_crypt_key_create(crypt, wkeydata, tag, &key);
	if(ret) goto error;

	//remove wkeydata from props since it should not be used again
	bzero(wkeydata, wkeydata_len);
	ret = nvlist_remove_all(props, "wkeydata");
	if(ret) goto error;
	
	*key_out = key;
	return 0;
	
error:
	LOG_ERROR(ret, "");
	if(key) zio_crypt_key_rele(key, tag);

	*key_out = NULL;
	return ret;
}

int zio_do_crypt(boolean_t encrypt, zio_crypt_key_t *key, uint8_t *ivbuf, uint_t ivlen, uint_t maclen, uint8_t *plainbuf, uint8_t *cipherbuf, uint_t datalen){
	int ret;
	uint64_t crypt = key->zk_crypt;
	crypto_data_t plaindata, cipherdata;
	CK_AES_CCM_PARAMS ccmp;
	CK_AES_GCM_PARAMS gcmp;
	crypto_mechanism_t mech;
	zio_crypt_info_t crypt_info;
	uint_t plain_full_len;
	
	LOG_DEBUG("zio_do_crypt() encrypt = %d, crypt = %lu, ivlen = %u, maclen = %u, datalen = %u", encrypt, crypt, ivlen, maclen, datalen);
	
	ASSERT(crypt < ZIO_CRYPT_FUNCTIONS);
	ASSERT(wkey->zk_key->ck_format == CRYPTO_KEY_RAW);

	//lookup the encryption info
	crypt_info = zio_crypt_table[crypt];
	
	//setup encryption mechanism (same as crypt)
	mech.cm_type = crypto_mech2id(crypt_info.ci_mechname);
	
	//plain length will include the MAC if we are decrypting
	if(encrypt) plain_full_len = datalen;
	else plain_full_len = datalen + maclen;
	
	//setup encryption params (currently only AES CCM and AES GCM are supported)
	if(crypt_info.ci_crypt_type == ZIO_CRYPT_TYPE_CCM){
		ccmp.ulNonceSize = ivlen;
		ccmp.ulAuthDataSize = 0;
		ccmp.authData = NULL;
		ccmp.ulMACSize = maclen;
		ccmp.nonce = ivbuf;
		ccmp.ulDataSize = plain_full_len;
		
		mech.cm_param = (char *)(&ccmp);
		mech.cm_param_len = sizeof(CK_AES_CCM_PARAMS);
	}else{
		gcmp.ulIvLen = ivlen;
		gcmp.ulIvBits = BYTES_TO_BITS(ivlen);
		gcmp.ulAADLen = 0;
		gcmp.pAAD = NULL;
		gcmp.ulTagBits = BYTES_TO_BITS(maclen);
		gcmp.pIv = ivbuf;
		
		mech.cm_param = (char *)(&gcmp);
		mech.cm_param_len = sizeof(CK_AES_GCM_PARAMS);
	}
	
	//setup plaindata struct with buffer from keydata
	plaindata.cd_format = CRYPTO_DATA_RAW;
	plaindata.cd_offset = 0;
	plaindata.cd_length = plain_full_len;
	plaindata.cd_miscdata = NULL;
	plaindata.cd_raw.iov_base = (char *)plainbuf;
	plaindata.cd_raw.iov_len = plain_full_len;
	
	//setup cipherdata to be filled 
	cipherdata.cd_format = CRYPTO_DATA_RAW;
	cipherdata.cd_offset = 0;
	cipherdata.cd_length = datalen + maclen;
	cipherdata.cd_miscdata = NULL;
	cipherdata.cd_raw.iov_base = (char *)cipherbuf;
	cipherdata.cd_raw.iov_len = datalen + maclen;
	
	//perform the actual encryption
	if(encrypt)	ret = crypto_encrypt(&mech, &plaindata, &key->zk_key, key->zk_ctx_tmpl, &cipherdata, NULL);
	else ret = crypto_decrypt(&mech, &cipherdata, &key->zk_key, key->zk_ctx_tmpl, &plaindata, NULL);
	
	if(ret != CRYPTO_SUCCESS){
		LOG_ERROR(ret, "");
		ret = EIO;
		goto error;
	}
	
	return 0;
	
error:
	LOG_ERROR(ret, "");
	return ret;
}
