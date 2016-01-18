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

int zio_crypt_key_allocate(zio_crypt_key_t **key_out){
	zio_crypt_key_t *key;

	key = kmem_zalloc(sizeof(zio_crypt_key_t), KM_SLEEP);
	if(!key) return (ENOMEM);
	
	refcount_create(&key->ck_refcnt);
	
	*key_out = key;
	return 0;
}

/* 
 * Returns key populated from props or NULL if key properties don't exist.
 * This function also checks props for validity of all encryption properties.
 */
int zio_crypt_key_from_props(nvlist_t *props, zio_crypt_key_t **key_out){
	int ret;
	boolean_t crypt_exists = B_TRUE, keydata_exists = B_TRUE, keysource_exists = B_TRUE; 
	zio_crypt_key_t *key;
	uint64_t crypt;
	uint8_t *keydata, *keydata_out = NULL;
	char *keysource;
	uint_t keydatalen;
	uint64_t salt;
	
	*key_out = NULL;
	
	/* get relevent properties from the nvlist */
	ret = nvlist_lookup_uint64(props, zfs_prop_to_name(ZFS_PROP_ENCRYPTION), &crypt);
	if(ret) crypt_exists = B_FALSE;
	
	ret = nvlist_lookup_string(props, zfs_prop_to_name(ZFS_PROP_KEYSOURCE), &keysource);
	if(ret) keysource_exists = B_FALSE;
	
	ret = nvlist_lookup_uint8_array(props, "wkeydata", &keydata, &keydatalen);
	if(ret) keydata_exists = B_FALSE;
	
	
	/* No encryption properties is valid, results in NULL key */
	if(!crypt_exists && !keydata_exists && !keysource_exists) return 0;
	
	/* all 3 properties must be present or not */
	if(!(crypt_exists && keydata_exists && keysource_exists)) return EINVAL;
	
	/* keysource should be of format passphrase for salt to exist */
	if(!strncmp(keysource, "passphrase", 10) && nvlist_lookup_uint64(props, zfs_prop_to_name(ZFS_PROP_SALT), &salt) != 0) return EINVAL;
	
	/* properties are valid and exist, create the key */
	ret = zio_crypt_key_allocate(&key);
	if(ret) goto error;
	
	key->ck_key.ck_format = CRYPTO_KEY_RAW;
	key->ck_key.ck_length = keydatalen * 8;
	
	keydata_out = kmem_alloc(keydatalen, KM_SLEEP);
	if(!keydata_out){
		ret = ENOMEM;
		goto error;
	}
	
	bcopy(keydata, keydata_out, keydatalen);
	key->ck_key.ck_data = keydata_out;
	key->ck_crypt = crypt;
	
	/* remove wkeydata from the properties since it should not be used again */
	bzero(keydata, keydatalen);
	ret = nvlist_remove_all(props, "wkeydata");

	*key_out = key;
	return 0;
	
error:
	if(keydata_out) kmem_free(keydata_out, keydatalen); 
	if(key) kmem_free(key, sizeof(zio_crypt_key_t));
	
	*key_out = NULL;
	return ret;
}