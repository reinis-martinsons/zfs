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
 * Copyright 2008 Sun Microsystems, Inc.  All rights reserved.
 * Copyright 2016 Datto, Inc.  All rights reserved.
 * Use is subject to license terms.
 */

#include <libintl.h>
#include <libzfs.h>
#include <sys/zio_crypt.h>

#include "libzfs_impl.h"
#include "zfeature_common.h"

typedef enum key_format {
	KEY_FORMAT_NONE = 0,
	KEY_FORMAT_RAW,
	KEY_FORMAT_HEX,
	KEY_FORMAT_PASSPHRASE
} key_format_t;

typedef enum key_locator {
	KEY_LOCATOR_NONE,
	KEY_LOCATOR_PROMPT,
	KEY_LOCATOR_URI
} key_locator_t;

static int parse_format(key_format_t *format, char *s, int len) {

	if (strncmp("raw", s, len) == 0 && len == 3)
		*format = KEY_FORMAT_RAW;
	else if (strncmp("hex", s, len) == 0 && len == 3)
		*format = KEY_FORMAT_HEX;
	else if (strncmp("passphrase", s, len) == 0 && len == 10)
		*format = KEY_FORMAT_PASSPHRASE;
	else
		return (EINVAL);
	
	return (0);
}

static int parse_locator(key_locator_t *locator, char *s, int len, char **uri) {
	if (len == 6 && strncmp("prompt", s, 6) == 0) {
		*locator = KEY_LOCATOR_PROMPT;
		return (0);
	}

	if (len > 8 && strncmp("file:///", s, 8) == 0) {
		*locator = KEY_LOCATOR_URI;
		*uri = s;
		return (0);
	}

	return (EINVAL);
}

static int keysource_prop_parser(char *keysource, key_format_t *format, key_locator_t *locator, char **uri) {
	int len, ret;
	int keysource_len = strlen(keysource);
	char *s = keysource;

	*format = KEY_FORMAT_NONE;
	*locator = KEY_LOCATOR_NONE;
	
	if (keysource_len > ZPOOL_MAXPROPLEN)
		return (EINVAL);

	for (len = 0; len < keysource_len; len++)
		if (s[len] == ',')
			break;

	/* If we are at the end of the key property, there is a problem */
	if (len == keysource_len)
		return (EINVAL);
	
	ret = parse_format(format, s, len);
	if (ret)
		return (ret);
	
	s = s + len + 1;
	len = keysource_len - len - 1;
	ret = parse_locator(locator, s, len, uri);
	
	return (ret);
}

static int get_key_material(libzfs_handle_t *hdl, key_format_t format, key_locator_t locator, int keylen, uint8_t **key_material_out, size_t *key_material_len){
	int ret;
	int rbytes;
	uint8_t *key_material = NULL;
	
	*key_material_out = NULL;
	*key_material_len = 0;

	switch (locator) {
	case KEY_LOCATOR_PROMPT:
		if (format == KEY_FORMAT_RAW) {
			key_material = zfs_alloc(hdl, keylen);
			if(!key_material)
				return (ENOMEM);
			
			errno = 0;
			rbytes = read(STDIN_FILENO, key_material, keylen);
			if (rbytes != keylen) {
				ret = errno;
				goto error;
			}
			*key_material_len = keylen;

		} else {
			zfs_error_aux(hdl, dgettext(TEXT_DOMAIN, "URI key location not yet supported."));
			return (EOPNOTSUPP);
		}

		break;

	case KEY_LOCATOR_URI:
		zfs_error_aux(hdl, dgettext(TEXT_DOMAIN, "URI key location not yet supported."));
		return (EOPNOTSUPP);
	default:
		zfs_error_aux(hdl, dgettext(TEXT_DOMAIN, "Invalid key locator."));
		return (EINVAL);
	}

	*key_material_out = key_material;
	return (0);

error:
	if(key_material)
		free(key_material);
	
	*key_material_len = 0;
	*key_material_out = NULL;
	return (ret);
}

static int derive_key(libzfs_handle_t *hdl, key_format_t format, int keylen, uint8_t *key_material, size_t key_material_len, uint64_t salt, uint8_t **key_out){
	int ret;
	uint8_t *key;
	
	*key_out = NULL;
	
	key = zfs_alloc(hdl, keylen);
	if (!key)
		return (ENOMEM);
	
	switch(format){
	case KEY_FORMAT_RAW:
		if(keylen != key_material_len){
			zfs_error_aux(hdl, dgettext(TEXT_DOMAIN, "Incorrect key size."));
			ret = EINVAL;
			goto error;
		}
		bcopy(key_material, key, keylen);
		break;
	case KEY_FORMAT_HEX:
	case KEY_FORMAT_PASSPHRASE:
		ret = EOPNOTSUPP;
		goto error;
	default:
		ret = EINVAL;
		goto error;
	}
	
	*key_out = key;
	return (0);
	
error:
	free(key);
	
	*key_out = NULL;
	return (ret);
}

static boolean_t encryption_feature_is_enabled(zpool_handle_t *zph) {
	nvlist_t *features;
	uint64_t feat_refcount;
	
	/* check that features can be enabled */
	if (zpool_get_prop_int(zph, ZPOOL_PROP_VERSION, NULL) < SPA_VERSION_FEATURES)
		return B_FALSE;
	
	/* check for crypto feature */
	features = zpool_get_features(zph);
	if (!features || nvlist_lookup_uint64(features, spa_feature_table[SPA_FEATURE_ENCRYPTION].fi_guid, &feat_refcount) != 0)
		return B_FALSE;
	
	return B_TRUE;
}

int zfs_crypto_create(libzfs_handle_t *hdl, nvlist_t *props, char *parent_name) {	
	char errbuf[1024];
	uint64_t crypt = 0, pcrypt = 0;
	char *keysource = NULL;
	int ret = 0;
	zfs_handle_t *pzhp = NULL;
	boolean_t local_crypt = B_TRUE;
	boolean_t local_keysource = B_TRUE;
	uint64_t salt = 0;
	key_format_t keyformat;
	key_locator_t keylocator;
	uint8_t *key_material = NULL;
	size_t key_material_len = 0;
	uint8_t *key_data = NULL;
	char *uri;
		
	(void) snprintf(errbuf, sizeof (errbuf), dgettext(TEXT_DOMAIN, "Encryption create error"));

	/* lookup crypt from props */
	ret = nvlist_lookup_uint64(props, zfs_prop_to_name(ZFS_PROP_ENCRYPTION), &crypt);
	if (ret != 0) {
		local_crypt = B_FALSE;
	}

	/* lookup keysource from props */
	ret = nvlist_lookup_string(props, zfs_prop_to_name(ZFS_PROP_KEYSOURCE), &keysource);
	if (ret != 0) {
		local_keysource = B_FALSE;
	}

	/* get a reference to parent dataset, should never be null */
	pzhp = make_dataset_handle(hdl, parent_name);
	if (pzhp == NULL) {
		zfs_error_aux(hdl, dgettext(TEXT_DOMAIN, "Failed to obtain parent to check for encryption feature."));
		return (ENOENT);
	}
	
	/* Lookup parent's crypt */
	pcrypt = zfs_prop_get_int(pzhp, ZFS_PROP_ENCRYPTION);

	/* Check for encryption feature */
	if (!encryption_feature_is_enabled(pzhp->zpool_hdl)) {
		if (!local_crypt && !local_keysource)
			return (0);

		zfs_error_aux(hdl, gettext("Encryption feature not enabled."));
		return (EINVAL);
	}
	
	/* Check for encryption being explicitly truned off */
	if (crypt == ZIO_CRYPT_OFF && pcrypt != ZIO_CRYPT_OFF) {
		zfs_error_aux(hdl, dgettext(TEXT_DOMAIN, "Invalid encryption value. Dataset must be encrypted."));
		return (EINVAL);
	}
	
	/* Inherit the encryption property if we don't have it locally */
	if (!local_crypt)
		crypt = pcrypt;
	
	/* At this point crypt should be the actual encryption value. Return if encryption is off */
	if (crypt == ZIO_CRYPT_OFF){
		if (local_keysource){
			zfs_error_aux(hdl, gettext("Encryption required to set keysource."));
			return (EINVAL);
		}
		
		return (0);
	}	
	
	/* Inherit the keysource property if we don't have it locally */
	if (!local_keysource) {
		keysource = zfs_alloc(hdl, ZPOOL_MAXPROPLEN);
		if (keysource == NULL) {
			(void) no_memory(hdl);
			return (ENOMEM);
		}

		if (zfs_prop_get(pzhp, ZFS_PROP_KEYSOURCE, keysource, ZPOOL_MAXPROPLEN, NULL, NULL, 0, FALSE) != 0) {
			zfs_error_aux(hdl, dgettext(TEXT_DOMAIN, "No keysource property available from parent."));
			ret = ENOENT;
			goto error;
		}
	}
	
	/* Parse the keysource */
	ret = keysource_prop_parser(keysource, &keyformat, &keylocator, &uri);
	if (ret) {
		zfs_error_aux(hdl, dgettext(TEXT_DOMAIN, "Invalid keysource."));
		goto error;
	}

	/* If a local keysource or crypt is provided, this dataset will have a new keychain. Otherwise use the parent's. */
	if (local_crypt || local_keysource) {
		
		/* get key material from keysource */
		ret = get_key_material(hdl, keyformat, keylocator, zio_crypt_table[crypt].ci_keylen, &key_material, &key_material_len);
		if (ret)
			goto error;
		
		/* passphrase formats require a salt property */
		if (keyformat == KEY_FORMAT_PASSPHRASE) {
			ret = random_get_bytes((uint8_t *)&salt, sizeof(uint64_t));
			if (ret) {
				zfs_error_aux(hdl, dgettext(TEXT_DOMAIN, "Failed to generate salt."));
				goto error;
			}
			
			ret = nvlist_add_uint64(props, zfs_prop_to_name(ZFS_PROP_SALT), salt);
			if (ret) {
				zfs_error_aux(hdl, dgettext(TEXT_DOMAIN, "Failed to add salt to properties."));
				goto error;
			}
		}
		
		/* derive a key from the key material */
		ret = derive_key(hdl, keyformat, zio_crypt_table[crypt].ci_keylen, key_material, key_material_len, salt, &key_data);
		if (ret)
			goto error;
		
		/* add the derived key to the properties array */
		ret = nvlist_add_uint8_array(props, "wkeydata", key_data, zio_crypt_table[crypt].ci_keylen);
		if (ret)
			goto error;
	}
	
	free(key_material);
	free(key_data);
	
	if (!local_keysource)
		free(keysource);
	
	return (0);
	
error:
	if (key_material)
		free(key_material);
	if (key_data)
		free(key_data);
	if (!local_keysource)
		free(keysource);
	
	return (ret);
}

int zfs_crypto_load_key(zfs_handle_t *zhp) {
	int ret;
	uint64_t crypt, salt = 0;
	char keysource[MAXNAMELEN];
	key_format_t format;
	key_locator_t locator;
	char *uri;
	uint8_t *key_material, *key_data;
	size_t key_material_len;
	nvlist_t *nvl = NULL;
	
	if (!encryption_feature_is_enabled(zhp->zpool_hdl)) {
		zfs_error_aux(zhp->zfs_hdl, gettext("Encryption feature not enabled."));
		return (EINVAL);
	}
	
	/* fetch relevent info from the dataset properties */
	crypt = zfs_prop_get_int(zhp, ZFS_PROP_ENCRYPTION);
	if (crypt == ZIO_CRYPT_OFF) {
		zfs_error_aux(zhp->zfs_hdl, dgettext(TEXT_DOMAIN, "Encryption not enabled for this dataset."));
		return (EINVAL);
	}

	ret = zfs_prop_get(zhp, ZFS_PROP_KEYSOURCE, keysource, sizeof (keysource), NULL, NULL, 0, B_TRUE);
	if (ret) {
		zfs_error_aux(zhp->zfs_hdl, dgettext(TEXT_DOMAIN, "Failed to obtain keysource property."));
		return (EIO);
	}
	
	/* parse the keysource */
	ret = keysource_prop_parser(keysource, &format, &locator, &uri);
	if (ret) {
		zfs_error_aux(zhp->zfs_hdl, dgettext(TEXT_DOMAIN, "Invalid keysource property."));
		return (EIO);
	}
	
	/* get key material from keysource */
	ret = get_key_material(zhp->zfs_hdl, format, locator, zio_crypt_table[crypt].ci_keylen, &key_material, &key_material_len);
	if (ret)
		goto error;
	
	/* passphrase formats require a salt property */
	if (format == KEY_FORMAT_PASSPHRASE)
		salt = zfs_prop_get_int(zhp, ZFS_PROP_SALT);
	
	/* derive a key from the key material */
	ret = derive_key(zhp->zfs_hdl, format, zio_crypt_table[crypt].ci_keylen, key_material, key_material_len, salt, &key_data);
	if (ret)
		goto error;
	
	/* put the key in an nvlist and pass to the ioctl */
	nvl = fnvlist_alloc();
	
	ret = nvlist_add_uint8_array(nvl, "wkeydata", key_data, zio_crypt_table[crypt].ci_keylen);
	if (ret)
		goto error;
	
	ret = lzc_crypto(zhp->zfs_name, ZFS_IOC_CRYPTO_LOAD_KEY, nvl);
	
	nvlist_free(nvl);
	free(key_material);
	free(key_data);
	
	return ret;

error:
	if (key_material)
		free(key_material);
	if (key_data)
		free(key_data);
	if (nvl)
		nvlist_free(nvl);
	
	return (ret);
}

int zfs_crypto_unload_key(zfs_handle_t *zhp) {
	uint64_t crypt;
	
	if (!encryption_feature_is_enabled(zhp->zpool_hdl)) {
		zfs_error_aux(zhp->zfs_hdl, gettext("Encryption feature not enabled."));
		return (EINVAL);
	}
	
	/* fetch relevent info from the dataset properties */
	crypt = zfs_prop_get_int(zhp, ZFS_PROP_ENCRYPTION);
	if (crypt == ZIO_CRYPT_OFF) {
		zfs_error_aux(zhp->zfs_hdl, dgettext(TEXT_DOMAIN, "Encryption not enabled."));
		return (EINVAL);
	}
	
	/* call the ioctl */
	return (lzc_crypto(zhp->zfs_name, ZFS_IOC_CRYPTO_UNLOAD_KEY, NULL));
}