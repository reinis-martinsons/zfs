/*
 * CDDL HEADER START
 *
 * This file and its contents are supplied under the terms of the
 * Common Development and Distribution License ("CDDL"), version 1.0.
 * You may only use this file in accordance with the terms of version
 * 1.0 of the CDDL.
 *
 * A full copy of the text of the CDDL should have accompanied this
 * source.  A copy of the CDDL is also available via the Internet at
 * http://www.illumos.org/license/CDDL.
 *
 * CDDL HEADER END
 */

/*
 * Copyright (c) 2017, Datto, Inc. All rights reserved.
 */

#include <sys/dsl_crypt.h>
#include <sys/dsl_pool.h>
#include <sys/zap.h>
#include <sys/zil.h>
#include <sys/dsl_dir.h>
#include <sys/dsl_prop.h>
#include <sys/spa_impl.h>
#include <sys/zvol.h>

/*
 * This file's primary purpose is for managing master encryption keys in
 * memory and on disk. For more info on how these keys are used, see the
 * block comment in zio_crypt.c.
 *
 * All master keys are stored encrypted on disk in the form of the DSL
 * Crypto Key ZAP object. The binary key data in this object is always
 * randomly generated and is encrypted with the user's secret key. This
 * layer of indirection allows the user to change their key without
 * needing to re-encrypt the entire dataset. The ZAP also holds on to the
 * (non-encrypted) encryption algorithm identifier, IV, and MAC needed to
 * safely decrypt the master key. For more info on the user's key see the
 * block comment in libzfs_crypto.c
 *
 * In memory encryption keys are managed through the spa_keystore. The
 * keystore consists of 3 AVL trees, which are as follows:
 *
 * The Wrapping Key Tree:
 * The wrapping key (wkey) tree stores the user's keys that are fed into the
 * kernel through 'zfs load-key' and related commands. Datasets inherit their
 * parent's wkey, so they are refcounted. The wrapping keys remain in memory
 * until they are explicitly unloaded (with "zfs unload-key"). Unloading is
 * only possible when no datasets are using them (refcount=0).
 *
 * The DSL Crypto Key Tree:
 * The DSL Crypto Keys are the in-memory representation of decrypted master
 * keys. They are used by the functions in zio_crypt.c to perform encryption
 * and decryption. The decrypted master key bit patterns are shared between
 * all datasets within a "clone family", but each clone may use a different
 * wrapping key. As a result, we maintain one of these structs for each clone
 * to allow us to manage the loading and unloading of each separately.
 * Snapshots of a given dataset, however, will share a DSL Crypto Key, so they
 * are also refcounted. Once the refcount on a key hits zero, it is immediately
 * zeroed out and freed.
 *
 * The Crypto Key Mapping Tree:
 * The zio layer needs to lookup master keys by their dataset object id. Since
 * the DSL Crypto Keys can belong to multiple datasets, we maintain a tree of
 * dsl_key_mapping_t's which essentially just map the dataset object id to its
 * appropriate DSL Crypto Key. The management for creating and destroying these
 * mappings hooks into the code for owning and disowning datasets. Usually,
 * there will only be one active dataset owner, but there are times
 * (particularly during dataset creation and destruction) when this may not be
 * true or the dataset may not be initialized enough to own. As a result, this
 * object is also refcounted.
 */

void
dsl_wrapping_key_hold(dsl_wrapping_key_t *wkey, void *tag)
{
	(void) refcount_add(&wkey->wk_refcnt, tag);
}

void
dsl_wrapping_key_rele(dsl_wrapping_key_t *wkey, void *tag)
{
	(void) refcount_remove(&wkey->wk_refcnt, tag);
}

void
dsl_wrapping_key_free(dsl_wrapping_key_t *wkey)
{
	ASSERT0(refcount_count(&wkey->wk_refcnt));

	if (wkey->wk_key.ck_data) {
		bzero(wkey->wk_key.ck_data,
		    BITS_TO_BYTES(wkey->wk_key.ck_length));
		kmem_free(wkey->wk_key.ck_data,
		    BITS_TO_BYTES(wkey->wk_key.ck_length));
	}

	refcount_destroy(&wkey->wk_refcnt);
	kmem_free(wkey, sizeof (dsl_wrapping_key_t));
}

int
dsl_wrapping_key_create(uint8_t *wkeydata, dsl_wrapping_key_t **wkey_out)
{
	int ret;
	dsl_wrapping_key_t *wkey;

	/* allocate the wrapping key */
	wkey = kmem_alloc(sizeof (dsl_wrapping_key_t), KM_SLEEP);
	if (!wkey)
		return (SET_ERROR(ENOMEM));

	/* allocate and initialize the underlying crypto key */
	wkey->wk_key.ck_data = kmem_alloc(WRAPPING_KEY_LEN, KM_SLEEP);
	if (!wkey->wk_key.ck_data) {
		ret = ENOMEM;
		goto error;
	}

	wkey->wk_key.ck_format = CRYPTO_KEY_RAW;
	wkey->wk_key.ck_length = BYTES_TO_BITS(WRAPPING_KEY_LEN);

	/* copy the data */
	bcopy(wkeydata, wkey->wk_key.ck_data, WRAPPING_KEY_LEN);

	/* initialize the refcount */
	refcount_create(&wkey->wk_refcnt);

	*wkey_out = wkey;
	return (0);

error:
	dsl_wrapping_key_free(wkey);

	*wkey_out = NULL;
	return (ret);
}

int
dsl_crypto_params_create_nvlist(nvlist_t *props, nvlist_t *crypto_args,
    dsl_crypto_params_t **dcp_out)
{
	int ret;
	boolean_t do_inherit = B_TRUE;
	uint64_t crypt = ZIO_CRYPT_INHERIT;
	uint64_t keyformat = ZFS_KEYFORMAT_NONE;
	dsl_crypto_params_t *dcp = NULL;
	dsl_wrapping_key_t *wkey = NULL;
	uint8_t *wkeydata = NULL;
	uint_t wkeydata_len = 0;
	char *keylocation = NULL;

	dcp = kmem_zalloc(sizeof (dsl_crypto_params_t), KM_SLEEP);
	if (!dcp) {
		ret = SET_ERROR(ENOMEM);
		goto error;
	}

	/* get relevant properties from the nvlist */
	if (props != NULL) {
		ret = nvlist_lookup_uint64(props,
		    zfs_prop_to_name(ZFS_PROP_ENCRYPTION), &crypt);
		if (ret == 0)
			do_inherit = B_FALSE;

		ret = nvlist_lookup_uint64(props,
		    zfs_prop_to_name(ZFS_PROP_KEYFORMAT), &keyformat);
		if (ret == 0)
			do_inherit = B_FALSE;

		ret = nvlist_lookup_string(props,
		    zfs_prop_to_name(ZFS_PROP_KEYLOCATION), &keylocation);
		if (ret == 0)
			do_inherit = B_FALSE;

		ret = nvlist_lookup_uint64(props,
		    zfs_prop_to_name(ZFS_PROP_PBKDF2_SALT), &dcp->cp_salt);
		if (ret == 0)
			do_inherit = B_FALSE;

		ret = nvlist_lookup_uint64(props,
		    zfs_prop_to_name(ZFS_PROP_PBKDF2_ITERS), &dcp->cp_iters);
		if (ret == 0)
			do_inherit = B_FALSE;
	}

	if (crypto_args != NULL) {
		ret = nvlist_lookup_uint8_array(crypto_args, "wkeydata",
		    &wkeydata, &wkeydata_len);
		if (ret == 0)
			do_inherit = B_FALSE;
	}

	/* no parameters are valid; results in inherited crypto settings */
	if (do_inherit) {
		kmem_free(dcp, sizeof (dsl_crypto_params_t));
		*dcp_out = NULL;
		return (0);
	}

	/* check for valid crypt */
	if (crypt >= ZIO_CRYPT_FUNCTIONS) {
		ret = SET_ERROR(EINVAL);
		goto error;
	} else {
		dcp->cp_crypt = crypt;
	}

	/* check for valid keyformat */
	if (keyformat >= ZFS_KEYFORMAT_FORMATS) {
		ret = SET_ERROR(EINVAL);
		goto error;
	} else {
		dcp->cp_keyformat = keyformat;
	}

	/* check for a valid keylocation (of any kind) and copy it in */
	if (keylocation != NULL) {
		if (!zfs_prop_valid_keylocation(keylocation, B_FALSE)) {
			ret = SET_ERROR(EINVAL);
			goto error;
		}

		dcp->cp_keylocation = spa_strdup(keylocation);
	}

	/* check wrapping key length, if given */
	if (wkeydata != NULL && wkeydata_len != WRAPPING_KEY_LEN) {
		ret = SET_ERROR(EINVAL);
		goto error;
	}

	/* specifying a keyformat requires keydata */
	if (keyformat != ZFS_KEYFORMAT_NONE && wkeydata == NULL) {
		ret = SET_ERROR(EINVAL);
		goto error;
	}

	/* if the user asked for the deault crypt, determine that now */
	if (dcp->cp_crypt == ZIO_CRYPT_ON)
		dcp->cp_crypt = ZIO_CRYPT_ON_VALUE;

	/* create the wrapping key from the raw data */
	if (wkeydata != NULL) {
		/* create the wrapping key with the verified parameters */
		ret = dsl_wrapping_key_create(wkeydata, &wkey);
		if (ret != 0)
			goto error;

		dcp->cp_wkey = wkey;
	}

	/*
	 * Remove the encryption property from the nvlist since it is not
	 * maintained through the DSL.
	 */
	(void) nvlist_remove_all(props, zfs_prop_to_name(ZFS_PROP_ENCRYPTION));

	*dcp_out = dcp;

	return (0);

error:
	if (wkey != NULL)
		dsl_wrapping_key_free(wkey);
	if (dcp != NULL)
		kmem_free(dcp, sizeof (dsl_crypto_params_t));

	*dcp_out = NULL;
	return (ret);
}

void
dsl_crypto_params_free(dsl_crypto_params_t *dcp, boolean_t unload)
{
	if (dcp == NULL)
		return;

	if (dcp->cp_keylocation != NULL)
		spa_strfree(dcp->cp_keylocation);
	if (unload && dcp->cp_wkey != NULL)
		dsl_wrapping_key_free(dcp->cp_wkey);

	kmem_free(dcp, sizeof (dsl_crypto_params_t));
}

static int
spa_crypto_key_compare(const void *a, const void *b)
{
	const dsl_crypto_key_t *dcka = a;
	const dsl_crypto_key_t *dckb = b;

	if (dcka->dck_obj < dckb->dck_obj)
		return (-1);
	if (dcka->dck_obj > dckb->dck_obj)
		return (1);
	return (0);
}

static int
spa_key_mapping_compare(const void *a, const void *b)
{
	const dsl_key_mapping_t *kma = a;
	const dsl_key_mapping_t *kmb = b;

	if (kma->km_dsobj < kmb->km_dsobj)
		return (-1);
	if (kma->km_dsobj > kmb->km_dsobj)
		return (1);
	return (0);
}

static int
spa_wkey_compare(const void *a, const void *b)
{
	const dsl_wrapping_key_t *wka = a;
	const dsl_wrapping_key_t *wkb = b;

	if (wka->wk_ddobj < wkb->wk_ddobj)
		return (-1);
	if (wka->wk_ddobj > wkb->wk_ddobj)
		return (1);
	return (0);
}

void
spa_keystore_init(spa_keystore_t *sk)
{
	rw_init(&sk->sk_dk_lock, NULL, RW_DEFAULT, NULL);
	rw_init(&sk->sk_km_lock, NULL, RW_DEFAULT, NULL);
	rw_init(&sk->sk_wkeys_lock, NULL, RW_DEFAULT, NULL);
	avl_create(&sk->sk_dsl_keys, spa_crypto_key_compare,
	    sizeof (dsl_crypto_key_t),
	    offsetof(dsl_crypto_key_t, dck_avl_link));
	avl_create(&sk->sk_key_mappings, spa_key_mapping_compare,
	    sizeof (dsl_key_mapping_t),
	    offsetof(dsl_key_mapping_t, km_avl_link));
	avl_create(&sk->sk_wkeys, spa_wkey_compare, sizeof (dsl_wrapping_key_t),
	    offsetof(dsl_wrapping_key_t, wk_avl_link));
}

void
spa_keystore_fini(spa_keystore_t *sk)
{
	dsl_wrapping_key_t *wkey;
	void *cookie = NULL;

	ASSERT(avl_is_empty(&sk->sk_dsl_keys));
	ASSERT(avl_is_empty(&sk->sk_key_mappings));

	while ((wkey = avl_destroy_nodes(&sk->sk_wkeys, &cookie)) != NULL)
		dsl_wrapping_key_free(wkey);

	avl_destroy(&sk->sk_wkeys);
	avl_destroy(&sk->sk_key_mappings);
	avl_destroy(&sk->sk_dsl_keys);
	rw_destroy(&sk->sk_wkeys_lock);
	rw_destroy(&sk->sk_km_lock);
	rw_destroy(&sk->sk_dk_lock);
}

static int
dsl_dir_hold_keylocation_source_dd(dsl_dir_t *dd, void *tag,
    dsl_dir_t **inherit_dd_out)
{
	int ret;
	dsl_dir_t *inherit_dd = NULL;
	char keylocation[MAXNAMELEN];
	char setpoint[MAXNAMELEN];

	/*
	 * Lookup dd's keylocation property and find out where it was
	 * inherited from. dsl_prop_get_dd() might not find anything and
	 * return the default value. We detect this by checking if setpoint
	 * is an empty string and return ENOENT.
	 */
	ret = dsl_prop_get_dd(dd, zfs_prop_to_name(ZFS_PROP_KEYLOCATION),
	    1, sizeof (keylocation), keylocation, setpoint, B_FALSE);
	if (ret != 0) {
		goto error;
	} else if (setpoint[0] == '\0') {
		ret = ENOENT;
		goto error;
	}

	/* hold the dsl dir that we inherited the property from */
	ret = dsl_dir_hold(dd->dd_pool, setpoint, tag, &inherit_dd, NULL);
	if (ret != 0)
		goto error;

	*inherit_dd_out = inherit_dd;
	return (0);

error:

	*inherit_dd_out = NULL;
	return (ret);
}

static int
spa_keystore_wkey_hold_ddobj_impl(spa_t *spa, uint64_t ddobj,
    void *tag, dsl_wrapping_key_t **wkey_out)
{
	int ret;
	dsl_wrapping_key_t search_wkey;
	dsl_wrapping_key_t *found_wkey;

	ASSERT(RW_LOCK_HELD(&spa->spa_keystore.sk_wkeys_lock));

	/* init the search wrapping key */
	search_wkey.wk_ddobj = ddobj;

	/* lookup the wrapping key */
	found_wkey = avl_find(&spa->spa_keystore.sk_wkeys, &search_wkey, NULL);
	if (!found_wkey) {
		ret = SET_ERROR(ENOENT);
		goto error;
	}

	/* increment the refcount */
	dsl_wrapping_key_hold(found_wkey, tag);

	*wkey_out = found_wkey;
	return (0);

error:
	*wkey_out = NULL;
	return (ret);
}

static int
spa_keystore_wkey_hold_ddobj(spa_t *spa, uint64_t ddobj, void *tag,
    dsl_wrapping_key_t **wkey_out)
{
	int ret;
	dsl_pool_t *dp = spa_get_dsl(spa);
	dsl_dir_t *dd = NULL, *inherit_dd = NULL;
	dsl_wrapping_key_t *wkey;
	boolean_t locked = B_FALSE;

	if (!RW_WRITE_HELD(&spa->spa_keystore.sk_wkeys_lock)) {
		rw_enter(&spa->spa_keystore.sk_wkeys_lock, RW_READER);
		locked = B_TRUE;
	}

	/*
	 * There is a special case for zfs_create_fs() where the wrapping key
	 * is needed before the filesystem's properties are set. This is
	 * problematic because dsl_dir_hold_keylocation_source_dd() uses the
	 * properties to determine where the wrapping key is inherited from.
	 * As a result, here we try to find a wrapping key for this dd before
	 * checking for wrapping key inheritance.
	 */
	ret = spa_keystore_wkey_hold_ddobj_impl(spa, ddobj, tag, &wkey);
	if (ret == 0) {
		if (locked)
			rw_exit(&spa->spa_keystore.sk_wkeys_lock);

		*wkey_out = wkey;
		return (0);
	}

	/* hold the dsl dir */
	ret = dsl_dir_hold_obj(dp, ddobj, NULL, FTAG, &dd);
	if (ret != 0)
		goto error;

	/* get the dd that the keylocation property was inherited from */
	ret = dsl_dir_hold_keylocation_source_dd(dd, FTAG, &inherit_dd);
	if (ret != 0)
		goto error;

	/* lookup the wkey in the avl tree */
	ret = spa_keystore_wkey_hold_ddobj_impl(spa, inherit_dd->dd_object,
	    tag, &wkey);
	if (ret != 0)
		goto error;

	/* unlock the wkey tree if we locked it */
	if (locked)
		rw_exit(&spa->spa_keystore.sk_wkeys_lock);

	dsl_dir_rele(inherit_dd, FTAG);
	dsl_dir_rele(dd, FTAG);

	*wkey_out = wkey;
	return (0);

error:
	if (locked)
		rw_exit(&spa->spa_keystore.sk_wkeys_lock);
	if (inherit_dd != NULL)
		dsl_dir_rele(inherit_dd, FTAG);
	if (dd != NULL)
		dsl_dir_rele(dd, FTAG);

	*wkey_out = NULL;
	return (ret);
}

int
dsl_crypto_can_set_keylocation(const char *dsname, zprop_source_t source,
    const char *keylocation)
{
	int ret = 0;
	dsl_dir_t *dd = NULL;
	dsl_dir_t *inherit_dd = NULL;
	dsl_pool_t *dp = NULL;
	dsl_wrapping_key_t *wkey = NULL;

	/* hold the dsl dir */
	ret = dsl_pool_hold(dsname, FTAG, &dp);
	if (ret != 0)
		goto out;

	ret = dsl_dir_hold(dp, dsname, FTAG, &dd, NULL);
	if (ret != 0)
		goto out;

	/* if dd is not encrypted, the value may only be "none" */
	if (dd->dd_crypto_obj == 0) {
		if (strcmp(keylocation, "none") != 0) {
			ret = SET_ERROR(EACCES);
			goto out;
		}

		ret = 0;
		goto out;
	}

	/* check for a valid keylocation for encrypted datasets */
	if (!zfs_prop_valid_keylocation(keylocation, B_TRUE)) {
		ret = SET_ERROR(EINVAL);
		goto out;
	}

	/* If this is a received keylocation we don't need do anything else */
	if ((source & ZPROP_SRC_RECEIVED) != 0) {
		ret = 0;
		goto out;
	}

	/*
	 * Now we want to check that this dataset is an encryption root since
	 * keylocation may only be set on encryption roots. Normally this is
	 * trivial, using dsl_dir_hold_keylocation_source_dd(), but this
	 * function also gets called during dataset creation when the
	 * properties have not been setup yet. Fortunately, the wrapping key
	 * will always be loaded at creation time, so we can check for this
	 * first.
	 */
	rw_enter(&dp->dp_spa->spa_keystore.sk_wkeys_lock, RW_READER);
	ret = spa_keystore_wkey_hold_ddobj_impl(dp->dp_spa, dd->dd_object,
	    FTAG, &wkey);
	rw_exit(&dp->dp_spa->spa_keystore.sk_wkeys_lock);
	if (ret != 0) {
		ret = dsl_dir_hold_keylocation_source_dd(dd, FTAG, &inherit_dd);
		if (ret != 0)
			goto out;

		if (inherit_dd->dd_object != dd->dd_object) {
			ret = SET_ERROR(EACCES);
			goto out;
		}
	}

	if (wkey != NULL)
		dsl_wrapping_key_rele(wkey, FTAG);
	if (inherit_dd != NULL)
		dsl_dir_rele(inherit_dd, FTAG);
	dsl_dir_rele(dd, FTAG);
	dsl_pool_rele(dp, FTAG);

	return (0);

out:
	if (wkey != NULL)
		dsl_wrapping_key_rele(wkey, FTAG);
	if (inherit_dd != NULL)
		dsl_dir_rele(inherit_dd, FTAG);
	if (dd != NULL)
		dsl_dir_rele(dd, FTAG);
	if (dp != NULL)
		dsl_pool_rele(dp, FTAG);

	return (ret);
}

static void
dsl_crypto_key_free(dsl_crypto_key_t *dck)
{
	ASSERT(refcount_count(&dck->dck_refcnt) == 0);

	/* destroy the zio_crypt_key_t */
	zio_crypt_key_destroy(&dck->dck_key);

	/* free the refcount, wrapping key, and lock */
	refcount_destroy(&dck->dck_refcnt);
	if (dck->dck_wkey)
		dsl_wrapping_key_rele(dck->dck_wkey, dck);

	/* free the key */
	kmem_free(dck, sizeof (dsl_crypto_key_t));
}

static void
dsl_crypto_key_rele(dsl_crypto_key_t *dck, void *tag)
{
	if (refcount_remove(&dck->dck_refcnt, tag) == 0)
		dsl_crypto_key_free(dck);
}

static int
dsl_crypto_key_open(objset_t *mos, dsl_wrapping_key_t *wkey,
    uint64_t dckobj, void *tag, dsl_crypto_key_t **dck_out)
{
	int ret;
	uint64_t crypt = 0;
	uint8_t raw_keydata[MAX_MASTER_KEY_LEN];
	uint8_t raw_hmac_keydata[HMAC_SHA256_KEYLEN];
	uint8_t iv[WRAPPING_IV_LEN];
	uint8_t mac[WRAPPING_MAC_LEN];
	dsl_crypto_key_t *dck;

	/* allocate and initialize the key */
	dck = kmem_zalloc(sizeof (dsl_crypto_key_t), KM_SLEEP);
	if (!dck)
		return (SET_ERROR(ENOMEM));

	/* fetch all of the values we need from the ZAP */
	ret = zap_lookup(mos, dckobj, DSL_CRYPTO_KEY_CRYPTO_SUITE, 8, 1,
	    &crypt);
	if (ret != 0)
		goto error;

	ret = zap_lookup(mos, dckobj, DSL_CRYPTO_KEY_MASTER_KEY, 1,
	    MAX_MASTER_KEY_LEN, raw_keydata);
	if (ret != 0)
		goto error;

	ret = zap_lookup(mos, dckobj, DSL_CRYPTO_KEY_HMAC_KEY, 1,
	    HMAC_SHA256_KEYLEN, raw_hmac_keydata);
	if (ret != 0)
		goto error;

	ret = zap_lookup(mos, dckobj, DSL_CRYPTO_KEY_IV, 1, WRAPPING_IV_LEN,
	    iv);
	if (ret != 0)
		goto error;

	ret = zap_lookup(mos, dckobj, DSL_CRYPTO_KEY_MAC, 1, WRAPPING_MAC_LEN,
	    mac);
	if (ret != 0)
		goto error;

	/*
	 * Unwrap the keys. If there is an error return EACCES to indicate
	 * an authentication failure.
	 */
	ret = zio_crypt_key_unwrap(&wkey->wk_key, crypt, raw_keydata,
	    raw_hmac_keydata, iv, mac, &dck->dck_key);
	if (ret != 0) {
		ret = SET_ERROR(EACCES);
		goto error;
	}

	/* finish initializing the dsl_crypto_key_t */
	refcount_create(&dck->dck_refcnt);
	dsl_wrapping_key_hold(wkey, dck);
	dck->dck_wkey = wkey;
	dck->dck_obj = dckobj;
	refcount_add(&dck->dck_refcnt, tag);

	*dck_out = dck;
	return (0);

error:
	if (dck != NULL) {
		bzero(dck, sizeof (dsl_crypto_key_t));
		kmem_free(dck, sizeof (dsl_crypto_key_t));
	}

	*dck_out = NULL;
	return (ret);
}

static int
spa_keystore_dsl_key_hold_impl(spa_t *spa, uint64_t dckobj, void *tag,
    dsl_crypto_key_t **dck_out)
{
	int ret;
	dsl_crypto_key_t search_dck;
	dsl_crypto_key_t *found_dck;

	ASSERT(RW_LOCK_HELD(&spa->spa_keystore.sk_dk_lock));

	/* init the search key */
	search_dck.dck_obj = dckobj;

	/* find the matching key in the keystore */
	found_dck = avl_find(&spa->spa_keystore.sk_dsl_keys, &search_dck, NULL);
	if (!found_dck) {
		ret = SET_ERROR(ENOENT);
		goto error;
	}

	/* increment the refcount */
	refcount_add(&found_dck->dck_refcnt, tag);

	*dck_out = found_dck;
	return (0);

error:
	*dck_out = NULL;
	return (ret);
}

static int
spa_keystore_dsl_key_hold_dd(spa_t *spa, dsl_dir_t *dd, void *tag,
    dsl_crypto_key_t **dck_out)
{
	int ret;
	avl_index_t where;
	dsl_crypto_key_t *dck = NULL;
	dsl_wrapping_key_t *wkey = NULL;
	uint64_t dckobj = dd->dd_crypto_obj;

	rw_enter(&spa->spa_keystore.sk_dk_lock, RW_WRITER);

	/* lookup the key in the tree of currently loaded keys */
	ret = spa_keystore_dsl_key_hold_impl(spa, dckobj, tag, &dck);
	if (!ret) {
		rw_exit(&spa->spa_keystore.sk_dk_lock);
		*dck_out = dck;
		return (0);
	}

	/* lookup the wrapping key from the keystore */
	ret = spa_keystore_wkey_hold_ddobj(spa, dd->dd_object, FTAG, &wkey);
	if (ret != 0) {
		ret = SET_ERROR(EACCES);
		goto error_unlock;
	}

	/* read the key from disk */
	ret = dsl_crypto_key_open(spa->spa_meta_objset, wkey, dckobj,
	    tag, &dck);
	if (ret != 0)
		goto error_unlock;

	/*
	 * add the key to the keystore (this should always succeed
	 * since we made sure it didn't exist before)
	 */
	avl_find(&spa->spa_keystore.sk_dsl_keys, dck, &where);
	avl_insert(&spa->spa_keystore.sk_dsl_keys, dck, where);

	/* release the wrapping key (the dsl key now has a reference to it) */
	dsl_wrapping_key_rele(wkey, FTAG);

	rw_exit(&spa->spa_keystore.sk_dk_lock);

	*dck_out = dck;
	return (0);

error_unlock:
	rw_exit(&spa->spa_keystore.sk_dk_lock);
	if (wkey != NULL)
		dsl_wrapping_key_rele(wkey, FTAG);

	*dck_out = NULL;
	return (ret);
}

void
spa_keystore_dsl_key_rele(spa_t *spa, dsl_crypto_key_t *dck, void *tag)
{
	rw_enter(&spa->spa_keystore.sk_dk_lock, RW_WRITER);

	if (refcount_remove(&dck->dck_refcnt, tag) == 0) {
		avl_remove(&spa->spa_keystore.sk_dsl_keys, dck);
		dsl_crypto_key_free(dck);
	}

	rw_exit(&spa->spa_keystore.sk_dk_lock);
}

int
spa_keystore_load_wkey_impl(spa_t *spa, dsl_wrapping_key_t *wkey)
{
	int ret;
	avl_index_t where;
	dsl_wrapping_key_t *found_wkey;

	rw_enter(&spa->spa_keystore.sk_wkeys_lock, RW_WRITER);

	/* insert the wrapping key into the keystore */
	found_wkey = avl_find(&spa->spa_keystore.sk_wkeys, wkey, &where);
	if (found_wkey != NULL) {
		ret = SET_ERROR(EEXIST);
		goto error_unlock;
	}
	avl_insert(&spa->spa_keystore.sk_wkeys, wkey, where);

	rw_exit(&spa->spa_keystore.sk_wkeys_lock);

	return (0);

error_unlock:
	rw_exit(&spa->spa_keystore.sk_wkeys_lock);
	return (ret);
}

int
spa_keystore_load_wkey(const char *dsname, dsl_crypto_params_t *dcp,
    boolean_t noop)
{
	int ret;
	dsl_dir_t *dd = NULL;
	dsl_crypto_key_t *dck = NULL;
	dsl_wrapping_key_t *wkey = dcp->cp_wkey;
	dsl_pool_t *dp = NULL;

	if (dcp == NULL || dcp->cp_wkey == NULL)
		return (SET_ERROR(EINVAL));
	if (dcp->cp_crypt != ZIO_CRYPT_INHERIT || dcp->cp_keylocation != NULL ||
	    dcp->cp_salt != 0 || dcp->cp_iters != 0)
		return (SET_ERROR(EINVAL));

	ret = dsl_pool_hold(dsname, FTAG, &dp);
	if (ret != 0)
		goto error;

	if (!spa_feature_is_enabled(dp->dp_spa, SPA_FEATURE_ENCRYPTION)) {
		ret = (SET_ERROR(ENOTSUP));
		goto error;
	}

	/* hold the dsl dir */
	ret = dsl_dir_hold(dp, dsname, FTAG, &dd, NULL);
	if (ret != 0)
		goto error;

	/* initialize the wkey's ddobj */
	wkey->wk_ddobj = dd->dd_object;

	/* verify that the wkey is correct by opening its dsl key */
	ret = dsl_crypto_key_open(dp->dp_meta_objset, wkey,
	    dd->dd_crypto_obj, FTAG, &dck);
	if (ret != 0)
		goto error;

	/*
	 * At this point we have verified the key. We can simply cleanup and
	 * return if this is all the user wanted to do.
	 */
	if (noop)
		goto error;

	/* insert the wrapping key into the keystore */
	ret = spa_keystore_load_wkey_impl(dp->dp_spa, wkey);
	if (ret != 0)
		goto error;

	dsl_crypto_key_rele(dck, FTAG);
	dsl_dir_rele(dd, FTAG);
	dsl_pool_rele(dp, FTAG);

	/* create any zvols under this ds */
	zvol_create_minors(dp->dp_spa, dsname, B_TRUE);

	return (0);

error:
	if (dck != NULL)
		dsl_crypto_key_rele(dck, FTAG);
	if (dd != NULL)
		dsl_dir_rele(dd, FTAG);
	if (dp != NULL)
		dsl_pool_rele(dp, FTAG);

	return (ret);
}

int
spa_keystore_unload_wkey_impl(spa_t *spa, uint64_t ddobj)
{
	int ret;
	dsl_wrapping_key_t search_wkey;
	dsl_wrapping_key_t *found_wkey;

	/* init the search wrapping key */
	search_wkey.wk_ddobj = ddobj;

	rw_enter(&spa->spa_keystore.sk_wkeys_lock, RW_WRITER);

	/* remove the wrapping key from the keystore */
	found_wkey = avl_find(&spa->spa_keystore.sk_wkeys,
	    &search_wkey, NULL);
	if (!found_wkey) {
		ret = SET_ERROR(ENOENT);
		goto error_unlock;
	} else if (refcount_count(&found_wkey->wk_refcnt) != 0) {
		ret = SET_ERROR(EBUSY);
		goto error_unlock;
	}
	avl_remove(&spa->spa_keystore.sk_wkeys, found_wkey);

	rw_exit(&spa->spa_keystore.sk_wkeys_lock);

	/* free the wrapping key */
	dsl_wrapping_key_free(found_wkey);

	return (0);

error_unlock:
	rw_exit(&spa->spa_keystore.sk_wkeys_lock);
	return (ret);
}

int
spa_keystore_unload_wkey(const char *dsname)
{
	int ret = 0;
	dsl_dir_t *dd = NULL;
	dsl_pool_t *dp = NULL;

	/* hold the dsl dir */
	ret = dsl_pool_hold(dsname, FTAG, &dp);
	if (ret != 0)
		goto error;

	if (!spa_feature_is_enabled(dp->dp_spa, SPA_FEATURE_ENCRYPTION)) {
		ret = (SET_ERROR(ENOTSUP));
		goto error;
	}

	ret = dsl_dir_hold(dp, dsname, FTAG, &dd, NULL);
	if (ret != 0)
		goto error;

	/* unload the wkey */
	ret = spa_keystore_unload_wkey_impl(dp->dp_spa, dd->dd_object);
	if (ret != 0)
		goto error;

	dsl_dir_rele(dd, FTAG);
	dsl_pool_rele(dp, FTAG);

	/* remove any zvols under this ds */
	zvol_remove_minors(dp->dp_spa, dsname, B_TRUE);

	return (0);

error:
	if (dd != NULL)
		dsl_dir_rele(dd, FTAG);
	if (dp != NULL)
		dsl_pool_rele(dp, FTAG);

	return (ret);
}

int
spa_keystore_create_mapping_impl(spa_t *spa, uint64_t dsobj,
    dsl_dir_t *dd, void *tag)
{
	int ret;
	avl_index_t where;
	dsl_key_mapping_t *km = NULL, *found_km;
	boolean_t should_free = B_FALSE;

	/* allocate the mapping */
	km = kmem_alloc(sizeof (dsl_key_mapping_t), KM_SLEEP);
	if (!km)
		return (SET_ERROR(ENOMEM));

	/* initialize the mapping */
	refcount_create(&km->km_refcnt);

	ret = spa_keystore_dsl_key_hold_dd(spa, dd, km, &km->km_key);
	if (ret != 0)
		goto error;

	km->km_dsobj = dsobj;

	rw_enter(&spa->spa_keystore.sk_km_lock, RW_WRITER);

	/*
	 * If a mapping already exists, simply increment its refcount and
	 * cleanup the one we made. We want to allocate / free outside of
	 * the lock because this lock is also used by the zio layer to lookup
	 * key mappings. Otherwise, use the one we created. Normally, there will
	 * only be one active reference at a time (the objset owner), but there
	 * are times when there could be multiple async users.
	 */
	found_km = avl_find(&spa->spa_keystore.sk_key_mappings, km, &where);
	if (found_km != NULL) {
		should_free = B_TRUE;
		refcount_add(&found_km->km_refcnt, tag);
	} else {
		refcount_add(&km->km_refcnt, tag);
		avl_insert(&spa->spa_keystore.sk_key_mappings, km, where);
	}

	rw_exit(&spa->spa_keystore.sk_km_lock);

	if (should_free) {
		spa_keystore_dsl_key_rele(spa, km->km_key, km);
		refcount_destroy(&km->km_refcnt);
		kmem_free(km, sizeof (dsl_key_mapping_t));
	}

	return (0);

error:
	if (km->km_key)
		spa_keystore_dsl_key_rele(spa, km->km_key, km);

	refcount_destroy(&km->km_refcnt);
	kmem_free(km, sizeof (dsl_key_mapping_t));

	return (ret);
}

int
spa_keystore_create_mapping(spa_t *spa, dsl_dataset_t *ds, void *tag)
{
	return (spa_keystore_create_mapping_impl(spa, ds->ds_object,
	    ds->ds_dir, tag));
}

int
spa_keystore_remove_mapping(spa_t *spa, uint64_t dsobj, void *tag)
{
	int ret;
	dsl_key_mapping_t search_km;
	dsl_key_mapping_t *found_km;
	boolean_t should_free = B_FALSE;

	/* init the search key mapping */
	search_km.km_dsobj = dsobj;

	rw_enter(&spa->spa_keystore.sk_km_lock, RW_WRITER);

	/* find the matching mapping */
	found_km = avl_find(&spa->spa_keystore.sk_key_mappings,
	    &search_km, NULL);
	if (found_km == NULL) {
		ret = SET_ERROR(ENOENT);
		goto error_unlock;
	}

	/*
	 * Decrement the refcount on the mapping and remove it from the tree if
	 * it is zero. Try to minimize time spent in this lock by deferring
	 * cleanup work.
	 */
	if (refcount_remove(&found_km->km_refcnt, tag) == 0) {
		should_free = B_TRUE;
		avl_remove(&spa->spa_keystore.sk_key_mappings, found_km);
	}

	rw_exit(&spa->spa_keystore.sk_km_lock);

	/* destroy the key mapping */
	if (should_free) {
		spa_keystore_dsl_key_rele(spa, found_km->km_key, found_km);
		kmem_free(found_km, sizeof (dsl_key_mapping_t));
	}

	return (0);

error_unlock:
	rw_exit(&spa->spa_keystore.sk_km_lock);
	return (ret);
}

/*
 * This function is primarily used by the zio and arc layer to lookup
 * DSL Crypto Keys for encryption. Callers must release the key with
 * spa_keystore_dsl_key_rele(). The function may also be called with
 * dck_out == NULL and tag == NULL to simply check that a key exists
 * without getting a reference to it.
 */
int
spa_keystore_lookup_key(spa_t *spa, uint64_t dsobj, void *tag,
    dsl_crypto_key_t **dck_out)
{
	int ret;
	dsl_key_mapping_t search_km;
	dsl_key_mapping_t *found_km;

	ASSERT((tag != NULL && dck_out != NULL) ||
	    (tag == NULL && dck_out == NULL));

	/* init the search key mapping */
	search_km.km_dsobj = dsobj;

	rw_enter(&spa->spa_keystore.sk_km_lock, RW_READER);

	/* remove the mapping from the tree */
	found_km = avl_find(&spa->spa_keystore.sk_key_mappings, &search_km,
	    NULL);
	if (found_km == NULL) {
		ret = SET_ERROR(ENOENT);
		goto error_unlock;
	}

	if (found_km && tag)
		refcount_add(&found_km->km_key->dck_refcnt, tag);

	rw_exit(&spa->spa_keystore.sk_km_lock);

	if (dck_out != NULL)
		*dck_out = found_km->km_key;
	return (0);

error_unlock:
	rw_exit(&spa->spa_keystore.sk_km_lock);

	if (dck_out != NULL)
		*dck_out = NULL;
	return (ret);
}

static int
dmu_objset_check_wkey_loaded(dsl_dir_t *dd)
{
	int ret;
	dsl_wrapping_key_t *wkey = NULL;

	ret = spa_keystore_wkey_hold_ddobj(dd->dd_pool->dp_spa,
	    dd->dd_object, FTAG, &wkey);
	if (ret != 0)
		return (SET_ERROR(EACCES));

	dsl_wrapping_key_rele(wkey, FTAG);

	return (0);
}

static void
dsl_crypto_key_sync_impl(objset_t *mos, uint64_t dckobj, uint64_t crypt,
    uint8_t *iv, uint8_t *mac, uint8_t *keydata, uint8_t *hmac_keydata,
    dmu_tx_t *tx)
{
	VERIFY0(zap_update(mos, dckobj, DSL_CRYPTO_KEY_CRYPTO_SUITE, 8, 1,
	    &crypt, tx));
	VERIFY0(zap_update(mos, dckobj, DSL_CRYPTO_KEY_IV, 1, WRAPPING_IV_LEN,
	    iv, tx));
	VERIFY0(zap_update(mos, dckobj, DSL_CRYPTO_KEY_MAC, 1, WRAPPING_MAC_LEN,
	    mac, tx));
	VERIFY0(zap_update(mos, dckobj, DSL_CRYPTO_KEY_MASTER_KEY, 1,
	    MAX_MASTER_KEY_LEN, keydata, tx));
	VERIFY0(zap_update(mos, dckobj, DSL_CRYPTO_KEY_HMAC_KEY, 1,
	    HMAC_SHA256_KEYLEN, hmac_keydata, tx));
}

static void
dsl_crypto_key_sync(dsl_crypto_key_t *dck, dmu_tx_t *tx)
{
	zio_crypt_key_t *key = &dck->dck_key;
	uint8_t keydata[MAX_MASTER_KEY_LEN];
	uint8_t hmac_keydata[HMAC_SHA256_KEYLEN];
	uint8_t iv[WRAPPING_IV_LEN];
	uint8_t mac[WRAPPING_MAC_LEN];

	ASSERT(dmu_tx_is_syncing(tx));
	ASSERT3U(key->zk_crypt, <, ZIO_CRYPT_FUNCTIONS);

	/* encrypt and store the keys along with the IV and MAC */
	VERIFY0(zio_crypt_key_wrap(&dck->dck_wkey->wk_key, key, iv, mac,
	    keydata, hmac_keydata));

	/* update the ZAP with the obtained values */
	dsl_crypto_key_sync_impl(tx->tx_pool->dp_meta_objset, dck->dck_obj,
	    key->zk_crypt, iv, mac, keydata, hmac_keydata, tx);
}

typedef struct spa_keystore_rewrap_args {
	const char *skra_dsname;
	dsl_crypto_params_t *skra_cp;
} spa_keystore_rewrap_args_t;

static int
spa_keystore_rewrap_check(void *arg, dmu_tx_t *tx)
{
	int ret;
	uint64_t keyformat = ZFS_KEYFORMAT_NONE;
	dsl_dir_t *dd = NULL, *inherit_dd = NULL;
	dsl_pool_t *dp = dmu_tx_pool(tx);
	spa_keystore_rewrap_args_t *skra = arg;
	dsl_crypto_params_t *dcp = skra->skra_cp;

	/* check for the encryption feature */
	if (!spa_feature_is_enabled(dp->dp_spa, SPA_FEATURE_ENCRYPTION)) {
		ret = SET_ERROR(ENOTSUP);
		goto error;
	}

	/* hold the dd */
	ret = dsl_dir_hold(dp, skra->skra_dsname, FTAG, &dd, NULL);
	if (ret != 0)
		goto error;

	/* verify that the dataset is encrypted */
	if (dd->dd_crypto_obj == 0) {
		ret = SET_ERROR(EINVAL);
		goto error;
	}

	/* hold the dd where this dd is inheritting its key from */
	ret = dsl_dir_hold_keylocation_source_dd(dd, FTAG, &inherit_dd);
	if (ret != 0)
		goto error;

	/*
	 * A NULL dcp implies that the user wants this dataset to inherit
	 * the parent's wrapping key.
	 */
	if (dcp == NULL) {
		/* check that this is an encryption root */
		if (dd->dd_object != inherit_dd->dd_object) {
			ret = SET_ERROR(EINVAL);
			goto error;
		}

		/* check that the parent is encrypted */
		if (dd->dd_parent->dd_crypto_obj == 0) {
			ret = SET_ERROR(EINVAL);
			goto error;
		}

		ret = dmu_objset_check_wkey_loaded(dd);
		if (ret != 0)
			goto error;

		ret = dmu_objset_check_wkey_loaded(dd->dd_parent);
		if (ret != 0)
			goto error;

		dsl_dir_rele(dd, FTAG);
		dsl_dir_rele(inherit_dd, FTAG);

		return (0);
	}

	/*
	 * If this dataset is not currently an encryption root we need a fully
	 * specified key for this dataset to become a new encryption root.
	 */
	if (dd->dd_object != inherit_dd->dd_object &&
	    (dcp->cp_keyformat == ZFS_KEYFORMAT_NONE ||
	    dcp->cp_keylocation == NULL)) {
		ret = SET_ERROR(EINVAL);
		goto error;
	}

	/* figure out what the new format will be */
	if (dcp->cp_keyformat == ZFS_KEYFORMAT_NONE) {
		ret = dsl_prop_get_dd(dd, zfs_prop_to_name(ZFS_PROP_KEYFORMAT),
		    8, 1, &keyformat, NULL, B_FALSE);
		if (ret != 0)
			goto error;
	} else {
		keyformat = dcp->cp_keyformat;
	}

	/* crypt cannot be changed after creation */
	if (dcp->cp_crypt != ZIO_CRYPT_INHERIT) {
		ret = SET_ERROR(EINVAL);
		goto error;
	}

	/* we are not inheritting our parent's wkey so we need one ourselves */
	if (dcp->cp_wkey == NULL) {
		ret = SET_ERROR(EINVAL);
		goto error;
	}

	/* check that the keylocation is valid or NULL */
	if (dcp->cp_keylocation != NULL &&
	    !zfs_prop_valid_keylocation(dcp->cp_keylocation, B_TRUE)) {
		ret = SET_ERROR(EINVAL);
		goto error;
	}

	/* passphrases require pbkdf2 salt and iters */
	if (keyformat == ZFS_KEYFORMAT_PASSPHRASE &&
	    (skra->skra_cp->cp_salt == 0 ||
	    skra->skra_cp->cp_iters < MIN_PBKDF2_ITERATIONS)) {
		ret = SET_ERROR(EINVAL);
		goto error;
	}

	/* make sure the dd's wkey is loaded */
	ret = dmu_objset_check_wkey_loaded(dd);
	if (ret != 0)
		goto error;

	dsl_dir_rele(dd, FTAG);
	dsl_dir_rele(inherit_dd, FTAG);

	return (0);

error:
	if (dd != NULL)
		dsl_dir_rele(dd, FTAG);
	if (inherit_dd != NULL)
		dsl_dir_rele(inherit_dd, FTAG);

	return (ret);
}


static void
spa_keystore_rewrap_sync_impl(uint64_t root_ddobj, uint64_t ddobj,
    dsl_wrapping_key_t *wkey, dmu_tx_t *tx)
{
	zap_cursor_t zc;
	zap_attribute_t za;
	dsl_pool_t *dp = dmu_tx_pool(tx);
	dsl_dir_t *dd = NULL, *inherit_dd = NULL;
	dsl_crypto_key_t *dck = NULL;

	ASSERT(RW_WRITE_HELD(&dp->dp_spa->spa_keystore.sk_wkeys_lock));

	/* hold the dd */
	VERIFY0(dsl_dir_hold_obj(dp, ddobj, NULL, FTAG, &dd));

	/* ignore hidden dsl dirs */
	if (dd->dd_myname[0] == '$' || dd->dd_myname[0] == '%') {
		dsl_dir_rele(dd, FTAG);
		return;
	}

	/* hold the dd we inherited the keylocation from */
	VERIFY0(dsl_dir_hold_keylocation_source_dd(dd, FTAG, &inherit_dd));

	/* stop recursing if this dsl dir didn't inherit from the root */
	if (inherit_dd->dd_object != root_ddobj) {
		dsl_dir_rele(inherit_dd, FTAG);
		dsl_dir_rele(dd, FTAG);
		return;
	}

	/* get the dsl_crypt_key_t for the current dsl dir */
	VERIFY0(spa_keystore_dsl_key_hold_dd(dp->dp_spa, dd, FTAG, &dck));

	/* replace the wrapping key */
	dsl_wrapping_key_hold(wkey, dck);
	dsl_wrapping_key_rele(dck->dck_wkey, dck);
	dck->dck_wkey = wkey;

	/* sync the dsl key wrapped with the new wrapping key */
	dsl_crypto_key_sync(dck, tx);

	/* recurse into all children dsl dirs */
	for (zap_cursor_init(&zc, dp->dp_meta_objset,
	    dsl_dir_phys(dd)->dd_child_dir_zapobj);
	    zap_cursor_retrieve(&zc, &za) == 0;
	    zap_cursor_advance(&zc)) {
		spa_keystore_rewrap_sync_impl(root_ddobj, za.za_first_integer,
		    wkey, tx);
	}
	zap_cursor_fini(&zc);

	spa_keystore_dsl_key_rele(dp->dp_spa, dck, FTAG);
	dsl_dir_rele(inherit_dd, FTAG);
	dsl_dir_rele(dd, FTAG);
}

static void
spa_keystore_rewrap_sync(void *arg, dmu_tx_t *tx)
{
	dsl_dataset_t *ds;
	avl_index_t where;
	dsl_pool_t *dp = dmu_tx_pool(tx);
	spa_t *spa = dp->dp_spa;
	spa_keystore_rewrap_args_t *skra = arg;
	dsl_wrapping_key_t *wkey, *found_wkey;
	dsl_wrapping_key_t wkey_search;
	uint64_t keyformat;
	const char *keylocation;

	/* create and initialize the wrapping key */
	VERIFY0(dsl_dataset_hold(dp, skra->skra_dsname, FTAG, &ds));
	ASSERT(!ds->ds_is_snapshot);

	if (skra->skra_cp != NULL) {
		/*
		 * We are changing to a new wkey. Set additional properties
		 * which can be sent along with this ioctl. Note that this
		 * command can set keylocation even if it can't normally be
		 * set via 'zfs set' due to a non-local keylocation.
		 */
		keylocation = skra->skra_cp->cp_keylocation;
		wkey = skra->skra_cp->cp_wkey;
		wkey->wk_ddobj = ds->ds_dir->dd_object;

		if (keylocation != NULL) {
			dsl_prop_set_sync_impl(ds,
			    zfs_prop_to_name(ZFS_PROP_KEYLOCATION),
			    ZPROP_SRC_LOCAL, 1, strlen(keylocation) + 1,
			    keylocation, tx);
		}

		if (skra->skra_cp->cp_keyformat != ZFS_KEYFORMAT_NONE) {
			keyformat = skra->skra_cp->cp_keyformat;
			dsl_prop_set_sync_impl(ds,
			    zfs_prop_to_name(ZFS_PROP_KEYFORMAT),
			    ZPROP_SRC_LOCAL, 8, 1, &keyformat, tx);
		}

		dsl_prop_set_sync_impl(ds,
		    zfs_prop_to_name(ZFS_PROP_PBKDF2_ITERS), ZPROP_SRC_LOCAL,
		    8, 1, &skra->skra_cp->cp_iters, tx);

		dsl_prop_set_sync_impl(ds,
		    zfs_prop_to_name(ZFS_PROP_PBKDF2_SALT), ZPROP_SRC_LOCAL,
		    8, 1, &skra->skra_cp->cp_salt, tx);
	} else {
		/*
		 * We are inheritting the parent's wkey. Unset encryption all
		 * parameters and grab a reference to the wkey.
		 */
		VERIFY0(spa_keystore_wkey_hold_ddobj(spa,
		    ds->ds_dir->dd_parent->dd_object, FTAG, &wkey));

		dsl_prop_set_sync_impl(ds,
		    zfs_prop_to_name(ZFS_PROP_KEYLOCATION), ZPROP_SRC_NONE,
		    0, 0, NULL, tx);

		dsl_prop_set_sync_impl(ds,
		    zfs_prop_to_name(ZFS_PROP_KEYFORMAT), ZPROP_SRC_NONE,
		    0, 0, NULL, tx);

		dsl_prop_set_sync_impl(ds,
		    zfs_prop_to_name(ZFS_PROP_PBKDF2_ITERS), ZPROP_SRC_NONE,
		    0, 0, NULL, tx);

		dsl_prop_set_sync_impl(ds,
		    zfs_prop_to_name(ZFS_PROP_PBKDF2_SALT), ZPROP_SRC_NONE,
		    0, 0, NULL, tx);
	}

	rw_enter(&spa->spa_keystore.sk_wkeys_lock, RW_WRITER);

	/* recurse through all children and rewrap their keys */
	spa_keystore_rewrap_sync_impl(wkey->wk_ddobj, ds->ds_dir->dd_object,
	    wkey, tx);

	/*
	 * All references to the old wkey should be released now (if it
	 * existed). Replace the wrapping key.
	 */
	wkey_search.wk_ddobj = ds->ds_dir->dd_object;
	found_wkey = avl_find(&spa->spa_keystore.sk_wkeys, &wkey_search, NULL);
	if (found_wkey != NULL) {
		ASSERT0(refcount_count(&found_wkey->wk_refcnt));
		avl_remove(&spa->spa_keystore.sk_wkeys, found_wkey);
		dsl_wrapping_key_free(found_wkey);
	}

	if (skra->skra_cp != NULL) {
		avl_find(&spa->spa_keystore.sk_wkeys, wkey, &where);
		avl_insert(&spa->spa_keystore.sk_wkeys, wkey, where);
	} else {
		dsl_wrapping_key_rele(wkey, FTAG);
	}

	rw_exit(&spa->spa_keystore.sk_wkeys_lock);

	dsl_dataset_rele(ds, FTAG);
}

int
spa_keystore_rewrap(const char *dsname, dsl_crypto_params_t *dcp)
{
	spa_keystore_rewrap_args_t skra;

	/* initialize the args struct */
	skra.skra_dsname = dsname;
	skra.skra_cp = dcp;

	/* perform the actual work in syncing context */
	return (dsl_sync_task(dsname, spa_keystore_rewrap_check,
	    spa_keystore_rewrap_sync, &skra, 0, ZFS_SPACE_CHECK_NORMAL));
}

int
dsl_dir_rename_crypt_check(dsl_dir_t *dd, dsl_dir_t *newparent)
{
	int ret;
	dsl_dir_t *inherit_dd = NULL;
	dsl_dir_t *pinherit_dd = NULL;

	if (dd->dd_crypto_obj == 0) {
		/* children of encrypted parents must be encrypted */
		if (newparent->dd_crypto_obj != 0) {
			ret = SET_ERROR(EACCES);
			goto error;
		}

		return (0);
	}

	ret = dsl_dir_hold_keylocation_source_dd(dd, FTAG, &inherit_dd);
	if (ret != 0)
		goto error;

	/*
	 * if this is not an encryption root, we must make sure we are not
	 * moving dd to a new encryption root
	 */
	if (dd->dd_object != inherit_dd->dd_object) {
		ret = dsl_dir_hold_keylocation_source_dd(newparent, FTAG,
		    &pinherit_dd);
		if (ret != 0)
			goto error;

		if (pinherit_dd->dd_object != inherit_dd->dd_object) {
			ret = SET_ERROR(EACCES);
			goto error;
		}
	}

	if (inherit_dd != NULL)
		dsl_dir_rele(inherit_dd, FTAG);
	if (pinherit_dd != NULL)
		dsl_dir_rele(pinherit_dd, FTAG);
	return (0);

error:
	if (inherit_dd != NULL)
		dsl_dir_rele(inherit_dd, FTAG);
	if (pinherit_dd != NULL)
		dsl_dir_rele(pinherit_dd, FTAG);
	return (ret);
}

/*
 * This is the combined check function for verifying encrypted create and
 * clone parameters. There are a lot of edge cases to handle here so it has
 * been commented rather extensively. Some checks are duplicated in an effort
 * to ensure the error codes returned are consistent (EINVAL before EACCES).
 */
int
dmu_objset_create_crypt_check(dsl_dir_t *parentdd, dsl_dir_t *origindd,
    dsl_crypto_params_t *dcp)
{
	int ret;
	uint64_t pcrypt, effective_crypt;

	/* get the parent's crypt */
	ret = dsl_dir_get_crypt(parentdd, &pcrypt);
	if (ret != 0)
		return (ret);

	/*
	 * Figure out what the crypt will be for the new dataset.
	 * Clones must always use the same crypt as their origin.
	 */
	if (origindd != NULL) {
		ret = dsl_dir_get_crypt(origindd, &effective_crypt);
		if (ret != 0)
			return (ret);
	} else if (dcp == NULL || dcp->cp_crypt == ZIO_CRYPT_INHERIT) {
		effective_crypt = pcrypt;
	} else {
		effective_crypt = dcp->cp_crypt;
	}

	ASSERT3U(pcrypt, !=, ZIO_CRYPT_INHERIT);
	ASSERT3U(effective_crypt, !=, ZIO_CRYPT_INHERIT);

	/*
	 * can't create an unencrypted child of an encrypted parent
	 * under any circumstances
	 */
	if (effective_crypt == ZIO_CRYPT_OFF && pcrypt != ZIO_CRYPT_OFF)
		return (SET_ERROR(EINVAL));

	/* NULL dcp implies inheritence. Make sure the needed keys exist. */
	if (dcp == NULL) {
		/* no encryption */
		if (effective_crypt == ZIO_CRYPT_OFF)
			return (0);

		/* check for parent key */
		ret = dmu_objset_check_wkey_loaded(parentdd);
		if (ret != 0)
			return (ret);

		/* check for origin key if this is a clone */
		if (origindd != NULL) {
			ret = dmu_objset_check_wkey_loaded(origindd);
			if (ret != 0)
				return (ret);
		}

		return (0);
	}

	/* flags are only used for raw receives, which are not checked here */
	ASSERT0(dcp->cp_flags);

	/* check for valid dcp with no encryption (inherited or local) */
	if (effective_crypt == ZIO_CRYPT_OFF) {
		/* Must not specify encryption params */
		if (dcp->cp_salt != 0 || dcp->cp_iters != 0 ||
		    dcp->cp_keyformat != ZFS_KEYFORMAT_NONE ||
		    dcp->cp_wkey != NULL ||
		    (dcp->cp_keylocation != NULL &&
		    strcmp(dcp->cp_keylocation, "none") != 0))
			return (SET_ERROR(EINVAL));

		return (0);
	}

	/* We will now definitely be encrypting. Check the feature flag */
	if (!spa_feature_is_enabled(parentdd->dd_pool->dp_spa,
	    SPA_FEATURE_ENCRYPTION)) {
		return (SET_ERROR(EOPNOTSUPP));
	}

	/* handle non-implicit inheritence */
	if (dcp->cp_wkey == NULL) {
		/* key must be fully unspecified */
		if (dcp->cp_keyformat != ZFS_KEYFORMAT_NONE ||
		    dcp->cp_keylocation != NULL || dcp->cp_salt != 0 ||
		    dcp->cp_iters != 0)
			return (SET_ERROR(EINVAL));

		/* parent must have a key to inherit */
		if (pcrypt == ZIO_CRYPT_OFF)
			return (SET_ERROR(EINVAL));

		/* check for parent key */
		ret = dmu_objset_check_wkey_loaded(parentdd);
		if (ret != 0)
			return (ret);

		/* check for origin key if this is a clone */
		if (origindd != NULL) {
			ret = dmu_objset_check_wkey_loaded(origindd);
			if (ret != 0)
				return (ret);
		}

		return (0);
	}

	/* At this point we should have a fully specified key. Check location */
	if (dcp->cp_keylocation == NULL ||
	    !zfs_prop_valid_keylocation(dcp->cp_keylocation, B_TRUE))
		return (SET_ERROR(EINVAL));

	/* Must have fully specified keyformat */
	switch (dcp->cp_keyformat) {
	case ZFS_KEYFORMAT_HEX:
	case ZFS_KEYFORMAT_RAW:
		/* requires no pbkdf2 iters and salt */
		if (dcp->cp_salt != 0 || dcp->cp_iters != 0)
			return (SET_ERROR(EINVAL));
		break;
	case ZFS_KEYFORMAT_PASSPHRASE:
		/* requires pbkdf2 iters and salt */
		if (dcp->cp_salt == 0 || dcp->cp_iters < MIN_PBKDF2_ITERATIONS)
			return (SET_ERROR(EINVAL));
		break;
	case ZFS_KEYFORMAT_NONE:
	default:
		/* keyformat must be specified and valid */
		return (SET_ERROR(EINVAL));
	}

	/* check for origin key if this is a clone */
	if (origindd != NULL) {
		ret = dmu_objset_check_wkey_loaded(origindd);
		if (ret != 0)
			return (ret);
	}

	return (0);
}

void
dsl_dataset_create_crypt_sync(uint64_t dsobj, dsl_dir_t *dd,
    dsl_dataset_t *origin, dsl_crypto_params_t *dcp, dmu_tx_t *tx)
{
	dsl_pool_t *dp = dd->dd_pool;
	uint64_t crypt = (dcp != NULL) ? dcp->cp_crypt : ZIO_CRYPT_INHERIT;
	dsl_wrapping_key_t *wkey = (dcp != NULL) ? dcp->cp_wkey : NULL;

	if (dcp != NULL) {
		/* raw receives will handle their own key creation */
		if (dcp->cp_flags & DCP_FLAG_RAW_RECV) {
			ASSERT3U(dcp->cp_crypt, ==, ZIO_CRYPT_INHERIT);
			ASSERT3U(dcp->cp_keyformat, ==, ZFS_KEYFORMAT_NONE);
			ASSERT3P(dcp->cp_keylocation, ==, NULL);
			ASSERT3P(dcp->cp_wkey, ==, NULL);
			ASSERT0(dcp->cp_salt);
			ASSERT0(dcp->cp_iters);
			return;
		}

		crypt = dcp->cp_crypt;
		wkey = dcp->cp_wkey;
	} else {
		crypt = ZIO_CRYPT_INHERIT;
		wkey = NULL;
	}

	/* figure out the effective crypt */
	if (!dsl_dir_is_clone(dd)) {
		if (crypt == ZIO_CRYPT_INHERIT && dd->dd_parent != NULL) {
			VERIFY0(dsl_dir_get_crypt(dd->dd_parent, &crypt));
		}
	} else if (origin->ds_dir->dd_crypto_obj != 0) {
		VERIFY0(dsl_dir_get_crypt(origin->ds_dir, &crypt));
	}

	/* if we aren't doing encryption just return */
	if (crypt == ZIO_CRYPT_OFF || crypt == ZIO_CRYPT_INHERIT)
		return;

	/* zapify the dd so that we can add the crypto key obj to it */
	dmu_buf_will_dirty(dd->dd_dbuf, tx);
	dsl_dir_zapify(dd, tx);

	/* use the new key if given or inherit from the parent */
	if (wkey == NULL) {
		VERIFY0(spa_keystore_wkey_hold_ddobj(dp->dp_spa,
		    dd->dd_parent->dd_object, FTAG, &wkey));
	} else {
		wkey->wk_ddobj = dd->dd_object;
	}

	/*
	 * Create or clone the DSL crypto key. If we are creating activate
	 * the feature on the dataset (cloning will do this automatically).
	 */
	if (!dsl_dir_is_clone(dd)) {
		dd->dd_crypto_obj = dsl_crypto_key_create_sync(crypt, wkey, tx);
		dsl_dataset_activate_feature(dsobj, SPA_FEATURE_ENCRYPTION, tx);
	} else if (origin->ds_dir->dd_crypto_obj != 0) {
		dd->dd_crypto_obj = dsl_crypto_key_clone_sync(origin->ds_dir,
		    wkey, tx);
	}

	/* add the crypto key obj to the dd on disk */
	VERIFY0(zap_add(dp->dp_meta_objset, dd->dd_object,
	    DD_FIELD_CRYPTO_KEY_OBJ, sizeof (uint64_t), 1, &dd->dd_crypto_obj,
	    tx));

	/*
	 * If we inherited the wrapping key we release our reference now.
	 * Otherwise, this is a new key and we need to load it into the
	 * keystore.
	 */
	if (dcp == NULL || dcp->cp_wkey == NULL) {
		dsl_wrapping_key_rele(wkey, FTAG);
	} else {
		VERIFY0(spa_keystore_load_wkey_impl(dp->dp_spa, wkey));
	}
}

typedef struct dsl_crypto_recv_key_arg {
	uint64_t dcrka_dsobj;
	nvlist_t *dcrka_nvl;
} dsl_crypto_recv_key_arg_t;

int
dsl_crypto_recv_key_check(void *arg, dmu_tx_t *tx)
{
	int ret;
	dsl_crypto_recv_key_arg_t *dcrka = arg;
	nvlist_t *nvl = dcrka->dcrka_nvl;
	dsl_dataset_t *ds = NULL;
	uint8_t *buf = NULL;
	uint_t len;
	uint64_t intval;
	boolean_t is_passphrase = B_FALSE;

	/*
	 * Check that the ds exists. Assert that it isn't already encrypted
	 * and that it is inconsistent for sanity.
	 */
	ret = dsl_dataset_hold_obj(tx->tx_pool, dcrka->dcrka_dsobj, FTAG, &ds);
	if (ret != 0)
		goto error;

	ASSERT0(ds->ds_dir->dd_crypto_obj);
	ASSERT(dsl_dataset_phys(ds)->ds_flags & DS_FLAG_INCONSISTENT);

	/*
	 * Read and check all the encryption values from the nvlist. We need
	 * all of the fields of a DSL Crypto Key, as well as a fully specified
	 * wrapping key.
	 */
	ret = nvlist_lookup_uint64(nvl, DSL_CRYPTO_KEY_CRYPTO_SUITE, &intval);
	if (ret != 0 || intval >= ZIO_CRYPT_FUNCTIONS ||
	    intval <= ZIO_CRYPT_OFF) {
		ret = SET_ERROR(EINVAL);
		goto error;
	}

	ret = nvlist_lookup_uint8_array(nvl, DSL_CRYPTO_KEY_MASTER_KEY,
	    &buf, &len);
	if (ret != 0 || len != MAX_MASTER_KEY_LEN) {
		ret = SET_ERROR(EINVAL);
		goto error;
	}

	ret = nvlist_lookup_uint8_array(nvl, DSL_CRYPTO_KEY_HMAC_KEY,
	    &buf, &len);
	if (ret != 0 || len != HMAC_SHA256_KEYLEN) {
		ret = SET_ERROR(EINVAL);
		goto error;
	}

	ret = nvlist_lookup_uint8_array(nvl, DSL_CRYPTO_KEY_IV, &buf, &len);
	if (ret != 0 || len != WRAPPING_IV_LEN) {
		ret = SET_ERROR(EINVAL);
		goto error;
	}

	ret = nvlist_lookup_uint8_array(nvl, DSL_CRYPTO_KEY_MAC, &buf, &len);
	if (ret != 0 || len != WRAPPING_MAC_LEN) {
		ret = SET_ERROR(EINVAL);
		goto error;
	}

	ret = nvlist_lookup_uint64(nvl, zfs_prop_to_name(ZFS_PROP_KEYFORMAT),
	    &intval);
	if (ret != 0 || intval >= ZFS_KEYFORMAT_FORMATS ||
	    intval <= ZFS_KEYFORMAT_NONE) {
		ret = SET_ERROR(EINVAL);
		goto error;
	}

	is_passphrase = (intval == ZFS_KEYFORMAT_PASSPHRASE);

	/*
	 * for raw receives we allow any number of pbkdf2iters since there
	 * won't be a chance for the user to change it.
	 */
	ret = nvlist_lookup_uint64(nvl, zfs_prop_to_name(ZFS_PROP_PBKDF2_ITERS),
	    &intval);
	if (ret != 0 || (is_passphrase == (intval == 0))) {
		ret = SET_ERROR(EINVAL);
		goto error;
	}

	ret = nvlist_lookup_uint64(nvl, zfs_prop_to_name(ZFS_PROP_PBKDF2_SALT),
	    &intval);
	if (ret != 0 || (is_passphrase == (intval == 0))) {
		ret = SET_ERROR(EINVAL);
		goto error;
	}

	dsl_dataset_rele(ds, FTAG);
	return (0);

error:
	if (ds != NULL)
		dsl_dataset_rele(ds, FTAG);
	return (ret);
}

static void
dsl_crypto_recv_key_sync(void *arg, dmu_tx_t *tx)
{
	dsl_crypto_recv_key_arg_t *dcrka = arg;
	uint64_t dsobj = dcrka->dcrka_dsobj;
	nvlist_t *nvl = dcrka->dcrka_nvl;
	dsl_pool_t *dp = tx->tx_pool;
	objset_t *mos = dp->dp_meta_objset;
	dsl_dataset_t *ds;
	uint8_t *keydata, *hmac_keydata, *iv, *mac;
	uint_t len;
	uint64_t crypt, keyformat, iters, salt;

	VERIFY0(dsl_dataset_hold_obj(dp, dsobj, FTAG, &ds));

	/* lookup the values we need to create the DSL Crypto Key */
	crypt = fnvlist_lookup_uint64(nvl, DSL_CRYPTO_KEY_CRYPTO_SUITE);
	keyformat = fnvlist_lookup_uint64(nvl,
	    zfs_prop_to_name(ZFS_PROP_KEYFORMAT));
	iters = fnvlist_lookup_uint64(nvl,
	    zfs_prop_to_name(ZFS_PROP_PBKDF2_ITERS));
	salt = fnvlist_lookup_uint64(nvl,
	    zfs_prop_to_name(ZFS_PROP_PBKDF2_SALT));
	VERIFY0(nvlist_lookup_uint8_array(nvl, DSL_CRYPTO_KEY_MASTER_KEY,
	    &keydata, &len));
	VERIFY0(nvlist_lookup_uint8_array(nvl, DSL_CRYPTO_KEY_HMAC_KEY,
	    &hmac_keydata, &len));
	VERIFY0(nvlist_lookup_uint8_array(nvl, DSL_CRYPTO_KEY_IV, &iv, &len));
	VERIFY0(nvlist_lookup_uint8_array(nvl, DSL_CRYPTO_KEY_MAC, &mac, &len));

	/* zapify the dsl dir so we can add the key object to it */
	dmu_buf_will_dirty(ds->ds_dir->dd_dbuf, tx);
	dsl_dir_zapify(ds->ds_dir, tx);

	/* create the DSL Crypto Key on disk and activate the feature */
	ds->ds_dir->dd_crypto_obj = zap_create(mos,
	    DMU_OTN_ZAP_METADATA, DMU_OT_NONE, 0, tx);
	dsl_crypto_key_sync_impl(mos, ds->ds_dir->dd_crypto_obj, crypt, iv,
	    mac, keydata, hmac_keydata, tx);
	dsl_dataset_activate_feature(dsobj, SPA_FEATURE_ENCRYPTION, tx);
	ds->ds_feature_inuse[SPA_FEATURE_ENCRYPTION] = B_TRUE;

	/* save the dd_crypto_obj on disk */
	VERIFY0(zap_add(mos, ds->ds_dir->dd_object, DD_FIELD_CRYPTO_KEY_OBJ,
	    sizeof (uint64_t), 1, &ds->ds_dir->dd_crypto_obj, tx));

	/* set the encryption properties from the nvlist */
	dsl_prop_set_sync_impl(ds, zfs_prop_to_name(ZFS_PROP_KEYFORMAT),
	    ZPROP_SRC_LOCAL, 8, 1, &keyformat, tx);
	dsl_prop_set_sync_impl(ds, zfs_prop_to_name(ZFS_PROP_PBKDF2_ITERS),
	    ZPROP_SRC_LOCAL, 8, 1, &iters, tx);
	dsl_prop_set_sync_impl(ds, zfs_prop_to_name(ZFS_PROP_PBKDF2_SALT),
	    ZPROP_SRC_LOCAL, 8, 1, &salt, tx);

	dsl_dataset_rele(ds, FTAG);
}

/*
 * This function is used to sync an nvlist representing a DSL Crypto Key and
 * the associated encryption parameters. The key will be written exactly as is
 * without wrapping it.
 */
int
dsl_crypto_recv_key(const char *poolname, uint64_t dsobj, nvlist_t *nvl)
{
	dsl_crypto_recv_key_arg_t dcrka;

	dcrka.dcrka_dsobj = dsobj;
	dcrka.dcrka_nvl = nvl;

	return (dsl_sync_task(poolname, dsl_crypto_recv_key_check,
	    dsl_crypto_recv_key_sync, &dcrka, 5, ZFS_SPACE_CHECK_NORMAL));
}

int
dsl_crypto_populate_key_nvlist(dsl_dataset_t *ds, nvlist_t **nvl_out)
{
	int ret;
	nvlist_t *nvl = NULL;
	uint64_t dckobj = ds->ds_dir->dd_crypto_obj;
	objset_t *mos = ds->ds_dir->dd_pool->dp_meta_objset;
	uint64_t crypt = 0, format = 0, iters = 0, salt = 0;
	uint8_t raw_keydata[MAX_MASTER_KEY_LEN];
	uint8_t raw_hmac_keydata[HMAC_SHA256_KEYLEN];
	uint8_t iv[WRAPPING_IV_LEN];
	uint8_t mac[WRAPPING_MAC_LEN];

	ASSERT(dckobj != 0);

	ret = nvlist_alloc(&nvl, NV_UNIQUE_NAME, KM_SLEEP);
	if (ret != 0)
		goto error;

	/* lookup values from the DSL Crypto Key */
	ret = zap_lookup(mos, dckobj, DSL_CRYPTO_KEY_CRYPTO_SUITE, 8, 1,
	    &crypt);
	if (ret != 0)
		goto error;

	ret = zap_lookup(mos, dckobj, DSL_CRYPTO_KEY_MASTER_KEY, 1,
	    MAX_MASTER_KEY_LEN, raw_keydata);
	if (ret != 0)
		goto error;

	ret = zap_lookup(mos, dckobj, DSL_CRYPTO_KEY_HMAC_KEY, 1,
	    HMAC_SHA256_KEYLEN, raw_hmac_keydata);
	if (ret != 0)
		goto error;

	ret = zap_lookup(mos, dckobj, DSL_CRYPTO_KEY_IV, 1, WRAPPING_IV_LEN,
	    iv);
	if (ret != 0)
		goto error;

	ret = zap_lookup(mos, dckobj, DSL_CRYPTO_KEY_MAC, 1, WRAPPING_MAC_LEN,
	    mac);
	if (ret != 0)
		goto error;

	/* lookup values from the properties */
	dsl_pool_config_enter(ds->ds_dir->dd_pool, FTAG);

	ret = dsl_prop_get_dd(ds->ds_dir, zfs_prop_to_name(ZFS_PROP_KEYFORMAT),
	    8, 1, &format, NULL, B_FALSE);
	if (ret != 0)
		goto error_unlock;

	if (format == ZFS_KEYFORMAT_PASSPHRASE) {
		ret = dsl_prop_get_dd(ds->ds_dir,
		    zfs_prop_to_name(ZFS_PROP_PBKDF2_ITERS), 8, 1, &iters,
		    NULL, B_FALSE);
		if (ret != 0)
			goto error_unlock;

		ret = dsl_prop_get_dd(ds->ds_dir,
		    zfs_prop_to_name(ZFS_PROP_PBKDF2_SALT), 8, 1, &salt,
		    NULL, B_FALSE);
		if (ret != 0)
			goto error_unlock;
	}

	dsl_pool_config_exit(ds->ds_dir->dd_pool, FTAG);

	fnvlist_add_uint64(nvl, DSL_CRYPTO_KEY_CRYPTO_SUITE, crypt);
	VERIFY0(nvlist_add_uint8_array(nvl, DSL_CRYPTO_KEY_MASTER_KEY,
	    raw_keydata, MAX_MASTER_KEY_LEN));
	VERIFY0(nvlist_add_uint8_array(nvl, DSL_CRYPTO_KEY_HMAC_KEY,
	    raw_hmac_keydata, HMAC_SHA256_KEYLEN));
	VERIFY0(nvlist_add_uint8_array(nvl, DSL_CRYPTO_KEY_IV, iv,
	    WRAPPING_IV_LEN));
	VERIFY0(nvlist_add_uint8_array(nvl, DSL_CRYPTO_KEY_MAC, mac,
	    WRAPPING_MAC_LEN));
	fnvlist_add_uint64(nvl, zfs_prop_to_name(ZFS_PROP_KEYFORMAT), format);
	fnvlist_add_uint64(nvl, zfs_prop_to_name(ZFS_PROP_PBKDF2_ITERS), iters);
	fnvlist_add_uint64(nvl, zfs_prop_to_name(ZFS_PROP_PBKDF2_SALT), salt);

	*nvl_out = nvl;
	return (0);

error_unlock:
	dsl_pool_config_exit(ds->ds_dir->dd_pool, FTAG);
error:
	nvlist_free(nvl);

	*nvl_out = NULL;
	return (ret);
}

uint64_t
dsl_crypto_key_create_sync(uint64_t crypt, dsl_wrapping_key_t *wkey,
    dmu_tx_t *tx)
{
	dsl_crypto_key_t dck;

	ASSERT(dmu_tx_is_syncing(tx));
	ASSERT3U(crypt, <, ZIO_CRYPT_FUNCTIONS);
	ASSERT3U(crypt, >, ZIO_CRYPT_OFF);

	/* create the DSL Crypto Key ZAP object */
	dck.dck_obj = zap_create(tx->tx_pool->dp_meta_objset,
	    DMU_OTN_ZAP_METADATA, DMU_OT_NONE, 0, tx);

	/* fill in the key (on the stack) and sync it to disk */
	dck.dck_wkey = wkey;
	VERIFY0(zio_crypt_key_init(crypt, &dck.dck_key));

	dsl_crypto_key_sync(&dck, tx);

	zio_crypt_key_destroy(&dck.dck_key);
	bzero(&dck.dck_key, sizeof (zio_crypt_key_t));

	return (dck.dck_obj);
}

uint64_t
dsl_crypto_key_clone_sync(dsl_dir_t *orig_dd, dsl_wrapping_key_t *wkey,
    dmu_tx_t *tx)
{
	dsl_pool_t *dp = tx->tx_pool;
	dsl_crypto_key_t *orig_dck;
	dsl_crypto_key_t dck;

	ASSERT(dmu_tx_is_syncing(tx));

	/* get the key from the original dataset */
	VERIFY0(spa_keystore_dsl_key_hold_dd(dp->dp_spa, orig_dd, FTAG,
	    &orig_dck));

	/* create the DSL Crypto Key ZAP object */
	dck.dck_obj = zap_create(dp->dp_meta_objset, DMU_OTN_ZAP_METADATA,
	    DMU_OT_NONE, 0, tx);

	/* assign the wrapping key temporarily */
	dck.dck_wkey = wkey;

	/*
	 * Fill in the temporary key with the original key's data. We only need
	 * to actually copy the fields that will be synced to disk, namely the
	 * master key, hmac key and crypt.
	 */
	bcopy(&orig_dck->dck_key.zk_master_keydata,
	    &dck.dck_key.zk_master_keydata, MAX_MASTER_KEY_LEN);
	bcopy(&orig_dck->dck_key.zk_hmac_keydata,
	    &dck.dck_key.zk_hmac_keydata, HMAC_SHA256_KEYLEN);

	dck.dck_key.zk_crypt = orig_dck->dck_key.zk_crypt;

	/* sync the new key, wrapped with the new wrapping key */
	dsl_crypto_key_sync(&dck, tx);
	bzero(&dck.dck_key, sizeof (zio_crypt_key_t));

	spa_keystore_dsl_key_rele(dp->dp_spa, orig_dck, FTAG);

	return (dck.dck_obj);
}

void
dsl_crypto_key_destroy_sync(uint64_t dckobj, dmu_tx_t *tx)
{
	/* destroy the DSL Crypto Key object */
	VERIFY0(zap_destroy(tx->tx_pool->dp_meta_objset, dckobj, tx));
}

zfs_keystatus_t
dsl_dataset_get_keystatus(dsl_dataset_t *ds)
{
	int ret;
	dsl_wrapping_key_t *wkey;

	/* check if this dataset has a owns a dsl key */
	if (ds->ds_dir->dd_crypto_obj == 0)
		return (ZFS_KEYSTATUS_NONE);

	/* lookup the wkey. if it doesn't exist the key is unavailable */
	ret = spa_keystore_wkey_hold_ddobj(ds->ds_dir->dd_pool->dp_spa,
	    ds->ds_dir->dd_object, FTAG, &wkey);
	if (ret != 0)
		return (ZFS_KEYSTATUS_UNAVAILABLE);

	dsl_wrapping_key_rele(wkey, FTAG);

	return (ZFS_KEYSTATUS_AVAILABLE);
}

int
dsl_dir_get_crypt(dsl_dir_t *dd, uint64_t *crypt)
{
	if (dd->dd_crypto_obj == 0) {
		*crypt = ZIO_CRYPT_OFF;
		return (0);
	}

	return (zap_lookup(dd->dd_pool->dp_meta_objset, dd->dd_crypto_obj,
	    DSL_CRYPTO_KEY_CRYPTO_SUITE, 8, 1, crypt));
}

int
spa_crypt_get_salt(spa_t *spa, uint64_t dsobj, uint8_t *salt)
{
	int ret;
	dsl_crypto_key_t *dck = NULL;

	/* look up the key from the spa's keystore */
	ret = spa_keystore_lookup_key(spa, dsobj, FTAG, &dck);
	if (ret != 0)
		goto error;

	ret = zio_crypt_key_get_salt(&dck->dck_key, salt);
	if (ret != 0)
		goto error;

	spa_keystore_dsl_key_rele(spa, dck, FTAG);
	return (0);

error:
	if (dck != NULL)
		spa_keystore_dsl_key_rele(spa, dck, FTAG);
	return (ret);
}

/*
 * This function serve as a multiplexer for encryption and decryption of
 * all blocks (except the L2ARC). For encryption, it will populate the IV,
 * salt, MAC, and cabd (the ciphertext). On decryption it will simply use
 * these fields to populate pabd (the plaintext).
 */
int
spa_do_crypt_abd(boolean_t encrypt, spa_t *spa, zbookmark_phys_t *zb,
    const blkptr_t *bp, uint64_t txgid, uint_t datalen, abd_t *pabd,
    abd_t *cabd, uint8_t *iv, uint8_t *mac, uint8_t *salt, boolean_t *no_crypt)
{
	int ret;
	dmu_object_type_t ot = BP_GET_TYPE(bp);
	dsl_crypto_key_t *dck = NULL;
	uint8_t *plainbuf = NULL, *cipherbuf = NULL;

	ASSERT(spa_feature_is_active(spa, SPA_FEATURE_ENCRYPTION));
	ASSERT(!BP_IS_EMBEDDED(bp));
	ASSERT(BP_IS_ENCRYPTED(bp));

	/* look up the key from the spa's keystore */
	ret = spa_keystore_lookup_key(spa, zb->zb_objset, FTAG, &dck);
	if (ret != 0)
		return (ret);

	if (encrypt) {
		plainbuf = abd_borrow_buf_copy(pabd, datalen);
		cipherbuf = abd_borrow_buf(cabd, datalen);
	} else {
		plainbuf = abd_borrow_buf(pabd, datalen);
		cipherbuf = abd_borrow_buf_copy(cabd, datalen);
	}

	/*
	 * Both encryption and decryption functions need a salt for key
	 * generation and an IV. When encrypting a non-dedup block, we
	 * generate the salt and IV randomly to be stored by the caller. Dedup
	 * blocks perform a (more expensive) HMAC of the plaintext to obtain
	 * the salt and the IV. ZIL blocks have their salt and IV generated
	 * at allocation time in zio_alloc_zil(). On decryption, we simply use
	 * the provided values.
	 */
	if (encrypt && ot != DMU_OT_INTENT_LOG && !BP_GET_DEDUP(bp)) {
		ret = zio_crypt_key_get_salt(&dck->dck_key, salt);
		if (ret != 0)
			goto error;

		ret = zio_crypt_generate_iv(iv);
		if (ret != 0)
			goto error;
	} else if (encrypt && BP_GET_DEDUP(bp)) {
		ret = zio_crypt_generate_iv_salt_dedup(&dck->dck_key,
		    plainbuf, datalen, iv, salt);
		if (ret != 0)
			goto error;
	}

	/* call lower level function to perform encryption / decryption */
	ret = zio_do_crypt_data(encrypt, &dck->dck_key, salt, ot, iv, mac,
	    datalen, plainbuf, cipherbuf, no_crypt);
	if (ret != 0)
		goto error;

	if (encrypt) {
		abd_return_buf(pabd, plainbuf, datalen);
		abd_return_buf_copy(cabd, cipherbuf, datalen);
	} else {
		abd_return_buf_copy(pabd, plainbuf, datalen);
		abd_return_buf(cabd, cipherbuf, datalen);
	}

	spa_keystore_dsl_key_rele(spa, dck, FTAG);

	return (0);

error:
	if (encrypt) {
		/* zero out any state we might have changed while encrypting */
		bzero(salt, ZIO_DATA_SALT_LEN);
		bzero(iv, ZIO_DATA_IV_LEN);
		bzero(mac, ZIO_DATA_MAC_LEN);
		abd_return_buf(pabd, plainbuf, datalen);
		abd_return_buf_copy(cabd, cipherbuf, datalen);
	} else {
		abd_return_buf_copy(pabd, plainbuf, datalen);
		abd_return_buf(cabd, cipherbuf, datalen);
	}

	if (dck != NULL)
		spa_keystore_dsl_key_rele(spa, dck, FTAG);

	return (ret);
}
