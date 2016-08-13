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

#ifndef	_SYS_ZIO_CRYPT_H
#define	_SYS_ZIO_CRYPT_H

#ifdef _KERNEL
#define	LOG_DEBUG(fmt, args...) printk(KERN_DEBUG  fmt "\n", ## args)
#define	LOG_BOOKMARK(s, zb) \
	LOG_DEBUG(s ": objset = %llu, object = %llu, level = %lld, \
	blkid = %llu", (zb)->zb_objset, (zb)->zb_object, (zb)->zb_level, \
	(zb)->zb_blkid)
#define	LOG_CHECKSUM(s, c) LOG_DEBUG(s ": %llx:%llx:%llx:%llx", \
	(c)->zc_word[0], (c)->zc_word[1], (c)->zc_word[2], (c)->zc_word[3]);
#define	DUMP_STACK() dump_stack()
#else
#define	LOG_DEBUG(fmt, args...)
#define	LOG_BOOKMARK(str, zb)
#define	LOG_CHECKSUM(s, c)
#define	DUMP_STACK()
#endif

#include <sys/dmu.h>
#include <sys/refcount.h>
#include <sys/crypto/api.h>
#include <sys/nvpair.h>
#include <sys/avl.h>
#include <sys/zio.h>

/* forward declarations */
struct zbookmark_phys;

/* macros defining encryption lengths */
#define	MAX_MASTER_KEY_LEN 32
#define	DATA_IV_LEN 12
#define	DATA_SALT_LEN 8
#define	DATA_MAC_LEN 16

#define	WRAPPING_KEY_LEN 32
#define	WRAPPING_IV_LEN DATA_IV_LEN
#define	WRAPPING_MAC_LEN 16

#define	L2ARC_IV_LEN 12
#define	L2ARC_MAC_LEN 8
#define	ZIL_MAC_LEN 8

#define	SHA1_DIGEST_LEN 20
#define	SHA_256_DIGEST_LEN 32
#define	HMAC_SHA256_KEYLEN 32

#define	L2ARC_DEFAULT_CRYPT ZIO_CRYPT_AES_256_CCM

#define	ZIO_NO_ENCRYPTION_NEEDED -1

/*
 * After encrypting many blocks with the same salt we may start to run
 * up against the theoretical limits of how much data can securely be
 * encrypted a single key using the supported encryption modes. To
 * counteract this we generate a new salt after writing
 * ZIO_CRYPT_MAX_SALT_USAGE blocks of data, tracked by zk_salt_count.
 * The current value was chosen because it is approximately the number
 * of blocks that would have to be written in order to acheive a
 * 1 / 1 trillion chance of having an IV collision. Developers looking to
 * change this number should make sure they take into account the
 * birthday problem in regards to IV generation and the limits of what the
 * underlying mode can actually handle.
 */
#define	ZIO_CRYPT_MAX_SALT_USAGE 400000000

/* utility macros */
#define	BITS_TO_BYTES(x) (((x) + 7) >> 3)
#define	BYTES_TO_BITS(x) (x << 3)

/* supported commands for zfs_ioc_crypto() */
typedef enum zfs_ioc_crypto_cmd {
	ZFS_IOC_CRYPTO_CMD_NONE = 0,
	ZFS_IOC_CRYPTO_LOAD_KEY,
	ZFS_IOC_CRYPTO_UNLOAD_KEY,
	ZFS_IOC_CRYPTO_REWRAP,
} zfs_ioc_crypto_cmd_t;

typedef enum zio_crypt_type {
	ZC_TYPE_NONE = 0,
	ZC_TYPE_CCM,
	ZC_TYPE_GCM
} zio_crypt_type_t;

/* table of supported crypto algorithms, modes and keylengths. */
typedef struct zio_crypt_info {
	/* mechanism name, needed by ICP */
	crypto_mech_name_t ci_mechname;

	/* cipher mode type (GCM, CCM) */
	zio_crypt_type_t ci_crypt_type;

	/* length of the encryption key */
	size_t ci_keylen;

	/* human-readable name of the encryption alforithm */
	char *ci_name;
} zio_crypt_info_t;

extern zio_crypt_info_t zio_crypt_table[ZIO_CRYPT_FUNCTIONS];

/* ZAP entry keys for DSL Encryption Keys stored on disk */
#define	DSL_CRYPTO_KEY_CRYPT "DSL_CRYPTO_CRYPT"
#define	DSL_CRYPTO_KEY_IV "DSL_CRYPTO_IV"
#define	DSL_CRYPTO_KEY_MAC "DSL_CRYPTO_MAC"
#define	DSL_CRYPTO_KEY_MASTER_BUF "DSL_CRYPTO_MASTER"
#define	DSL_CRYPTO_KEY_HMAC_KEY_BUF "DSL_CRYPTO_HMAC_KEY"

/* in memory representation of an unwrapped key that is loaded into memory */
typedef struct zio_crypt_key {
	/* encryption algorithm */
	uint64_t zk_crypt;

	/* buffer for master key */
	uint8_t zk_master_keydata[MAX_MASTER_KEY_LEN];

	/* buffer for hmac key */
	uint8_t zk_hmac_keydata[HMAC_SHA256_KEYLEN];

	/* buffer for currrent encryption key derived from master key */
	uint8_t zk_current_keydata[MAX_MASTER_KEY_LEN];

	/* current 64 bit salt for deriving an encryption key */
	uint8_t zk_salt[DATA_SALT_LEN];

	/* count of how many times the current salt has been used */
	uint64_t zk_salt_count;

	/* illumos crypto api current encryption key */
	crypto_key_t zk_current_key;

	/* template of current encryption key for illumos crypto api */
	crypto_ctx_template_t zk_current_tmpl;

	/* illumos crypto api current hmac key */
	crypto_key_t zk_hmac_key;

	/* template of hmac key for illumos crypto api */
	crypto_ctx_template_t zk_hmac_tmpl;

	/* lock for changing the salt and dependant values */
	krwlock_t zk_salt_lock;
} zio_crypt_key_t;

/* in memory representation of the global L2ARC encryption key */
typedef struct l2arc_crypt_key {
	/* encryption algorithm */
	enum zio_encrypt l2ck_crypt;

	/* illumos crypto api key representation */
	crypto_key_t l2ck_key;

	/* private data for illumos crypto api */
	crypto_ctx_template_t l2ck_ctx_tmpl;
} l2arc_crypt_key_t;

void l2arc_crypt_key_destroy(l2arc_crypt_key_t *key);
int l2arc_crypt_key_init(l2arc_crypt_key_t *key);
void zio_crypt_key_destroy(zio_crypt_key_t *key);
int zio_crypt_key_init(uint64_t crypt, zio_crypt_key_t *key);
int zio_crypt_key_get_salt(zio_crypt_key_t *key, uint8_t *salt_out);

int zio_do_crypt_uio(boolean_t encrypt, uint64_t crypt, crypto_key_t *key,
    crypto_ctx_template_t tmpl, uint8_t *ivbuf, uint_t datalen,
    uio_t *puio, uio_t *cuio);
#define	zio_encrypt_uio(crypt, key, tmpl, iv, datalen, pu, cu) \
    zio_do_crypt_uio(B_TRUE, crypt, key, tmpl, iv, datalen, pu, cu)
#define	zio_decrypt_uio(crypt, key, tmpl, iv, datalen, pu, cu) \
    zio_do_crypt_uio(B_FALSE, crypt, key, tmpl, iv, datalen, pu, cu)

int zio_crypt_key_wrap(crypto_key_t *cwkey, zio_crypt_key_t *key, uint8_t *iv,
    uint8_t *mac, uint8_t *keydata_out, uint8_t *hmac_keydata_out);
int zio_crypt_key_unwrap(crypto_key_t *cwkey, uint64_t crypt, uint8_t *keydata,
    uint8_t *hmac_keydata, uint8_t *iv, uint8_t *mac, zio_crypt_key_t *key);
int zio_crypt_generate_iv(blkptr_t *bp, dmu_object_type_t ot, uint8_t *salt,
    uint64_t txgid, zbookmark_phys_t *zb, uint8_t *ivbuf);
int zio_crypt_generate_iv_salt_dedup(zio_crypt_key_t *key, uint8_t *data,
    uint_t datalen, uint8_t *ivbuf, uint8_t *salt);
int zio_crypt_generate_iv_l2arc(uint64_t spa, dva_t *dva, uint64_t birth,
    uint64_t daddr, uint8_t *ivbuf);

int zio_do_crypt_data(boolean_t encrypt, zio_crypt_key_t *key, uint8_t *salt,
    dmu_object_type_t ot, uint8_t *iv, uint8_t *mac, uint_t datalen,
    uint8_t *plainbuf, uint8_t *cipherbuf);

#endif
