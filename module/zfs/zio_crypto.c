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

#include <sys/zio.h>
#include <sys/sdt.h>

void zio_encrypt_data(enum zio_crypto crypto, void *src, void *dst, size_t len){
	char *c;
	
	ASSERT(crypto != ZIO_CRYPTO_OFF);
	
	bcopy(src, dst, len);
	
	for(c = (char *)dst; c < ((char *)dst) + len; c++){
		if(*c == 't') *c = 'T';
		else if(*c == 'T') *c = 't';
	}
}

int zio_decrypt_data(void *src, void *dst, size_t len){
	char *c;
		
	bcopy(src, dst, len);
	
	for(c = (char *)dst; c < ((char *)dst) + len; c++){
		if(*c == 't') *c = 'T';
		else if(*c == 'T') *c = 't';
	}
	
	return 0;
}