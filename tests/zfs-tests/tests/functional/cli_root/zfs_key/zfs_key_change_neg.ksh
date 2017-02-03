#!/bin/ksh -p
#
# CDDL HEADER START
#
# The contents of this file are subject to the terms of the
# Common Development and Distribution License (the "License").
# You may not use this file except in compliance with the License.
#
# You can obtain a copy of the license at usr/src/OPENSOLARIS.LICENSE
# or http://www.opensolaris.org/os/licensing.
# See the License for the specific language governing permissions
# and limitations under the License.
#
# When distributing Covered Code, include this CDDL HEADER in each
# file and include the License file at usr/src/OPENSOLARIS.LICENSE.
# If applicable, add the following below this CDDL HEADER, with the
# fields enclosed by brackets "[]" replaced with your own identifying
# information: Portions Copyright [yyyy] [name of copyright owner]
#
# CDDL HEADER END
#

#
# Copyright 2007 Sun Microsystems, Inc.  All rights reserved.
# Use is subject to license terms.
#

#
# Copyright (c) 2017, Datto, Inc. All rights reserved.
#

. $STF_SUITE/tests/functional/cli_root/zfs_key/zfs_key_common.kshlib

#
# DESCRIPTION:
# 'zfs change-key' should not be able to change an unloaded
# wrapping key or allow a change to an invalid key
#
# STRATEGY:
# 1. Create an encrypted dataset and unmount it
# 2. Attempt to change the wrapping key to an invalid key
# 3. Verify that the old key still works for the encrypted system
# 4. Unload the wrapping key
# 5. Attempt to change the key and keyformat to a valid key
# 6. Verify that the old key still works for the encrypted system
# 7. Attempt to change the key and keyformat on an unencrypted filesystem
#

verify_runnable "both"

function cleanup
{
	destroy_default_encrypted_dataset
}

log_onexit cleanup

log_assert "'zfs change-key' should not change an unloaded wrapping key \
	or allow a change to an invalid key"

create_default_encrypted_dataset
log_must $ZFS unmount $TESTPOOL/$CRYPTDS

log_mustnot eval '$ECHO $SHORT_PKEY | \
	$ZFS change-key -o keyformat=passphrase $TESTPOOL/$CRYPTDS'

log_must $ZFS unload-key $TESTPOOL/$CRYPTDS
log_must eval '$ECHO $PKEY | $ZFS load-key $TESTPOOL/$CRYPTDS'
check_key_available $TESTPOOL/$CRYPTDS

log_must $ZFS unload-key $TESTPOOL/$CRYPTDS

log_mustnot eval '$ECHO $HKEY | $ZFS change-key -o keyformat=hex \
	$TESTPOOL/$CRYPTDS'
check_key_unavailable $TESTPOOL/$CRYPTDS

log_mustnot eval '$ECHO $PKEY | $ZFS change-key -o keyformat=passphrase \
	$TESTPOOL'

log_pass "'zfs change-key' does not change an unloaded wrapping key \
	or allow a change to an invalid key"
