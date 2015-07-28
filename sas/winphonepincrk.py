#!/usr/bin/python
# -*- coding: utf-8 -*-
#
# Copyright 2015, Francesco "dfirfpi" Picasso <francesco.picasso@gmail.com>
#
# Licensed under the Apache License, Version 2.0 (the "License");
# you may not use this file except in compliance with the License.
# You may obtain a copy of the License at
#
# http://www.apache.org/licenses/LICENSE-2.0
#
# Unless required by applicable law or agreed to in writing, software
# distributed under the License is distributed on an "AS IS" BASIS,
# WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
# See the License for the specific language governing permissions and
# limitations under the License.
"""Windows Phone Simple Pin cracker."""

import construct
import hashlib
import itertools
import optparse
import os
import sys

from Registry import Registry


CREDENTIAL_HASH_BLOB = construct.Struct(
    'CREDENTIAL_HASH_BLOB',
    construct.ULInt32('salt_len'),
    construct.ULInt32('hash_algo_name_len'),
    construct.ULInt32('hash_len'),
    construct.Bytes('salt', lambda ctx: ctx.salt_len),
    construct.String(
        'hash_algo', lambda ctx: ctx.hash_algo_name_len, encoding='utf16'),
    construct.Bytes('hash', lambda ctx: ctx.hash_len)
)


def reg_key_get_value_or_die(reg_key, value_name):
    try:
        value_obj = reg_key.value(value_name)
    except:
        sys.exit('Missing {} value!'.format(value_name))
    else:
        return value_obj.value()


if __name__ == '__main__':
    """Utility core."""
    usage = (
        'usage: %prog [options]\n\n'
        'Windows Phones Simple Pin Cracker.')

    parser = optparse.OptionParser(usage=usage)
    parser.add_option('--software', metavar='HIVE', dest='software')

    (options, args) = parser.parse_args()

    PIN_KEY = 'Microsoft\\Comms\\Security\\DeviceLock\\Object21'

    if not options.software:
        sys.exit('SOFTWARE hive is needed!')

    with open(options.software, 'rb') as hive_sw:

        reg_handle = Registry.Registry(hive_sw)

        try:
            reg_pin_key = reg_handle.open(PIN_KEY)
        except Registry.RegistryKeyNotFoundException:
            sys.exit('Object21 key not found, no PIN used.')

        cred_len = reg_key_get_value_or_die(
            reg_pin_key, 'CredentialActualLength')

        cred_hash = reg_key_get_value_or_die(reg_pin_key, 'CredentialHash')

    cred_hash_blob = CREDENTIAL_HASH_BLOB.parse(cred_hash)
    target_hash = cred_hash_blob.hash
    salt = cred_hash_blob.salt

    hash_algo = cred_hash_blob.hash_algo.rstrip('\x00').encode('utf8').lower()
    halgo = getattr(hashlib, hash_algo, None)
    if not halgo:
        sys.exit('Hash algo [{}] not available'.format(hash_algo))

    for i in itertools.product('0123456789', repeat=cred_len):
        pin = ''.join(i)
        t = '\x00'.join(i) + '\x00'
        t += salt
        hash = halgo(t)
        if hash.digest() == target_hash:
            print 'PIN code is {}'.format(pin)
            break
        else:
            pin = ''

    if not pin:
        print 'Weird, no PIN found!'
