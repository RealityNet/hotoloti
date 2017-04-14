#!/usr/bin/python
# -*- coding: utf-8 -*-
#
# Copyright 2017, Francesco "dfirfpi" Picasso <francesco.picasso@gmail.com>
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
#
# -----------------------------------------------------------------------------
#
# Dropbox DBX key extraction *offline* (why not? even online)
#
# python27 dbx-key-win-dpapi.py
#   --masterkey=/mnt/win81/Users/user/AppData/Roaming/Microsoft/Protect/S-1-5-21-2128076315-4144300488-3078399761-1001/
#   --sid=S-1-5-21-2128076315-4144300488-3078399761-1001
#   --password=fuffa
#   --ntuser=NTUSER.DAT
#
# In case you have not the password but its SHA1 (see Happy DPAPI blog post)
#
# python27 dbx-key-win-dpapi.py
#   --masterkey=/mnt/win81/Users/user/AppData/Roaming/Microsoft/Protect/S-1-5-21-2128076315-4144300488-3078399761-1001/
#   --sid=S-1-5-21-2128076315-4144300488-3078399761-1001
#   --hash=51d2e3226fca7f5932784a8e44cc9240
#   --ntuser=NTUSER.DAT
#
# In case you need the old credentials, add the credhist paramenter
#
# python27 dbx-key-win-dpapi.py
#   --masterkey=/mnt/win81/Users/user/AppData/Roaming/Microsoft/Protect/S-1-5-21-2128076315-4144300488-3078399761-1001/
#   --sid=S-1-5-21-2128076315-4144300488-3078399761-1001
#   --credhist=/mnt/win81/Users/user/AppData/Roaming/Microsoft/Protect/CREDHIST
#   --password=fuffa
#   --ntuser=NTUSER.DAT
#
# -----------------------------------------------------------------------------

from __future__ import print_function

# requires pip install pbkdf2
from pbkdf2 import PBKDF2
import optparse
import os
import sys

try:
    from DPAPI.Core import blob
    from DPAPI.Core import masterkey
    from DPAPI.Core import registry
    from DPAPI.Probes import dropbox
except ImportError, e:
    sys.stderr.write('Missing dpapick or its dependencies. ')
    sys.stderr.write('Install it or set PYTHONPATH.\n')
    raise ImportError(e)


def derive_dbx_password(user_key):

    APP_KEY = b'\rc\x8c\t.\x8b\x82\xfcE(\x83\xf9_5[\x8e'
    APP_ITER = 1066

    return PBKDF2(
        passphrase=user_key, salt=APP_KEY, iterations=APP_ITER).read(16)


if __name__ == "__main__":
    parser = optparse.OptionParser()
    parser.add_option('--sid', metavar='SID', dest='sid')
    parser.add_option('--masterkey', metavar='DIRECTORY', dest='masterkeydir')
    parser.add_option('--credhist', metavar='FILE', dest='credhist')
    parser.add_option('--password', metavar='PASSWORD', dest='password')
    parser.add_option('--hash', metavar='HASH', dest='h')
    parser.add_option('--ntuser', metavar='NTUSER', dest='ntuser')

    (options, args) = parser.parse_args()

    if options.password and options.h:
        sys.stderr.write('Choose either password or hash option.\n')
        sys.exit(1)

    mkp = masterkey.MasterKeyPool()
    if options.masterkeydir:
        mkp.loadDirectory(options.masterkeydir)
    if options.credhist and options.sid:
        mkp.addCredhistFile(options.sid, options.credhist)

    with open(options.ntuser, 'rb') as f:
        r = registry.Registry.Registry(f)
        for key_name in ('ks', 'ks1'):
            print('-'*80)
            datablob = dropbox.Dropbox(
                r.open('Software\\Dropbox\\'+key_name).value('Client').value())

            if options.h:
                datablob.try_decrypt_with_hash(
                    options.h.decode('hex'), mkp, options.sid)
            if options.password:
                datablob.try_decrypt_with_password(
                    options.password, mkp, options.sid)

            if datablob.dpapiblob.decrypted:
                user_key = datablob.user_key
                print('[{0}] user key:\t{1}'.format(
                    key_name, user_key.encode('hex')))
                dbx_key = derive_dbx_password(datablob.user_key)
                print('[{0}]  DBX key:\t{1}'.format(
                    key_name, dbx_key.encode('hex')))
            else:
                sys.stderr.write('Unable to decrypt DPAPI blob!\n')
        print('-'*80)

# vim:ts=4:expandtab:sw=4
