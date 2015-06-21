#!/usr/bin/python
# -*- coding: utf-8 -*-
#
# Copyright 2015, Francesco "dfirfpi" Picasso <francesco.picasso@gmail.com>
#
# Licensed under the Apache License, Version 2.0 (the "License");
# you may not use this file except in compliance with the License.
# You may obtain a copy of the License at
#
#    http://www.apache.org/licenses/LICENSE-2.0
#
# Unless required by applicable law or agreed to in writing, software
# distributed under the License is distributed on an "AS IS" BASIS,
# WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
# See the License for the specific language governing permissions and
# limitations under the License.
#
"""Python Windows-only utility to decompress MAM compressed files."""

import binascii
import ctypes
import struct
import sys


def tohex(val, nbits):
    """Utility to convert (signed) integer to hex."""
    return hex((val + (1 << nbits)) % (1 << nbits))

def main():
    """Utility core."""
    if len(sys.argv) != 3:
        sys.exit('Missing params [win10compressed.pf] [win10decompressed.pf]')

    NULL = ctypes.POINTER(ctypes.c_uint)()
    SIZE_T = ctypes.c_uint
    DWORD = ctypes.c_uint32
    USHORT = ctypes.c_uint16
    UCHAR  = ctypes.c_ubyte
    ULONG = ctypes.c_uint32

    # You must have at least Windows 8, or it should fail.
    try:
        RtlDecompressBufferEx = ctypes.windll.ntdll.RtlDecompressBufferEx
    except AttributeError:
        sys.exit('You must have Windows with version >=8.')

    RtlGetCompressionWorkSpaceSize = \
        ctypes.windll.ntdll.RtlGetCompressionWorkSpaceSize

    with open(sys.argv[1], 'rb') as fin:
        header = fin.read(8)
        compressed = fin.read()

        signature, decompressed_size = struct.unpack('<LL', header)
        calgo = (signature & 0x0F000000) >> 24
        crcck = (signature & 0xF0000000) >> 28
        magic = signature & 0x00FFFFFF
        if magic != 0x004d414d :
            sys.exit('Wrong signature... wrong file?')

        if crcck:
            # I could have used RtlComputeCrc32.
            file_crc = struct.unpack('<L', compressed[:4])[0]
            crc = binascii.crc32(header)
            crc = binascii.crc32(struct.pack('<L',0), crc)
            compressed = compressed[4:]
            crc = binascii.crc32(compressed, crc)          
            if crc != file_crc:
                sys.exit('Wrong file CRC {0:x} - {1:x}!'.format(crc, file_crc))

        compressed_size = len(compressed)

        ntCompressBufferWorkSpaceSize = ULONG()
        ntCompressFragmentWorkSpaceSize = ULONG()

        ntstatus = RtlGetCompressionWorkSpaceSize(USHORT(calgo),
            ctypes.byref(ntCompressBufferWorkSpaceSize),
            ctypes.byref(ntCompressFragmentWorkSpaceSize))

        if ntstatus:
            sys.exit('Cannot get workspace size, err: {}'.format(
                tohex(ntstatus, 32)))
                
        ntCompressed = (UCHAR * compressed_size).from_buffer_copy(compressed)
        ntDecompressed = (UCHAR * decompressed_size)()
        ntFinalUncompressedSize = ULONG()
        ntWorkspace = (UCHAR * ntCompressFragmentWorkSpaceSize.value)()
        
        ntstatus = RtlDecompressBufferEx(
            USHORT(calgo),
            ctypes.byref(ntDecompressed),
            ULONG(decompressed_size),
            ctypes.byref(ntCompressed),
            ULONG(compressed_size),
            ctypes.byref(ntFinalUncompressedSize),
            ctypes.byref(ntWorkspace))

        if ntstatus:
            sys.exit('Decompression failed, err: {}'.format(
                tohex(ntstatus, 32)))

        if ntFinalUncompressedSize.value != decompressed_size:
            print 'Decompressed with a different size than original!'

        with open(sys.argv[2], 'wb') as fout:
            fout.write(bytearray(ntDecompressed))

        print 'Lucky man, you have your prefetch file ready to be parsed!'

if __name__ == "__main__":
    main()
