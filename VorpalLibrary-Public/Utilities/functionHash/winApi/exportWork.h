/**
* Copyright (C) 2023 Vorpal. All rights reserved.
*
* Licensed under the Vorpal Library Software License. You may obtain a copy
* in the file "LICENSE" found at the root of this repository.
*/

#pragma once
typedef struct _PEB_LDR_DATA_ {
    BYTE Reserved1[8];
    PVOID Reserved2[3];
    LIST_ENTRY *InMemoryOrderModuleList;
} PEB_LDR_DATA_, *PPEB_LDR_DATA_;

typedef struct _PEB_c {
    BYTE Reserved1[2];
    BYTE BeingDebugged;
    BYTE Reserved2[21];
    PPEB_LDR_DATA_ Ldr;
} PEB_c;




#pragma warning (disable : 4996)
namespace VorpalAPI {
    extern __forceinline LPVOID parseExportTable(HMODULE module, uint64_t api_hash, uint64_t len, const uint64_t seed);
    extern __forceinline LPVOID getApi(uint64_t api_hash, std::string module, uint64_t len, const uint64_t seed);
}