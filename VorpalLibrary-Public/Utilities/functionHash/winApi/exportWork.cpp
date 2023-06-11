#include "common.h"

#include "hashWork.h"
#include "ExportWork.h"
#include "Utilities/Utils.h"
#include "Utilities/Security/SecurityChecks.h"

#pragma warning (disable : 4996)
namespace VorpalAPI {


    __forceinline LPVOID parseExportTable(HMODULE module, uint64_t api_hash, uint64_t len, const uint64_t seed) {
        PIMAGE_DOS_HEADER dos = (PIMAGE_DOS_HEADER)module;
        PIMAGE_NT_HEADERS nt = (PIMAGE_NT_HEADERS)((uintptr_t)dos + dos->e_lfanew);
        PIMAGE_EXPORT_DIRECTORY inExport = (PIMAGE_EXPORT_DIRECTORY)((uintptr_t)dos + nt->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_EXPORT].VirtualAddress);

        PDWORD rvaName = (PDWORD)((uintptr_t)dos + inExport->AddressOfNames);
        PWORD rvaOrdinal = (PWORD)((uintptr_t)dos + inExport->AddressOfNameOrdinals);

        uint64_t ord = -1;
        char* apiName = (char*)"";
        unsigned int i;

        for (i = 0; i < inExport->NumberOfNames - 1; i++) {
            apiName = (PCHAR)((uintptr_t)dos + rvaName[i]);
            const uint64_t getHash = t1ha0(apiName, len, seed);
            if (api_hash == getHash) {
                ord = static_cast<uint64_t>(rvaOrdinal[i]);
                break;
            }
        }
        const auto funcAddr = (PDWORD)((uintptr_t)dos + inExport->AddressOfFunctions);
        const auto funcFind = (LPVOID)((uintptr_t)dos + funcAddr[ord]);


        if (!SecurityChecks::IsFunctionExportAddrLegit(module, apiName, (uintptr_t)funcFind)) return 0;

        LOG("Calling %s at 0x%p\n", apiName, funcFind);

        return funcFind;
    }

    __forceinline LPVOID getApi(uint64_t api_hash, std::string module, uint64_t len, const uint64_t seed) {
        LPVOID api_func = static_cast<LPVOID>(parseExportTable(Utils::getModule(module), api_hash, len, seed));
        return api_func;
    }
}