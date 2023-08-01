/**
* Copyright (C) 2023 Vorpal. All rights reserved.
*
* Licensed under the Vorpal Library Software License. You may obtain a copy
* in the file "LICENSE" found at the root of this repository.
*/

#include "common.h"
#include "Utilities/Utils.h"
#include "Utilities/Memory/PE.h"

#include <Psapi.h>
#include <strsafe.h>
#include <Softpub.h>
#include <wintrust.h>
#include <mscat.h>
#include <stdio.h>

#pragma comment (lib, "wintrust")

namespace VorpalAPI {
	using namespace Utils;
	namespace SecurityChecks {
		DWORD Rva2Offset(DWORD rva, PIMAGE_SECTION_HEADER psh, PIMAGE_NT_HEADERS pnt) {
			if (rva == 0) 
				return (rva);
			
			for (size_t i = 0; i < pnt->FileHeader.NumberOfSections; i++) {
				if (rva >= psh->VirtualAddress && rva < psh->VirtualAddress + psh->Misc.VirtualSize)
					break;
				
				psh++;
			}

			return (rva - psh->VirtualAddress + psh->PointerToRawData);
		}

		//Thanks Peter for this one <3
        int verifySignature(const wchar_t* file_path) {
            int ret = 0;
            long status = 0;
            GUID policy_guid = WINTRUST_ACTION_GENERIC_VERIFY_V2;


            HANDLE file_handle = CreateFileW(file_path, GENERIC_READ, FILE_SHARE_READ, NULL, OPEN_EXISTING, 0, NULL);
            if (file_handle == INVALID_HANDLE_VALUE) {
                ret = GetLastError();
				return ret;
            }

            WINTRUST_FILE_INFO file_info;
            ZeroMemory(&file_info, sizeof(file_info));
            file_info.cbStruct = sizeof(WINTRUST_FILE_INFO);
            file_info.pcwszFilePath = file_path;
            file_info.hFile = file_handle;

            wchar_t* sign_hash = (wchar_t*)"RSA/SHA256;RSA/SHA512;DSA/SHA256;DSA/SHA512;ECDSA/SHA256;ECDSA/SHA512";

            CERT_STRONG_SIGN_SERIALIZED_INFO policy_rule;
            policy_rule.dwFlags = 0;
            policy_rule.pwszCNGSignHashAlgids = sign_hash;
            policy_rule.pwszCNGPubKeyMinBitLengths = nullptr;

            CERT_STRONG_SIGN_PARA policy;
            ZeroMemory(&policy, sizeof(policy));
            policy.cbSize = sizeof(CERT_STRONG_SIGN_PARA);
            policy.dwInfoChoice = CERT_STRONG_SIGN_SERIALIZED_INFO_CHOICE;
            policy.pSerializedInfo = &policy_rule;

            HCATINFO  info_handle = NULL;
            HCATADMIN admin_handle = NULL;

            if (!CryptCATAdminAcquireContext2(&admin_handle, NULL, 0, NULL, 0)) {
                ret = GetLastError();
				if (file_handle != NULL) {
					CloseHandle(file_handle);
				}
				return ret;
            }

            DWORD len = 0;
            BYTE* data = nullptr;
            CryptCATAdminCalcHashFromFileHandle2(admin_handle, file_handle, &len, NULL, 0);
            data = new BYTE[len];
			

            if (!CryptCATAdminCalcHashFromFileHandle2(admin_handle, file_handle, &len, data, 0)) {

				if (data != nullptr) {
					delete[] data;
				}
				if (admin_handle != NULL) {
					CryptCATAdminReleaseContext(admin_handle, NULL);
				}
				if (file_handle != NULL) {
					CloseHandle(file_handle);
				}
            }

            CATALOG_INFO catalog;
            ZeroMemory(&catalog, sizeof(CATALOG_INFO));
            do {
                info_handle = CryptCATAdminEnumCatalogFromHash(admin_handle, data, len, 0, &info_handle);

                if (CryptCATCatalogInfoFromContext(info_handle, &catalog, 0)) {
					//LOGW(L"Catalog %ls \n", catalog.wszCatalogFile);
                }

            } while (info_handle != NULL);

            // [2] Check for embeded ones

            WINTRUST_SIGNATURE_SETTINGS sign_settings;
            ZeroMemory(&sign_settings, sizeof(sign_settings));
            sign_settings.cbStruct = sizeof(WINTRUST_SIGNATURE_SETTINGS);
            sign_settings.dwFlags = WSS_VERIFY_SPECIFIC;
            sign_settings.dwIndex = 0;

            WINTRUST_DATA wintrust_data;
            ZeroMemory(&wintrust_data, sizeof(wintrust_data));
            wintrust_data.cbStruct = sizeof(WINTRUST_DATA);
            wintrust_data.dwUIChoice = WTD_UI_NONE;
            wintrust_data.fdwRevocationChecks = WTD_REVOKE_NONE;
            wintrust_data.dwUnionChoice = WTD_CHOICE_FILE;
            wintrust_data.dwProvFlags = WTD_HASH_ONLY_FLAG;

            wintrust_data.pFile = &file_info;
            wintrust_data.pSignatureSettings = &sign_settings;
            wintrust_data.pSignatureSettings->pCryptoPolicy = &policy;

            CRYPT_PROVIDER_DATA* prov_data = nullptr;
            CRYPT_PROVIDER_SGNR* prov_signer = nullptr;

            do {
                wintrust_data.dwStateAction = WTD_STATEACTION_VERIFY;
                status = WinVerifyTrust((HWND)INVALID_HANDLE_VALUE, &policy_guid, (LPVOID)&wintrust_data);

                // Check -> WinTruest.h:291
                if (status == ERROR_SUCCESS) {
                    prov_data = WTHelperProvDataFromStateData(wintrust_data.hWVTStateData);
                    prov_signer = WTHelperGetProvSignerFromChain(prov_data, wintrust_data.pSignatureSettings->dwIndex, FALSE, 0);

                    if (prov_signer != nullptr) {
                       // LOG("Embeded %s \n", prov_signer->pChainContext->rgpChain[0]->rgpElement[0]->pCertContext->pCertInfo->SignatureAlgorithm.pszObjId);
                    }
                }

                wintrust_data.dwStateAction = WTD_STATEACTION_CLOSE;
                WinVerifyTrust((HWND)INVALID_HANDLE_VALUE, &policy_guid, (LPVOID)&wintrust_data);

                wintrust_data.pSignatureSettings->dwIndex++;
            } while (wintrust_data.pSignatureSettings->dwIndex <= wintrust_data.pSignatureSettings->cSecondarySigs);

			if (data != nullptr) {
				delete[] data;
			}
			if (admin_handle != NULL) {
				CryptCATAdminReleaseContext(admin_handle, NULL);
			}
			if (file_handle != NULL) {
				CloseHandle(file_handle);
			}

            return ret;
        }

		bool IsFunctionExportAddrLegit(HMODULE mod, std::string function, uint64_t addr) {
			TCHAR path[_MAX_PATH]; 
			GetModuleFileNameW(mod, path, _MAX_PATH);

			if (verifySignature(path)) return false;

			const auto fileHandle = CreateFileW(path, GENERIC_READ, FILE_SHARE_READ, 0, OPEN_EXISTING, FILE_ATTRIBUTE_NORMAL, 0);
			if (!fileHandle || fileHandle == INVALID_HANDLE_VALUE) {
				LOG("Failed to CreateFile\n");
				return 0;
			}

			const auto fileMapping = CreateFileMappingW(fileHandle, 0, PAGE_READONLY, 0, 0, 0);
			if (!fileMapping) {
				LOG("Failed to CreateFileMappingW\n");
				CloseHandle(fileHandle);
				return 0;
			}

			auto bffr = reinterpret_cast<std::uintptr_t>(MapViewOfFile(fileMapping, FILE_MAP_READ, 0, 0, 0));

			Memory::PE pe((uintptr_t)bffr);
			PIMAGE_DOS_HEADER Dos = pe.DosHeader();
			PIMAGE_NT_HEADERS Nt = pe.NtHeader(Dos);

			bool ret = false;

			// get pointer to import descriptor's file offset. Note that the formula for calculating file offset is: imageBaseAddress + pointerToRawDataOfTheSectionContainingRVAofInterest + (RVAofInterest - SectionContainingRVAofInterest.VirtualAddress)
			auto Export = Nt->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_EXPORT];
			if (Export.Size) {
				auto ExportDir = (PIMAGE_EXPORT_DIRECTORY)((DWORD_PTR)bffr + Rva2Offset(Nt->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_EXPORT].VirtualAddress, IMAGE_FIRST_SECTION(Nt), Nt));
				
				uint32_t* rvaName = (uint32_t*)((uint8_t*)Dos + Rva2Offset(ExportDir->AddressOfNames, IMAGE_FIRST_SECTION(Nt), Nt));
				PWORD rvaOrdinal = (PWORD)((uint8_t*)Dos + Rva2Offset(ExportDir->AddressOfNameOrdinals, IMAGE_FIRST_SECTION(Nt), Nt));
				const auto funcAddr = (PDWORD)((uintptr_t)Dos + Rva2Offset(ExportDir->AddressOfFunctions, IMAGE_FIRST_SECTION(Nt), Nt));
				void* address = nullptr;

				WORD ordinal = 0;
				DWORD ordBase = 0;

				//Is function ordinal
				if (((DWORD)function.c_str() >> 16) == 0) {
					ordinal = LOWORD(function.c_str());
					ordBase = Rva2Offset(ExportDir->Base, IMAGE_FIRST_SECTION(Nt), Nt);

					//Check if Ordinal is valid
					if (ordinal < ordBase || ordinal > ordBase + Rva2Offset(ExportDir->NumberOfFunctions, IMAGE_FIRST_SECTION(Nt), Nt))
						return false;

					const auto funcFind = (LPVOID)((uintptr_t)Dos + funcAddr[ordinal - ordBase]);

					if (((uintptr_t)funcFind - (uintptr_t)bffr) == ((uintptr_t)addr - (uintptr_t)mod)) ret = true;

					LOG("%s in %ws[0x%p] addr 0x%p->0x%p Offset Compare 0x%p -> 0x%p\n", function.c_str(), path, (uintptr_t)mod, addr, (uintptr_t)funcFind, ((uintptr_t)funcFind - (uintptr_t)bffr), ((uintptr_t)addr - (uintptr_t)mod));
				}
				else {
					for (size_t i = 0; i < Rva2Offset(ExportDir->NumberOfNames, IMAGE_FIRST_SECTION(Nt), Nt); i++) {
						const char* name = (const char*)(uint8_t*)bffr + Rva2Offset(rvaName[i], IMAGE_FIRST_SECTION(Nt), Nt);

						if (strcmp(function.c_str(), name) == 0) {
							const auto funcFind = (LPVOID)((uintptr_t)Dos + funcAddr[static_cast<uint64_t>(rvaOrdinal[i])]);

							if (((uintptr_t)funcFind - (uintptr_t)bffr) == ((uintptr_t)addr - (uintptr_t)mod)) ret = true;

							LOG("%s in %ws[0x%p] addr 0x%p->0x%p Offset Compare 0x%p -> 0x%p\n", function.c_str(), path, (uintptr_t)mod, addr, (uintptr_t)funcFind, ((uintptr_t)funcFind - (uintptr_t)bffr), ((uintptr_t)addr - (uintptr_t)mod));

							break;
						}
					}
				}
			}

			UnmapViewOfFile(reinterpret_cast<void*>(bffr));
			CloseHandle(fileHandle);

			return ret;
		}

		bool IsInLegitModule(uintptr_t rip) {
			PPEB peb = Utils::NtCurrentPeb();
			PPEB_LDR_DATA ldr = peb->Ldr;
			PLDR_DATA_TABLE_ENTRY mod = NULL;
			PLIST_ENTRY list = ldr->InMemoryOrderModuleList.Flink;

			while (list != NULL && list != &ldr->InMemoryOrderModuleList) {
				mod = CONTAINING_RECORD(list, LDR_DATA_TABLE_ENTRY, InMemoryOrderLinks);
				PIMAGE_NT_HEADERS nt = (PIMAGE_NT_HEADERS)((uintptr_t)mod->DllBase + ((PIMAGE_DOS_HEADER)mod->DllBase)->e_lfanew);

				if ((rip >= (uintptr_t)mod->DllBase) && (rip <= (uintptr_t)mod->DllBase + nt->OptionalHeader.SizeOfImage)) {
					return true;
				}
				list = list->Flink;
			}

			return false;
		}
	}
}