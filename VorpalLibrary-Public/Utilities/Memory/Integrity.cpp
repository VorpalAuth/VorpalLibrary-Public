#include "common.h"
#include "Integrity.h"
#include "crc.h"
#include "Utilities/crt.h"
#include "Utilities/Utils.h"
namespace VorpalAPI {
	namespace Memory {
		namespace Integ {
			std::vector<Integrity::integrity> Integrity::crc(std::vector<IMAGE_SECTION_HEADER> sections) {
				std::vector<integrity> tmpintergrity;
				for (size_t i = 0; i < sections.size(); i++) {
					auto section = sections[i];
					void* address = pe->getAddressFromVa<void*>(section.VirtualAddress);

					integrity tmpInt;
					tmpInt.crc32 = CRC::Calculate(address, section.Misc.VirtualSize, CRC::CRC_32());
					tmpInt.addr = address;
					tmpInt.size = section.Misc.VirtualSize;
					tmpintergrity.push_back(tmpInt);
				}

				return tmpintergrity;
			}

			Integrity::Integrity(uintptr_t addr) {
				if (!addr)
					addr = (uintptr_t)Utils::getModule(strEnc(".exe"));

				pe = new PE(addr);
				//Setup Cache 
				this->cachedIntegrity = crc(pe->getSections());
			}

			void Integrity::Checksum() {
				auto newIntegrity = crc(pe->getSections());
				for (size_t i = 0; i < newIntegrity.size(); i++) {
					if (newIntegrity[i].crc32 == this->cachedIntegrity[i].crc32) {
						LOG("[Vorpal] Matched Page addr %p offset %p size 0x%p \n", (uint64_t)newIntegrity[i].addr, (uint64_t)((uint64_t)newIntegrity[i].addr - (uint64_t)GetModuleHandleW(NULL)), newIntegrity[i].size);
					}
					else {
						LOG("[Vorpal] Modified Page addr %p offset %p size 0x%p\n", (uint64_t)newIntegrity[i].addr, (uint64_t)((uint64_t)newIntegrity[i].addr - (uint64_t)GetModuleHandleW(NULL)), newIntegrity[i].size);
						
						//TODO: Report back to server & auto ban user (if bannable offense)
					}
				}
			}

			void Integrity::ChecksumFromDisk() {
				wchar_t filename[MAX_PATH];
				DWORD size = MAX_PATH;
				HANDLE process = hash_GetCurrentProcess();
				hash_QueryFullProcessImageNameW(process, 0, filename, &size);

				const auto fileHandle = hash_CreateFileW(filename, GENERIC_READ, FILE_SHARE_READ, 0, OPEN_EXISTING, FILE_ATTRIBUTE_NORMAL, 0);
				if (!fileHandle || fileHandle == INVALID_HANDLE_VALUE) {
					//TODO: Report back to server & auto ban user (if bannable offense)
					return;
				}

				const auto fileMapping = hash_CreateFileMappingW(fileHandle, 0, PAGE_READONLY, 0, 0, 0);
				if (!fileMapping) {
					//TODO: Report back to server & auto ban user (if bannable offense)
					hash_CloseHandle(fileHandle);
					return;
				}

				auto bffr = reinterpret_cast<std::uintptr_t>(hash_MapViewOfFile(fileMapping, FILE_MAP_READ, 0, 0, 0));

				PE file((uintptr_t)bffr);
				PIMAGE_DOS_HEADER Dos = file.DosHeader();
				PIMAGE_NT_HEADERS Nt = file.NtHeader(Dos);
				auto newIntegrity = crc(file.getSections());
				for (size_t i = 0; i < newIntegrity.size(); i++) {
					if (newIntegrity[i].crc32 == this->cachedIntegrity[i].crc32) {
						LOG("[Vorpal] Matched Page from Disk addr %p offset %p size 0x%p \n", (uint64_t)newIntegrity[i].addr, (uint64_t)((uint64_t)newIntegrity[i].addr - (uint64_t)GetModuleHandleW(NULL)), newIntegrity[i].size);
					}
					else {
						LOG("[Vorpal] Modified Page from Disk addr %p offset %p size 0x%p\n", (uint64_t)newIntegrity[i].addr, (uint64_t)((uint64_t)newIntegrity[i].addr - (uint64_t)GetModuleHandleW(NULL)), newIntegrity[i].size);
						//TODO: Report back to server & auto ban user (if bannable offense)
					}
				}

				//Cleanup
				hash_UnmapViewOfFile(reinterpret_cast<void*>(bffr));
				hash_CloseHandle(fileHandle);
			}
		}
	}
}