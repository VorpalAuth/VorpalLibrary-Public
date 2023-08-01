/**
* Copyright (C) 2023 Vorpal. All rights reserved.
*
* Licensed under the Vorpal Library Software License. You may obtain a copy
* in the file "LICENSE" found at the root of this repository.
*/

#include "common.h"
#include "PE.h"

namespace VorpalAPI {
	namespace Memory {
		bool PE::CheckPE() {
			return (DosHeader()->e_magic == 0x5A4D); //"MZ"
		}

		PE::PE(uintptr_t addr) {
			Module = addr;
		}

		PIMAGE_DOS_HEADER PE::DosHeader() {
			return (PIMAGE_DOS_HEADER)(this->Module);
		}

		PIMAGE_NT_HEADERS PE::NtHeader(PIMAGE_DOS_HEADER pe) {
			if (!CheckPE()) return 0;
			return (PIMAGE_NT_HEADERS)(this->Module + pe->e_lfanew);
		}

		IMAGE_OPTIONAL_HEADER PE::OptHeader(PIMAGE_NT_HEADERS pe) {
			return (IMAGE_OPTIONAL_HEADER)pe->OptionalHeader;
		}

		PIMAGE_SECTION_HEADER PE::getFirstSection(PIMAGE_NT_HEADERS pe) {
			return IMAGE_FIRST_SECTION(pe);
		}

		std::vector<IMAGE_SECTION_HEADER> PE::getSections() {
			std::vector<IMAGE_SECTION_HEADER> tmpSections;
			auto dosHeader = DosHeader();
			auto ntHeader = NtHeader(dosHeader);
			if (ntHeader == 0) return {};

			auto sections = getFirstSection(ntHeader);
			for (size_t i = 0; i < ntHeader->FileHeader.NumberOfSections; i++) {
				auto section = sections[i];
				if (section.Characteristics == IMAGE_SCN_MEM_WRITE) continue;
				tmpSections.push_back(section);
			}

			return tmpSections;
		}
	}
}