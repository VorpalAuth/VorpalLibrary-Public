/**
* Copyright (C) 2023 Vorpal. All rights reserved.
*
* Licensed under the Vorpal Library Software License. You may obtain a copy
* in the file "LICENSE" found at the root of this repository.
*/

#pragma once

namespace VorpalAPI {
	namespace Memory {
		class PE {
		private:

			uintptr_t Module;

			bool CheckPE();

		public:
			PE(uintptr_t addr);

			template <typename type = std::uintptr_t>
			const type getAddressFromVa(std::uintptr_t virtual_address) const {
				return reinterpret_cast<type>(this->Module + virtual_address);
			}

			PIMAGE_DOS_HEADER DosHeader();

			PIMAGE_NT_HEADERS NtHeader(PIMAGE_DOS_HEADER pe);

			IMAGE_OPTIONAL_HEADER OptHeader(PIMAGE_NT_HEADERS pe);

			PIMAGE_SECTION_HEADER getFirstSection(PIMAGE_NT_HEADERS pe);

			std::vector<IMAGE_SECTION_HEADER> getSections();
		};
	}
}