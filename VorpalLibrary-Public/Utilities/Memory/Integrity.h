/**
* Copyright (C) 2023 Vorpal. All rights reserved.
*
* Licensed under the Vorpal Library Software License. You may obtain a copy
* in the file "LICENSE" found at the root of this repository.
*/

#pragma once

#include "PE.h"
namespace VorpalAPI {
	namespace Memory {
		namespace Integ {
			class Integrity {
			private:
				PE* pe;

				struct integrity {
					std::uint32_t crc32;
					void* addr;
					size_t size;
				};

				inline Botan::secure_vector<uint8_t> CRC32(std::vector<uint8_t> data);

				std::vector<integrity> crc(std::vector<IMAGE_SECTION_HEADER> sections);

				std::vector< integrity> cachedIntegrity;

			public:
				Integrity(uintptr_t addr = 0);

				void Checksum();

				void ChecksumFromDisk();
			};
		}
	}
}