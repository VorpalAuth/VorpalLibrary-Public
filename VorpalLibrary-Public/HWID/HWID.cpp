
#include "common.h"

/**
* Copyright (C) 2023 Vorpal. All rights reserved.
*
* Licensed under the Vorpal Library Software License. You may obtain a copy
* in the file "LICENSE" found at the root of this repository.
*/

#include "HWID.h"
#include "Identifiers/baseboard.h"
#include "Identifiers/cpu.h"
#include "Identifiers/disk.h"

namespace VorpalAPI {
	namespace HWID {

		std::string grabHWID() {
			std::string hwid = strEnc("");
			hwid += HWID::BASEBOARD::getBaseboard();
			hwid += strEnc("_");
			hwid += HWID::CPU::getCPUInfo();
			hwid += strEnc("_");
			hwid += HWID::DISK::getDiskSerial();
			const std::string strKey = HWID::CPU::getCPUInfo();

			std::unique_ptr<Botan::MessageAuthenticationCode> mac(Botan::MessageAuthenticationCode::create(strEnc("HMAC(SHA-256)")));
			mac->set_key(reinterpret_cast<const uint8_t*>(strKey.data()), strKey.size());
			mac->update(hwid);

			return Botan::hex_encode(mac->final(), false);
		}
	}
}