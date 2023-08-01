/**
* Copyright (C) 2023 Vorpal. All rights reserved.
*
* Licensed under the Vorpal Library Software License. You may obtain a copy
* in the file "LICENSE" found at the root of this repository.
*/

#include "common.h"
#include "Utils.h"
#include "crt.h"



namespace Utils {
    __forceinline HMODULE getModule(std::string module) {
        const auto ModuleList = 0x18;
        const auto ModuleListFlink = 0x18;
        const INT_PTR peb = __readgsqword(0x60); //x64 support only..
        const auto mdllist = *(INT_PTR*)(peb + ModuleList);
        const auto mlink = *(INT_PTR*)(mdllist + ModuleListFlink);
        auto mdl = (LDR_MODULE*)mlink;

        do {
            mdl = (LDR_MODULE*)mdl->e[0].Flink;
            if (mdl->base != nullptr) {
                auto bffr = CRT::String::ws2s(mdl->dllname.Buffer);

                std::transform(bffr.begin(), bffr.end(), bffr.begin(), [](unsigned char c) { return std::tolower(c); });
                std::transform(module.begin(), module.end(), module.begin(), [](unsigned char c) { return std::tolower(c); });
                if (CRT::String::myStrStr((char*)bffr.c_str(), (char*)module.c_str()) != NULL) {
                    return mdl->base;
                    break;
                }
            }
        } while (mlink != (INT_PTR)mdl);

        return 0;
    }

    //PEB support for x86, x64, ARM, ARM64, IA64, Alpha AXP, MIPS, and PowerPC.
    inline PEB* NtCurrentPeb() {
#ifdef _M_X64
        return (PEB*)(__readgsqword(0x60));
#elif _M_IX86
        return (PEB*)(__readfsdword(0x30));
#elif _M_ARM
        return *(PEB**)(_MoveFromCoprocessor(15, 0, 13, 0, 2) + 0x30);
#elif _M_ARM64
        return *(PEB**)(__getReg(18) + 0x60); // TEB in x18
#elif _M_IA64
        return *(PEB**)((size_t)_rdteb() + 0x60); // TEB in r13
#elif _M_ALPHA
        return *(PEB**)((size_t)_rdteb() + 0x30); // TEB pointer returned from callpal 0xAB
#elif _M_MIPS
        return *(PEB**)((*(size_t*)(0x7ffff030)) + 0x30); // TEB pointer located at 0x7ffff000 (PCR in user-mode) + 0x30
#elif _M_PPC
        // winnt.h of the period uses __builtin_get_gpr13() or __gregister_get(13) depending on _MSC_VER
        return *(PEB**)(__gregister_get(13) + 0x30); // TEB in r13
#else
#error "This architecture is currently unsupported"
#endif
    }

	std::string uint8VectorToHex(const std::vector<uint8_t>& v) {
		std::string result;
		result.reserve(v.size() * 2);

		static constexpr char hex[] = "0123456789ABCDEF";

		for (uint8_t c : v) {
			result.push_back(hex[c / 16]);
			result.push_back(hex[c % 16]);
		}

		return result;
	}

    inline std::string sha256(std::string data) {
		std::unique_ptr<Botan::HashFunction> hash1(Botan::HashFunction::create("SHA-256"));
		hash1->update(data);
		return Botan::hex_encode(hash1->final());
        return "";
	}

    const char base64UrlAlphabet[] = {
       'A', 'B', 'C', 'D', 'E', 'F', 'G', 'H', 'I', 'J', 'K', 'L', 'M',
       'N', 'O', 'P', 'Q', 'R', 'S', 'T', 'U', 'V', 'W', 'X', 'Y', 'Z',
       'a', 'b', 'c', 'd', 'e', 'f', 'g', 'h', 'i', 'j', 'k', 'l', 'm',
       'n', 'o', 'p', 'q', 'r', 's', 't', 'u', 'v', 'w', 'x', 'y', 'z',
       '0', '1', '2', '3', '4', '5', '6', '7', '8', '9', '-', '_', '+',
       '/','='
    };

    std::string base64UrlEncode(const std::string& in) {
        std::string out;
        int val = 0, valb = -6;
        size_t len = in.length();
        unsigned int i = 0;
        for (i = 0; i < len; i++) {
            unsigned char c = in[i];
            val = (val << 8) + c;
            valb += 8;
            while (valb >= 0) {
                out.push_back(base64UrlAlphabet[(val >> valb) & 0x3F]);
                valb -= 6;
            }
        }
        if (valb > -6) {
            out.push_back(base64UrlAlphabet[((val << 8) >> (valb + 8)) & 0x3F]);
        }
        return out;
    }
}