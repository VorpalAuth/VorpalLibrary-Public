/**
* Copyright (C) 2023 Vorpal. All rights reserved.
*
* Licensed under the Vorpal Library Software License. You may obtain a copy
* in the file "LICENSE" found at the root of this repository.
*/

#include "common.h"
#include "cpu.h"
namespace VorpalAPI {
    namespace HWID {
        namespace CPU {

            std::string getCPUInfo() {
                int CPUInfo[4] = { -1 };
                unsigned   nExIds, i = 0;
                char CPUBrandString[0x40];
                __cpuid(CPUInfo, 0x80000000);
                nExIds = CPUInfo[0];

                for (i = 0x80000000; i <= nExIds; ++i) {
                    __cpuid(CPUInfo, i);
                    if (i == 0x80000002)
                        memcpy(CPUBrandString, CPUInfo, sizeof(CPUInfo));
                    else if (i == 0x80000003)
                        memcpy(CPUBrandString + 16, CPUInfo, sizeof(CPUInfo));
                    else if (i == 0x80000004)
                        memcpy(CPUBrandString + 32, CPUInfo, sizeof(CPUInfo));
                }

                return CPUBrandString;
            }
        }
    }
}