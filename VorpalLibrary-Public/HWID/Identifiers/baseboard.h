/**
* Copyright (C) 2023 Vorpal. All rights reserved.
*
* Licensed under the Vorpal Library Software License. You may obtain a copy
* in the file "LICENSE" found at the root of this repository.
*/

#pragma once
#include <string>
#include <Windows.h>

namespace VorpalAPI {
    namespace HWID {
        namespace BASEBOARD {
            typedef struct _dmi_header
            {
                BYTE type;
                BYTE length;
                WORD handle;
            }dmi_header;

            typedef struct _RawSMBIOSData {
                BYTE    Used20CallingMethod;
                BYTE    SMBIOSMajorVersion;
                BYTE    SMBIOSMinorVersion;
                BYTE    DmiRevision;
                DWORD   Length;
                BYTE    SMBIOSTableData[];
            }RawSMBIOSData;

            extern std::string getBaseboard();
        }
    }
}