/**
* Copyright (C) 2023 Vorpal. All rights reserved.
*
* Licensed under the Vorpal Library Software License. You may obtain a copy
* in the file "LICENSE" found at the root of this repository.
*/

#include "baseboard.h"
#include "common.h"

namespace VorpalAPI {
    namespace HWID {
        namespace BASEBOARD {

            const char* dmiString(const dmi_header* d, BYTE s) {
                char* bp = (char*)d;

                if (s == 0)
                    return "Unspecified";

                bp += d->length;

                while (s > 1 && *bp) {
                    bp += strlen(bp);
                    bp++;

                    s--;
                }

                if (!*bp)
                    return "BAD_INDEX";

                /* ASCII filtering and buffer for filtered string */
                size_t len = strlen(bp);
                for (size_t i = 0; i < len; i++)
                    if (bp[i] < 32 || bp[i] == 127)
                        bp[i] = '.';


                return bp;
            }

            template<typename ... Args>
            std::string string_format(const std::string& format, Args ... args) {
                size_t size = snprintf(nullptr, 0, format.c_str(), args ...) + 1; // Extra space for '\0'
                if (size <= 0) { throw std::runtime_error("Error during formatting."); }
                std::unique_ptr<char[]> buf(new char[size]);
                snprintf(buf.get(), size, format.c_str(), args ...);
                return std::string(buf.get(), buf.get() + size - 1); // We don't want the '\0' inside
            }

            static std::string dmi_system_uuid(const BYTE* p, short ver) {
                int only0xFF = 1, only0x00 = 1;
                int i;

                for (i = 0; i < 16 && (only0x00 || only0xFF); i++) {
                    if (p[i] != 0x00) only0x00 = 0;
                    if (p[i] != 0xFF) only0xFF = 0;
                }

                if (only0xFF) {
                    return strEnc("Not Present");
                }

                if (only0x00) {
                    return strEnc("Not Settable");
                }

                if (ver >= 0x0206) {
                    return string_format(strEnc("%02X%02X%02X%02X-%02X%02X-%02X%02X-%02X%02X-%02X%02X%02X%02X%02X%02X"), p[3], p[2], p[1], p[0], p[5], p[4], p[7], p[6], p[8], p[9], p[10], p[11], p[12], p[13], p[14], p[15]);

                }
                else
                    return string_format(strEnc("-%02X%02X%02X%02X-%02X%02X-%02X%02X-%02X%02X-%02X%02X%02X%02X%02X%02X\n"), p[0], p[1], p[2], p[3], p[4], p[5], p[6], p[7], p[8], p[9], p[10], p[11], p[12], p[13], p[14], p[15]);
            }

            std::string getBaseboard() {
                BYTE buf[65536] = { 0 };

                size_t RSMBSize = hash_GetSystemFirmwareTable('RSMB', 0, 0, 0);
                if (!RSMBSize) {
                    LOG(strEnc("Failed to get size of baseboard!\n"));
                    return "";
                }

                RSMBSize = hash_GetSystemFirmwareTable('RSMB', 0, buf, RSMBSize);
                if (!RSMBSize) {
                    LOG(strEnc("Failed to get baseboard!\n"));
                    return "";
                }

                RawSMBIOSData* biosData = (RawSMBIOSData*)buf;
                if (biosData->Length != RSMBSize - 8) {
                    LOG(strEnc("Smbios length error\n"));
                    return "";
                }

                BYTE* p = biosData->SMBIOSTableData;
                std::string serial = "";
                for (int i = 0; i < biosData->Length; i++) {
                    dmi_header* h = (dmi_header*)p;

                    if (h->type == 1) {
                        serial += dmi_string(h, p[0x7]);
                        serial += strEnc("_");
                        serial += dmi_system_uuid(p + 0x8, biosData->SMBIOSMajorVersion * 0x100 + biosData->SMBIOSMinorVersion);
                    }

                    p += h->length;
                    while ((*(WORD*)p) != 0) p++;
                    p += 2;
                }
                return serial;
            }
        }
    }
}