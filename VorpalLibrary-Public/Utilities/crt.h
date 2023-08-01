/**
* Copyright (C) 2023 Vorpal. All rights reserved.
*
* Licensed under the Vorpal Library Software License. You may obtain a copy
* in the file "LICENSE" found at the root of this repository.
*/

#pragma once
namespace Utils {
    namespace CRT {
        namespace String {
            extern inline unsigned int _strnlen_s(const char* str, size_t maxsize);

            extern char* myStrncpy(char* dst, const char* src, unsigned long long num);

            extern int myStrncmp(const char* s1, const char* s2, size_t n);

            extern char* myStrStr(char* str, char* substr);

            extern std::string ws2s(const std::wstring& wstr);
        }

        namespace Memory {
            extern void* myMemset(void* dst, int val, size_t size);

            extern void myMemcpy(void* dst, void* src, size_t size);

            extern int myMemcmp(const void* s1, const void* s2, size_t n);
        }
    }
}

#define myRtlZeroMemory(Destination,Length) Utils::CRT::Memory::myMemset((Destination),0,(Length))