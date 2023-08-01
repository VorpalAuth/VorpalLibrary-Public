/**
* Copyright (C) 2023 Vorpal. All rights reserved.
*
* Licensed under the Vorpal Library Software License. You may obtain a copy
* in the file "LICENSE" found at the root of this repository.
*/

#include "common.h"
#include "crt.h"


namespace Utils {
    namespace CRT {
        namespace String {
            static inline unsigned int _strnlen_s(const char* str, size_t maxsize) {
                const char* s;
                for (s = str; *s && maxsize--; ++s);
                return (unsigned int)(s - str);
            }

            char* myStrncpy(char* dst, const char* src, unsigned long long num) {
                size_t i = 0;
                while (i++ != num && (*dst++ = *src++));

                return dst;
            }

            int myStrncmp(const char* s1, const char* s2, size_t n) {
                while (n && *s1 && (*s1 == *s2)) {
                    ++s1;
                    ++s2;
                    --n;
                }
                if (n == 0) {
                    return 0;
                }
                else {
                    return (*(unsigned char*)s1 - *(unsigned char*)s2);
                }
            }

            char* myStrStr(char* str, char* substr) {
                static char* ptr;

                ptr = str;

                while (*ptr) {
                    if (myStrncmp(ptr, substr, _strnlen_s(substr, sizeof substr)) == 0)
                        return ptr;
                    ptr++;
                }
                return NULL;
            }

            std::string ws2s(const std::wstring& wstr) {
                std::string str(wstr.begin(), wstr.end());
                return str;
            }
        }

        namespace Memory {
            // custom implementation of memset/memmove.
            // I've opted for __stosb / __movsb due to the REPNE STOSB / REPNE MOVSB
            // code output. Honestly, this is as good as we'll get in terms of size.
            __declspec(noinline) void* __crt_memset(void* dst, uint8_t value, size_t size) {
                uint8_t* dest = reinterpret_cast<uint8_t*>(dst);

                if (dest)
                    __stosb(dest, value, size);

                return dst;
            }
            //Couldn't get __movsb to work for memmove (memcpy), so going with this C styled version
            void __crt_memmove(void* dest, void* src, size_t n)
            {
                char* csrc = (char*)src;
                char* cdest = (char*)dest;

                for (int i = 0; i < n; i++)
                    cdest[i] = csrc[i];
            }

            //Thankyou reactos
            int myMemcmp(const void* s1, const void* s2, size_t n)
            {
                if (n != 0) {
                    const unsigned char* p1 = (const unsigned char*)s1, * p2 = (const unsigned char*)s2;
                    do {
                        if (*p1++ != *p2++)
                            return (*--p1 - *--p2);
                    } while (--n != 0);
                }
                return 0;
            }

            void* myMemset(void* dst, int val, size_t size) { 
                return __crt_memset(dst, static_cast<uint8_t>(val), size); 
            }

            void myMemcpy(void* dst, void* src, size_t size) { 
                return __crt_memmove(dst, src, size); 
            }
        }
    }
}