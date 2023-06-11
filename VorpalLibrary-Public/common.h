#pragma once

#ifndef WIN32_LEAN_AND_MEAN
#define WIN32_LEAN_AND_MEAN
#endif

#define CPPHTTPLIB_NO_EXCEPTIONS
#define CPPHTTPLIB_OPENSSL_SUPPORT

#include <iostream>
#include <string>
#include <memory>
#include <Windows.h>
#include <intrin.h> //instructions
#include <stdexcept>
#include <vector>
#include <locale>
#include <list>
#include <sstream>
#include <iomanip>
#include <winioctl.h>
#include <unordered_map>
#include <mutex>
#include <codecvt>
#include <functional>
#include <set>
#include <map>
#include <array>
#include <stdio.h>

#pragma comment(lib, "Ws2_32.lib")

//Botan
#include "botan/pipe.h"
#include <botan/hex.h>
#include <botan/base64.h>
#include <botan/filters.h>
#include <botan/auto_rng.h>
#include <botan/block_cipher.h>
#include <botan/symkey.h>
#include <botan/base64.h>
#include <botan/pk_keys.h>
#include <botan/pkcs8.h>
#include <botan/pubkey.h>
#include <botan/rng.h>

#include "t1ha.h"
#include "Utilities/functionHash/winApi/hashWork.h"

#include "Utilities/Obfuscation/CompileTime/xorstr.hpp"

#include "Utilities/Memory/Threads.h"

//comment to not use cert pinning
#define CERT_PINNING

#define strEnc(...) xorstr_(__VA_ARGS__)
#define intEnc(...) 

//#define DEBUG_INFO
#ifdef DEBUG_INFO
#define LOG(fmt, ...) std::printf(fmt, ##__VA_ARGS__)
#define LOGW(fmt, ...) std::wprintf(fmt, ##__VA_ARGS__)
#else
#define LOG
#define LOGW
#endif

#define STRONG_SEED 10376313370251892926