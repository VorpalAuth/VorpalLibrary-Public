/**
* Copyright (C) 2023 Vorpal. All rights reserved.
*
* Licensed under the Vorpal Library Software License. You may obtain a copy
* in the file "LICENSE" found at the root of this repository.
*/

#include "common.h"

namespace VorpalAPI {


	namespace SecurityChecks {
		bool IsInLegitModule(uintptr_t rip);
		bool CheckReturnAddress();
		bool IsFunctionExportAddrLegit(HMODULE mod, std::string function, uint64_t addr);
		void CheckDriverBlacklist();
		void OnBoot(bool vm);
	}
}