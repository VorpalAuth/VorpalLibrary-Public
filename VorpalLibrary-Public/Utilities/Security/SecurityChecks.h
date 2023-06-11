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