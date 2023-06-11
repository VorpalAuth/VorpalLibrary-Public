#include "common.h"

#include "exportWork.h"

void (WINAPI* temp_Sleep)(DWORD dwMilliseconds) = nullptr;
bool (WINAPI* temp_IsDebuggerPresent)() = nullptr;
uint64_t(WINAPI* temp_NtQueryInformationProcess)(HANDLE ProcessHandle, int ProcessInformationClass, PVOID ProcessInformation, ULONG ProcessInformationLength, PULONG ReturnLength) = nullptr;
uint64_t(WINAPI* temp_NtQuerySystemInformation)(ULONG SystemInformationClass, PVOID                    SystemInformation, ULONG                    SystemInformationLength, PULONG                   ReturnLength) = nullptr;
HANDLE(WINAPI* temp_GetCurrentProcess)() = nullptr;
BOOL(WINAPI* temp_CloseHandle)(HANDLE hObject) = nullptr;
BOOL(WINAPI* temp_GetThreadContext)(HANDLE hThread, LPCONTEXT lpContext);
BOOL(WINAPI* temp_SetThreadContext)(HANDLE hThread, const CONTEXT* lpContext);
HANDLE(WINAPI* temp_CreateFileW)(LPCWSTR lpFileName, DWORD dwDesiredAccess, DWORD dwShareMode, LPSECURITY_ATTRIBUTES lpSecurityAttributes, DWORD dwCreationDisposition,  DWORD dwFlagsAndAttributes, HANDLE hTemplateFile);
UINT(WINAPI* temp_GetSystemFirmwareTable)(DWORD FirmwareTableProviderSignature, DWORD FirmwareTableID, PVOID pFirmwareTableBuffer, DWORD BufferSize);
BOOL(WINAPI* temp_DeviceIoControl)(HANDLE hDevice, DWORD dwIoControlCode, LPVOID lpInBuffer, DWORD nInBufferSize, LPVOID lpOutBuffer, DWORD nOutBufferSize, LPDWORD lpBytesReturned, LPOVERLAPPED lpOverlapped);
BOOL(WINAPI* temp_QueryPerformanceFrequency)(LARGE_INTEGER* lpFrequency) = nullptr;
BOOL(WINAPI* temp_QueryPerformanceCounter)(LARGE_INTEGER* lpPerformanceCount) = nullptr;
int(WINAPI* temp_GetSystemMetrics)(int nIndex) = nullptr;
PVOID(WINAPI* temp_AddVectoredExceptionHandler)(ULONG First, PVECTORED_EXCEPTION_HANDLER Handler) = nullptr;
ULONG(WINAPI* temp_RemoveVectoredExceptionHandler)(PVOID Handle) = nullptr;
BOOL(WINAPI* temp_GetCursorPos)(_Out_ LPPOINT lpPoint) = nullptr;
BOOL(WINAPI* temp_SetWindowPos)(_In_ HWND hWnd, _In_opt_ HWND hWndInsertAfter, _In_ int X, _In_ int Y, _In_ int cx, _In_ int cy, _In_ UINT uFlags) = nullptr;
BOOL(WINAPI* temp_GetWindowRect)(_In_ HWND hWnd, _Out_ LPRECT lpRect) = nullptr;
ATOM(WINAPI* temp_RegisterClassExW)(_In_ CONST WNDCLASSEXW*) = nullptr;
HWND(WINAPI* temp_CreateWindowExW)(_In_ DWORD dwExStyle, _In_opt_ LPCWSTR lpClassName, _In_opt_ LPCWSTR lpWindowName, _In_ DWORD dwStyle, _In_ int X, _In_ int Y, _In_ int nWidth, _In_ int nHeight, _In_opt_ HWND hWndParent, _In_opt_ HMENU hMenu, _In_opt_ HINSTANCE hInstance, _In_opt_ LPVOID lpParam) = nullptr;
ULONGLONG(WINAPI* temp_GetTickCount64)() = nullptr;
HMODULE(WINAPI* temp_GetModuleHandleW)(LPCWSTR lpModuleName) = nullptr;
HINSTANCE(WINAPI* temp_ShellExecuteA)(HWND hwnd, LPCSTR lpOperation, LPCSTR lpFile, LPCSTR lpParameters, LPCSTR lpDirectory, INT nShowCmd) = nullptr;
BOOL(WINAPI* temp_PeekMessageA)(_Out_ LPMSG lpMsg, _In_opt_ HWND hWnd, _In_ UINT wMsgFilterMin, _In_ UINT wMsgFilterMax, _In_ UINT wRemoveMsg) = nullptr;
LRESULT(WINAPI* temp_DispatchMessageA)(_In_ CONST MSG* lpMsg) = nullptr;
BOOL(WINAPI* temp_TranslateMessage)(_In_ CONST MSG* lpMsg) = nullptr;
BOOL(WINAPI* temp_UpdateWindow)(_In_ HWND hWnd) = nullptr;
BOOL(WINAPI* temp_ShowWindow)(_In_ HWND hWnd, _In_ int nCmdShow) = nullptr;
NTSTATUS(WINAPI * temp_NtSetInformationThread)(HANDLE ThreadHandle, UINT ThreadInformationClass, PVOID ThreadInformation, ULONG ThreadInformationLength) = nullptr;
BOOL(WINAPI* temp_UnmapViewOfFile)(LPCVOID lpBaseAddress) = nullptr;
LPVOID(WINAPI* temp_MapViewOfFile)(HANDLE hFileMappingObject, DWORD dwDesiredAccess, DWORD dwFileOffsetHigh, DWORD dwFileOffsetLow, SIZE_T dwNumberOfBytesToMap) = nullptr;
HANDLE(WINAPI* temp_CreateFileMappingW)(HANDLE hFile, LPSECURITY_ATTRIBUTES lpFileMappingAttributes, DWORD flProtect, DWORD dwMaximumSizeHigh, DWORD dwMaximumSizeLow, LPCWSTR lpName) = nullptr;
BOOL(WINAPI* temp_QueryFullProcessImageNameW)(HANDLE hProcess, DWORD dwFlags, LPWSTR lpExeName, PDWORD lpdwSize) = nullptr;

using namespace VorpalAPI;

BOOL hash_QueryFullProcessImageNameW(HANDLE hProcess, DWORD dwFlags, LPWSTR lpExeName, PDWORD lpdwSize) {
    std::string func = strEnc("QueryFullProcessImageNameW");
    const auto _hash = t1ha0(func.c_str(), func.size(), STRONG_SEED);
    temp_QueryFullProcessImageNameW = static_cast<BOOL(WINAPI*)(HANDLE, DWORD, LPWSTR, PDWORD)>(getApi(_hash, xorstr_("Kernel32.dll"), func.size(), STRONG_SEED));

    return temp_QueryFullProcessImageNameW(hProcess, dwFlags, lpExeName, lpdwSize);
}

HANDLE hash_CreateFileMappingW(HANDLE hFile, LPSECURITY_ATTRIBUTES lpFileMappingAttributes, DWORD flProtect, DWORD dwMaximumSizeHigh, DWORD dwMaximumSizeLow, LPCWSTR lpName) {
    std::string func = strEnc("CreateFileMappingW");
    const auto _hash = t1ha0(func.c_str(), func.size(), STRONG_SEED);
    temp_CreateFileMappingW = static_cast<HANDLE(WINAPI*)(HANDLE, LPSECURITY_ATTRIBUTES, DWORD, DWORD, DWORD, LPCWSTR)>(getApi(_hash, xorstr_("Kernel32.dll"), func.size(), STRONG_SEED));

    return temp_CreateFileMappingW(hFile, lpFileMappingAttributes, flProtect, dwMaximumSizeHigh, dwMaximumSizeLow, lpName);
}

LPVOID hash_MapViewOfFile(HANDLE hFileMappingObject, DWORD dwDesiredAccess, DWORD dwFileOffsetHigh, DWORD dwFileOffsetLow, SIZE_T dwNumberOfBytesToMap) {
    std::string func = strEnc("MapViewOfFile");
    const auto _hash = t1ha0(func.c_str(), func.size(), STRONG_SEED);
    temp_MapViewOfFile = static_cast<LPVOID(WINAPI*)(HANDLE, DWORD, DWORD, DWORD, SIZE_T)>(getApi(_hash, xorstr_("Kernel32.dll"), func.size(), STRONG_SEED));

    return temp_MapViewOfFile(hFileMappingObject, dwDesiredAccess, dwFileOffsetHigh, dwFileOffsetLow, dwNumberOfBytesToMap);
}

BOOL hash_UnmapViewOfFile(LPCVOID lpBaseAddress) {
    std::string func = strEnc("UnmapViewOfFile");
    const auto _hash = t1ha0(func.c_str(), func.size(), STRONG_SEED);
    temp_UnmapViewOfFile = static_cast<BOOL(WINAPI*)(LPCVOID)>(getApi(_hash, xorstr_("Kernel32.dll"), func.size(), STRONG_SEED));

    return temp_UnmapViewOfFile(lpBaseAddress);
}

NTSTATUS hash_NtSetInformationThread(HANDLE ThreadHandle, UINT ThreadInformationClass, PVOID ThreadInformation, ULONG ThreadInformationLength) {
    std::string func = strEnc("NtSetInformationThread");
    const auto _hash = t1ha0(func.c_str(), func.size(), STRONG_SEED);
    temp_NtSetInformationThread = static_cast<NTSTATUS(WINAPI*)(HANDLE, UINT, PVOID, ULONG)>(getApi(_hash, xorstr_("ntdll.dll"), func.size(), STRONG_SEED));

    return temp_NtSetInformationThread(ThreadHandle, ThreadInformationClass, ThreadInformation, ThreadInformationLength);
}

BOOL hash_UpdateWindow(_In_ HWND hWnd) {
    std::string func = strEnc("UpdateWindow");
    const auto _hash = t1ha0(func.c_str(), func.size(), STRONG_SEED);
    temp_UpdateWindow = static_cast<BOOL(WINAPI*)(HWND)>(getApi(_hash, xorstr_("User32.dll"), func.size(), STRONG_SEED));

    return temp_UpdateWindow(hWnd);
}

BOOL hash_ShowWindow(_In_ HWND hWnd, _In_ int nCmdShow) {
    std::string func = strEnc("ShowWindow");
    const auto _hash = t1ha0(func.c_str(), func.size(), STRONG_SEED);
    temp_ShowWindow = static_cast<BOOL(WINAPI*)(HWND, int)>(getApi(_hash, xorstr_("User32.dll"), func.size(), STRONG_SEED));

    return temp_ShowWindow(hWnd, nCmdShow);
}

BOOL hash_TranslateMessage(_In_ CONST MSG* lpMsg) {
    std::string func = strEnc("TranslateMessage");
    const auto _hash = t1ha0(func.c_str(), func.size(), STRONG_SEED);
    if(!temp_TranslateMessage)
    temp_TranslateMessage = static_cast<BOOL(WINAPI*)(CONST MSG*)>(getApi(_hash, xorstr_("User32.dll"), func.size(), STRONG_SEED));

    return temp_TranslateMessage(lpMsg);
}

LRESULT hash_DispatchMessageA(_In_ CONST MSG* lpMsg) {
    std::string func = strEnc("DispatchMessageA");
    const auto _hash = t1ha0(func.c_str(), func.size(), STRONG_SEED);
    if(!temp_DispatchMessageA)
    temp_DispatchMessageA = static_cast<LRESULT(WINAPI*)(CONST MSG*)>(getApi(_hash, xorstr_("User32.dll"), func.size(), STRONG_SEED));

    return temp_DispatchMessageA(lpMsg);
}

BOOL hash_PeekMessageA(_Out_ LPMSG lpMsg, _In_opt_ HWND hWnd, _In_ UINT wMsgFilterMin, _In_ UINT wMsgFilterMax, _In_ UINT wRemoveMsg) {

    std::string func = strEnc("PeekMessageA");
    const auto _hash = t1ha0(func.c_str(), func.size(), STRONG_SEED);
    if(!temp_PeekMessageA)
    temp_PeekMessageA = static_cast<BOOL(WINAPI*)(LPMSG, HWND, UINT, UINT, UINT)>(getApi(_hash, xorstr_("User32.dll"), func.size(), STRONG_SEED));

    return temp_PeekMessageA(lpMsg, hWnd, wMsgFilterMin, wMsgFilterMax, wRemoveMsg);
}

HINSTANCE hash_ShellExecuteA(HWND hwnd, LPCSTR lpOperation, LPCSTR lpFile, LPCSTR lpParameters, LPCSTR lpDirectory, INT nShowCmd) {
    std::string func = strEnc("ShellExecuteA");
    const auto _hash = t1ha0(func.c_str(), func.size(), STRONG_SEED);
    temp_ShellExecuteA = static_cast<HINSTANCE(WINAPI*)(HWND, LPCSTR, LPCSTR, LPCSTR, LPCSTR, INT)>(getApi(_hash, strEnc("shell32.dll"), func.size(), STRONG_SEED));

    return temp_ShellExecuteA(hwnd, lpOperation, lpFile, lpParameters, lpDirectory, nShowCmd);
}

HMODULE hash_GetModuleHandleW(LPCWSTR lpModuleName) {
    std::string func = strEnc("GetModuleHandleW");
    const auto _hash = t1ha0(func.c_str(), func.size(), STRONG_SEED);
    temp_GetModuleHandleW = static_cast<HMODULE(WINAPI*)(LPCWSTR)>(getApi(_hash, strEnc("kernel32.dll"), func.size(), STRONG_SEED));

    return temp_GetModuleHandleW(lpModuleName);
}

ULONGLONG hash_GetTickCount64() {
    std::string func = strEnc("GetTickCount64");
    const auto _hash = t1ha0(func.c_str(), func.size(), STRONG_SEED);
    temp_GetTickCount64 = static_cast<ULONGLONG(WINAPI*)()>(getApi(_hash, strEnc("kernel32.dll"), func.size(), STRONG_SEED));

    return temp_GetTickCount64();
}

BOOL hash_GetCursorPos(_Out_ LPPOINT lpPoint) {

    std::string func = strEnc("GetCursorPos");
    const auto _hash = t1ha0(func.c_str(), func.size(), STRONG_SEED);
    temp_GetCursorPos = static_cast<BOOL(WINAPI*)(LPPOINT)>(getApi(_hash, strEnc("User32.dll"), func.size(), STRONG_SEED));

    return temp_GetCursorPos(lpPoint);
}

BOOL hash_SetWindowPos(_In_ HWND hWnd, _In_opt_ HWND hWndInsertAfter, _In_ int X, _In_ int Y, _In_ int cx, _In_ int cy, _In_ UINT uFlags) {
    std::string func = strEnc("SetWindowPos");
    const auto _hash = t1ha0(func.c_str(), func.size(), STRONG_SEED);
    temp_SetWindowPos = static_cast<BOOL(WINAPI*)(HWND, HWND, int, int, int, int, UINT)>(getApi(_hash, strEnc("User32.dll"), func.size(), STRONG_SEED));

    return temp_SetWindowPos(hWnd, hWndInsertAfter, X, Y, cx, cy, uFlags);
}

BOOL hash_GetWindowRect(_In_ HWND hWnd, _Out_ LPRECT lpRect) {

    std::string func = strEnc("GetWindowRect");
    const auto _hash = t1ha0(func.c_str(), func.size(), STRONG_SEED);

    temp_GetWindowRect = static_cast<BOOL(WINAPI*)(HWND, LPRECT)>(getApi(_hash, strEnc("User32.dll"), func.size(), STRONG_SEED));

    return temp_GetWindowRect(hWnd, lpRect);
}

ATOM hash_RegisterClassExW(_In_ CONST WNDCLASSEXW* a) {
    std::string  func = strEnc("RegisterClassExW");
    const auto _hash = t1ha0(func.c_str(), func.size(), STRONG_SEED);
    temp_RegisterClassExW = static_cast<ATOM(WINAPI*)(CONST WNDCLASSEXW*)>(getApi(_hash, strEnc("User32.dll"), func.size(), STRONG_SEED));

    return temp_RegisterClassExW(a);
}

HWND hash_CreateWindowExW(_In_ DWORD dwExStyle, _In_opt_ LPCWSTR lpClassName, _In_opt_ LPCWSTR lpWindowName, _In_ DWORD dwStyle, _In_ int X, _In_ int Y, _In_ int nWidth, _In_ int nHeight, _In_opt_ HWND hWndParent, _In_opt_ HMENU hMenu, _In_opt_ HINSTANCE hInstance, _In_opt_ LPVOID lpParam) {
    std::string func = strEnc("CreateWindowExW");
    const auto _hash = t1ha0(func.c_str(), func.size(), STRONG_SEED);
    temp_CreateWindowExW = static_cast<HWND(WINAPI*)(DWORD, LPCWSTR, LPCWSTR, DWORD, int, int, int, int, HWND, HMENU, HINSTANCE, LPVOID)>(getApi(_hash, strEnc("User32.dll"), func.size(), STRONG_SEED));

    return temp_CreateWindowExW(dwExStyle, lpClassName, lpWindowName, dwStyle, X, Y, nWidth, nHeight, hWndParent, hMenu, hInstance, lpParam);
}


//BOOL(WINAPI* temp_EnumDeviceDrivers)(LPVOID* lpImageBase, DWORD cb, LPDWORD lpcbNeeded) = nullptr;
//DWORD(WINAPI* temp_GetDeviceDriverBaseNameW)(LPVOID ImageBase, LPWSTR lpBaseName, DWORD nSize) = nullptr;


//DWORD hash_GetDeviceDriverBaseNameW(LPVOID ImageBase, LPWSTR lpBaseName, DWORD nSize) {
//    std::string func = strEnc("GetDeviceDriverBaseNameW");
//    const auto _hash = t1ha0(func.c_str(), func.size(), STRONG_SEED);
//    temp_GetDeviceDriverBaseNameW = static_cast<DWORD(WINAPI*)(LPVOID, LPWSTR, DWORD)>(getApi(_hash, strEnc("kernel32.dll"), func.size(), STRONG_SEED));
//
//    return temp_GetDeviceDriverBaseNameW(ImageBase, lpBaseName, nSize);
//}

//BOOL hash_EnumDeviceDrivers(LPVOID* lpImageBase, DWORD cb, LPDWORD lpcbNeeded) {
//    std::string func = strEnc("EnumDeviceDrivers");
//    const auto _hash = t1ha0(func.c_str(), func.size(), STRONG_SEED);
//    temp_EnumDeviceDrivers = static_cast<BOOL(WINAPI*)(LPVOID*, DWORD, LPDWORD)>(getApi(_hash, strEnc("kernel32.dll"), func.size(), STRONG_SEED));
//
//    return temp_EnumDeviceDrivers(lpImageBase, cb, lpcbNeeded);
//}

ULONG hash_RemoveVectoredExceptionHandler(PVOID Handle) {
    std::string func = strEnc("RemoveVectoredExceptionHandler");
    const auto _hash = t1ha0(func.c_str(), func.size(), STRONG_SEED);
    temp_RemoveVectoredExceptionHandler = static_cast<ULONG(WINAPI*)(PVOID)>(getApi(_hash, strEnc("kernel32.dll"), func.size(), STRONG_SEED));

    return temp_RemoveVectoredExceptionHandler(Handle);
}

PVOID hash_AddVectoredExceptionHandler(ULONG First, PVECTORED_EXCEPTION_HANDLER Handler) {
    std::string func = strEnc("AddVectoredExceptionHandler");
    const auto _hash = t1ha0(func.c_str(), func.size(), STRONG_SEED);
    temp_AddVectoredExceptionHandler = static_cast<PVOID(WINAPI*)(ULONG, PVECTORED_EXCEPTION_HANDLER)>(getApi(_hash, strEnc("kernel32.dll"), func.size(), STRONG_SEED));

    return temp_AddVectoredExceptionHandler(First, Handler);
}

int hash_GetSystemMetrics(int nIndex) {
    std::string func = strEnc("GetSystemMetrics");
    const auto _hash = t1ha0(func.c_str(), func.size(), STRONG_SEED);
    temp_GetSystemMetrics = static_cast<int(WINAPI*)(int)>(getApi(_hash, strEnc("user32.dll"), func.size(), STRONG_SEED));

    return temp_GetSystemMetrics(nIndex);
}

BOOL hash_QueryPerformanceCounter(LARGE_INTEGER* lpPerformanceCount) {
    std::string func = strEnc("QueryPerformanceCounter");
    const auto _hash = t1ha0(func.c_str(), func.size(), STRONG_SEED);
    temp_QueryPerformanceCounter = static_cast<BOOL(WINAPI*)(LARGE_INTEGER*)>(getApi(_hash, strEnc("kernel32.dll"), func.size(), STRONG_SEED));

    return temp_QueryPerformanceCounter(lpPerformanceCount);
}

BOOL hash_QueryPerformanceFrequency(LARGE_INTEGER* lpFrequency) {
    std::string func = strEnc("QueryPerformanceFrequency");
    const auto _hash = t1ha0(func.c_str(), func.size(), STRONG_SEED);
    temp_QueryPerformanceFrequency = static_cast<BOOL(WINAPI*)(LARGE_INTEGER*)>(getApi(_hash, strEnc("kernel32.dll"), func.size(), STRONG_SEED));

    return temp_QueryPerformanceFrequency(lpFrequency);
}

void hash_Sleep(DWORD dwMilliseconds) {
    std::string func = strEnc("Sleep");
    const auto _hash = t1ha0(func.c_str(), func.size(), STRONG_SEED);
    temp_Sleep = static_cast<void(WINAPI *)(DWORD)>(getApi(_hash, strEnc("kernel32.dll"), func.size(), STRONG_SEED));

    return temp_Sleep(dwMilliseconds);
}

bool hash_GetSystemFirmwareTable(DWORD FirmwareTableProviderSignature, DWORD FirmwareTableID, PVOID pFirmwareTableBuffer, DWORD BufferSize) {
    std::string func = strEnc("GetSystemFirmwareTable");
    const auto _hash = t1ha0(func.c_str(), func.size(), STRONG_SEED);
    temp_GetSystemFirmwareTable = static_cast<UINT(WINAPI*)(DWORD, DWORD, PVOID, DWORD)>(getApi(_hash, strEnc("kernel32.dll"), func.size(), STRONG_SEED));

    return temp_GetSystemFirmwareTable(FirmwareTableProviderSignature, FirmwareTableID, pFirmwareTableBuffer, BufferSize);
}

BOOL hash_CloseHandle(HANDLE hObject) {
    std::string func = strEnc("CloseHandle");
    const auto _hash = t1ha0(func.c_str(), func.size(), STRONG_SEED);
    temp_CloseHandle = static_cast<BOOL(WINAPI*)(HANDLE)>(getApi(_hash, strEnc("kernel32.dll"), func.size(), STRONG_SEED));

    return temp_CloseHandle(hObject);
}

bool hash_IsDebuggerPresent() {
    std::string func = strEnc("IsDebuggerPresent");
    const auto _hash = t1ha0(func.c_str(), func.size(), STRONG_SEED);
    temp_IsDebuggerPresent = static_cast<bool(WINAPI*)()>(getApi(_hash, strEnc("kernel32.dll"), func.size(), STRONG_SEED));

    return temp_IsDebuggerPresent();
}

HANDLE hash_GetCurrentProcess() {
    std::string func = strEnc("GetCurrentProcess");
    const auto _hash = t1ha0(func.c_str(), func.size(), STRONG_SEED);
    temp_GetCurrentProcess = static_cast<HANDLE(WINAPI*)()>(getApi(_hash, strEnc("kernel32.dll"), func.size(), STRONG_SEED));

    return temp_GetCurrentProcess();
}

BOOL hash_GetThreadContext(HANDLE hThread, LPCONTEXT lpContext) {
    std::string func = strEnc("GetThreadContext");
    const auto _hash = t1ha0(func.c_str(), func.size(), STRONG_SEED);
    temp_GetThreadContext = static_cast<BOOL(WINAPI*)(HANDLE, LPCONTEXT)>(getApi(_hash, strEnc("kernel32.dll"), func.size(), STRONG_SEED));

    return temp_GetThreadContext(hThread, lpContext);
}

BOOL hash_SetThreadContext(HANDLE hThread, const CONTEXT* lpContext) {
    std::string func = strEnc("SetThreadContext");
    const auto _hash = t1ha0(func.c_str(), func.size(), STRONG_SEED);
    temp_SetThreadContext = static_cast<BOOL(WINAPI*)(HANDLE, const CONTEXT*)>(getApi(_hash, strEnc("kernel32.dll"), func.size(), STRONG_SEED));

    return temp_SetThreadContext(hThread, lpContext);
}

HANDLE hash_CreateFileW(LPCWSTR lpFileName, DWORD dwDesiredAccess, DWORD dwShareMode, LPSECURITY_ATTRIBUTES lpSecurityAttributes, DWORD dwCreationDisposition, DWORD dwFlagsAndAttributes, HANDLE hTemplateFile) {
    std::string func = strEnc("CreateFileW");
    const auto _hash = t1ha0(func.c_str(), func.size(), STRONG_SEED);
    temp_CreateFileW = static_cast<HANDLE(WINAPI*)(LPCWSTR, DWORD, DWORD, LPSECURITY_ATTRIBUTES, DWORD, DWORD, HANDLE)>(getApi(_hash, strEnc("kernel32.dll"), func.size(), STRONG_SEED));

    return temp_CreateFileW(lpFileName, dwDesiredAccess, dwShareMode, lpSecurityAttributes, dwCreationDisposition, dwFlagsAndAttributes, hTemplateFile);
}

BOOL hash_DeviceIoControl(HANDLE hDevice, DWORD dwIoControlCode, LPVOID lpInBuffer, DWORD nInBufferSize, LPVOID lpOutBuffer, DWORD nOutBufferSize, LPDWORD lpBytesReturned, LPOVERLAPPED lpOverlapped) {
    std::string func = strEnc("DeviceIoControl");
    const auto _hash = t1ha0(func.c_str(), func.size(), STRONG_SEED);
    temp_DeviceIoControl = static_cast<BOOL(WINAPI*)(HANDLE, DWORD, LPVOID, DWORD, LPVOID, DWORD, LPDWORD, LPOVERLAPPED)>(getApi(_hash, strEnc("kernel32.dll"), func.size(), STRONG_SEED));

    return temp_DeviceIoControl(hDevice, dwIoControlCode, lpInBuffer, nInBufferSize, lpOutBuffer, nOutBufferSize, lpBytesReturned, lpOverlapped);
}


bool hash_NtQueryInformationProcess(HANDLE ProcessHandle, int ProcessInformationClass, PVOID ProcessInformation, ULONG ProcessInformationLength, PULONG ReturnLength) {
    std::string func = strEnc("NtQueryInformationProcess");
    const auto _hash = t1ha0(func.c_str(), func.size(), STRONG_SEED);
    temp_NtQueryInformationProcess = static_cast<uint64_t(WINAPI*)(HANDLE, int, PVOID, ULONG, PULONG)>(getApi(_hash, strEnc("ntdll.dll"), func.size(), STRONG_SEED));

    return temp_NtQueryInformationProcess(ProcessHandle, ProcessInformationClass, ProcessInformation, ProcessInformationLength, ReturnLength);
}


uint64_t hash_NtQuerySystemInformation(ULONG SystemInformationClass, PVOID SystemInformation, ULONG SystemInformationLength, PULONG ReturnLength) {
    std::string func = strEnc("NtQuerySystemInformation");
    const auto _hash = t1ha0(func.c_str(), func.size(), STRONG_SEED);
    temp_NtQuerySystemInformation = static_cast<uint64_t(WINAPI*)(ULONG, PVOID, ULONG, PULONG)>(getApi(_hash, strEnc("ntdll.dll"), func.size(), STRONG_SEED));

    return temp_NtQuerySystemInformation(SystemInformationClass, SystemInformation, SystemInformationLength, ReturnLength);
}