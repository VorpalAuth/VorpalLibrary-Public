#pragma once
#include <WinTrust.h>
typedef HANDLE          HCATADMIN;
typedef HANDLE          HCATINFO;

extern void hash_Sleep(DWORD dwMilliseconds);
extern bool hash_IsDebuggerPresent();
extern HANDLE hash_GetCurrentProcess();
extern BOOL hash_CloseHandle(HANDLE hObject);
extern BOOL hash_SetThreadContext(HANDLE hThread, const CONTEXT* lpContext);
extern BOOL hash_GetThreadContext(HANDLE hThread, LPCONTEXT lpContext);
extern bool hash_GetSystemFirmwareTable(DWORD FirmwareTableProviderSignature, DWORD FirmwareTableID, PVOID pFirmwareTableBuffer, DWORD BufferSize);
extern HANDLE hash_CreateFileW(LPCWSTR lpFileName, DWORD dwDesiredAccess, DWORD dwShareMode, LPSECURITY_ATTRIBUTES lpSecurityAttributes, DWORD dwCreationDisposition, DWORD dwFlagsAndAttributes, HANDLE hTemplateFile);
extern bool hash_NtQueryInformationProcess(HANDLE ProcessHandle, int ProcessInformationClass, PVOID ProcessInformation, ULONG ProcessInformationLength, PULONG ReturnLength);
extern uint64_t hash_NtQuerySystemInformation(ULONG SystemInformationClass, PVOID SystemInformation, ULONG SystemInformationLength, PULONG ReturnLength);
extern BOOL hash_DeviceIoControl(HANDLE hDevice, DWORD dwIoControlCode, LPVOID lpInBuffer, DWORD nInBufferSize, LPVOID lpOutBuffer, DWORD nOutBufferSize, LPDWORD lpBytesReturned, LPOVERLAPPED lpOverlapped);
extern BOOL hash_QueryPerformanceFrequency(LARGE_INTEGER* lpFrequency);
extern BOOL hash_QueryPerformanceCounter(LARGE_INTEGER* lpPerformanceCount);
extern int hash_GetSystemMetrics(int nIndex);
extern PVOID hash_AddVectoredExceptionHandler(ULONG First, PVECTORED_EXCEPTION_HANDLER Handler);
extern ULONG hash_RemoveVectoredExceptionHandler(PVOID Handle);

extern BOOL hash_GetWindowRect(_In_ HWND hWnd, _Out_ LPRECT lpRect);
extern BOOL hash_SetWindowPos(_In_ HWND hWnd, _In_opt_ HWND hWndInsertAfter, _In_ int X, _In_ int Y, _In_ int cx, _In_ int cy, _In_ UINT uFlags);
extern BOOL hash_GetCursorPos(_Out_ LPPOINT lpPoint);
extern ATOM hash_RegisterClassExW(_In_ CONST WNDCLASSEXW* a);
extern HWND hash_CreateWindowExW(_In_ DWORD dwExStyle, _In_opt_ LPCWSTR lpClassName, _In_opt_ LPCWSTR lpWindowName, _In_ DWORD dwStyle, _In_ int X, _In_ int Y, _In_ int nWidth, _In_ int nHeight, _In_opt_ HWND hWndParent, _In_opt_ HMENU hMenu, _In_opt_ HINSTANCE hInstance, _In_opt_ LPVOID lpParam);
extern ULONGLONG hash_GetTickCount64();
extern HMODULE hash_GetModuleHandleW(LPCWSTR lpModuleName);
extern HINSTANCE hash_ShellExecuteA(HWND hwnd, LPCSTR lpOperation, LPCSTR lpFile, LPCSTR lpParameters, LPCSTR lpDirectory, INT nShowCmd);
extern BOOL hash_PeekMessageA(_Out_ LPMSG lpMsg, _In_opt_ HWND hWnd, _In_ UINT wMsgFilterMin, _In_ UINT wMsgFilterMax, _In_ UINT wRemoveMsg);
extern BOOL hash_TranslateMessage(_In_ CONST MSG* lpMsg);
extern LRESULT hash_DispatchMessageA(_In_ CONST MSG* lpMsg);
extern BOOL hash_UpdateWindow(_In_ HWND hWnd);
extern BOOL hash_ShowWindow(_In_ HWND hWnd, _In_ int nCmdShow);

extern NTSTATUS hash_NtSetInformationThread(HANDLE ThreadHandle, UINT ThreadInformationClass, PVOID ThreadInformation, ULONG ThreadInformationLength);

extern BOOL hash_UnmapViewOfFile(LPCVOID lpBaseAddress);
extern LPVOID hash_MapViewOfFile(HANDLE hFileMappingObject, DWORD dwDesiredAccess, DWORD dwFileOffsetHigh, DWORD dwFileOffsetLow, SIZE_T dwNumberOfBytesToMap);
extern HANDLE hash_CreateFileMappingW(HANDLE hFile, LPSECURITY_ATTRIBUTES lpFileMappingAttributes, DWORD flProtect, DWORD dwMaximumSizeHigh, DWORD dwMaximumSizeLow, LPCWSTR lpName);
extern BOOL hash_QueryFullProcessImageNameW(HANDLE hProcess, DWORD dwFlags, LPWSTR lpExeName, PDWORD lpdwSize);









//extern DWORD hash_GetDeviceDriverBaseNameW(LPVOID ImageBase, LPWSTR lpBaseName, DWORD nSize);
//extern BOOL hash_EnumDeviceDrivers(LPVOID* lpImageBase, DWORD cb, LPDWORD lpcbNeeded);











