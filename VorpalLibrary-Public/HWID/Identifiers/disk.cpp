/**
* Copyright (C) 2023 Vorpal. All rights reserved.
*
* Licensed under the Vorpal Library Software License. You may obtain a copy
* in the file "LICENSE" found at the root of this repository.
*/

#include "common.h"
#include "disk.h"

//TODO since this is for Windows specific, change the winapi we call to our function hasher when we have time.
namespace VorpalAPI {
    namespace HWID {
        namespace DISK {

            std::string getDiskSerial() {

                HANDLE hand = hash_CreateFileW(L"\\\\.\\PhysicalDrive0", 0, FILE_SHARE_READ | FILE_SHARE_WRITE, NULL, OPEN_EXISTING, 0, NULL);
                if (hand == INVALID_HANDLE_VALUE)
                    return {};

                std::unique_ptr<std::remove_pointer<HANDLE>::type, void(*)(HANDLE)> hDevice{ hand, [](HANDLE handle) {
                    hash_CloseHandle(handle);
                } };

                STORAGE_PROPERTY_QUERY storagePropertyQuery{};
                storagePropertyQuery.PropertyId = StorageDeviceProperty;
                storagePropertyQuery.QueryType = PropertyStandardQuery;
                STORAGE_DESCRIPTOR_HEADER storageDescriptorHeader{};

                DWORD dwBytesReturned = 0;
                if (!hash_DeviceIoControl(hDevice.get(), IOCTL_STORAGE_QUERY_PROPERTY, &storagePropertyQuery, sizeof(STORAGE_PROPERTY_QUERY), &storageDescriptorHeader, sizeof(STORAGE_DESCRIPTOR_HEADER), &dwBytesReturned, NULL))
                    return {};

                const DWORD dwOutBufferSize = storageDescriptorHeader.Size;
                std::unique_ptr<BYTE[]> pOutBuffer{ new BYTE[dwOutBufferSize]{} };

                if (!hash_DeviceIoControl(hDevice.get(), IOCTL_STORAGE_QUERY_PROPERTY, &storagePropertyQuery, sizeof(STORAGE_PROPERTY_QUERY), pOutBuffer.get(), dwOutBufferSize, &dwBytesReturned, NULL))
                    return {};

                STORAGE_DEVICE_DESCRIPTOR* pDeviceDescriptor = reinterpret_cast<STORAGE_DEVICE_DESCRIPTOR*>(pOutBuffer.get());
                const DWORD dwSerialNumberOffset = pDeviceDescriptor->SerialNumberOffset;

                if (dwSerialNumberOffset == 0)
                    return {};

                const char* serialNumber = reinterpret_cast<const char*>(pOutBuffer.get() + dwSerialNumberOffset);

                return serialNumber;
            }
        }
    }
}