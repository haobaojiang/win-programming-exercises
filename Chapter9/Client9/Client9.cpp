// Client8.cpp : This file contains the 'main' function. Program execution begins and ends there.
//

#include <windows.h>
#include <string>
#include "../Driveri9/common.h"
#include "../../wil/include/wil/resource.h"


int Error(const char* msg) {
	printf("%s (Error: %d)\n", msg, ::GetLastError());
	return 1;
}





int main()
{
	wil::unique_hfile hFiile(CreateFile(CLIENT_SYM_LINK_NAME, GENERIC_READ | GENERIC_WRITE, 0, nullptr, OPEN_EXISTING, 0, nullptr));
	if (!hFiile) {
		return Error("Failed to open device");
	}


	/*
	9.2 Implement a driver that protects a registry key from modifications.
	    A client can send the driver registry keys to protect or unprotect.
	*/
	{
		DWORD bytesReturn;
		RegKeyProtectInfo info;
		wcscpy_s(info.KeyName, _countof(info.KeyName), L"\\REGISTRY\\USER\\S-1-5-21-1140183434-2069593765-52490107-500\\Software\\360Safe");
		auto success = DeviceIoControl(hFiile.get(), IOCTL_REG_PROTECT_ADD, &info, sizeof(info), nullptr, 0, &bytesReturn, nullptr);
		if (!success) {
			return Error("Failed in DeviceIoControl");
		}
	}

	/*
	9.3 Implement a driver that redirects registry write operations coming from selected processes (configured by a client application) 
	    to their own private key if they access HKEY_LOCAL_MACHINE. If the app is writing data, it goes to its private store. 
		If it¡¯s reading data, first check the private store, and if no value is there go to the real registry key. 
		This is one facet of application sandboxing.
	*/
	{
		DWORD bytesReturn;
		RegRedirectInfo info;
		wcscpy_s(info.ProcessName, _countof(info.ProcessName), L"c:\\windows\\regedit.exe");
		auto success = DeviceIoControl(hFiile.get(), IOCTL_REG_KEY_REDIRCT_ADD, &info, sizeof(info), nullptr, 0, &bytesReturn, nullptr);
		if (!success) {
			return Error("Failed in DeviceIoControl");
		}
	}


	while (true)
	{
		Sleep(5000);
	}


}

