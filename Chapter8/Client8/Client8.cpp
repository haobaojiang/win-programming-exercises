// Client8.cpp : This file contains the 'main' function. Program execution begins and ends there.
//

#include <windows.h>
#include <string>
#include "../Driver8/common.h"
#include "../../wil/include/wil/resource.h"


int Error(const char* msg) {
	printf("%s (Error: %d)\n", msg, ::GetLastError());
	return 1;
}

void DisplayTime(const LARGE_INTEGER& time) {
	SYSTEMTIME st;
	::FileTimeToSystemTime((FILETIME*)& time, &st);
	printf("%02d:%02d:%02d.%03d: ", st.wHour, st.wMinute, st.wSecond, st.wMilliseconds);
}

void DisplayInfo(BYTE* buffer, DWORD size) {
	auto count = size;
	while (count > 0) {
		auto header = (ItemHeader*)buffer;
		switch (header->Type) {

		case ItemType::ProcessCreate:
		{
			DisplayTime(header->Time);
			auto info = (ProcessCreateInfo*)buffer;
			std::wstring commandline((WCHAR*)(buffer + info->CommandLineOffset), info->CommandLineLength);
			printf("Process %d Created. Command line: %ws\n", info->ProcessId, commandline.c_str());
			break;
		}

		case ItemType::RemoteThreadCreate:
		{
			DisplayTime(header->Time);
			auto info = (RemoteThreadInfo*)buffer;
			printf("Remote Thread %d Created in process %d\n", info->ThreadId, info->ProcessId);
			break;
		}

		default:
			break;
		}
		buffer += header->Size;
		count -= header->Size;
	}

}



int main()
{
	wil::unique_hfile hFiile(CreateFile(CLIENT_SYM_LINK_NAME, GENERIC_READ | GENERIC_WRITE, 0, nullptr, OPEN_EXISTING, 0, nullptr));
	if (!hFiile) {
		return Error("Failed to open device");
	}
	

	// add exec path
	{
		DWORD bytesReturn;
		ExecInfo info;
		wcscpy_s(info.Path, _countof(info.Path), L"C:\\Windows\\System32\\calc.exe");
		auto success = DeviceIoControl(hFiile.get(), IOCTL_MONIT_PROCESS_ADD, &info, sizeof(info), nullptr, 0, &bytesReturn, nullptr);
		if (!success) {
			return Error("Failed in DeviceIoControl");
		}
		printf("after added executable path\n");
	}


	while (true)
	{
		DWORD bytes;
		BYTE buffer[4096];

		auto success = DeviceIoControl(hFiile.get(), IOCTL_EVENTS_READ,nullptr,0, buffer, sizeof(buffer), &bytes, nullptr);
		if (!success) {
			return Error("Failed in DeviceIoControl");
		}

		if (bytes) {
			DisplayInfo(buffer, bytes);
		}

		Sleep(5000);
	}


}

