#pragma once

#define DRIVER_TAG 'ommm'

#define SYM_LINK_NAME  L"\\??\\ProCreationMon"
#define CLIENT_SYM_LINK_NAME L"\\\\.\\ProCreationMon"
#define DEVICE_NAME L"\\Device\\ProCreationMon"
static const WCHAR* s_RegistryAltitude = L"7657.124";

#define IOCTL_MONIT_PROCESS_ADD	    CTL_CODE(0x8000, 0x800, METHOD_BUFFERED, FILE_ANY_ACCESS)
#define IOCTL_MONIT_PROCESS_CLEAR	CTL_CODE(0x8000, 0x801, METHOD_BUFFERED, FILE_ANY_ACCESS)
#define IOCTL_EVENTS_READ	        CTL_CODE(0x8000, 0x802, METHOD_BUFFERED, FILE_ANY_ACCESS)

enum class ItemType : short {
	None,
	ProcessCreate,
	RemoteThreadCreate
};

struct ItemHeader {
	ItemType Type;
	LARGE_INTEGER Time;
	USHORT Size;
};

const int MaxImageFileSize = 300;
struct ProcessCreateInfo:ItemHeader {
	ULONG ProcessId = 0;
	ULONG ParentProcessId = 0;
	USHORT CommandLineLength = 0;
	USHORT CommandLineOffset = 0;
};

struct RemoteThreadInfo :ItemHeader {
	ULONG ProcessId = 0;
	ULONG ThreadId = 0;
};

struct ExecInfo {
	WCHAR Path[MaxImageFileSize]{};
};



template<typename T>
struct FullItem {
	LIST_ENTRY Entry;
	T Data;
};