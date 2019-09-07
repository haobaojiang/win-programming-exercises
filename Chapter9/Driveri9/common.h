#pragma once

#define DRIVER_TAG 'omm9'

#define SYM_LINK_NAME  L"\\??\\chapter9"
#define CLIENT_SYM_LINK_NAME L"\\\\.\\chapter9"
#define DEVICE_NAME L"\\Device\\chapter9"
static const WCHAR* s_RegistryAltitude = L"7657.124";



#define IOCTL_REG_KEY_REDIRCT_ADD	CTL_CODE(0x8000, 0x801, METHOD_BUFFERED, FILE_ANY_ACCESS)
#define IOCTL_REG_KEY_REDIRCT_DEL	CTL_CODE(0x8000, 0x802, METHOD_BUFFERED, FILE_ANY_ACCESS)
#define IOCTL_REG_PROTECT_ADD CTL_CODE(0x8000, 0x803, METHOD_BUFFERED, FILE_ANY_ACCESS)
#define IOCTL_REG_PROTECT_DEL CTL_CODE(0x8000, 0x804, METHOD_BUFFERED, FILE_ANY_ACCESS)






const int MaxRegNameSize = 300;
struct RegRedirectInfo {
	WCHAR ProcessName[MaxRegNameSize]{};
};

struct RegKeyProtectInfo  {
	WCHAR KeyName[MaxRegNameSize]{};
};



template<typename T>
struct FullItem {
	LIST_ENTRY Entry;
	T Data;
};