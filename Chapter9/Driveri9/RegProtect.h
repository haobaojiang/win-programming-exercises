

namespace RegProtect {

	NTSTATUS Add(const PWCHAR KeyName);
	BOOLEAN Find(const UNICODE_STRING* KeyName);
	// call by DriverEntry
	BOOLEAN Initialize();
	// call by DriverUnload
	BOOLEAN Finiallize();
}
