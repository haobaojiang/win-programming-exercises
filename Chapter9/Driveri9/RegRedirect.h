

namespace RegRedirect {

	NTSTATUS Add(const PWCHAR KeyName);
	BOOLEAN Find(const UNICODE_STRING* KeyName);
	// call by DriverEntry
	BOOLEAN Initialize();
	// call by DriverUnload
	BOOLEAN Finiallize();
	NTSTATUS ProcessRegRedirect(const UNICODE_STRING* KeyName,
		UNICODE_STRING* ValueName,
		const PVOID Data,
		ULONG DataType,
		ULONG DataSize,
		BOOLEAN* SuccessRedirect);
}
