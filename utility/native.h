#pragma once

#include <ntifs.h>

extern"C"
{
	NTSYSAPI NTSTATUS NTAPI ZwQueryInformationProcess(
			IN  HANDLE ProcessHandle,
			IN  PROCESSINFOCLASS ProcessInformationClass,
			OUT PVOID ProcessInformation,
			IN  ULONG ProcessInformationLength,
			IN  PULONG ReturnLength
		);

	NTSTATUS
		PsReferenceProcessFilePointer(
			IN PEPROCESS Process,
			OUT PVOID* pFilePointer
		);

}