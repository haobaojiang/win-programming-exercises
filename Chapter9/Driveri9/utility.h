#pragma once

namespace Utility::Process {

	NTSTATUS IsProcessDebugged(PEPROCESS eProcess, PBOOLEAN result);
	NTSTATUS GetProcessParentId(HANDLE pid, PHANDLE parentPid);
	NTSTATUS GetProcessFullName(PEPROCESS Process, PWCHAR OuputBuffer, ULONG BufferLength);

}

namespace Utility::SafeCapture {
	NTSTATUS
		CaptureBuffer(
			_Outptr_result_maybenull_ PVOID* CapturedBuffer,
			_In_reads_bytes_(Length)PVOID Buffer,
			_In_ SIZE_T Length,
			_In_ ULONG PoolTag
		);

	VOID
		FreeCapturedBuffer(
			_In_ PVOID Buffer,
			_In_ ULONG PoolTag
		);

	NTSTATUS
		CaptureUnicodeString(
			_Inout_ UNICODE_STRING* DestString,
			_In_ PCUNICODE_STRING SourceString,
			_In_ ULONG PoolTag
		);

	VOID
		FreeCapturedUnicodeString(
			_In_ UNICODE_STRING* String,
			_In_ ULONG PoolTag
		);
}

namespace Utility::Reg {
	NTSTATUS SetValueKey(PUNICODE_STRING Root, PUNICODE_STRING Value, ULONG DataType, PVOID Data, ULONG DataSize);
}