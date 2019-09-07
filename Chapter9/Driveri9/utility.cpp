#include <ntifs.h>
#include <GenericLibrary/Memory.h>
#include <wil/resource.h>
#include "native.h"
#include "utility.h"


namespace Utility::Process {

	NTSTATUS IsProcessDebugged(PEPROCESS eProcess, PBOOLEAN result) {

		if (eProcess == nullptr || result == nullptr) {
			return STATUS_INVALID_PARAMETER;
		}

		*result = FALSE;
		wil::unique_kernel_handle handle;
		auto status = ObOpenObjectByPointer(eProcess, OBJ_KERNEL_HANDLE, nullptr, READ_CONTROL, nullptr, KernelMode, &handle);
		if (!NT_SUCCESS(status)) {
			return status;
		}

		PULONG debugPointer = nullptr;
		ULONG returnLength = 0;
		status = ZwQueryInformationProcess(handle.get(), ProcessDebugPort, &debugPointer, sizeof(debugPointer), &returnLength);
		if (!NT_SUCCESS(status)) {
			return status;
		}

		if (debugPointer) {
			*result = TRUE;
		}

		return STATUS_SUCCESS;
	}

	NTSTATUS GetProcessFullName(PEPROCESS Process,PWCHAR OuputBuffer,ULONG BufferLength) {

		PFILE_OBJECT fileObject = nullptr;
		POBJECT_NAME_INFORMATION objectNameInfo = nullptr;

		auto status = PsReferenceProcessFilePointer(Process, reinterpret_cast<PVOID*>(&fileObject));
		if (!NT_SUCCESS(status)) {
			return status;
		}

		auto fileObjectGuard = wil::scope_exit([&] {
			ObDereferenceObject(fileObject);
			});

		status = IoQueryFileDosDeviceName(fileObject, &objectNameInfo);
		if (!NT_SUCCESS(status)) {
			return status;
		}

		auto objectNameInfoGuard = wil::scope_exit([&] {
			ExFreePool(objectNameInfo);
			});

		if (BufferLength < objectNameInfo->Name.Length) {
			return STATUS_BUFFER_TOO_SMALL;
		}
		__try {
			RtlCopyMemory(OuputBuffer,
				objectNameInfo->Name.Buffer, 
				objectNameInfo->Name.Length);
		}
		__except (EXCEPTION_EXECUTE_HANDLER) {
			return STATUS_INVALID_USER_BUFFER;
		}
		
		return STATUS_SUCCESS;
	}

	NTSTATUS GetProcessParentId(HANDLE pid, PHANDLE parentPid) {

		wil::unique_kernel_handle handle;
		CLIENT_ID clientId = {};
		OBJECT_ATTRIBUTES objectAttributes;
		InitializeObjectAttributes(&objectAttributes, nullptr, 0, 0, nullptr);
		clientId.UniqueProcess = pid;
		clientId.UniqueThread = 0;
		auto status = ZwOpenProcess(&handle, READ_CONTROL, &objectAttributes, &clientId);
		if (!NT_SUCCESS(status))
		{
			return status;
		}

		PROCESS_BASIC_INFORMATION basicInfo;
		status = ZwQueryInformationProcess(
			handle.get(),
			ProcessBasicInformation,
			&basicInfo,
			sizeof(basicInfo),
			NULL);

		if (!NT_SUCCESS(status))
		{
			return status;
		}

		*parentPid = reinterpret_cast<HANDLE>(basicInfo.InheritedFromUniqueProcessId);
		return status;
	}
}

namespace Utility::SafeCapture {

	NTSTATUS CaptureBuffer(
		_Outptr_result_maybenull_ PVOID* CapturedBuffer,
		_In_reads_bytes_(Length) PVOID Buffer,
		_In_ SIZE_T Length,
		_In_ ULONG PoolTag
	)
	{
		NTSTATUS Status = STATUS_SUCCESS;
		PVOID TempBuffer = NULL;

		NT_ASSERT(CapturedBuffer != NULL);

		if (Length == 0) {
			*CapturedBuffer = NULL;
			return Status;
		}

		TempBuffer = ExAllocatePoolWithTag(
			PagedPool,
			Length,
			PoolTag);

		if (TempBuffer != NULL) {
			__try {
				RtlCopyMemory(TempBuffer, Buffer, Length);
			}
			__except (EXCEPTION_EXECUTE_HANDLER) {
				ExFreePoolWithTag(TempBuffer, PoolTag);
				TempBuffer = NULL;
				Status = GetExceptionCode();
			}
		}
		else {
			Status = STATUS_INSUFFICIENT_RESOURCES;
		}

		*CapturedBuffer = TempBuffer;

		return Status;
	}


	VOID
		FreeCapturedBuffer(
			_In_ PVOID CapturedBuffer,
			_In_ ULONG PoolTag
		)
	{
		if (CapturedBuffer != NULL) {
			ExFreePoolWithTag(CapturedBuffer, PoolTag);
		}
	}


	NTSTATUS
		CaptureUnicodeString(
			_Inout_ UNICODE_STRING* DestString,
			_In_ PCUNICODE_STRING SourceString,
			_In_ ULONG PoolTag
		)
	{
		NTSTATUS Status = STATUS_SUCCESS;


		if (SourceString->Length == 0) {
			DestString->Length = 0;
			DestString->Buffer = NULL;
			DestString->MaximumLength = 0;
			return Status;
		}

		DestString->Length = SourceString->Length;
		DestString->MaximumLength = SourceString->Length + sizeof(WCHAR);

		DestString->Buffer = (PWSTR)ExAllocatePoolWithTag(
			PagedPool,
			DestString->MaximumLength,
			PoolTag);

		if (DestString->Buffer != NULL) {

			RtlZeroMemory(DestString->Buffer, DestString->MaximumLength);

			__try {
				RtlCopyMemory(DestString->Buffer,
					SourceString->Buffer,
					SourceString->Length);
			}
			__except (EXCEPTION_EXECUTE_HANDLER) {
				ExFreePoolWithTag(DestString->Buffer, PoolTag);
				DestString->Buffer = NULL;
				Status = GetExceptionCode();
			}
		}
		else {
			Status = STATUS_INSUFFICIENT_RESOURCES;
		}

		if (DestString->Buffer == NULL) {
			DestString->Length = 0;
			DestString->MaximumLength = 0;
		}

		return Status;

	}

	VOID
		FreeCapturedUnicodeString(
			_In_ UNICODE_STRING* String,
			_In_ ULONG PoolTag
		)
	{
		if (String->Length != 0) {
			String->Length = 0;
			String->MaximumLength = 0;
			FreeCapturedBuffer(String->Buffer, PoolTag);
			String->Buffer = NULL;
		}
	}
}

namespace Utility::Reg {

	NTSTATUS SetValueKey(PUNICODE_STRING Root,PUNICODE_STRING Value,ULONG DataType,PVOID Data,ULONG DataSize) {

		wil::unique_kernel_handle key;
		OBJECT_ATTRIBUTES keyAttributes = { 0 };
		InitializeObjectAttributes(&keyAttributes,
			Root, 
			OBJ_CASE_INSENSITIVE | OBJ_KERNEL_HANDLE, 
			nullptr, 
			nullptr);

		auto status = ZwCreateKey(&key,
			KEY_SET_VALUE,
			&keyAttributes,
			0,
			nullptr,
			REG_OPTION_NON_VOLATILE,
			nullptr
		);
		if (!NT_SUCCESS(status)) {
			return status;
		}

		status = ZwSetValueKey(key.get(), Value, 0, DataType, Data, DataSize);
		if (!NT_SUCCESS(status)) {
			return status;
		}

		return STATUS_SUCCESS;
	}

}