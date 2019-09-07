#include <ntifs.h>
#include <fltKernel.h>
#pragma warning( push )
#pragma warning( disable: 5040 )
#include "../wil/include/wil/resource.h"
#pragma warning( pop )
#include "native.h"
#include "utility.h"
#include "../../ndcoslo2019/CppKernel/GenericLibrary/kstring.h"


const static ULONG g_poolTag = 'uflt';


namespace Utility::Process {
	_IRQL_requires_max_(APC_LEVEL)
		NTSTATUS IsProcessDebugged(PEPROCESS eProcess, PBOOLEAN result) {

		if (eProcess == nullptr || result == nullptr) {
			return STATUS_INVALID_PARAMETER;
		}

		*result = FALSE;
		HANDLE handle = nullptr;
		auto status = ObOpenObjectByPointer(eProcess, OBJ_KERNEL_HANDLE, nullptr, READ_CONTROL, nullptr, KernelMode, &handle);
		if (!NT_SUCCESS(status)) {
			return status;
		}

		PULONG debugPointer = nullptr;
		ULONG returnLength = 0;
		status = ZwQueryInformationProcess(handle, ProcessDebugPort, &debugPointer, sizeof(debugPointer), &returnLength);
		if (!NT_SUCCESS(status)) {
			ZwClose(handle);
			return status;
		}

		if (debugPointer) {
			*result = TRUE;
		}
		ZwClose(handle);

		return STATUS_SUCCESS;
	}

	_IRQL_requires_max_(PASSIVE_LEVEL)
		NTSTATUS GetProcessFullName(const PEPROCESS Process, PVOID OuputBuffer, ULONG BufferLength) {

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

	_IRQL_requires_max_(PASSIVE_LEVEL)
		NTSTATUS GetProcessFullName(const PEPROCESS Process, __out UNICODE_STRING* Processname) {

		PFILE_OBJECT fileObject = nullptr;
		POBJECT_NAME_INFORMATION objectNameInfo = nullptr;

		if (Processname == nullptr) {
			return STATUS_INVALID_USER_BUFFER;
		}

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

		//
		return  Utility::SafeCapture::CaptureUnicodeString(Processname, &objectNameInfo->Name, g_poolTag);
	}


	void FreeProcessFullName(UNICODE_STRING* Processname) {
		return Utility::SafeCapture::FreeCapturedUnicodeString(Processname, g_poolTag);
	}


	_IRQL_requires_max_(PASSIVE_LEVEL)
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

	/*
		UserToken : need to call FreeToken To Release Resource
	 */
	_IRQL_requires_max_(PASSIVE_LEVEL)
		NTSTATUS GetUserToken(__in SECURITY_SUBJECT_CONTEXT* SecContext, __out PTOKEN_USER* UserToken)
	{
		if (SecContext == nullptr) {
			return STATUS_INVALID_PARAMETER_1;
		}

		if (UserToken == nullptr) {
			return STATUS_INVALID_PARAMETER_2;
		}

		SeLockSubjectContext(SecContext);
		auto cleanup = wil::scope_exit([&]() {SeUnlockSubjectContext(SecContext); });
		auto accessToekn = SeQuerySubjectContextToken(SecContext);

		NTSTATUS status = SeQueryInformationToken(accessToekn, TokenUser, reinterpret_cast<PVOID*>(UserToken));
		if (!NT_SUCCESS(status)) {
			return status;
		}

		return STATUS_SUCCESS;
	}




	_IRQL_requires_max_(PASSIVE_LEVEL)
		void FreeToken(PTOKEN_USER UserToken)
	{
		if (UserToken) {
			ExFreePool(UserToken);
		}
	}

	_IRQL_requires_max_(PASSIVE_LEVEL)
		void FreeSidString(__out UNICODE_STRING* SidString)
	{
		if (SidString && SidString->Buffer) {
			RtlFreeUnicodeString(SidString);
			RtlZeroMemory(SidString, sizeof(UNICODE_STRING));
		}
	}


	_IRQL_requires_max_(PASSIVE_LEVEL)
		NTSTATUS GetCurrentSidString(__out UNICODE_STRING* SidString)
	{
		PTOKEN_USER userToken;

		// get current context
		SECURITY_SUBJECT_CONTEXT secContext{ 0 };
		SeCaptureSubjectContext(&secContext);
		auto cleanup = wil::scope_exit([&]() { SeReleaseSubjectContext(&secContext); });

		auto status = GetUserToken(&secContext, &userToken);
		if (!NT_SUCCESS(status)) {
			return status;
		}

		status = RtlConvertSidToUnicodeString(SidString, userToken->User.Sid, TRUE);
		FreeToken(userToken);
		return status;
	}
	/*
	   FreeSidString need to be called for releasing SidString
	*/
	_IRQL_requires_max_(PASSIVE_LEVEL)
		NTSTATUS GetSecContextSidString(SECURITY_SUBJECT_CONTEXT* SecContext, __out UNICODE_STRING* SidString)
	{

		PTOKEN_USER userToken;
		auto status = GetUserToken(SecContext, &userToken);
		if (!NT_SUCCESS(status)) {
			return status;
		}

		status = RtlConvertSidToUnicodeString(SidString, userToken->User.Sid, TRUE);
		FreeToken(userToken);
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
			NonPagedPool,
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
			NonPagedPool,
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

	void FreeUnicodeString(_In_ UNICODE_STRING* Name) {
		if (Name && Name->Buffer) {
			ExFreePool(Name->Buffer);
			RtlZeroMemory(Name, sizeof(UNICODE_STRING));
		}
	}

}

namespace Utility::Reg {
	_IRQL_requires_max_(PASSIVE_LEVEL)
		NTSTATUS SetKeyValue(UNICODE_STRING* Root, UNICODE_STRING* Value, ULONG DataType, const PVOID Data, ULONG DataSize) {

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

	_IRQL_requires_max_(PASSIVE_LEVEL)
		NTSTATUS CreateKey(UNICODE_STRING* Root) {

		wil::unique_kernel_handle key;
		OBJECT_ATTRIBUTES keyAttributes = { 0 };
		InitializeObjectAttributes(&keyAttributes,
			Root,
			OBJ_CASE_INSENSITIVE | OBJ_KERNEL_HANDLE,
			nullptr,
			nullptr);

		return ZwCreateKey(&key,
			KEY_SET_VALUE,
			&keyAttributes,
			0,
			nullptr,
			REG_OPTION_NON_VOLATILE,
			nullptr
		);
	}
}

namespace Utility::Sync {


	KernelFastMutexLock::KernelFastMutexLock() noexcept {
		::ExInitializeFastMutex(&this->m_lock);
	}

	[[nodiscard]]
	_IRQL_requires_max_(DISPATCH_LEVEL)
		KernelFastMutexLock::MutexGuard KernelFastMutexLock::acquire()
	{
		ExAcquireFastMutex(&this->m_lock);
		return KernelFastMutexLock::MutexGuard(&this->m_lock);
	}
}

namespace Utility::Flt {



	_IRQL_requires_max_(APC_LEVEL)
		void FreeFileNameInfo(PFLT_FILE_NAME_INFORMATION* FileNameInfo)
	{
		if (FileNameInfo && *FileNameInfo) {
			FltReleaseFileNameInformation(*FileNameInfo);
			*FileNameInfo = nullptr;
		}
	}


	_IRQL_requires_max_(APC_LEVEL)
		NTSTATUS GetAndParseFileNameInfo(_In_ PFLT_CALLBACK_DATA Data,
			_Out_ PFLT_FILE_NAME_INFORMATION* NameInfo,
			FLT_FILE_NAME_OPTIONS Options)
	{
		*NameInfo = nullptr;
		auto status = FltGetFileNameInformation(Data, Options, NameInfo);
		if (!NT_SUCCESS(status)) {
			return status;
		}

		status = FltParseFileNameInformation(*NameInfo);
		if (!NT_SUCCESS(status)) {
			FltReleaseFileNameInformation(*NameInfo);
			return status;
		}

		return STATUS_SUCCESS;
	}

	_IRQL_requires_max_(APC_LEVEL)
		NTSTATUS GetVolumeName(_In_ PFLT_CALLBACK_DATA Data, _Out_ UNICODE_STRING* VolumeName)
	{
		PFLT_FILE_NAME_INFORMATION nameInfo = nullptr;
		auto status = GetAndParseFileNameInfo(Data, &nameInfo, FLT_FILE_NAME_QUERY_DEFAULT | FLT_FILE_NAME_NORMALIZED);
		if (!NT_SUCCESS(status)) {
			return status;
		}

		status = Utility::SafeCapture::CaptureUnicodeString(VolumeName, &nameInfo->Volume, g_poolTag);
		FltReleaseFileNameInformation(nameInfo);
		return status;
	}

	_IRQL_requires_max_(APC_LEVEL)
		NTSTATUS GetFileName(_In_ PFLT_CALLBACK_DATA Data, _Out_ UNICODE_STRING* FileName)
	{
		PFLT_FILE_NAME_INFORMATION nameInfo = nullptr;
		auto status = GetAndParseFileNameInfo(Data, &nameInfo, FLT_FILE_NAME_QUERY_DEFAULT | FLT_FILE_NAME_NORMALIZED);
		if (!NT_SUCCESS(status)) {
			return status;
		}

		status = Utility::SafeCapture::CaptureUnicodeString(FileName, &nameInfo->Name, g_poolTag);
		FltReleaseFileNameInformation(nameInfo);
		return status;
	}

	_IRQL_requires_max_(DISPATCH_LEVEL)
		void FreeName(_Out_ UNICODE_STRING* VolumeName)
	{
		Utility::SafeCapture::FreeCapturedUnicodeString(VolumeName, g_poolTag);
	}


	_IRQL_requires_max_(APC_LEVEL)
		NTSTATUS GetVolumeName(PFLT_VOLUME Volume, _Out_ PUNICODE_STRING VolumeName)
	{

		if (!Volume) {
			return STATUS_INVALID_PARAMETER_1;
		}

		if (!VolumeName) {
			return STATUS_INVALID_PARAMETER_2;
		}


		ULONG sizeNeeded = 0;
		FltGetVolumeName(Volume, nullptr, &sizeNeeded);

		sizeNeeded += sizeof(WCHAR);
		RtlZeroMemory(VolumeName, sizeof(UNICODE_STRING));
		VolumeName->Buffer = static_cast<PWCH>(ExAllocatePoolWithTag(NonPagedPool, sizeNeeded, g_poolTag));
		VolumeName->Length = static_cast<USHORT>(sizeNeeded);
		VolumeName->MaximumLength = static_cast<USHORT>(sizeNeeded);

		if (VolumeName->Buffer == nullptr) {
			return STATUS_MEMORY_NOT_ALLOCATED;
		}

		RtlZeroMemory(VolumeName->Buffer, sizeNeeded);

		auto status = FltGetVolumeName(Volume, VolumeName, &sizeNeeded);
		if (!NT_SUCCESS(status)) {
			ExFreePoolWithTag(VolumeName->Buffer, g_poolTag);
			VolumeName->Buffer = nullptr;
			return status;
		}

		return STATUS_SUCCESS;
	}

}