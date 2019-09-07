#include <fltKernel.h>
#include <dontuse.h>

#include "../../utility/utility.h"


#pragma prefast(disable:__WARNING_ENCODE_MEMBER_FUNCTION_POINTER, "Not valid for kernel mode drivers")

#define  DRIVER_TAG ('dr10')
PFLT_FILTER gFilterHandle;
ULONG_PTR OperationStatusCtx = 1;

#define PTDBG_TRACE_ROUTINES            0x00000001
#define PTDBG_TRACE_OPERATION_STATUS    0x00000002

ULONG gTraceFlags = 0;


#define PT_DBG_PRINT( _dbgLevel, _string )          \
    (FlagOn(gTraceFlags,(_dbgLevel)) ?              \
        DbgPrint _string :                          \
        ((int)0))

/*************************************************************************
	Prototypes
*************************************************************************/

EXTERN_C_START

DRIVER_INITIALIZE DriverEntry;
NTSTATUS
DriverEntry(
	_In_ PDRIVER_OBJECT DriverObject,
	_In_ PUNICODE_STRING RegistryPath
);

NTSTATUS
Driver10InstanceSetup(
	_In_ PCFLT_RELATED_OBJECTS FltObjects,
	_In_ FLT_INSTANCE_SETUP_FLAGS Flags,
	_In_ DEVICE_TYPE VolumeDeviceType,
	_In_ FLT_FILESYSTEM_TYPE VolumeFilesystemType
);

VOID
Driver10InstanceTeardownStart(
	_In_ PCFLT_RELATED_OBJECTS FltObjects,
	_In_ FLT_INSTANCE_TEARDOWN_FLAGS Flags
);

VOID
Driver10InstanceTeardownComplete(
	_In_ PCFLT_RELATED_OBJECTS FltObjects,
	_In_ FLT_INSTANCE_TEARDOWN_FLAGS Flags
);

NTSTATUS
Driver10Unload(
	_In_ FLT_FILTER_UNLOAD_FLAGS Flags
);

NTSTATUS
Driver10InstanceQueryTeardown(
	_In_ PCFLT_RELATED_OBJECTS FltObjects,
	_In_ FLT_INSTANCE_QUERY_TEARDOWN_FLAGS Flags
);

FLT_PREOP_CALLBACK_STATUS
PreCreate(
	_Inout_ PFLT_CALLBACK_DATA Data,
	_In_ PCFLT_RELATED_OBJECTS FltObjects,
	_Flt_CompletionContext_Outptr_ PVOID* CompletionContext
);

FLT_POSTOP_CALLBACK_STATUS
PostCreate(
	_Inout_ PFLT_CALLBACK_DATA Data,
	_In_ PCFLT_RELATED_OBJECTS FltObjects,
	_Flt_CompletionContext_Outptr_ PVOID CompletionContext,
	_In_ FLT_POST_OPERATION_FLAGS Flags);

FLT_PREOP_CALLBACK_STATUS PreSetInformation(
	_Inout_ PFLT_CALLBACK_DATA Data,
	_In_ PCFLT_RELATED_OBJECTS FltObjects,
	PVOID*);

EXTERN_C_END


NTSTATUS ConvertDosNameToNtName(_In_ PCWSTR dosName, _Out_ PUNICODE_STRING ntName);

//
//  Assign text sections for each routine.
//

#ifdef ALLOC_PRAGMA
#pragma alloc_text(INIT, DriverEntry)
#pragma alloc_text(PAGE, Driver10Unload)
#pragma alloc_text(PAGE, Driver10InstanceQueryTeardown)
#pragma alloc_text(PAGE, Driver10InstanceSetup)
#pragma alloc_text(PAGE, Driver10InstanceTeardownStart)
#pragma alloc_text(PAGE, Driver10InstanceTeardownComplete)
#endif

//
//  operation registration
//

CONST FLT_OPERATION_REGISTRATION Callbacks[] = {
	{ IRP_MJ_CREATE,0,PreCreate,PostCreate },
	{ IRP_MJ_SET_INFORMATION, 0,PreSetInformation,nullptr },
	{ IRP_MJ_OPERATION_END }
};



struct VolumeContext {
	UNICODE_STRING name;  // null-terminated string
	VolumeContext() {
		RtlZeroMemory(&name, sizeof(name));
	}
};


struct FileContext {
	UNICODE_STRING name;  // null-terminated string
	FileContext() {
		RtlZeroMemory(&name, sizeof(name));
	}
};


VOID VolumeContextCleanup(_In_ PFLT_CONTEXT Context, _In_ FLT_CONTEXT_TYPE /*ContextType*/) {

	auto volumeContext = reinterpret_cast<VolumeContext*>(Context);
	if (volumeContext && volumeContext->name.Buffer) {
		ExFreePool(volumeContext->name.Buffer);
		RtlZeroMemory(&volumeContext->name, sizeof(volumeContext->name));
		return;
	}
}

VOID FileContextCleanup(_In_ PFLT_CONTEXT Context, _In_ FLT_CONTEXT_TYPE /*ContextType*/) {

	auto context = reinterpret_cast<FileContext*>(Context);
	if (context && context->name.Buffer) {
		Utility::SafeCapture::FreeCapturedUnicodeString(&context->name, DRIVER_TAG);
	}
}



const FLT_CONTEXT_REGISTRATION Contexts[] = {
	{FLT_VOLUME_CONTEXT,0, VolumeContextCleanup, sizeof(VolumeContext),'dr10'},
	{FLT_FILE_CONTEXT,0, FileContextCleanup, sizeof(FileContext),'dr10'},
	{FLT_CONTEXT_END}
};

//
//  This defines what we want to filter with FltMgr
//

CONST FLT_REGISTRATION FilterRegistration = {

	sizeof(FLT_REGISTRATION),         //  Size
	FLT_REGISTRATION_VERSION,           //  Version
	0,                                  //  Flags

	Contexts,                               //  Context
	Callbacks,                          //  Operation callbacks

	Driver10Unload,                           //  MiniFilterUnload

	Driver10InstanceSetup,                    //  InstanceSetup
	Driver10InstanceQueryTeardown,            //  InstanceQueryTeardown
	Driver10InstanceTeardownStart,            //  InstanceTeardownStart
	Driver10InstanceTeardownComplete,         //  InstanceTeardownComplete

	NULL,                               //  GenerateFileName
	NULL,                               //  GenerateDestinationFileName
	NULL                                //  NormalizeNameComponent

};



NTSTATUS
Driver10InstanceSetup(
	_In_ PCFLT_RELATED_OBJECTS FltObjects,
	_In_ FLT_INSTANCE_SETUP_FLAGS Flags,
	_In_ DEVICE_TYPE VolumeDeviceType,
	_In_ FLT_FILESYSTEM_TYPE VolumeFilesystemType
)
{
	UNREFERENCED_PARAMETER(FltObjects);
	UNREFERENCED_PARAMETER(Flags);
	UNREFERENCED_PARAMETER(VolumeDeviceType);
	UNREFERENCED_PARAMETER(VolumeFilesystemType);

	PAGED_CODE();

	PT_DBG_PRINT(PTDBG_TRACE_ROUTINES,
		("Driver10!Driver10InstanceSetup: Entered\n"));


	if (VolumeFilesystemType != FLT_FSTYPE_NTFS) {
		KdPrint(("Not attaching to non-NTFS volume\n"));
		return STATUS_FLT_DO_NOT_ATTACH;
	}

	VolumeContext* context = nullptr;
	auto status = FltAllocateContext(FltObjects->Filter, FLT_VOLUME_CONTEXT, sizeof(VolumeContext), NonPagedPool,reinterpret_cast<PFLT_CONTEXT*>(&context));
	if (!NT_SUCCESS(status)) {
		KdPrint(("failed to FltAllocateContext ,status : (0x%08X)\n", status));
		return STATUS_FLT_DO_NOT_ATTACH;
	}
	auto cleanup = wil::scope_exit([&]() {FltReleaseContext(reinterpret_cast<PFLT_CONTEXT>(context)); });

	status = Utility::Flt::GetVolumeName(FltObjects->Volume, &context->name);
	if (!NT_SUCCESS(status)) {
		KdPrint(("failed to GetVolumeName ,status : (0x%08X)\n", status));
		return STATUS_FLT_DO_NOT_ATTACH;
	}

	PFLT_CONTEXT newContext = nullptr;
	status = FltSetVolumeContext(FltObjects->Volume, FLT_SET_CONTEXT_KEEP_IF_EXISTS, context, &newContext);
	if (!NT_SUCCESS(status)) {
		KdPrint(("failed to FltSetVolumeContext ,status : (0x%08X)\n", status));
		return STATUS_FLT_DO_NOT_ATTACH;
	}

	return STATUS_SUCCESS;
}


NTSTATUS
Driver10InstanceQueryTeardown(
	_In_ PCFLT_RELATED_OBJECTS FltObjects,
	_In_ FLT_INSTANCE_QUERY_TEARDOWN_FLAGS Flags
)
{
	UNREFERENCED_PARAMETER(FltObjects);
	UNREFERENCED_PARAMETER(Flags);

	PAGED_CODE();

	PT_DBG_PRINT(PTDBG_TRACE_ROUTINES,
		("Driver10!Driver10InstanceQueryTeardown: Entered\n"));

	return STATUS_SUCCESS;
}


VOID
Driver10InstanceTeardownStart(
	_In_ PCFLT_RELATED_OBJECTS FltObjects,
	_In_ FLT_INSTANCE_TEARDOWN_FLAGS Flags
)
{
	UNREFERENCED_PARAMETER(FltObjects);
	UNREFERENCED_PARAMETER(Flags);

	PAGED_CODE();

	PT_DBG_PRINT(PTDBG_TRACE_ROUTINES,
		("Driver10!Driver10InstanceTeardownStart: Entered\n"));
}


VOID
Driver10InstanceTeardownComplete(
	_In_ PCFLT_RELATED_OBJECTS FltObjects,
	_In_ FLT_INSTANCE_TEARDOWN_FLAGS Flags
)
{
	UNREFERENCED_PARAMETER(FltObjects);
	UNREFERENCED_PARAMETER(Flags);

	PAGED_CODE();

	PT_DBG_PRINT(PTDBG_TRACE_ROUTINES,
		("Driver10!Driver10InstanceTeardownComplete: Entered\n"));

	PFLT_CONTEXT context = nullptr;
	auto status = FltGetVolumeContext(FltObjects->Filter,
		FltObjects->Volume,
		&context);
	if (!NT_SUCCESS(status)) {
		KdPrint(("falied on FltGetVolumeContext, status (0x%08X)\n", status));
		return;
	}

	FltReleaseContext(context);
}


/*************************************************************************
	MiniFilter initialization and unload routines.
*************************************************************************/

NTSTATUS
DriverEntry(
	_In_ PDRIVER_OBJECT DriverObject,
	_In_ PUNICODE_STRING RegistryPath
)
{
	NTSTATUS status;

	UNREFERENCED_PARAMETER(RegistryPath);

	PT_DBG_PRINT(PTDBG_TRACE_ROUTINES,
		("Driver10!DriverEntry: Entered\n"));

	//
	//  Register with FltMgr to tell it our callback routines
	//

	status = FltRegisterFilter(DriverObject,
		&FilterRegistration,
		&gFilterHandle);

	KdPrint(("failed to FltRegisterFilter,status : (0x%08X)\n", status));

	if (NT_SUCCESS(status)) {

		//
		//  Start filtering i/o
		//

		status = FltStartFiltering(gFilterHandle);

		if (!NT_SUCCESS(status)) {

			FltUnregisterFilter(gFilterHandle);
		}
	}

	return status;
}

NTSTATUS
Driver10Unload(
	_In_ FLT_FILTER_UNLOAD_FLAGS Flags
)
{
	UNREFERENCED_PARAMETER(Flags);

	PAGED_CODE();

	PT_DBG_PRINT(PTDBG_TRACE_ROUTINES,
		("Driver10!Driver10Unload: Entered\n"));

	FltUnregisterFilter(gFilterHandle);

	return STATUS_SUCCESS;
}


/*************************************************************************
	MiniFilter callback routines.
*************************************************************************/

NTSTATUS IsDeleteAllowed(const PEPROCESS Process, BOOLEAN* Result) {

	UNICODE_STRING processName = { 0 };
	*Result = TRUE;
	auto status = Utility::Process::GetProcessFullName(Process, &processName);
	if (!NT_SUCCESS(status)) {
		return status;
	}
	auto cleanup = wil::scope_exit([&]() { Utility::Process::FreeProcessFullName(&processName); });

	const static UNICODE_STRING systemCmdPath = RTL_CONSTANT_STRING(L"c:\\windows\\system32\\cmd.exe");
	const static UNICODE_STRING wow64CmdPath = RTL_CONSTANT_STRING(L"c:\\windows\\syswow64\\cmd.exe");

	if (RtlEqualUnicodeString(&processName, &systemCmdPath, TRUE) ||
		RtlEqualUnicodeString(&processName, &wow64CmdPath, TRUE)) {
		*Result = FALSE;
	}

	return STATUS_SUCCESS;
}


NTSTATUS RenameFile(_In_ PCFLT_RELATED_OBJECTS FltObjects, const UNICODE_STRING* NewFileName) {

	auto len = NewFileName->Length + sizeof(FILE_RENAME_INFORMATION) + sizeof(WCHAR);
	PFILE_RENAME_INFORMATION fileRenameInfo = static_cast<PFILE_RENAME_INFORMATION>(ExAllocatePool(NonPagedPool, len));
	if (fileRenameInfo == nullptr) {
		return STATUS_MEMORY_NOT_ALLOCATED;
	}
	auto renameCleanup = wil::scope_exit([&]() {ExFreePool(fileRenameInfo); });

	RtlZeroMemory(fileRenameInfo, len);
	fileRenameInfo->ReplaceIfExists = TRUE;
	fileRenameInfo->RootDirectory = nullptr;
	fileRenameInfo->FileNameLength = NewFileName->Length;
	RtlCopyMemory(&fileRenameInfo->FileName[0], NewFileName->Buffer, NewFileName->Length);

	return FltSetInformationFile(FltObjects->Instance,
		FltObjects->FileObject,
		fileRenameInfo,
		len,
		FileRenameInformation);
}


inline void FreeRecycleName(_In_ UNICODE_STRING* Name) {
	Utility::SafeCapture::FreeUnicodeString(Name);
}

NTSTATUS GenerateRecycleFileName(_Out_ UNICODE_STRING* Name) {

	if (Name == nullptr) {
		return STATUS_INVALID_PARAMETER;
	}

	LARGE_INTEGER currentTime{ 0 };
	KeQuerySystemTime(&currentTime);

	RtlZeroMemory(Name, sizeof(UNICODE_STRING));
	Name->Buffer = static_cast<PWCH>(ExAllocatePool(NonPagedPool, 100));
	if (Name->Buffer == nullptr) {
		return STATUS_MEMORY_NOT_ALLOCATED;
	}

	Name->MaximumLength = 100;
	RtlZeroMemory(Name->Buffer, Name->MaximumLength);
	auto status = RtlInt64ToUnicodeString(currentTime.QuadPart, 16, Name);
	if (!NT_SUCCESS(status)) {
		FreeRecycleName(Name);
		return status;
	}

	return status;
}

FLT_POSTOP_CALLBACK_STATUS
PostCreate(
	_Inout_ PFLT_CALLBACK_DATA Data,
	_In_ PCFLT_RELATED_OBJECTS FltObjects,
	_Flt_CompletionContext_Outptr_ PVOID CompletionContext,
	_In_ FLT_POST_OPERATION_FLAGS Flags
)
{
	UNREFERENCED_PARAMETER(Flags);
	UNREFERENCED_PARAMETER(CompletionContext);

	// if failed
	if (!NT_SUCCESS(Data->IoStatus.Status)) {
		return FLT_POSTOP_FINISHED_PROCESSING;
	}

	// check process name
	auto process = PsGetThreadProcess(Data->Thread);
	BOOLEAN isAllowed = FALSE;
	auto status = IsDeleteAllowed(process, &isAllowed);
	if (!NT_SUCCESS(status)) {
		KdPrint(("failed on IsDeleteAllowed (0x%08X)\n", status));
		return FLT_POSTOP_FINISHED_PROCESSING;
	}
	if (isAllowed) {
		return FLT_POSTOP_FINISHED_PROCESSING;
	}

	// get sid
	UNICODE_STRING sidString{ 0 };
	status = Utility::Process::GetCurrentSidString(&sidString);
	if (!NT_SUCCESS(status)) {
		KdPrint(("failed on GetSidString (0x%08X)\n", status));
		return FLT_POSTOP_FINISHED_PROCESSING;
	}
	auto sidCleanup = wil::scope_exit([&]() {Utility::Process::FreeSidString(&sidString); });


	// generate a random string as file name
	UNICODE_STRING fileName{ 0 };
	status = GenerateRecycleFileName(&fileName);
	if (!NT_SUCCESS(status)) {
		return FLT_POSTOP_FINISHED_PROCESSING;
	}
	auto recycleFileClean = wil::scope_exit([&]() {FreeRecycleName(&fileName); });

	// volume name
	VolumeContext* context = nullptr;
	status = FltGetVolumeContext(FltObjects->Filter,
		FltObjects->Volume,
		reinterpret_cast<PFLT_CONTEXT*>(&context)
	);
	if (!NT_SUCCESS(status)) {
		KdPrint(("failed on FltGetVolumeContext (0x%08X)\n", status));
		return FLT_POSTOP_FINISHED_PROCESSING;
	}
	auto contxtCleanup = wil::scope_exit([&]() {FltReleaseContext(reinterpret_cast<PFLT_CONTEXT>(context)); });

	// full file path
	Utility::String::KString<DRIVER_TAG> fullPath(&context->name);
	fullPath.SafeAppend(L"\\$RECYCLE.BIN\\");
	fullPath.SafeAppend(&sidString);
	fullPath.SafeAppend(L"\\");
	fullPath.SafeAppend(&fileName);


	// if no close flag , save context for further uses
	if (!FlagOn(Data->Iopb->Parameters.Create.Options, FILE_DELETE_ON_CLOSE)) {

		// save context
		FileContext* fileContext = nullptr;
		status = FltAllocateContext(FltObjects->Filter,
			FLT_FILE_CONTEXT,
			sizeof(FileContext),
			NonPagedPool, reinterpret_cast<PFLT_CONTEXT*>(&fileContext));
		if (!NT_SUCCESS(status)) {
			return FLT_POSTOP_FINISHED_PROCESSING;
		}
		RtlZeroMemory(fileContext, sizeof(FileContext));
		auto cleanup = wil::scope_exit([&]() {FltReleaseContext(reinterpret_cast<PFLT_CONTEXT>(fileContext)); });

		status = Utility::SafeCapture::CaptureUnicodeString(&fileContext->name, fullPath.Get(), DRIVER_TAG);
		if (!NT_SUCCESS(status)) {
			return FLT_POSTOP_FINISHED_PROCESSING;
		}

		status = FltSetFileContext(FltObjects->Instance, FltObjects->FileObject, FLT_SET_CONTEXT_KEEP_IF_EXISTS, fileContext, nullptr);
		if (!NT_SUCCESS(status)) {
			return FLT_POSTOP_FINISHED_PROCESSING;
		}
		return FLT_POSTOP_FINISHED_PROCESSING;
	}
	else {

		status = RenameFile(FltObjects, fullPath.Get());
		if (!NT_SUCCESS(status)) {
			KdPrint(("failed on RenameFile (0x%08X)\n", status));
			return FLT_POSTOP_FINISHED_PROCESSING;
		}
		Data->IoStatus.Status = STATUS_SUCCESS;
		return FLT_POSTOP_FINISHED_PROCESSING;
	}
}

FLT_PREOP_CALLBACK_STATUS
PreCreate(
	_Inout_ PFLT_CALLBACK_DATA Data,
	_In_ PCFLT_RELATED_OBJECTS FltObjects,
	_Flt_CompletionContext_Outptr_ PVOID* CompletionContext
)
{
	UNREFERENCED_PARAMETER(CompletionContext);
	UNREFERENCED_PARAMETER(FltObjects);


	if (Data->RequestorMode == KernelMode) {
		return FLT_PREOP_SUCCESS_NO_CALLBACK;
	}

	if (FlagOn(Data->Iopb->Parameters.Create.Options, FILE_DIRECTORY_FILE)) {
		return FLT_PREOP_SUCCESS_NO_CALLBACK;
	}

	if (FlagOn(Data->Iopb->OperationFlags, SL_OPEN_TARGET_DIRECTORY)) {
		return FLT_PREOP_SUCCESS_NO_CALLBACK;
	}

	if (FlagOn(Data->Iopb->OperationFlags, SL_OPEN_PAGING_FILE)) {
		return FLT_PREOP_SUCCESS_NO_CALLBACK;
	}


	if (FlagOn(FltObjects->FileObject->Flags, FO_VOLUME_OPEN)) {
		return FLT_PREOP_SUCCESS_NO_CALLBACK;
	}

	// further processes will be in "PostCreate"
	return FLT_PREOP_SUCCESS_WITH_CALLBACK;
}

FLT_PREOP_CALLBACK_STATUS PreSetInformation(_Inout_ PFLT_CALLBACK_DATA Data, _In_ PCFLT_RELATED_OBJECTS FltObjects, PVOID*) {

	UNREFERENCED_PARAMETER(FltObjects);

	if (Data->RequestorMode == KernelMode) {
		return FLT_PREOP_SUCCESS_NO_CALLBACK;
	}

	auto& params = Data->Iopb->Parameters.SetFileInformation;

	if (params.FileInformationClass == FileDispositionInformation) {
		auto info = static_cast<FILE_DISPOSITION_INFORMATION*>(params.InfoBuffer);
		if (!info->DeleteFile) {
			return FLT_PREOP_SUCCESS_NO_CALLBACK;
		}
	}
	else if (params.FileInformationClass == FileDispositionInformationEx) {
		auto info = static_cast<PFILE_DISPOSITION_INFORMATION_EX>(params.InfoBuffer);
		if (info->Flags != FILE_DISPOSITION_DELETE && info->Flags != FILE_DISPOSITION_POSIX_SEMANTICS) {
			return FLT_PREOP_SUCCESS_NO_CALLBACK;
		}
	}
	else if (params.FileInformationClass == FileRenameInformation) {
		auto info = static_cast<FILE_RENAME_INFORMATION*>(params.InfoBuffer);
		UNICODE_STRING us;
		us.Length = static_cast<USHORT>(info->FileNameLength);
		us.Buffer = info->FileName;
		us.MaximumLength = us.Length;
		KdPrint(("new file name : %wZ\n", &us));
		// not a delete operation
		return FLT_PREOP_SUCCESS_NO_CALLBACK;
	}
	else {
		// not a delete operation
		return FLT_PREOP_SUCCESS_NO_CALLBACK;
	}

	// get file name from context
	FileContext* context = nullptr;
	auto status = FltGetFileContext(FltObjects->Instance, FltObjects->FileObject, reinterpret_cast<PFLT_CONTEXT*>(&context));
	if (!NT_SUCCESS(status)) {
		return FLT_PREOP_SUCCESS_NO_CALLBACK;
	}
	auto contextCleanup = wil::scope_exit([&]() {FltReleaseContext(context); });

	status = RenameFile(FltObjects, &context->name);
	if (!NT_SUCCESS(status)) {
		KdPrint(("failed on RenameFile (0x%08X)\n", status));
		return FLT_PREOP_SUCCESS_NO_CALLBACK;
	}

	Data->IoStatus.Status = STATUS_SUCCESS;
	return FLT_PREOP_COMPLETE;
}

