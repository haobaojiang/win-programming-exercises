#include <ntifs.h>
#include "../../../ndcoslo2019/CppKernel/GenericLibrary/Memory.h"
#include "../../wil/include/wil/resource.h"
#include <ntstrsafe.h>
#include "common.h"
#include "processMonit.h"
#include "../../utility/utility.h"


DRIVER_UNLOAD DriverUnload;
DRIVER_DISPATCH DeviceControl;
DRIVER_DISPATCH ProcessProtectCreateClose;

//
struct Globals {
	LIST_ENTRY itemsHead;
	int itemCount;
	Utility::Sync::KernelFastMutexLock lock;
};

static Globals* g_Data = nullptr;


NTSTATUS OnRegistryNotify(PVOID context, PVOID arg1, PVOID arg2);


void PushItem(LIST_ENTRY* entry) {
	auto lockGuard = g_Data->lock.acquire();
	if (g_Data->itemCount > 1024) {
		// too many items, remove oldest one
		auto head = RemoveHeadList(&g_Data->itemsHead);
		g_Data->itemCount--;
		auto item = CONTAINING_RECORD(head, FullItem<ItemHeader>, Entry);
		ExFreePool(item);
	}
	InsertTailList(&g_Data->itemsHead, entry);
	g_Data->itemCount++;
}



void OnProcessNotify(PEPROCESS Process, HANDLE ProcessId, PPS_CREATE_NOTIFY_INFO CreateInfo) {

	// we only intercept create event
	if (CreateInfo == nullptr) {
		return;
	}

	KdPrint(("process create event , pid: %d\n", ProcessId));

	// look up process path
	UNICODE_STRING processName { 0 };
	auto status = Utility::Process::GetProcessFullName(Process,&processName);
	if (!NT_SUCCESS(status)) {
		KdPrint(("GetProcessFullName() failed ,status : (0x%08X)\n", status));
		return;
	}
	auto cleanup = Utility::Process::FreeProcessFullName(&processName);
	if (!ProcessMonit::Find(&processName)) {
		return;
	}
	
	// generate event
	USHORT allocSize = sizeof(FullItem<ProcessCreateInfo>);
	USHORT commandLineSize = 0;
	if (CreateInfo->CommandLine) {
		commandLineSize = CreateInfo->CommandLine->Length;
		allocSize += commandLineSize;
	}
	
	auto info = (FullItem<ProcessCreateInfo>*)ExAllocatePoolWithTag(NonPagedPool, allocSize, DRIVER_TAG);
	if (info == nullptr) {
		KdPrint(("failed allocation\n"));
		return;
	}
	auto& item = info->Data;
	KeQuerySystemTime(&item.Time);
	item.Type = ItemType::ProcessCreate;
	item.Size = sizeof(ProcessCreateInfo) + commandLineSize;
	item.ProcessId = HandleToULong(ProcessId);
	item.ParentProcessId = HandleToULong(CreateInfo->ParentProcessId);

	if (commandLineSize > 0) {
		::memcpy((UCHAR*)& item + sizeof(item), CreateInfo->CommandLine->Buffer, commandLineSize);
		item.CommandLineLength = commandLineSize / sizeof(WCHAR);
		item.CommandLineOffset = sizeof(item);
	}
	else {
		item.CommandLineLength = 0;
	}
	PushItem(&info->Entry);
}

void OnThreadNotify(HANDLE processId, HANDLE threadId, BOOLEAN isCreate) {

	if (!isCreate) {
		return;
	}

	auto currentPid = PsGetCurrentProcessId();
	if (currentPid == processId) {
		return;
	}

	HANDLE parentPid = nullptr;
	auto status = Utility::Process::GetProcessParentId(processId, &parentPid);
	if (!NT_SUCCESS(status)) {
		KdPrint(("failed to get parentId, threadId:%d ,status : (0x%08X)\n", threadId, status));
		return;
	}

	// the first thread of a process is always created by its parent process
	if (parentPid == currentPid) {
		return;
	}

	KdPrint(("remote thread injected, currentPid:%d, pid:%d\n", currentPid, processId));

	auto size = sizeof(FullItem<RemoteThreadInfo>);
	auto info = (FullItem<RemoteThreadInfo>*)ExAllocatePoolWithTag(NonPagedPool, size, DRIVER_TAG);
	if (info == nullptr) {
		KdPrint(("Failed to allocate memory\n"));
		return;
	}

	auto& item = info->Data;
	KeQuerySystemTime(&item.Time);
	item.Size = sizeof(item);
	item.Type = ItemType::RemoteThreadCreate;
	item.ProcessId = HandleToULong(processId);
	item.ThreadId = HandleToULong(threadId);

	PushItem(&info->Entry);
}




extern "C" NTSTATUS
DriverEntry(PDRIVER_OBJECT DriverObject, PUNICODE_STRING) {

	NTSTATUS status = STATUS_SUCCESS;
	PDEVICE_OBJECT DeviceObject = nullptr;
	UNICODE_STRING symLink = RTL_CONSTANT_STRING(SYM_LINK_NAME);
	UNICODE_STRING devName = RTL_CONSTANT_STRING(DEVICE_NAME);
	bool symLinkCreate = false;
	bool threadCallBack = false;

	do
	{

		if (!ProcessMonit::Initialize()) {
			KdPrint(("failed at ProcessMonit::Initialize()"));
			status = STATUS_UNSUCCESSFUL;
			break;
		}

		// device object
		status = IoCreateDevice(DriverObject,
			0,
			&devName,
			FILE_DEVICE_UNKNOWN,
			0,
			TRUE,
			&DeviceObject);
		if (!NT_SUCCESS(status)) {
			KdPrint(("failed to create device (0x%08X)\n", status));
			break;
		}
		DeviceObject->Flags |= DO_BUFFERED_IO;

		// symbolic
		status = IoCreateSymbolicLink(&symLink, &devName);
		if (!NT_SUCCESS(status)) {
			KdPrint(("failed to create symLink (0x%08X)\n", status));
			break;
		}
		symLinkCreate = true;

		// global variable
		g_Data = new (NonPagedPool, DRIVER_TAG) Globals;
		if (g_Data == nullptr) {
			KdPrint(("failed on new vector<ProcessCreateInfo> (0x%08X)\n", status));
			break;
		}
		InitializeListHead(&g_Data->itemsHead);
		
		// thread callBack
		status = PsSetCreateThreadNotifyRoutine(OnThreadNotify);
		if (!NT_SUCCESS(status)) {
			KdPrint(("failed on PsSetCreateThreadNotifyRoutine (0x%08X)\n", status));
			break;
		}
		threadCallBack = true;

		// process callBack
		status = PsSetCreateProcessNotifyRoutineEx(OnProcessNotify, FALSE);
		if (!NT_SUCCESS(status)) {
			KdPrint(("failed on PsSetCreateProcessNotifyRoutineEx (0x%08X)\n", status));
			break;
		}

		break;

	} while (false);


	if (!NT_SUCCESS(status)) {


		ProcessMonit::Finiallize();

		if (threadCallBack) {
			status = PsRemoveCreateThreadNotifyRoutine(OnThreadNotify);
			if (!NT_SUCCESS(status)) {
				KdPrint(("failed on PsRemoveCreateThreadNotifyRoutine (0x%08X)\n", status));
			}
		}
		if (symLinkCreate) {
			status = IoDeleteSymbolicLink(&symLink);
			if (!NT_SUCCESS(status)) {
				KdPrint(("failed on IoDeleteSymbolicLink (0x%08X)\n", status));
			}
		}
		if (DeviceObject) {
			IoDeleteDevice(DeviceObject);
		}
		if (g_Data) {
			delete g_Data;
		}

		return STATUS_UNSUCCESSFUL;
	}

	DriverObject->DriverUnload = DriverUnload;
	DriverObject->MajorFunction[IRP_MJ_DEVICE_CONTROL] = DeviceControl;
	DriverObject->MajorFunction[IRP_MJ_CREATE] = ProcessProtectCreateClose;
	DriverObject->MajorFunction[IRP_MJ_CLOSE] = ProcessProtectCreateClose;
	return STATUS_SUCCESS;
}

NTSTATUS ProcessProtectCreateClose(PDEVICE_OBJECT, PIRP Irp) {
	Irp->IoStatus.Status = STATUS_SUCCESS;
	Irp->IoStatus.Information = 0;
	IoCompleteRequest(Irp, IO_NO_INCREMENT);
	return STATUS_SUCCESS;
}

NTSTATUS DeviceControl(PDEVICE_OBJECT, PIRP Irp) {

	auto stack = IoGetCurrentIrpStackLocation(Irp);
	auto status = STATUS_SUCCESS;
	auto len = 0;

	switch (stack->Parameters.DeviceIoControl.IoControlCode) {

	case IOCTL_MONIT_PROCESS_ADD: {

		auto size = stack->Parameters.DeviceIoControl.InputBufferLength;
		if (size != sizeof(ExecInfo)) {
			status = STATUS_INVALID_BUFFER_SIZE;
			break;
		}

		auto data = static_cast<ExecInfo*>(Irp->AssociatedIrp.SystemBuffer);
		status = ProcessMonit::Add(data->Path);
		if (!NT_SUCCESS(status)) {
			KdPrint(("failed on rocessMonit::Add (0x%08X)\n", status));
			break;
		}
		break;
	}

	case IOCTL_MONIT_PROCESS_CLEAR: {
		ProcessMonit::Clear();
		break;
	}

	case IOCTL_EVENTS_READ: {

		auto outputBuffer = static_cast<UCHAR*>(Irp->AssociatedIrp.SystemBuffer);
		auto bufferLength = stack->Parameters.DeviceIoControl.OutputBufferLength;

		auto lockGuard = g_Data->lock.acquire();
		while (true) {
			if (IsListEmpty(&g_Data->itemsHead))	// can also check g_Globals.ItemCount
				break;

			auto entry = RemoveHeadList(&g_Data->itemsHead);
			auto info = CONTAINING_RECORD(entry, FullItem<ItemHeader>, Entry);
			auto size = info->Data.Size;
			if (bufferLength < size) {
				// user's buffer full, insert item back
				InsertHeadList(&g_Data->itemsHead, entry);
				break;
			}
			g_Data->itemCount--;
			::memcpy(outputBuffer, &info->Data, size);
			bufferLength -= size;
			outputBuffer += size;
			len += size;

			ExFreePool(info);
		}
		break;
	}


	default:
		status = STATUS_INVALID_DEVICE_REQUEST;
		break;
	}

	Irp->IoStatus.Status = status;
	Irp->IoStatus.Information = len;
	IoCompleteRequest(Irp, IO_NO_INCREMENT);
	return status;
}


void DriverUnload(PDRIVER_OBJECT DriverObject) {

	auto status = PsSetCreateProcessNotifyRoutineEx(OnProcessNotify, true);
	if (!NT_SUCCESS(status)) {
		KdPrint(("failed on PsRemoveLoadImageNotifyRoutine (0x%08X)\n", status));
	}

	status = PsRemoveCreateThreadNotifyRoutine(OnThreadNotify);
	if (!NT_SUCCESS(status)) {
		KdPrint(("failed on PsRemoveCreateThreadNotifyRoutine (0x%08X)\n", status));
	}

	UNICODE_STRING symLink = RTL_CONSTANT_STRING(SYM_LINK_NAME);
	status = IoDeleteSymbolicLink(&symLink);
	if (!NT_SUCCESS(status)) {
		KdPrint(("failed on IoDeleteSymbolicLink (0x%08X)\n", status));
	}

	IoDeleteDevice(DriverObject->DeviceObject);


	ProcessMonit::Finiallize();

	//
	while (!IsListEmpty(&g_Data->itemsHead)) {
		auto entry = RemoveHeadList(&g_Data->itemsHead);
		ExFreePool(CONTAINING_RECORD(entry, FullItem<ItemHeader>, Entry));
	}

	if (g_Data) {
		delete g_Data;
	}
}