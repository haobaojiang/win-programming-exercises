#include <ntifs.h>
#include <ntstrsafe.h>
#include "common.h"
#include "../../../utility/utility.h"
#pragma warning( push )
#pragma warning( disable: 5040 )
#include "../../wil/include/wil/resource.h"
#pragma warning( pop )
#include "../../../ndcoslo2019/CppKernel/GenericLibrary/Memory.h"
#include "RegProtect.h"
#include "RegRedirect.h"

DRIVER_UNLOAD DriverUnload;
DRIVER_DISPATCH DeviceControl;
DRIVER_DISPATCH ProcessProtectCreateClose;

#define PROCESS_CREATE_THREAD              (0x0002)  
#define PROCESS_QUERY_INFORMATION          (0x0400)  
#define PROCESS_VM_OPERATION               (0x0008) 
#define PROCESS_VM_WRITE                   (0x0020) 
#define PROCESS_VM_READ                    (0x0010)

const ULONG RemoteThreadAccessMask = (PROCESS_CREATE_THREAD |
	PROCESS_QUERY_INFORMATION
	| PROCESS_VM_OPERATION
	| PROCESS_VM_WRITE
	| PROCESS_VM_READ);

//
struct Globals {
	PVOID regHandle = nullptr;  // preProcess
	LARGE_INTEGER regCookie{ 0 }; //registry
};

static Globals* g_Data = nullptr;


NTSTATUS OnRegistryNotify(PVOID context, PVOID arg1, PVOID arg2);


/*
   9.1 Implement a driver that will not allow thread injection into other processes unless the target process is being debugged.
*/
OB_PREOP_CALLBACK_STATUS OnPreOpenProcess(PVOID /* RegistrationContext */, POB_PRE_OPERATION_INFORMATION Info) {

	do
	{
		if (Info->KernelHandle) {
			break;
		}

		auto process = static_cast<PEPROCESS>(Info->Object);
		auto currentProcess = PsGetCurrentProcess();
		if (currentProcess == process) {
			break;
		}

		if (Info->Operation == OB_OPERATION_HANDLE_CREATE &&
			(Info->Parameters->CreateHandleInformation.DesiredAccess & RemoteThreadAccessMask)) {

			BOOLEAN isDebugged = FALSE;
			auto status = Utility::Process::IsProcessDebugged(process, &isDebugged);
			if (!NT_SUCCESS(status)) {
				KdPrint(("failed on IsProcessDebugged, status (0x%08X)\n", status));
				break;
			}

			if (isDebugged) {
				break;
			}

			Info->Parameters->CreateHandleInformation.DesiredAccess &= ~PROCESS_CREATE_THREAD;

		}
		else {
			if (Info->Parameters->DuplicateHandleInformation.DesiredAccess & RemoteThreadAccessMask) {

				BOOLEAN isDebugged = FALSE;
				auto status = Utility::Process::IsProcessDebugged(process, &isDebugged);
				if (!NT_SUCCESS(status)) {
					KdPrint(("failed on IsProcessDebugged, status (0x%08X)\n", status));
					break;
				}

				if (isDebugged) {
					break;
				}

				Info->Parameters->DuplicateHandleInformation.DesiredAccess &= ~PROCESS_CREATE_THREAD;
			}
		}
	} while (false);

	return OB_PREOP_SUCCESS;
}




NTSTATUS OnRegistryNotify(PVOID, PVOID arg1, PVOID arg2) {

	auto status = STATUS_SUCCESS;

	switch ((REG_NOTIFY_CLASS)(ULONG_PTR)arg1) {
	case RegNtPreSetValueKey: {

		auto preInfo = static_cast<PREG_SET_VALUE_KEY_INFORMATION>(arg2);
		PCUNICODE_STRING keyName = nullptr;
		if (!NT_SUCCESS(CmCallbackGetKeyObjectID(&g_Data->regCookie, preInfo->Object, nullptr, &keyName))) {
			break;
		}

		/*
		   9.2 Implement a driver that protects a registry key from modifications. A client can send the driver registry keys to protect or unprotect
		*/

		if (RegProtect::Find(keyName)) {
			status = STATUS_CALLBACK_BYPASS;
			break;
		}

		/*
		   9.3 Implement a driver that redirects registry write operations coming from selected processes (configured by a client application)
		   to their own private key if they access HKEY_LOCAL_MACHINE.
		   If the app is writing data, it goes to its private store.
		   If it¡¯s reading data, first check the private store,
		   and if no value is there go to the real registry key.
		   This is one facet of application sandboxing
		*/

		// only intercept selected process
		WCHAR processName[300] = { 0 };
		status = Utility::Process::GetProcessFullName(PsGetCurrentProcess(), processName, sizeof(processName) - sizeof(WCHAR));
		if (!NT_SUCCESS(status)) {
			KdPrint(("failed to GetProcessFullName (0x%08X)\n", status));
			status = STATUS_SUCCESS; // let it continue
			break;

		}
		UNICODE_STRING us;
		RtlInitUnicodeString(&us, processName);
		if (!RegRedirect::Find(&us)) {
			break;
		}

		// get key data
		PVOID data = nullptr;
		status = Utility::SafeCapture::CaptureBuffer(&data,
			preInfo->Data,
			preInfo->DataSize,
			DRIVER_TAG);
		if (!NT_SUCCESS(status)) {
			KdPrint(("failed to CaptureBuffer (0x%08X)\n", status));
			status = STATUS_SUCCESS; // let it continue
			break;
		}
		auto cleanup = wil::scope_exit([&] {Utility::SafeCapture::FreeCapturedBuffer(data, DRIVER_TAG); });

		// 
		BOOLEAN successRedirect = FALSE;
		status = RegRedirect::ProcessRegRedirect(keyName,
			preInfo->ValueName,
			data,
			preInfo->Type,
			preInfo->DataSize,
			&successRedirect);
		if (!NT_SUCCESS(status)) {
			KdPrint(("failed to ProcessRegRedirect: (0x%08X)\n", status));
			status = STATUS_SUCCESS; // let it continue
			break;
		}

		if (successRedirect) {
			status = STATUS_CALLBACK_BYPASS;
			break;
		}

		break;
	}

	}
	return status;
}



extern "C" NTSTATUS
DriverEntry(PDRIVER_OBJECT DriverObject, PUNICODE_STRING) {

	NTSTATUS status = STATUS_SUCCESS;
	PDEVICE_OBJECT DeviceObject = nullptr;
	UNICODE_STRING symLink = RTL_CONSTANT_STRING(SYM_LINK_NAME);
	UNICODE_STRING devName = RTL_CONSTANT_STRING(DEVICE_NAME);
	bool symLinkCreate = false;
	bool registerCallBack = false;



	OB_OPERATION_REGISTRATION operations[] = {
	{
		PsProcessType,		// object type
		OB_OPERATION_HANDLE_CREATE | OB_OPERATION_HANDLE_DUPLICATE,
		OnPreOpenProcess, nullptr	// pre, post
	}
	};
	OB_CALLBACK_REGISTRATION reg = {
		OB_FLT_REGISTRATION_VERSION,
		1,				// operation count
		RTL_CONSTANT_STRING(L"12345.6171"),		// altitude
		nullptr,		// context
		operations
	};

	do
	{
		if (!RegProtect::Initialize()) {
			status = STATUS_UNSUCCESSFUL;
			KdPrint(("failed to RegProtect::Initialize()"));
			break;
		}

		if (!RegRedirect::Initialize()) {
			status = STATUS_UNSUCCESSFUL;
			KdPrint(("failed to RegRedirect::Initialize()"));
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

		// ObRegisterCallbacks
		status = ObRegisterCallbacks(&reg, &g_Data->regHandle);
		if (!NT_SUCCESS(status)) {
			KdPrint(("failed on ObRegisterCallbacks (0x%08X)\n", status));
			break;
		}

		// reg callBack
		UNICODE_STRING altitude = RTL_CONSTANT_STRING(L"7657.124");
		status = CmRegisterCallbackEx(OnRegistryNotify, &altitude, DriverObject, nullptr, &g_Data->regCookie, nullptr);
		if (!NT_SUCCESS(status)) {
			KdPrint(("failed on CmRegisterCallbackEx (0x%08X)\n", status));
			break;
		}
		registerCallBack = true;


		break;

	} while (false);


	if (!NT_SUCCESS(status)) {

		RegRedirect::Finiallize();
		RegProtect::Finiallize();

		if (registerCallBack) {
			status = CmUnRegisterCallback(g_Data->regCookie);
			if (!NT_SUCCESS(status)) {
				KdPrint(("failed on CmUnRegisterCallback (0x%08X)\n", status));
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
			if (g_Data->regHandle) {
				ObUnRegisterCallbacks(g_Data->regHandle);
			}
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



	case IOCTL_REG_KEY_REDIRCT_ADD: {

		auto size = stack->Parameters.DeviceIoControl.InputBufferLength;
		if (size < sizeof(RegRedirectInfo)) {
			status = STATUS_INVALID_BUFFER_SIZE;
			break;
		}

		auto data = static_cast<RegRedirectInfo*>(Irp->AssociatedIrp.SystemBuffer);
		status = RegRedirect::Add(data->ProcessName);
		if (!NT_SUCCESS(status)) {
			KdPrint(("failed on RegFilter::Add (0x%08X)\n", status));
			break;
		}

		break;
	}

	case IOCTL_REG_PROTECT_ADD: {

		auto size = stack->Parameters.DeviceIoControl.InputBufferLength;
		if (size < sizeof(RegRedirectInfo)) {
			status = STATUS_INVALID_BUFFER_SIZE;
			break;
		}

		auto data = static_cast<RegKeyProtectInfo*>(Irp->AssociatedIrp.SystemBuffer);
		status = RegProtect::Add(data->KeyName);
		if (!NT_SUCCESS(status)) {
			KdPrint(("failed on RegFilter::Add (0x%08X)\n", status));
			break;
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

	RegRedirect::Finiallize();
	RegProtect::Finiallize();

	auto status = CmUnRegisterCallback(g_Data->regCookie);
	if (!NT_SUCCESS(status)) {
		KdPrint(("failed on CmUnRegisterCallback (0x%08X)\n", status));
	}

	UNICODE_STRING symLink = RTL_CONSTANT_STRING(SYM_LINK_NAME);
	status = IoDeleteSymbolicLink(&symLink);
	if (!NT_SUCCESS(status)) {
		KdPrint(("failed on IoDeleteSymbolicLink (0x%08X)\n", status));
	}


	IoDeleteDevice(DriverObject->DeviceObject);


	if (g_Data) {
		if (g_Data->regHandle) {
			ObUnRegisterCallbacks(g_Data->regHandle);
		}
		delete g_Data;
	}
}