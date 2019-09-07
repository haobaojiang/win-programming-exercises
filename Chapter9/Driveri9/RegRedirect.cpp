#include <ntifs.h>
#include "../../ndcoslo2019/CppKernel/GenericLibrary/Memory.h"
#pragma warning( push )
#pragma warning( disable: 5040 )
#include "../../wil/include/wil/resource.h"
#pragma warning( pop )
#include "RegRedirect.h"
#include "common.h"
#include "../../../utility/utility.h"

namespace RegRedirect {

	struct Info {
		UNICODE_STRING ProcessName;
	};

	struct Filter {
		Utility::Sync::KernelFastMutexLock lock;
		LIST_ENTRY ListHead;
	};


	Filter* g_Filter = nullptr;

	void FreeItem(FullItem<Info>* Item) {
		if (Item) {
			if (Item->Data.ProcessName.Buffer) {
				ExFreePoolWithTag(Item->Data.ProcessName.Buffer,DRIVER_TAG);
			}
			delete Item;
		}
	}

	NTSTATUS ProcessRegRedirect(const UNICODE_STRING* KeyName,
		UNICODE_STRING* ValueName,
		const PVOID Data,
		ULONG DataType,
		ULONG DataSize,
		BOOLEAN* SuccessRedirect) {


		UNREFERENCED_PARAMETER(Data);
		UNREFERENCED_PARAMETER(DataType);
		UNREFERENCED_PARAMETER(DataSize);
		UNREFERENCED_PARAMETER(ValueName);

		*SuccessRedirect = FALSE;

		// only intercept the operation if the key name understand HLKM
		static const WCHAR machine[] = L"\\REGISTRY\\MACHINE";
		if (wcsncmp(machine, 
			KeyName->Buffer,
			min(KeyName->Length / sizeof(WCHAR), wcslen(machine)))!=0) {
			return STATUS_SUCCESS;
		}

		// sid
		UNICODE_STRING sidString { 0 };
		auto status = Utility::Process::GetCurrentSidString(&sidString);
		if (!NT_SUCCESS(status)) {
			return status;
		}
		auto cleanup = wil::scope_exit([&]() {
			Utility::Process::FreeSidString(&sidString);
			});

		// key = root + sid + relativePath
		const WCHAR root[] = L"\\REGISTRY\\USER\\";

		USHORT relativePathLength = KeyName->Length - (ARRAYSIZE(machine)-1) * sizeof(WCHAR);
		USHORT sidLength = sidString.Length;
		USHORT totalLength = relativePathLength + sidLength + sizeof(root);

		wil::unique_tagged_pool_ptr<PVOID, DRIVER_TAG> keyBuffer(ExAllocatePoolWithTag(NonPagedPool, totalLength, DRIVER_TAG));
		if (!keyBuffer) {
			return STATUS_MEMORY_NOT_ALLOCATED;
		}
		RtlZeroMemory(keyBuffer.get(), totalLength);

		UNICODE_STRING newKey{ 0 };
		newKey.Buffer = static_cast<PWCH>(keyBuffer.get());
		newKey.Length = 0;
		newKey.MaximumLength = totalLength;

		// copy root
		RtlAppendUnicodeToString(&newKey, root);

		// copy sid
		RtlAppendUnicodeStringToString(&newKey, &sidString);

		// copy relativePath
		UNICODE_STRING relativePathString { 0 };
		relativePathString.Buffer = PWCHAR(KeyName->Buffer) + ARRAYSIZE(machine) - 1;
		relativePathString.Length = relativePathLength;
		relativePathString.MaximumLength = relativePathLength;
		RtlAppendUnicodeStringToString(&newKey, &relativePathString);

		KdPrint(("%wZ\n", &newKey));

		// set key value
		 status = Utility::Reg::SetKeyValue(&newKey, ValueName, DataType, Data, DataSize);
		if (!NT_SUCCESS(status)) {
			return status;
		}

		*SuccessRedirect = TRUE;

		return STATUS_SUCCESS;

	}

	NTSTATUS Add(const PWCHAR ProcessName) {

		auto item = new (NonPagedPool,DRIVER_TAG)FullItem<Info>();
		if (item == nullptr) {
			return STATUS_NO_MEMORY;
		}

		USHORT length = static_cast<USHORT>(wcslen(ProcessName) * sizeof(WCHAR));
		item->Data.ProcessName.Buffer = static_cast<PWCH>(ExAllocatePoolWithTag(NonPagedPool, length, DRIVER_TAG));
		RtlZeroMemory(item->Data.ProcessName.Buffer, length);
		item->Data.ProcessName.Length = length;
		item->Data.ProcessName.MaximumLength = length;
		RtlCopyMemory(item->Data.ProcessName.Buffer, ProcessName, length);


		auto lockGuard = g_Filter->lock.acquire();
		InsertTailList(&g_Filter->ListHead, &item->Entry);
		return STATUS_SUCCESS;
	}

	BOOLEAN Find(const UNICODE_STRING* ProcessName) {
		auto lockGuard = g_Filter->lock.acquire();
		auto  head = &g_Filter->ListHead;
		for (auto p = head->Flink; p != head; p = p->Flink) {
			auto item = CONTAINING_RECORD(p, FullItem<Info>, Entry);
			if (RtlCompareUnicodeString(ProcessName, &item->Data.ProcessName, TRUE)==0) {
				return TRUE;
			}
		}
		return FALSE;
	}

	// call by DriverEntry
	BOOLEAN Initialize() {

		if (g_Filter) {
			return TRUE;
		}

		g_Filter = new (NonPagedPool,DRIVER_TAG)Filter();
		if (g_Filter == nullptr) {
			return FALSE;
		}

		InitializeListHead(&g_Filter->ListHead);
		return TRUE;
	}

	// call by DriverUnload
	BOOLEAN Finiallize() {

		if (g_Filter == nullptr) {
			return TRUE;
		}

		// release resource
		auto  head = &g_Filter->ListHead;
		auto  p = head->Flink;
		while (p != head) {
			auto item = CONTAINING_RECORD(p, FullItem<Info>, Entry);
			p = p->Flink;
			FreeItem(item);
		}

		delete g_Filter;
		g_Filter = nullptr;
		return TRUE;
	}
}
