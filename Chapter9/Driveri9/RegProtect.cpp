#include <ntifs.h>
#include "../../ndcoslo2019/CppKernel/GenericLibrary/Memory.h"
#include "../../utility/utility.h"
#include "RegProtect.h"
#include "common.h"

namespace RegProtect {

	struct Info {
		UNICODE_STRING KeyName;
	};

	struct Filter {
		Utility::Sync::KernelFastMutexLock lock;
		LIST_ENTRY ListHead;
	};


	static Filter* g_Filter = nullptr;

	void FreeItem(FullItem<Info>* Item) {
		if (Item) {
			if (Item->Data.KeyName.Buffer) {
				ExFreePoolWithTag(Item->Data.KeyName.Buffer,DRIVER_TAG);
			}
			delete Item;
		}
	}

	NTSTATUS Add(const PWCHAR KeyName) {

		auto item = new (NonPagedPool, DRIVER_TAG)FullItem<Info>();
		if (item == nullptr) {
			return STATUS_NO_MEMORY;
		}

		USHORT length = static_cast<USHORT>(wcslen(KeyName) * sizeof(WCHAR));
		item->Data.KeyName.Buffer = static_cast<PWCH>(ExAllocatePoolWithTag(NonPagedPool, length, DRIVER_TAG));
		RtlZeroMemory(item->Data.KeyName.Buffer, length);
		item->Data.KeyName.Length = length;
		item->Data.KeyName.MaximumLength = length;
		RtlCopyMemory(item->Data.KeyName.Buffer, KeyName, length);


		auto lockGuard = g_Filter->lock.acquire();
		InsertTailList(&g_Filter->ListHead, &item->Entry);
		return STATUS_SUCCESS;
	}

	BOOLEAN Find(const UNICODE_STRING* KeyName) {
		auto lockGuard = g_Filter->lock.acquire();
		auto  head = &g_Filter->ListHead;
		for (auto p = head->Flink; p != head; p = p->Flink) {
			auto item = CONTAINING_RECORD(p, FullItem<Info>, Entry);
			if (RtlCompareUnicodeString(KeyName, &item->Data.KeyName, TRUE) == 0) {
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

		g_Filter = new (NonPagedPool, DRIVER_TAG)Filter();
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
