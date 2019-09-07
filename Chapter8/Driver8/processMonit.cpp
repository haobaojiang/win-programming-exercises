#include <ntifs.h>
#include "../../../ndcoslo2019/CppKernel/GenericLibrary/Memory.h"
#include "../../../ndcoslo2019/CppKernel/GenericLibrary/FastMutex.h"
#include "../../utility/utility.h"
#include "processMonit.h"
#include "common.h"

namespace ProcessMonit {

	struct Info {
		UNICODE_STRING name;
	};

	struct Filter {
		Utility::Sync::KernelFastMutexLock lock;
		LIST_ENTRY ListHead;
		Filter() {
			InitializeListHead(&ListHead);
		}
	};

	Filter* g_Filter = nullptr;

	void FreeItem(FullItem<Info>* Item) {
		if (Item) {
			if (Item->Data.name.Buffer) {
				ExFreePoolWithTag(Item->Data.name.Buffer, DRIVER_TAG);
			}
			delete Item;
		}
	}

	NTSTATUS Add(PCWCHAR Name) {

		auto item = new (NonPagedPool,DRIVER_TAG) FullItem<Info>;
		if (item == nullptr) {
			return STATUS_NO_MEMORY;
		}

		USHORT length = static_cast<USHORT>(wcslen(Name) * sizeof(WCHAR));
		item->Data.name.Buffer = static_cast<PWCH>(ExAllocatePoolWithTag(NonPagedPool, length, DRIVER_TAG));
		RtlZeroMemory(item->Data.name.Buffer, length);
		item->Data.name.Length = length;
		item->Data.name.MaximumLength = length;
		RtlCopyMemory(item->Data.name.Buffer, Name, length);


		auto lockGuard = g_Filter->lock.acquire();
		InsertTailList(&g_Filter->ListHead, &item->Entry);
		return STATUS_SUCCESS;
	}


	void Remove(PCWCHAR Name) {

		UNICODE_STRING us = { 0 };
		RtlInitUnicodeString(&us, Name);

		auto lockGuard = g_Filter->lock.acquire();
		auto  head = &g_Filter->ListHead;
		for (auto p = head->Flink; p != head; p = p->Flink) {
			auto item = CONTAINING_RECORD(p, FullItem<Info>, Entry);
			if (RtlCompareUnicodeString(&us, &item->Data.name, TRUE)==0) {
				RemoveEntryList(p);
				FreeItem(item);
				break;
			}
		}
	}

	void Clear() {
		auto lockGuard = g_Filter->lock.acquire();
		while (!IsListEmpty(&g_Filter->ListHead))
		{
			auto p = RemoveHeadList(&g_Filter->ListHead);
			auto item = CONTAINING_RECORD(p, FullItem<Info>, Entry);
			FreeItem(item);
		}
	}

	BOOLEAN Find(PCUNICODE_STRING Name) {

		auto lockGuard = g_Filter->lock.acquire();
		auto  head = &g_Filter->ListHead;
		for (auto p = head->Flink; p != head; p = p->Flink) {
			auto item = CONTAINING_RECORD(p, FullItem<Info>, Entry);
			if (RtlCompareUnicodeString(Name, &item->Data.name, TRUE) == 0) {
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

		g_Filter = new (NonPagedPool,DRIVER_TAG) Filter();
		if (g_Filter == nullptr) {
			return FALSE;
		}


		return TRUE;
	}

	// call by DriverUnload
	VOID Finiallize() {

		if (g_Filter == nullptr) {
			return ;
		}

		// release resource
		auto  head = &g_Filter->ListHead;
		auto  p = head->Flink;
		while(p != head) {
			auto item = CONTAINING_RECORD(p, FullItem<Info>, Entry);
			p = p->Flink;
			FreeItem(item);
		}

		delete g_Filter;
		g_Filter = nullptr;
	}
}