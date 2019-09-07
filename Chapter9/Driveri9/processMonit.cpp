#include <ntifs.h>
#include <GenericLibrary/Memory.h>
#include <wil/resource.h>
#include "processMonit.h"
#include "common.h"

namespace ProcessMonit {

	struct Info {
		UNICODE_STRING KeyName;
	};

	struct Filter {
		wil::kernel_spin_lock lock;
		LIST_ENTRY ListHead;
	};

	static Filter* g_Filter = nullptr;

	NTSTATUS Add(PCWCHAR KeyName) {

		auto item = new (NonPagedPool,DRIVER_TAG) FullItem<Info>;
		if (item == nullptr) {
			return STATUS_NO_MEMORY;
		}

		USHORT length = static_cast<USHORT>(wcslen(KeyName) * sizeof(WCHAR));
		item->Data.KeyName.Buffer = reinterpret_cast<PWCH>(new (NonPagedPool,DRIVER_TAG) UCHAR[length]);
		RtlZeroMemory(item->Data.KeyName.Buffer, length);
		item->Data.KeyName.Length = length;
		item->Data.KeyName.MaximumLength = length;
		RtlCopyMemory(item->Data.KeyName.Buffer, KeyName, length);


		auto lockGuard = g_Filter->lock.acquire();
		InsertHeadList(&g_Filter->ListHead, &item->Entry);
		return STATUS_SUCCESS;
	}

	void Remove(PCWCHAR KeyName) {

		UNICODE_STRING us = { 0 };
		RtlInitUnicodeString(&us, KeyName);

		auto lockGuard = g_Filter->lock.acquire();
		auto  head = g_Filter->ListHead;
		for (auto p = head.Flink; p != &head; p = p->Flink) {
			auto item = CONTAINING_RECORD(p, FullItem<Info>, Entry);
			if (RtlEqualUnicodeString(&us, &item->Data.KeyName, FALSE)) {
				RemoveEntryList(p);
				delete item->Data.KeyName.Buffer;
				delete item;
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
			delete item->Data.KeyName.Buffer;
			delete item;
		}
	}

	BOOLEAN IsExists(PCUNICODE_STRING KeyName) {

		auto lockGuard = g_Filter->lock.acquire();
		auto  head = g_Filter->ListHead;
		for (auto p = head.Flink; p != &head; p = p->Flink) {
			auto item = CONTAINING_RECORD(p, FullItem<Info>, Entry);
			if (RtlEqualUnicodeString(KeyName, &item->Data.KeyName, FALSE)) {
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

		InitializeListHead(&g_Filter->ListHead);
		return TRUE;
	}

	// call by DriverUnload
	BOOLEAN Finiallize() {

		if (g_Filter == nullptr) {
			return TRUE;
		}

		// release resource
		auto  head = g_Filter->ListHead;
		for (auto p = head.Flink; p != &head; p = p->Flink) {
			auto item = CONTAINING_RECORD(p, FullItem<Info>, Entry);
			delete item->Data.KeyName.Buffer;
			delete item;
		}

		delete g_Filter;
		g_Filter = nullptr;
		return true;
	}
}