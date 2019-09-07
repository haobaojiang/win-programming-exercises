#pragma once
#pragma warning( push )
#pragma warning( disable: 5040 )
#include "../../wil/include/wil/resource.h"
#pragma warning( pop )

namespace Utility::String {

	template<ULONG Tag>
	class KString {
	public:
		KString(const UNICODE_STRING* Str) {

			if (Str == nullptr) {
				return;
			}

			auto status = Utility::SafeCapture::CaptureUnicodeString(&m_str, Str, Tag);
			if (!NT_SUCCESS(status)) {
				return;
			}
		}

		~KString() {
			Release();
		}

		const UNICODE_STRING* Get() {
			return &m_str;
		}

		void Release() {
			if (m_str.Buffer) {
				ExFreePoolWithTag(m_str.Buffer, Tag);
				RtlZeroMemory(m_str.Buffer, sizeof(m_str));
			}
		}

		NTSTATUS SafeAppend(PCWSTR Str) {
			UNICODE_STRING us{ 0 };
			RtlInitUnicodeString(&us, Str);
			return SafeAppend(&us);
		}

		NTSTATUS SafeAppend(const UNICODE_STRING* Str) {

			USHORT len = m_str.Length + Str->Length;
			if (len >= m_str.MaximumLength) {
				auto status = Realloc(len + 100);
				if (!NT_SUCCESS(status)) {
					return status;
				}
			}

			return RtlAppendUnicodeStringToString(&m_str, Str);
		}
	protected:
		NTSTATUS Realloc(USHORT N) {

			auto str = ExAllocatePoolWithTag(NonPagedPool, N, Tag);
			if (str == nullptr) {
				return STATUS_MEMORY_NOT_ALLOCATED;
			}

			UNICODE_STRING us;
			us.Length = 0;
			us.MaximumLength = N;
			us.Buffer = static_cast<PWCH>(str);

			RtlCopyUnicodeString(&us, &m_str);

			ExFreePoolWithTag(m_str.Buffer, Tag);
			m_str.Buffer = us.Buffer;
			m_str.Length = us.Length;
			m_str.MaximumLength = us.MaximumLength;

			
			return STATUS_SUCCESS;
		}

	private:
		UNICODE_STRING m_str{ 0 };
		NTSTATUS m_status{ STATUS_SUCCESS };
	};
}

namespace Utility::Process {

	_IRQL_requires_max_(APC_LEVEL)
		NTSTATUS IsProcessDebugged(PEPROCESS eProcess, PBOOLEAN result);

	_IRQL_requires_max_(PASSIVE_LEVEL)
		NTSTATUS GetProcessParentId(HANDLE pid, PHANDLE parentPid);

	_IRQL_requires_max_(PASSIVE_LEVEL)
		NTSTATUS GetProcessFullName(const PEPROCESS Process, PVOID OuputBuffer, ULONG BufferLength);

	_IRQL_requires_max_(PASSIVE_LEVEL)
		NTSTATUS GetSecContextSidString(SECURITY_SUBJECT_CONTEXT* SecContext, __out UNICODE_STRING* SidString);

	_IRQL_requires_max_(PASSIVE_LEVEL)
		NTSTATUS GetCurrentSidString(__out UNICODE_STRING* SidString);

	_IRQL_requires_max_(PASSIVE_LEVEL)
		void FreeSidString(__out UNICODE_STRING* SidString);

	_IRQL_requires_max_(PASSIVE_LEVEL)
		NTSTATUS GetProcessFullName(const PEPROCESS Process, __out UNICODE_STRING* Processname);

	void FreeProcessFullName(UNICODE_STRING* Processname);

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

	void FreeUnicodeString(_In_ UNICODE_STRING* Name);
}

namespace Utility::Reg {
	_IRQL_requires_max_(PASSIVE_LEVEL)
		NTSTATUS SetKeyValue(UNICODE_STRING* Root, UNICODE_STRING* Value, ULONG DataType, const PVOID Data, ULONG DataSize);
}

namespace Utility::Sync {

	class KernelFastMutexLock {

		using MutexGuard = wil::unique_any<PFAST_MUTEX,
			decltype(&::ExReleaseFastMutex),
			::ExReleaseFastMutex>;
	public:
		KernelFastMutexLock() noexcept;
		[[nodiscard]] _IRQL_requires_max_(APC_LEVEL) MutexGuard acquire();
	private:
		FAST_MUTEX m_lock;
	};
}

namespace Utility::Flt {

	_IRQL_requires_max_(APC_LEVEL)
		void FreeFileNameInfo(PFLT_FILE_NAME_INFORMATION* FileNameInfo);

	_IRQL_requires_max_(APC_LEVEL)
		NTSTATUS GetAndParseFileNameInfo(_In_ PFLT_CALLBACK_DATA Data,
			_Out_ PFLT_FILE_NAME_INFORMATION* NameInfo,
			FLT_FILE_NAME_OPTIONS Option = FLT_FILE_NAME_QUERY_DEFAULT | FLT_FILE_NAME_NORMALIZED);

	_IRQL_requires_max_(APC_LEVEL)
		NTSTATUS GetVolumeName(_In_ PFLT_CALLBACK_DATA Data, _Out_ UNICODE_STRING* VolumeName);

	_IRQL_requires_max_(APC_LEVEL)
		NTSTATUS GetFileName(_In_ PFLT_CALLBACK_DATA Data, _Out_ UNICODE_STRING* FileName);

	_IRQL_requires_max_(DISPATCH_LEVEL)
		void FreeName(_Out_ UNICODE_STRING* VolumeName);


	_IRQL_requires_max_(APC_LEVEL)
		NTSTATUS GetVolumeName(PFLT_VOLUME Volume, _Out_ PUNICODE_STRING VolumeName);

}