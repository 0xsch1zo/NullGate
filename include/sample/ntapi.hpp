#pragma once

#include <windows.h>

#define THREAD_CREATE_FLAGS_CREATE_SUSPENDED                                   \
  0x00000001 // NtCreateUserProcess & NtCreateThreadEx
#define THREAD_CREATE_FLAGS_SKIP_THREAD_ATTACH                                 \
  0x00000002 // NtCreateThreadEx only
#define THREAD_CREATE_FLAGS_HIDE_FROM_DEBUGGER                                 \
  0x00000004 // NtCreateThreadEx only
#define THREAD_CREATE_FLAGS_LOADER_WORKER                                      \
  0x00000010 // NtCreateThreadEx only // since THRESHOLD
#define THREAD_CREATE_FLAGS_SKIP_LOADER_INIT                                   \
  0x00000020 // NtCreateThreadEx only // since REDSTONE2
#define THREAD_CREATE_FLAGS_BYPASS_PROCESS_FREEZE                              \
  0x00000040 // NtCreateThreadEx only // since 19H1

#define NT_SUCCESS(Status) (((NTSTATUS)(Status)) >= 0)

typedef struct _UNICODE_STRING {
  USHORT Length;
  USHORT MaximumLength;
#ifdef MIDL_PASS
  [ size_is(MaximumLength / 2), length_is((Length) / 2) ] USHORT *Buffer;
#else  // MIDL_PASS
  _Field_size_bytes_part_opt_(MaximumLength, Length) PWCH Buffer;
#endif // MIDL_PASS
} UNICODE_STRING;
typedef UNICODE_STRING *PUNICODE_STRING;
typedef const UNICODE_STRING *PCUNICODE_STRING;
// end_sdfwdm
// end_wudfwdm

#define UNICODE_NULL ((WCHAR)0) // winnt

typedef struct _OBJECT_ATTRIBUTES {
  ULONG Length;
  HANDLE RootDirectory;
  PUNICODE_STRING ObjectName;
  ULONG Attributes;
  PVOID SecurityDescriptor;       // Points to type SECURITY_DESCRIPTOR
  PVOID SecurityQualityOfService; // Points to type SECURITY_QUALITY_OF_SERVICE
} OBJECT_ATTRIBUTES;
typedef OBJECT_ATTRIBUTES *POBJECT_ATTRIBUTES;
typedef CONST OBJECT_ATTRIBUTES *PCOBJECT_ATTRIBUTES;

// 0x10 bytes (sizeof)
typedef struct _CLIENT_ID {
  VOID *UniqueProcess; // 0x0
  VOID *UniqueThread;  // 0x8
} CLIENT_ID, *PCLIENT_ID;

typedef struct _PS_ATTRIBUTE {
  ULONG_PTR Attribute;
  SIZE_T Size;
  union {
    ULONG_PTR Value;
    PVOID ValuePtr;
  };
  PSIZE_T ReturnLength;
} PS_ATTRIBUTE, *PPS_ATTRIBUTE;

typedef struct _PS_ATTRIBUTE_LIST {
  SIZE_T TotalLength;
  PS_ATTRIBUTE Attributes[1];
} PS_ATTRIBUTE_LIST, *PPS_ATTRIBUTE_LIST;

typedef _Function_class_(USER_THREAD_START_ROUTINE) NTSTATUS NTAPI
    USER_THREAD_START_ROUTINE(_In_ PVOID ThreadParameter);
typedef USER_THREAD_START_ROUTINE *PUSER_THREAD_START_ROUTINE;

typedef NTSTATUS NTAPI NtOpenProcess(_Out_ PHANDLE ProcessHandle,
                                     _In_ ACCESS_MASK DesiredAccess,
                                     _In_ PCOBJECT_ATTRIBUTES ObjectAttributes,
                                     _In_opt_ PCLIENT_ID ClientId);

typedef NTSTATUS NTAPI NtAllocateVirtualMemory(
    _In_ HANDLE ProcessHandle,
    _Inout_ _At_(*BaseAddress,
                 _Readable_bytes_(*RegionSize) _Writable_bytes_(*RegionSize)
                     _Post_readable_byte_size_(*RegionSize)) PVOID *BaseAddress,
    _In_ ULONG_PTR ZeroBits, _Inout_ PSIZE_T RegionSize,
    _In_ ULONG AllocationType, _In_ ULONG PageProtection);

typedef NTSTATUS NTAPI NtWriteVirtualMemory(
    _In_ HANDLE ProcessHandle, _In_opt_ PVOID BaseAddress,
    _In_reads_bytes_(NumberOfBytesToWrite) PVOID Buffer,
    _In_ SIZE_T NumberOfBytesToWrite, _Out_opt_ PSIZE_T NumberOfBytesWritten);

typedef NTSTATUS NTAPI NtCreateThreadEx(
    _Out_ PHANDLE ThreadHandle, _In_ ACCESS_MASK DesiredAccess,
    _In_opt_ PCOBJECT_ATTRIBUTES ObjectAttributes, _In_ HANDLE ProcessHandle,
    _In_ PUSER_THREAD_START_ROUTINE StartRoutine, _In_opt_ PVOID Argument,
    _In_ ULONG CreateFlags, // THREAD_CREATE_FLAGS_*
    _In_ SIZE_T ZeroBits, _In_ SIZE_T StackSize, _In_ SIZE_T MaximumStackSize,
    _In_opt_ PPS_ATTRIBUTE_LIST AttributeList);

typedef NTSTATUS NTAPI NtResumeThread(_In_ HANDLE ThreadHandle,
                                      _Out_opt_ PULONG PreviousSuspendCount);

typedef NTSTATUS NTAPI NtClose(_In_ HANDLE Handle);

typedef NTSTATUS NTAPI NtWaitForSingleObject(_In_ HANDLE Handle,
                                             _In_ BOOLEAN Alertable,
                                             _In_opt_ PLARGE_INTEGER Timeout);

typedef NTSTATUS NTAPI NtQuerySystemTime(_Out_ PLARGE_INTEGER SystemTime);
