#pragma once


#include <ntddk.h>
#include <wdm.h>
#include <ntstrsafe.h>

extern "C" {
    typedef enum _GDP_SYSTEM_INFORMATION_CLASS {
        GDP_SystemBasicInformation = 0,
        GDP_SystemProcessorInformation = 1,
        GDP_SystemPerformanceInformation = 2,
        GDP_SystemTimeOfDayInformation = 3,
        GDP_SystemPathInformation = 4,
        GDP_SystemProcessInformation = 5,
        GDP_SystemCallCountInformation = 6,
        GDP_SystemDeviceInformation = 7,
        GDP_SystemProcessorPerformanceInformation = 8,
        GDP_SystemFlagsInformation = 9,
        GDP_SystemCallTimeInformation = 10,
        GDP_SystemModuleInformation = 11,
        GDP_SystemLocksInformation = 12,
        GDP_SystemStackTraceInformation = 13,
        GDP_SystemPagedPoolInformation = 14,
        GDP_SystemNonPagedPoolInformation = 15,
        GDP_SystemHandleInformation = 16,
        GDP_SystemObjectInformation = 17,
        GDP_SystemPageFileInformation = 18,
        GDP_SystemVdmInstemulInformation = 19,
        GDP_SystemVdmBopInformation = 20,
        GDP_SystemFileCacheInformation = 21,
        GDP_SystemPoolTagInformation = 22,
        GDP_SystemInterruptInformation = 23,
        GDP_SystemDpcBehaviorInformation = 24,
        GDP_SystemFullMemoryInformation = 25,
        GDP_SystemLoadGdiDriverInformation = 26,
        GDP_SystemUnloadGdiDriverInformation = 27,
        GDP_SystemTimeAdjustmentInformation = 28,
        GDP_SystemSummaryMemoryInformation = 29,
        GDP_SystemMirrorMemoryInformation = 30,
        GDP_SystemPerformanceTraceInformation = 31,
        GDP_SystemObsolete0 = 32,
        GDP_SystemExceptionInformation = 33,
        GDP_SystemCrashDumpStateInformation = 34,
        GDP_SystemKernelDebuggerInformation = 35,
        GDP_SystemContextSwitchInformation = 36,
        GDP_SystemRegistryQuotaInformation = 37,
        GDP_SystemExtendServiceTableInformation = 38,
        GDP_SystemPrioritySeperation = 39,
        GDP_SystemVerifierNullDriverInformation = 40,
        GDP_SystemCopyOnWriteInformation = 41,
        GDP_SystemFileCacheInformationEx = 42,
        GDP_SystemPageFileInformationEx = 43,
        GDP_SystemSystemPartitionInformation = 44,
        GDP_SystemJournalAndAccessInformation = 45,
        GDP_SystemSectionInformation = 46,
        GDP_SystemFirmwareTableInformation = 75,
        GDP_SystemModuleInformationEx = 77,
    } GDP_SYSTEM_INFORMATION_CLASS;

    typedef enum _GDP_SYSTEM_FIRMWARE_TABLE_ACTION {
        GDP_SystemFirmwareTable_Get = 0,
        GDP_SystemFirmwareTable_Set = 1,
        GDP_SystemFirmwareTable_Enumerate = 2,
        GDP_SystemFirmwareTable_Max = 3
    } GDP_SYSTEM_FIRMWARE_TABLE_ACTION;

    typedef struct _GDP_SYSTEM_FIRMWARE_TABLE_INFORMATION {
        ULONG ProviderSignature;
        ULONG Action;
        ULONG TableID;
        ULONG TableBufferLength;
        UCHAR TableBuffer[1];
    } GDP_SYSTEM_FIRMWARE_TABLE_INFORMATION, *PGDP_SYSTEM_FIRMWARE_TABLE_INFORMATION;

    NTSYSCALLAPI NTSTATUS NTAPI ZwQuerySystemInformation(
        _In_ ULONG SystemInformationClass,
        _Inout_ PVOID SystemInformation,
        _In_ ULONG SystemInformationLength,
        _Out_opt_ PULONG ReturnLength
    );

    typedef LONG (NTAPI *PVECTORED_EXCEPTION_HANDLER)(
        struct _EXCEPTION_POINTERS *ExceptionInfo
    );
}


#define SPOOF_INLINE        __forceinline
#define SPOOF_NOINLINE      __declspec( noinline )
#define SPOOF_ALIGN( n )    __declspec( align( n ) )
#define SPOOF_SECTION( s )  __declspec( code_seg( s ) )

#define SPOOF_DRIVER_TAG    'fops'


#define SPOOF_ASSERT( expr )                                                     \
    do                                                                           \
    {                                                                            \
        if ( !( expr ) )                                                         \
        {                                                                        \
            KeBugCheckEx( MANUALLY_INITIATED_CRASH, 0xDEAD, 0xBEEF, 0, 0 );    \
        }                                                                        \
    } while ( 0 )


SPOOF_INLINE void* spoof_alloc_np( SIZE_T size )
{
#if NTDDI_VERSION >= NTDDI_WIN10_CO
    return ExAllocatePool2( POOL_FLAG_NON_PAGED, size, SPOOF_DRIVER_TAG );
#else
    return ExAllocatePoolWithTag( NonPagedPoolNx, size, SPOOF_DRIVER_TAG );
#endif
}

SPOOF_INLINE void* spoof_alloc_paged( SIZE_T size )
{
#if NTDDI_VERSION >= NTDDI_WIN10_CO
    return ExAllocatePool2( POOL_FLAG_PAGED, size, SPOOF_DRIVER_TAG );
#else
    return ExAllocatePoolWithTag( PagedPool, size, SPOOF_DRIVER_TAG );
#endif
}

SPOOF_INLINE void spoof_free( void* ptr )
{
    if ( ptr )
    {
        ExFreePoolWithTag( ptr, SPOOF_DRIVER_TAG );
    }
}


using u8   = UINT8;
using u16  = UINT16;
using u32  = UINT32;
using u64  = UINT64;
using i8   = INT8;
using i16  = INT16;
using i32  = INT32;
using i64  = INT64;
using uptr = ULONG_PTR;
using iptr = LONG_PTR;


constexpr u32 k_max_serial_len   = 32;
constexpr u32 k_max_path_len     = 260;
constexpr u32 k_spoof_tag        = SPOOF_DRIVER_TAG;


namespace util
{
    SPOOF_INLINE u64 rdtsc_seed( )
    {
        return __rdtsc( );
    }


    SPOOF_INLINE u64 lcg_rand( u64& state )
    {
        state = state * 6364136223846793005ULL + 1442695040888963407ULL;

        return state;
    }


    SPOOF_INLINE void mutate_serial_digit(
        char*  serial,
        SIZE_T length,
        u64&   rng_state )
    {
        if ( !serial || length < 2 )
        {
            return;
        }


        u32  digit_positions[ 64 ] = { };
        u32  digit_count           = 0;

        for ( SIZE_T i = 0; i < length && digit_count < 64; ++i )
        {
            if ( serial[ i ] >= '0' && serial[ i ] <= '9' )
            {
                digit_positions[ digit_count++ ] = static_cast< u32 >( i );
            }
        }

        if ( digit_count < 2 )
        {
            return;
        }


        u32 pos_a = static_cast< u32 >( lcg_rand( rng_state ) % digit_count );
        u32 pos_b = static_cast< u32 >( lcg_rand( rng_state ) % digit_count );

        while ( pos_b == pos_a && digit_count > 1 )
        {
            pos_b = static_cast< u32 >( lcg_rand( rng_state ) % digit_count );
        }

        char new_digit_a = '0' + static_cast< char >( lcg_rand( rng_state ) % 10 );
        char new_digit_b = '0' + static_cast< char >( lcg_rand( rng_state ) % 10 );


        while ( new_digit_a == serial[ digit_positions[ pos_a ] ] )
        {
            new_digit_a = '0' + static_cast< char >( lcg_rand( rng_state ) % 10 );
        }

        while ( new_digit_b == serial[ digit_positions[ pos_b ] ] )
        {
            new_digit_b = '0' + static_cast< char >( lcg_rand( rng_state ) % 10 );
        }

        serial[ digit_positions[ pos_a ] ] = new_digit_a;
        serial[ digit_positions[ pos_b ] ] = new_digit_b;
    }

}
