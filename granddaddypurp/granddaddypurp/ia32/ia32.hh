#pragma once


#include <ntddk.h>
#include <intrin.h>

namespace ia32
{

    union cr0_t
    {
        struct
        {
            UINT64 protection_enable      : 1;
            UINT64 monitor_coprocessor    : 1;
            UINT64 emulate_fpu            : 1;
            UINT64 task_switched          : 1;
            UINT64 extension_type         : 1;
            UINT64 numeric_error          : 1;
            UINT64 reserved_0             : 10;
            UINT64 write_protect          : 1;
            UINT64 reserved_1             : 1;
            UINT64 alignment_mask         : 1;
            UINT64 reserved_2             : 10;
            UINT64 not_write_through      : 1;
            UINT64 cache_disable          : 1;
            UINT64 paging_enable          : 1;
            UINT64 reserved_3             : 32;
        };

        UINT64 flags;
    };


    union cr4_t
    {
        struct
        {
            UINT64 vme                    : 1;
            UINT64 pvi                    : 1;
            UINT64 tsd                    : 1;
            UINT64 de                     : 1;
            UINT64 pse                    : 1;
            UINT64 pae                    : 1;
            UINT64 mce                    : 1;
            UINT64 pge                    : 1;
            UINT64 pce                    : 1;
            UINT64 osfxsr                 : 1;
            UINT64 osxmmexcept            : 1;
            UINT64 umip                   : 1;
            UINT64 la57                   : 1;
            UINT64 vmxe                   : 1;
            UINT64 smxe                   : 1;
            UINT64 reserved_0             : 1;
            UINT64 fsgsbase               : 1;
            UINT64 pcide                  : 1;
            UINT64 osxsave                : 1;
            UINT64 reserved_1             : 1;
            UINT64 smep                   : 1;
            UINT64 smap                   : 1;
            UINT64 pke                    : 1;
            UINT64 cet                    : 1;
            UINT64 pks                    : 1;
            UINT64 reserved_2             : 39;
        };

        UINT64 flags;
    };


    union rflags_t
    {
        struct
        {
            UINT64 carry_flag             : 1;
            UINT64 read_as_one            : 1;
            UINT64 parity_flag            : 1;
            UINT64 reserved_0             : 1;
            UINT64 aux_carry_flag         : 1;
            UINT64 reserved_1             : 1;
            UINT64 zero_flag              : 1;
            UINT64 sign_flag              : 1;
            UINT64 trap_flag              : 1;
            UINT64 interrupt_enable       : 1;
            UINT64 direction_flag         : 1;
            UINT64 overflow_flag          : 1;
            UINT64 io_privilege_level     : 2;
            UINT64 nested_task            : 1;
            UINT64 reserved_2             : 1;
            UINT64 resume_flag            : 1;
            UINT64 virtual_8086_mode      : 1;
            UINT64 alignment_check        : 1;
            UINT64 virtual_interrupt      : 1;
            UINT64 virtual_interrupt_pend : 1;
            UINT64 cpuid_allowed          : 1;
            UINT64 reserved_3             : 42;
        };

        UINT64 flags;
    };


    enum class msr : UINT32
    {
        ia32_apic_base          = 0x0000001B,
        ia32_feature_control    = 0x0000003A,
        ia32_sysenter_cs        = 0x00000174,
        ia32_sysenter_esp       = 0x00000175,
        ia32_sysenter_eip       = 0x00000176,
        ia32_debugctl           = 0x000001D9,
        ia32_pat                = 0x00000277,
        ia32_perf_global_ctrl   = 0x0000038F,
        ia32_vmx_basic          = 0x00000480,
        ia32_lstar              = 0xC0000082,
        ia32_cstar              = 0xC0000083,
        ia32_fmask              = 0xC0000084,
        ia32_kernel_gs_base     = 0xC0000102,
    };


    struct cpuid_result_t
    {
        int eax;
        int ebx;
        int ecx;
        int edx;
    };

    inline cpuid_result_t cpuid( int leaf, int subleaf = 0 )
    {
        cpuid_result_t result = { };

        __cpuidex( reinterpret_cast< int* >( &result ), leaf, subleaf );

        return result;
    }


    inline void disable_write_protect( )
    {
        cr0_t cr0 = { };

        cr0.flags           = __readcr0( );
        cr0.write_protect   = 0;

        __writecr0( cr0.flags );
    }

    inline void enable_write_protect( )
    {
        cr0_t cr0 = { };

        cr0.flags           = __readcr0( );
        cr0.write_protect   = 1;

        __writecr0( cr0.flags );
    }


    inline UINT64 read_msr( msr id )
    {
        return __readmsr( static_cast< ULONG >( id ) );
    }

    inline void write_msr( msr id, UINT64 value )
    {
        __writemsr( static_cast< ULONG >( id ), value );
    }

}
