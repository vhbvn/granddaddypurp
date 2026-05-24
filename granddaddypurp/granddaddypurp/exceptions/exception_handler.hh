#pragma once


#include "../includes/globals.hh"
#include "../includes/logging.hh"

namespace exception_handler
{

    constexpr u32 k_exc_access_violation       = 0xC0000005;
    constexpr u32 k_exc_illegal_instruction    = 0xC000001D;
    constexpr u32 k_exc_int_divide_by_zero     = 0xC0000094;
    constexpr u32 k_exc_stack_overflow         = 0xC00000FD;
    constexpr u32 k_exc_breakpoint             = 0x80000003;
    constexpr u32 k_exc_single_step            = 0x80000004;
    constexpr u32 k_exc_guard_page             = 0x80000001;


    struct safe_call_result_t
    {
        bool    raised_exception;
        u32     exception_code;
        u64     exception_address;
        u64     return_value;
    };


    using safe_fn_t = u64 ( * )( void* );

    safe_call_result_t  safe_call( safe_fn_t fn, void* arg );

    bool                probe_address_read( u64 address, SIZE_T size );
    bool                probe_address_write( u64 address, SIZE_T size );


    NTSTATUS    install_veh( );
    void        remove_veh( );


    LONG NTAPI  veh_handler( PEXCEPTION_POINTERS exception_info );

}
