
#include "exception_handler.hh"

namespace exception_handler
{

    static void* g_veh_handle = nullptr;


    LONG NTAPI veh_handler( PEXCEPTION_POINTERS exception_info )
    {
        if ( !exception_info || !exception_info->ExceptionRecord )
        {
            return EXCEPTION_CONTINUE_SEARCH;
        }

        u32 code    = exception_info->ExceptionRecord->ExceptionCode;
        u64 addr    = reinterpret_cast< u64 >(
            exception_info->ExceptionRecord->ExceptionAddress );

        switch ( code )
        {
        case k_exc_access_violation:
        {
            logging::warn( "VEH: access violation at 0x%llX", addr );

            break;
        }

        case k_exc_illegal_instruction:
        {
            logging::warn( "VEH: illegal instruction at 0x%llX", addr );

            break;
        }

        case k_exc_single_step:
        {

            exception_info->ContextRecord->EFlags &= ~0x100UL;

            return EXCEPTION_CONTINUE_EXECUTION;
        }

        default:
        {
            break;
        }

        }


        return EXCEPTION_CONTINUE_SEARCH;
    }


    NTSTATUS install_veh( )
    {

        using fn_add_t = PVOID ( NTAPI* )( ULONG, PVECTORED_EXCEPTION_HANDLER );

        UNICODE_STRING fn_name = { };

        RtlInitUnicodeString( &fn_name, L"RtlAddVectoredExceptionHandler" );

        fn_add_t fn_add = reinterpret_cast< fn_add_t >(
            MmGetSystemRoutineAddress( &fn_name ) );

        if ( !fn_add )
        {
            logging::error( "RtlAddVectoredExceptionHandler not found" );

            return STATUS_NOT_FOUND;
        }

        g_veh_handle = fn_add( 1, veh_handler );

        if ( !g_veh_handle )
        {
            logging::error( "VEH install failed" );

            return STATUS_UNSUCCESSFUL;
        }

        logging::info( "VEH installed at 0x%llX", (u64)g_veh_handle );

        return STATUS_SUCCESS;
    }


    void remove_veh( )
    {
        if ( g_veh_handle )
        {
            using fn_remove_t = ULONG ( NTAPI* )( PVOID );

            UNICODE_STRING fn_name = { };

            RtlInitUnicodeString( &fn_name, L"RtlRemoveVectoredExceptionHandler" );

            fn_remove_t fn_remove = reinterpret_cast< fn_remove_t >(
                MmGetSystemRoutineAddress( &fn_name ) );

            if ( fn_remove )
            {
                fn_remove( g_veh_handle );
            }

            g_veh_handle = nullptr;

            logging::info( "VEH removed" );
        }
    }


    safe_call_result_t safe_call( safe_fn_t fn, void* arg )
    {
        safe_call_result_t result = { };

        __try
        {
            result.return_value = fn( arg );
        }
        __except ( EXCEPTION_EXECUTE_HANDLER )
        {
            result.raised_exception    = true;
            result.exception_code      = GetExceptionCode( );
            result.exception_address   = 0;

            logging::warn( "safe_call caught exception: 0x%08X", result.exception_code );
        }

        return result;
    }


    bool probe_address_read( u64 address, SIZE_T size )
    {
        __try
        {
            ProbeForRead(
                reinterpret_cast< void* >( address ),
                size,
                sizeof( u8 ) );

            return true;
        }
        __except ( EXCEPTION_EXECUTE_HANDLER )
        {
            return false;
        }
    }


    bool probe_address_write( u64 address, SIZE_T size )
    {
        __try
        {
            ProbeForWrite(
                reinterpret_cast< void* >( address ),
                size,
                sizeof( u8 ) );

            return true;
        }
        __except ( EXCEPTION_EXECUTE_HANDLER )
        {
            return false;
        }
    }

}
