
#include "hook_engine.hh"

namespace hook_engine
{

    hook_t  g_hook_table[ k_max_hooks ] = { };
    u32     g_hook_count                = 0;


    namespace trampoline
    {
        static void*    g_pool_base     = nullptr;
        static u32      g_pool_offset   = 0;
        static u32      g_pool_size     = k_max_hooks * k_trampoline_size;

        NTSTATUS init( )
        {
            g_pool_base = spoof_alloc_np( g_pool_size );

            if ( !g_pool_base )
            {
                logging::error( "trampoline pool allocation failed" );

                return STATUS_INSUFFICIENT_RESOURCES;
            }

            RtlZeroMemory( g_pool_base, g_pool_size );

            g_pool_offset = 0;

            logging::info( "trampoline pool at 0x%llX (%u bytes)", (u64)g_pool_base, g_pool_size );

            return STATUS_SUCCESS;
        }

        void destroy( )
        {
            if ( g_pool_base )
            {
                spoof_free( g_pool_base );

                g_pool_base   = nullptr;
                g_pool_offset = 0;
            }
        }

        void* allocate( )
        {
            if ( !g_pool_base )
            {
                return nullptr;
            }

            if ( g_pool_offset + k_trampoline_size > g_pool_size )
            {
                logging::error( "trampoline pool exhausted" );

                return nullptr;
            }

            void* slot = reinterpret_cast< u8* >( g_pool_base ) + g_pool_offset;

            g_pool_offset += k_trampoline_size;

            return slot;
        }

        void free( void* ptr )
        {

            if ( ptr )
            {
                RtlZeroMemory( ptr, k_trampoline_size );
            }
        }

    }


    static void write_absolute_jmp( void* dest, void* target )
    {
        u8* p = reinterpret_cast< u8* >( dest );

        p[ 0 ]  = 0xFF;
        p[ 1 ]  = 0x25;
        p[ 2 ]  = 0x00;
        p[ 3 ]  = 0x00;
        p[ 4 ]  = 0x00;
        p[ 5 ]  = 0x00;

        *reinterpret_cast< u64* >( p + 6 ) = reinterpret_cast< u64 >( target );
    }


    NTSTATUS install_hook(
        void*   target,
        void*   detour,
        void**  out_trampoline )
    {
        if ( !target || !detour )
        {
            return STATUS_INVALID_PARAMETER;
        }

        if ( g_hook_count >= k_max_hooks )
        {
            return STATUS_INSUFFICIENT_RESOURCES;
        }

        hook_t* entry = &g_hook_table[ g_hook_count ];

        RtlZeroMemory( entry, sizeof( hook_t ) );

        entry->target   = target;
        entry->detour   = detour;
        entry->hook_size = k_abs_jmp_size;


        RtlCopyMemory( entry->original_bytes, target, k_abs_jmp_size );


        entry->trampoline = trampoline::allocate( );

        if ( !entry->trampoline )
        {
            return STATUS_INSUFFICIENT_RESOURCES;
        }


        RtlCopyMemory( entry->trampoline, target, k_abs_jmp_size );


        void* return_addr = reinterpret_cast< u8* >( target ) + k_abs_jmp_size;

        write_absolute_jmp(
            reinterpret_cast< u8* >( entry->trampoline ) + k_abs_jmp_size,
            return_addr );


        ia32::disable_write_protect( );

        write_absolute_jmp( target, detour );

        ia32::enable_write_protect( );

        entry->installed = true;

        if ( out_trampoline )
        {
            *out_trampoline = entry->trampoline;
        }

        ++g_hook_count;

        logging::info( "hook installed: 0x%llX -> 0x%llX  trampoline=0x%llX",
            (u64)target, (u64)detour, (u64)entry->trampoline );

        return STATUS_SUCCESS;
    }


    NTSTATUS remove_hook( void* target )
    {
        for ( u32 i = 0; i < g_hook_count; ++i )
        {
            hook_t* entry = &g_hook_table[ i ];

            if ( entry->target != target || !entry->installed )
            {
                continue;
            }


            ia32::disable_write_protect( );

            RtlCopyMemory( target, entry->original_bytes, entry->hook_size );

            ia32::enable_write_protect( );

            trampoline::free( entry->trampoline );

            entry->installed = false;

            logging::info( "hook removed: 0x%llX", (u64)target );

            return STATUS_SUCCESS;
        }

        return STATUS_NOT_FOUND;
    }


    void remove_all_hooks( )
    {
        for ( u32 i = 0; i < g_hook_count; ++i )
        {
            hook_t* entry = &g_hook_table[ i ];

            if ( !entry->installed )
            {
                continue;
            }

            ia32::disable_write_protect( );

            RtlCopyMemory( entry->target, entry->original_bytes, entry->hook_size );

            ia32::enable_write_protect( );

            trampoline::free( entry->trampoline );

            entry->installed = false;
        }

        g_hook_count = 0;

        logging::info( "all hooks removed" );
    }

}
