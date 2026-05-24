
#include "pattern_scan.hh"

namespace pattern_scan
{

    bool compile_pattern( const char* pattern_str, pattern_t& out )
    {
        if ( !pattern_str )
        {
            return false;
        }

        RtlZeroMemory( &out, sizeof( out ) );

        const char* p   = pattern_str;
        u32         idx = 0;

        while ( *p && idx < k_max_pattern_len )
        {

            while ( *p == ' ' || *p == '\t' )
            {
                ++p;
            }

            if ( !*p )
            {
                break;
            }


            if ( p[ 0 ] == '?' )
            {
                out.bytes[ idx ] = 0x00;
                out.mask[ idx ]  = false;

                if ( p[ 1 ] == '?' )
                {
                    p += 2;
                }
                else
                {
                    p += 1;
                }

                ++idx;

                continue;
            }


            auto hex_nibble = []( char c ) -> u8
            {
                if ( c >= '0' && c <= '9' ) return (u8)( c - '0' );
                if ( c >= 'A' && c <= 'F' ) return (u8)( c - 'A' + 10 );
                if ( c >= 'a' && c <= 'f' ) return (u8)( c - 'a' + 10 );

                return 0;
            };

            if ( !p[ 0 ] || !p[ 1 ] )
            {
                break;
            }

            out.bytes[ idx ] = ( hex_nibble( p[ 0 ] ) << 4 ) | hex_nibble( p[ 1 ] );
            out.mask[ idx ]  = true;

            p   += 2;
            idx += 1;
        }

        out.length = idx;

        return ( idx > 0 );
    }


    u64 scan(
        u64             base,
        u32             size,
        const pattern_t& pat )
    {
        if ( !base || !size || !pat.length )
        {
            return 0;
        }

        const u8* region    = reinterpret_cast< const u8* >( base );
        u32       scan_size = size - pat.length;

        for ( u32 i = 0; i <= scan_size; ++i )
        {
            bool found = true;

            for ( u32 j = 0; j < pat.length && found; ++j )
            {
                if ( pat.mask[ j ] && region[ i + j ] != pat.bytes[ j ] )
                {
                    found = false;
                }
            }

            if ( found )
            {
                return base + i;
            }
        }

        return 0;
    }


    u64 scan_str(
        u64         base,
        u32         size,
        const char* pattern_str )
    {
        pattern_t pat = { };

        if ( !compile_pattern( pattern_str, pat ) )
        {
            logging::error( "Failed to compile pattern: %s", pattern_str );

            return 0;
        }

        return scan( base, size, pat );
    }


    u64 get_module_base( const wchar_t* module_name )
    {
        constexpr u32 k_initial_size = 0x20000;

        u32  needed     = k_initial_size;
        u8*  buf        = reinterpret_cast< u8* >( spoof_alloc_paged( needed ) );

        if ( !buf )
        {
            return 0;
        }

        NTSTATUS status = ZwQuerySystemInformation(
            0x4B,
            buf,
            needed,
            reinterpret_cast< PULONG >( &needed ) );

        if ( status == STATUS_INFO_LENGTH_MISMATCH )
        {
            spoof_free( buf );

            buf = reinterpret_cast< u8* >( spoof_alloc_paged( needed ) );

            if ( !buf )
            {
                return 0;
            }

            status = ZwQuerySystemInformation(
                0x4B,
                buf,
                needed,
                reinterpret_cast< PULONG >( &needed ) );
        }

        if ( !NT_SUCCESS( status ) )
        {
            spoof_free( buf );

            return 0;
        }


        u32 count = *reinterpret_cast< u32* >( buf );

        struct sys_module_t
        {
            ULONG_PTR   reserved[ 2 ];
            void*       image_base;
            ULONG       image_size;
            ULONG       flags;
            u16         load_order;
            u16         init_order;
            u16         load_count;
            u16         offset_to_file_name;
            char        full_path_name[ 256 ];
        };

        sys_module_t* modules = reinterpret_cast< sys_module_t* >( buf + sizeof( u32 ) );

        u64 result = 0;

        for ( u32 i = 0; i < count; ++i )
        {
            const sys_module_t& mod = modules[ i ];


            const char* file_name = mod.full_path_name + mod.offset_to_file_name;

            wchar_t wide_name[ 64 ] = { };

            for ( u32 c = 0; c < 63 && file_name[ c ]; ++c )
            {
                wide_name[ c ] = static_cast< wchar_t >( (u8)file_name[ c ] );
            }

            if ( _wcsicmp( wide_name, module_name ) == 0 )
            {
                result = reinterpret_cast< u64 >( mod.image_base );

                break;
            }
        }

        spoof_free( buf );

        return result;
    }


    u32 get_module_size( u64 module_base )
    {
        if ( !module_base )
        {
            return 0;
        }


        constexpr u32 k_dos_e_lfanew_offset = 0x3C;
        constexpr u32 k_size_of_image_offset = 0x50;

        __try
        {
            u32 pe_offset = *reinterpret_cast< u32* >( module_base + k_dos_e_lfanew_offset );

            return *reinterpret_cast< u32* >( module_base + pe_offset + k_size_of_image_offset );
        }
        __except ( EXCEPTION_EXECUTE_HANDLER )
        {
            return 0;
        }
    }


    u64 scan_module(
        const wchar_t*  module_name,
        const char*     pattern_str )
    {
        u64 base = get_module_base( module_name );

        if ( !base )
        {
            logging::error( "Module not found: %S", module_name );

            return 0;
        }

        u32 size = get_module_size( base );

        if ( !size )
        {
            return 0;
        }

        logging::verbose( "Scanning %S at 0x%llX size 0x%X for: %s",
            module_name, base, size, pattern_str );

        u64 result = scan_str( base, size, pattern_str );

        if ( result )
        {
            logging::info( "Pattern found at 0x%llX", result );
        }
        else
        {
            logging::warn( "Pattern not found in %S", module_name );
        }

        return result;
    }

}
