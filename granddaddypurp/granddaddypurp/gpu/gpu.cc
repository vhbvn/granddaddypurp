
#include "gpu.hh"

namespace gpu
{

    gpu_entry_t g_gpu_table[ k_max_gpus ] = { };
    u32         g_gpu_count               = 0;


    namespace registry
    {
        NTSTATUS read_sz(
            HANDLE          hkey,
            const wchar_t*  value_name,
            wchar_t*        out_buf,
            u32             out_len )
        {
            UNICODE_STRING val_name = { };

            RtlInitUnicodeString( &val_name, value_name );

            u8  raw[ 1024 ] = { };
            u32 needed      = 0;

            NTSTATUS status = ZwQueryValueKey(
                hkey,
                &val_name,
                KeyValuePartialInformation,
                raw,
                sizeof( raw ),
                reinterpret_cast< PULONG >( &needed ) );

            if ( !NT_SUCCESS( status ) )
            {
                return status;
            }

            KEY_VALUE_PARTIAL_INFORMATION* kvi =
                reinterpret_cast< KEY_VALUE_PARTIAL_INFORMATION* >( raw );

            if ( kvi->Type != REG_SZ && kvi->Type != REG_EXPAND_SZ )
            {
                return STATUS_INVALID_PARAMETER;
            }

            u32 copy_bytes = min( kvi->DataLength, out_len * sizeof( wchar_t ) );

            RtlCopyMemory( out_buf, kvi->Data, copy_bytes );

            return STATUS_SUCCESS;
        }

        NTSTATUS write_sz(
            HANDLE          hkey,
            const wchar_t*  value_name,
            const wchar_t*  value )
        {
            UNICODE_STRING val_name = { };

            RtlInitUnicodeString( &val_name, value_name );

            u32 val_len = static_cast< u32 >( ( wcslen( value ) + 1 ) * sizeof( wchar_t ) );

            return ZwSetValueKey(
                hkey,
                &val_name,
                0,
                REG_SZ,
                const_cast< wchar_t* >( value ),
                val_len );
        }

        NTSTATUS open_display_key(
            u32     adapter_index,
            HANDLE* out_hkey )
        {
            if ( !out_hkey )
            {
                return STATUS_INVALID_PARAMETER;
            }

            wchar_t path[ k_max_path_len ] = { };

            RtlStringCchPrintfW( path, ARRAYSIZE( path ),
                L"\\Registry\\Machine\\SYSTEM\\CurrentControlSet\\Control\\"
                L"Video\\{ADAPTER%04u}\\0000",
                adapter_index );

            UNICODE_STRING    upath  = { };
            OBJECT_ATTRIBUTES attr   = { };

            RtlInitUnicodeString( &upath, path );

            InitializeObjectAttributes(
                &attr,
                &upath,
                OBJ_CASE_INSENSITIVE | OBJ_KERNEL_HANDLE,
                nullptr,
                nullptr );

            return ZwOpenKey( out_hkey, KEY_ALL_ACCESS, &attr );
        }

    }


    NTSTATUS enumerate( )
    {
        g_gpu_count = 0;

        const wchar_t* ven_keys[] =
        {
            L"\\Registry\\Machine\\SYSTEM\\CurrentControlSet\\Enum\\PCI",
        };

        for ( const wchar_t* root_path : ven_keys )
        {
            UNICODE_STRING    upath  = { };
            OBJECT_ATTRIBUTES attr   = { };

            RtlInitUnicodeString( &upath, root_path );

            InitializeObjectAttributes(
                &attr,
                &upath,
                OBJ_CASE_INSENSITIVE | OBJ_KERNEL_HANDLE,
                nullptr,
                nullptr );

            HANDLE hroot = nullptr;

            NTSTATUS status = ZwOpenKey( &hroot, KEY_READ, &attr );

            if ( !NT_SUCCESS( status ) )
            {
                continue;
            }


            for ( u32 i = 0; i < 512 && g_gpu_count < k_max_gpus; ++i )
            {
                constexpr SIZE_T k_kbi_size =
                    sizeof( KEY_BASIC_INFORMATION ) + 256 * sizeof( wchar_t );

                u8  kbi_buf[ k_kbi_size ] = { };
                u32 needed                = 0;

                KEY_BASIC_INFORMATION* kbi =
                    reinterpret_cast< KEY_BASIC_INFORMATION* >( kbi_buf );

                status = ZwEnumerateKey(
                    hroot,
                    i,
                    KeyBasicInformation,
                    kbi,
                    sizeof( kbi_buf ),
                    reinterpret_cast< PULONG >( &needed ) );

                if ( status == STATUS_NO_MORE_ENTRIES )
                {
                    break;
                }

                if ( !NT_SUCCESS( status ) )
                {
                    continue;
                }


                wchar_t key_name[ 128 ] = { };

                SIZE_T copy_chars = min( (SIZE_T)( kbi->NameLength / sizeof( wchar_t ) ), (SIZE_T)127 );

                RtlCopyMemory( key_name, kbi->Name, copy_chars * sizeof( wchar_t ) );

                vendor_t vendor = vendor_t::unknown;

                if ( wcsstr( key_name, L"VEN_10DE" ) )
                {
                    vendor = vendor_t::nvidia;
                }
                else if ( wcsstr( key_name, L"VEN_1002" ) )
                {
                    vendor = vendor_t::amd;
                }
                else
                {
                    continue;
                }


                UNICODE_STRING sub_str = { };

                RtlInitUnicodeString( &sub_str, key_name );

                OBJECT_ATTRIBUTES sub_attr = { };

                InitializeObjectAttributes(
                    &sub_attr,
                    &sub_str,
                    OBJ_CASE_INSENSITIVE | OBJ_KERNEL_HANDLE,
                    hroot,
                    nullptr );

                HANDLE hsub = nullptr;

                status = ZwOpenKey( &hsub, KEY_READ, &sub_attr );

                if ( !NT_SUCCESS( status ) )
                {
                    continue;
                }

                gpu_entry_t* entry = &g_gpu_table[ g_gpu_count ];

                RtlZeroMemory( entry, sizeof( gpu_entry_t ) );

                entry->vendor = vendor;


                u8  inst_kbi_buf[ k_kbi_size ] = { };
                u32 inst_needed                 = 0;

                KEY_BASIC_INFORMATION* inst_kbi =
                    reinterpret_cast< KEY_BASIC_INFORMATION* >( inst_kbi_buf );

                status = ZwEnumerateKey(
                    hsub,
                    0,
                    KeyBasicInformation,
                    inst_kbi,
                    sizeof( inst_kbi_buf ),
                    reinterpret_cast< PULONG >( &inst_needed ) );

                ZwClose( hsub );

                if ( !NT_SUCCESS( status ) )
                {
                    continue;
                }

                wchar_t inst_name[ 128 ] = { };

                SIZE_T inst_chars = min( (SIZE_T)( inst_kbi->NameLength / sizeof( wchar_t ) ), (SIZE_T)127 );

                RtlCopyMemory( inst_name, inst_kbi->Name, inst_chars * sizeof( wchar_t ) );


                RtlStringCchPrintfW( entry->registry_path, k_max_path_len,
                    L"\\Registry\\Machine\\SYSTEM\\CurrentControlSet\\Enum\\PCI\\%s\\%s",
                    key_name, inst_name );


                UNICODE_STRING   inst_upath = { };
                OBJECT_ATTRIBUTES inst_attr  = { };

                RtlInitUnicodeString( &inst_upath, entry->registry_path );

                InitializeObjectAttributes(
                    &inst_attr,
                    &inst_upath,
                    OBJ_CASE_INSENSITIVE | OBJ_KERNEL_HANDLE,
                    nullptr,
                    nullptr );

                HANDLE hinst = nullptr;

                status = ZwOpenKey( &hinst, KEY_READ, &inst_attr );

                if ( NT_SUCCESS( status ) )
                {
                    wchar_t wide_name[ 128 ] = { };

                    if ( NT_SUCCESS( registry::read_sz( hinst, L"FriendlyName", wide_name, ARRAYSIZE( wide_name ) ) ) ||
                         NT_SUCCESS( registry::read_sz( hinst, L"DeviceDesc", wide_name, ARRAYSIZE( wide_name ) ) ) )
                    {
                        for ( int c = 0; c < 127 && wide_name[ c ]; ++c )
                        {
                            entry->original_name[ c ] = static_cast< char >( wide_name[ c ] & 0xFF );
                        }
                    }

                    ZwClose( hinst );
                }

                entry->active = true;

                logging::info( "GPU[%u] vendor=%s name='%s'",
                    g_gpu_count,
                    vendor == vendor_t::nvidia ? "NVIDIA" : "AMD",
                    entry->original_name );

                ++g_gpu_count;
            }

            ZwClose( hroot );
        }

        logging::info( "%u GPUs enumerated", g_gpu_count );

        return STATUS_SUCCESS;
    }


    NTSTATUS spoof_all( )
    {
        NTSTATUS status = enumerate( );

        if ( !NT_SUCCESS( status ) )
        {
            return status;
        }

        u64 rng = util::rdtsc_seed( );

        for ( u32 i = 0; i < g_gpu_count; ++i )
        {
            gpu_entry_t* entry = &g_gpu_table[ i ];


            RtlStringCchPrintfA(
                entry->spoofed_serial,
                k_max_serial_len,
                "%04X%04X%04X",
                (u32)( util::lcg_rand( rng ) & 0xFFFF ),
                (u32)( util::lcg_rand( rng ) & 0xFFFF ),
                (u32)( util::lcg_rand( rng ) & 0xFFFF ) );


            RtlStringCchCopyA( entry->spoofed_name, sizeof( entry->spoofed_name ), entry->original_name );

            util::mutate_serial_digit( entry->spoofed_name, strlen( entry->spoofed_name ), rng );


            if ( entry->registry_path[ 0 ] )
            {
                UNICODE_STRING   upath = { };
                OBJECT_ATTRIBUTES attr  = { };

                RtlInitUnicodeString( &upath, entry->registry_path );

                InitializeObjectAttributes(
                    &attr,
                    &upath,
                    OBJ_CASE_INSENSITIVE | OBJ_KERNEL_HANDLE,
                    nullptr,
                    nullptr );

                HANDLE hkey = nullptr;

                if ( NT_SUCCESS( ZwOpenKey( &hkey, KEY_ALL_ACCESS, &attr ) ) )
                {
                    wchar_t wide_spoofed[ 128 ] = { };

                    for ( int c = 0; c < 127 && entry->spoofed_name[ c ]; ++c )
                    {
                        wide_spoofed[ c ] = static_cast< wchar_t >( (u8)entry->spoofed_name[ c ] );
                    }

                    registry::write_sz( hkey, L"FriendlyName", wide_spoofed );

                    ZwClose( hkey );
                }
            }

            logging::info( "GPU[%u] spoofed name='%s' serial='%s'",
                i, entry->spoofed_name, entry->spoofed_serial );
        }

        return STATUS_SUCCESS;
    }


    void restore_all( )
    {
        for ( u32 i = 0; i < g_gpu_count; ++i )
        {
            gpu_entry_t* entry = &g_gpu_table[ i ];

            if ( entry->registry_path[ 0 ] && entry->original_name[ 0 ] )
            {
                UNICODE_STRING   upath = { };
                OBJECT_ATTRIBUTES attr  = { };

                RtlInitUnicodeString( &upath, entry->registry_path );

                InitializeObjectAttributes(
                    &attr,
                    &upath,
                    OBJ_CASE_INSENSITIVE | OBJ_KERNEL_HANDLE,
                    nullptr,
                    nullptr );

                HANDLE hkey = nullptr;

                if ( NT_SUCCESS( ZwOpenKey( &hkey, KEY_ALL_ACCESS, &attr ) ) )
                {
                    wchar_t wide_orig[ 128 ] = { };

                    for ( int c = 0; c < 127 && entry->original_name[ c ]; ++c )
                    {
                        wide_orig[ c ] = static_cast< wchar_t >( (u8)entry->original_name[ c ] );
                    }

                    registry::write_sz( hkey, L"FriendlyName", wide_orig );

                    ZwClose( hkey );
                }
            }

            entry->active = false;
        }

        g_gpu_count = 0;
    }


    namespace nvidia
    {
        NTSTATUS enumerate( ) { return gpu::enumerate( ); }
        NTSTATUS spoof_serial( u32 index ) { UNREFERENCED_PARAMETER( index ); return gpu::spoof_all( ); }
        NTSTATUS patch_registry( u32 index ) { UNREFERENCED_PARAMETER( index ); return STATUS_SUCCESS; }
    }

    namespace amd
    {
        NTSTATUS enumerate( ) { return gpu::enumerate( ); }
        NTSTATUS spoof_serial( u32 index ) { UNREFERENCED_PARAMETER( index ); return gpu::spoof_all( ); }
        NTSTATUS patch_registry( u32 index ) { UNREFERENCED_PARAMETER( index ); return STATUS_SUCCESS; }
    }

}
