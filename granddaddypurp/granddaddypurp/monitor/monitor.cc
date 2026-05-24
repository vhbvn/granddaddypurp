
#include "monitor.hh"

namespace monitor
{

    monitor_entry_t g_monitor_table[ k_max_monitors ] = { };
    u32             g_monitor_count                   = 0;


    namespace edid
    {
        u8 compute_checksum( const u8* edid )
        {
            u8 sum = 0;

            for ( u32 i = 0; i < k_edid_size - 1; ++i )
            {
                sum += edid[ i ];
            }

            return static_cast< u8 >( 256 - sum );
        }

        bool find_serial_descriptor(
            const u8*   edid,
            u32*        out_desc_offset )
        {

            for ( u32 block = 0; block < 4; ++block )
            {
                u32 offset = k_edid_desc_offset + block * 18;

                if ( offset + 18 > k_edid_size )
                {
                    break;
                }

                const edid_descriptor_t* desc =
                    reinterpret_cast< const edid_descriptor_t* >( edid + offset );


                if ( desc->pixel_clock != 0 )
                {
                    continue;
                }

                if ( desc->descriptor_type == k_edid_desc_serial )
                {
                    if ( out_desc_offset )
                    {
                        *out_desc_offset = offset;
                    }

                    return true;
                }
            }

            return false;
        }

        void patch_serial_descriptor(
            u8*         edid,
            const char* new_serial )
        {
            u32 desc_offset = 0;

            if ( !find_serial_descriptor( edid, &desc_offset ) )
            {
                logging::warn( "No EDID serial descriptor block found" );

                return;
            }

            edid_descriptor_t* desc =
                reinterpret_cast< edid_descriptor_t* >( edid + desc_offset );


            SIZE_T slen = strlen( new_serial );

            RtlZeroMemory( desc->data, sizeof( desc->data ) );
            RtlFillMemory( desc->data, sizeof( desc->data ), 0x20 );

            SIZE_T copy_len = min( slen, (SIZE_T)( sizeof( desc->data ) - 1 ) );

            RtlCopyMemory( desc->data, new_serial, copy_len );

            desc->data[ copy_len ] = 0x0A;


            edid[ k_edid_size - 1 ] = compute_checksum( edid );
        }

        void patch_hw_serial(
            u8*     edid,
            u64&    rng )
        {

            u32 new_serial = static_cast< u32 >( util::lcg_rand( rng ) );

            RtlCopyMemory( edid + k_edid_serial_offset, &new_serial, 4 );
        }

    }


    NTSTATUS enumerate( )
    {
        g_monitor_count = 0;

        UNICODE_STRING   root_path = { };
        OBJECT_ATTRIBUTES root_attr = { };

        RtlInitUnicodeString( &root_path,
            L"\\Registry\\Machine\\SYSTEM\\CurrentControlSet\\Enum\\DISPLAY" );

        InitializeObjectAttributes(
            &root_attr,
            &root_path,
            OBJ_CASE_INSENSITIVE | OBJ_KERNEL_HANDLE,
            nullptr,
            nullptr );

        HANDLE hroot = nullptr;

        NTSTATUS status = ZwOpenKey( &hroot, KEY_READ, &root_attr );

        if ( !NT_SUCCESS( status ) )
        {
            logging::warn( "Could not open DISPLAY enum key: 0x%08X", status );

            return status;
        }


        for ( u32 model_idx = 0; model_idx < 64 && g_monitor_count < k_max_monitors; ++model_idx )
        {
            constexpr SIZE_T k_kbi_buf = sizeof( KEY_BASIC_INFORMATION ) + 256 * sizeof( wchar_t );

            u8  model_kbi_buf[ k_kbi_buf ] = { };
            u32 model_needed               = 0;

            KEY_BASIC_INFORMATION* model_kbi =
                reinterpret_cast< KEY_BASIC_INFORMATION* >( model_kbi_buf );

            status = ZwEnumerateKey(
                hroot,
                model_idx,
                KeyBasicInformation,
                model_kbi,
                sizeof( model_kbi_buf ),
                reinterpret_cast< PULONG >( &model_needed ) );

            if ( status == STATUS_NO_MORE_ENTRIES )
            {
                break;
            }

            if ( !NT_SUCCESS( status ) )
            {
                continue;
            }

            wchar_t model_name[ 128 ] = { };

            SIZE_T mc = min( (SIZE_T)( model_kbi->NameLength / sizeof( wchar_t ) ), (SIZE_T)127 );

            RtlCopyMemory( model_name, model_kbi->Name, mc * sizeof( wchar_t ) );


            UNICODE_STRING   model_str = { };
            OBJECT_ATTRIBUTES model_attr = { };

            RtlInitUnicodeString( &model_str, model_name );

            InitializeObjectAttributes(
                &model_attr,
                &model_str,
                OBJ_CASE_INSENSITIVE | OBJ_KERNEL_HANDLE,
                hroot,
                nullptr );

            HANDLE hmodel = nullptr;

            status = ZwOpenKey( &hmodel, KEY_READ, &model_attr );

            if ( !NT_SUCCESS( status ) )
            {
                continue;
            }

            for ( u32 inst_idx = 0; inst_idx < 4 && g_monitor_count < k_max_monitors; ++inst_idx )
            {
                u8  inst_kbi_buf[ k_kbi_buf ] = { };
                u32 inst_needed               = 0;

                KEY_BASIC_INFORMATION* inst_kbi =
                    reinterpret_cast< KEY_BASIC_INFORMATION* >( inst_kbi_buf );

                status = ZwEnumerateKey(
                    hmodel,
                    inst_idx,
                    KeyBasicInformation,
                    inst_kbi,
                    sizeof( inst_kbi_buf ),
                    reinterpret_cast< PULONG >( &inst_needed ) );

                if ( status == STATUS_NO_MORE_ENTRIES )
                {
                    break;
                }

                if ( !NT_SUCCESS( status ) )
                {
                    continue;
                }

                wchar_t inst_name[ 128 ] = { };

                SIZE_T ic = min( (SIZE_T)( inst_kbi->NameLength / sizeof( wchar_t ) ), (SIZE_T)127 );

                RtlCopyMemory( inst_name, inst_kbi->Name, ic * sizeof( wchar_t ) );


                monitor_entry_t* entry = &g_monitor_table[ g_monitor_count ];

                RtlZeroMemory( entry, sizeof( monitor_entry_t ) );

                RtlStringCchPrintfW( entry->registry_path, k_max_path_len,
                    L"\\Registry\\Machine\\SYSTEM\\CurrentControlSet\\Enum\\DISPLAY\\%s\\%s\\Device Parameters",
                    model_name, inst_name );


                UNICODE_STRING   dp_path = { };
                OBJECT_ATTRIBUTES dp_attr = { };

                RtlInitUnicodeString( &dp_path, entry->registry_path );

                InitializeObjectAttributes(
                    &dp_attr,
                    &dp_path,
                    OBJ_CASE_INSENSITIVE | OBJ_KERNEL_HANDLE,
                    nullptr,
                    nullptr );

                HANDLE hdp = nullptr;

                status = ZwOpenKey( &hdp, KEY_READ, &dp_attr );

                if ( !NT_SUCCESS( status ) )
                {
                    continue;
                }

                UNICODE_STRING  edid_val = { };

                RtlInitUnicodeString( &edid_val, L"EDID" );

                u8  raw[ sizeof( KEY_VALUE_PARTIAL_INFORMATION ) + k_edid_size ] = { };
                u32 raw_needed = 0;

                KEY_VALUE_PARTIAL_INFORMATION* kvi =
                    reinterpret_cast< KEY_VALUE_PARTIAL_INFORMATION* >( raw );

                status = ZwQueryValueKey(
                    hdp,
                    &edid_val,
                    KeyValuePartialInformation,
                    kvi,
                    sizeof( raw ),
                    reinterpret_cast< PULONG >( &raw_needed ) );

                if ( NT_SUCCESS( status ) && kvi->DataLength >= k_edid_size )
                {
                    RtlCopyMemory( entry->original_edid, kvi->Data, k_edid_size );


                    u32 desc_off = 0;

                    if ( edid::find_serial_descriptor( entry->original_edid, &desc_off ) )
                    {
                        const edid_descriptor_t* desc =
                            reinterpret_cast< const edid_descriptor_t* >(
                                entry->original_edid + desc_off );

                        RtlCopyMemory( entry->original_serial_str, desc->data,
                            sizeof( entry->original_serial_str ) - 1 );
                    }

                    entry->active = true;

                    logging::info( "Monitor[%u] path='%S' serial='%.13s'",
                        g_monitor_count,
                        entry->registry_path,
                        entry->original_serial_str );

                    ++g_monitor_count;
                }

                ZwClose( hdp );
            }

            ZwClose( hmodel );
        }

        ZwClose( hroot );

        logging::info( "%u monitors enumerated", g_monitor_count );

        return STATUS_SUCCESS;
    }


    NTSTATUS spoof_monitor( u32 index )
    {
        if ( index >= g_monitor_count )
        {
            return STATUS_INVALID_PARAMETER;
        }

        monitor_entry_t* entry = &g_monitor_table[ index ];

        if ( !entry->active )
        {
            return STATUS_NOT_FOUND;
        }

        u64 rng = util::rdtsc_seed( );


        RtlCopyMemory( entry->spoofed_edid, entry->original_edid, k_edid_size );

        edid::patch_hw_serial( entry->spoofed_edid, rng );


        RtlStringCchCopyA( entry->spoofed_serial_str,
            sizeof( entry->spoofed_serial_str ),
            entry->original_serial_str );

        util::mutate_serial_digit( entry->spoofed_serial_str,
            strlen( entry->spoofed_serial_str ), rng );

        edid::patch_serial_descriptor( entry->spoofed_edid, entry->spoofed_serial_str );


        UNICODE_STRING   dp_path = { };
        OBJECT_ATTRIBUTES dp_attr = { };

        RtlInitUnicodeString( &dp_path, entry->registry_path );

        InitializeObjectAttributes(
            &dp_attr,
            &dp_path,
            OBJ_CASE_INSENSITIVE | OBJ_KERNEL_HANDLE,
            nullptr,
            nullptr );

        HANDLE hdp = nullptr;

        NTSTATUS status = ZwOpenKey( &hdp, KEY_ALL_ACCESS, &dp_attr );

        if ( NT_SUCCESS( status ) )
        {
            UNICODE_STRING edid_val = { };

            RtlInitUnicodeString( &edid_val, L"EDID" );

            ZwSetValueKey(
                hdp,
                &edid_val,
                0,
                REG_BINARY,
                entry->spoofed_edid,
                k_edid_size );

            ZwClose( hdp );

            logging::info( "Monitor[%u] EDID serial patched: '%.13s' -> '%.13s'",
                index,
                entry->original_serial_str,
                entry->spoofed_serial_str );
        }

        return status;
    }


    NTSTATUS spoof_all( )
    {
        NTSTATUS status = enumerate( );

        if ( !NT_SUCCESS( status ) )
        {
            return status;
        }

        for ( u32 i = 0; i < g_monitor_count; ++i )
        {
            spoof_monitor( i );
        }

        return STATUS_SUCCESS;
    }


    void restore_all( )
    {
        for ( u32 i = 0; i < g_monitor_count; ++i )
        {
            monitor_entry_t* entry = &g_monitor_table[ i ];

            if ( !entry->active )
            {
                continue;
            }

            UNICODE_STRING   dp_path = { };
            OBJECT_ATTRIBUTES dp_attr = { };

            RtlInitUnicodeString( &dp_path, entry->registry_path );

            InitializeObjectAttributes(
                &dp_attr,
                &dp_path,
                OBJ_CASE_INSENSITIVE | OBJ_KERNEL_HANDLE,
                nullptr,
                nullptr );

            HANDLE hdp = nullptr;

            if ( NT_SUCCESS( ZwOpenKey( &hdp, KEY_ALL_ACCESS, &dp_attr ) ) )
            {
                UNICODE_STRING edid_val = { };

                RtlInitUnicodeString( &edid_val, L"EDID" );

                ZwSetValueKey(
                    hdp,
                    &edid_val,
                    0,
                    REG_BINARY,
                    entry->original_edid,
                    k_edid_size );

                ZwClose( hdp );
            }

            entry->active = false;
        }

        g_monitor_count = 0;
    }

}
