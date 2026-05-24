
#include "network.hh"

namespace network
{

    adapter_entry_t g_adapter_table[ k_max_adapters ] = { };
    u32             g_adapter_count                   = 0;


    NTSTATUS enumerate_adapters( )
    {
        g_adapter_count = 0;

        UNICODE_STRING key_path = { };

        RtlInitUnicodeString( &key_path,
            L"\\Registry\\Machine\\SYSTEM\\CurrentControlSet\\Control\\Class\\"
            L"{4D36E972-E325-11CE-BFC1-08002BE10318}" );

        OBJECT_ATTRIBUTES obj = { };

        InitializeObjectAttributes(
            &obj,
            &key_path,
            OBJ_CASE_INSENSITIVE | OBJ_KERNEL_HANDLE,
            nullptr,
            nullptr );

        HANDLE hkey = nullptr;

        NTSTATUS status = ZwOpenKey( &hkey, KEY_READ, &obj );

        if ( !NT_SUCCESS( status ) )
        {
            logging::warn( "Could not open NIC class key: 0x%08X", status );

            return status;
        }


        for ( u32 i = 0; i < k_max_adapters; ++i )
        {
            KEY_BASIC_INFORMATION kbi   = { };
            u32                   idx   = i;
            u32                   needed = 0;

            status = ZwEnumerateKey(
                hkey,
                idx,
                KeyBasicInformation,
                &kbi,
                sizeof( kbi ),
                reinterpret_cast< PULONG >( &needed ) );

            if ( status == STATUS_NO_MORE_ENTRIES )
            {
                break;
            }

            if ( !NT_SUCCESS( status ) && status != STATUS_BUFFER_OVERFLOW )
            {
                continue;
            }


            wchar_t sub_name[ 8 ] = { };

            RtlStringCchPrintfW( sub_name, ARRAYSIZE( sub_name ), L"%04u", i );

            UNICODE_STRING sub_str = { };

            RtlInitUnicodeString( &sub_str, sub_name );

            HANDLE  hsub    = nullptr;
            OBJECT_ATTRIBUTES sub_attr = { };

            InitializeObjectAttributes(
                &sub_attr,
                &sub_str,
                OBJ_CASE_INSENSITIVE | OBJ_KERNEL_HANDLE,
                hkey,
                nullptr );

            status = ZwOpenKey( &hsub, KEY_READ, &sub_attr );

            if ( !NT_SUCCESS( status ) )
            {
                continue;
            }

            UNICODE_STRING val_name = { };

            RtlInitUnicodeString( &val_name, L"NetworkAddress" );

            u8   val_buf[ 256 ]   = { };
            u32  val_len           = sizeof( val_buf );

            KEY_VALUE_PARTIAL_INFORMATION* kvi =
                reinterpret_cast< KEY_VALUE_PARTIAL_INFORMATION* >( val_buf );

            status = ZwQueryValueKey(
                hsub,
                &val_name,
                KeyValuePartialInformation,
                kvi,
                val_len,
                reinterpret_cast< PULONG >( &val_len ) );

            if ( NT_SUCCESS( status ) && kvi->DataLength >= 12 )
            {

                const wchar_t* mac_str = reinterpret_cast< const wchar_t* >( kvi->Data );

                adapter_entry_t* entry = &g_adapter_table[ g_adapter_count ];

                RtlZeroMemory( entry, sizeof( adapter_entry_t ) );


                int byte_idx = 0;

                for ( int c = 0; c < 17 && byte_idx < 6; ++c )
                {
                    wchar_t ch = mac_str[ c ];

                    if ( ch == L'-' || ch == L':' )
                    {
                        continue;
                    }

                    u8 nibble = 0;

                    if ( ch >= L'0' && ch <= L'9' )      nibble = (u8)( ch - L'0' );
                    else if ( ch >= L'A' && ch <= L'F' )  nibble = (u8)( ch - L'A' + 10 );
                    else if ( ch >= L'a' && ch <= L'f' )  nibble = (u8)( ch - L'a' + 10 );

                    if ( c % 3 == 0 || ( c % 2 == 0 && mac_str[ 2 ] != L'-' ) )
                    {
                        entry->original_mac.bytes[ byte_idx ] = nibble << 4;
                    }
                    else
                    {
                        entry->original_mac.bytes[ byte_idx ] |= nibble;

                        ++byte_idx;
                    }
                }

                entry->active = true;

                logging::info( "NIC[%u] MAC: %02X:%02X:%02X:%02X:%02X:%02X",
                    g_adapter_count,
                    entry->original_mac.bytes[ 0 ],
                    entry->original_mac.bytes[ 1 ],
                    entry->original_mac.bytes[ 2 ],
                    entry->original_mac.bytes[ 3 ],
                    entry->original_mac.bytes[ 4 ],
                    entry->original_mac.bytes[ 5 ] );

                ++g_adapter_count;
            }

            ZwClose( hsub );
        }

        ZwClose( hkey );

        logging::info( "%u adapters enumerated", g_adapter_count );

        return STATUS_SUCCESS;
    }


    NTSTATUS spoof_adapter( u32 index )
    {
        if ( index >= g_adapter_count )
        {
            return STATUS_INVALID_PARAMETER;
        }

        adapter_entry_t* entry = &g_adapter_table[ index ];

        u64 rng = util::rdtsc_seed( );

        generate_mac( entry->spoofed_mac, rng );

        logging::info( "NIC[%u] MAC spoofed: %02X:%02X:%02X:%02X:%02X:%02X -> %02X:%02X:%02X:%02X:%02X:%02X",
            index,
            entry->original_mac.bytes[ 0 ],
            entry->original_mac.bytes[ 1 ],
            entry->original_mac.bytes[ 2 ],
            entry->original_mac.bytes[ 3 ],
            entry->original_mac.bytes[ 4 ],
            entry->original_mac.bytes[ 5 ],
            entry->spoofed_mac.bytes[ 0 ],
            entry->spoofed_mac.bytes[ 1 ],
            entry->spoofed_mac.bytes[ 2 ],
            entry->spoofed_mac.bytes[ 3 ],
            entry->spoofed_mac.bytes[ 4 ],
            entry->spoofed_mac.bytes[ 5 ] );

        return STATUS_SUCCESS;
    }


    NTSTATUS spoof_all( )
    {
        NTSTATUS status = enumerate_adapters( );

        if ( !NT_SUCCESS( status ) )
        {
            return status;
        }

        for ( u32 i = 0; i < g_adapter_count; ++i )
        {
            spoof_adapter( i );
        }

        return STATUS_SUCCESS;
    }


    void restore_all( )
    {
        for ( u32 i = 0; i < g_adapter_count; ++i )
        {
            g_adapter_table[ i ].active = false;
        }

        g_adapter_count = 0;
    }


    namespace arp
    {
        NTSTATUS flush_table( )
        {

            UNICODE_STRING  dev_name    = { };
            OBJECT_ATTRIBUTES obj_attr  = { };
            HANDLE          hdev        = nullptr;
            IO_STATUS_BLOCK iosb        = { };

            RtlInitUnicodeString( &dev_name, L"\\Device\\Nsi" );

            InitializeObjectAttributes(
                &obj_attr,
                &dev_name,
                OBJ_CASE_INSENSITIVE | OBJ_KERNEL_HANDLE,
                nullptr,
                nullptr );

            NTSTATUS status = ZwCreateFile(
                &hdev,
                GENERIC_READ | GENERIC_WRITE | SYNCHRONIZE,
                &obj_attr,
                &iosb,
                nullptr,
                0,
                FILE_SHARE_READ | FILE_SHARE_WRITE,
                FILE_OPEN,
                FILE_SYNCHRONOUS_IO_NONALERT,
                nullptr,
                0 );

            if ( NT_SUCCESS( status ) )
            {

                constexpr u32 k_ioctl_nsi_arp_flush = 0x12001B;

                ZwDeviceIoControlFile(
                    hdev,
                    nullptr,
                    nullptr,
                    nullptr,
                    &iosb,
                    k_ioctl_nsi_arp_flush,
                    nullptr,
                    0,
                    nullptr,
                    0 );

                ZwClose( hdev );

                logging::info( "ARP table flush requested" );
            }
            else
            {
                logging::warn( "NSI open failed: 0x%08X", status );
            }

            return status;
        }

        NTSTATUS inject_spoofed_entry( const mac_addr_t& spoofed )
        {
            UNREFERENCED_PARAMETER( spoofed );


            return STATUS_SUCCESS;
        }

    }


    namespace oid_hooks
    {
        void patch_oid_query_response(
            u32   oid,
            void* buf,
            u32   buf_len )
        {
            if ( !buf || buf_len < 6 )
            {
                return;
            }

            if ( oid == k_oid_802_3_permanent_address ||
                 oid == k_oid_802_3_current_address )
            {
                mac_addr_t* mac = reinterpret_cast< mac_addr_t* >( buf );

                for ( u32 i = 0; i < g_adapter_count; ++i )
                {
                    if ( mac_equal( *mac, g_adapter_table[ i ].original_mac ) )
                    {
                        RtlCopyMemory( mac->bytes, g_adapter_table[ i ].spoofed_mac.bytes, 6 );

                        break;
                    }
                }
            }
        }

    }


    namespace nsi_hooks
    {
        NTSTATUS install( )
        {
            logging::info( "NSI hooks installed (stub)" );

            return STATUS_SUCCESS;
        }

        void remove( )
        {
            logging::info( "NSI hooks removed" );
        }

        NTSTATUS on_ioctl_nsi_proxy(
            PDEVICE_OBJECT  dev_obj,
            PIRP            irp )
        {
            UNREFERENCED_PARAMETER( dev_obj );

            return irp->IoStatus.Status;
        }

    }

}
