
#include "usb.hh"

namespace usb
{

    usb_entry_t g_usb_table[ k_max_usb_devices ] = { };
    u32         g_usb_count                       = 0;


    static void wide_to_ascii( const wchar_t* src, char* dst, SIZE_T dst_len )
    {
        SIZE_T i = 0;

        while ( i + 1 < dst_len && src[ i ] )
        {
            dst[ i ] = static_cast< char >( src[ i ] & 0xFF );

            ++i;
        }

        dst[ i ] = '\0';
    }


    static void ascii_to_wide( const char* src, wchar_t* dst, SIZE_T dst_len )
    {
        SIZE_T i = 0;

        while ( i + 1 < dst_len && src[ i ] )
        {
            dst[ i ] = static_cast< wchar_t >( static_cast< u8 >( src[ i ] ) );

            ++i;
        }

        dst[ i ] = L'\0';
    }


    static NTSTATUS query_hub_serial(
        const wchar_t*  hub_path,
        u32             port_index,
        char*           out_serial,
        SIZE_T          out_len )
    {
        UNICODE_STRING  upath       = { };
        OBJECT_ATTRIBUTES obj_attr  = { };
        HANDLE          hdev        = nullptr;
        IO_STATUS_BLOCK iosb        = { };

        RtlInitUnicodeString( &upath, hub_path );

        InitializeObjectAttributes(
            &obj_attr,
            &upath,
            OBJ_CASE_INSENSITIVE | OBJ_KERNEL_HANDLE,
            nullptr,
            nullptr );

        NTSTATUS status = ZwCreateFile(
            &hdev,
            GENERIC_READ | SYNCHRONIZE,
            &obj_attr,
            &iosb,
            nullptr,
            0,
            FILE_SHARE_READ | FILE_SHARE_WRITE,
            FILE_OPEN,
            FILE_SYNCHRONOUS_IO_NONALERT,
            nullptr,
            0 );

        if ( !NT_SUCCESS( status ) )
        {
            return status;
        }


        constexpr SIZE_T req_size =
            sizeof( usb_descriptor_request_t ) + sizeof( usb_string_descriptor_t );

        u8* req_buf = reinterpret_cast< u8* >( spoof_alloc_paged( req_size ) );

        if ( !req_buf )
        {
            ZwClose( hdev );
            return STATUS_INSUFFICIENT_RESOURCES;
        }

        RtlZeroMemory( req_buf, req_size );

        usb_descriptor_request_t* req =
            reinterpret_cast< usb_descriptor_request_t* >( req_buf );

        req->connection_index       = port_index;
        req->setup_packet.bm_request = 0x80;
        req->setup_packet.b_request  = 0x06;
        req->setup_packet.w_value    = 0x0300 | 3;
        req->setup_packet.w_index    = 0x0409;
        req->setup_packet.w_length   = sizeof( usb_string_descriptor_t );

        status = ZwDeviceIoControlFile(
            hdev,
            nullptr,
            nullptr,
            nullptr,
            &iosb,
            k_ioctl_usb_get_descriptor_from_node_connection,
            req_buf,
            static_cast< u32 >( req_size ),
            req_buf,
            static_cast< u32 >( req_size ) );

        if ( NT_SUCCESS( status ) )
        {
            usb_string_descriptor_t* str_desc =
                reinterpret_cast< usb_string_descriptor_t* >( req->data );

            if ( str_desc->descriptor_type == 0x03 && str_desc->length > 2 )
            {
                SIZE_T wchar_count = ( str_desc->length - 2 ) / sizeof( wchar_t );

                wchar_t tmp[ k_max_serial_len ] = { };

                SIZE_T copy_count = min( wchar_count, (SIZE_T)( k_max_serial_len - 1 ) );

                RtlCopyMemory( tmp, str_desc->string, copy_count * sizeof( wchar_t ) );

                wide_to_ascii( tmp, out_serial, out_len );
            }
        }

        spoof_free( req_buf );

        ZwClose( hdev );

        return status;
    }


    NTSTATUS enumerate( )
    {
        g_usb_count = 0;

        for ( u32 hub_idx = 0; hub_idx < 16; ++hub_idx )
        {
            wchar_t hub_path[ k_max_path_len ] = { };

            RtlStringCchPrintfW( hub_path, ARRAYSIZE( hub_path ),
                L"\\Device\\USBPDO-%u", hub_idx );

            for ( u32 port = 1; port <= 16 && g_usb_count < k_max_usb_devices; ++port )
            {
                char serial[ k_max_serial_len ] = { };

                NTSTATUS status = query_hub_serial( hub_path, port, serial, sizeof( serial ) );

                if ( !NT_SUCCESS( status ) || serial[ 0 ] == '\0' )
                {
                    continue;
                }

                usb_entry_t* entry = &g_usb_table[ g_usb_count ];

                RtlZeroMemory( entry, sizeof( usb_entry_t ) );

                RtlCopyMemory( entry->hub_path, hub_path, sizeof( hub_path ) );

                entry->port_index = port;

                RtlStringCchCopyA( entry->original_serial, k_max_serial_len, serial );

                entry->active = true;

                logging::info( "USB hub%u port%u serial: '%s'", hub_idx, port, serial );

                ++g_usb_count;
            }
        }

        logging::info( "%u USB serial entries found", g_usb_count );

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

        for ( u32 i = 0; i < g_usb_count; ++i )
        {
            usb_entry_t* entry = &g_usb_table[ i ];

            RtlStringCchCopyA( entry->spoofed_serial, k_max_serial_len, entry->original_serial );

            util::mutate_serial_digit( entry->spoofed_serial, strlen( entry->spoofed_serial ), rng );

            logging::info( "USB[%u] spoofed: '%s' -> '%s'",
                i, entry->original_serial, entry->spoofed_serial );
        }

        return STATUS_SUCCESS;
    }


    void restore_all( )
    {
        for ( u32 i = 0; i < g_usb_count; ++i )
        {
            g_usb_table[ i ].active = false;
        }

        g_usb_count = 0;
    }


    namespace irp_hooks
    {
        void patch_string_descriptor(
            usb_string_descriptor_t*    desc,
            const wchar_t*              original_wide,
            const char*                 spoofed_serial )
        {
            if ( !desc || !original_wide || !spoofed_serial )
            {
                return;
            }

            wchar_t spoofed_wide[ k_max_serial_len ] = { };

            ascii_to_wide( spoofed_serial, spoofed_wide, k_max_serial_len );

            SIZE_T wlen = wcslen( spoofed_wide );
            SIZE_T orig = wcslen( original_wide );

            SIZE_T copy_wchar = min( wlen, orig );

            RtlCopyMemory( desc->string, spoofed_wide, copy_wchar * sizeof( wchar_t ) );
        }

        NTSTATUS on_internal_device_control(
            PDEVICE_OBJECT  dev_obj,
            PIRP            irp )
        {
            UNREFERENCED_PARAMETER( dev_obj );

            PIO_STACK_LOCATION stack = IoGetCurrentIrpStackLocation( irp );

            u32 ioctl = stack->Parameters.DeviceIoControl.IoControlCode;

            if ( ioctl == k_ioctl_usb_get_descriptor_from_node_connection )
            {
                if ( NT_SUCCESS( irp->IoStatus.Status ) &&
                     irp->AssociatedIrp.SystemBuffer )
                {
                    usb_descriptor_request_t* req =
                        reinterpret_cast< usb_descriptor_request_t* >(
                            irp->AssociatedIrp.SystemBuffer );

                    usb_string_descriptor_t* str_desc =
                        reinterpret_cast< usb_string_descriptor_t* >( req->data );

                    if ( str_desc->descriptor_type == 0x03 )
                    {

                        char orig[ k_max_serial_len ] = { };

                        wide_to_ascii( str_desc->string, orig, sizeof( orig ) );

                        for ( u32 i = 0; i < g_usb_count; ++i )
                        {
                            if ( strcmp( g_usb_table[ i ].original_serial, orig ) == 0 )
                            {
                                patch_string_descriptor(
                                    str_desc,
                                    str_desc->string,
                                    g_usb_table[ i ].spoofed_serial );

                                break;
                            }
                        }
                    }
                }
            }

            return irp->IoStatus.Status;
        }

    }

}
