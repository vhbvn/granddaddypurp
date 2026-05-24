
#include "disk.hh"
#include "../includes/globals.hh"
#include "../includes/logging.hh"

namespace disk
{

    disk_entry_t    g_disk_table[ k_max_disks ] = { };
    u32             g_disk_count                = 0;





    NTSTATUS enumerate_disks( )
    {
        g_disk_count = 0;

        for ( u32 idx = 0; idx < k_max_disks; ++idx )
        {
            UNICODE_STRING dev_name = { };
            wchar_t        dev_buf[ 64 ] = { };

            RtlStringCchPrintfW( dev_buf, ARRAYSIZE( dev_buf ),
                L"\\Device\\Harddisk%u\\DR%u", idx, idx );

            RtlInitUnicodeString( &dev_name, dev_buf );

            OBJECT_ATTRIBUTES obj_attr = { };

            InitializeObjectAttributes(
                &obj_attr,
                &dev_name,
                OBJ_CASE_INSENSITIVE | OBJ_KERNEL_HANDLE,
                nullptr,
                nullptr );

            HANDLE          hdev    = nullptr;
            IO_STATUS_BLOCK iosb    = { };

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
                break;
            }


            constexpr u32 k_buf_size = 1024;

            u8* out_buf = reinterpret_cast< u8* >( spoof_alloc_paged( k_buf_size ) );

            if ( !out_buf )
            {
                ZwClose( hdev );
                break;
            }

            RtlZeroMemory( out_buf, k_buf_size );


            struct
            {
                u32 property_id;    // StorageDeviceProperty = 0
                u32 query_type;     // PropertyStandardQuery  = 0
                u8  additional[ 1 ];
            } query = { 0, 0, { 0 } };

            status = ZwDeviceIoControlFile(
                hdev,
                nullptr,
                nullptr,
                nullptr,
                &iosb,
                k_ioctl_storage_query_property,
                &query,
                sizeof( query ),
                out_buf,
                k_buf_size );

            if ( NT_SUCCESS( status ) )
            {
                storage_device_descriptor_t* desc =
                    reinterpret_cast< storage_device_descriptor_t* >( out_buf );

                disk_entry_t* entry = &g_disk_table[ g_disk_count ];

                RtlZeroMemory( entry, sizeof( disk_entry_t ) );

                if ( desc->serial_number_offset &&
                     desc->serial_number_offset < k_buf_size )
                {
                    const char* raw_serial =
                        reinterpret_cast< const char* >( out_buf ) + desc->serial_number_offset;

                    RtlStringCchCopyA( entry->original_serial,
                        k_max_serial_len, raw_serial );

                    logging::info( "Disk[%u] serial: '%s'", idx, entry->original_serial );
                }

                if ( desc->product_id_offset &&
                     desc->product_id_offset < k_buf_size )
                {
                    const char* raw_model =
                        reinterpret_cast< const char* >( out_buf ) + desc->product_id_offset;

                    RtlStringCchCopyA( entry->original_model,
                        k_max_serial_len, raw_model );
                }

                entry->active = true;

                ++g_disk_count;
            }

            spoof_free( out_buf );

            ZwClose( hdev );
        }

        logging::info( "%u disks enumerated", g_disk_count );

        return STATUS_SUCCESS;
    }


    NTSTATUS spoof_disk( u32 index )
    {
        if ( index >= g_disk_count )
        {
            return STATUS_INVALID_PARAMETER;
        }

        disk_entry_t* entry = &g_disk_table[ index ];

        if ( !entry->active )
        {
            return STATUS_NOT_FOUND;
        }

        u64 rng = util::rdtsc_seed( );

        RtlStringCchCopyA( entry->spoofed_serial, k_max_serial_len, entry->original_serial );
        RtlStringCchCopyA( entry->spoofed_model,  k_max_serial_len, entry->original_model );

        util::mutate_serial_digit( entry->spoofed_serial, strlen( entry->spoofed_serial ), rng );
        util::mutate_serial_digit( entry->spoofed_model,  strlen( entry->spoofed_model ),  rng );

        logging::info( "Disk[%u] serial spoofed: '%s' -> '%s'",
            index, entry->original_serial, entry->spoofed_serial );

        return STATUS_SUCCESS;
    }


    NTSTATUS spoof_all( )
    {
        NTSTATUS status = enumerate_disks( );

        if ( !NT_SUCCESS( status ) )
        {
            return status;
        }

        for ( u32 i = 0; i < g_disk_count; ++i )
        {
            spoof_disk( i );
        }

        return STATUS_SUCCESS;
    }


    void restore_all( )
    {
        for ( u32 i = 0; i < g_disk_count; ++i )
        {
            g_disk_table[ i ].active = false;
        }

        g_disk_count = 0;

        logging::info( "disk entries cleared" );
    }


    const char* get_spoofed_serial( const char* original )
    {
        for ( u32 i = 0; i < g_disk_count; ++i )
        {
            if ( strcmp( g_disk_table[ i ].original_serial, original ) == 0 )
            {
                return g_disk_table[ i ].spoofed_serial;
            }
        }

        return nullptr;
    }


    namespace irp_hooks
    {
        void patch_storage_descriptor(
            storage_device_descriptor_t*  desc,
            SIZE_T                        buf_len )
        {
            if ( !desc || buf_len < sizeof( storage_device_descriptor_t ) )
            {
                return;
            }

            if ( desc->serial_number_offset &&
                 desc->serial_number_offset < buf_len )
            {
                char* serial = reinterpret_cast< char* >( desc ) + desc->serial_number_offset;

                const char* spoofed = get_spoofed_serial( serial );

                if ( spoofed )
                {
                    SIZE_T slen = min( strlen( spoofed ), strlen( serial ) );

                    RtlCopyMemory( serial, spoofed, slen );
                }
            }
        }

        NTSTATUS on_device_control(
            PDEVICE_OBJECT  dev_obj,
            PIRP            irp )
        {
            UNREFERENCED_PARAMETER( dev_obj );

            PIO_STACK_LOCATION stack = IoGetCurrentIrpStackLocation( irp );

            u32 ioctl = stack->Parameters.DeviceIoControl.IoControlCode;

            if ( ioctl == k_ioctl_storage_query_property )
            {

                NTSTATUS status = irp->IoStatus.Status;

                if ( NT_SUCCESS( status ) && irp->AssociatedIrp.SystemBuffer )
                {
                    storage_device_descriptor_t* desc =
                        reinterpret_cast< storage_device_descriptor_t* >(
                            irp->AssociatedIrp.SystemBuffer );

                    patch_storage_descriptor(
                        desc,
                        stack->Parameters.DeviceIoControl.OutputBufferLength );
                }
            }

            return irp->IoStatus.Status;
        }

    }

}
