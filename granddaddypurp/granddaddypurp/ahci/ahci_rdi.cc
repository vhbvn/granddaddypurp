
#include "ahci_rdi.hh"
#include "../includes/globals.hh"
#include "../includes/logging.hh"

namespace ahci_rdi
{

    ahci_port_entry_t   g_ahci_ports[ k_max_ahci_ports ] = { };
    u32                 g_ahci_port_count                 = 0;


    namespace identify
    {

        void swap_ata_string( char* str, SIZE_T len )
        {
            for ( SIZE_T i = 0; i + 1 < len; i += 2 )
            {
                char tmp    = str[ i ];
                str[ i ]    = str[ i + 1 ];
                str[ i + 1 ] = tmp;
            }
        }

        void patch_serial( ata_identify_t* id, const char* new_serial )
        {
            if ( !id || !new_serial )
            {
                return;
            }

            RtlZeroMemory( id->serial_number, sizeof( id->serial_number ) );

            RtlFillMemory( id->serial_number, sizeof( id->serial_number ), ' ' );

            SIZE_T slen = min( strlen( new_serial ), sizeof( id->serial_number ) );

            RtlCopyMemory( id->serial_number, new_serial, slen );


            swap_ata_string( id->serial_number, sizeof( id->serial_number ) );
        }

        void patch_model( ata_identify_t* id, const char* new_model )
        {
            if ( !id || !new_model )
            {
                return;
            }

            RtlZeroMemory( id->model_number, sizeof( id->model_number ) );

            RtlFillMemory( id->model_number, sizeof( id->model_number ), ' ' );

            SIZE_T mlen = min( strlen( new_model ), sizeof( id->model_number ) );

            RtlCopyMemory( id->model_number, new_model, mlen );

            swap_ata_string( id->model_number, sizeof( id->model_number ) );
        }

    }


    NTSTATUS locate_miniport_identify_buffers( )
    {
        u64 storahci_base = pattern_scan::get_module_base( L"StorAHCI.sys" );

        if ( !storahci_base )
        {
            logging::warn( "StorAHCI.sys not loaded — trying storahci.sys" );

            storahci_base = pattern_scan::get_module_base( L"storahci.sys" );
        }

        if ( !storahci_base )
        {
            logging::warn( "StorAHCI miniport not found; using IOCTL-level intercept only" );

            return STATUS_NOT_FOUND;
        }

        u32 storahci_size = pattern_scan::get_module_size( storahci_base );

        u64 pattern_addr = pattern_scan::scan_str(
            storahci_base,
            storahci_size,
            k_storahci_identify_pattern );

        if ( !pattern_addr )
        {
            logging::warn( "AHCI IDENTIFY pattern not found in StorAHCI" );

            return STATUS_NOT_FOUND;
        }


        u32 id_offset = *reinterpret_cast< u32* >( pattern_addr + 3 );

        logging::info( "StorAHCI IDENTIFY offset: 0x%X (found at 0x%llX)",
            id_offset, pattern_addr );

        return STATUS_SUCCESS;
    }


    NTSTATUS spoof_port( u32 port_index )
    {
        if ( port_index >= g_ahci_port_count )
        {
            return STATUS_INVALID_PARAMETER;
        }

        ahci_port_entry_t* entry = &g_ahci_ports[ port_index ];

        if ( !entry->active )
        {
            return STATUS_NOT_FOUND;
        }

        u64 rng = util::rdtsc_seed( );


        RtlCopyMemory( &entry->spoofed_id, &entry->original_id, sizeof( ata_identify_t ) );


        char orig_serial[ 21 ] = { };

        RtlCopyMemory( orig_serial, entry->original_id.serial_number, 20 );

        identify::swap_ata_string( orig_serial, 20 );


        for ( int i = 19; i >= 0 && orig_serial[ i ] == ' '; --i )
        {
            orig_serial[ i ] = '\0';
        }


        char spoofed_serial[ 21 ] = { };

        RtlStringCchCopyA( spoofed_serial, sizeof( spoofed_serial ), orig_serial );

        util::mutate_serial_digit( spoofed_serial, strlen( spoofed_serial ), rng );


        identify::patch_serial( &entry->spoofed_id, spoofed_serial );

        logging::info( "AHCI port[%u] serial: '%s' -> '%s'",
            port_index, orig_serial, spoofed_serial );

        return STATUS_SUCCESS;
    }


    NTSTATUS spoof_all( )
    {
        locate_miniport_identify_buffers( );

        g_ahci_port_count = 0;

        for ( u32 disk_idx = 0; disk_idx < k_max_ahci_ports; ++disk_idx )
        {
            UNICODE_STRING dev_name = { };
            wchar_t        dev_buf[ 64 ] = { };

            RtlStringCchPrintfW( dev_buf, ARRAYSIZE( dev_buf ),
                L"\\Device\\Harddisk%u\\DR%u", disk_idx, disk_idx );

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


            #pragma pack( push, 1 )

            struct ata_passthrough_ex_t
            {
                u16 length;
                u16 ataflag;            // 0x02 = DRDY required, 0x04 = use DMA
                u8  timeout_value;
                u8  reserved1;
                u16 channel_number;
                u8  drive_select;       // 0xA0 = master, 0xB0 = slave
                u8  reserved2;
                u8  control;
                u8  feature;
                u8  sector_count;
                u8  reserved3;
                u8  sector_number;
                u8  reserved4;
                u16 cylinder_low;
                u16 cylinder_high;
                u8  device_head;
                u8  reserved5;
                u8  command;            // 0xEC = ATA IDENTIFY DEVICE
                u8  reserved6;
                u16 reserved7;
            };

            #pragma pack( pop )

            constexpr u32 k_ata_pt_ioctl    = 0x0004D02C;
            constexpr SIZE_T k_pt_buf_size  = sizeof( ata_passthrough_ex_t ) + sizeof( ata_identify_t );

            u8* pt_buf = reinterpret_cast< u8* >( spoof_alloc_paged( k_pt_buf_size ) );

            if ( !pt_buf )
            {
                ZwClose( hdev );
                break;
            }

            RtlZeroMemory( pt_buf, k_pt_buf_size );

            ata_passthrough_ex_t* pt =
                reinterpret_cast< ata_passthrough_ex_t* >( pt_buf );

            pt->length       = sizeof( ata_passthrough_ex_t );
            pt->ataflag      = 0x04 | 0x40;
            pt->timeout_value = 20;
            pt->drive_select = 0xA0;
            pt->command      = 0xEC;
            pt->sector_count = 1;

            status = ZwDeviceIoControlFile(
                hdev,
                nullptr,
                nullptr,
                nullptr,
                &iosb,
                k_ata_pt_ioctl,
                pt_buf,
                static_cast< u32 >( k_pt_buf_size ),
                pt_buf,
                static_cast< u32 >( k_pt_buf_size ) );

            if ( NT_SUCCESS( status ) )
            {
                ahci_port_entry_t* entry = &g_ahci_ports[ g_ahci_port_count ];

                RtlZeroMemory( entry, sizeof( ahci_port_entry_t ) );

                entry->port_index = disk_idx;

                RtlCopyMemory(
                    &entry->original_id,
                    pt_buf + sizeof( ata_passthrough_ex_t ),
                    sizeof( ata_identify_t ) );

                entry->active = true;

                ++g_ahci_port_count;

                spoof_port( g_ahci_port_count - 1 );
            }

            spoof_free( pt_buf );

            ZwClose( hdev );
        }

        logging::info( "AHCI: %u ports spoofed", g_ahci_port_count );

        return STATUS_SUCCESS;
    }


    void restore_all( )
    {
        for ( u32 i = 0; i < g_ahci_port_count; ++i )
        {
            g_ahci_ports[ i ].active = false;
        }

        g_ahci_port_count = 0;
    }

}
