#pragma once


#include "../includes/globals.hh"
#include "../includes/logging.hh"

namespace disk
{

    constexpr u32 k_ioctl_storage_query_property      = 0x002D1400;
    constexpr u32 k_ioctl_ata_passthrough             = 0x0004D02C;
    constexpr u32 k_ioctl_scsi_passthrough            = 0x0004D008;
    constexpr u32 k_ioctl_nvme_passthrough            = 0x0E000011;


    #pragma pack( push, 1 )

    struct storage_descriptor_header_t
    {
        u32 version;
        u32 size;
    };

    struct storage_device_descriptor_t
    {
        u32  version;
        u32  size;
        u8   device_type;
        u8   device_type_modifier;
        u8   removable_media;
        u8   command_queueing;
        u32  vendor_id_offset;
        u32  product_id_offset;
        u32  product_revision_offset;
        u32  serial_number_offset;
        u32  bus_type;
        u32  raw_properties_length;
        u8   raw_device_properties[ 1 ];
    };

    #pragma pack( pop )


    struct disk_entry_t
    {
        char  original_serial[ k_max_serial_len ];
        char  spoofed_serial[ k_max_serial_len ];
        char  original_model[ k_max_serial_len ];
        char  spoofed_model[ k_max_serial_len ];
        bool  active;
    };

    constexpr u32 k_max_disks = 16;

    extern disk_entry_t g_disk_table[ k_max_disks ];
    extern u32          g_disk_count;


    NTSTATUS    enumerate_disks( );
    NTSTATUS    spoof_all( );
    NTSTATUS    spoof_disk( u32 index );
    void        restore_all( );
    const char* get_spoofed_serial( const char* original );


    namespace irp_hooks
    {
        NTSTATUS on_device_control(
            PDEVICE_OBJECT  dev_obj,
            PIRP            irp );

        void patch_storage_descriptor(
            storage_device_descriptor_t*  desc,
            SIZE_T                        buf_len );

    }

}
