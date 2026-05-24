#pragma once


#include "../includes/globals.hh"
#include "../includes/logging.hh"

namespace smbios
{

    #pragma pack( push, 1 )

    struct entry_point_t
    {
        char    anchor_string[ 4 ];     // "_SM_"
        u8      ep_checksum;
        u8      ep_length;
        u8      smbios_major;
        u8      smbios_minor;
        u16     max_struct_size;
        u8      ep_revision;
        u8      formatted_area[ 5 ];
        char    int_anchor[ 5 ];        // "_DMI_"
        u8      int_checksum;
        u16     struct_table_length;
        u32     struct_table_address;
        u16     struct_count;
        u8      bcd_revision;
    };

    struct entry_point_30_t
    {
        char    anchor_string[ 5 ];     // "_SM3_"
        u8      ep_checksum;
        u8      ep_length;
        u8      smbios_major;
        u8      smbios_minor;
        u8      smbios_docrev;
        u8      ep_revision;
        u8      reserved;
        u32     struct_table_max_size;
        u64     struct_table_address;
    };

    struct header_t
    {
        u8  type;
        u8  length;
        u16 handle;
    };

    struct type0_t       // BIOS Information
    {
        header_t    header;
        u8          vendor;
        u8          bios_version;
        u16         bios_starting_segment;
        u8          bios_release_date;
        u8          bios_rom_size;
        u64         bios_characteristics;
        u8          bios_char_ext[ 2 ];
        u8          major_release;
        u8          minor_release;
        u8          ec_major;
        u8          ec_minor;
    };

    struct type1_t       // System Information
    {
        header_t    header;
        u8          manufacturer;
        u8          product_name;
        u8          version;
        u8          serial_number;
        u8          uuid[ 16 ];
        u8          wake_up_type;
        u8          sku_number;
        u8          family;
    };

    struct type2_t       // Baseboard
    {
        header_t    header;
        u8          manufacturer;
        u8          product;
        u8          version;
        u8          serial_number;
        u8          asset_tag;
        u8          feature_flags;
        u8          location_in_chassis;
        u16         chassis_handle;
        u8          board_type;
        u8          num_contained;
    };

    struct type17_t      // Memory Device
    {
        header_t    header;
        u16         phys_memory_array_handle;
        u16         memory_error_info_handle;
        u16         total_width;
        u16         data_width;
        u16         size;
        u8          form_factor;
        u8          device_set;
        u8          device_locator;
        u8          bank_locator;
        u8          memory_type;
        u16         type_detail;
        u16         speed;
        u8          manufacturer;
        u8          serial_number;
        u8          asset_tag;
        u8          part_number;
        u8          attributes;
        u32         extended_size;
        u16         configured_clock_speed;
        u16         min_voltage;
        u16         max_voltage;
        u16         configured_voltage;
    };

    #pragma pack( pop )


    struct spoof_result_t
    {
        bool bios_spoofed;
        bool system_spoofed;
        bool baseboard_spoofed;
        bool memory_spoofed;
    };


    NTSTATUS        locate_table( void** out_base, u32* out_length );
    const char*     get_string( const header_t* hdr, u8 index );
    bool            patch_string( header_t* hdr, u8 index, const char* replacement );
    NTSTATUS        spoof_all( spoof_result_t* out_result );
    void            log_table( );

}
