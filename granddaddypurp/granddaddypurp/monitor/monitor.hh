#pragma once


#include "../includes/globals.hh"
#include "../includes/logging.hh"

namespace monitor
{

    constexpr u32 k_edid_size           = 128;
    constexpr u32 k_edid_serial_offset  = 8;
    constexpr u32 k_edid_desc_offset    = 54;


    constexpr u8  k_edid_desc_serial    = 0xFF;

    #pragma pack( push, 1 )

    struct edid_header_t
    {
        u8  magic[ 8 ];         // 00 FF FF FF FF FF FF 00
        u16 manufacturer_id;    // big-endian, 3-char code packed into 15 bits
        u16 product_code;
        u32 serial_number;      // 4-byte serial (not always used)
        u8  manufacture_week;
        u8  manufacture_year;   // year - 1990
        u8  edid_version;
        u8  edid_revision;
    };

    struct edid_descriptor_t
    {
        u16 pixel_clock;        // 0x0000 for monitor descriptor blocks
        u8  reserved_0;
        u8  descriptor_type;    // 0xFF = serial number, 0xFE = unspec text, etc.
        u8  reserved_1;
        u8  data[ 13 ];         // 13 bytes of string / data
    };

    #pragma pack( pop )


    struct monitor_entry_t
    {
        wchar_t  registry_path[ k_max_path_len ];
        u8       original_edid[ k_edid_size ];
        u8       spoofed_edid[ k_edid_size ];
        char     original_serial_str[ 14 ];
        char     spoofed_serial_str[ 14 ];
        bool     active;
    };

    constexpr u32 k_max_monitors = 8;

    extern monitor_entry_t  g_monitor_table[ k_max_monitors ];
    extern u32              g_monitor_count;


    NTSTATUS    enumerate( );
    NTSTATUS    spoof_all( );
    NTSTATUS    spoof_monitor( u32 index );
    void        restore_all( );


    namespace edid
    {
        u8      compute_checksum( const u8* edid );

        bool    find_serial_descriptor(
            const u8*   edid,
            u32*        out_desc_offset );

        void    patch_serial_descriptor(
            u8*         edid,
            const char* new_serial );

        void    patch_hw_serial(
            u8*         edid,
            u64&        rng );

    }

}
