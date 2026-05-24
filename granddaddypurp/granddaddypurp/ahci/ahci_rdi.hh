#pragma once


#include "../includes/globals.hh"
#include "../includes/logging.hh"
#include "../pattern/pattern_scan.hh"

namespace ahci_rdi
{

    #pragma pack( push, 1 )

    struct ata_identify_t
    {
        u16 general_config;             // word 0
        u16 obsolete_1;                 // word 1
        u16 specific_config;            // word 2
        u16 obsolete_3;                 // word 3
        u16 retired_4_5[ 2 ];
        u16 obsolete_6;
        u16 compact_flash_assoc[ 2 ];
        u16 retired_9;
        char serial_number[ 20 ];       // words 10-19 (byte-swapped ATA)
        u16 retired_20_21[ 2 ];
        u16 obsolete_22;
        char firmware_revision[ 8 ];    // words 23-26 (byte-swapped)
        char model_number[ 40 ];        // words 27-46 (byte-swapped)
        u16 max_transfer;               // word 47
        u16 trusted_computing;          // word 48
        u16 capabilities_49_50[ 2 ];
        u16 obsolete_51_52[ 2 ];
        u16 field_validity;             // word 53
        u16 obsolete_54_58[ 5 ];
        u16 obsolete_59_62[ 4 ];
        u16 multiword_dma;              // word 63
        u16 pio_modes;                  // word 64
        u16 padding[ 191 ];             // words 65-255
    };

    #pragma pack( pop )

    static_assert( sizeof( ata_identify_t ) == 512, "ATA IDENTIFY must be 512 bytes" );


    struct ahci_port_entry_t
    {
        u32             port_index;
        ata_identify_t  original_id;
        ata_identify_t  spoofed_id;
        bool            active;
    };

    constexpr u32 k_max_ahci_ports = 8;

    extern ahci_port_entry_t    g_ahci_ports[ k_max_ahci_ports ];
    extern u32                  g_ahci_port_count;


    NTSTATUS    locate_miniport_identify_buffers( );
    NTSTATUS    spoof_port( u32 port_index );
    NTSTATUS    spoof_all( );
    void        restore_all( );


    namespace identify
    {
        void    swap_ata_string( char* str, SIZE_T len );
        void    patch_serial( ata_identify_t* id, const char* new_serial );
        void    patch_model( ata_identify_t* id, const char* new_model );

    } // namespace identify


    constexpr const char* k_storahci_identify_pattern =
        "48 8B 87 ?? ?? ?? ?? 48 85 C0";

} // namespace ahci_rdi
