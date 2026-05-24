#pragma once


#include "../includes/globals.hh"
#include "../includes/logging.hh"

namespace network
{

    struct mac_addr_t
    {
        u8 bytes[ 6 ];
    };


    constexpr u32 k_oid_gen_current_packet_filter    = 0x0001010E;
    constexpr u32 k_oid_802_3_permanent_address      = 0x01010101;
    constexpr u32 k_oid_802_3_current_address        = 0x01010102;
    constexpr u32 k_oid_802_3_multicast_list         = 0x01010103;
    constexpr u32 k_oid_gen_link_speed               = 0x00010107;
    constexpr u32 k_oid_gen_media_connect_status     = 0x00010114;


    struct adapter_entry_t
    {
        wchar_t  friendly_name[ 64 ];
        mac_addr_t original_mac;
        mac_addr_t spoofed_mac;
        bool       active;
    };

    constexpr u32 k_max_adapters = 16;

    extern adapter_entry_t  g_adapter_table[ k_max_adapters ];
    extern u32              g_adapter_count;


    NTSTATUS    enumerate_adapters( );
    NTSTATUS    spoof_all( );
    NTSTATUS    spoof_adapter( u32 index );
    void        restore_all( );


    namespace arp
    {
        NTSTATUS    flush_table( );
        NTSTATUS    inject_spoofed_entry( const mac_addr_t& spoofed );

    }


    namespace nsi_hooks
    {
        NTSTATUS    install( );
        void        remove( );

        NTSTATUS on_ioctl_nsi_proxy(
            PDEVICE_OBJECT  dev_obj,
            PIRP            irp );

    }


    namespace oid_hooks
    {
        void patch_oid_query_response(
            u32          oid,
            void*        buf,
            u32          buf_len );

    }


    SPOOF_INLINE void generate_mac( mac_addr_t& out, u64& rng )
    {
        for ( int i = 0; i < 6; ++i )
        {
            out.bytes[ i ] = static_cast< u8 >( util::lcg_rand( rng ) & 0xFF );
        }


        out.bytes[ 0 ] = ( out.bytes[ 0 ] & 0xFE ) | 0x02;
    }

    SPOOF_INLINE bool mac_equal( const mac_addr_t& a, const mac_addr_t& b )
    {
        return RtlCompareMemory( a.bytes, b.bytes, 6 ) == 6;
    }

}
