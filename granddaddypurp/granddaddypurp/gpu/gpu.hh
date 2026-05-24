#pragma once


#include "../includes/globals.hh"
#include "../includes/logging.hh"

namespace gpu
{

    enum class vendor_t : u16
    {
        unknown = 0x0000,
        nvidia  = 0x10DE,
        amd     = 0x1002,
        intel   = 0x8086,
    };


    struct gpu_entry_t
    {
        vendor_t    vendor;
        u16         device_id;
        char        original_name[ 128 ];
        char        spoofed_name[ 128 ];
        char        original_serial[ k_max_serial_len ];
        char        spoofed_serial[ k_max_serial_len ];
        wchar_t     registry_path[ k_max_path_len ];
        bool        active;
    };

    constexpr u32 k_max_gpus = 8;

    extern gpu_entry_t  g_gpu_table[ k_max_gpus ];
    extern u32          g_gpu_count;


    namespace nvidia
    {
        NTSTATUS enumerate( );
        NTSTATUS spoof_serial( u32 index );
        NTSTATUS patch_registry( u32 index );

    }

    namespace amd
    {
        NTSTATUS enumerate( );
        NTSTATUS spoof_serial( u32 index );
        NTSTATUS patch_registry( u32 index );

    }


    NTSTATUS    enumerate( );
    NTSTATUS    spoof_all( );
    void        restore_all( );


    namespace registry
    {
        NTSTATUS read_sz(
            HANDLE          hkey,
            const wchar_t*  value_name,
            wchar_t*        out_buf,
            u32             out_len );

        NTSTATUS write_sz(
            HANDLE          hkey,
            const wchar_t*  value_name,
            const wchar_t*  value );

        NTSTATUS open_display_key(
            u32             adapter_index,
            HANDLE*         out_hkey );

    }

}
