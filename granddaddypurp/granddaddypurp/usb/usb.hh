#pragma once


#include "../includes/globals.hh"
#include "../includes/logging.hh"

namespace usb
{

    constexpr u32 k_ioctl_usb_get_root_hub_name                  = 0x00220408;
    constexpr u32 k_ioctl_usb_get_node_information               = 0x00220408;
    constexpr u32 k_ioctl_usb_get_node_connection_info_ex        = 0x00220448;
    constexpr u32 k_ioctl_usb_get_node_connection_driverkey_name = 0x00220420;
    constexpr u32 k_ioctl_usb_get_descriptor_from_node_connection = 0x00220410;


    #pragma pack( push, 1 )

    struct usb_device_descriptor_t
    {
        u8   length;
        u8   descriptor_type;
        u16  bcd_usb;
        u8   device_class;
        u8   device_sub_class;
        u8   device_protocol;
        u8   max_packet_size;
        u16  id_vendor;
        u16  id_product;
        u16  bcd_device;
        u8   manufacturer;
        u8   product;
        u8   serial_number;
        u8   num_configurations;
    };

    struct usb_string_descriptor_t
    {
        u8      length;
        u8      descriptor_type;
        wchar_t string[ 126 ];
    };

    struct usb_descriptor_request_t
    {
        u32                        connection_index;
        struct
        {
            u8  bm_request;
            u8  b_request;
            u16 w_value;
            u16 w_index;
            u16 w_length;
        }                          setup_packet;
        u8                         data[ 1 ];
    };

    #pragma pack( pop )


    struct usb_entry_t
    {
        wchar_t  hub_path[ k_max_path_len ];
        u32      port_index;
        char     original_serial[ k_max_serial_len ];
        char     spoofed_serial[ k_max_serial_len ];
        bool     active;
    };

    constexpr u32 k_max_usb_devices = 64;

    extern usb_entry_t  g_usb_table[ k_max_usb_devices ];
    extern u32          g_usb_count;


    NTSTATUS    enumerate( );
    NTSTATUS    spoof_all( );
    void        restore_all( );


    namespace irp_hooks
    {
        void patch_string_descriptor(
            usb_string_descriptor_t*    desc,
            const wchar_t*              original_wide,
            const char*                 spoofed_serial );

        NTSTATUS on_internal_device_control(
            PDEVICE_OBJECT  dev_obj,
            PIRP            irp );

    }

}
