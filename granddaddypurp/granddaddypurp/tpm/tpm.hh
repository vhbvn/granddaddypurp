#pragma once


#include "../includes/globals.hh"
#include "../includes/logging.hh"

namespace tpm
{

    constexpr u32 k_tpm_device_ioctl_base    = 0x00000022;
    constexpr u32 k_ioctl_tpm_submit_command = 0x00220000;


    constexpr u32 k_tpm2_cc_get_capability  = 0x0000017A;
    constexpr u32 k_tpm2_cc_read_public     = 0x00000173;
    constexpr u32 k_tpm2_cc_nv_read        = 0x0000014E;


    constexpr u32 k_tpm2_pt_manufacturer    = 0x00000105;
    constexpr u32 k_tpm2_pt_vendor_string_1 = 0x00000106;
    constexpr u32 k_tpm2_pt_vendor_string_2 = 0x00000107;
    constexpr u32 k_tpm2_pt_vendor_string_3 = 0x00000108;
    constexpr u32 k_tpm2_pt_vendor_string_4 = 0x00000109;
    constexpr u32 k_tpm2_pt_firmware_v1     = 0x0000010B;
    constexpr u32 k_tpm2_pt_firmware_v2     = 0x0000010C;


    #pragma pack( push, 1 )

    struct tpm2_command_header_t
    {
        u16 tag;
        u32 size;
        u32 command_code;
    };

    struct tpm2_response_header_t
    {
        u16 tag;
        u32 size;
        u32 response_code;
    };

    struct tpm2_get_capability_cmd_t
    {
        tpm2_command_header_t header;
        u32 capability;
        u32 property;
        u32 property_count;
    };

    #pragma pack( pop )


    struct spoof_config_t
    {
        char manufacturer_override[ 5 ];    // 4 char JEDEC code + NUL
        char vendor_str_override[ 17 ];     // up to 16 chars + NUL
        u32  firmware_v1_override;
        u32  firmware_v2_override;
    };

    extern spoof_config_t g_config;


    NTSTATUS    init( );
    NTSTATUS    spoof_all( );
    void        restore( );


    namespace patch
    {
        bool is_get_capability( const u8* cmd_buf, SIZE_T cmd_len );

        void patch_capability_response(
            u8*     rsp_buf,
            SIZE_T  rsp_len,
            u32     requested_property );

    }


    namespace irp_hooks
    {
        NTSTATUS on_device_control(
            PDEVICE_OBJECT  dev_obj,
            PIRP            irp );

    }

}
