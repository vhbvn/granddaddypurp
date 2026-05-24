
#include "tpm.hh"

namespace tpm
{

    spoof_config_t g_config = { };


    NTSTATUS init( )
    {
        u64 rng = util::rdtsc_seed( );


        const char* vendor_pool[] = { "INTC", "AMD\0", "IBM\0", "STM\0", "NTC\0", "IFX\0" };

        u32 vendor_idx = static_cast< u32 >( util::lcg_rand( rng ) % 6 );

        RtlCopyMemory( g_config.manufacturer_override, vendor_pool[ vendor_idx ], 5 );


        RtlStringCchPrintfA(
            g_config.vendor_str_override,
            sizeof( g_config.vendor_str_override ),
            "%04X%04X%04X%04X",
            (u32)( util::lcg_rand( rng ) & 0xFFFF ),
            (u32)( util::lcg_rand( rng ) & 0xFFFF ),
            (u32)( util::lcg_rand( rng ) & 0xFFFF ),
            (u32)( util::lcg_rand( rng ) & 0xFFFF ) );


        g_config.firmware_v1_override = (u32)( util::lcg_rand( rng ) & 0x0000FFFF ) | 0x00050000;
        g_config.firmware_v2_override = (u32)( util::lcg_rand( rng ) & 0x0000FFFF );

        logging::info( "TPM config: manufacturer='%.4s' vendor='%s' fw=%08X.%08X",
            g_config.manufacturer_override,
            g_config.vendor_str_override,
            g_config.firmware_v1_override,
            g_config.firmware_v2_override );

        return STATUS_SUCCESS;
    }


    NTSTATUS spoof_all( )
    {
        return init( );
    }


    void restore( )
    {
        RtlZeroMemory( &g_config, sizeof( g_config ) );
    }


    namespace patch
    {

        bool is_get_capability( const u8* cmd_buf, SIZE_T cmd_len )
        {
            if ( !cmd_buf || cmd_len < sizeof( tpm2_get_capability_cmd_t ) )
            {
                return false;
            }

            const tpm2_get_capability_cmd_t* cmd =
                reinterpret_cast< const tpm2_get_capability_cmd_t* >( cmd_buf );

            u32 cc = RtlUlongByteSwap( cmd->header.command_code );

            return ( cc == k_tpm2_cc_get_capability );
        }


        void patch_capability_response(
            u8*     rsp_buf,
            SIZE_T  rsp_len,
            u32     requested_property )
        {
            UNREFERENCED_PARAMETER( requested_property );
            if ( !rsp_buf || rsp_len < sizeof( tpm2_response_header_t ) + 8 )
            {
                return;
            }

            tpm2_response_header_t* hdr =
                reinterpret_cast< tpm2_response_header_t* >( rsp_buf );

            u32 rc = RtlUlongByteSwap( hdr->response_code );

            if ( rc != 0 )
            {
                return;
            }


            constexpr SIZE_T k_rsp_payload_offset = 10 + 1 + 4 + 4;

            if ( rsp_len < k_rsp_payload_offset + 8 )
            {
                return;
            }

            u8* payload = rsp_buf + k_rsp_payload_offset;
            u8* rsp_end = rsp_buf + rsp_len;

            while ( payload + 8 <= rsp_end )
            {

                u32 prop  = RtlUlongByteSwap( *reinterpret_cast< u32* >( payload ) );
                u32 value = RtlUlongByteSwap( *reinterpret_cast< u32* >( payload + 4 ) );

                (void)value;

                u32 new_value = 0;

                switch ( prop )
                {
                case k_tpm2_pt_manufacturer:
                {
                    RtlCopyMemory( &new_value, g_config.manufacturer_override, 4 );

                    break;
                }

                case k_tpm2_pt_vendor_string_1:
                {
                    RtlCopyMemory( &new_value, g_config.vendor_str_override + 0, 4 );

                    break;
                }

                case k_tpm2_pt_vendor_string_2:
                {
                    RtlCopyMemory( &new_value, g_config.vendor_str_override + 4, 4 );

                    break;
                }

                case k_tpm2_pt_vendor_string_3:
                {
                    RtlCopyMemory( &new_value, g_config.vendor_str_override + 8, 4 );

                    break;
                }

                case k_tpm2_pt_vendor_string_4:
                {
                    RtlCopyMemory( &new_value, g_config.vendor_str_override + 12, 4 );

                    break;
                }

                case k_tpm2_pt_firmware_v1:
                {
                    new_value = g_config.firmware_v1_override;

                    break;
                }

                case k_tpm2_pt_firmware_v2:
                {
                    new_value = g_config.firmware_v2_override;

                    break;
                }

                default:
                {
                    payload += 8;

                    continue;
                }

                }


                u32 be = RtlUlongByteSwap( new_value );

                RtlCopyMemory( payload + 4, &be, 4 );

                logging::verbose( "TPM prop 0x%08X -> 0x%08X", prop, new_value );

                payload += 8;
            }
        }

    }


    namespace irp_hooks
    {
        NTSTATUS on_device_control(
            PDEVICE_OBJECT  dev_obj,
            PIRP            irp )
        {
            UNREFERENCED_PARAMETER( dev_obj );

            PIO_STACK_LOCATION stack = IoGetCurrentIrpStackLocation( irp );

            u32 ioctl = stack->Parameters.DeviceIoControl.IoControlCode;

            if ( ioctl != k_ioctl_tpm_submit_command )
            {
                return irp->IoStatus.Status;
            }

            if ( !NT_SUCCESS( irp->IoStatus.Status ) )
            {
                return irp->IoStatus.Status;
            }

            u8* in_buf  = reinterpret_cast< u8* >( irp->AssociatedIrp.SystemBuffer );
            u8* out_buf = reinterpret_cast< u8* >( irp->AssociatedIrp.SystemBuffer );

            SIZE_T in_len  = stack->Parameters.DeviceIoControl.InputBufferLength;
            SIZE_T out_len = stack->Parameters.DeviceIoControl.OutputBufferLength;

            if ( !in_buf || !out_buf )
            {
                return irp->IoStatus.Status;
            }

            if ( patch::is_get_capability( in_buf, in_len ) )
            {
                const tpm2_get_capability_cmd_t* cmd =
                    reinterpret_cast< const tpm2_get_capability_cmd_t* >( in_buf );

                u32 prop = RtlUlongByteSwap( cmd->property );

                patch::patch_capability_response( out_buf, out_len, prop );
            }

            return irp->IoStatus.Status;
        }

    }

}
