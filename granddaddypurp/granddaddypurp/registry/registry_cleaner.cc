
#include "registry_cleaner.hh"

namespace registry_cleaner
{

    const reg_target_t g_targets[] =
    {
        {
            L"\\Registry\\Machine\\SOFTWARE\\Microsoft\\Cryptography",
            L"MachineGuid",
            target_type_t::spoof_guid
        },

        {
            L"\\Registry\\Machine\\SOFTWARE\\Microsoft\\Windows NT\\CurrentVersion",
            L"InstallDate",
            target_type_t::delete_value
        },

        {
            L"\\Registry\\Machine\\SOFTWARE\\Microsoft\\SQMClient",
            L"MachineId",
            target_type_t::spoof_guid
        },

        {
            L"\\Registry\\Machine\\SYSTEM\\CurrentControlSet\\Control\\SystemInformation",
            L"ComputerHardwareId",
            target_type_t::spoof_guid
        },

        {
            L"\\Registry\\Machine\\SOFTWARE\\Microsoft\\Windows NT\\CurrentVersion",
            L"DigitalProductId",
            target_type_t::zero_binary
        },

        {
            L"\\Registry\\Machine\\SOFTWARE\\Microsoft\\EventSystem\\{26A0DB25-12B1-11D1-AD9A-00C04FD8FDFF}\\Subscriptions\\{00000000-0000-0000-0000-000000000000}",
            L"SubscriberID",
            target_type_t::spoof_guid
        },

        {
            L"\\Registry\\Machine\\SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\WindowsUpdate",
            L"SusClientId",
            target_type_t::spoof_guid
        },

        {
            L"\\Registry\\Machine\\SYSTEM\\CurrentControlSet\\Services\\disk\\Enum",
            L"0",
            target_type_t::spoof_serial
        },

        {
            L"\\Registry\\Machine\\SYSTEM\\CurrentControlSet\\Services\\Tcpip\\Parameters",
            L"NV Hostname",
            target_type_t::spoof_serial
        },

        {
            L"\\Registry\\Machine\\SOFTWARE\\NVIDIA Corporation\\NvTelemetry",
            L"ClientId",
            target_type_t::spoof_guid
        },

        {
            L"\\Registry\\Machine\\SOFTWARE\\AMD\\CN",
            L"install_id",
            target_type_t::spoof_guid
        },

        {
            L"\\Registry\\Machine\\SOFTWARE\\Valve\\Steam",
            L"SteamPath",
            target_type_t::delete_value
        },

        {
            L"\\Registry\\Machine\\SYSTEM\\CurrentControlSet\\Control\\Session Manager\\Environment",
            L"EAC_ID",
            target_type_t::delete_value
        },

        {
            L"\\Registry\\Machine\\SOFTWARE\\BattlEye",
            L"GUID",
            target_type_t::spoof_guid
        },
    };

    const u32 g_target_count = static_cast< u32 >( ARRAYSIZE( g_targets ) );


    namespace guid_gen
    {
        void generate( u64& rng, wchar_t out[ 39 ] )
        {
            u32 a = static_cast< u32 >( util::lcg_rand( rng ) );
            u16 b = static_cast< u16 >( util::lcg_rand( rng ) );
            u16 c = static_cast< u16 >( util::lcg_rand( rng ) );
            u16 d = static_cast< u16 >( util::lcg_rand( rng ) );
            u32 e_hi = static_cast< u32 >( util::lcg_rand( rng ) );
            u16 e_lo = static_cast< u16 >( util::lcg_rand( rng ) );


            c = ( c & 0x0FFF ) | 0x4000;
            d = ( d & 0x3FFF ) | 0x8000;

            RtlStringCchPrintfW( out, 39,
                L"{%08X-%04X-%04X-%04X-%08X%04X}",
                a, b, c, d, e_hi, e_lo );
        }

    }


    static NTSTATUS open_key(
        const wchar_t*  path,
        ACCESS_MASK     access,
        HANDLE*         out_hkey )
    {
        UNICODE_STRING   upath  = { };
        OBJECT_ATTRIBUTES attr   = { };

        RtlInitUnicodeString( &upath, path );

        InitializeObjectAttributes(
            &attr,
            &upath,
            OBJ_CASE_INSENSITIVE | OBJ_KERNEL_HANDLE,
            nullptr,
            nullptr );

        return ZwOpenKey( out_hkey, access, &attr );
    }


    NTSTATUS process_target( const reg_target_t& target, u64& rng )
    {
        HANDLE hkey = nullptr;

        NTSTATUS status = open_key( target.key_path, KEY_ALL_ACCESS, &hkey );

        if ( !NT_SUCCESS( status ) )
        {
            logging::warn( "Key open failed '%S': 0x%08X", target.key_path, status );

            return status;
        }

        UNICODE_STRING val_name = { };

        RtlInitUnicodeString( &val_name, target.value_name );

        switch ( target.action )
        {

        case target_type_t::spoof_guid:
        case target_type_t::spoof_machine_id:
        {
            wchar_t new_guid[ 39 ] = { };

            guid_gen::generate( rng, new_guid );

            u32 len = static_cast< u32 >( ( wcslen( new_guid ) + 1 ) * sizeof( wchar_t ) );

            status = ZwSetValueKey(
                hkey,
                &val_name,
                0,
                REG_SZ,
                new_guid,
                len );

            logging::info( "GUID spoofed: '%S'\\%S -> %S",
                target.key_path, target.value_name, new_guid );

            break;
        }


        case target_type_t::spoof_serial:
        {
            u8  raw[ sizeof( KEY_VALUE_PARTIAL_INFORMATION ) + 256 ] = { };
            u32 needed = 0;

            KEY_VALUE_PARTIAL_INFORMATION* kvi =
                reinterpret_cast< KEY_VALUE_PARTIAL_INFORMATION* >( raw );

            status = ZwQueryValueKey(
                hkey,
                &val_name,
                KeyValuePartialInformation,
                kvi,
                sizeof( raw ),
                reinterpret_cast< PULONG >( &needed ) );

            if ( NT_SUCCESS( status ) && ( kvi->Type == REG_SZ || kvi->Type == REG_EXPAND_SZ ) )
            {
                wchar_t* wstr = reinterpret_cast< wchar_t* >( kvi->Data );

                char ascii[ k_max_serial_len ] = { };

                for ( u32 i = 0; i < k_max_serial_len - 1 && wstr[ i ]; ++i )
                {
                    ascii[ i ] = static_cast< char >( wstr[ i ] & 0xFF );
                }

                util::mutate_serial_digit( ascii, strlen( ascii ), rng );

                wchar_t new_wstr[ k_max_serial_len ] = { };

                for ( u32 i = 0; i < k_max_serial_len - 1 && ascii[ i ]; ++i )
                {
                    new_wstr[ i ] = static_cast< wchar_t >( (u8)ascii[ i ] );
                }

                u32 len = static_cast< u32 >( ( wcslen( new_wstr ) + 1 ) * sizeof( wchar_t ) );

                status = ZwSetValueKey(
                    hkey,
                    &val_name,
                    0,
                    REG_SZ,
                    new_wstr,
                    len );

                logging::info( "Serial spoofed: '%S'\\%S", target.key_path, target.value_name );
            }

            break;
        }


        case target_type_t::delete_value:
        {
            status = ZwDeleteValueKey( hkey, &val_name );

            logging::info( "Value deleted: '%S'\\%S", target.key_path, target.value_name );

            break;
        }


        case target_type_t::zero_binary:
        {
            u8  raw[ sizeof( KEY_VALUE_PARTIAL_INFORMATION ) + 1024 ] = { };
            u32 needed = 0;

            KEY_VALUE_PARTIAL_INFORMATION* kvi =
                reinterpret_cast< KEY_VALUE_PARTIAL_INFORMATION* >( raw );

            status = ZwQueryValueKey(
                hkey,
                &val_name,
                KeyValuePartialInformation,
                kvi,
                sizeof( raw ),
                reinterpret_cast< PULONG >( &needed ) );

            if ( NT_SUCCESS( status ) && kvi->Type == REG_BINARY && kvi->DataLength > 0 )
            {
                RtlZeroMemory( kvi->Data, kvi->DataLength );

                status = ZwSetValueKey(
                    hkey,
                    &val_name,
                    0,
                    REG_BINARY,
                    kvi->Data,
                    kvi->DataLength );

                logging::info( "Binary zeroed: '%S'\\%S", target.key_path, target.value_name );
            }

            break;
        }

        default:
        {
            break;
        }

        }

        ZwClose( hkey );

        return status;
    }


    NTSTATUS run_all( )
    {
        u64 rng = util::rdtsc_seed( );

        u32 success_count = 0;

        for ( u32 i = 0; i < g_target_count; ++i )
        {
            NTSTATUS status = process_target( g_targets[ i ], rng );

            if ( NT_SUCCESS( status ) )
            {
                ++success_count;
            }
        }

        logging::info( "Registry clean complete: %u/%u targets processed", success_count, g_target_count );

        return STATUS_SUCCESS;
    }


    void log_current( )
    {
        for ( u32 i = 0; i < g_target_count; ++i )
        {
            logging::verbose( "target[%u]: %S \\ %S (%u)",
                i,
                g_targets[ i ].key_path,
                g_targets[ i ].value_name,
                (u32)g_targets[ i ].action );
        }
    }

}
