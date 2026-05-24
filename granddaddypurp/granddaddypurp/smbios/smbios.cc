
#include "smbios.hh"
#include "../includes/globals.hh"
#include "../includes/logging.hh"

namespace smbios
{

    static constexpr u32 k_rsmb_provider = 'RSMB';


    NTSTATUS locate_table( void** out_base, u32* out_length )
    {
        if ( !out_base || !out_length )
        {
            return STATUS_INVALID_PARAMETER;
        }


        u32 needed = 0;

        GDP_SYSTEM_FIRMWARE_TABLE_INFORMATION sfti = { };
        sfti.ProviderSignature  = k_rsmb_provider;
        sfti.Action             = GDP_SystemFirmwareTable_Get;
        sfti.TableID            = 0;
        sfti.TableBufferLength  = 0;

        NTSTATUS status = ZwQuerySystemInformation(
            GDP_SystemFirmwareTableInformation,
            &sfti,
            sizeof( sfti ),
            reinterpret_cast< PULONG >( &needed ) );

        if ( status != STATUS_BUFFER_TOO_SMALL )
        {
            logging::error( "SMBIOS ZwQuerySystemInformation probe failed: 0x%08X", status );

            return status;
        }

        u32 alloc_size = needed;

        GDP_SYSTEM_FIRMWARE_TABLE_INFORMATION* p_sfti =
            reinterpret_cast< GDP_SYSTEM_FIRMWARE_TABLE_INFORMATION* >(
                spoof_alloc_paged( alloc_size ) );

        if ( !p_sfti )
        {
            return STATUS_INSUFFICIENT_RESOURCES;
        }

        RtlZeroMemory( p_sfti, alloc_size );

        p_sfti->ProviderSignature  = k_rsmb_provider;
        p_sfti->Action             = GDP_SystemFirmwareTable_Get;
        p_sfti->TableID            = 0;
        p_sfti->TableBufferLength  = alloc_size - sizeof( GDP_SYSTEM_FIRMWARE_TABLE_INFORMATION );

        status = ZwQuerySystemInformation(
            GDP_SystemFirmwareTableInformation,
            p_sfti,
            alloc_size,
            nullptr );

        if ( !NT_SUCCESS( status ) )
        {
            logging::error( "SMBIOS ZwQuerySystemInformation failed: 0x%08X", status );

            spoof_free( p_sfti );

            return status;
        }

        *out_base   = p_sfti->TableBuffer;
        *out_length = p_sfti->TableBufferLength;

        logging::info( "SMBIOS table at 0x%llX (%u bytes)", (u64)(*out_base), *out_length );

        return STATUS_SUCCESS;
    }


    const char* get_string( const header_t* hdr, u8 index )
    {
        if ( !hdr || index == 0 )
        {
            return nullptr;
        }

        const char* str = reinterpret_cast< const char* >( hdr ) + hdr->length;

        for ( u8 i = 1; i < index; ++i )
        {
            if ( *str == '\0' )
            {
                return nullptr;
            }

            str += strlen( str ) + 1;
        }

        return str;
    }


    bool patch_string( header_t* hdr, u8 index, const char* replacement )
    {
        if ( !hdr || index == 0 || !replacement )
        {
            return false;
        }

        char* str = reinterpret_cast< char* >( hdr ) + hdr->length;

        for ( u8 i = 1; i < index; ++i )
        {
            if ( *str == '\0' )
            {
                return false;
            }

            str += strlen( str ) + 1;
        }

        SIZE_T old_len = strlen( str );
        SIZE_T new_len = strlen( replacement );

        if ( new_len > old_len )
        {
            new_len = old_len;
        }

        RtlCopyMemory( str, replacement, new_len );

        if ( new_len < old_len )
        {
            RtlFillMemory( str + new_len, old_len - new_len, ' ' );
        }

        return true;
    }


    NTSTATUS spoof_all( spoof_result_t* out_result )
    {
        void* table_base    = nullptr;
        u32   table_length  = 0;

        NTSTATUS status = locate_table( &table_base, &table_length );

        if ( !NT_SUCCESS( status ) )
        {
            return status;
        }

        u64  rng = util::rdtsc_seed( );

        spoof_result_t result = { };

        u8* ptr = reinterpret_cast< u8* >( table_base );
        u8* end = ptr + table_length;

        while ( ptr < end )
        {
            header_t* hdr = reinterpret_cast< header_t* >( ptr );

            if ( hdr->length < sizeof( header_t ) )
            {
                break;
            }

            switch ( hdr->type )
            {

            case 0:
            {
                type0_t* t0 = reinterpret_cast< type0_t* >( hdr );

                const char* ver_str = get_string( hdr, t0->bios_version );

                if ( ver_str )
                {
                    char mut[ k_max_serial_len ] = { };

                    RtlStringCchCopyA( mut, sizeof( mut ), ver_str );

                    util::mutate_serial_digit( mut, strlen( mut ), rng );

                    patch_string( hdr, t0->bios_version, mut );

                    logging::info( "BIOS version: '%s' -> '%s'", ver_str, mut );
                }

                result.bios_spoofed = true;

                break;
            }


            case 1:
            {
                type1_t* t1 = reinterpret_cast< type1_t* >( hdr );

                const char* serial = get_string( hdr, t1->serial_number );

                if ( serial )
                {
                    char mut[ k_max_serial_len ] = { };

                    RtlStringCchCopyA( mut, sizeof( mut ), serial );

                    util::mutate_serial_digit( mut, strlen( mut ), rng );

                    patch_string( hdr, t1->serial_number, mut );

                    logging::info( "System serial: '%s' -> '%s'", serial, mut );
                }


                for ( int i = 0; i < 8; ++i )
                {
                    t1->uuid[ i ] = static_cast< u8 >( util::lcg_rand( rng ) & 0xFF );
                }

                result.system_spoofed = true;

                break;
            }


            case 2:
            {
                type2_t* t2 = reinterpret_cast< type2_t* >( hdr );

                const char* serial = get_string( hdr, t2->serial_number );

                if ( serial )
                {
                    char mut[ k_max_serial_len ] = { };

                    RtlStringCchCopyA( mut, sizeof( mut ), serial );

                    util::mutate_serial_digit( mut, strlen( mut ), rng );

                    patch_string( hdr, t2->serial_number, mut );

                    logging::info( "Baseboard serial: '%s' -> '%s'", serial, mut );
                }

                result.baseboard_spoofed = true;

                break;
            }


            case 17:
            {
                type17_t* t17 = reinterpret_cast< type17_t* >( hdr );

                const char* serial = get_string( hdr, t17->serial_number );

                if ( serial )
                {
                    char mut[ k_max_serial_len ] = { };

                    RtlStringCchCopyA( mut, sizeof( mut ), serial );

                    util::mutate_serial_digit( mut, strlen( mut ), rng );

                    patch_string( hdr, t17->serial_number, mut );

                    logging::info( "Memory serial: '%s' -> '%s'", serial, mut );
                }

                result.memory_spoofed = true;

                break;
            }

            default:
            {
                break;
            }

            }


            ptr = reinterpret_cast< u8* >( hdr ) + hdr->length;

            while ( ptr + 1 < end && !( ptr[ 0 ] == 0 && ptr[ 1 ] == 0 ) )
            {
                ++ptr;
            }

            ptr += 2;
        }

        if ( out_result )
        {
            *out_result = result;
        }

        return STATUS_SUCCESS;
    }


    void log_table( )
    {
        void* table_base    = nullptr;
        u32   table_length  = 0;

        if ( !NT_SUCCESS( locate_table( &table_base, &table_length ) ) )
        {
            return;
        }

        u8* ptr = reinterpret_cast< u8* >( table_base );
        u8* end = ptr + table_length;

        while ( ptr < end )
        {
            header_t* hdr = reinterpret_cast< header_t* >( ptr );

            if ( hdr->length < sizeof( header_t ) )
            {
                break;
            }

            logging::verbose( "SMBIOS type=%u handle=0x%04X len=%u",
                hdr->type, hdr->handle, hdr->length );

            ptr = reinterpret_cast< u8* >( hdr ) + hdr->length;

            while ( ptr + 1 < end && !( ptr[ 0 ] == 0 && ptr[ 1 ] == 0 ) )
            {
                ++ptr;
            }

            ptr += 2;
        }
    }

}
