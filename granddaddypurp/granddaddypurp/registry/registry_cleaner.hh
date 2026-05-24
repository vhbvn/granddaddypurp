#pragma once


#include "../includes/globals.hh"
#include "../includes/logging.hh"

namespace registry_cleaner
{

    enum class target_type_t : u8
    {
        spoof_guid,
        spoof_serial,
        delete_value,
        zero_binary,
        spoof_machine_id
    };

    struct reg_target_t
    {
        const wchar_t*  key_path;
        const wchar_t*  value_name;
        target_type_t   action;
    };


    extern const reg_target_t g_targets[];
    extern const u32          g_target_count;


    NTSTATUS    run_all( );
    NTSTATUS    process_target( const reg_target_t& target, u64& rng );
    void        log_current( );


    namespace guid_gen
    {
        void generate(
            u64&    rng,
            wchar_t out[ 39 ] );

    }

}
