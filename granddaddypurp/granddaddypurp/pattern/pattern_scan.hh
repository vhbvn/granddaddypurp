#pragma once


#include "../includes/globals.hh"
#include "../includes/logging.hh"

namespace pattern_scan
{

    constexpr u32 k_max_pattern_len = 128;
    constexpr u8  k_wildcard        = 0xCC;


    struct pattern_t
    {
        u8   bytes[ k_max_pattern_len ];
        bool mask[ k_max_pattern_len ];  // true = match, false = wildcard
        u32  length;
    };


    struct section_t
    {
        const char* name;
        u64         base;
        u32         size;
    };


    bool    compile_pattern( const char* pattern_str, pattern_t& out );

    u64     scan(
        u64             base,
        u32             size,
        const pattern_t& pat );

    u64     scan_str(
        u64             base,
        u32             size,
        const char*     pattern_str );


    u64     get_module_base( const wchar_t* module_name );
    u32     get_module_size( u64 module_base );

    u64     scan_module(
        const wchar_t*  module_name,
        const char*     pattern_str );


    SPOOF_INLINE u64 resolve_rip_relative( u64 instr_addr, u32 instr_len )
    {

        i32 rel = *reinterpret_cast< i32* >( instr_addr + instr_len - 4 );

        return instr_addr + instr_len + rel;
    }

}
