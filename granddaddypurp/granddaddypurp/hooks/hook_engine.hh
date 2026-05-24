#pragma once


#include "../includes/globals.hh"
#include "../includes/logging.hh"
#include "../ia32/ia32.hh"

namespace hook_engine
{

    constexpr u32 k_trampoline_size     = 32;
    constexpr u32 k_abs_jmp_size        = 14;
    constexpr u32 k_rel_jmp_size        = 5;
    constexpr u32 k_max_hooks           = 128;


    struct hook_t
    {
        void*   target;                          // original function address
        void*   detour;                          // replacement function address
        void*   trampoline;                      // allocated trampoline buffer
        u8      original_bytes[ k_abs_jmp_size ]; // saved original prologue
        u32     hook_size;                       // bytes overwritten
        bool    installed;
    };


    extern hook_t g_hook_table[ k_max_hooks ];
    extern u32    g_hook_count;


    NTSTATUS install_hook(
        void*   target,
        void*   detour,
        void**  out_trampoline );

    NTSTATUS remove_hook( void* target );
    void     remove_all_hooks( );


    namespace trampoline
    {
        NTSTATUS  init( );
        void      destroy( );
        void*     allocate( );
        void      free( void* ptr );
    }

}
