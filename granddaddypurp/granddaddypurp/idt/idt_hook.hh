#pragma once


#include "../includes/globals.hh"
#include "../includes/logging.hh"
#include "../ia32/ia32.hh"

namespace idt_hook
{

    #pragma pack( push, 1 )

    struct idt_entry_t
    {
        u16 offset_low;     // [15:0]  of handler
        u16 segment;        // code segment selector
        u8  ist      : 3;   // interrupt stack table index
        u8  reserved : 5;
        u8  type     : 4;   // gate type: 0xE = 64-bit interrupt gate
        u8  zero     : 1;
        u8  dpl      : 2;   // descriptor privilege level
        u8  present  : 1;
        u16 offset_mid;     // [31:16] of handler
        u32 offset_high;    // [63:32] of handler
        u32 reserved2;
    };

    struct idtr_t
    {
        u16 limit;
        u64 base;
    };

    #pragma pack( pop )


    struct saved_entry_t
    {
        u8           vector;
        idt_entry_t  original;
        bool         hooked;
    };

    constexpr u32 k_max_idt_hooks = 8;

    extern saved_entry_t g_idt_hooks[ k_max_idt_hooks ];
    extern u32           g_idt_hook_count;


    void    read_idtr( idtr_t& out );
    void    write_idtr( const idtr_t& idtr );

    void    encode_entry(
        idt_entry_t&    entry,
        void*           handler,
        u16             segment,
        u8              dpl,
        u8              ist );

    NTSTATUS hook_vector( u8 vector, void* new_handler );
    NTSTATUS unhook_vector( u8 vector );
    void     unhook_all( );


    extern "C"
    {
        void __cdecl idt_stub_cpuid_intercept( );
        void __cdecl idt_stub_rdmsr_intercept( );
    }

}
