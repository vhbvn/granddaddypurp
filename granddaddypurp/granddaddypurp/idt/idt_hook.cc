
#include "idt_hook.hh"

namespace idt_hook
{

    saved_entry_t   g_idt_hooks[ k_max_idt_hooks ] = { };
    u32             g_idt_hook_count                = 0;


    void read_idtr( idtr_t& out )
    {
        __sidt( &out );
    }


    void write_idtr( const idtr_t& idtr )
    {
        __lidt( const_cast< void* >( static_cast< const void* >( &idtr ) ) );
    }


    void encode_entry(
        idt_entry_t&    entry,
        void*           handler,
        u16             segment,
        u8              dpl,
        u8              ist )
    {
        u64 addr = reinterpret_cast< u64 >( handler );

        entry.offset_low    = static_cast< u16 >( addr & 0xFFFF );
        entry.offset_mid    = static_cast< u16 >( ( addr >> 16 ) & 0xFFFF );
        entry.offset_high   = static_cast< u32 >( ( addr >> 32 ) & 0xFFFFFFFF );
        entry.segment       = segment;
        entry.ist           = ist & 0x7;
        entry.reserved      = 0;
        entry.type          = 0xE;
        entry.zero          = 0;
        entry.dpl           = dpl & 0x3;
        entry.present       = 1;
        entry.reserved2     = 0;
    }


    NTSTATUS hook_vector( u8 vector, void* new_handler )
    {
        if ( g_idt_hook_count >= k_max_idt_hooks )
        {
            return STATUS_INSUFFICIENT_RESOURCES;
        }

        idtr_t idtr = { };

        read_idtr( idtr );

        idt_entry_t* idt_table =
            reinterpret_cast< idt_entry_t* >( idtr.base );

        idt_entry_t* entry = &idt_table[ vector ];


        saved_entry_t* saved = &g_idt_hooks[ g_idt_hook_count ];

        saved->vector   = vector;
        saved->original = *entry;
        saved->hooked   = true;


        idt_entry_t new_entry = { };

        encode_entry(
            new_entry,
            new_handler,
            entry->segment,
            entry->dpl,
            entry->ist );


        ia32::disable_write_protect( );

        *entry = new_entry;

        ia32::enable_write_protect( );

        ++g_idt_hook_count;

        logging::info( "IDT hook: vector 0x%02X -> 0x%llX", vector, (u64)new_handler );

        return STATUS_SUCCESS;
    }


    NTSTATUS unhook_vector( u8 vector )
    {
        idtr_t idtr = { };

        read_idtr( idtr );

        idt_entry_t* idt_table =
            reinterpret_cast< idt_entry_t* >( idtr.base );

        for ( u32 i = 0; i < g_idt_hook_count; ++i )
        {
            saved_entry_t* saved = &g_idt_hooks[ i ];

            if ( saved->vector != vector || !saved->hooked )
            {
                continue;
            }

            ia32::disable_write_protect( );

            idt_table[ vector ] = saved->original;

            ia32::enable_write_protect( );

            saved->hooked = false;

            logging::info( "IDT unhook: vector 0x%02X", vector );

            return STATUS_SUCCESS;
        }

        return STATUS_NOT_FOUND;
    }


    void unhook_all( )
    {
        for ( u32 i = 0; i < g_idt_hook_count; ++i )
        {
            if ( g_idt_hooks[ i ].hooked )
            {
                unhook_vector( g_idt_hooks[ i ].vector );
            }
        }

        g_idt_hook_count = 0;
    }

}
