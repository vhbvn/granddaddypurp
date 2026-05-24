#pragma once


#include "../includes/globals.hh"
#include "../includes/logging.hh"

namespace dpc_context
{

    using dpc_routine_t = void ( * )( u32 cpu_index, void* context );

    struct cpu_work_t
    {
        dpc_routine_t   routine;
        void*           context;
        KEVENT          completion_event;
        LONG            remaining;
    };


    NTSTATUS    run_on_all_cpus( dpc_routine_t routine, void* context );
    NTSTATUS    run_on_cpu( u32 cpu_index, dpc_routine_t routine, void* context );

    u32         get_cpu_count( );

}
