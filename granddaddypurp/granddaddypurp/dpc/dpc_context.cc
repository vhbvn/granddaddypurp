
#include "dpc_context.hh"

namespace dpc_context
{

    struct dpc_wrapper_t
    {
        KDPC            kdpc;
        cpu_work_t*     work;
        u32             cpu_index;
    };


    static void NTAPI dpc_callback(
        PKDPC   kdpc,
        void*   deferred_context,
        void*   system_arg1,
        void*   system_arg2 )
    {
        UNREFERENCED_PARAMETER( kdpc );
        UNREFERENCED_PARAMETER( system_arg1 );
        UNREFERENCED_PARAMETER( system_arg2 );

        dpc_wrapper_t* wrapper = reinterpret_cast< dpc_wrapper_t* >( deferred_context );

        cpu_work_t* work = wrapper->work;

        if ( work && work->routine )
        {
            work->routine( wrapper->cpu_index, work->context );
        }

        if ( InterlockedDecrement( &work->remaining ) == 0 )
        {
            KeSetEvent( &work->completion_event, IO_NO_INCREMENT, FALSE );
        }
    }


    u32 get_cpu_count( )
    {
        return static_cast< u32 >( KeQueryActiveProcessorCountEx( ALL_PROCESSOR_GROUPS ) );
    }


    NTSTATUS run_on_all_cpus( dpc_routine_t routine, void* context )
    {
        u32 cpu_count = get_cpu_count( );

        if ( cpu_count == 0 )
        {
            return STATUS_INVALID_PARAMETER;
        }


        dpc_wrapper_t* wrappers = reinterpret_cast< dpc_wrapper_t* >(
            spoof_alloc_np( sizeof( dpc_wrapper_t ) * cpu_count ) );

        if ( !wrappers )
        {
            return STATUS_INSUFFICIENT_RESOURCES;
        }

        RtlZeroMemory( wrappers, sizeof( dpc_wrapper_t ) * cpu_count );

        cpu_work_t work = { };

        work.routine   = routine;
        work.context   = context;
        work.remaining = static_cast< LONG >( cpu_count );

        KeInitializeEvent( &work.completion_event, NotificationEvent, FALSE );

        for ( u32 i = 0; i < cpu_count; ++i )
        {
            dpc_wrapper_t* w = &wrappers[ i ];

            w->work      = &work;
            w->cpu_index = i;

            KeInitializeDpc( &w->kdpc, dpc_callback, w );

            KeSetTargetProcessorDpcEx( &w->kdpc, reinterpret_cast< PPROCESSOR_NUMBER >(
                &i ) );

            KeInsertQueueDpc( &w->kdpc, nullptr, nullptr );
        }


        LARGE_INTEGER timeout = { };

        timeout.QuadPart = -50000000LL;

        NTSTATUS status = KeWaitForSingleObject(
            &work.completion_event,
            Executive,
            KernelMode,
            FALSE,
            &timeout );

        spoof_free( wrappers );

        if ( status == STATUS_TIMEOUT )
        {
            logging::warn( "DPC all-CPU wait timed out" );
        }

        return status;
    }


    NTSTATUS run_on_cpu( u32 cpu_index, dpc_routine_t routine, void* context )
    {
        dpc_wrapper_t* wrapper = reinterpret_cast< dpc_wrapper_t* >(
            spoof_alloc_np( sizeof( dpc_wrapper_t ) ) );

        if ( !wrapper )
        {
            return STATUS_INSUFFICIENT_RESOURCES;
        }

        RtlZeroMemory( wrapper, sizeof( dpc_wrapper_t ) );

        cpu_work_t* work = reinterpret_cast< cpu_work_t* >(
            spoof_alloc_np( sizeof( cpu_work_t ) ) );

        if ( !work )
        {
            spoof_free( wrapper );

            return STATUS_INSUFFICIENT_RESOURCES;
        }

        RtlZeroMemory( work, sizeof( cpu_work_t ) );

        work->routine   = routine;
        work->context   = context;
        work->remaining = 1;

        KeInitializeEvent( &work->completion_event, NotificationEvent, FALSE );

        wrapper->work      = work;
        wrapper->cpu_index = cpu_index;

        KeInitializeDpc( &wrapper->kdpc, dpc_callback, wrapper );

        PROCESSOR_NUMBER proc_num = { };
        proc_num.Number = static_cast< u8 >( cpu_index );

        KeSetTargetProcessorDpcEx( &wrapper->kdpc, &proc_num );

        KeInsertQueueDpc( &wrapper->kdpc, nullptr, nullptr );

        LARGE_INTEGER timeout = { };

        timeout.QuadPart = -20000000LL;

        NTSTATUS status = KeWaitForSingleObject(
            &work->completion_event,
            Executive,
            KernelMode,
            FALSE,
            &timeout );

        spoof_free( work );
        spoof_free( wrapper );

        return status;
    }

}
