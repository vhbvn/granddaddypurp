
#include "includes/globals.hh"
#include "includes/logging.hh"

#include "ia32/ia32.hh"

#include "hooks/hook_engine.hh"
#include "idt/idt_hook.hh"
#include "exceptions/exception_handler.hh"
#include "pattern/pattern_scan.hh"
#include "dpc/dpc_context.hh"

#include "smbios/smbios.hh"
#include "ahci/ahci_rdi.hh"
#include "disk/disk.hh"
#include "usb/usb.hh"
#include "tpm/tpm.hh"
#include "network/network.hh"
#include "gpu/gpu.hh"
#include "monitor/monitor.hh"
#include "registry/registry_cleaner.hh"


extern "C"
{
    DRIVER_UNLOAD   DriverUnload;
    DRIVER_INITIALIZE DriverEntry;

    NTSTATUS DriverEntry(
        _In_    PDRIVER_OBJECT  driver_object,
        _In_    PUNICODE_STRING registry_path );

    void DriverUnload( _In_ PDRIVER_OBJECT driver_object );
}


static PDRIVER_OBJECT g_driver_object = nullptr;


static void dpc_smoke_test_cb( u32 cpu_idx, void* ctx )
{
    UNREFERENCED_PARAMETER( ctx );

    logging::verbose( "DPC running on CPU %u (IRQL=%u)", cpu_idx, KeGetCurrentIrql( ) );
}


void DriverUnload( _In_ PDRIVER_OBJECT driver_object )
{
    UNREFERENCED_PARAMETER( driver_object );

    logging::info( "=== gdp spoofer unloading ===" );


    monitor::restore_all( );
    gpu::restore_all( );
    network::restore_all( );
    disk::restore_all( );
    ahci_rdi::restore_all( );
    usb::restore_all( );
    tpm::restore( );


    hook_engine::remove_all_hooks( );
    idt_hook::unhook_all( );
    exception_handler::remove_veh( );


    hook_engine::trampoline::destroy( );

    logging::info( "gdp spoofer unloaded cleanly" );
}


extern "C"
NTSTATUS DriverEntry(
    _In_    PDRIVER_OBJECT  driver_object,
    _In_    PUNICODE_STRING registry_path )
{
    UNREFERENCED_PARAMETER( registry_path );

    g_driver_object = driver_object;

    driver_object->DriverUnload = DriverUnload;

    logging::info( "driver object: 0x%llX", (u64)driver_object );

    NTSTATUS status = STATUS_SUCCESS;


    status = exception_handler::install_veh( );

    if ( !NT_SUCCESS( status ) )
    {
        logging::warn( "VEH install failed (non-fatal): 0x%08X", status );
    }


    status = hook_engine::trampoline::init( );

    if ( !NT_SUCCESS( status ) )
    {
        logging::error( "Trampoline pool init failed: 0x%08X", status );

        exception_handler::remove_veh( );

        return status;
    }


    {
        u32 cpu_count = dpc_context::get_cpu_count( );

        logging::info( "System has %u logical processors", cpu_count );

        dpc_context::run_on_cpu( 0, dpc_smoke_test_cb, nullptr );
    }


    {
        smbios::spoof_result_t smb_result = { };

        status = smbios::spoof_all( &smb_result );

        if ( NT_SUCCESS( status ) )
        {
            logging::info( "SMBIOS: bios=%d sys=%d board=%d mem=%d",
                smb_result.bios_spoofed,
                smb_result.system_spoofed,
                smb_result.baseboard_spoofed,
                smb_result.memory_spoofed );
        }
        else
        {
            logging::warn( "SMBIOS spoof partial/failed: 0x%08X", status );
        }
    }


    {
        status = ahci_rdi::spoof_all( );

        logging::info( "AHCI spoof: %s (0x%08X)",
            NT_SUCCESS( status ) ? "OK" : "WARN", status );
    }


    {
        status = disk::spoof_all( );

        logging::info( "Disk spoof: %s (%u disks)",
            NT_SUCCESS( status ) ? "OK" : "WARN",
            disk::g_disk_count );
    }


    {
        status = usb::spoof_all( );

        logging::info( "USB spoof: %s (%u devices)",
            NT_SUCCESS( status ) ? "OK" : "WARN",
            usb::g_usb_count );
    }


    {
        status = tpm::spoof_all( );

        logging::info( "TPM spoof: %s (0x%08X)",
            NT_SUCCESS( status ) ? "OK" : "WARN", status );
    }


    {
        status = network::spoof_all( );

        logging::info( "Network spoof: %s (%u adapters)",
            NT_SUCCESS( status ) ? "OK" : "WARN",
            network::g_adapter_count );

        network::arp::flush_table( );
    }


    {
        status = gpu::spoof_all( );

        logging::info( "GPU spoof: %s (%u GPUs)",
            NT_SUCCESS( status ) ? "OK" : "WARN",
            gpu::g_gpu_count );
    }


    {
        status = monitor::spoof_all( );

        logging::info( "Monitor spoof: %s (%u monitors)",
            NT_SUCCESS( status ) ? "OK" : "WARN",
            monitor::g_monitor_count );
    }


    {
        status = registry_cleaner::run_all( );

        logging::info( "Registry clean: %s (0x%08X)",
            NT_SUCCESS( status ) ? "OK" : "WARN", status );
    }


    logging::info( "success" );

    return STATUS_SUCCESS;
}
