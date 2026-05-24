#pragma once


#include <ntddk.h>
#include "globals.hh"

namespace logging
{
    enum class level : u32
    {
        verbose = 0,
        info    = 1,
        warning = 2,
        error   = 3,
        none    = 4,
    };


    static constexpr level k_min_level = level::verbose;


    template < typename... Args >
    SPOOF_INLINE void print( level lvl, const char* fmt, Args&&... args )
    {
        if ( lvl < k_min_level )
        {
            return;
        }

        const char* prefix = "[?]";

        switch ( lvl )
        {
        case level::verbose: prefix = "[V]"; break;
        case level::info:    prefix = "[+]"; break;
        case level::warning: prefix = "[!]"; break;
        case level::error:   prefix = "[-]"; break;
        default:             break;
        }

        char buf[ 512 ] = { };

        RtlStringCchPrintfA( buf, sizeof( buf ), fmt, args... );

        DbgPrint( "[gdp spoofer] %s %s\n", prefix, buf );
    }


    template < typename... Args >
    SPOOF_INLINE void verbose( const char* fmt, Args&&... args )
    {
        print( level::verbose, fmt, args... );
    }

    template < typename... Args >
    SPOOF_INLINE void info( const char* fmt, Args&&... args )
    {
        print( level::info, fmt, args... );
    }

    template < typename... Args >
    SPOOF_INLINE void warn( const char* fmt, Args&&... args )
    {
        print( level::warning, fmt, args... );
    }

    template < typename... Args >
    SPOOF_INLINE void error( const char* fmt, Args&&... args )
    {
        print( level::error, fmt, args... );
    }

}
