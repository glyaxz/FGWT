@echo off
>nul 2>&1 net session
if %errorlevel% NEQ 0 (
    echo.
    echo    [-] You must run this script as an administrator.
    exit /b 1
) else (
    del /s /q /f evidences
    del /s /q /f logs
    rmdir /s /q evidences\hives
    rmdir /s /q evidences\ETLs
    rmdir /s /q evidences\memdump
    rmdir /s /q logs
    mkdir evidences
    mkdir logs
    cls

    echo.
    echo    ______ _______          _________ 
    echo   ^|  ____/ ____\ \        / /__   __^|
    echo   ^| ^|__ ^| ^|  __ \ \  /\  / /   ^| ^|   
    echo   ^|  __^|^| ^| ^|_ ^| \ \/  \/ /    ^| ^|   
    echo   ^| ^|   ^| ^|__^| ^|  \  /\  /     ^| ^|   
    echo   ^|_^|    \_____^|   \/  \/      ^|_^|   
    echo.
    echo.
    echo      by Javier 'Glyaxz' Garcia
    echo      -------------------------
    echo      https://github.com/glyaxz
    echo.
    echo.

    
    rem Verificar si se pasaron parámetros
    if "%~1"=="" (
        echo    [!] Please specify the architecture
        echo    [!] Usage: fgwt.bat [x64/x86]
        exit /b 1
    )

    if "%1" equ "x64" (
        cd tools\x64
        echo    [+] Arquitecture selected: 
        echo        [-] "%1"

        :: System Information
        echo.
        echo    [+] System Information
        echo        [-] User: %USERNAME%
        echo        [-] Domain: %USERDOMAIN%
        echo        [-] Hostname: %COMPUTERNAME%
        echo        [-] OS: %OS%
        echo        [-] OS Architecture: %PROCESSOR_ARCHITECTURE%
        echo        [-] OS Domain: %USERDOMAIN%
        
        systeminfo /fo csv > ..\..\evidences\sysinfo.csv
        echo.
        echo        [-] Saved system information to: evidences/sysinfo.csv
        echo.

        :: Memory Dump
        echo    [+] Dumping RAM...

        mkdir ..\..\evidences\memdump
        winpmem64.exe ..\..\evidences\memdump\memdump.raw > ..\..\logs\memdump.log

        echo        [-] Saved memory dump to: evidences/memdump.raw
        echo        [-] Saved memory dump logs to: logs/memdump.log
        echo.

        :: Registry Hives
        echo    [+] Saving registry config hives...

        mkdir ..\..\evidences\hives
        cd ..\..\evidences\hives

        reg save HKLM\SYSTEM system.hive > ../../logs/system.hive.log
        reg save HKLM\SOFTWARE software.hive > ../../logs/software.hive.log
        reg save HKLM\SAM sam.hive > ../../logs/sam.hive.log
        reg save HKLM\SECURITY security.hive > ../../logs/security.hive.log

        echo        [-] Saved registry config hives to: evidences/hives
        echo.

        cd ..\..\tools\global

        :: ETL Traces
        echo    [+] Saving ETL traces...
        mkdir ..\..\evidences\ETLs

        ETLParser.exe -c ips -s C:\Windows\ServiceProfiles\NetworkService\AppData\Local\Microsoft\Windows\DeliveryOptimization\Logs\ -o ..\..\evidences\ETLs > ../../logs/etlparser.log

        echo        [-] Saved ETL logs to: logs/etlparser.log
        echo        [-] Saved ETL evidences to: evidences/ETLs
        echo.

        :: Processes
        echo    [+] Saving all process tree...
        tasklist /v > ..\..\evidences\tasklist.txt

        echo        [-] Saved all process list to: evidences/tasklist.txt
        echo.
        :: Network Connections
        echo    [+] Saving all connections list...
        netstat -ano > ..\..\evidences\netstat.txt

        echo        [-] Saved all connections list to: evidences/netstat.txt
        echo.

        ::Finish
        echo    [+] Done, you can find the evidences in the evidences folder. 
        echo.
        echo    [$] Enjoy! [$]
        echo.
        cd ../../
        exit /b 0

    ) else if "%1" equ "x86" (
        cd tools\x86
        echo    [+] Arquitecture selected: 
        echo        [-] "%1"

        :: System Information
        echo.
        echo    [+] System Information
        echo        [-] User: %USERNAME%
        echo        [-] Domain: %USERDOMAIN%
        echo        [-] Hostname: %COMPUTERNAME%
        echo        [-] OS: %OS%
        echo        [-] OS Architecture: %PROCESSOR_ARCHITECTURE%
        echo        [-] OS Domain: %USERDOMAIN%
        
        systeminfo /fo csv > ..\..\evidences\sysinfo.csv

        echo    [+] Saved system information to: evidences/sysinfo.txt
        echo.

        :: Memory Dump
        echo    [+] Dumping RAM...
        mkdir ..\..\evidences\memdump
        winpmem.exe ..\..\evidences\memdump\memdump.raw > ..\..\logs\memdump.log

        echo        [-] Saved memory dump to: evidences/memdump.raw
        echo        [-] Saved memory dump logs to: logs/memdump.log
        echo.

        :: Registry Hives
        echo    [+] Saving registry config hives...

        mkdir ..\..\evidences\hives
        cd ..\..\evidences\hives

        reg save HKLM\SYSTEM system.hive > ../../logs/system.hive.log
        reg save HKLM\SOFTWARE software.hive > ../../logs/software.hive.log
        reg save HKLM\SAM sam.hive > ../../logs/sam.hive.log
        reg save HKLM\SECURITY security.hive > ../../logs/security.hive.log

        echo        [-] Saved registry config hives to: evidences/hives
        echo.

        cd ..\..\tools\global

        :: ETL Traces
        echo    [+] Saving ETL traces...
        mkdir ..\..\evidences\ETLs
        ETLParser.exe -c ips -s C:\Windows\ServiceProfiles\NetworkService\AppData\Local\Microsoft\Windows\DeliveryOptimization\Logs\ -o ..\..\evidences\ETLs > ../../logs/etlparser.log
        echo.
        echo        [-] Saved ETL logs to: logs/etlparser.log
        echo        [-] Saved ETL evidences to: evidences/ETLs
        echo.
        echo    [+] Done, you can find the evidences in the evidences folder. 

    
        :: Processes
        echo    [+] Saving all process tree...
        tasklist /v > ..\..\evidences\tasklist.txt

        echo        [-] Saved all process list to: evidences/tasklist.txt
        echo.
        :: Network Connections
        echo    [+] Saving all connections list...
        netstat -ano > ..\..\evidences\netstat.txt

        echo        [-] Saved all connections list to: evidences/netstat.txt
        echo.

        ::Finish
        echo.
        echo    [$] Enjoy! [$]
        echo.
        cd ../../
        exit /b 0

    ) else (
        echo    [!] Invalid architecture
        echo    [!] Usage: fgwt.bat [x64/x86]
        exit /b 1
    )
)
