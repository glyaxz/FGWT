# Forensics Getter Windows Toolkit

FGWT is a command-line toolkit for Windows that allows you to collect digital evidence from a running system.


## Features
    - Memory Dump
    - Registry
    - Network
    - Process
    - System Information
    - ETLs

## Usage
You need to run the `fgwt.bat` command with the following options:
```powershell
fgwt.bat [x64/x86]
```

When you run the `fgwt.bat` command, it will ask you to choose the architecture of the system you want to collect evidence from.

At the end of the process, the toolkit will create a folder `evidences` with the evidence collected. Also, it will create a `logs` folder with the logs of the subprocesses created by the toolkit instance.

***
_Created by Javier 'Glyaxz' García_