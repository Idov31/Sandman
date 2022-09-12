/*
   YARA Rule Set
   Author: Ido Veltzman
   Date: 2022-09-12
   Reference: https://github.com/Idov31/Sandman
*/

/* Rule Set ----------------------------------------------------------------- */

rule Sandman {
   meta:
      description = "Sandman - NTP Backdoor"
      author = "Ido Veltzman"
      reference = "https://github.com/Idov31/Sandman"
      date = "2022-09-12"
      
   strings:
      $shellcode = { 48 83 ec 38 68 64 6c 6c 00 48 b8 77 69 6e 69 6e 65 74 2e 50 48 8b cc 48 83 ec 20 48 b8 ?? ?? ?? ?? ?? ?? ?? ?? ff d0 48 83 c4 30 68 74 73 65 74 6a 00 48 8b cc 33 d2 45 33 c0 45 33 c9 48 c7 44 24 20 00 00 00 00 48 b8 ?? ?? ?? ?? ?? ?? ?? ?? ff d0 48 89 44 24 30 48 c7 44 24 20 00 00 00 00 48 c7 44 24 28 00 44 00 80 45 33 c9 45 33 c0 48 ba ?? ?? ?? ?? ?? ?? ?? ?? 48 8b 4c 24 30 48 b8 ?? ?? ?? ?? ?? ?? ?? ?? ff d0 48 89 44 24 28 41 b9 40 00 00 00 41 b8 00 30 00 00 ba ?? ?? ?? ?? 33 c9 48 b8 ?? ?? ?? ?? ?? ?? ?? ?? ff d0 48 89 44 24 20 4c 8b cc 41 b8 ?? ?? ?? ?? 48 8b 54 24 20 48 8b 4c 24 28 48 b8 ?? ?? ?? ?? ?? ?? ?? ?? ff d0 48 8b 4c 24 28 48 b8 ?? ?? ?? ?? ?? ?? ?? ?? ff d0 48 8b 4c 24 30 48 b8 ?? ?? ?? ?? ?? ?? ?? ?? ff d0 48 8b 44 24 20 ff d0 48 83 c4 38 c3 }
      $s1 = "InjectShellcode" fullword ascii
      $s2 = "Sandman.exe" fullword wide
      $s3 = "shellcode" fullword ascii
      $s4 = "rawShellcode" fullword ascii
      $s5 = "PatchShellcode" fullword ascii
      $s6 = "Failed to write to process memory" fullword wide
      $s7 = "payloadUrlAddress" fullword ascii
      $s8 = "payloadUrl" fullword ascii
      $s9 = "ntpPort" fullword ascii
      $s10 = "ntpData" fullword ascii
      $s11 = "INTERNETREADFILE_OFFSET" fullword ascii
      $s12 = "time.windows.com" fullword ascii
      $s13 = "ntpServerAddress" fullword ascii
      $s14 = "Wininet.dll" fullword ascii
      $s15 = "INTERNETOPENA_OFFSET" fullword ascii
      $s16 = "INTERNETOPENURLA_OFFSET" fullword ascii
      $s17 = "VIRTUALALLOC_OFFSET" fullword ascii
      $s18 = "LOADLIBRARYA_OFFSET" fullword ascii
      $s19 = "INTERNETCLOSEHANDLE_OFFSET" ascii
      $s20 = "URL_OFFSET" fullword ascii

   condition:
      uint16(0) == 0x5a4d and filesize < 30KB and
      10 of ($s*) and $shellcode
}