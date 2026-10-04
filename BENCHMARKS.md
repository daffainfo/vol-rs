# Runtime against volatility3

Same plugin, same image, same machine, byte-identical output, wall clock. Both sides measured in one pass with warm caches, nothing else running.

Measured on one machine with one set of captures, so the figures will differ on other hardware, other images and a different amount of free memory.

## Machine

| | |
|---|---|
| CPU | 4 vCPU, 2.49 GHz, sse4_2, aes, avx2 |
| RAM | 7.8 GiB |
| Disk | 160 GB virtio |
| OS | Ubuntu 24.04.4, Linux 6.8.0-137-generic |
| Python | 3.12.3, volatility3 2.28.0, capstone 5.0.6 |
| Rust | 1.98.0, release profile |

## Images

All three come from the Volatility Foundation's own test data, release v0.0.1.

| Image | Size | Format | System |
|---|---:|---|---|
| `win-10_19041-2025_03.dmp` | 2.0 GB | Windows crash dump | Windows 10, build 19041, 120 processes |
| `win-xp-laptop-2005-06-25.img` | 512 MB | raw | Windows XP, 47 processes |
| `linux-sample-1.bin` | 512 MB | raw | Linux 3.2, 133 tasks |

## Windows 10 19041, 2.0 GB crash dump

| Plugin | Rust | Python | Faster |
|---|---:|---:|---:|
| `windows.malware.suspicious_threads.SuspiciousThreads` | 0.574 s | 346 s | x603 |
| `windows.suspicious_threads.SuspiciousThreads` | 0.725 s | 343 s | x473 |
| `windows.malware.malfind.Malfind` | 0.687 s | 313 s | x456 |
| `windows.malware.hollowprocesses.HollowProcesses` | 0.555 s | 240 s | x432 |
| `windows.malfind.Malfind` | 0.792 s | 320 s | x404 |
| `windows.hollowprocesses.HollowProcesses` | 0.615 s | 244 s | x396 |
| `windows.vadinfo.VadInfo` | 1.11 s | 412 s | x371 |
| `yarascan.YaraScan` | 0.035 s | 11.7 s | x336 |
| `configwriter.ConfigWriter` | 0.055 s | 14.5 s | x265 |
| `windows.registry.hivelist.HiveList` | 0.036 s | 7.54 s | x211 |
| `windows.vadyarascan.VadYaraScan` | 0.037 s | 6.59 s | x178 |
| `windows.kpcrs.KPCRs` | 0.042 s | 7.38 s | x174 |
| `windows.verinfo.VerInfo` | 0.344 s | 59.6 s | x174 |
| `windows.iat.IAT` | 0.116 s | 20.1 s | x173 |
| `windows.virtmap.VirtMap` | 0.035 s | 6.05 s | x172 |
| `windows.truecrypt.Passphrase` | 0.039 s | 6.55 s | x170 |
| `windows.registry.cachedump.Cachedump` | 0.053 s | 8.84 s | x168 |
| `windows.registry.hashdump.Hashdump` | 0.050 s | 8.27 s | x167 |
| `windows.hashdump.Hashdump` | 0.061 s | 10.2 s | x166 |
| `windows.lsadump.Lsadump` | 0.060 s | 9.74 s | x162 |
| `windows.crashinfo.Crashinfo` | 0.036 s | 5.54 s | x156 |
| `windows.shimcachemem.ShimcacheMem` | 0.049 s | 7.51 s | x153 |
| `windows.malware.skeleton_key_check.Skeleton_Key_Check` | 0.044 s | 6.66 s | x150 |
| `windows.registry.lsadump.Lsadump` | 0.060 s | 8.83 s | x147 |
| `windows.etwpatch.EtwPatch` | 0.333 s | 49.0 s | x147 |
| `windows.skeleton_key_check.Skeleton_Key_Check` | 0.059 s | 8.34 s | x141 |
| `windows.pslist.PsList` | 0.047 s | 6.55 s | x141 |
| `windows.ssdt.SSDT` | 0.061 s | 8.52 s | x140 |
| `windows.cachedump.Cachedump` | 0.066 s | 9.01 s | x137 |
| `windows.unloadedmodules.UnloadedModules` | 0.049 s | 6.53 s | x134 |
| `windows.modules.Modules` | 0.055 s | 7.33 s | x133 |
| `windows.info.Info` | 0.063 s | 7.57 s | x121 |
| `windows.suspended_threads.SuspendedThreads` | 0.057 s | 6.70 s | x117 |
| `windows.privileges.Privs` | 0.060 s | 6.92 s | x115 |
| `windows.pstree.PsTree` | 0.072 s | 7.89 s | x110 |
| `windows.envars.Envars` | 0.086 s | 9.19 s | x107 |
| `windows.timers.Timers` | 0.078 s | 8.01 s | x102 |
| `windows.mftscan.MFTScan` | 0.469 s | 46.1 s | x98 |
| `windows.sessions.Sessions` | 0.074 s | 7.24 s | x98 |
| `windows.cmdline.CmdLine` | 0.070 s | 6.89 s | x98 |
| `windows.registry.printkey.PrintKey` | 0.109 s | 10.6 s | x97 |
| `windows.getsids.GetSIDs` | 0.135 s | 13.1 s | x97 |
| `windows.debugregisters.DebugRegisters` | 0.482 s | 46.1 s | x96 |
| `windows.joblinks.JobLinks` | 0.081 s | 7.64 s | x95 |
| `windows.processghosting.ProcessGhosting` | 0.530 s | 50.2 s | x95 |
| `windows.registry.userassist.UserAssist` | 0.104 s | 9.50 s | x92 |
| `regexscan.RegExScan` | 0.012 s | 1.12 s | x91 |
| `windows.consoles.Consoles` | 0.118 s | 10.5 s | x89 |
| `windows.mftscan.ADS` | 0.321 s | 27.2 s | x85 |
| `windows.vadwalk.VadWalk` | 0.661 s | 55.3 s | x84 |
| `windows.bigpools.BigPools` | 0.186 s | 15.5 s | x83 |
| `windows.mftscan.ResidentData` | 0.324 s | 27.0 s | x83 |
| `windows.registry.hivescan.HiveScan` | 0.146 s | 12.0 s | x82 |
| `windows.ldrmodules.LdrModules` | 0.664 s | 54.0 s | x81 |
| `windows.threads.Threads` | 0.637 s | 51.3 s | x81 |
| `windows.netstat.NetStat` | 0.089 s | 7.01 s | x79 |
| `windows.malware.ldrmodules.LdrModules` | 0.637 s | 49.8 s | x78 |
| `windows.registry.certificates.Certificates` | 0.182 s | 14.2 s | x78 |
| `windows.unhooked_system_calls.unhooked_system_calls` | 0.536 s | 41.4 s | x77 |
| `windows.registry.amcache.Amcache` | 0.289 s | 22.2 s | x77 |
| `windows.handles.Handles` | 1.43 s | 108 s | x75 |
| `windows.getservicesids.GetServiceSIDs` | 0.140 s | 10.5 s | x75 |
| `windows.registry.scheduled_tasks.ScheduledTasks` | 0.369 s | 27.4 s | x74 |
| `windows.scheduled_tasks.ScheduledTasks` | 0.349 s | 25.8 s | x74 |
| `windows.svclist.SvcList` | 0.341 s | 24.7 s | x72 |
| `windows.dlllist.DllList` | 0.339 s | 24.2 s | x71 |
| `windows.amcache.Amcache` | 0.316 s | 22.4 s | x71 |
| `windows.pe_symbols.PESymbols` | 0.012 s | 0.815 s | x70 |
| `windows.malware.processghosting.ProcessGhosting` | 0.686 s | 47.5 s | x69 |
| `windows.pedump.PEDump` | 0.012 s | 0.779 s | x67 |
| `windows.vadregexscan.VadRegExScan` | 0.012 s | 0.753 s | x64 |
| `windows.malware.pebmasquerade.PebMasquerade` | 0.121 s | 7.63 s | x63 |
| `windows.dumpfiles.DumpFiles` | 6.14 s | 383 s | x62 |
| `windows.malware.unhooked_system_calls.UnhookedSystemCalls` | 0.769 s | 46.1 s | x60 |
| `windows.strings.Strings` | 0.010 s | 0.612 s | x59 |
| `banners.Banners` | 0.553 s | 25.7 s | x46 |
| `windows.statistics.Statistics` | 11.6 s | 537 s | x46 |
| `windows.thrdscan.ThrdScan` | 1.68 s | 64.7 s | x39 |
| `windows.cmdscan.CmdScan` | 0.423 s | 16.1 s | x38 |
| `timeliner.Timeliner` | 8.17 s | 310 s | x38 |
| `windows.mbrscan.MBRScan` | 1.51 s | 44.4 s | x30 |
| `windows.filescan.FileScan` | 1.39 s | 40.2 s | x29 |
| `windows.poolscanner.PoolScanner` | 1.87 s | 52.6 s | x28 |
| `windows.windows.Windows` | 1.02 s | 24.2 s | x24 |
| `windows.desktops.Desktops` | 1.28 s | 29.7 s | x23 |
| `windows.svcdiff.SvcDiff` | 1.23 s | 28.5 s | x23 |
| `windows.windowstations.WindowStations` | 1.08 s | 23.2 s | x21 |
| `windows.netscan.NetScan` | 0.909 s | 19.5 s | x21 |
| `windows.modscan.ModScan` | 0.921 s | 19.1 s | x21 |
| `windows.drivermodule.DriverModule` | 1.10 s | 22.7 s | x21 |
| `windows.svcscan.SvcScan` | 1.28 s | 25.5 s | x20 |
| `windows.psscan.PsScan` | 0.980 s | 19.4 s | x20 |
| `windows.malware.drivermodule.DriverModule` | 1.16 s | 22.4 s | x19 |
| `windows.malware.svcdiff.SvcDiff` | 1.47 s | 28.4 s | x19 |
| `windows.registry.getcellroutine.GetCellRoutine` | 0.430 s | 8.28 s | x19 |
| `windows.psxview.PsXView` | 2.27 s | 43.0 s | x19 |
| `windows.driverirp.DriverIrp` | 1.14 s | 20.8 s | x18 |
| `windows.symlinkscan.SymlinkScan` | 1.17 s | 21.2 s | x18 |
| `vmscan.Vmscan` | 0.797 s | 14.1 s | x18 |
| `windows.devicetree.DeviceTree` | 1.19 s | 20.5 s | x17 |
| `windows.mutantscan.MutantScan` | 1.14 s | 19.3 s | x17 |
| `windows.driverscan.DriverScan` | 1.16 s | 19.5 s | x17 |
| `windows.deskscan.DeskScan` | 1.28 s | 20.9 s | x16 |
| `windows.callbacks.Callbacks` | 1.38 s | 21.3 s | x15 |
| `windows.malware.psxview.PsXView` | 3.00 s | 45.5 s | x15 |
| `windows.orphan_kernel_threads.Threads` | 2.06 s | 28.8 s | x14 |
| `windows.malware.indirect_system_calls.IndirectSystemCalls` | 38.4 s | 183 s | x4.8 |
| `windows.direct_system_calls.DirectSystemCalls` | 34.7 s | 135 s | x3.9 |
| `windows.indirect_system_calls.IndirectSystemCalls` | 36.2 s | 135 s | x3.7 |
| `windows.malware.direct_system_calls.DirectSystemCalls` | 33.2 s | 119 s | x3.6 |
| `layerwriter.LayerWriter` | 8.65 s | 23.2 s | x2.7 |
| **111 plugins** | **233 s** | **6113 s** | **x26** |

## Windows XP, 512 MB raw capture

| Plugin | Rust | Python | Faster |
|---|---:|---:|---:|
| `windows.suspicious_threads.SuspiciousThreads` | 0.148 s | 34.5 s | x233 |
| `windows.malware.suspicious_threads.SuspiciousThreads` | 0.152 s | 33.2 s | x218 |
| `windows.hollowprocesses.HollowProcesses` | 0.142 s | 28.1 s | x197 |
| `windows.malware.hollowprocesses.HollowProcesses` | 0.192 s | 31.0 s | x161 |
| `windows.mftscan.MFTScan` | 0.322 s | 48.2 s | x150 |
| `windows.etwpatch.EtwPatch` | 0.103 s | 15.2 s | x147 |
| `windows.malware.malfind.Malfind` | 0.203 s | 28.2 s | x139 |
| `windows.mftscan.ADS` | 0.189 s | 25.0 s | x132 |
| `windows.malfind.Malfind` | 0.201 s | 26.3 s | x131 |
| `windows.vadinfo.VadInfo` | 0.294 s | 38.5 s | x131 |
| `timeliner.Timeliner` | 1.09 s | 126 s | x116 |
| `windows.verinfo.VerInfo` | 0.229 s | 25.1 s | x110 |
| `windows.registry.hashdump.Hashdump` | 0.079 s | 8.32 s | x105 |
| `windows.timers.Timers` | 0.069 s | 7.24 s | x105 |
| `windows.registry.lsadump.Lsadump` | 0.104 s | 10.7 s | x103 |
| `windows.registry.printkey.PrintKey` | 0.082 s | 8.11 s | x99 |
| `windows.iat.IAT` | 0.115 s | 11.4 s | x99 |
| `windows.registry.hivelist.HiveList` | 0.063 s | 6.15 s | x98 |
| `windows.threads.Threads` | 0.134 s | 13.0 s | x97 |
| `configwriter.ConfigWriter` | 0.073 s | 7.07 s | x96 |
| `windows.handles.Handles` | 0.369 s | 34.5 s | x93 |
| `windows.mftscan.ResidentData` | 0.297 s | 27.6 s | x93 |
| `windows.amcache.Amcache` | 0.076 s | 7.09 s | x93 |
| `windows.ldrmodules.LdrModules` | 0.157 s | 14.5 s | x92 |
| `windows.vadyarascan.VadYaraScan` | 0.069 s | 6.30 s | x92 |
| `yarascan.YaraScan` | 0.077 s | 7.11 s | x92 |
| `windows.registry.cachedump.Cachedump` | 0.086 s | 7.78 s | x91 |
| `windows.shimcachemem.ShimcacheMem` | 0.116 s | 10.5 s | x91 |
| `windows.lsadump.Lsadump` | 0.110 s | 9.85 s | x90 |
| `windows.vadwalk.VadWalk` | 0.146 s | 13.1 s | x89 |
| `windows.netstat.NetStat` | 0.070 s | 6.24 s | x89 |
| `windows.cachedump.Cachedump` | 0.085 s | 7.56 s | x89 |
| `windows.deskscan.DeskScan` | 0.074 s | 6.33 s | x85 |
| `windows.virtmap.VirtMap` | 0.078 s | 6.64 s | x85 |
| `windows.malware.ldrmodules.LdrModules` | 0.155 s | 13.2 s | x85 |
| `windows.bigpools.BigPools` | 0.062 s | 5.18 s | x84 |
| `windows.strings.Strings` | 0.012 s | 0.978 s | x83 |
| `windows.pedump.PEDump` | 0.012 s | 0.952 s | x82 |
| `windows.malware.processghosting.ProcessGhosting` | 0.149 s | 12.1 s | x81 |
| `windows.processghosting.ProcessGhosting` | 0.185 s | 15.0 s | x81 |
| `windows.malware.skeleton_key_check.Skeleton_Key_Check` | 0.060 s | 4.80 s | x80 |
| `windows.kpcrs.KPCRs` | 0.064 s | 5.18 s | x80 |
| `windows.info.Info` | 0.062 s | 4.95 s | x79 |
| `windows.hashdump.Hashdump` | 0.087 s | 6.83 s | x78 |
| `windows.suspended_threads.SuspendedThreads` | 0.068 s | 5.30 s | x78 |
| `windows.windows.Windows` | 0.085 s | 6.60 s | x77 |
| `windows.dlllist.DllList` | 0.138 s | 10.5 s | x76 |
| `windows.registry.amcache.Amcache` | 0.071 s | 5.39 s | x75 |
| `windows.cmdscan.CmdScan` | 0.110 s | 8.20 s | x75 |
| `windows.malware.svcdiff.SvcDiff` | 0.074 s | 5.54 s | x75 |
| `windows.thrdscan.ThrdScan` | 0.247 s | 18.1 s | x73 |
| `windows.joblinks.JobLinks` | 0.068 s | 4.99 s | x73 |
| `windows.scheduled_tasks.ScheduledTasks` | 0.067 s | 4.83 s | x72 |
| `windows.registry.scheduled_tasks.ScheduledTasks` | 0.062 s | 4.45 s | x72 |
| `windows.registry.certificates.Certificates` | 0.159 s | 11.4 s | x72 |
| `windows.filescan.FileScan` | 0.338 s | 24.1 s | x72 |
| `windows.unhooked_system_calls.unhooked_system_calls` | 0.187 s | 13.3 s | x71 |
| `windows.netscan.NetScan` | 0.077 s | 5.46 s | x71 |
| `regexscan.RegExScan` | 0.012 s | 0.841 s | x70 |
| `windows.malware.unhooked_system_calls.UnhookedSystemCalls` | 0.183 s | 12.9 s | x70 |
| `windows.consoles.Consoles` | 0.131 s | 9.13 s | x70 |
| `windows.envars.Envars` | 0.091 s | 6.32 s | x69 |
| `windows.svclist.SvcList` | 0.078 s | 5.43 s | x69 |
| `windows.crashinfo.Crashinfo` | 0.086 s | 5.84 s | x68 |
| `windows.skeleton_key_check.Skeleton_Key_Check` | 0.083 s | 5.56 s | x67 |
| `windows.ssdt.SSDT` | 0.095 s | 6.34 s | x67 |
| `windows.pstree.PsTree` | 0.095 s | 6.33 s | x66 |
| `windows.malware.pebmasquerade.PebMasquerade` | 0.085 s | 5.64 s | x66 |
| `windows.cmdline.CmdLine` | 0.086 s | 5.65 s | x66 |
| `windows.unloadedmodules.UnloadedModules` | 0.078 s | 5.10 s | x65 |
| `windows.getsids.GetSIDs` | 0.100 s | 6.44 s | x65 |
| `windows.modules.Modules` | 0.093 s | 5.90 s | x63 |
| `windows.vadregexscan.VadRegExScan` | 0.013 s | 0.822 s | x62 |
| `windows.windowstations.WindowStations` | 0.091 s | 5.59 s | x62 |
| `windows.getservicesids.GetServiceSIDs` | 0.077 s | 4.68 s | x61 |
| `windows.sessions.Sessions` | 0.082 s | 4.95 s | x60 |
| `windows.svcdiff.SvcDiff` | 0.092 s | 5.42 s | x59 |
| `windows.registry.userassist.UserAssist` | 0.105 s | 6.12 s | x58 |
| `windows.svcscan.SvcScan` | 0.097 s | 5.61 s | x58 |
| `windows.psscan.PsScan` | 0.206 s | 11.5 s | x56 |
| `windows.malware.psxview.PsXView` | 0.305 s | 17.0 s | x56 |
| `windows.pslist.PsList` | 0.102 s | 5.67 s | x56 |
| `windows.pe_symbols.PESymbols` | 0.013 s | 0.728 s | x55 |
| `windows.orphan_kernel_threads.Threads` | 0.228 s | 12.4 s | x54 |
| `windows.poolscanner.PoolScanner` | 0.842 s | 45.2 s | x54 |
| `windows.registry.getcellroutine.GetCellRoutine` | 0.137 s | 7.09 s | x52 |
| `windows.psxview.PsXView` | 0.435 s | 22.4 s | x52 |
| `windows.dumpfiles.DumpFiles` | 2.44 s | 122 s | x50 |
| `windows.drivermodule.DriverModule` | 0.204 s | 10.1 s | x50 |
| `windows.statistics.Statistics` | 0.132 s | 6.49 s | x49 |
| `windows.malware.drivermodule.DriverModule` | 0.193 s | 9.41 s | x49 |
| `windows.driverirp.DriverIrp` | 0.246 s | 12.0 s | x49 |
| `banners.Banners` | 0.187 s | 9.04 s | x48 |
| `windows.privileges.Privs` | 0.140 s | 6.71 s | x48 |
| `windows.truecrypt.Passphrase` | 0.116 s | 5.30 s | x46 |
| `windows.desktops.Desktops` | 0.136 s | 6.15 s | x45 |
| `windows.driverscan.DriverScan` | 0.218 s | 9.60 s | x44 |
| `windows.registry.hivescan.HiveScan` | 0.143 s | 6.23 s | x44 |
| `windows.modscan.ModScan` | 0.156 s | 6.60 s | x42 |
| `windows.devicetree.DeviceTree` | 0.259 s | 10.9 s | x42 |
| `windows.mutantscan.MutantScan` | 0.167 s | 6.82 s | x41 |
| `windows.symlinkscan.SymlinkScan` | 0.156 s | 6.30 s | x40 |
| `vmscan.Vmscan` | 0.261 s | 7.31 s | x28 |
| `windows.mbrscan.MBRScan` | 0.361 s | 10.0 s | x28 |
| `windows.memmap.Memmap` | 6.84 s | 156 s | x23 |
| `windows.callbacks.Callbacks` | 0.515 s | 9.95 s | x19 |
| `layerwriter.LayerWriter` | 0.675 s | 7.78 s | x12 |
| `windows.debugregisters.DebugRegisters` | 2.13 s | 21.3 s | x10 |
| `windows.malware.indirect_system_calls.IndirectSystemCalls` | 5.52 s | 26.9 s | x4.9 |
| `windows.malware.direct_system_calls.DirectSystemCalls` | 4.45 s | 21.4 s | x4.8 |
| `windows.direct_system_calls.DirectSystemCalls` | 5.13 s | 23.5 s | x4.6 |
| `windows.indirect_system_calls.IndirectSystemCalls` | 4.72 s | 19.9 s | x4.2 |
| **112 plugins** | **48.0 s** | **1674 s** | **x35** |

## Linux 3.2, 512 MB raw capture

| Plugin | Rust | Python | Faster |
|---|---:|---:|---:|
| `linux.library_list.LibraryList` | 0.657 s | 917 s | x1396 |
| `linux.pscallstack.PsCallStack` | 0.314 s | 98.8 s | x315 |
| `linux.lsmod.Lsmod` | 0.076 s | 9.58 s | x127 |
| `linux.check_idt.Check_idt` | 0.132 s | 15.1 s | x114 |
| `linux.malware.tty_check.Tty_Check` | 0.132 s | 15.0 s | x114 |
| `linux.malware.check_idt.Check_idt` | 0.136 s | 15.2 s | x112 |
| `linux.malware.check_modules.Check_modules` | 0.055 s | 5.74 s | x104 |
| `linux.kallsyms.Kallsyms` | 0.291 s | 28.9 s | x99 |
| `linux.keyboard_notifiers.Keyboard_notifiers` | 0.110 s | 10.8 s | x98 |
| `linux.boottime.Boottime` | 0.060 s | 5.48 s | x92 |
| `linux.tty_check.tty_check` | 0.159 s | 14.3 s | x90 |
| `linux.netfilter.Netfilter` | 0.122 s | 10.9 s | x89 |
| `linux.pslist.PsList` | 0.058 s | 4.98 s | x85 |
| `linux.ebpf.EBPF` | 0.053 s | 4.49 s | x85 |
| `linux.tracing.perf_events.PerfEvents` | 0.064 s | 5.18 s | x81 |
| `linux.vmayarascan.VmaYaraScan` | 0.062 s | 4.89 s | x79 |
| `linux.mountinfo.MountInfo` | 0.068 s | 5.30 s | x79 |
| `linux.pidhashtable.PIDHashTable` | 0.076 s | 5.99 s | x78 |
| `linux.graphics.fbdev.Fbdev` | 0.055 s | 4.30 s | x78 |
| `linux.sockstat.Sockstat` | 0.292 s | 22.1 s | x76 |
| `linux.malware.keyboard_notifiers.Keyboard_notifiers` | 0.138 s | 10.3 s | x75 |
| `linux.module_extract.ModuleExtract` | 0.010 s | 0.751 s | x75 |
| `linux.ptrace.Ptrace` | 0.069 s | 5.10 s | x74 |
| `linux.check_modules.Check_modules` | 0.073 s | 5.35 s | x74 |
| `linux.ip.Addr` | 0.068 s | 4.99 s | x74 |
| `linux.malware.check_afinfo.Check_afinfo` | 0.129 s | 9.24 s | x72 |
| `linux.malware.check_creds.Check_creds` | 0.071 s | 4.98 s | x70 |
| `linux.ip.Link` | 0.070 s | 4.85 s | x70 |
| `linux.pagecache.InodePages` | 0.066 s | 4.50 s | x69 |
| `linux.psaux.PsAux` | 0.072 s | 4.90 s | x68 |
| `linux.tracing.tracepoints.CheckTracepoints` | 0.172 s | 11.7 s | x68 |
| `linux.lsof.Lsof` | 0.372 s | 25.1 s | x67 |
| `linux.iomem.IOMem` | 0.070 s | 4.66 s | x67 |
| `linux.vmaregexscan.VmaRegExScan` | 0.011 s | 0.701 s | x66 |
| `linux.malware.malfind.Malfind` | 1.09 s | 71.6 s | x66 |
| `linux.proc.Maps` | 1.20 s | 78.7 s | x65 |
| `linux.malware.process_spoofing.ProcessSpoofing` | 0.089 s | 5.80 s | x65 |
| `linux.pstree.PsTree` | 0.080 s | 5.18 s | x64 |
| `linux.capabilities.Capabilities` | 0.093 s | 5.82 s | x63 |
| `linux.check_creds.Check_creds` | 0.088 s | 5.50 s | x63 |
| `linux.malfind.Malfind` | 1.33 s | 81.7 s | x61 |
| `linux.check_afinfo.Check_afinfo` | 0.160 s | 9.73 s | x61 |
| `linux.malware.netfilter.Netfilter` | 0.191 s | 11.3 s | x59 |
| `linux.bash.Bash` | 0.110 s | 6.22 s | x56 |
| `linux.check_syscall.Check_syscall` | 0.208 s | 11.6 s | x56 |
| `linux.envars.Envars` | 0.089 s | 4.76 s | x53 |
| `linux.elfs.Elfs` | 0.765 s | 40.1 s | x52 |
| `linux.pagecache.Files` | 0.696 s | 36.1 s | x52 |
| `linux.kmsg.Kmsg` | 0.096 s | 4.86 s | x50 |
| `linux.psscan.PsScan` | 0.182 s | 9.01 s | x50 |
| `linux.malware.check_syscall.Check_syscall` | 0.237 s | 11.1 s | x47 |
| `linux.modxview.Modxview` | 0.268 s | 10.0 s | x37 |
| `linux.hidden_modules.Hidden_modules` | 0.317 s | 11.2 s | x35 |
| `linux.malware.modxview.Modxview` | 0.323 s | 11.2 s | x35 |
| `linux.malware.hidden_modules.Hidden_modules` | 0.325 s | 10.6 s | x33 |
| `linux.tracing.ftrace.CheckFtrace` | 0.133 s | 3.87 s | x29 |
| `linux.kthreads.Kthreads` | 0.145 s | 4.18 s | x29 |
| `linux.sockscan.Sockscan` | 0.427 s | 8.95 s | x21 |
| `linux.vmcoreinfo.VMCoreInfo` | 0.406 s | 4.44 s | x11 |
| `linux.pagecache.RecoverFs` | 22.6 s | 131 s | x5.8 |
| **60 plugins** | **36.1 s** | **1896 s** | **x53** |

## Not comparable

| Plugin | Why |
|---|---|
| `windows.memmap.Memmap` | on the Windows 10 capture `vol` is killed for running out of memory part way through. Where it stops depends on how much memory is free at the time, so two `vol` runs do not agree with each other either. This port finishes all 9,014,410 lines, and every line `vol` wrote before dying matches. On the Windows XP capture both finish and the row for it is in that table above |
| `isfinfo.IsfInfo` | without `--live` upstream lists its own identifier database rather than the image, and the rows come back in that database's order. This port lists the symbol directories instead. Both describe the installation |

