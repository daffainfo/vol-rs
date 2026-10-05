# Runtime against volatility3

Same plugin, same image, same machine, same arguments, byte-identical output,
wall clock. One plugin at a time with warm caches and nothing else running.
Only plugins where both tools finished and agreed byte for byte are listed.

The Rust column is the median of three runs after a discarded warm up run. The
Python column was measured the same way but not in the same pass, so a figure
here is two measurements taken against the same image rather than a single
race. `vol` is unchanged between them, and its runs had the page cache already
warm, so where the two disagree the error favours `vol` and the ratio is the
conservative one.

Measured on one machine with one set of captures, so the figures will differ on
other hardware, other images and a different amount of free memory.

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

The figures below were measured on the Volatility Foundation's own test data,
release [v0.0.1](https://github.com/volatilityfoundation/volatility3-test-data/releases/tag/v0.0.1).

| Image | Size | Format | System | Source |
|---|---:|---|---|---|
| `win-10_19041-2025_03.dmp` | 2.0 GB | Windows crash dump | Windows 10, build 19041, 120 processes | [win-10_19041-2025_03.dmp.gz](https://github.com/volatilityfoundation/volatility3-test-data/releases/download/v0.0.1/win-10_19041-2025_03.dmp.gz) |
| `win-xp-laptop-2005-06-25.img` | 512 MB | raw | Windows XP, 47 processes | [win-xp-laptop-2005-06-25.img.gz](https://github.com/volatilityfoundation/volatility3-test-data/releases/download/v0.0.1/win-xp-laptop-2005-06-25.img.gz) |
| `linux-sample-1.bin` | 512 MB | raw | Linux 3.2, 133 tasks | [linux-sample-1.bin.gz](https://github.com/volatilityfoundation/volatility3-test-data/releases/download/v0.0.1/linux-sample-1.bin.gz) |

Two larger captures check that the output stays byte identical on a recent
Windows build and a recent Linux kernel.

| Image | Size | Format | System | Source |
|---|---:|---|---|---|
| `memory.dmp` | 4.3 GB | Windows crash dump | Windows 11 24H2, build 26100, 160 processes | [13Cubed Windows memory forensics](https://www.iblue.team/ctf-challenges/13cubed-windows-memory-forensics) |
| `memory.vmem` with `memory.vmsn` | 4.3 GB | VMware snapshot | Ubuntu 22.04, kernel 6.5.0-41, 344 tasks | [13Cubed Linux memory forensics](https://www.iblue.team/ctf-challenges/13cubed-linux-memory-forensics) |

## Windows 10 19041, 2.0 GB crash dump

| Plugin | Rust | Python | Faster |
|---|---:|---:|---:|
| `windows.malware.suspicious_threads.SuspiciousThreads` | 0.573 s | 346 s | x604 |
| `windows.suspicious_threads.SuspiciousThreads` | 0.688 s | 343 s | x499 |
| `windows.malfind.Malfind` | 0.678 s | 320 s | x472 |
| `windows.malware.malfind.Malfind` | 0.72 s | 313 s | x435 |
| `windows.malware.hollowprocesses.HollowProcesses` | 0.555 s | 240 s | x432 |
| `windows.vadinfo.VadInfo` | 0.962 s | 412 s | x428 |
| `configwriter.ConfigWriter` | 0.034 s | 14.5 s | x426 |
| `windows.hollowprocesses.HollowProcesses` | 0.589 s | 244 s | x414 |
| `layerwriter.LayerWriter` | 0.051 s | 11.9 s | x233 |
| `windows.verinfo.VerInfo` | 0.295 s | 59.6 s | x202 |
| `windows.kpcrs.KPCRs` | 0.037 s | 7.38 s | x199 |
| `windows.skeleton_key_check.Skeleton_Key_Check` | 0.043 s | 8.34 s | x194 |
| `windows.registry.hivelist.HiveList` | 0.039 s | 7.54 s | x193 |
| `windows.hashdump.Hashdump` | 0.053 s | 10.2 s | x192 |
| `windows.modules.Modules` | 0.039 s | 7.33 s | x188 |
| `windows.lsadump.Lsadump` | 0.052 s | 9.74 s | x187 |
| `windows.unloadedmodules.UnloadedModules` | 0.035 s | 6.53 s | x187 |
| `windows.joblinks.JobLinks` | 0.041 s | 7.64 s | x186 |
| `windows.info.Info` | 0.041 s | 7.57 s | x185 |
| `windows.virtmap.VirtMap` | 0.033 s | 6.05 s | x183 |
| `windows.shimcachemem.ShimcacheMem` | 0.042 s | 7.51 s | x179 |
| `windows.registry.cachedump.Cachedump` | 0.051 s | 8.84 s | x173 |
| `windows.truecrypt.Passphrase` | 0.038 s | 6.55 s | x172 |
| `windows.pslist.PsList` | 0.038 s | 6.55 s | x172 |
| `windows.ssdt.SSDT` | 0.052 s | 8.52 s | x164 |
| `windows.iat.IAT` | 0.125 s | 20.1 s | x161 |
| `windows.etwpatch.EtwPatch` | 0.305 s | 49.0 s | x161 |
| `windows.crashinfo.Crashinfo` | 0.035 s | 5.54 s | x158 |
| `windows.cachedump.Cachedump` | 0.057 s | 9.01 s | x158 |
| `windows.malware.skeleton_key_check.Skeleton_Key_Check` | 0.043 s | 6.66 s | x155 |
| `windows.registry.lsadump.Lsadump` | 0.06 s | 8.83 s | x147 |
| `windows.privileges.Privs` | 0.049 s | 6.92 s | x141 |
| `windows.getsids.GetSIDs` | 0.093 s | 13.1 s | x141 |
| `windows.malware.pebmasquerade.PebMasquerade` | 0.058 s | 7.63 s | x132 |
| `windows.pstree.PsTree` | 0.062 s | 7.89 s | x127 |
| `windows.bigpools.BigPools` | 0.124 s | 15.5 s | x125 |
| `windows.timers.Timers` | 0.065 s | 8.01 s | x123 |
| `windows.cmdline.CmdLine` | 0.056 s | 6.89 s | x123 |
| `windows.mftscan.MFTScan` | 0.378 s | 46.1 s | x122 |
| `windows.sessions.Sessions` | 0.06 s | 7.24 s | x121 |
| `windows.suspended_threads.SuspendedThreads` | 0.056 s | 6.7 s | x120 |
| `windows.envars.Envars` | 0.078 s | 9.19 s | x118 |
| `windows.dlllist.DllList` | 0.207 s | 24.2 s | x117 |
| `windows.threads.Threads` | 0.472 s | 51.3 s | x109 |
| `windows.consoles.Consoles` | 0.101 s | 10.5 s | x104 |
| `windows.debugregisters.DebugRegisters` | 0.447 s | 46.1 s | x103 |
| `windows.registry.hashdump.Hashdump` | 0.082 s | 8.27 s | x101 |
| `windows.vadwalk.VadWalk` | 0.551 s | 55.3 s | x100 |
| `windows.getservicesids.GetServiceSIDs` | 0.107 s | 10.5 s | x98 |
| `windows.registry.userassist.UserAssist` | 0.098 s | 9.5 s | x97 |
| `windows.mftscan.ADS` | 0.281 s | 27.2 s | x97 |
| `windows.malware.processghosting.ProcessGhosting` | 0.491 s | 47.5 s | x97 |
| `windows.dumpfiles.DumpFiles` | 1.1 s | 106 s | x97 |
| `windows.processghosting.ProcessGhosting` | 0.583 s | 50.2 s | x86 |
| `windows.ldrmodules.LdrModules` | 0.638 s | 54.0 s | x85 |
| `windows.registry.hivescan.HiveScan` | 0.144 s | 12.0 s | x83 |
| `windows.registry.printkey.PrintKey` | 0.129 s | 10.6 s | x82 |
| `windows.handles.Handles` | 1.32 s | 108 s | x82 |
| `windows.amcache.Amcache` | 0.281 s | 22.4 s | x80 |
| `windows.malware.ldrmodules.LdrModules` | 0.64 s | 49.8 s | x78 |
| `windows.mftscan.ResidentData` | 0.354 s | 27.0 s | x76 |
| `windows.registry.scheduled_tasks.ScheduledTasks` | 0.362 s | 27.4 s | x76 |
| `windows.pe_symbols.PESymbols` | 0.011 s | 0.815 s | x74 |
| `windows.netstat.NetStat` | 0.096 s | 7.01 s | x73 |
| `windows.registry.amcache.Amcache` | 0.305 s | 22.2 s | x73 |
| `windows.unhooked_system_calls.unhooked_system_calls` | 0.57 s | 41.4 s | x73 |
| `windows.pedump.PEDump` | 0.011 s | 0.779 s | x71 |
| `windows.scheduled_tasks.ScheduledTasks` | 0.371 s | 25.8 s | x70 |
| `windows.malware.unhooked_system_calls.UnhookedSystemCalls` | 0.693 s | 46.1 s | x67 |
| `windows.svclist.SvcList` | 0.38 s | 24.7 s | x65 |
| `windows.registry.certificates.Certificates` | 0.22 s | 14.2 s | x65 |
| `banners.Banners` | 0.402 s | 25.7 s | x64 |
| `windows.cmdscan.CmdScan` | 0.261 s | 16.1 s | x62 |
| `windows.statistics.Statistics` | 9.77 s | 537 s | x55 |
| `windows.thrdscan.ThrdScan` | 1.48 s | 64.7 s | x44 |
| `windows.strings.Strings` | 0.017 s | 0.612 s | x36 |
| `timeliner.Timeliner` | 9.05 s | 310 s | x34 |
| `windows.mbrscan.MBRScan` | 1.39 s | 44.4 s | x32 |
| `windows.filescan.FileScan` | 1.4 s | 40.2 s | x29 |
| `windows.poolscanner.PoolScanner` | 1.9 s | 52.6 s | x28 |
| `windows.orphan_kernel_threads.Threads` | 1.04 s | 28.8 s | x28 |
| `windows.desktops.Desktops` | 1.1 s | 29.7 s | x27 |
| `windows.malware.svcdiff.SvcDiff` | 1.06 s | 28.4 s | x27 |
| `regexscan.RegExScan` | 0.902 s | 23.2 s | x26 |
| `windows.svcdiff.SvcDiff` | 1.16 s | 28.5 s | x25 |
| `windows.svcscan.SvcScan` | 1.05 s | 25.5 s | x24 |
| `windows.vadregexscan.VadRegExScan` | 6.69 s | 153 s | x23 |
| `windows.devicetree.DeviceTree` | 0.908 s | 20.5 s | x23 |
| `windows.malware.psxview.PsXView` | 2.03 s | 45.5 s | x22 |
| `windows.symlinkscan.SymlinkScan` | 0.948 s | 21.2 s | x22 |
| `windows.windows.Windows` | 1.1 s | 24.2 s | x22 |
| `windows.malware.drivermodule.DriverModule` | 1.02 s | 22.4 s | x22 |
| `windows.psxview.PsXView` | 1.98 s | 43.0 s | x22 |
| `windows.driverirp.DriverIrp` | 0.997 s | 20.8 s | x21 |
| `windows.drivermodule.DriverModule` | 1.1 s | 22.7 s | x21 |
| `windows.registry.getcellroutine.GetCellRoutine` | 0.419 s | 8.28 s | x20 |
| `windows.psscan.PsScan` | 1.02 s | 19.4 s | x19 |
| `windows.netscan.NetScan` | 1.03 s | 19.5 s | x19 |
| `windows.driverscan.DriverScan` | 1.04 s | 19.5 s | x19 |
| `windows.modscan.ModScan` | 1.04 s | 19.1 s | x18 |
| `vmscan.Vmscan` | 0.774 s | 14.1 s | x18 |
| `windows.windowstations.WindowStations` | 1.29 s | 23.2 s | x18 |
| `windows.mutantscan.MutantScan` | 1.08 s | 19.3 s | x18 |
| `windows.deskscan.DeskScan` | 1.26 s | 20.9 s | x17 |
| `windows.callbacks.Callbacks` | 1.37 s | 21.3 s | x16 |
| `windows.vadyarascan.VadYaraScan` | 42.1 s | 364 s | x8.6 |
| `windows.malware.indirect_system_calls.IndirectSystemCalls` | 47.3 s | 183 s | x3.9 |
| `windows.direct_system_calls.DirectSystemCalls` | 40.1 s | 135 s | x3.4 |
| `windows.indirect_system_calls.IndirectSystemCalls` | 43.6 s | 135 s | x3.1 |
| `windows.malware.direct_system_calls.DirectSystemCalls` | 43.6 s | 119 s | x2.7 |
| `yarascan.YaraScan` | 26.4 s | 25.2 s | x1.0 |
| **111 plugins** | **321 s** | **6370 s** | **x20** |

## Windows XP, 512 MB raw capture

| Plugin | Rust | Python | Faster |
|---|---:|---:|---:|
| `windows.malware.suspicious_threads.SuspiciousThreads` | 0.118 s | 33.2 s | x281 |
| `windows.suspicious_threads.SuspiciousThreads` | 0.14 s | 34.5 s | x246 |
| `windows.vadinfo.VadInfo` | 0.158 s | 38.5 s | x244 |
| `windows.malware.hollowprocesses.HollowProcesses` | 0.134 s | 31.0 s | x231 |
| `windows.mftscan.MFTScan` | 0.268 s | 48.2 s | x180 |
| `windows.mftscan.ResidentData` | 0.164 s | 27.6 s | x168 |
| `windows.hollowprocesses.HollowProcesses` | 0.172 s | 28.1 s | x163 |
| `windows.etwpatch.EtwPatch` | 0.094 s | 15.2 s | x162 |
| `windows.mftscan.ADS` | 0.161 s | 25.0 s | x155 |
| `windows.malware.malfind.Malfind` | 0.192 s | 28.2 s | x147 |
| `timeliner.Timeliner` | 0.872 s | 126 s | x144 |
| `windows.verinfo.VerInfo` | 0.175 s | 25.1 s | x143 |
| `windows.malfind.Malfind` | 0.186 s | 26.3 s | x141 |
| `windows.registry.lsadump.Lsadump` | 0.084 s | 10.7 s | x127 |
| `configwriter.ConfigWriter` | 0.056 s | 7.07 s | x126 |
| `windows.registry.hashdump.Hashdump` | 0.067 s | 8.32 s | x124 |
| `windows.iat.IAT` | 0.092 s | 11.4 s | x124 |
| `windows.amcache.Amcache` | 0.058 s | 7.09 s | x122 |
| `windows.dlllist.DllList` | 0.087 s | 10.5 s | x121 |
| `windows.cachedump.Cachedump` | 0.065 s | 7.56 s | x116 |
| `windows.registry.cachedump.Cachedump` | 0.067 s | 7.78 s | x116 |
| `windows.windows.Windows` | 0.057 s | 6.6 s | x116 |
| `windows.virtmap.VirtMap` | 0.059 s | 6.64 s | x113 |
| `windows.registry.printkey.PrintKey` | 0.073 s | 8.11 s | x111 |
| `windows.lsadump.Lsadump` | 0.09 s | 9.85 s | x109 |
| `windows.cmdscan.CmdScan` | 0.075 s | 8.2 s | x109 |
| `windows.deskscan.DeskScan` | 0.058 s | 6.33 s | x109 |
| `windows.hashdump.Hashdump` | 0.064 s | 6.83 s | x107 |
| `windows.netstat.NetStat` | 0.059 s | 6.24 s | x106 |
| `windows.timers.Timers` | 0.069 s | 7.24 s | x105 |
| `windows.crashinfo.Crashinfo` | 0.057 s | 5.84 s | x102 |
| `windows.consoles.Consoles` | 0.09 s | 9.13 s | x101 |
| `windows.unhooked_system_calls.unhooked_system_calls` | 0.132 s | 13.3 s | x101 |
| `windows.ssdt.SSDT` | 0.063 s | 6.34 s | x101 |
| `windows.ldrmodules.LdrModules` | 0.146 s | 14.5 s | x99 |
| `windows.skeleton_key_check.Skeleton_Key_Check` | 0.056 s | 5.56 s | x99 |
| `windows.registry.hivelist.HiveList` | 0.062 s | 6.15 s | x99 |
| `windows.processghosting.ProcessGhosting` | 0.152 s | 15.0 s | x99 |
| `windows.privileges.Privs` | 0.068 s | 6.71 s | x99 |
| `windows.vadwalk.VadWalk` | 0.133 s | 13.1 s | x98 |
| `windows.strings.Strings` | 0.01 s | 0.978 s | x98 |
| `windows.shimcachemem.ShimcacheMem` | 0.108 s | 10.5 s | x97 |
| `windows.malware.svcdiff.SvcDiff` | 0.057 s | 5.54 s | x97 |
| `windows.malware.unhooked_system_calls.UnhookedSystemCalls` | 0.133 s | 12.9 s | x97 |
| `layerwriter.LayerWriter` | 0.064 s | 6.19 s | x97 |
| `windows.netscan.NetScan` | 0.057 s | 5.46 s | x96 |
| `windows.handles.Handles` | 0.362 s | 34.5 s | x95 |
| `windows.pedump.PEDump` | 0.01 s | 0.952 s | x95 |
| `windows.pslist.PsList` | 0.061 s | 5.67 s | x93 |
| `windows.kpcrs.KPCRs` | 0.056 s | 5.18 s | x92 |
| `windows.windowstations.WindowStations` | 0.061 s | 5.59 s | x92 |
| `windows.cmdline.CmdLine` | 0.062 s | 5.65 s | x91 |
| `windows.modules.Modules` | 0.065 s | 5.9 s | x91 |
| `windows.malware.ldrmodules.LdrModules` | 0.147 s | 13.2 s | x90 |
| `windows.envars.Envars` | 0.071 s | 6.32 s | x89 |
| `windows.registry.getcellroutine.GetCellRoutine` | 0.081 s | 7.09 s | x88 |
| `windows.bigpools.BigPools` | 0.06 s | 5.18 s | x86 |
| `windows.filescan.FileScan` | 0.28 s | 24.1 s | x86 |
| `windows.malware.processghosting.ProcessGhosting` | 0.142 s | 12.1 s | x85 |
| `windows.svclist.SvcList` | 0.064 s | 5.43 s | x85 |
| `windows.joblinks.JobLinks` | 0.059 s | 4.99 s | x85 |
| `windows.desktops.Desktops` | 0.073 s | 6.15 s | x84 |
| `windows.suspended_threads.SuspendedThreads` | 0.063 s | 5.3 s | x84 |
| `windows.psxview.PsXView` | 0.267 s | 22.4 s | x84 |
| `windows.pstree.PsTree` | 0.076 s | 6.33 s | x83 |
| `windows.svcdiff.SvcDiff` | 0.067 s | 5.42 s | x81 |
| `windows.pe_symbols.PESymbols` | 0.009 s | 0.728 s | x81 |
| `windows.thrdscan.ThrdScan` | 0.224 s | 18.1 s | x81 |
| `windows.registry.certificates.Certificates` | 0.142 s | 11.4 s | x80 |
| `windows.registry.amcache.Amcache` | 0.069 s | 5.39 s | x78 |
| `windows.unloadedmodules.UnloadedModules` | 0.066 s | 5.1 s | x77 |
| `windows.getsids.GetSIDs` | 0.086 s | 6.44 s | x75 |
| `windows.malware.pebmasquerade.PebMasquerade` | 0.076 s | 5.64 s | x74 |
| `windows.threads.Threads` | 0.177 s | 13.0 s | x73 |
| `windows.registry.scheduled_tasks.ScheduledTasks` | 0.061 s | 4.45 s | x73 |
| `windows.registry.userassist.UserAssist` | 0.084 s | 6.12 s | x73 |
| `windows.psscan.PsScan` | 0.16 s | 11.5 s | x72 |
| `windows.info.Info` | 0.069 s | 4.95 s | x72 |
| `windows.orphan_kernel_threads.Threads` | 0.175 s | 12.4 s | x71 |
| `windows.truecrypt.Passphrase` | 0.075 s | 5.3 s | x71 |
| `windows.driverirp.DriverIrp` | 0.172 s | 12.0 s | x70 |
| `windows.svcscan.SvcScan` | 0.081 s | 5.61 s | x69 |
| `windows.getservicesids.GetServiceSIDs` | 0.068 s | 4.68 s | x69 |
| `windows.dumpfiles.DumpFiles` | 1.12 s | 77.1 s | x69 |
| `windows.sessions.Sessions` | 0.073 s | 4.95 s | x68 |
| `windows.scheduled_tasks.ScheduledTasks` | 0.072 s | 4.83 s | x67 |
| `windows.malware.psxview.PsXView` | 0.264 s | 17.0 s | x64 |
| `windows.drivermodule.DriverModule` | 0.158 s | 10.1 s | x64 |
| `windows.poolscanner.PoolScanner` | 0.732 s | 45.2 s | x62 |
| `windows.malware.drivermodule.DriverModule` | 0.153 s | 9.41 s | x62 |
| `windows.malware.skeleton_key_check.Skeleton_Key_Check` | 0.079 s | 4.8 s | x61 |
| `banners.Banners` | 0.153 s | 9.04 s | x59 |
| `windows.statistics.Statistics` | 0.111 s | 6.49 s | x58 |
| `windows.driverscan.DriverScan` | 0.241 s | 9.6 s | x40 |
| `windows.devicetree.DeviceTree` | 0.279 s | 10.9 s | x39 |
| `windows.mutantscan.MutantScan` | 0.175 s | 6.82 s | x39 |
| `regexscan.RegExScan` | 0.212 s | 8.06 s | x38 |
| `windows.symlinkscan.SymlinkScan` | 0.195 s | 6.3 s | x32 |
| `windows.mbrscan.MBRScan` | 0.317 s | 10.0 s | x32 |
| `windows.vadregexscan.VadRegExScan` | 0.49 s | 15.3 s | x31 |
| `vmscan.Vmscan` | 0.236 s | 7.31 s | x31 |
| `windows.modscan.ModScan` | 0.219 s | 6.6 s | x30 |
| `windows.registry.hivescan.HiveScan` | 0.238 s | 6.23 s | x26 |
| `windows.memmap.Memmap` | 6.34 s | 156 s | x25 |
| `windows.callbacks.Callbacks` | 0.407 s | 9.95 s | x24 |
| `windows.debugregisters.DebugRegisters` | 1.73 s | 21.3 s | x12 |
| `windows.vadyarascan.VadYaraScan` | 3.02 s | 20.3 s | x6.7 |
| `windows.direct_system_calls.DirectSystemCalls` | 4.97 s | 23.5 s | x4.7 |
| `windows.malware.indirect_system_calls.IndirectSystemCalls` | 6.32 s | 26.9 s | x4.3 |
| `windows.malware.direct_system_calls.DirectSystemCalls` | 5.39 s | 21.4 s | x4.0 |
| `windows.indirect_system_calls.IndirectSystemCalls` | 5.51 s | 19.9 s | x3.6 |
| `yarascan.YaraScan` | 5.5 s | 15.3 s | x2.8 |
| **112 plugins** | **54.0 s** | **1671 s** | **x31** |

## Linux 3.2, 512 MB raw capture

| Plugin | Rust | Python | Faster |
|---|---:|---:|---:|
| `linux.library_list.LibraryList` | 0.589 s | 917 s | x1557 |
| `linux.pscallstack.PsCallStack` | 0.356 s | 98.8 s | x278 |
| `linux.lsmod.Lsmod` | 0.066 s | 9.58 s | x145 |
| `linux.malware.check_idt.Check_idt` | 0.131 s | 15.2 s | x116 |
| `linux.check_idt.Check_idt` | 0.135 s | 15.1 s | x112 |
| `linux.malware.tty_check.Tty_Check` | 0.145 s | 15.0 s | x103 |
| `linux.sockstat.Sockstat` | 0.22 s | 22.1 s | x100 |
| `linux.tty_check.tty_check` | 0.149 s | 14.3 s | x96 |
| `linux.kallsyms.Kallsyms` | 0.309 s | 28.9 s | x94 |
| `linux.malware.check_modules.Check_modules` | 0.062 s | 5.74 s | x93 |
| `linux.capabilities.Capabilities` | 0.066 s | 5.82 s | x88 |
| `linux.malware.netfilter.Netfilter` | 0.129 s | 11.3 s | x88 |
| `linux.boottime.Boottime` | 0.063 s | 5.48 s | x87 |
| `linux.tracing.tracepoints.CheckTracepoints` | 0.135 s | 11.7 s | x87 |
| `linux.check_creds.Check_creds` | 0.066 s | 5.5 s | x83 |
| `linux.tracing.perf_events.PerfEvents` | 0.063 s | 5.18 s | x82 |
| `linux.netfilter.Netfilter` | 0.133 s | 10.9 s | x82 |
| `linux.pidhashtable.PIDHashTable` | 0.075 s | 5.99 s | x80 |
| `linux.keyboard_notifiers.Keyboard_notifiers` | 0.136 s | 10.8 s | x79 |
| `linux.check_afinfo.Check_afinfo` | 0.126 s | 9.73 s | x77 |
| `linux.graphics.fbdev.Fbdev` | 0.056 s | 4.3 s | x77 |
| `linux.ebpf.EBPF` | 0.059 s | 4.49 s | x76 |
| `linux.kmsg.Kmsg` | 0.064 s | 4.86 s | x76 |
| `linux.check_modules.Check_modules` | 0.071 s | 5.35 s | x75 |
| `linux.pagecache.InodePages` | 0.061 s | 4.5 s | x74 |
| `linux.pslist.PsList` | 0.068 s | 4.98 s | x73 |
| `linux.malware.check_creds.Check_creds` | 0.068 s | 4.98 s | x73 |
| `linux.mountinfo.MountInfo` | 0.073 s | 5.3 s | x73 |
| `linux.ip.Link` | 0.067 s | 4.85 s | x72 |
| `linux.malfind.Malfind` | 1.13 s | 81.7 s | x72 |
| `linux.iomem.IOMem` | 0.065 s | 4.66 s | x72 |
| `linux.ip.Addr` | 0.071 s | 4.99 s | x70 |
| `linux.malware.keyboard_notifiers.Keyboard_notifiers` | 0.147 s | 10.3 s | x70 |
| `linux.pstree.PsTree` | 0.074 s | 5.18 s | x70 |
| `linux.malware.process_spoofing.ProcessSpoofing` | 0.084 s | 5.8 s | x69 |
| `linux.elfs.Elfs` | 0.587 s | 40.1 s | x68 |
| `linux.lsof.Lsof` | 0.373 s | 25.1 s | x67 |
| `linux.psaux.PsAux` | 0.074 s | 4.9 s | x66 |
| `linux.malware.check_syscall.Check_syscall` | 0.174 s | 11.1 s | x64 |
| `linux.malware.malfind.Malfind` | 1.14 s | 71.6 s | x63 |
| `linux.check_syscall.Check_syscall` | 0.189 s | 11.6 s | x61 |
| `linux.bash.Bash` | 0.103 s | 6.22 s | x60 |
| `linux.malware.check_afinfo.Check_afinfo` | 0.155 s | 9.24 s | x60 |
| `linux.envars.Envars` | 0.08 s | 4.76 s | x59 |
| `linux.proc.Maps` | 1.4 s | 78.7 s | x56 |
| `linux.ptrace.Ptrace` | 0.092 s | 5.1 s | x55 |
| `linux.module_extract.ModuleExtract` | 0.014 s | 0.751 s | x54 |
| `linux.psscan.PsScan` | 0.18 s | 9.01 s | x50 |
| `linux.pagecache.Files` | 0.75 s | 36.1 s | x48 |
| `linux.hidden_modules.Hidden_modules` | 0.313 s | 11.2 s | x36 |
| `linux.modxview.Modxview` | 0.328 s | 10.0 s | x30 |
| `linux.malware.modxview.Modxview` | 0.408 s | 11.2 s | x27 |
| `linux.malware.hidden_modules.Hidden_modules` | 0.458 s | 10.6 s | x23 |
| `linux.vmaregexscan.VmaRegExScan` | 2.78 s | 63.1 s | x23 |
| `linux.kthreads.Kthreads` | 0.196 s | 4.18 s | x21 |
| `linux.tracing.ftrace.CheckFtrace` | 0.212 s | 3.87 s | x18 |
| `linux.sockscan.Sockscan` | 0.654 s | 8.95 s | x14 |
| `linux.vmcoreinfo.VMCoreInfo` | 0.469 s | 4.44 s | x9.5 |
| `linux.vmayarascan.VmaYaraScan` | 11.8 s | 110 s | x9.3 |
| `linux.pagecache.RecoverFs` | 18.9 s | 131 s | x6.9 |
| **60 plugins** | **47.2 s** | **2063 s** | **x44** |

## Windows 11 24H2, 4.3 GB crash dump

| Plugin | Rust | Python | Faster |
|---|---:|---:|---:|
| `windows.malfind.Malfind` | 0.57 s | 392 s | x688 |
| `windows.suspicious_threads.SuspiciousThreads` | 0.671 s | 461 s | x687 |
| `windows.malware.suspicious_threads.SuspiciousThreads` | 0.796 s | 488 s | x613 |
| `windows.malware.malfind.Malfind` | 0.664 s | 393 s | x592 |
| `windows.hollowprocesses.HollowProcesses` | 0.631 s | 326 s | x516 |
| `windows.vadinfo.VadInfo` | 0.99 s | 488 s | x493 |
| `configwriter.ConfigWriter` | 0.034 s | 16.7 s | x491 |
| `layerwriter.LayerWriter` | 0.039 s | 17.4 s | x446 |
| `windows.malware.hollowprocesses.HollowProcesses` | 0.876 s | 322 s | x367 |
| `windows.verinfo.VerInfo` | 0.582 s | 159 s | x273 |
| `windows.iat.IAT` | 0.155 s | 24.6 s | x159 |
| `windows.mftscan.MFTScan` | 0.973 s | 148 s | x152 |
| `windows.etwpatch.EtwPatch` | 0.461 s | 54.5 s | x118 |
| `windows.mftscan.ResidentData` | 0.632 s | 70.4 s | x111 |
| `windows.mftscan.ADS` | 0.603 s | 66.9 s | x111 |
| `windows.processghosting.ProcessGhosting` | 0.615 s | 61.3 s | x100 |
| `windows.malware.processghosting.ProcessGhosting` | 0.573 s | 52.4 s | x91 |
| `windows.threads.Threads` | 0.666 s | 57.8 s | x87 |
| `windows.consoles.Consoles` | 0.125 s | 10.8 s | x86 |
| `windows.getsids.GetSIDs` | 0.126 s | 10.4 s | x83 |
| `windows.debugregisters.DebugRegisters` | 0.629 s | 51.8 s | x82 |
| `windows.malware.unhooked_system_calls.UnhookedSystemCalls` | 0.623 s | 50.0 s | x80 |
| `windows.handles.Handles` | 1.74 s | 139 s | x80 |
| `windows.malware.ldrmodules.LdrModules` | 0.726 s | 58.1 s | x80 |
| `windows.registry.hivelist.HiveList` | 0.036 s | 2.86 s | x79 |
| `windows.bigpools.BigPools` | 0.16 s | 12.5 s | x78 |
| `windows.kpcrs.KPCRs` | 0.032 s | 2.49 s | x78 |
| `windows.registry.printkey.PrintKey` | 0.132 s | 10.2 s | x78 |
| `windows.timers.Timers` | 0.074 s | 5.67 s | x77 |
| `windows.vadwalk.VadWalk` | 0.734 s | 55.8 s | x76 |
| `windows.registry.amcache.Amcache` | 1.08 s | 81.2 s | x75 |
| `windows.skeleton_key_check.Skeleton_Key_Check` | 0.043 s | 3.21 s | x75 |
| `windows.registry.hivescan.HiveScan` | 0.103 s | 7.67 s | x74 |
| `windows.virtmap.VirtMap` | 0.039 s | 2.83 s | x73 |
| `windows.dumpfiles.DumpFiles` | 1.66 s | 119 s | x72 |
| `windows.unhooked_system_calls.unhooked_system_calls` | 0.67 s | 47.6 s | x71 |
| `windows.scheduled_tasks.ScheduledTasks` | 0.266 s | 18.9 s | x71 |
| `windows.suspended_threads.SuspendedThreads` | 0.058 s | 3.97 s | x68 |
| `windows.pslist.PsList` | 0.044 s | 2.99 s | x68 |
| `windows.modules.Modules` | 0.039 s | 2.59 s | x66 |
| `windows.amcache.Amcache` | 1.18 s | 77.2 s | x66 |
| `windows.registry.certificates.Certificates` | 0.23 s | 15.1 s | x65 |
| `windows.malware.skeleton_key_check.Skeleton_Key_Check` | 0.048 s | 3.07 s | x64 |
| `windows.registry.scheduled_tasks.ScheduledTasks` | 0.295 s | 18.3 s | x62 |
| `windows.dlllist.DllList` | 0.338 s | 20.9 s | x62 |
| `windows.info.Info` | 0.039 s | 2.36 s | x61 |
| `windows.privileges.Privs` | 0.057 s | 3.44 s | x60 |
| `windows.shimcachemem.ShimcacheMem` | 0.061 s | 3.66 s | x60 |
| `windows.ldrmodules.LdrModules` | 1.01 s | 60.6 s | x60 |
| `windows.cmdscan.CmdScan` | 0.241 s | 14.3 s | x59 |
| `windows.truecrypt.Passphrase` | 0.049 s | 2.87 s | x59 |
| `windows.joblinks.JobLinks` | 0.051 s | 2.95 s | x58 |
| `windows.ssdt.SSDT` | 0.06 s | 3.43 s | x57 |
| `windows.pstree.PsTree` | 0.056 s | 3.06 s | x55 |
| `windows.svclist.SvcList` | 0.61 s | 30.2 s | x50 |
| `banners.Banners` | 0.886 s | 43.6 s | x49 |
| `windows.envars.Envars` | 0.107 s | 5.26 s | x49 |
| `windows.getservicesids.GetServiceSIDs` | 0.15 s | 7.22 s | x48 |
| `windows.sessions.Sessions` | 0.071 s | 3.27 s | x46 |
| `windows.unloadedmodules.UnloadedModules` | 0.043 s | 1.97 s | x46 |
| `windows.netstat.NetStat` | 0.097 s | 4.11 s | x42 |
| `windows.cmdline.CmdLine` | 0.072 s | 3.05 s | x42 |
| `windows.registry.userassist.UserAssist` | 0.098 s | 4.09 s | x42 |
| `windows.malware.pebmasquerade.PebMasquerade` | 0.07 s | 2.81 s | x40 |
| `windows.crashinfo.Crashinfo` | 0.042 s | 1.61 s | x38 |
| `windows.statistics.Statistics` | 14.3 s | 508 s | x35 |
| `windows.mbrscan.MBRScan` | 1.56 s | 51.2 s | x33 |
| `timeliner.Timeliner` | 20.2 s | 656 s | x33 |
| `windows.malware.svcdiff.SvcDiff` | 1.28 s | 36.7 s | x29 |
| `windows.svcscan.SvcScan` | 1.32 s | 34.4 s | x26 |
| `frameworkinfo.FrameworkInfo` | 0.036 s | 0.9 s | x25 |
| `windows.thrdscan.ThrdScan` | 4 s | 99.0 s | x25 |
| `windows.svcdiff.SvcDiff` | 1.37 s | 31.2 s | x23 |
| `windows.filescan.FileScan` | 3.66 s | 79.5 s | x22 |
| `windows.poolscanner.PoolScanner` | 4.65 s | 98.3 s | x21 |
| `windows.vadregexscan.VadRegExScan` | 12.0 s | 195 s | x16 |
| `regexscan.RegExScan` | 3 s | 47.9 s | x16 |
| `windows.netscan.NetScan` | 3.05 s | 46.0 s | x15 |
| `windows.mutantscan.MutantScan` | 2.68 s | 39.5 s | x15 |
| `windows.orphan_kernel_threads.Threads` | 3.11 s | 45.6 s | x15 |
| `windows.windowstations.WindowStations` | 3.14 s | 42.6 s | x14 |
| `windows.psxview.PsXView` | 6.4 s | 85.6 s | x13 |
| `windows.modscan.ModScan` | 2.68 s | 35.2 s | x13 |
| `windows.malware.psxview.PsXView` | 5.84 s | 75.0 s | x13 |
| `windows.windows.Windows` | 3.21 s | 40.7 s | x13 |
| `windows.psscan.PsScan` | 3.06 s | 37.2 s | x12 |
| `windows.malware.drivermodule.DriverModule` | 2.93 s | 34.7 s | x12 |
| `vmscan.Vmscan` | 1.81 s | 20.7 s | x11 |
| `windows.devicetree.DeviceTree` | 3.25 s | 36.5 s | x11 |
| `windows.deskscan.DeskScan` | 3.14 s | 35.0 s | x11 |
| `windows.driverscan.DriverScan` | 2.76 s | 30.4 s | x11 |
| `windows.symlinkscan.SymlinkScan` | 3.42 s | 37.0 s | x11 |
| `windows.desktops.Desktops` | 3.97 s | 41.0 s | x10 |
| `windows.drivermodule.DriverModule` | 3.09 s | 31.7 s | x10 |
| `windows.driverirp.DriverIrp` | 3.94 s | 38.1 s | x9.7 |
| `windows.vadyarascan.VadYaraScan` | 71.0 s | 642 s | x9.0 |
| `windows.registry.getcellroutine.GetCellRoutine` | 0.915 s | 7.08 s | x7.7 |
| `windows.malware.indirect_system_calls.IndirectSystemCalls` | 67.5 s | 345 s | x5.1 |
| `windows.indirect_system_calls.IndirectSystemCalls` | 51.0 s | 168 s | x3.3 |
| `windows.malware.direct_system_calls.DirectSystemCalls` | 53.2 s | 174 s | x3.3 |
| `windows.direct_system_calls.DirectSystemCalls` | 57.2 s | 177 s | x3.1 |
| `yarascan.YaraScan` | 134 s | 55.0 s | x0.4 |
| **102 plugins** | **590 s** | **8797 s** | **x15** |

## Ubuntu 22.04, 4.3 GB VMware snapshot

| Plugin | Rust | Python | Faster |
|---|---:|---:|---:|
| `linux.sockstat.Sockstat` | 6.03 s | 2030 s | x337 |
| `timeliner.Timeliner` | 10.9 s | 1070 s | x98 |
| `linux.psscan.PsScan` | 1.32 s | 111 s | x84 |
| `linux.lsmod.Lsmod` | 0.356 s | 29.0 s | x82 |
| `linux.mountinfo.MountInfo` | 0.952 s | 70.3 s | x74 |
| `linux.lsof.Lsof` | 8.13 s | 535 s | x66 |
| `linux.pagecache.Files` | 3.39 s | 215 s | x64 |
| `linux.malware.netfilter.Netfilter` | 0.798 s | 49.9 s | x63 |
| `linux.kthreads.Kthreads` | 0.728 s | 43.3 s | x59 |
| `linux.elfs.Elfs` | 3.72 s | 217 s | x58 |
| `linux.capabilities.Capabilities` | 0.301 s | 17.1 s | x57 |
| `linux.netfilter.Netfilter` | 0.855 s | 45.8 s | x54 |
| `linux.malfind.Malfind` | 10.2 s | 543 s | x53 |
| `linux.tracing.ftrace.CheckFtrace` | 0.817 s | 42.7 s | x52 |
| `linux.malware.malfind.Malfind` | 10.7 s | 549 s | x51 |
| `layerwriter.LayerWriter` | 0.212 s | 10.7 s | x50 |
| `linux.proc.Maps` | 12.8 s | 642 s | x50 |
| `linux.pstree.PsTree` | 0.328 s | 16.2 s | x49 |
| `linux.check_creds.Check_creds` | 0.326 s | 16.1 s | x49 |
| `linux.check_idt.Check_idt` | 0.86 s | 41.8 s | x49 |
| `linux.malware.tty_check.Tty_Check` | 0.809 s | 39.3 s | x49 |
| `linux.ip.Link` | 0.338 s | 16.4 s | x48 |
| `linux.ptrace.Ptrace` | 0.432 s | 20.4 s | x47 |
| `linux.malware.check_idt.Check_idt` | 0.862 s | 40.5 s | x47 |
| `linux.graphics.fbdev.Fbdev` | 0.292 s | 13.7 s | x47 |
| `linux.keyboard_notifiers.Keyboard_notifiers` | 0.6 s | 27.6 s | x46 |
| `linux.pslist.PsList` | 0.376 s | 17.1 s | x46 |
| `linux.check_modules.Check_modules` | 0.353 s | 15.9 s | x45 |
| `linux.ebpf.EBPF` | 0.325 s | 14.6 s | x45 |
| `linux.tracing.perf_events.PerfEvents` | 0.439 s | 19.8 s | x45 |
| `linux.iomem.IOMem` | 0.313 s | 14.0 s | x45 |
| `linux.pidhashtable.PIDHashTable` | 0.467 s | 20.5 s | x44 |
| `linux.psaux.PsAux` | 0.387 s | 16.9 s | x44 |
| `linux.malware.check_creds.Check_creds` | 0.393 s | 16.7 s | x43 |
| `linux.malware.check_modules.Check_modules` | 0.381 s | 16.2 s | x43 |
| `linux.pagecache.InodePages` | 0.325 s | 13.8 s | x42 |
| `linux.tty_check.tty_check` | 0.902 s | 36.8 s | x41 |
| `linux.malware.process_spoofing.ProcessSpoofing` | 0.498 s | 19.0 s | x38 |
| `linux.envars.Envars` | 0.428 s | 15.8 s | x37 |
| `linux.boottime.Boottime` | 0.396 s | 14.5 s | x37 |
| `linux.modxview.Modxview` | 0.764 s | 27.6 s | x36 |
| `linux.ip.Addr` | 0.379 s | 13.7 s | x36 |
| `linux.malware.keyboard_notifiers.Keyboard_notifiers` | 0.778 s | 27.4 s | x35 |
| `linux.malware.check_afinfo.Check_afinfo` | 0.841 s | 28.5 s | x34 |
| `linux.check_afinfo.Check_afinfo` | 0.733 s | 24.4 s | x33 |
| `linux.malware.modxview.Modxview` | 0.847 s | 27.7 s | x33 |
| `linux.tracing.tracepoints.CheckTracepoints` | 0.859 s | 26.5 s | x31 |
| `banners.Banners` | 1.19 s | 35.7 s | x30 |
| `linux.check_syscall.Check_syscall` | 1.2 s | 33.1 s | x28 |
| `linux.bash.Bash` | 0.537 s | 14.6 s | x27 |
| `linux.malware.check_syscall.Check_syscall` | 1.32 s | 34.8 s | x26 |
| `configwriter.ConfigWriter` | 0.478 s | 9.65 s | x20 |
| `yarascan.YaraScan` | 5.57 s | 79.6 s | x14 |
| `regexscan.RegExScan` | 1.9 s | 18.2 s | x9.6 |
| `linux.vmayarascan.VmaYaraScan` | 79.6 s | 675 s | x8.5 |
| `linux.vmcoreinfo.VMCoreInfo` | 2.52 s | 20.8 s | x8.3 |
| `vmscan.Vmscan` | 1.91 s | 14.0 s | x7.3 |
| `frameworkinfo.FrameworkInfo` | 0.316 s | 0.68 s | x2.2 |
| **58 plugins** | **185 s** | **7817 s** | **x42** |

## Not comparable

| Plugin | Why |
|---|---|
| `windows.memmap.Memmap` | on the Windows 10 capture `vol` is killed for running out of memory part way through. Where it stops depends on how much memory is free at the time, so two `vol` runs do not agree with each other either. This port finishes all 9,014,410 lines, and every line `vol` wrote before dying matches. On the Windows XP capture both finish and the row for it is in that table above |
| `isfinfo.IsfInfo` | without `--live` upstream lists its own identifier database rather than the image, and the rows come back in that database's order. This port lists the symbol directories instead. Both describe the installation |

