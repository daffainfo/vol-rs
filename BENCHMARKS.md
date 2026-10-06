# Runtime against volatility3

Same plugin, same image, same machine, same arguments, byte-identical output, wall clock. One plugin at a time with warm caches and nothing else running. Only plugins where both tools finished and agreed byte for byte are listed.

The Rust column is the median of three runs after a discarded warm up run, measured at `e872b2c`. The Python column was measured the same way but not in the same pass, so a figure here is two measurements taken against the same image rather than a single race. `vol` is unchanged between them, and its runs had the page cache already warm, so where the two disagree the error favours `vol` and the ratio is the conservative one.

Every row was checked against the row count `vol` produced for the same plugin and arguments. A plugin whose output moved would not be timed here at all.

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

The figures below were measured on the Volatility Foundation's own test data, release [v0.0.1](https://github.com/volatilityfoundation/volatility3-test-data/releases/tag/v0.0.1).

| Image | Size | Format | System | Source |
|---|---:|---|---|---|
| `win-10_19041-2025_03.dmp` | 2.0 GB | Windows crash dump | Windows 10, build 19041, 120 processes | [win-10_19041-2025_03.dmp.gz](https://github.com/volatilityfoundation/volatility3-test-data/releases/download/v0.0.1/win-10_19041-2025_03.dmp.gz) |
| `win-xp-laptop-2005-06-25.img` | 512 MB | raw | Windows XP, 47 processes | [win-xp-laptop-2005-06-25.img.gz](https://github.com/volatilityfoundation/volatility3-test-data/releases/download/v0.0.1/win-xp-laptop-2005-06-25.img.gz) |
| `linux-sample-1.bin` | 512 MB | raw | Linux 3.2, 133 tasks | [linux-sample-1.bin.gz](https://github.com/volatilityfoundation/volatility3-test-data/releases/download/v0.0.1/linux-sample-1.bin.gz) |

Two larger captures check that the output stays byte identical on a recent Windows build and a recent Linux kernel.

| Image | Size | Format | System | Source |
|---|---:|---|---|---|
| `memory.dmp` | 4.3 GB | Windows crash dump | Windows 11 24H2, build 26100, 160 processes | [13Cubed Windows memory forensics](https://www.iblue.team/ctf-challenges/13cubed-windows-memory-forensics) |
| `memory.vmem` with `memory.vmsn` | 4.3 GB | VMware snapshot | Ubuntu 22.04, kernel 6.5.0-41, 344 tasks | [13Cubed Linux memory forensics](https://www.iblue.team/ctf-challenges/13cubed-linux-memory-forensics) |

## Windows 10 19041, 2.0 GB crash dump

| Plugin | Rust | Python | Faster |
|---|---:|---:|---:|
| `windows.malware.suspicious_threads.SuspiciousThreads` | 0.677 s | 346 s | x511 |
| `windows.suspicious_threads.SuspiciousThreads` | 0.677 s | 343 s | x507 |
| `windows.malfind.Malfind` | 0.734 s | 320 s | x436 |
| `windows.hollowprocesses.HollowProcesses` | 0.565 s | 244 s | x432 |
| `windows.malware.malfind.Malfind` | 0.73 s | 313 s | x429 |
| `windows.vadinfo.VadInfo` | 0.983 s | 412 s | x419 |
| `windows.malware.hollowprocesses.HollowProcesses` | 0.648 s | 240 s | x370 |
| `configwriter.ConfigWriter` | 0.043 s | 14.5 s | x337 |
| `layerwriter.LayerWriter` | 0.039 s | 11.9 s | x304 |
| `windows.registry.hivelist.HiveList` | 0.038 s | 7.54 s | x198 |
| `windows.etwpatch.EtwPatch` | 0.251 s | 49.0 s | x195 |
| `windows.info.Info` | 0.04 s | 7.57 s | x189 |
| `windows.hashdump.Hashdump` | 0.055 s | 10.2 s | x185 |
| `windows.kpcrs.KPCRs` | 0.04 s | 7.38 s | x184 |
| `windows.modules.Modules` | 0.04 s | 7.33 s | x183 |
| `windows.verinfo.VerInfo` | 0.339 s | 59.6 s | x176 |
| `windows.lsadump.Lsadump` | 0.057 s | 9.74 s | x171 |
| `windows.unloadedmodules.UnloadedModules` | 0.039 s | 6.53 s | x167 |
| `windows.truecrypt.Passphrase` | 0.04 s | 6.55 s | x164 |
| `windows.skeleton_key_check.Skeleton_Key_Check` | 0.051 s | 8.34 s | x164 |
| `windows.pslist.PsList` | 0.041 s | 6.55 s | x160 |
| `windows.cachedump.Cachedump` | 0.057 s | 9.01 s | x158 |
| `windows.joblinks.JobLinks` | 0.049 s | 7.64 s | x156 |
| `windows.ssdt.SSDT` | 0.056 s | 8.52 s | x152 |
| `windows.shimcachemem.ShimcacheMem` | 0.051 s | 7.51 s | x147 |
| `windows.getsids.GetSIDs` | 0.093 s | 13.1 s | x141 |
| `windows.registry.cachedump.Cachedump` | 0.063 s | 8.84 s | x140 |
| `windows.malware.skeleton_key_check.Skeleton_Key_Check` | 0.048 s | 6.66 s | x139 |
| `windows.virtmap.VirtMap` | 0.044 s | 6.05 s | x138 |
| `windows.iat.IAT` | 0.149 s | 20.1 s | x135 |
| `windows.registry.hashdump.Hashdump` | 0.062 s | 8.27 s | x133 |
| `windows.crashinfo.Crashinfo` | 0.042 s | 5.54 s | x132 |
| `windows.pstree.PsTree` | 0.06 s | 7.89 s | x132 |
| `windows.registry.hivescan.HiveScan` | 0.092 s | 12.0 s | x130 |
| `windows.timers.Timers` | 0.062 s | 8.01 s | x129 |
| `windows.registry.lsadump.Lsadump` | 0.069 s | 8.83 s | x128 |
| `windows.envars.Envars` | 0.073 s | 9.19 s | x126 |
| `windows.privileges.Privs` | 0.057 s | 6.92 s | x121 |
| `windows.cmdline.CmdLine` | 0.058 s | 6.89 s | x119 |
| `windows.bigpools.BigPools` | 0.133 s | 15.5 s | x117 |
| `windows.threads.Threads` | 0.452 s | 51.3 s | x113 |
| `windows.suspended_threads.SuspendedThreads` | 0.06 s | 6.7 s | x112 |
| `windows.mftscan.MFTScan` | 0.423 s | 46.1 s | x109 |
| `windows.getservicesids.GetServiceSIDs` | 0.101 s | 10.5 s | x104 |
| `windows.registry.userassist.UserAssist` | 0.095 s | 9.5 s | x100 |
| `windows.dumpfiles.DumpFiles` | 1.07 s | 106 s | x99 |
| `windows.consoles.Consoles` | 0.106 s | 10.5 s | x99 |
| `windows.ldrmodules.LdrModules` | 0.557 s | 54.0 s | x97 |
| `windows.debugregisters.DebugRegisters` | 0.483 s | 46.1 s | x95 |
| `windows.sessions.Sessions` | 0.076 s | 7.24 s | x95 |
| `windows.mftscan.ResidentData` | 0.287 s | 27.0 s | x94 |
| `windows.malware.pebmasquerade.PebMasquerade` | 0.084 s | 7.63 s | x91 |
| `windows.mftscan.ADS` | 0.303 s | 27.2 s | x90 |
| `windows.vadwalk.VadWalk` | 0.624 s | 55.3 s | x89 |
| `windows.malware.ldrmodules.LdrModules` | 0.583 s | 49.8 s | x85 |
| `windows.dlllist.DllList` | 0.284 s | 24.2 s | x85 |
| `windows.registry.printkey.PrintKey` | 0.126 s | 10.6 s | x84 |
| `windows.netstat.NetStat` | 0.085 s | 7.01 s | x82 |
| `windows.unhooked_system_calls.unhooked_system_calls` | 0.506 s | 41.4 s | x82 |
| `windows.handles.Handles` | 1.33 s | 108 s | x81 |
| `windows.malware.unhooked_system_calls.UnhookedSystemCalls` | 0.568 s | 46.1 s | x81 |
| `windows.cmdscan.CmdScan` | 0.201 s | 16.1 s | x80 |
| `windows.registry.amcache.Amcache` | 0.283 s | 22.2 s | x78 |
| `windows.registry.certificates.Certificates` | 0.184 s | 14.2 s | x77 |
| `windows.malware.processghosting.ProcessGhosting` | 0.621 s | 47.5 s | x76 |
| `windows.registry.scheduled_tasks.ScheduledTasks` | 0.361 s | 27.4 s | x76 |
| `windows.processghosting.ProcessGhosting` | 0.664 s | 50.2 s | x76 |
| `windows.amcache.Amcache` | 0.302 s | 22.4 s | x74 |
| `windows.pe_symbols.PESymbols` | 0.012 s | 0.815 s | x68 |
| `banners.Banners` | 0.396 s | 25.7 s | x65 |
| `windows.svclist.SvcList` | 0.406 s | 24.7 s | x61 |
| `windows.statistics.Statistics` | 9.41 s | 537 s | x57 |
| `timeliner.Timeliner` | 5.45 s | 310 s | x57 |
| `windows.pedump.PEDump` | 0.014 s | 0.779 s | x56 |
| `windows.strings.Strings` | 0.012 s | 0.612 s | x51 |
| `windows.thrdscan.ThrdScan` | 1.33 s | 64.7 s | x49 |
| `windows.scheduled_tasks.ScheduledTasks` | 0.543 s | 25.8 s | x48 |
| `windows.filescan.FileScan` | 0.925 s | 40.2 s | x43 |
| `windows.mbrscan.MBRScan` | 1.16 s | 44.4 s | x38 |
| `regexscan.RegExScan` | 0.715 s | 23.2 s | x32 |
| `windows.orphan_kernel_threads.Threads` | 0.899 s | 28.8 s | x32 |
| `windows.malware.psxview.PsXView` | 1.47 s | 45.5 s | x31 |
| `yarascan.YaraScan` | 0.867 s | 25.2 s | x29 |
| `windows.malware.svcdiff.SvcDiff` | 0.981 s | 28.4 s | x29 |
| `windows.drivermodule.DriverModule` | 0.787 s | 22.7 s | x29 |
| `windows.symlinkscan.SymlinkScan` | 0.738 s | 21.2 s | x29 |
| `windows.psxview.PsXView` | 1.52 s | 43.0 s | x28 |
| `windows.deskscan.DeskScan` | 0.755 s | 20.9 s | x28 |
| `windows.malware.drivermodule.DriverModule` | 0.812 s | 22.4 s | x28 |
| `windows.driverscan.DriverScan` | 0.716 s | 19.5 s | x27 |
| `windows.devicetree.DeviceTree` | 0.753 s | 20.5 s | x27 |
| `windows.driverirp.DriverIrp` | 0.81 s | 20.8 s | x26 |
| `windows.desktops.Desktops` | 1.16 s | 29.7 s | x26 |
| `windows.netscan.NetScan` | 0.773 s | 19.5 s | x25 |
| `windows.mutantscan.MutantScan` | 0.801 s | 19.3 s | x24 |
| `windows.windowstations.WindowStations` | 0.981 s | 23.2 s | x24 |
| `windows.vadregexscan.VadRegExScan` | 6.48 s | 153 s | x24 |
| `windows.windows.Windows` | 1.06 s | 24.2 s | x23 |
| `windows.svcscan.SvcScan` | 1.14 s | 25.5 s | x22 |
| `windows.svcdiff.SvcDiff` | 1.33 s | 28.5 s | x21 |
| `windows.psscan.PsScan` | 0.911 s | 19.4 s | x21 |
| `windows.modscan.ModScan` | 0.9 s | 19.1 s | x21 |
| `windows.callbacks.Callbacks` | 1.02 s | 21.3 s | x21 |
| `windows.registry.getcellroutine.GetCellRoutine` | 0.417 s | 8.28 s | x20 |
| `windows.poolscanner.PoolScanner` | 3.17 s | 52.6 s | x17 |
| `vmscan.Vmscan` | 0.859 s | 14.1 s | x16 |
| `windows.vadyarascan.VadYaraScan` | 38.7 s | 364 s | x9.4 |
| `windows.malware.indirect_system_calls.IndirectSystemCalls` | 42.2 s | 183 s | x4.3 |
| `windows.indirect_system_calls.IndirectSystemCalls` | 32.5 s | 135 s | x4.2 |
| `windows.direct_system_calls.DirectSystemCalls` | 36.1 s | 135 s | x3.7 |
| `windows.malware.direct_system_calls.DirectSystemCalls` | 34.4 s | 119 s | x3.5 |
| **111 plugins** | **255 s** | **6370 s** | **x25** |

## Windows XP, 512 MB raw capture

| Plugin | Rust | Python | Faster |
|---|---:|---:|---:|
| `windows.suspicious_threads.SuspiciousThreads` | 0.184 s | 34.5 s | x188 |
| `windows.malware.suspicious_threads.SuspiciousThreads` | 0.2 s | 33.2 s | x166 |
| `windows.malware.hollowprocesses.HollowProcesses` | 0.209 s | 31.0 s | x148 |
| `windows.vadinfo.VadInfo` | 0.263 s | 38.5 s | x146 |
| `windows.hollowprocesses.HollowProcesses` | 0.207 s | 28.1 s | x136 |
| `windows.mftscan.ResidentData` | 0.205 s | 27.6 s | x135 |
| `windows.malfind.Malfind` | 0.203 s | 26.3 s | x130 |
| `windows.mftscan.MFTScan` | 0.393 s | 48.2 s | x123 |
| `windows.malware.malfind.Malfind` | 0.24 s | 28.2 s | x118 |
| `windows.verinfo.VerInfo` | 0.215 s | 25.1 s | x117 |
| `windows.processghosting.ProcessGhosting` | 0.141 s | 15.0 s | x106 |
| `windows.mftscan.ADS` | 0.236 s | 25.0 s | x106 |
| `windows.etwpatch.EtwPatch` | 0.147 s | 15.2 s | x103 |
| `windows.iat.IAT` | 0.111 s | 11.4 s | x103 |
| `windows.amcache.Amcache` | 0.073 s | 7.09 s | x97 |
| `windows.windows.Windows` | 0.068 s | 6.6 s | x97 |
| `configwriter.ConfigWriter` | 0.073 s | 7.07 s | x97 |
| `timeliner.Timeliner` | 1.31 s | 126 s | x96 |
| `windows.registry.cachedump.Cachedump` | 0.084 s | 7.78 s | x93 |
| `windows.shimcachemem.ShimcacheMem` | 0.115 s | 10.5 s | x91 |
| `windows.privileges.Privs` | 0.074 s | 6.71 s | x91 |
| `windows.registry.hashdump.Hashdump` | 0.094 s | 8.32 s | x89 |
| `windows.cmdscan.CmdScan` | 0.093 s | 8.2 s | x88 |
| `windows.modules.Modules` | 0.067 s | 5.9 s | x88 |
| `windows.cachedump.Cachedump` | 0.086 s | 7.56 s | x88 |
| `windows.unhooked_system_calls.unhooked_system_calls` | 0.152 s | 13.3 s | x88 |
| `windows.dlllist.DllList` | 0.122 s | 10.5 s | x86 |
| `windows.netstat.NetStat` | 0.073 s | 6.24 s | x85 |
| `windows.desktops.Desktops` | 0.072 s | 6.15 s | x85 |
| `windows.registry.printkey.PrintKey` | 0.096 s | 8.11 s | x84 |
| `windows.registry.lsadump.Lsadump` | 0.13 s | 10.7 s | x82 |
| `windows.strings.Strings` | 0.012 s | 0.978 s | x82 |
| `windows.pslist.PsList` | 0.07 s | 5.67 s | x81 |
| `windows.ssdt.SSDT` | 0.079 s | 6.34 s | x80 |
| `windows.threads.Threads` | 0.162 s | 13.0 s | x80 |
| `windows.lsadump.Lsadump` | 0.123 s | 9.85 s | x80 |
| `windows.unloadedmodules.UnloadedModules` | 0.064 s | 5.1 s | x80 |
| `windows.malware.svcdiff.SvcDiff` | 0.07 s | 5.54 s | x79 |
| `windows.deskscan.DeskScan` | 0.08 s | 6.33 s | x79 |
| `windows.truecrypt.Passphrase` | 0.067 s | 5.3 s | x79 |
| `windows.registry.getcellroutine.GetCellRoutine` | 0.09 s | 7.09 s | x79 |
| `windows.thrdscan.ThrdScan` | 0.23 s | 18.1 s | x79 |
| `windows.cmdline.CmdLine` | 0.072 s | 5.65 s | x78 |
| `windows.crashinfo.Crashinfo` | 0.075 s | 5.84 s | x78 |
| `windows.windowstations.WindowStations` | 0.072 s | 5.59 s | x78 |
| `windows.svcdiff.SvcDiff` | 0.07 s | 5.42 s | x77 |
| `windows.kpcrs.KPCRs` | 0.067 s | 5.18 s | x77 |
| `windows.malware.processghosting.ProcessGhosting` | 0.161 s | 12.1 s | x75 |
| `windows.filescan.FileScan` | 0.321 s | 24.1 s | x75 |
| `windows.malware.skeleton_key_check.Skeleton_Key_Check` | 0.064 s | 4.8 s | x75 |
| `windows.netscan.NetScan` | 0.073 s | 5.46 s | x75 |
| `windows.vadwalk.VadWalk` | 0.176 s | 13.1 s | x74 |
| `windows.ldrmodules.LdrModules` | 0.195 s | 14.5 s | x74 |
| `windows.registry.scheduled_tasks.ScheduledTasks` | 0.06 s | 4.45 s | x74 |
| `windows.pedump.PEDump` | 0.013 s | 0.952 s | x73 |
| `windows.suspended_threads.SuspendedThreads` | 0.073 s | 5.3 s | x73 |
| `windows.pstree.PsTree` | 0.088 s | 6.33 s | x72 |
| `windows.timers.Timers` | 0.101 s | 7.24 s | x72 |
| `windows.malware.pebmasquerade.PebMasquerade` | 0.079 s | 5.64 s | x71 |
| `windows.joblinks.JobLinks` | 0.07 s | 4.99 s | x71 |
| `windows.skeleton_key_check.Skeleton_Key_Check` | 0.078 s | 5.56 s | x71 |
| `windows.info.Info` | 0.07 s | 4.95 s | x71 |
| `windows.registry.certificates.Certificates` | 0.163 s | 11.4 s | x70 |
| `windows.virtmap.VirtMap` | 0.095 s | 6.64 s | x70 |
| `windows.registry.hivelist.HiveList` | 0.088 s | 6.15 s | x70 |
| `windows.sessions.Sessions` | 0.071 s | 4.95 s | x70 |
| `windows.hashdump.Hashdump` | 0.098 s | 6.83 s | x70 |
| `windows.scheduled_tasks.ScheduledTasks` | 0.07 s | 4.83 s | x69 |
| `windows.consoles.Consoles` | 0.133 s | 9.13 s | x69 |
| `windows.bigpools.BigPools` | 0.076 s | 5.18 s | x68 |
| `layerwriter.LayerWriter` | 0.091 s | 6.19 s | x68 |
| `windows.registry.amcache.Amcache` | 0.08 s | 5.39 s | x67 |
| `windows.driverirp.DriverIrp` | 0.179 s | 12.0 s | x67 |
| `windows.orphan_kernel_threads.Threads` | 0.189 s | 12.4 s | x66 |
| `windows.devicetree.DeviceTree` | 0.168 s | 10.9 s | x65 |
| `windows.driverscan.DriverScan` | 0.148 s | 9.6 s | x65 |
| `windows.malware.ldrmodules.LdrModules` | 0.205 s | 13.2 s | x64 |
| `windows.psxview.PsXView` | 0.348 s | 22.4 s | x64 |
| `windows.getservicesids.GetServiceSIDs` | 0.074 s | 4.68 s | x63 |
| `windows.handles.Handles` | 0.549 s | 34.5 s | x63 |
| `windows.envars.Envars` | 0.101 s | 6.32 s | x63 |
| `windows.registry.userassist.UserAssist` | 0.1 s | 6.12 s | x61 |
| `yarascan.YaraScan` | 0.25 s | 15.3 s | x61 |
| `windows.pe_symbols.PESymbols` | 0.012 s | 0.728 s | x61 |
| `windows.psscan.PsScan` | 0.19 s | 11.5 s | x61 |
| `windows.drivermodule.DriverModule` | 0.169 s | 10.1 s | x60 |
| `windows.getsids.GetSIDs` | 0.109 s | 6.44 s | x59 |
| `windows.modscan.ModScan` | 0.117 s | 6.6 s | x56 |
| `windows.svclist.SvcList` | 0.097 s | 5.43 s | x56 |
| `windows.statistics.Statistics` | 0.116 s | 6.49 s | x56 |
| `banners.Banners` | 0.163 s | 9.04 s | x55 |
| `windows.malware.unhooked_system_calls.UnhookedSystemCalls` | 0.235 s | 12.9 s | x55 |
| `windows.malware.drivermodule.DriverModule` | 0.174 s | 9.41 s | x54 |
| `windows.poolscanner.PoolScanner` | 0.843 s | 45.2 s | x54 |
| `windows.svcscan.SvcScan` | 0.105 s | 5.61 s | x53 |
| `windows.malware.psxview.PsXView` | 0.324 s | 17.0 s | x52 |
| `windows.registry.hivescan.HiveScan` | 0.125 s | 6.23 s | x50 |
| `windows.dumpfiles.DumpFiles` | 1.57 s | 77.1 s | x49 |
| `windows.mutantscan.MutantScan` | 0.142 s | 6.82 s | x48 |
| `windows.symlinkscan.SymlinkScan` | 0.145 s | 6.3 s | x43 |
| `vmscan.Vmscan` | 0.203 s | 7.31 s | x36 |
| `windows.mbrscan.MBRScan` | 0.301 s | 10.0 s | x33 |
| `windows.vadregexscan.VadRegExScan` | 0.487 s | 15.3 s | x31 |
| `regexscan.RegExScan` | 0.303 s | 8.06 s | x27 |
| `windows.memmap.Memmap` | 6.86 s | 156 s | x23 |
| `windows.callbacks.Callbacks` | 0.595 s | 9.95 s | x17 |
| `windows.vadyarascan.VadYaraScan` | 1.25 s | 20.3 s | x16 |
| `windows.debugregisters.DebugRegisters` | 2.1 s | 21.3 s | x10 |
| `windows.direct_system_calls.DirectSystemCalls` | 4.92 s | 23.5 s | x4.8 |
| `windows.malware.direct_system_calls.DirectSystemCalls` | 4.51 s | 21.4 s | x4.7 |
| `windows.malware.indirect_system_calls.IndirectSystemCalls` | 5.74 s | 26.9 s | x4.7 |
| `windows.indirect_system_calls.IndirectSystemCalls` | 4.98 s | 19.9 s | x4.0 |
| **112 plugins** | **48.9 s** | **1671 s** | **x34** |

## Linux 3.2, 512 MB raw capture

| Plugin | Rust | Python | Faster |
|---|---:|---:|---:|
| `linux.library_list.LibraryList` | 0.525 s | 917 s | x1747 |
| `linux.pscallstack.PsCallStack` | 0.31 s | 98.8 s | x319 |
| `linux.lsmod.Lsmod` | 0.059 s | 9.58 s | x162 |
| `linux.malware.check_idt.Check_idt` | 0.11 s | 15.2 s | x138 |
| `linux.check_idt.Check_idt` | 0.115 s | 15.1 s | x131 |
| `linux.tty_check.tty_check` | 0.114 s | 14.3 s | x125 |
| `linux.malware.tty_check.Tty_Check` | 0.129 s | 15.0 s | x116 |
| `linux.malware.check_modules.Check_modules` | 0.055 s | 5.74 s | x104 |
| `linux.kallsyms.Kallsyms` | 0.278 s | 28.9 s | x104 |
| `linux.capabilities.Capabilities` | 0.056 s | 5.82 s | x104 |
| `linux.malware.netfilter.Netfilter` | 0.111 s | 11.3 s | x102 |
| `linux.keyboard_notifiers.Keyboard_notifiers` | 0.111 s | 10.8 s | x97 |
| `linux.check_creds.Check_creds` | 0.057 s | 5.5 s | x96 |
| `linux.mountinfo.MountInfo` | 0.055 s | 5.3 s | x96 |
| `linux.sockstat.Sockstat` | 0.236 s | 22.1 s | x94 |
| `linux.netfilter.Netfilter` | 0.118 s | 10.9 s | x92 |
| `linux.pidhashtable.PIDHashTable` | 0.067 s | 5.99 s | x89 |
| `linux.boottime.Boottime` | 0.062 s | 5.48 s | x88 |
| `linux.check_afinfo.Check_afinfo` | 0.111 s | 9.73 s | x88 |
| `linux.pslist.PsList` | 0.057 s | 4.98 s | x87 |
| `linux.tracing.tracepoints.CheckTracepoints` | 0.139 s | 11.7 s | x84 |
| `linux.kmsg.Kmsg` | 0.058 s | 4.86 s | x84 |
| `linux.iomem.IOMem` | 0.056 s | 4.66 s | x83 |
| `linux.tracing.perf_events.PerfEvents` | 0.063 s | 5.18 s | x82 |
| `linux.pstree.PsTree` | 0.063 s | 5.18 s | x82 |
| `linux.malfind.Malfind` | 0.994 s | 81.7 s | x82 |
| `linux.graphics.fbdev.Fbdev` | 0.054 s | 4.3 s | x80 |
| `linux.malware.keyboard_notifiers.Keyboard_notifiers` | 0.134 s | 10.3 s | x77 |
| `linux.pagecache.InodePages` | 0.059 s | 4.5 s | x76 |
| `linux.malware.process_spoofing.ProcessSpoofing` | 0.079 s | 5.8 s | x73 |
| `linux.ip.Link` | 0.067 s | 4.85 s | x72 |
| `linux.elfs.Elfs` | 0.554 s | 40.1 s | x72 |
| `linux.check_syscall.Check_syscall` | 0.166 s | 11.6 s | x70 |
| `linux.bash.Bash` | 0.091 s | 6.22 s | x68 |
| `linux.module_extract.ModuleExtract` | 0.011 s | 0.751 s | x68 |
| `linux.check_modules.Check_modules` | 0.079 s | 5.35 s | x68 |
| `linux.malware.malfind.Malfind` | 1.07 s | 71.6 s | x67 |
| `linux.ptrace.Ptrace` | 0.078 s | 5.1 s | x65 |
| `linux.proc.Maps` | 1.23 s | 78.7 s | x64 |
| `linux.envars.Envars` | 0.075 s | 4.76 s | x63 |
| `linux.ebpf.EBPF` | 0.072 s | 4.49 s | x62 |
| `linux.malware.check_creds.Check_creds` | 0.08 s | 4.98 s | x62 |
| `linux.lsof.Lsof` | 0.404 s | 25.1 s | x62 |
| `linux.malware.check_afinfo.Check_afinfo` | 0.149 s | 9.24 s | x62 |
| `linux.pagecache.Files` | 0.601 s | 36.1 s | x60 |
| `linux.ip.Addr` | 0.086 s | 4.99 s | x58 |
| `linux.malware.check_syscall.Check_syscall` | 0.195 s | 11.1 s | x57 |
| `linux.psaux.PsAux` | 0.089 s | 4.9 s | x55 |
| `linux.psscan.PsScan` | 0.181 s | 9.01 s | x50 |
| `linux.malware.hidden_modules.Hidden_modules` | 0.267 s | 10.6 s | x40 |
| `linux.modxview.Modxview` | 0.254 s | 10.0 s | x39 |
| `linux.malware.modxview.Modxview` | 0.289 s | 11.2 s | x39 |
| `linux.hidden_modules.Hidden_modules` | 0.298 s | 11.2 s | x38 |
| `linux.kthreads.Kthreads` | 0.112 s | 4.18 s | x37 |
| `linux.tracing.ftrace.CheckFtrace` | 0.111 s | 3.87 s | x35 |
| `linux.vmaregexscan.VmaRegExScan` | 2.13 s | 63.1 s | x30 |
| `linux.vmcoreinfo.VMCoreInfo` | 0.205 s | 4.44 s | x22 |
| `linux.vmayarascan.VmaYaraScan` | 5.32 s | 110 s | x21 |
| `linux.sockscan.Sockscan` | 0.436 s | 8.95 s | x21 |
| `linux.pagecache.RecoverFs` | 17.4 s | 131 s | x7.5 |
| **60 plugins** | **36.6 s** | **2063 s** | **x56** |

## Windows 11 24H2, 4.3 GB crash dump

| Plugin | Rust | Python | Faster |
|---|---:|---:|---:|
| `windows.malfind.Malfind` | 0.494 s | 392 s | x793 |
| `windows.malware.suspicious_threads.SuspiciousThreads` | 0.621 s | 488 s | x786 |
| `windows.malware.malfind.Malfind` | 0.569 s | 393 s | x691 |
| `windows.suspicious_threads.SuspiciousThreads` | 0.739 s | 461 s | x624 |
| `windows.hollowprocesses.HollowProcesses` | 0.646 s | 326 s | x504 |
| `windows.malware.hollowprocesses.HollowProcesses` | 0.661 s | 322 s | x487 |
| `layerwriter.LayerWriter` | 0.044 s | 17.4 s | x395 |
| `configwriter.ConfigWriter` | 0.046 s | 16.7 s | x363 |
| `windows.vadinfo.VadInfo` | 1.36 s | 488 s | x358 |
| `windows.verinfo.VerInfo` | 0.541 s | 159 s | x294 |
| `windows.iat.IAT` | 0.168 s | 24.6 s | x146 |
| `windows.mftscan.MFTScan` | 1.01 s | 148 s | x146 |
| `windows.etwpatch.EtwPatch` | 0.382 s | 54.5 s | x143 |
| `windows.threads.Threads` | 0.555 s | 57.8 s | x104 |
| `windows.mftscan.ResidentData` | 0.737 s | 70.4 s | x95 |
| `windows.mftscan.ADS` | 0.721 s | 66.9 s | x93 |
| `windows.getsids.GetSIDs` | 0.113 s | 10.4 s | x92 |
| `windows.processghosting.ProcessGhosting` | 0.681 s | 61.3 s | x90 |
| `windows.dumpfiles.DumpFiles` | 1.35 s | 119 s | x88 |
| `windows.handles.Handles` | 1.61 s | 139 s | x86 |
| `windows.virtmap.VirtMap` | 0.033 s | 2.83 s | x86 |
| `windows.malware.unhooked_system_calls.UnhookedSystemCalls` | 0.6 s | 50.0 s | x83 |
| `windows.timers.Timers` | 0.068 s | 5.67 s | x83 |
| `windows.bigpools.BigPools` | 0.152 s | 12.5 s | x82 |
| `windows.unhooked_system_calls.unhooked_system_calls` | 0.588 s | 47.6 s | x81 |
| `windows.debugregisters.DebugRegisters` | 0.68 s | 51.8 s | x76 |
| `windows.malware.processghosting.ProcessGhosting` | 0.698 s | 52.4 s | x75 |
| `windows.vadwalk.VadWalk` | 0.747 s | 55.8 s | x75 |
| `windows.pslist.PsList` | 0.042 s | 2.99 s | x71 |
| `windows.pstree.PsTree` | 0.043 s | 3.06 s | x71 |
| `windows.envars.Envars` | 0.074 s | 5.26 s | x71 |
| `windows.truecrypt.Passphrase` | 0.041 s | 2.87 s | x70 |
| `windows.consoles.Consoles` | 0.155 s | 10.8 s | x70 |
| `windows.dlllist.DllList` | 0.305 s | 20.9 s | x68 |
| `windows.skeleton_key_check.Skeleton_Key_Check` | 0.047 s | 3.21 s | x68 |
| `windows.ldrmodules.LdrModules` | 0.89 s | 60.6 s | x68 |
| `windows.amcache.Amcache` | 1.16 s | 77.2 s | x67 |
| `windows.registry.printkey.PrintKey` | 0.155 s | 10.2 s | x66 |
| `windows.registry.hivescan.HiveScan` | 0.116 s | 7.67 s | x66 |
| `windows.malware.ldrmodules.LdrModules` | 0.885 s | 58.1 s | x66 |
| `windows.registry.amcache.Amcache` | 1.26 s | 81.2 s | x65 |
| `windows.kpcrs.KPCRs` | 0.039 s | 2.49 s | x64 |
| `windows.info.Info` | 0.037 s | 2.36 s | x64 |
| `windows.cmdscan.CmdScan` | 0.227 s | 14.3 s | x63 |
| `windows.registry.hivelist.HiveList` | 0.046 s | 2.86 s | x62 |
| `windows.malware.skeleton_key_check.Skeleton_Key_Check` | 0.051 s | 3.07 s | x60 |
| `windows.shimcachemem.ShimcacheMem` | 0.061 s | 3.66 s | x60 |
| `windows.registry.certificates.Certificates` | 0.253 s | 15.1 s | x59 |
| `windows.unloadedmodules.UnloadedModules` | 0.034 s | 1.97 s | x58 |
| `windows.svclist.SvcList` | 0.537 s | 30.2 s | x56 |
| `windows.suspended_threads.SuspendedThreads` | 0.071 s | 3.97 s | x56 |
| `windows.privileges.Privs` | 0.064 s | 3.44 s | x54 |
| `windows.getservicesids.GetServiceSIDs` | 0.135 s | 7.22 s | x53 |
| `windows.registry.scheduled_tasks.ScheduledTasks` | 0.344 s | 18.3 s | x53 |
| `windows.modules.Modules` | 0.05 s | 2.59 s | x52 |
| `windows.scheduled_tasks.ScheduledTasks` | 0.365 s | 18.9 s | x52 |
| `windows.ssdt.SSDT` | 0.067 s | 3.43 s | x51 |
| `windows.joblinks.JobLinks` | 0.059 s | 2.95 s | x50 |
| `timeliner.Timeliner` | 13.8 s | 656 s | x47 |
| `windows.netstat.NetStat` | 0.088 s | 4.11 s | x47 |
| `windows.thrdscan.ThrdScan` | 2.15 s | 99.0 s | x46 |
| `windows.cmdline.CmdLine` | 0.073 s | 3.05 s | x42 |
| `windows.sessions.Sessions` | 0.083 s | 3.27 s | x39 |
| `banners.Banners` | 1.12 s | 43.6 s | x39 |
| `windows.filescan.FileScan` | 2.06 s | 79.5 s | x39 |
| `windows.crashinfo.Crashinfo` | 0.042 s | 1.61 s | x38 |
| `windows.statistics.Statistics` | 14.1 s | 508 s | x36 |
| `windows.malware.pebmasquerade.PebMasquerade` | 0.078 s | 2.81 s | x36 |
| `windows.registry.userassist.UserAssist` | 0.124 s | 4.09 s | x33 |
| `windows.malware.svcdiff.SvcDiff` | 1.17 s | 36.7 s | x31 |
| `windows.mbrscan.MBRScan` | 1.67 s | 51.2 s | x31 |
| `windows.orphan_kernel_threads.Threads` | 1.66 s | 45.6 s | x27 |
| `yarascan.YaraScan` | 2.1 s | 55.0 s | x26 |
| `windows.poolscanner.PoolScanner` | 3.77 s | 98.3 s | x26 |
| `windows.svcdiff.SvcDiff` | 1.21 s | 31.2 s | x26 |
| `windows.netscan.NetScan` | 1.81 s | 46.0 s | x25 |
| `windows.psxview.PsXView` | 3.56 s | 85.6 s | x24 |
| `windows.vadregexscan.VadRegExScan` | 8.14 s | 195 s | x24 |
| `windows.psscan.PsScan` | 1.58 s | 37.2 s | x24 |
| `windows.svcscan.SvcScan` | 1.56 s | 34.4 s | x22 |
| `windows.windows.Windows` | 1.85 s | 40.7 s | x22 |
| `regexscan.RegExScan` | 2.18 s | 47.9 s | x22 |
| `windows.malware.psxview.PsXView` | 3.5 s | 75.0 s | x21 |
| `windows.symlinkscan.SymlinkScan` | 1.73 s | 37.0 s | x21 |
| `windows.modscan.ModScan` | 1.66 s | 35.2 s | x21 |
| `windows.windowstations.WindowStations` | 2.02 s | 42.6 s | x21 |
| `windows.driverirp.DriverIrp` | 1.83 s | 38.1 s | x21 |
| `windows.malware.drivermodule.DriverModule` | 1.71 s | 34.7 s | x20 |
| `windows.mutantscan.MutantScan` | 1.95 s | 39.5 s | x20 |
| `frameworkinfo.FrameworkInfo` | 0.047 s | 0.9 s | x19 |
| `windows.drivermodule.DriverModule` | 1.74 s | 31.7 s | x18 |
| `windows.driverscan.DriverScan` | 1.72 s | 30.4 s | x18 |
| `windows.devicetree.DeviceTree` | 2.22 s | 36.5 s | x16 |
| `windows.desktops.Desktops` | 2.63 s | 41.0 s | x16 |
| `vmscan.Vmscan` | 1.68 s | 20.7 s | x12 |
| `windows.deskscan.DeskScan` | 3.15 s | 35.0 s | x11 |
| `windows.vadyarascan.VadYaraScan` | 59.4 s | 642 s | x11 |
| `windows.malware.indirect_system_calls.IndirectSystemCalls` | 51.9 s | 345 s | x6.7 |
| `windows.registry.getcellroutine.GetCellRoutine` | 1.17 s | 7.08 s | x6.1 |
| `windows.direct_system_calls.DirectSystemCalls` | 38.9 s | 177 s | x4.5 |
| `windows.malware.direct_system_calls.DirectSystemCalls` | 40.1 s | 174 s | x4.3 |
| `windows.indirect_system_calls.IndirectSystemCalls` | 39.6 s | 168 s | x4.3 |
| **102 plugins** | **349 s** | **8797 s** | **x25** |

## Ubuntu 22.04, 4.3 GB VMware snapshot

| Plugin | Rust | Python | Faster |
|---|---:|---:|---:|
| `linux.sockstat.Sockstat` | 6.36 s | 2030 s | x319 |
| `timeliner.Timeliner` | 9.56 s | 1070 s | x112 |
| `linux.lsmod.Lsmod` | 0.282 s | 29.0 s | x103 |
| `linux.psscan.PsScan` | 1.09 s | 111 s | x102 |
| `linux.mountinfo.MountInfo` | 0.697 s | 70.3 s | x101 |
| `yarascan.YaraScan` | 0.909 s | 79.6 s | x88 |
| `linux.malware.netfilter.Netfilter` | 0.6 s | 49.9 s | x83 |
| `linux.ptrace.Ptrace` | 0.253 s | 20.4 s | x81 |
| `linux.pstree.PsTree` | 0.213 s | 16.2 s | x76 |
| `linux.ip.Link` | 0.22 s | 16.4 s | x74 |
| `linux.check_idt.Check_idt` | 0.59 s | 41.8 s | x71 |
| `linux.malware.check_modules.Check_modules` | 0.229 s | 16.2 s | x71 |
| `linux.pidhashtable.PIDHashTable` | 0.297 s | 20.5 s | x69 |
| `linux.tracing.ftrace.CheckFtrace` | 0.625 s | 42.7 s | x68 |
| `linux.malware.process_spoofing.ProcessSpoofing` | 0.281 s | 19.0 s | x68 |
| `linux.malware.tty_check.Tty_Check` | 0.582 s | 39.3 s | x68 |
| `linux.pagecache.Files` | 3.21 s | 215 s | x67 |
| `linux.pagecache.InodePages` | 0.207 s | 13.8 s | x67 |
| `linux.netfilter.Netfilter` | 0.693 s | 45.8 s | x66 |
| `linux.capabilities.Capabilities` | 0.259 s | 17.1 s | x66 |
| `linux.kthreads.Kthreads` | 0.661 s | 43.3 s | x65 |
| `linux.pslist.PsList` | 0.262 s | 17.1 s | x65 |
| `linux.malware.check_creds.Check_creds` | 0.257 s | 16.7 s | x65 |
| `linux.check_creds.Check_creds` | 0.251 s | 16.1 s | x64 |
| `linux.malware.check_idt.Check_idt` | 0.635 s | 40.5 s | x64 |
| `linux.ebpf.EBPF` | 0.236 s | 14.6 s | x62 |
| `linux.check_modules.Check_modules` | 0.268 s | 15.9 s | x59 |
| `linux.tty_check.tty_check` | 0.64 s | 36.8 s | x58 |
| `linux.psaux.PsAux` | 0.298 s | 16.9 s | x57 |
| `linux.lsof.Lsof` | 9.51 s | 535 s | x56 |
| `linux.tracing.perf_events.PerfEvents` | 0.359 s | 19.8 s | x55 |
| `linux.iomem.IOMem` | 0.257 s | 14.0 s | x55 |
| `linux.boottime.Boottime` | 0.266 s | 14.5 s | x54 |
| `linux.malware.malfind.Malfind` | 10.4 s | 549 s | x53 |
| `linux.elfs.Elfs` | 4.15 s | 217 s | x52 |
| `linux.graphics.fbdev.Fbdev` | 0.266 s | 13.7 s | x51 |
| `linux.bash.Bash` | 0.284 s | 14.6 s | x51 |
| `linux.ip.Addr` | 0.269 s | 13.7 s | x51 |
| `linux.malfind.Malfind` | 10.9 s | 543 s | x50 |
| `linux.keyboard_notifiers.Keyboard_notifiers` | 0.583 s | 27.6 s | x47 |
| `layerwriter.LayerWriter` | 0.226 s | 10.7 s | x47 |
| `linux.proc.Maps` | 13.8 s | 642 s | x47 |
| `linux.malware.check_afinfo.Check_afinfo` | 0.613 s | 28.5 s | x46 |
| `configwriter.ConfigWriter` | 0.215 s | 9.65 s | x45 |
| `linux.modxview.Modxview` | 0.622 s | 27.6 s | x44 |
| `linux.check_afinfo.Check_afinfo` | 0.557 s | 24.4 s | x44 |
| `linux.malware.keyboard_notifiers.Keyboard_notifiers` | 0.649 s | 27.4 s | x42 |
| `linux.envars.Envars` | 0.379 s | 15.8 s | x42 |
| `linux.malware.modxview.Modxview` | 0.667 s | 27.7 s | x41 |
| `linux.tracing.tracepoints.CheckTracepoints` | 0.664 s | 26.5 s | x40 |
| `linux.malware.check_syscall.Check_syscall` | 0.976 s | 34.8 s | x36 |
| `banners.Banners` | 1.02 s | 35.7 s | x35 |
| `linux.check_syscall.Check_syscall` | 1 s | 33.1 s | x33 |
| `regexscan.RegExScan` | 0.764 s | 18.2 s | x24 |
| `linux.vmayarascan.VmaYaraScan` | 38.8 s | 675 s | x17 |
| `linux.vmcoreinfo.VMCoreInfo` | 1.28 s | 20.8 s | x16 |
| `vmscan.Vmscan` | 1.72 s | 14.0 s | x8.1 |
| `frameworkinfo.FrameworkInfo` | 0.234 s | 0.68 s | x2.9 |
| **58 plugins** | **132 s** | **7817 s** | **x59** |

## Not comparable

| Plugin | Why |
|---|---|
| `windows.memmap.Memmap` | on the Windows 10 capture `vol` is killed for running out of memory part way through. Where it stops depends on how much memory is free at the time, so two `vol` runs do not agree with each other either. This port finishes all 9,014,410 lines, and every line `vol` wrote before dying matches. On the Windows XP capture both finish and the row for it is in that table above |
| `isfinfo.IsfInfo` | without `--live` upstream lists its own identifier database rather than the image, and the rows come back in that database's order. This port lists the symbol directories instead. Both describe the installation |

