# Runtime against volatility3

Same plugin, same image, same machine, byte-identical output, wall clock. Both sides measured in one pass with warm caches, nothing else running.

Measured on one machine with one pair of captures, so the figures will differ on other hardware, other images and a different amount of free memory.

## Machine

| | |
|---|---|
| CPU | 4 vCPU, 2.49 GHz, sse4_2, aes, avx2 |
| RAM | 7.8 GiB |
| Disk | 160 GB virtio |
| OS | Ubuntu, Linux 6.8.0-137-generic |
| Python | 3.12.3, volatility3 2.28.0 |
| Rust | 1.98.0, release profile |

## Windows, 4.6 GB VMware capture, Windows 10 19045, 136 processes

| Plugin | Rust | Python | Faster |
|---|---:|---:|---:|
| `windows.malware.suspicious_threads.SuspiciousThreads` | 0.47 s | 281.6 s | x599 |
| `windows.suspicious_threads.SuspiciousThreads` | 0.50 s | 259.1 s | x518 |
| `windows.malware.hollowprocesses.HollowProcesses` | 0.52 s | 257.9 s | x496 |
| `windows.suspended_threads.SuspendedThreads` | 0.090 s | 42.0 s | x467 |
| `windows.malware.malfind.Malfind` | 0.52 s | 236.5 s | x455 |
| `windows.hollowprocesses.HollowProcesses` | 0.59 s | 263.0 s | x446 |
| `windows.debugregisters.DebugRegisters` | 0.090 s | 37.0 s | x411 |
| `windows.malfind.Malfind` | 0.65 s | 239.7 s | x369 |
| `windows.vadinfo.VadInfo` | 0.99 s | 329.7 s | x333 |
| `windows.verinfo.VerInfo` | 0.99 s | 150.7 s | x152 |
| `windows.threads.Threads` | 0.40 s | 40.7 s | x102 |
| `windows.mftscan.MFTScan` | 2.37 s | 226.0 s | x95 |
| `windows.processghosting.ProcessGhosting` | 0.48 s | 45.0 s | x94 |
| `windows.registry.hivelist.HiveList` | 0.030 s | 2.71 s | x90 |
| `windows.registry.hashdump.Hashdump` | 0.070 s | 6.31 s | x90 |
| `windows.malware.processghosting.ProcessGhosting` | 0.55 s | 47.8 s | x87 |
| `windows.vadwalk.VadWalk` | 0.55 s | 46.3 s | x84 |
| `windows.registry.lsadump.Lsadump` | 0.070 s | 5.81 s | x83 |
| `windows.registry.cachedump.Cachedump` | 0.080 s | 6.51 s | x81 |
| `windows.pslist.PsList` | 0.030 s | 2.38 s | x79 |
| `windows.lsadump.Lsadump` | 0.060 s | 4.67 s | x78 |
| `windows.mftscan.ADS` | 1.10 s | 84.5 s | x77 |
| `windows.hashdump.Hashdump` | 0.090 s | 6.68 s | x74 |
| `windows.amcache.Amcache` | 1.57 s | 115.5 s | x74 |
| `windows.mftscan.ResidentData` | 1.37 s | 99.7 s | x73 |
| `windows.shimcachemem.ShimcacheMem` | 0.060 s | 4.26 s | x71 |
| `windows.scheduled_tasks.ScheduledTasks` | 0.28 s | 19.7 s | x70 |
| `windows.registry.hivescan.HiveScan` | 0.13 s | 9.14 s | x70 |
| `windows.cachedump.Cachedump` | 0.080 s | 5.51 s | x69 |
| `windows.malware.ldrmodules.LdrModules` | 0.64 s | 43.0 s | x67 |
| `windows.etwpatch.EtwPatch` | 0.65 s | 42.1 s | x65 |
| `windows.registry.printkey.PrintKey` | 0.080 s | 5.13 s | x64 |
| `windows.handles.Handles` | 1.61 s | 103.0 s | x64 |
| `windows.ldrmodules.LdrModules` | 0.72 s | 44.7 s | x62 |
| `windows.truecrypt.Passphrase` | 0.030 s | 1.85 s | x62 |
| `windows.joblinks.JobLinks` | 0.050 s | 3.07 s | x61 |
| `windows.timers.Timers` | 0.060 s | 3.67 s | x61 |
| `windows.bigpools.BigPools` | 0.17 s | 10.3 s | x60 |
| `windows.kpcrs.KPCRs` | 0.030 s | 1.81 s | x60 |
| `windows.registry.amcache.Amcache` | 1.99 s | 117.3 s | x59 |
| `windows.info.Info` | 0.030 s | 1.72 s | x57 |
| `windows.registry.certificates.Certificates` | 0.16 s | 9.01 s | x56 |
| `windows.consoles.Consoles` | 0.090 s | 4.98 s | x55 |
| `windows.modules.Modules` | 0.040 s | 2.13 s | x53 |
| `windows.ssdt.SSDT` | 0.050 s | 2.63 s | x53 |
| `windows.getsids.GetSIDs` | 0.14 s | 7.14 s | x51 |
| `windows.unloadedmodules.UnloadedModules` | 0.040 s | 2.02 s | x50 |
| `windows.registry.userassist.UserAssist` | 0.090 s | 4.52 s | x50 |
| `windows.registry.scheduled_tasks.ScheduledTasks` | 0.42 s | 20.5 s | x49 |
| `windows.pstree.PsTree` | 0.070 s | 3.29 s | x47 |
| `windows.malware.pebmasquerade.PebMasquerade` | 0.060 s | 2.76 s | x46 |
| `windows.statistics.Statistics` | 2.19 s | 100.6 s | x46 |
| `windows.virtmap.VirtMap` | 0.040 s | 1.70 s | x42 |
| `windows.sessions.Sessions` | 0.070 s | 2.91 s | x42 |
| `windows.crashinfo.Crashinfo` | 0.040 s | 1.64 s | x41 |
| `windows.privileges.Privs` | 0.070 s | 2.74 s | x39 |
| `windows.dlllist.DllList` | 0.47 s | 17.9 s | x38 |
| `windows.filescan.FileScan` | 2.65 s | 89.4 s | x34 |
| `windows.getservicesids.GetServiceSIDs` | 0.16 s | 5.29 s | x33 |
| `windows.cmdscan.CmdScan` | 0.15 s | 4.75 s | x32 |
| `windows.cmdline.CmdLine` | 0.080 s | 2.24 s | x28 |
| `windows.thrdscan.ThrdScan` | 2.52 s | 70.2 s | x28 |
| `windows.dumpfiles.DumpFiles` | 16.6 s | 450.3 s | x27 |
| `windows.envars.Envars` | 0.18 s | 4.85 s | x27 |
| `windows.poolscanner.PoolScanner` | 4.03 s | 101.1 s | x25 |
| `windows.iat.IAT` | 1.14 s | 26.6 s | x23 |
| `windows.windowstations.WindowStations` | 2.16 s | 42.3 s | x20 |
| `windows.svclist.SvcList` | 1.34 s | 23.2 s | x17 |
| `windows.desktops.Desktops` | 2.37 s | 41.1 s | x17 |
| `windows.mbrscan.MBRScan` | 2.64 s | 45.2 s | x17 |
| `windows.malware.drivermodule.DriverModule` | 1.88 s | 29.9 s | x16 |
| `windows.orphan_kernel_threads.Threads` | 1.90 s | 29.4 s | x15 |
| `windows.netscan.NetScan` | 2.11 s | 30.3 s | x14 |
| `windows.devicetree.DeviceTree` | 1.67 s | 23.3 s | x14 |
| `windows.psxview.PsXView` | 4.18 s | 58.2 s | x14 |
| `windows.windows.Windows` | 2.97 s | 41.0 s | x14 |
| `windows.deskscan.DeskScan` | 2.05 s | 28.1 s | x14 |
| `windows.malware.psxview.PsXView` | 4.36 s | 58.9 s | x14 |
| `windows.drivermodule.DriverModule` | 1.68 s | 22.4 s | x13 |
| `windows.driverirp.DriverIrp` | 2.04 s | 27.2 s | x13 |
| `windows.mutantscan.MutantScan` | 2.14 s | 28.0 s | x13 |
| `windows.psscan.PsScan` | 1.88 s | 24.5 s | x13 |
| `windows.callbacks.Callbacks` | 2.73 s | 35.2 s | x13 |
| `windows.modscan.ModScan` | 1.98 s | 23.8 s | x12 |
| `windows.symlinkscan.SymlinkScan` | 2.39 s | 27.2 s | x11 |
| `windows.driverscan.DriverScan` | 2.11 s | 23.0 s | x11 |
| `windows.svcdiff.SvcDiff` | 2.94 s | 30.1 s | x10 |
| `windows.malware.svcdiff.SvcDiff` | 2.91 s | 28.9 s | x9.9 |
| `windows.svcscan.SvcScan` | 2.85 s | 27.9 s | x9.8 |
| `windows.registry.getcellroutine.GetCellRoutine` | 0.67 s | 4.82 s | x7.2 |
| `windows.malware.indirect_system_calls.IndirectSystemCalls (vol with capstone)` | 37.8 s | 234.4 s | x6.2 |
| `windows.malware.direct_system_calls.DirectSystemCalls (vol with capstone)` | 31.8 s | 150.4 s | x4.7 |
| `windows.indirect_system_calls.IndirectSystemCalls (vol with capstone)` | 34.9 s | 159.2 s | x4.6 |
| `windows.direct_system_calls.DirectSystemCalls (vol with capstone)` | 34.1 s | 150.8 s | x4.4 |
| `windows.unhooked_system_calls.unhooked_system_calls` | 9.92 s | 37.8 s | x3.8 |
| `windows.malware.unhooked_system_calls.UnhookedSystemCalls` | 10.1 s | 33.5 s | x3.3 |
| `windows.netstat.NetStat` | 1.08 s | 2.71 s | x2.5 |
| `windows.skeleton_key_check.Skeleton_Key_Check` | 2.38 s | 2.84 s | x1.2 |
| `windows.malware.skeleton_key_check.Skeleton_Key_Check` | 2.18 s | 2.23 s | x1.0 |
| **99 plugins** | **273 s** | **5723 s** | **x21** |

## Linux, 4.1 GB LiME capture, Linux 6.8

| Plugin | Rust | Python | Faster |
|---|---:|---:|---:|
| `linux.library_list.LibraryList` | 1.99 s | 788.7 s | x396 |
| `linux.kallsyms.Kallsyms` | 2.41 s | 161.6 s | x67 |
| `linux.netfilter.Netfilter` | 0.89 s | 56.3 s | x63 |
| `linux.lsof.Lsof` | 0.89 s | 55.6 s | x62 |
| `linux.sockstat.Sockstat` | 1.60 s | 97.2 s | x61 |
| `linux.check_idt.Check_idt` | 0.82 s | 49.7 s | x61 |
| `linux.malware.netfilter.Netfilter` | 1.07 s | 62.0 s | x58 |
| `linux.pagecache.Files` | 1.67 s | 93.4 s | x56 |
| `linux.kthreads.Kthreads` | 0.87 s | 47.2 s | x54 |
| `linux.proc.Maps` | 2.53 s | 135.4 s | x54 |
| `linux.boottime.Boottime` | 0.35 s | 18.7 s | x53 |
| `linux.lsmod.Lsmod` | 0.57 s | 29.1 s | x51 |
| `linux.malware.malfind.Malfind` | 1.73 s | 87.8 s | x51 |
| `linux.malware.check_idt.Check_idt` | 0.93 s | 45.6 s | x49 |
| `linux.kmsg.Kmsg` | 0.38 s | 17.9 s | x47 |
| `linux.mountinfo.MountInfo` | 0.91 s | 42.9 s | x47 |
| `linux.malfind.Malfind` | 1.87 s | 87.5 s | x47 |
| `linux.malware.tty_check.Tty_Check` | 1.04 s | 46.8 s | x45 |
| `linux.capabilities.Capabilities` | 0.44 s | 19.7 s | x45 |
| `linux.pslist.PsList` | 0.42 s | 18.1 s | x43 |
| `linux.ip.Addr` | 0.30 s | 12.9 s | x43 |
| `linux.keyboard_notifiers.Keyboard_notifiers` | 0.77 s | 32.1 s | x42 |
| `linux.graphics.fbdev.Fbdev` | 0.33 s | 13.5 s | x41 |
| `linux.ip.Link` | 0.33 s | 13.4 s | x41 |
| `linux.tracing.ftrace.CheckFtrace` | 1.31 s | 53.0 s | x40 |
| `linux.tty_check.tty_check` | 1.35 s | 53.4 s | x40 |
| `linux.iomem.IOMem` | 0.35 s | 13.0 s | x37 |
| `linux.pidhashtable.PIDHashTable` | 0.38 s | 14.1 s | x37 |
| `linux.pagecache.RecoverFs` | 2.83 s | 103.8 s | x37 |
| `linux.malware.check_creds.Check_creds` | 0.39 s | 14.1 s | x36 |
| `linux.psaux.PsAux` | 0.60 s | 21.6 s | x36 |
| `linux.malware.keyboard_notifiers.Keyboard_notifiers` | 0.87 s | 30.7 s | x35 |
| `linux.check_creds.Check_creds` | 0.51 s | 17.4 s | x34 |
| `linux.ebpf.EBPF` | 0.51 s | 16.1 s | x32 |
| `linux.psscan.PsScan` | 4.14 s | 128.2 s | x31 |
| `linux.malware.check_modules.Check_modules` | 0.47 s | 14.5 s | x31 |
| `linux.check_syscall.Check_syscall` | 1.24 s | 37.3 s | x30 |
| `linux.check_modules.Check_modules` | 0.61 s | 18.0 s | x29 |
| `linux.hidden_modules.Hidden_modules` | 0.92 s | 27.1 s | x29 |
| `linux.tracing.perf_events.PerfEvents` | 0.67 s | 19.6 s | x29 |
| `linux.check_afinfo.Check_afinfo` | 1.05 s | 29.5 s | x28 |
| `linux.malware.hidden_modules.Hidden_modules` | 1.09 s | 28.8 s | x26 |
| `linux.elfs.Elfs` | 1.79 s | 47.2 s | x26 |
| `linux.malware.check_syscall.Check_syscall` | 1.34 s | 35.1 s | x26 |
| `linux.sockscan.Sockscan` | 4.47 s | 112.4 s | x25 |
| `linux.pagecache.InodePages` | 0.49 s | 12.3 s | x25 |
| `linux.tracing.tracepoints.CheckTracepoints` | 1.85 s | 46.0 s | x25 |
| `linux.envars.Envars` | 0.66 s | 16.0 s | x24 |
| `linux.ptrace.Ptrace` | 0.79 s | 19.1 s | x24 |
| `linux.malware.process_spoofing.ProcessSpoofing` | 0.69 s | 16.6 s | x24 |
| `linux.malware.modxview.Modxview` | 1.28 s | 30.5 s | x24 |
| `linux.malware.check_afinfo.Check_afinfo` | 1.08 s | 25.3 s | x23 |
| `linux.modxview.Modxview` | 1.41 s | 31.8 s | x23 |
| `linux.pstree.PsTree` | 1.07 s | 18.2 s | x17 |
| `linux.bash.Bash` | 1.94 s | 19.2 s | x9.9 |
| `linux.vmcoreinfo.VMCoreInfo` | 4.43 s | 27.4 s | x6.2 |
| **56 plugins** | **68 s** | **3130 s** | **x46** |

## Not comparable

| Plugin | Why |
|---|---|
| `windows.memmap.Memmap` | `vol` is OOM-killed after 7,870,303 lines. This port finishes all 12,263,859 in 223 s, and every byte `vol` wrote before dying matches |
| `linux.pscallstack.PsCallStack` | `vol` is killed before finishing on this image. Every row it wrote first matches, and this port produces all 15,320 in 1.0 s |
| `frameworkinfo.FrameworkInfo`, `isfinfo.IsfInfo` | they describe the tool's own installation rather than the image |
