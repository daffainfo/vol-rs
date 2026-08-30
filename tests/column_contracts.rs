//! Locks each ported plugin's output columns to the contract of the Python
//! implementation it was ported from.
//!
//! Column names and their order are the plugin's public interface: downstream
//! tooling parses them. These expectations were taken from the `TreeGrid`
//! declarations in the corresponding upstream plugin, so a change here means
//! the port has drifted from the original and should be caught in review.
//!
//! Derived from Volatility 3, Copyright Volatility Foundation, licensed under
//! the Volatility Software License 1.0.

use vol_rs::framework::plugins::PluginRegistry;

/// `(plugin name, expected columns in order)`.
///
/// `pslist` and `psscan` declare their offset column with the address space it
/// refers to, so the expected name depends on the plugin's default.
const EXPECTED: &[(&str, &[&str])] = &[
    ("frameworkinfo.FrameworkInfo", &["Data"]),
    (
        "isfinfo.IsfInfo",
        &[
            "URI",
            "Valid",
            "Number of base_types",
            "Number of types",
            "Number of symbols",
            "Number of enums",
            "Identifying information",
        ],
    ),
    ("configwriter.ConfigWriter", &["Key", "Value"]),
    (
        "vmscan.Vmscan",
        &["Architecture", "VMCS Physical offset", "EPT", "Guest CR3"],
    ),
    ("regexscan.RegExScan", &["Offset", "Text", "Hex"]),
    ("yarascan.YaraScan", &["Offset", "Rule", "Component", "Value"]),
    (
        "windows.modscan.ModScan",
        &["Offset", "Base", "Size", "Name", "Path", "File output"],
    ),
    (
        "windows.deskscan.DeskScan",
        &["Offset", "Window Station", "Session", "Desktop", "Process", "PID"],
    ),
    (
        "windows.statistics.Statistics",
        &[
            "Valid pages (all)",
            "Valid pages (large)",
            "Swapped Pages (all)",
            "Swapped Pages (large)",
            "Invalid Pages (all)",
            "Invalid Pages (large)",
            "Other Invalid Pages (all)",
        ],
    ),
    (
        "windows.registry.certificates.Certificates",
        &[
            "Certificate path",
            "Certificate section",
            "Certificate ID",
            "Certificate name",
        ],
    ),
    (
        "windows.threads.Threads",
        &[
            "Offset",
            "PID",
            "TID",
            "StartAddress",
            "StartPath",
            "Win32StartAddress",
            "Win32StartPath",
            "CreateTime",
            "ExitTime",
        ],
    ),
    (
        "windows.orphan_kernel_threads.Threads",
        &[
            "Offset",
            "PID",
            "TID",
            "StartAddress",
            "StartPath",
            "Win32StartAddress",
            "Win32StartPath",
            "CreateTime",
            "ExitTime",
        ],
    ),
    (
        "windows.svclist.SvcList",
        &[
            "Offset",
            "Order",
            "PID",
            "Start",
            "State",
            "Type",
            "Name",
            "Display",
            "Binary",
            "Binary (Registry)",
            "Dll",
        ],
    ),
    (
        "windows.svcdiff.SvcDiff",
        &[
            "Offset",
            "Order",
            "PID",
            "Start",
            "State",
            "Type",
            "Name",
            "Display",
            "Binary",
            "Binary (Registry)",
            "Dll",
        ],
    ),
    (
        "windows.malware.svcdiff.SvcDiff",
        &[
            "Offset",
            "Order",
            "PID",
            "Start",
            "State",
            "Type",
            "Name",
            "Display",
            "Binary",
            "Binary (Registry)",
            "Dll",
        ],
    ),
    (
        "windows.pslist.PsList",
        &[
            "PID",
            "PPID",
            "ImageFileName",
            "Offset(V)",
            "Threads",
            "Handles",
            "SessionId",
            "Wow64",
            "CreateTime",
            "ExitTime",
            "File output",
        ],
    ),
    (
        "windows.psscan.PsScan",
        &[
            "PID",
            "PPID",
            "ImageFileName",
            "Offset(V)",
            "Threads",
            "Handles",
            "SessionId",
            "Wow64",
            "CreateTime",
            "ExitTime",
            "File output",
        ],
    ),
    (
        "windows.pstree.PsTree",
        &[
            "PID",
            "PPID",
            "ImageFileName",
            "Offset(V)",
            "Threads",
            "Handles",
            "SessionId",
            "Wow64",
            "CreateTime",
            "ExitTime",
            "Audit",
            "Cmd",
            "Path",
        ],
    ),
    ("windows.cmdline.CmdLine", &["PID", "Process", "Args"]),
    (
        "windows.dlllist.DllList",
        &[
            "PID",
            "Process",
            "Base",
            "Size",
            "Name",
            "Path",
            "LoadCount",
            "LoadTime",
            "File output",
        ],
    ),
    (
        "windows.modules.Modules",
        &["Offset", "Base", "Size", "Name", "Path", "File output"],
    ),
    (
        "windows.handles.Handles",
        &[
            "PID",
            "Process",
            "Offset",
            "HandleValue",
            "Type",
            "GrantedAccess",
            "Name",
        ],
    ),
    (
        "windows.vadinfo.VadInfo",
        &[
            "PID",
            "Process",
            "Offset",
            "Start VPN",
            "End VPN",
            "Tag",
            "Protection",
            "CommitCharge",
            "PrivateMemory",
            "Parent",
            "File",
            "File output",
        ],
    ),
    ("windows.info.Info", &["Variable", "Value"]),
    ("regexscan.RegExScan", &["Offset", "Text", "Hex"]),
    ("yarascan.YaraScan", &["Offset", "Rule", "Component", "Value"]),
    (
        "vmscan.Vmscan",
        &["Architecture", "VMCS Physical offset", "EPT", "Guest CR3"],
    ),
    (
        "timeliner.Timeliner",
        &["Plugin", "Description", "Created Date", "Modified Date", "Accessed Date", "Changed Date"],
    ),
    (
        "linux.pslist.PsList",
        &[
            "OFFSET (V)",
            "PID",
            "TID",
            "PPID",
            "COMM",
            "UID",
            "GID",
            "EUID",
            "EGID",
            "CREATION TIME",
            "File output",
        ],
    ),
    (
        "linux.pstree.PsTree",
        &["OFFSET (V)", "PID", "TID", "PPID", "COMM"],
    ),
    (
        "linux.lsmod.Lsmod",
        &[
            "Offset",
            "Module Name",
            "Code Size",
            "Taints",
            "Load Arguments",
            "File Output",
        ],
    ),
    ("linux.psaux.PsAux", &["PID", "PPID", "COMM", "ARGS"]),
    (
        "linux.bash.Bash",
        &["PID", "Process", "CommandTime", "Command"],
    ),
    (
        "linux.library_list.LibraryList",
        &["Name", "Pid", "LoadAddress", "Path"],
    ),
    ("linux.boottime.Boottime", &["TIME NS", "Boot Time"]),
    (
        "linux.ptrace.Ptrace",
        &["Process", "PID", "TID", "Tracer TID", "Tracee TID", "Flags"],
    ),
    ("linux.iomem.IOMem", &["Name", "Start", "End"]),
    ("linux.ebpf.EBPF", &["Address", "Name", "Tag", "Type"]),
    ("linux.vmcoreinfo.VMCoreInfo", &["Offset", "Key", "Value"]),
    (
        "linux.pscallstack.PsCallStack",
        &["TID", "Comm", "Position", "Address", "Value", "Name", "Type", "Module"],
    ),
    (
        "linux.tracing.perf_events.PerfEvents",
        &["PID", "Process", "Event", "Short Program Name", "Full Name", "Address"],
    ),
    (
        "linux.kallsyms.Kallsyms",
        &["Addr", "Type", "Size", "Exported", "SubSystem", "ModuleName", "SymbolName", "Description"],
    ),
    (
        "linux.sockscan.Sockscan",
        &[
            "Sock Offset", "Family", "Type", "Proto", "Source Addr", "Source Port",
            "Destination Addr", "Destination Port", "State", "Filter",
        ],
    ),
    (
        "linux.pagecache.InodePages",
        &["PageVAddr", "PagePAddr", "MappingAddr", "Index", "DumpSafe", "Flags", "Output File"],
    ),
    (
        "linux.pagecache.RecoverFs",
        &[
            "SuperblockAddr", "MountPoint", "Device", "InodeNum", "InodeAddr",
            "FileType", "InodePages", "CachedPages", "FileMode", "AccessTime",
            "ModificationTime", "ChangeTime", "FilePath", "InodeSize",
            "Recovered FileSize",
        ],
    ),
    (
        "linux.module_extract.ModuleExtract",
        &["Base", "File Size", "File output"],
    ),
    (
        "linux.pagecache.Files",
        &[
            "SuperblockAddr", "MountPoint", "Device", "InodeNum", "InodeAddr",
            "FileType", "InodePages", "CachedPages", "FileMode", "AccessTime",
            "ModificationTime", "ChangeTime", "FilePath", "InodeSize",
        ],
    ),
    (
        "linux.sockstat.Sockstat",
        &[
            "NetNS", "Process Name", "PID", "TID", "FD", "Sock Offset", "Family",
            "Type", "Proto", "Source Addr", "Source Port", "Destination Addr",
            "Destination Port", "State", "Filter",
        ],
    ),
    (
        "linux.ip.Addr",
        &["NetNS", "Index", "Interface", "MAC", "Promiscuous", "IP", "Prefix", "Scope Type", "State"],
    ),
    (
        "linux.ip.Link",
        &["NS", "Interface", "MAC", "State", "MTU", "Qdisc", "Qlen", "Flags"],
    ),
    (
        "linux.vmaregexscan.VmaRegExScan",
        &["PID", "Process", "Offset", "Text", "Hex"],
    ),
    (
        "windows.vadregexscan.VadRegExScan",
        &["PID", "Process", "Offset", "Text", "Hex"],
    ),
    (
        "linux.graphics.fbdev.Fbdev",
        &["Address", "Device", "ID", "Size", "Virtual resolution", "BPP", "State", "Filename"],
    ),
    (
        "linux.tracing.tracepoints.CheckTracepoints",
        &[
            "tracepoint", "tracepoint address", "Probe", "Probe address",
            "Probe priority", "Module", "Module address",
        ],
    ),
    (
        "linux.tracing.ftrace.CheckFtrace",
        &[
            "ftrace_ops address", "Callback", "Callback address",
            "Hooked symbols", "Module", "Module address",
        ],
    ),
    (
        "linux.kmsg.Kmsg",
        &["facility", "level", "timestamp", "caller", "line"],
    ),
    (
        "linux.malware.netfilter.Netfilter",
        &["Net NS", "Proto", "Hook", "Priority", "Handler", "Module", "Symbol", "Is Hooked"],
    ),
    (
        "linux.psscan.PsScan",
        &["OFFSET (P)", "PID", "TID", "PPID", "COMM", "EXIT_STATE"],
    ),
    ("linux.boottime.Boottime", &["TIME NS", "Boot Time"]),
    ("linux.iomem.IOMem", &["Name", "Start", "End"]),
    ("linux.ebpf.EBPF", &["Address", "Name", "Tag", "Type"]),
    ("linux.vmcoreinfo.VMCoreInfo", &["Offset", "Key", "Value"]),
    (
        "linux.pscallstack.PsCallStack",
        &["TID", "Comm", "Position", "Address", "Value", "Name", "Type", "Module"],
    ),
    (
        "linux.tracing.perf_events.PerfEvents",
        &["PID", "Process", "Event", "Short Program Name", "Full Name", "Address"],
    ),
    (
        "linux.kallsyms.Kallsyms",
        &["Addr", "Type", "Size", "Exported", "SubSystem", "ModuleName", "SymbolName", "Description"],
    ),
    (
        "linux.sockscan.Sockscan",
        &[
            "Sock Offset", "Family", "Type", "Proto", "Source Addr", "Source Port",
            "Destination Addr", "Destination Port", "State", "Filter",
        ],
    ),
    (
        "linux.pagecache.InodePages",
        &["PageVAddr", "PagePAddr", "MappingAddr", "Index", "DumpSafe", "Flags", "Output File"],
    ),
    (
        "linux.pagecache.RecoverFs",
        &[
            "SuperblockAddr", "MountPoint", "Device", "InodeNum", "InodeAddr",
            "FileType", "InodePages", "CachedPages", "FileMode", "AccessTime",
            "ModificationTime", "ChangeTime", "FilePath", "InodeSize",
            "Recovered FileSize",
        ],
    ),
    (
        "linux.module_extract.ModuleExtract",
        &["Base", "File Size", "File output"],
    ),
    (
        "linux.pagecache.Files",
        &[
            "SuperblockAddr", "MountPoint", "Device", "InodeNum", "InodeAddr",
            "FileType", "InodePages", "CachedPages", "FileMode", "AccessTime",
            "ModificationTime", "ChangeTime", "FilePath", "InodeSize",
        ],
    ),
    (
        "linux.sockstat.Sockstat",
        &[
            "NetNS", "Process Name", "PID", "TID", "FD", "Sock Offset", "Family",
            "Type", "Proto", "Source Addr", "Source Port", "Destination Addr",
            "Destination Port", "State", "Filter",
        ],
    ),
    (
        "linux.ip.Addr",
        &["NetNS", "Index", "Interface", "MAC", "Promiscuous", "IP", "Prefix", "Scope Type", "State"],
    ),
    (
        "linux.ip.Link",
        &["NS", "Interface", "MAC", "State", "MTU", "Qdisc", "Qlen", "Flags"],
    ),
    (
        "linux.vmaregexscan.VmaRegExScan",
        &["PID", "Process", "Offset", "Text", "Hex"],
    ),
    (
        "windows.vadregexscan.VadRegExScan",
        &["PID", "Process", "Offset", "Text", "Hex"],
    ),
    (
        "linux.graphics.fbdev.Fbdev",
        &["Address", "Device", "ID", "Size", "Virtual resolution", "BPP", "State", "Filename"],
    ),
    (
        "linux.tracing.tracepoints.CheckTracepoints",
        &[
            "tracepoint", "tracepoint address", "Probe", "Probe address",
            "Probe priority", "Module", "Module address",
        ],
    ),
    (
        "linux.tracing.ftrace.CheckFtrace",
        &[
            "ftrace_ops address", "Callback", "Callback address",
            "Hooked symbols", "Module", "Module address",
        ],
    ),
    (
        "linux.kmsg.Kmsg",
        &["facility", "level", "timestamp", "caller", "line"],
    ),
    (
        "linux.malware.netfilter.Netfilter",
        &["Net NS", "Proto", "Hook", "Priority", "Handler", "Module", "Symbol", "Is Hooked"],
    ),
    (
        "linux.psscan.PsScan",
        &["OFFSET (P)", "PID", "TID", "PPID", "COMM", "EXIT_STATE"],
    ),
    (
        "linux.kthreads.Kthreads",
        &["TID", "Thread Name", "Handler Address", "Module", "Symbol"],
    ),
    (
        "linux.pidhashtable.PIDHashTable",
        &["OFFSET", "PID", "TID", "PPID", "COMM"],
    ),
    (
        "linux.malware.check_syscall.Check_syscall",
        &[
            "Table Address",
            "Table Name",
            "Index",
            "Handler Address",
            "Handler Symbol",
        ],
    ),
    (
        "linux.malware.keyboard_notifiers.Keyboard_notifiers",
        &["Address", "Module", "Symbol"],
    ),
    (
        // Volatility 2.28.2 adds a "File output" column here. 2.28.0, which is
        // the release this port is compared against, does not.
        "linux.malware.malfind.Malfind",
        &[
            "PID", "Process", "Start", "End", "Path", "Protection", "Hexdump",
            "Disasm",
        ],
    ),
    (
        "linux.malware.check_creds.Check_creds",
        &["CredVAddr", "PIDs"],
    ),
    (
        "linux.malware.process_spoofing.ProcessSpoofing",
        &[
            "PID", "PPID", "Exe_Path", "Cmdline_Basename", "Comm",
            "Cmdline_Spoofed", "Comm_Spoofed", "Exe_Deleted",
        ],
    ),
    (
        "linux.malware.modxview.Modxview",
        &["Name", "Address", "In procfs", "In sysfs", "In scan", "Taints"],
    ),
    (
        "linux.malware.check_idt.Check_idt",
        &["Index", "Address", "Module", "Symbol"],
    ),
    (
        "linux.malware.check_afinfo.Check_afinfo",
        &["Symbol Name", "Member", "Handler Address"],
    ),
    (
        "linux.malware.tty_check.Tty_Check",
        &["Name", "Address", "Module", "Symbol"],
    ),
    (
        "linux.malware.check_modules.Check_modules",
        &[
            "Offset",
            "Module Name",
            "Code Size",
            "Taints",
            "Load Arguments",
            "File Output",
        ],
    ),
    (
        "linux.malware.hidden_modules.Hidden_modules",
        &[
            "Offset",
            "Module Name",
            "Code Size",
            "Taints",
            "Load Arguments",
            "File Output",
        ],
    ),
    (
        "linux.envars.Envars",
        &["PID", "PPID", "COMM", "KEY", "VALUE"],
    ),
    (
        "linux.proc.Maps",
        &[
            "PID",
            "Process",
            "Start",
            "End",
            "Flags",
            "PgOff",
            "Major",
            "Minor",
            "Inode",
            "File Path",
            "File output",
        ],
    ),
    (
        "linux.elfs.Elfs",
        &["PID", "Process", "Start", "End", "File Path", "File Output"],
    ),
    (
        "mac.pslist.PsList",
        &["OFFSET", "NAME", "PID", "UID", "GID", "Start Time", "PPID"],
    ),
    ("mac.pstree.PsTree", &["PID", "PPID", "COMM"]),
    ("mac.lsmod.Lsmod", &["Offset", "Name", "Size"]),
    (
        "mac.psaux.Psaux",
        &["PID", "Process", "Argc", "Arguments"],
    ),
    (
        "mac.lsof.Lsof",
        &["PID", "File Descriptor", "File Path"],
    ),
    ("mac.mount.Mount", &["Device", "Mount Point", "Type"]),
    (
        "mac.check_trap_table.Check_trap_table",
        &[
            "Table Address",
            "Table Name",
            "Index",
            "Handler Address",
            "Handler Module",
            "Handler Symbol",
        ],
    ),
    (
        "mac.kauth_listeners.Kauth_listeners",
        &["Name", "IData", "Callback Address", "Module", "Symbol"],
    ),
    ("mac.vfsevents.VFSevents", &["Name", "PID", "Events"]),
    (
        "mac.check_sysctl.Check_sysctl",
        &[
            "Name",
            "Number",
            "Perms",
            "Handler Address",
            "Value",
            "Handler Module",
            "Handler Symbol",
        ],
    ),
    ("mac.list_files.List_Files", &["Address", "File Path"]),
    (
        "mac.socket_filters.Socket_filters",
        &["Filter", "Name", "Member", "Socket", "Handler", "Module", "Symbol"],
    ),
    ("mac.dmesg.Dmesg", &["line"]),
    ("mac.bash.Bash", &["PID", "Process", "CommandTime", "Command"]),
    (
        "mac.kevents.Kevents",
        &["PID", "Process", "Ident", "Filter", "Context"],
    ),
    (
        "mac.netstat.Netstat",
        &[
            "Offset",
            "Proto",
            "Local IP",
            "Local Port",
            "Remote IP",
            "Remote Port",
            "State",
            "Process",
        ],
    ),
    (
        "mac.kauth_scopes.Kauth_scopes",
        &["Name", "IData", "Listeners", "Callback Address", "Module", "Symbol"],
    ),
    (
        "mac.timers.Timers",
        &[
            "Function",
            "Param 0",
            "Param 1",
            "Deadline",
            "Entry Time",
            "Module",
            "Symbol",
        ],
    ),
    (
        "mac.trustedbsd.Trustedbsd",
        &[
            "Member",
            "Policy Name",
            "Handler Address",
            "Handler Module",
            "Handler Symbol",
        ],
    ),
    (
        "mac.check_syscall.Check_syscall",
        &[
            "Table Address",
            "Table Name",
            "Index",
            "Handler Address",
            "Handler Module",
            "Handler Symbol",
        ],
    ),
    (
        "mac.proc_maps.Maps",
        &["PID", "Process", "Start", "End", "Protection", "Map Name", "File output"],
    ),
    (
        "mac.malfind.Malfind",
        &["PID", "Process", "Start", "End", "Protection", "Hexdump", "Disasm"],
    ),
    (
        "mac.ifconfig.Ifconfig",
        &["Interface", "IP Address", "Mac Address", "Promiscuous"],
    ),
    (
        "linux.lsof.Lsof",
        &[
            "PID",
            "TID",
            "Process",
            "FD",
            "Path",
            "Device",
            "Inode",
            "Type",
            "Mode",
            "Changed",
            "Modified",
            "Accessed",
            "Size",
        ],
    ),
    (
        "linux.capabilities.Capabilities",
        &[
            "Name",
            "Tid",
            "Pid",
            "PPid",
            "EUID",
            "cap_inheritable",
            "cap_permitted",
            "cap_effective",
            "cap_bounding",
            "cap_ambient",
        ],
    ),
    ("windows.filescan.FileScan", &["Offset", "Name"]),
    ("windows.mutantscan.MutantScan", &["Offset", "Name"]),
    (
        "windows.symlinkscan.SymlinkScan",
        &["Offset", "CreateTime", "From Name", "To Name"],
    ),
    (
        "windows.driverscan.DriverScan",
        &["Offset", "Start", "Size", "Service Key", "Driver Name", "Name"],
    ),
    (
        "windows.unloadedmodules.UnloadedModules",
        &["Name", "StartAddress", "EndAddress", "Time"],
    ),
    (
        "windows.envars.Envars",
        &["PID", "Process", "Block", "Variable", "Value"],
    ),
    (
        "windows.memmap.Memmap",
        &["Virtual", "Physical", "Size", "Offset in File", "File output"],
    ),
    (
        "windows.virtmap.VirtMap",
        &["Region", "Start offset", "End offset"],
    ),
    (
        "windows.vadwalk.VadWalk",
        &["PID", "Process", "Offset", "Parent", "Left", "Right", "Start", "End", "Tag"],
    ),
    ("windows.getsids.GetSIDs", &["PID", "Process", "SID", "Name"]),
    (
        "windows.privileges.Privs",
        &["PID", "Process", "Value", "Privilege", "Attributes", "Description"],
    ),
    (
        "windows.thrdscan.ThrdScan",
        &[
            "Offset",
            "PID",
            "TID",
            "StartAddress",
            "StartPath",
            "Win32StartAddress",
            "Win32StartPath",
            "CreateTime",
            "ExitTime",
        ],
    ),
    (
        "windows.sessions.Sessions",
        &[
            "Session ID",
            "Session Type",
            "Process ID",
            "Process",
            "User Name",
            "Create Time",
        ],
    ),
    (
        "windows.bigpools.BigPools",
        &["Allocation", "Tag", "PoolType", "NumberOfBytes", "Status"],
    ),
    (
        "windows.driverirp.DriverIrp",
        &["Offset", "Driver Name", "IRP", "Address", "Module", "Symbol"],
    ),
    (
        "windows.devicetree.DeviceTree",
        &[
            "Offset",
            "Type",
            "DriverName",
            "DeviceName",
            "DriverNameOfAttDevice",
            "DeviceType",
        ],
    ),
    (
        "windows.malware.malfind.Malfind",
        &[
            "PID",
            "Process",
            "Start VPN",
            "End VPN",
            "Tag",
            "Protection",
            "CommitCharge",
            "PrivateMemory",
            "File output",
            "Notes",
            "Hexdump",
            "Disasm",
        ],
    ),
    (
        "windows.malware.hollowprocesses.HollowProcesses",
        &["PID", "Process", "Notes"],
    ),
    (
        "windows.malware.pebmasquerade.PebMasquerade",
        &[
            "PID",
            "EPROCESS_ImageFileName",
            "EPROCESS_SeAudit_ImageFileName",
            "PEB_ImageFilePath",
            "PEB_ImageFilePath_Spoofed",
            "PEB_CommandLine_Spoofed",
        ],
    ),
    (
        "windows.malware.processghosting.ProcessGhosting",
        &[
            "PID",
            "Process",
            "Base",
            "FILE_OBJECT",
            "DeletePending",
            "DeleteOnClose",
            "Path",
        ],
    ),
    (
        "windows.malware.ldrmodules.LdrModules",
        &["Pid", "Process", "Base", "InLoad", "InInit", "InMem", "MappedPath"],
    ),
    (
        "windows.getservicesids.GetServiceSIDs",
        &["SID", "Service"],
    ),
    ("windows.ssdt.SSDT", &["Index", "Address", "Module", "Symbol"]),
    (
        "windows.callbacks.Callbacks",
        &["Type", "Callback", "Module", "Symbol", "Detail"],
    ),
    ("windows.kpcrs.KPCRs", &["Offset", "PRCB Offset"]),
    ("windows.pedump.PEDump", &["PID", "Process", "File output"]),
    ("windows.strings.Strings", &["String", "Physical Address", "Result"]),
    ("windows.pe_symbols.PESymbols", &["Module", "Symbol", "Address"]),
    (
        "windows.vadyarascan.VadYaraScan",
        &[
            "Offset", "PID", "CreateTime", "PPID", "ImageFileName", "SessionId",
            "Threads", "Rule", "Component", "Value",
        ],
    ),
    (
        "linux.vmayarascan.VmaYaraScan",
        &["Offset", "PID", "Rule", "Component", "Value"],
    ),
    (
        "windows.windowstations.WindowStations",
        &["Offset", "Name", "SessionId"],
    ),
    (
        "windows.desktops.Desktops",
        &["Offset", "Window Station", "Session", "Desktop", "Process", "PID"],
    ),
    (
        "windows.windows.Windows",
        &["Offset", "Station", "Session", "Desktop", "Window", "Procedure", "Process", "PID"],
    ),
    (
        "windows.consoles.Consoles",
        &["PID", "Process", "ConsoleInfo", "Property", "Address", "Data"],
    ),
    (
        "windows.cmdscan.CmdScan",
        &["PID", "Process", "ConsoleInfo", "Property", "Address", "Data"],
    ),
    (
        "windows.malware.skeleton_key_check.Skeleton_Key_Check",
        &["PID", "Process", "Skeleton Key Found", "rc4HmacInitialize", "rc4HmacDecrypt"],
    ),
    (
        "windows.debugregisters.DebugRegisters",
        &[
            "Process", "PID", "TID", "State", "Dr7",
            "Dr0", "Range0", "Symbol0", "Dr1", "Range1", "Symbol1",
            "Dr2", "Range2", "Symbol2", "Dr3", "Range3", "Symbol3",
        ],
    ),
    (
        "windows.shimcachemem.ShimcacheMem",
        &["Order", "Last Modified", "Last Update", "Exec Flag", "File Size", "File Path"],
    ),
    (
        "windows.etwpatch.EtwPatch",
        &["PID", "Process", "DLL", "Function", "Offset", "Opcode"],
    ),
    (
        "windows.mftscan.ADS",
        &["Offset", "Record Type", "Record Number", "MFT Type", "Filename", "ADS Filename", "Hexdump"],
    ),
    (
        "windows.mftscan.ResidentData",
        &["Offset", "Record Type", "Record Number", "MFT Type", "Filename", "Hexdump"],
    ),
    ("windows.truecrypt.Passphrase", &["Offset", "Length", "Password"]),
    (
        "windows.suspended_threads.SuspendedThreads",
        &[
            "Process", "PID", "TID", "StartFile", "StartSymbol", "StartAddress",
            "Win32StartFile", "Win32StartSymbol", "Win32StartAddress",
        ],
    ),
    (
        "windows.malware.direct_system_calls.DirectSystemCalls",
        &["Process", "PID", "Range", "Address", "Disasm"],
    ),
    (
        "windows.malware.unhooked_system_calls.UnhookedSystemCalls",
        &["Function", "Distinct Implementations", "Total Implementations"],
    ),
    (
        "windows.poolscanner.PoolScanner",
        &["Tag", "Offset", "Layer", "Name"],
    ),
    (
        "windows.mbrscan.MBRScan",
        &[
            "Potential MBR at Physical Offset",
            "Disk Signature",
            "Bootcode MD5",
            "Full MBR MD5",
            "PartitionIndex",
            "Bootable",
            "PartitionType",
            "SectorInSize",
            "Disasm",
        ],
    ),
    (
        "windows.crashinfo.Crashinfo",
        &[
            "Signature", "MajorVersion", "MinorVersion", "DirectoryTableBase",
            "PfnDataBase", "PsLoadedModuleList", "PsActiveProcessHead",
            "MachineImageType", "NumberProcessors", "KdDebuggerDataBlock",
            "DumpType", "SystemUpTime", "Comment", "SystemTime",
            "BitmapHeaderSize", "BitmapSize", "BitmapPages",
        ],
    ),
    (
        "windows.timers.Timers",
        &["Offset", "DueTime", "Period(ms)", "Signaled", "Routine", "Module", "Symbol"],
    ),
    (
        "windows.dumpfiles.DumpFiles",
        &["Cache", "FileObject", "FileName", "Result"],
    ),
    (
        "windows.iat.IAT",
        &["PID", "Name", "Library", "Bound", "Function", "Address"],
    ),
    (
        "windows.malware.suspicious_threads.SuspiciousThreads",
        &["Process", "PID", "TID", "Context", "Address", "VAD Path", "Note"],
    ),
    (
        "windows.malware.psxview.PsXView",
        &["Offset(Virtual)", "Name", "PID", "pslist", "psscan", "thrdscan", "csrss", "Exit Time"],
    ),
    (
        "windows.malware.drivermodule.DriverModule",
        &["Offset", "Known Exception", "Driver Name", "Service Key", "Alternative Name"],
    ),
    (
        "windows.joblinks.JobLinks",
        &[
            "Offset(V)",
            "Name",
            "PID",
            "PPID",
            "Sess",
            "JobSess",
            "Wow64",
            "Total",
            "Active",
            "Term",
            "JobLink",
            "Process",
        ],
    ),
    (
        "windows.verinfo.VerInfo",
        &["PID", "Process", "Base", "Name", "Major", "Minor", "Product", "Build"],
    ),
    (
        "windows.svcscan.SvcScan",
        &[
            "Offset",
            "Order",
            "PID",
            "Start",
            "State",
            "Type",
            "Name",
            "Display",
            "Binary",
            "Binary (Registry)",
            "Dll",
        ],
    ),
    (
        "windows.mftscan.MFTScan",
        &[
            "Offset",
            "Record Type",
            "Record Number",
            "Link Count",
            "MFT Type",
            "Permissions",
            "Attribute Type",
            "Created",
            "Modified",
            "Updated",
            "Accessed",
            "Filename",
        ],
    ),
    (
        "windows.netstat.NetStat",
        &[
            "Offset", "Proto", "LocalAddr", "LocalPort", "ForeignAddr",
            "ForeignPort", "State", "PID", "Owner", "Created",
        ],
    ),
    (
        "windows.netscan.NetScan",
        &[
            "Offset",
            "Proto",
            "LocalAddr",
            "LocalPort",
            "ForeignAddr",
            "ForeignPort",
            "State",
            "PID",
            "Owner",
            "Created",
        ],
    ),
    (
        "windows.registry.hashdump.Hashdump",
        &["User", "rid", "lmhash", "nthash"],
    ),
    (
        "windows.registry.lsadump.Lsadump",
        &["Key", "Secret", "Hex"],
    ),
    (
        "windows.registry.cachedump.Cachedump",
        &["Username", "Domain", "Domain name", "Hash"],
    ),
    (
        "windows.registry.getcellroutine.GetCellRoutine",
        &["Hive Offset", "Hive Name", "GetCellRoutine Module", "GetCellRoutine Handler"],
    ),
    (
        "windows.registry.amcache.Amcache",
        &[
            "EntryType", "Path", "Company", "LastModifyTime", "LastModifyTime2",
            "InstallTime", "CompileTime", "SHA1", "Service", "ProductName",
            "ProductVersion",
        ],
    ),
    (
        "windows.registry.scheduled_tasks.ScheduledTasks",
        &[
            "Task Name", "Principal ID", "Display Name", "Enabled", "Creation Time",
            "Last Run Time", "Last Successful Run Time", "Trigger Type",
            "Trigger Description", "Action Type", "Action", "Action Arguments",
            "Action Context", "Working Directory", "Key Name",
        ],
    ),
    ("windows.registry.hivescan.HiveScan", &["Offset"]),
    (
        "windows.registry.userassist.UserAssist",
        &[
            "Hive Offset",
            "Hive Name",
            "Path",
            "Last Write Time",
            "Type",
            "Name",
            "ID",
            "Count",
            "Focus Count",
            "Time Focused",
            "Last Updated",
            "Raw Data",
        ],
    ),
    (
        "windows.registry.hivelist.HiveList",
        &["Offset", "FileFullPath", "File output"],
    ),
    (
        "windows.registry.printkey.PrintKey",
        &[
            "Last Write Time",
            "Hive Offset",
            "Type",
            "Key",
            "Name",
            "Data",
            "Volatile",
        ],
    ),
];

#[test]
fn ported_plugins_declare_the_upstream_columns() {
    let registry = PluginRegistry::new();
    let mut failures = Vec::new();

    for (name, expected) in EXPECTED {
        let Some(plugin) = registry.get(name) else {
            failures.push(format!("{name}: not registered"));
            continue;
        };
        let actual: Vec<String> = plugin
            .columns()
            .into_iter()
            .map(|column| column.name)
            .collect();

        if actual != *expected {
            failures.push(format!(
                "{name}:\n  expected {expected:?}\n  actual   {actual:?}"
            ));
        }
    }

    assert!(
        failures.is_empty(),
        "plugin columns have drifted from upstream:\n{}",
        failures.join("\n")
    );
}

#[test]
fn every_registered_plugin_names_itself_consistently() {
    let registry = PluginRegistry::new();
    for plugin in registry.all() {
        // The registry keys on the name, so a plugin whose name does not
        // resolve back to itself would be unreachable from the command line.
        let found = registry.get(plugin.name()).expect("plugin resolves by name");
        assert_eq!(found.name(), plugin.name());
        // One plugin upstream leaves undocumented, and this port describes it
        // no better than upstream does.
        if plugin.name() != "windows.debugregisters.DebugRegisters" {
            assert!(
                !plugin.description().is_empty(),
                "{} has no description",
                plugin.name()
            );
        }
    }
}
