# vol-rs

A port of the Volatility 3 memory forensics framework from Python to Rust. It reads the same memory images, runs the same plugins with the same options, and prints the same output, byte for byte, a good deal faster.

## License

This project is a port of Volatility 3 and is therefore an "Addition" under the Volatility Software License 1.0, so it is published under that same license. The full text is in [LICENSE](LICENSE) and online at https://www.volatilityfoundation.org/license/vsl-v1.0. Every source file keeps the notice recording what it was derived from.

This project is not affiliated with or endorsed by the Volatility Foundation. The name Volatility is used only to say what this is a port of.

## Building

Rust 1.85 or newer, then:

```
cargo build --release
```

The binary lands at `target/release/vol-rs`. Nothing optional is needed. Symbol decompression, RC4, DES, AES, YARA matching, PNG writing and tar archives are all built in, where the Python version reaches for `pycryptodomex`, `yara-python` and `pillow`. Instructions are decoded by capstone 5.0.6, the same library the Python version uses for the same columns, compiled in rather than installed alongside.

## Using it

```
./target/release/vol-rs -f memory.raw windows.pslist.PsList
./target/release/vol-rs -f memory.lime linux.bash.Bash
./target/release/vol-rs -f memory.raw -r csv windows.netscan.NetScan
./target/release/vol-rs windows.malfind.Malfind --help
./target/release/vol-rs --list-plugins
```

Every option the Python version takes is taken here too, with the same names and the same defaults, including `-o`, `-r`, `-s`, `-c`, `-e`, `--filters`, `--hide-columns`, `--save-config`, `--stackers` and `--single-swap-locations`. Each plugin's own options match as well, which the help pages show: all 197 of them are identical to the Python ones, character for character.

## Symbols

Symbol packs go in `$XDG_DATA_HOME/vol-rs/symbols`, or `~/.local/share/vol-rs/symbols` when that variable is not set. A pack somewhere else is named with `--symbol-dirs` or through the `VOLRS_SYMBOL_PATH` environment variable. A Windows kernel that no pack describes is looked up on the Microsoft symbol server, and the database found there is turned into a symbol file and kept, so the fetch happens once. The database itself is cached under `~/.cache/vol-rs` and the symbol file is written beside the packs.

## What has been checked

Both sides were run against the same captures and diffed, header framing and trailing newlines included:

| Check | Result |
|---|---|
| Windows plugins with no arguments, Windows 10 19041 crash dump | 112 of 114 identical |
| Windows plugins with no arguments, Windows XP raw capture | 113 of 114 identical |
| Linux plugins with no arguments, Linux 3.2 raw capture | 60 of 60 identical |
| Files written by extracting plugins | 24,441 compared across the three captures, every one equal |
| Plugin help pages | 197 of 197 identical |
| Renderers | `csv`, `json`, `jsonl`, `quick` and `pretty` compared on several plugins, all identical |

Two plugins account for every row that is not identical. `isfinfo` without `--live` lists the Python version's own identifier database rather than the image, in that database's own order, where this port lists the symbol directories, so neither answer is derivable from the other. `windows.memmap.Memmap` on the Windows 10 capture is killed by the out of memory killer part way through, and where it stops depends on the free memory at the time, so two Python runs do not agree with each other either. This port finishes all 9,014,410 lines of it, and every line the Python version wrote first is reproduced exactly. On the Windows XP capture both finish and the output matches.

Instructions are decoded by the same library the Python version uses, compiled in at version 5.0.6, which is the version the reference was pinned to for these comparisons. Version 5.0.7 decodes one more instruction form, which changes how about two percent of `windows.mbrscan`'s lines are spelled on the Windows 10 capture and nothing else.

Windows symbols for the captures used here come from the symbol packs the Volatility Foundation publishes, read by both tools. For an earlier Windows 10 19045 capture whose kernel no pack described, the description this port builds from the database Microsoft publishes matched the one the Python version builds from the same database exactly, across all 16 base types, 293 enumerations, 1,653 structures and 40,007 symbols.

Across every plugin that runs with no arguments, the Windows 10 sweep takes 233 seconds here against 6113 seconds, the Windows XP sweep 48 seconds against 1674 seconds, and the Linux sweep 36 seconds against 1896 seconds.

## Speed

The ten widest gaps on each capture, out of every plugin that runs with no arguments:

### Windows 10 19041 crash dump

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

### Windows XP raw capture

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

### Linux 3.2 raw capture

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

[BENCHMARKS.md](BENCHMARKS.md) has the rest: every plugin on all three captures and the machine the numbers were measured on.

## Known differences

A handful of things cannot match, and each is deliberate:

* `linux.pagecache.RecoverFs` stamps every file in the tarball it writes with the moment the plugin ran, so no two runs agree, not even two Python runs. The table matches and so does the unpacked tree.
* `--save-config` and `timeliner --record-config` record every setting that describes the image, but not the Python version's checks that an imported component is new enough, because this port has no such checks to record.
* `linux.mountinfo --mount-format` joins a Python set, so its column order changes between two Python runs. This port lists the mount options first and the filesystem options after, in the order the kernel holds them.
* `frameworkinfo` and `isfinfo` describe the tool rather than the image, so they report this port's own layers, plugins and symbol files.
* The line in `--help` naming the cache directory names this port's own cache.

## To do

Everything below is ported and builds, but has not been run against real evidence yet:

- [ ] Test the 23 macOS plugins against a real Mac capture. All 23 were read line by line against the Python source, and every type, member and symbol they touch was checked against the 129 published Darwin symbol files covering 10.6 to 10.15, so the version fallbacks are known to be complete. What is left is a real Mac image to run them on.
- [ ] Test the remaining image formats. Raw, VMware, LiME and Windows crash dump captures have all been used, so the AVML, QEMU, ELF core and Xen layers are the ones still unproven on real files.
- [ ] Test more kernel versions. Windows XP, Windows 10 19041 and 19045, Linux 3.2 and Linux 6.8 is still a narrow base, and plugins that read version specific structures are where a port is most likely to drift.
- [ ] Add the arrow and parquet renderers. They are accepted on the command line and refused, which is what the Python version does when its table library is missing.

## Credit

Volatility 3 is the work of the Volatility Foundation and its contributors. This is a port of their design, their plugin set and their output format, and it exists because that work is open.
