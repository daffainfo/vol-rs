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

The binary lands at `target/release/vol-rs`. Nothing optional is needed. Symbol decompression, RC4, DES, AES, YARA matching, x86 disassembly, PNG writing and tar archives are all built in, where the Python version reaches for `pycryptodomex`, `yara-python`, `capstone` and `pillow`.

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

Symbol packs go in `$XDG_DATA_HOME/vol-rs/symbols`, or `~/.local/share/vol-rs/symbols` when that variable is not set. A pack somewhere else is named with `--symbol-dirs` or through the `VOLRS_SYMBOL_PATH` environment variable. Windows symbols are fetched from the Microsoft symbol server on demand and cached under `~/.cache/vol-rs`.

## What has been checked

Both sides were run against the same captures and diffed, header framing and trailing newlines included:

| Check | Result |
|---|---|
| Windows plugins with no arguments | 99 of 100 identical |
| Linux plugins with no arguments | 56 of 57 identical |
| Runs that take arguments | 43 of 43 identical |
| Files written by extracting plugins | 1,747 compared, every file both tools wrote is equal |
| Plugin help pages | 197 of 197 identical |

The eight files that did not compare equal are the two cases listed under Known differences below. Seven are partial files the Python version leaves on disk after reporting that it could not dump them, which this port does not create, and one is a tarball whose contents match but whose timestamps record when each run happened.

The two plugins missing from those counts are the ones the Python version cannot finish on the test machine. `windows.memmap.Memmap` is killed by the out of memory killer after 7.8 million lines, and `linux.pscallstack.PsCallStack` is killed before it ends. In both cases every line the Python version managed to write first is reproduced exactly.

Across every plugin that runs with no arguments, the Windows sweep takes 273 seconds here against 5723 seconds, and the Linux sweep 68 seconds against 3130 seconds.

## Speed

The ten widest gaps on each capture, out of every plugin that runs with no arguments:

### Windows

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

### Linux

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

[BENCHMARKS.md](BENCHMARKS.md) has the rest: every plugin on both captures, the runs that take arguments, and the machine the numbers were measured on.

## Known differences

A handful of things cannot match, and each is deliberate:

* `linux.pagecache.RecoverFs` stamps every file in the tarball it writes with the moment the plugin ran, so no two runs agree, not even two Python runs. The table matches and so does the unpacked tree.
* `--save-config` and `timeliner --record-config` record every setting that describes the image, but not the Python version's checks that an imported component is new enough, because this port has no such checks to record.
* `linux.mountinfo --mount-format` joins a Python set, so its column order changes between two Python runs. This port lists the mount options first and the filesystem options after, in the order the kernel holds them.
* `frameworkinfo` and `isfinfo` describe the tool rather than the image, so they report this port's own layers, plugins and symbol files.
* `windows.dumpfiles` does not leave behind the partial files the Python version creates before it discovers it cannot read them. The tables agree, the directories differ by those files.
* The line in `--help` naming the cache directory names this port's own cache.

## To do

Everything below is ported and builds, but has not been run against real evidence yet:

- [ ] Test the 23 macOS plugins against a real Mac capture. All 23 were read line by line against the Python source, and every type, member and symbol they touch was checked against the 129 published Darwin symbol files covering 10.10 to 10.15, so the version fallbacks are known to be complete. What is left is a real Mac image to run them on.
- [ ] Test 32 bit images. All the verification so far used 64 bit captures, so the Intel32 and PAE paging paths have only unit test coverage.
- [ ] Test the other image formats. Only VMware and LiME captures have been used, so the crash dump, AVML, QEMU, ELF core and Xen layers are still unproven on real files.
- [ ] Test more kernel versions. One Windows 10 19045 and one Linux 6.8 capture is a narrow base, and plugins that read version specific structures are where a port is most likely to drift.
- [ ] Add the arrow and parquet renderers. They are accepted on the command line and refused, which is what the Python version does when its table library is missing.

## Credit

Volatility 3 is the work of the Volatility Foundation and its contributors. This is a port of their design, their plugin set and their output format, and it exists because that work is open.
