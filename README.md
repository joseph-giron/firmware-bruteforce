# XOR Filesystem Finder (Multithreaded)

A blazing-fast Rust tool to brute-force XOR keys on binary files to discover hidden filesystems.

## What it does

- Reads the first 1MB of a binary file
- XORs it with ALL keys from 0x00000000 to 0xFFFFFFFF (4 billion keys!)
- Checks for filesystem magic bytes:
  - **Squashfs** (both little and big endian)
  - **CramFS** (both little and big endian)
  - **JFFS2** (both little and big endian)
- Uses multithreading for maximum speed
- Reports any found filesystem signatures with type, offset, and endianness

## Features

✨ **No binwalk dependency** - checks magic bytes directly  
⚡ **Multithreaded** - uses all your CPU cores  
🎯 **Complete scan** - tests all 4 billion possible XOR keys  
🔍 **Multiple filesystems** - Squashfs, CramFS, and JFFS2  
📊 **Both endians** - detects LE and BE variants

## Build

```bash
cargo build --release
```

## Usage

```bash
# Use all CPU cores (default)
cargo run --release firmware.bin

# Specify number of threads
cargo run --release firmware.bin 16
```

Or after building:
```bash
./target/release/xor_squashfs firmware.bin
./target/release/xor_squashfs firmware.bin 8
```

## Performance

With modern hardware (8-16 cores):
- **Speed**: ~10-50 million keys/second
- **Time for full scan**: ~1-7 minutes for all 4 billion keys!

The actual time depends on:
- CPU cores (more = faster)
- CPU speed
- RAM speed

## Output

```
[*] Squashfs/CramFS/JFFS2 XOR Brute Forcer
[*] Reading first 1MB from: firmware.bin
[*] Read 1048576 bytes
[*] Using 16 threads
[*] Starting XOR brute force (0x00000000 to 0xFFFFFFFF)...
[*] Searching for:
    - Squashfs (LE: 0x73717368, BE: 0x68737173)
    - CramFS   (LE: 0x28cd3d45, BE: 0x453dcd28)
    - JFFS2    (LE: 0x1985, BE: 0x8519)

[Thread 0] Progress: 10.0% (key 0x19999999)
...

[+] Found 2 filesystem signature(s):

  [+] XOR Key: 0xDEADBEEF
      Filesystem: Squashfs
      Offset: 0x1000 (4096 bytes)
      Endianness: Little Endian

  [+] XOR Key: 0x12345678
      Filesystem: JFFS2
      Offset: 0x0 (0 bytes)
      Endianness: Big Endian

[*] Performance: 25000000 keys/second
```

## Tips

- The tool tests EVERY possible 32-bit XOR key
- Once you find a key, you can decode the entire file with that key
- Finding offset 0x0 means the filesystem starts at the beginning
- Multiple matches might indicate false positives - validate manually
