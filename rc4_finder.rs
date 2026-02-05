use std::fs::File;
use std::io::Read;
use std::sync::{Arc, Mutex};
use std::thread;

const CHUNK_SIZE: usize = 1 * 1024 * 1024; // 1 MB

// Filesystem magic numbers
const SQUASHFS_MAGIC_LE: u32 = 0x73717368; // "hsqs" in little endian
const SQUASHFS_MAGIC_BE: u32 = 0x68737173; // "hsqs" in big endian
const CRAMFS_MAGIC: u32 = 0x28cd3d45;      // CramFS magic
const CRAMFS_MAGIC_BE: u32 = 0x453dcd28;   // CramFS big endian
const JFFS2_MAGIC_BITMASK: u16 = 0x1985;   // JFFS2 uses 16-bit magic
const JFFS2_MAGIC_BITMASK_BE: u16 = 0x8519; // JFFS2 big endian

#[derive(Debug)]
struct FilesystemMatch {
    offset: usize,
    fs_type: String,
    endian: String,
}

// RC4 implementation
struct RC4 {
    s: [u8; 256],
    i: u8,
    j: u8,
}

impl RC4 {
    fn new(key: &[u8]) -> Self {
        let mut s = [0u8; 256];
        for i in 0..256 {
            s[i] = i as u8;
        }
        
        let mut j: u8 = 0;
        for i in 0..256 {
            j = j.wrapping_add(s[i]).wrapping_add(key[i % key.len()]);
            s.swap(i, j as usize);
        }
        
        RC4 { s, i: 0, j: 0 }
    }
    
    fn decrypt(&mut self, data: &[u8]) -> Vec<u8> {
        let mut output = Vec::with_capacity(data.len());
        
        for &byte in data {
            self.i = self.i.wrapping_add(1);
            self.j = self.j.wrapping_add(self.s[self.i as usize]);
            self.s.swap(self.i as usize, self.j as usize);
            
            let k = self.s[(self.s[self.i as usize].wrapping_add(self.s[self.j as usize])) as usize];
            output.push(byte ^ k);
        }
        
        output
    }
}

fn rc4_decrypt(data: &[u8], key: &[u8]) -> Vec<u8> {
    let mut rc4 = RC4::new(key);
    rc4.decrypt(data)
}

fn find_filesystem_magic(data: &[u8]) -> Vec<FilesystemMatch> {
    let mut matches = Vec::new();
    
    // Need at least 4 bytes for magic number
    if data.len() < 4 {
        return matches;
    }
    
    // Scan through data looking for magic bytes
    for i in 0..=(data.len() - 4) {
        // Check 32-bit magics (Squashfs, CramFS)
        let magic32 = u32::from_le_bytes([data[i], data[i+1], data[i+2], data[i+3]]);
        
        if magic32 == SQUASHFS_MAGIC_LE {
            matches.push(FilesystemMatch {
                offset: i,
                fs_type: "Squashfs".to_string(),
                endian: "Little Endian".to_string(),
            });
        } else if magic32 == SQUASHFS_MAGIC_BE {
            matches.push(FilesystemMatch {
                offset: i,
                fs_type: "Squashfs".to_string(),
                endian: "Big Endian".to_string(),
            });
        } else if magic32 == CRAMFS_MAGIC {
            matches.push(FilesystemMatch {
                offset: i,
                fs_type: "CramFS".to_string(),
                endian: "Little Endian".to_string(),
            });
        } else if magic32 == CRAMFS_MAGIC_BE {
            matches.push(FilesystemMatch {
                offset: i,
                fs_type: "CramFS".to_string(),
                endian: "Big Endian".to_string(),
            });
        }
        
        // Check 16-bit magics (JFFS2)
        let magic16 = u16::from_le_bytes([data[i], data[i+1]]);
        
        if magic16 == JFFS2_MAGIC_BITMASK {
            matches.push(FilesystemMatch {
                offset: i,
                fs_type: "JFFS2".to_string(),
                endian: "Little Endian".to_string(),
            });
        } else if magic16 == JFFS2_MAGIC_BITMASK_BE {
            matches.push(FilesystemMatch {
                offset: i,
                fs_type: "JFFS2".to_string(),
                endian: "Big Endian".to_string(),
            });
        }
    }
    
    matches
}

fn worker_thread(
    data: Arc<Vec<u8>>,
    start_key: u32,
    end_key: u32,
    results: Arc<Mutex<Vec<(Vec<u8>, FilesystemMatch)>>>,
    thread_id: usize,
    key_length: usize,
) {
    let mut local_results = Vec::new();
    let total_keys = end_key - start_key;
    
    for (count, key_val) in (start_key..end_key).enumerate() {
        // Progress update every 100k keys (RC4 is slower than XOR)
        if count % 100_000 == 0 && count > 0 {
            let progress = (count as f64 / total_keys as f64) * 100.0;
            println!("[Thread {}] Progress: {:.1}% (key 0x{:08X})", thread_id, progress, key_val);
        }
        
        // Generate key bytes based on key length
        let key_bytes: Vec<u8> = match key_length {
            1 => vec![key_val as u8],
            2 => vec![key_val as u8, (key_val >> 8) as u8],
            3 => vec![key_val as u8, (key_val >> 8) as u8, (key_val >> 16) as u8],
            4 => vec![key_val as u8, (key_val >> 8) as u8, (key_val >> 16) as u8, (key_val >> 24) as u8],
            _ => vec![key_val as u8, (key_val >> 8) as u8, (key_val >> 16) as u8, (key_val >> 24) as u8],
        };
        
        // RC4 decrypt the data
        let decrypted_data = rc4_decrypt(&data, &key_bytes);
        
        // Check for filesystem magic bytes
        let matches = find_filesystem_magic(&decrypted_data);
        
        if !matches.is_empty() {
            for fs_match in matches {
                local_results.push((key_bytes.clone(), fs_match));
            }
        }
    }
    
    // Store results
    if !local_results.is_empty() {
        let mut results_lock = results.lock().unwrap();
        results_lock.extend(local_results);
    }
}

fn main() -> Result<(), Box<dyn std::error::Error>> {
    let args: Vec<String> = std::env::args().collect();
    
    if args.len() < 2 {
        eprintln!("Usage: {} <binary_file> [key_length] [num_threads]", args[0]);
        eprintln!("  key_length: 1-4 bytes (default: 4)");
        eprintln!("  num_threads: optional, default is number of CPU cores");
        std::process::exit(1);
    }
    
    let input_file = &args[1];
    let key_length = if args.len() >= 3 {
        args[2].parse::<usize>()?.min(4).max(1)
    } else {
        4
    };
    let num_threads = if args.len() >= 4 {
        args[3].parse::<usize>()?
    } else {
        num_cpus::get()
    };
    
    println!("[*] RC4 Filesystem Brute Forcer");
    println!("[*] Reading first 1MB from: {}", input_file);
    
    // Read the first 1MB
    let mut file = File::open(input_file)?;
    let mut buffer = vec![0u8; CHUNK_SIZE];
    let bytes_read = file.read(&mut buffer)?;
    buffer.truncate(bytes_read);
    
    println!("[*] Read {} bytes", bytes_read);
    println!("[*] RC4 key length: {} byte(s)", key_length);
    println!("[*] Using {} threads", num_threads);
    
    let max_key_value = match key_length {
        1 => 0xFF_u32,
        2 => 0xFFFF_u32,
        3 => 0xFFFFFF_u32,
        4 => 0xFFFFFFFF_u32,
        _ => 0xFFFFFFFF_u32,
    };
    
    println!("[*] Testing {} possible keys (0x00 to 0x{:X})...", max_key_value + 1, max_key_value);
    println!("[*] Searching for:");
    println!("    - Squashfs (LE: 0x73717368, BE: 0x68737173)");
    println!("    - CramFS   (LE: 0x28cd3d45, BE: 0x453dcd28)");
    println!("    - JFFS2    (LE: 0x1985, BE: 0x8519)");
    println!();
    
    let data = Arc::new(buffer);
    let results = Arc::new(Mutex::new(Vec::new()));
    
    let keys_per_thread = ((max_key_value as u64 + 1) / num_threads as u64) as u32;
    let mut handles = vec![];
    
    let start_time = std::time::Instant::now();
    
    for i in 0..num_threads {
        let data_clone = Arc::clone(&data);
        let results_clone = Arc::clone(&results);
        
        let start_key = (i as u32) * keys_per_thread;
        let end_key = if i == num_threads - 1 {
            max_key_value
        } else {
            ((i as u32) + 1) * keys_per_thread
        };
        
        println!("[*] Thread {} scanning: 0x{:08X} to 0x{:08X}", i, start_key, end_key);
        
        let handle = thread::spawn(move || {
            worker_thread(data_clone, start_key, end_key, results_clone, i, key_length);
        });
        
        handles.push(handle);
    }
    
    // Wait for all threads to complete
    for handle in handles {
        handle.join().unwrap();
    }
    
    let elapsed = start_time.elapsed();
    
    println!("\n[*] Scan complete in {:.2?}", elapsed);
    
    let results_lock = results.lock().unwrap();
    
    if results_lock.is_empty() {
        println!("[*] No filesystems detected");
    } else {
        println!("[+] Found {} filesystem signature(s):", results_lock.len());
        println!();
        
        for (key_bytes, fs_match) in results_lock.iter() {
            print!("  [+] RC4 Key: ");
            for byte in key_bytes {
                print!("{:02X}", byte);
            }
            println!();
            println!("      Filesystem: {}", fs_match.fs_type);
            println!("      Offset: 0x{:X} ({} bytes)", fs_match.offset, fs_match.offset);
            println!("      Endianness: {}", fs_match.endian);
            println!();
        }
    }
    
    // Performance stats
    let keys_tested = max_key_value as u64 + 1;
    let keys_per_sec = keys_tested as f64 / elapsed.as_secs_f64();
    println!("[*] Performance: {:.0} keys/second", keys_per_sec);
    
    Ok(())
}
