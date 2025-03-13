use std::collections::HashSet;
use std::fmt;
use std::fs::{self, File};
use std::io::{self, BufRead, Read, Seek, SeekFrom};
use std::path::Path;

fn main() {
    if cfg!(not(target_os = "linux")) {
        panic!("This program can only run on Linux!");
    }

    let args = parse_args().unwrap();
    println!("{:?}", args);

    search_memory(args.pid, args.continuous).unwrap();
}

#[derive(Debug)]
#[allow(dead_code)]
enum SearchError {
    CliArgParseError(String),
    ProcTraversePidsIo(io::Error),
    ProcParseInt {
        file: String,
        val: String,
        err: std::num::ParseIntError,
    },
    ProcParseLine {
        file: String,
        line: String,
    },
    SearchMemIo {
        pid: u32,
        err: io::Error,
    },
    PermissionDeniedKallsyms,
    SearchMemPermissionDeniedPid {
        pid: u32,
        err: io::Error,
    },
}

impl fmt::Display for SearchError {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        write!(f, "{:?}", self)
    }
}

impl std::error::Error for SearchError {}

type Result<T> = std::result::Result<T, SearchError>;

impl From<(u32, io::Error)> for SearchError {
    fn from(err: (u32, io::Error)) -> SearchError {
        match err.1.kind() {
            io::ErrorKind::PermissionDenied => SearchError::SearchMemPermissionDeniedPid {
                pid: err.0,
                err: err.1,
            },
            _ => SearchError::SearchMemIo {
                pid: err.0,
                err: err.1,
            },
        }
    }
}

#[derive(Debug)]
struct CliArgs {
    pid: Option<u32>,
    continuous: bool,
}

// Yes i know clap exists but I don't want the dependency for now...
// TODO add usage()
fn parse_args() -> Result<CliArgs> {
    let args: Vec<String> = std::env::args().collect();

    // Default values
    let mut parsed = CliArgs {
        pid: None,
        continuous: false,
    };

    let mut i = 1;
    while i < args.len() {
        match args[i].as_ref() {
            "--pid" => {
                i += 1;
                if i >= args.len() {
                    return Err(SearchError::CliArgParseError(
                        "Argument --pid requires parameter".to_string(),
                    ));
                }

                parsed.pid = Some(args[i].parse::<u32>().map_err(|_| {
                    SearchError::CliArgParseError(format!(
                        "Argument --pid ({}) is not a number",
                        args[i]
                    ))
                })?);
            }
            "--continuous" => parsed.continuous = true,
            _ => {
                return Err(SearchError::CliArgParseError(format!(
                    "Unexpected argument {}",
                    args[i]
                )))
            }
        }

        i += 1;
    }

    Ok(parsed)
}

const ENTROPY_MULTIPLIER: u64 = 1000000;

#[derive(Debug, Eq, Hash, PartialEq, Clone)]
struct Match {
    val: Vec<u8>,
    pid: u32,
    pname: String,
    addr: u64, // Address in process memory.
    // We save the entropy as fixed precision integer pre-multiplied by
    // ENTROPY_MULTIPLIER in order to still be able to derive Eq/PartialEq/Hash
    // for the Match struct.
    entropy: u64,
}

impl fmt::Display for Match {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        write!(
            f,
            "Found string with entropy {:.4} in process {:16} with pid {:7} at 0x{:016X}: \"{}\" ",
            self.entropy as f64 / ENTROPY_MULTIPLIER as f64,
            self.pname,
            self.pid,
            self.addr,
            std::str::from_utf8(&self.val).unwrap(),
        )
    }
}

fn search_memory(pid: Option<u32>, continuous: bool) -> Result<()> {
    let ownpid = std::process::id();

    let mut matches: HashSet<Match> = HashSet::new();

    loop {
        let pids = {
            let mut res = Vec::new();
            match pid {
                Some(p) => {
                    if p != ownpid {
                        res.push(p)
                    }
                }
                None => {
                    for entry in
                        fs::read_dir(Path::new("/proc")).map_err(SearchError::ProcTraversePidsIo)?
                    {
                        let path = entry.map_err(SearchError::ProcTraversePidsIo)?.path();

                        if path.is_dir() {
                            if let Some(p_) = path.file_name().and_then(|s| s.to_str()) {
                                if let Ok(p) = p_.parse::<u32>() {
                                    // Don't search own process memory.
                                    if p == ownpid {
                                        continue;
                                    }

                                    res.push(p);
                                }
                            }
                        }
                    }
                }
            }
            res
        };

        for p in pids.into_iter() {
            match search_memory_pid(p) {
                Ok(ms) => {
                    for m in ms {
                        if continuous {
                            if matches.contains(&m) {
                                continue;
                            } else {
                                matches.insert(m.clone());
                            }
                        }
                        println!("{}", m);
                    }
                    Ok(())
                }
                Err(SearchError::SearchMemPermissionDeniedPid { pid: p, err }) => {
                    println!("PID {}: {:?}", p, err);
                    Ok(())
                }
                Err(e) => Err(e),
            }?;
        }

        if !continuous {
            break;
        }
    }

    Ok(())
}

fn search_memory_pid(pid: u32) -> Result<Vec<Match>> {
    let minlen = 8; // TODO move to CLI argument

    let mut matches = Vec::new();

    let pname = fs::read_to_string(format!("/proc/{pid}/comm"))
        .map_err(|e| (pid, e))?
        .trim()
        .to_string();

    let regions = read_memory_maps(pid)?;
    let mem_file_path = format!("/proc/{pid}/mem");
    let mut mem_file = File::open(mem_file_path).map_err(|e| (pid, e))?;

    for region in regions {
        // Exclude non-readable memory regions.
        if !region.permissions.contains('r') {
            continue;
        }

        // Filter special cases on pathname
        if let Some(p) = &region.pathname {
            // https://lwn.net/Articles/615809/ Implementing virtual system calls.
            // These memory regions somehow cause an error on reading, even thow by page table
            // permissions they are supposed to be readable. => Just exclude them, they probably don't
            // contain anything of interest.
            if p == "[vdso]" || p == "[vvar]" || p == "[vvar_vclock]" {
                continue;
            }

            if p.starts_with("/dev/dri/") && region.permissions == "rw-s" {
                continue;
            }
        }

        let size = region.end - region.start;
        let mut buffer = vec![0u8; size as usize];

        mem_file
            .seek(SeekFrom::Start(region.start))
            .map_err(|e| (pid, e))?;
        match mem_file.read_exact(&mut buffer) {
            Ok(_) => {
                let mut i = 0;
                while i < buffer.len() {
                    let start = i;
                    while i < buffer.len() && is_ascii_printable(buffer[i]) {
                        i += 1;
                    }
                    if i - start >= minlen {
                        let buf = &buffer[start..i];
                        matches.push(Match {
                            val: buf.to_vec(),
                            pid,
                            pname: pname.clone(),
                            addr: region.start + start as u64,
                            entropy: (calculate_entropy(buf) * ENTROPY_MULTIPLIER as f64) as u64,
                        });
                    }

                    i += 1;
                }
            }
            Err(e) => {
                eprintln!("Could not read memory region {:?}: {}", region, e);
            }
        }
    }

    Ok(matches)
}

fn is_ascii_printable(b: u8) -> bool {
    0x20 <= b && b <= 0x7e
}

// Calculate the Shannon Entropy, or at least an approximation thereof since
// we (probably wrongly) assume a uniform distribution of bytes.
// Note that since there are only 256 different possibilities / values a single
// byte can take, the maximum value the entropy can take is log2(256) = 8.0.
fn calculate_entropy(buf: &[u8]) -> f64 {
    let mut vals: Vec<u64> = vec![0; 0x100];
    for b in buf.iter() {
        vals[*b as usize] += 1;
    }

    let mut entropy = 0.0;
    for val in vals.into_iter() {
        if val > 0 {
            let p = val as f64 / buf.len() as f64;
            entropy -= p * f64::log2(p);
        }
    }

    entropy
}

#[derive(Debug)]
struct MemoryRegion {
    start: u64,
    end: u64,
    permissions: String,
    pathname: Option<String>,
}

fn read_memory_maps(pid: u32) -> Result<Vec<MemoryRegion>> {
    let path = format!("/proc/{pid}/maps");
    let file = File::open(path.clone()).map_err(|e| (pid, e))?;
    let reader = io::BufReader::new(file);

    let mut regions = Vec::new();

    for line in reader.lines() {
        let line = line.map_err(|e| (pid, e))?;
        let parts: Vec<&str> = line.split_whitespace().collect();

        let address_range: Vec<&str> = parts[0].split('-').collect();
        let start =
            u64::from_str_radix(address_range[0], 16).map_err(|err| SearchError::ProcParseInt {
                file: path.clone(),
                val: address_range[0].to_string(),
                err,
            })?;
        let end =
            u64::from_str_radix(address_range[1], 16).map_err(|err| SearchError::ProcParseInt {
                file: path.clone(),
                val: address_range[0].to_string(),
                err,
            })?;
        let permissions = parts[1].to_string();
        let pathname = if parts.len() > 5 {
            Some(parts[5..].join(" "))
        } else {
            None
        };

        regions.push(MemoryRegion {
            start,
            end,
            permissions,
            pathname,
        });
    }

    Ok(regions)
}
