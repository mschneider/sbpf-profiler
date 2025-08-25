use std::fs::File;
use std::io::BufWriter;
use std::{cell::RefCell, path::PathBuf};

pub struct ProfilingState {
    pub(crate) writer: Option<BufWriter<File>>,
    pub(crate) trace_path: Option<PathBuf>,
    pub(crate) root_program_path: Option<PathBuf>,
    pub(crate) next_program_id: Option<[u8; 32]>,
    pub(crate) nesting_level: u32,
    pub(crate) symbolizable_stack: Vec<bool>,
    pub(crate) symbolizable_programs: Vec<(String, bool)>,
}

impl ProfilingState {
    pub(crate) fn is_program_symbolizable(&mut self, pubkey: &String) -> bool {
        if pubkey == "ROOT_PLACEHOLDER" {
            return true;
        }

        const SYSTEM_PROGRAMS: &[&str] = &[
            "11111111111111111111111111111111",
            "AddressLookupTab1e1111111111111111111111111",
            "BPFLoader1111111111111111111111111111111111",
            "BPFLoader2111111111111111111111111111111111",
            "BPFLoaderUpgradeab1e11111111111111111111111",
            "ComputeBudget111111111111111111111111111111",
            "Config1111111111111111111111111111111111111",
            "Ed25519SigVerify111111111111111111111111111",
            "Feature111111111111111111111111111111111111",
            "KeccakSecp256k11111111111111111111111111111",
            "Stake11111111111111111111111111111111111111",
            "Vote111111111111111111111111111111111111111",
        ];

        if SYSTEM_PROGRAMS.contains(&pubkey.as_str()) {
            return false;
        }

        if let Some(record) = self
            .symbolizable_programs
            .iter()
            .find(|val| *pubkey == val.0)
        {
            record.1
        } else {
            let so_filename = format!("{pubkey}.so");
            let mut so_path = self.root_program_path.clone().expect("should be set");
            so_path.set_file_name(so_filename);
            let is_symbolizable = so_path.is_file();

            if !is_symbolizable {
                println!("[SBPF Profiler] .so file for {} not found", pubkey);
            }

            self.symbolizable_programs
                .push((pubkey.to_owned(), is_symbolizable));
            is_symbolizable
        }
    }
}

thread_local! {
    pub static PROFILING_STATE: RefCell<ProfilingState> = const { RefCell::new(ProfilingState {
        writer: None,
        trace_path: None,
        root_program_path: None,
        next_program_id: None,
        nesting_level: 0,
        symbolizable_stack: Vec::new(),
        symbolizable_programs: Vec::new(),
    })
    };
}
