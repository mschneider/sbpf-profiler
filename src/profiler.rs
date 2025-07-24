#![allow(clippy::arithmetic_side_effects)]
//! Generates a flame chart from call trace data

use inferno::flamegraph;
use object::{Object, ObjectSection, ObjectSymbol, SymbolKind};
use rustc_demangle::demangle;
use std::collections::{BTreeMap, HashMap, HashSet};
use std::fs::{self, File};
use std::io::{BufRead, BufReader, Write};
use std::path::{Path, PathBuf};
use uuid::Uuid;

struct SymbolizerContext {
    symbol_map: BTreeMap<u64, (String, u64)>,
    text_base_addr: u64,
}

impl SymbolizerContext {
    fn new(elf_path: &Path) -> Result<Self, Box<dyn std::error::Error>> {
        let elf_data = fs::read(elf_path)?;
        let object_file = object::File::parse(&*elf_data)?;

        let text_section = object_file
            .section_by_name(".text")
            .ok_or("Failed to find .text section in the ELF file")?;
        let text_base_addr = text_section.address();

        let mut symbol_map: BTreeMap<u64, (String, u64)> = BTreeMap::new();
        for symbol in object_file.symbols() {
            if symbol.kind() == SymbolKind::Text && symbol.size() > 0 {
                if let Ok(name) = symbol.name() {
                    let demangled = demangle(name).to_string();
                    let clean_name = demangled
                        .rsplit_once("::h")
                        .map_or(demangled.as_str(), |(base, _)| base)
                        .to_string();
                    symbol_map.insert(symbol.address(), (clean_name, symbol.size()));
                }
            }
        }

        Ok(SymbolizerContext {
            symbol_map,
            text_base_addr,
        })
    }

    fn symbolize_pc(&self, pc_index: u64) -> String {
        const INSTRUCTION_SIZE: u64 = 8;
        let byte_offset = pc_index
            .checked_mul(INSTRUCTION_SIZE)
            .expect("mul overflowed");
        let lookup_address = self.text_base_addr + byte_offset;

        if let Some((func_addr, (name, size))) =
            self.symbol_map.range(..=lookup_address).next_back()
        {
            if lookup_address < func_addr + size {
                return name.clone();
            }
        }
        format!("0x{:x}", lookup_address)
    }
}

/// Trace file to flame chart in svg format
pub fn process_trace_file(
    trace_path: &Path,
    root_program_path: &Path,
) -> Result<PathBuf, Box<dyn std::error::Error>> {
    let program_dir = root_program_path
        .parent()
        .ok_or("Failed to get parent directory of the program")?;

    let mut symbolizer_contexts: HashMap<String, SymbolizerContext> = HashMap::new();

    println!(
        "[SBPF Profiler] Loading main program: {:?}",
        root_program_path
    );
    symbolizer_contexts.insert(
        "ROOT_PLACEHOLDER".to_string(),
        SymbolizerContext::new(root_program_path)?,
    );

    let trace_file = File::open(trace_path)?;
    let reader = BufReader::new(trace_file);

    let mut vm_context_stack: Vec<(String, Vec<String>)> = Vec::new();
    let mut time_series_stacks: Vec<String> = Vec::new();
    let mut seen_program_ids = HashSet::new();

    for line in reader.lines() {
        let line = line?.trim().to_string();
        if line.is_empty() {
            continue;
        }

        if let Some(program_id) = line.strip_prefix("VM_START:") {
            if !symbolizer_contexts.contains_key(program_id) {
                let program_path = program_dir.join(format!("{}.so", program_id));
                if program_path.exists() {
                    println!(
                        "[SBPF Profiler] Loading symbols for CPI program: {}",
                        program_id
                    );
                    match SymbolizerContext::new(&program_path) {
                        Ok(ctx) => {
                            symbolizer_contexts.insert(program_id.to_string(), ctx);
                        }
                        Err(e) => {
                            eprintln!(
                                "[SBPF Profiler] Warning: Failed to load symbols for {}: {}",
                                program_id, e
                            );
                        }
                    }
                } else if !seen_program_ids.contains(program_id) {
                    eprintln!(
                        "[SBPF Profiler] Warning: No .so file found for program '{}'",
                        program_id
                    );
                }
            }
            seen_program_ids.insert(program_id.to_string());
            vm_context_stack.push((program_id.to_string(), Vec::new()));
        } else if line == "VM_END" {
            vm_context_stack.pop();
        } else if line.starts_with("CPI_BOUNDARY:") {
            // This is handled by the subsequent VM_START (for non native programs).
            continue;
        } else if let Some((current_program_id, _)) = vm_context_stack.last() {
            let mut symbolized_frames: Vec<String> = Vec::new();
            for pc_str in line.split(';') {
                if let Ok(pc_index) = pc_str.parse::<u64>() {
                    let mut symbol = symbolizer_contexts
                        .get(current_program_id)
                        .map(|ctx| ctx.symbolize_pc(pc_index))
                        .unwrap_or_else(|| format!("{}:0x{:x}", "?", pc_index * 8));

                    if current_program_id != "ROOT_PLACEHOLDER" {
                        let short_id = current_program_id.get(..8).unwrap_or(current_program_id);
                        symbol = format!("CPI_{}:{}", short_id, symbol);
                    }

                    symbolized_frames.push(symbol);
                }
            }
            symbolized_frames.reverse(); // Convert from leaf->root to root->leaf

            let mut full_sample_stack: Vec<String> = Vec::new();
            for item in vm_context_stack
                .iter()
                .take(vm_context_stack.len().saturating_sub(1))
            {
                full_sample_stack.extend_from_slice(&item.1);
            }
            full_sample_stack.extend(symbolized_frames.clone());

            let folded_line = full_sample_stack.join(";");
            time_series_stacks.push(folded_line);

            if let Some((_, last_frames)) = vm_context_stack.last_mut() {
                *last_frames = symbolized_frames;
            }
        }
    }

    let program_name = root_program_path
        .file_stem()
        .and_then(|s| s.to_str())
        .unwrap_or("unknown");

    let output_filename = format!("flamechart_{}_{}.txt", program_name, Uuid::new_v4());
    let output_path = program_dir.join(output_filename);
    let mut output_file = File::create(&output_path)?;

    time_series_stacks.reverse();
    for stack in time_series_stacks {
        writeln!(output_file, "{} 1", stack)?;
    }
    output_file.sync_all()?;

    let mut options = flamegraph::Options::default();
    options.title = "SBPF profile".to_string();
    options.count_name = "steps".to_string();
    options.font_type = "monospace".to_string();
    options.font_size = 12;
    options.frame_height = 16;
    options.flame_chart = true;

    let input_file = File::open(&output_path)?;
    let svg_path = output_path.with_extension("svg");
    let output_file = File::create(&svg_path)?;

    flamegraph::from_reader(&mut options, input_file, output_file)?;

    let _ = fs::remove_file(&output_path);

    Ok(svg_path)
}
