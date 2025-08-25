#![allow(clippy::arithmetic_side_effects)]
//! Generates a flame chart from call trace data

use inferno::flamegraph;
use object::{Object, ObjectSection, ObjectSymbol, SymbolKind};
use rustc_demangle::demangle;
use std::collections::{BTreeMap, HashMap};
use std::fs::{self, File};
use std::io::{BufRead, BufReader, Write};
use std::path::{Path, PathBuf};
use uuid::Uuid;

/// Maps PC to program symbol
pub struct SymbolizerContext {
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

    /// mock symbolizer for testing
    #[cfg(test)]
    fn new_mock(symbols: Vec<(u64, String, u64)>) -> Self {
        let mut symbol_map = BTreeMap::new();
        for (addr, name, size) in symbols {
            symbol_map.insert(addr, (name, size));
        }
        SymbolizerContext {
            symbol_map,
            text_base_addr: 0,
        }
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

struct ProgramCtx {
    id: String,
    symbolizable: bool,
    cu_used: u64,
    /// The index in the `full_call_stack` where this program's frames begin.
    stack_base_index: usize,
}

/// Process trace data and generate folded stacks output
pub fn process_trace_to_folded_stacks<R: BufRead, W: Write>(
    reader: R,
    writer: &mut W,
    symbolizer_contexts: &HashMap<String, SymbolizerContext>,
) -> Result<(), Box<dyn std::error::Error>> {
    // solana_program_runtime::execution_budget::SVMTransactionExecutionCost::invoke_units
    const CPI_INVOKE_COST: u64 = 1000;

    let mut full_call_stack: Vec<String> = Vec::new();
    let mut vm_context_stack: Vec<ProgramCtx> = Vec::new();
    let mut time_series_stacks: Vec<(String, u64)> = Vec::new();
    let mut pc_line_counter: u64 = 0;

    vm_context_stack.push(ProgramCtx {
        id: "ROOT_PLACEHOLDER".to_string(),
        symbolizable: true,
        cu_used: 0,
        stack_base_index: 0, // Root program starts at the base of the stack.
    });

    for line in reader.lines() {
        let line = line?.trim().to_string();
        if line.is_empty() {
            continue;
        }

        if line.starts_with("PROGRAM_START") {
            let mut id = String::new();
            let mut symbolizable = false;

            for tok in line.split_whitespace().skip(1) {
                if let Some((k, v)) = tok.split_once('=') {
                    match k {
                        "program_id" => id = v.to_string(),
                        "symbolizable" => symbolizable = v == "true",
                        _ => {}
                    }
                }
            }

            let caller_ctx = vm_context_stack
                .last_mut()
                .expect("VM context stack should not be empty");
            if caller_ctx.symbolizable {
                caller_ctx.cu_used += pc_line_counter;
            }
            pc_line_counter = 0;

            let mut cpi_invoke_stack = full_call_stack.join(";");
            if !cpi_invoke_stack.is_empty() {
                cpi_invoke_stack.push(';');
            }
            cpi_invoke_stack.push_str("CPI_Invoke");
            time_series_stacks.push((cpi_invoke_stack, CPI_INVOKE_COST));

            let new_stack_base = full_call_stack.len();
            if !symbolizable {
                let short_id = id.get(..8).unwrap_or(&id);
                full_call_stack.push(format!("CPI_{}", short_id));
            }

            vm_context_stack.push(ProgramCtx {
                id,
                symbolizable,
                cu_used: 0,
                stack_base_index: new_stack_base,
            });
        } else if line.starts_with("PROGRAM_END") {
            let mut id = String::new();
            let mut cu_consumed: u64 = 0;

            for tok in line.split_whitespace().skip(1) {
                if let Some((k, v)) = tok.split_once('=') {
                    match k {
                        "program_id" => id = v.to_string(),
                        "cu_consumed" => cu_consumed = v.parse().unwrap_or(0),
                        _ => {}
                    }
                }
            }

            let child_ctx = vm_context_stack
                .pop()
                .expect("PROGRAM_END without a matching PROGRAM_START");

            if child_ctx.id != id {
                eprintln!(
                    "[SBPF Profiler] Warning: PROGRAM_END id mismatch. Expected {}, got {}",
                    child_ctx.id, id
                );
            }

            // Capture the final stack state before unwinding it.
            let final_child_stack_str = full_call_stack.join(";");

            // Unwind the call stack to where it was before this program was called.
            full_call_stack.truncate(child_ctx.stack_base_index);

            let traced_cu_in_child = if child_ctx.symbolizable {
                child_ctx.cu_used + pc_line_counter
            } else {
                child_ctx.cu_used
            };

            let cost_inside_child = cu_consumed.saturating_sub(CPI_INVOKE_COST);
            let internal_unattributed = cost_inside_child.saturating_sub(traced_cu_in_child);

            if internal_unattributed > 0 {
                let mut unattributed_stack = final_child_stack_str;
                if child_ctx.symbolizable {
                    if !unattributed_stack.is_empty() {
                        unattributed_stack.push(';');
                    }
                    unattributed_stack.push_str("Unattributed_(likely_used_inside_bpf_loader)");
                }
                time_series_stacks.push((unattributed_stack, internal_unattributed));
            }

            let parent_ctx = vm_context_stack
                .last_mut()
                .expect("Stack should have a parent");
            parent_ctx.cu_used += cu_consumed;
            pc_line_counter = 0;
        } else if line.starts_with("SYSCALL") {
            let mut name = String::new();
            let mut cu_consumed: u64 = 0;
            let mut cu_since: u64 = 0;

            for tok in line.split_whitespace().skip(1) {
                if let Some((k, v)) = tok.split_once('=') {
                    match k {
                        "name" => name = v.to_string(),
                        "cu_consumed" => cu_consumed = v.parse().unwrap_or(0),
                        "cu_since_last_checkpoint" => cu_since = v.parse().unwrap_or(0),
                        _ => {}
                    }
                }
            }

            if let Some(ctx) = vm_context_stack.last_mut() {
                let current_stack_str = full_call_stack.join(";");

                if ctx.symbolizable {
                    ctx.cu_used += pc_line_counter;
                } else if cu_since > 0 {
                    time_series_stacks.push((current_stack_str.clone(), cu_since));
                    ctx.cu_used += cu_since;
                }

                let mut syscall_stack_str = current_stack_str;
                if !syscall_stack_str.is_empty() {
                    syscall_stack_str.push(';');
                }
                syscall_stack_str.push_str(&format!("SYSCALL:{}", name));
                time_series_stacks.push((syscall_stack_str, cu_consumed));

                ctx.cu_used += cu_consumed;
                pc_line_counter = 0;
            }
        } else {
            // PC Line
            if let Some(ctx) = vm_context_stack.last_mut() {
                if !ctx.symbolizable {
                    continue;
                }

                let frames: Vec<String> = line
                    .split(';')
                    .filter_map(|pc_str| pc_str.parse::<u64>().ok())
                    .map(|pc_index| {
                        let mut symbol = symbolizer_contexts
                            .get(&ctx.id)
                            .map(|sctx| sctx.symbolize_pc(pc_index))
                            .unwrap_or_else(|| format!("{}:0x{:x}", ctx.id, pc_index * 8));
                        if ctx.id != "ROOT_PLACEHOLDER" {
                            let short_id = ctx.id.get(..8).unwrap_or(&ctx.id);
                            symbol = format!("CPI_{}:{}", short_id, symbol);
                        }
                        symbol
                    })
                    .collect();

                if !frames.is_empty() {
                    let mut reversed_frames = frames;
                    reversed_frames.reverse();

                    full_call_stack.truncate(ctx.stack_base_index);
                    full_call_stack.extend(reversed_frames);

                    time_series_stacks.push((full_call_stack.join(";"), 1));
                    pc_line_counter += 1;
                }
            }
        }
    }

    time_series_stacks.reverse(); // inferno flamechart requires reversal
    for (stack, weight) in time_series_stacks {
        if weight > 0 {
            writeln!(writer, "{} {}", stack, weight)?;
        }
    }

    Ok(())
}

/// Process trace file to flame chart in svg format
pub fn process_trace_file(
    trace_path: &Path,
    root_program_path: &Path,
) -> Result<PathBuf, Box<dyn std::error::Error>> {
    let program_dir = root_program_path
        .parent()
        .ok_or("Failed to get parent directory of the program")?;

    let mut symbolizer_contexts: HashMap<String, SymbolizerContext> = HashMap::new();
    symbolizer_contexts.insert(
        "ROOT_PLACEHOLDER".to_string(),
        SymbolizerContext::new(root_program_path)?,
    );

    let trace_file = File::open(trace_path)?;
    let reader = BufReader::new(&trace_file);

    for line in reader.lines() {
        let line = line?;
        if line.starts_with("PROGRAM_START") {
            let mut id = String::new();
            let mut symbolizable = false;

            for tok in line.split_whitespace().skip(1) {
                if let Some((k, v)) = tok.split_once('=') {
                    match k {
                        "program_id" => id = v.to_string(),
                        "symbolizable" => symbolizable = v == "true",
                        _ => {}
                    }
                }
            }

            if symbolizable && !symbolizer_contexts.contains_key(&id) {
                let program_path = program_dir.join(format!("{}.so", id));
                if program_path.exists() {
                    match SymbolizerContext::new(&program_path) {
                        Ok(ctx) => {
                            symbolizer_contexts.insert(id.clone(), ctx);
                            println!("[SBPF Profiler] {}.so symbols loaded", id);
                        }
                        Err(e) => eprintln!(
                            "[SBPF Profiler] Warning: Failed to load symbols for {}: {}",
                            id, e
                        ),
                    }
                }
            }
        }
    }

    let trace_file = File::open(trace_path)?;
    let reader = BufReader::new(trace_file);

    let program_name = root_program_path
        .file_stem()
        .and_then(|s| s.to_str())
        .unwrap_or("unknown");
    let output_filename = format!("flamechart_{}_{}.txt", program_name, Uuid::new_v4());
    let output_path = program_dir.join(output_filename);
    let mut output_file = File::create(&output_path)?;

    process_trace_to_folded_stacks(reader, &mut output_file, &symbolizer_contexts)?;
    output_file.sync_all()?;

    // Generate SVG
    let mut options = flamegraph::Options::default();
    options.title = "SBPF profile".to_string();
    options.count_name = "CU".to_string();
    options.font_type = "monospace".to_string();
    options.font_size = 12;
    options.frame_height = 16;
    options.flame_chart = true;

    let input_file = File::open(&output_path)?;
    let svg_path = output_path.with_extension("svg");
    let mut svg_file = File::create(&svg_path)?;

    flamegraph::from_reader(&mut options, BufReader::new(input_file), &mut svg_file)?;

    let _ = fs::remove_file(&output_path);
    Ok(svg_path)
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::io::Cursor;

    #[test]
    fn test_syscall_processing() {
        // Tests that syscalls are properly accounted for in CU consumption
        let mut symbolizers = HashMap::new();
        let root_symbols = SymbolizerContext::new_mock(vec![
            (0, "entrypoint".to_string(), 200),
            (200, "process_instruction".to_string(), 100),
        ]);
        symbolizers.insert("ROOT_PLACEHOLDER".to_string(), root_symbols);

        let trace_input = r#"
10
SYSCALL name=sol_log_ cu_consumed=100 cu_since_last_checkpoint=1 cu_checkpoint=1399899
10
25;10
SYSCALL name=sol_get_rent_sysvar cu_consumed=124 cu_since_last_checkpoint=2 cu_checkpoint=1399773
25;10
"#
        .trim();

        let reader = Cursor::new(trace_input);
        let mut output = Vec::new();

        process_trace_to_folded_stacks(reader, &mut output, &symbolizers)
            .expect("Processing should succeed");

        let output_str = String::from_utf8(output).expect("Valid UTF-8");

        assert!(output_str.contains("entrypoint;SYSCALL:sol_log_ 100"));
        assert!(
            output_str.contains("entrypoint;process_instruction;SYSCALL:sol_get_rent_sysvar 124")
        );
    }

    #[test]
    fn test_nested_cpi_calls() {
        // Tests CPI call from root to Token program, which then calls System program
        let mut symbolizers = HashMap::new();

        let root_symbols = SymbolizerContext::new_mock(vec![
            (0, "entrypoint".to_string(), 100),
            (100, "create_account_handler".to_string(), 200),
        ]);
        symbolizers.insert("ROOT_PLACEHOLDER".to_string(), root_symbols);

        let token_symbols = SymbolizerContext::new_mock(vec![
            (0, "token_entrypoint".to_string(), 100),
            (100, "initialize_mint".to_string(), 100),
        ]);
        symbolizers.insert("TokenProgram".to_string(), token_symbols);

        let trace_input = r#"
13;0
PROGRAM_START program_id=TokenProgram symbolizable=true
0
13;0
PROGRAM_START program_id=11111111111111111111111111111111 symbolizable=false
PROGRAM_END program_id=11111111111111111111111111111111 cu_consumed=1150
13;0
PROGRAM_END program_id=TokenProgram cu_consumed=2154
13;0
"#
        .trim();

        let reader = Cursor::new(trace_input);
        let mut output = Vec::new();

        process_trace_to_folded_stacks(reader, &mut output, &symbolizers)
            .expect("Processing should succeed");

        let output_str = String::from_utf8(output).expect("Valid UTF-8");

        assert!(output_str.contains("entrypoint;create_account_handler;CPI_Invoke 1000"));
        assert!(
            output_str.contains("entrypoint;create_account_handler;CPI_TokenPro:token_entrypoint")
        );
        assert!(output_str.contains("entrypoint;create_account_handler;CPI_TokenPro:token_entrypoint;CPI_TokenPro:initialize_mint;CPI_Invoke 1000"));
        assert!(output_str.contains("entrypoint;create_account_handler;CPI_TokenPro:token_entrypoint;CPI_TokenPro:initialize_mint;CPI_11111111 150"));
    }

    #[test]
    fn test_chronological_ordering_of_complex_trace() {
        let mut symbolizers = HashMap::new();
        symbolizers.insert(
            "ROOT_PLACEHOLDER".to_string(),
            SymbolizerContext::new_mock(vec![(0, "root_entry".to_string(), 100)]),
        );
        symbolizers.insert(
            "ProgramA".to_string(),
            SymbolizerContext::new_mock(vec![
                (0, "prog_a_entry".to_string(), 400),
                (400, "prog_a_handler".to_string(), 100),
            ]),
        );

        let trace_input = r#"
0
PROGRAM_START program_id=ProgramA symbolizable=true
0
SYSCALL name=sol_log cu_consumed=100
50;0
PROGRAM_START program_id=ProgramB symbolizable=false
PROGRAM_END program_id=ProgramB cu_consumed=1150
0
PROGRAM_END program_id=ProgramA cu_consumed=2355
0
"#
        .trim();

        let reader = Cursor::new(trace_input);
        let mut output = Vec::new();
        process_trace_to_folded_stacks(reader, &mut output, &symbolizers).unwrap();
        let output_str = String::from_utf8(output).unwrap();

        let mut chronological_output: Vec<String> = output_str
            .lines()
            .filter(|&l| !l.is_empty())
            .map(String::from)
            .collect();
        chronological_output.reverse();

        let expected_events = vec![
            "root_entry 1",
            "root_entry;CPI_Invoke 1000",
            "root_entry;CPI_ProgramA:prog_a_entry 1",
            "root_entry;CPI_ProgramA:prog_a_entry;SYSCALL:sol_log 100",
            "root_entry;CPI_ProgramA:prog_a_entry;CPI_ProgramA:prog_a_handler 1",
            "root_entry;CPI_ProgramA:prog_a_entry;CPI_ProgramA:prog_a_handler;CPI_Invoke 1000",
            "root_entry;CPI_ProgramA:prog_a_entry;CPI_ProgramA:prog_a_handler;CPI_ProgramB 150",
            "root_entry;CPI_ProgramA:prog_a_entry 1",
            "root_entry;CPI_ProgramA:prog_a_entry;Unattributed_(likely_used_inside_bpf_loader) 102",
            "root_entry 1",
        ];

        assert_eq!(
            chronological_output.len(),
            expected_events.len(),
            "Mismatch in number of output events"
        );

        for (i, (actual, expected)) in chronological_output
            .iter()
            .zip(expected_events.iter())
            .enumerate()
        {
            assert_eq!(
                actual, *expected,
                "Mismatch at chronological event index {}",
                i
            );
        }
    }
}
