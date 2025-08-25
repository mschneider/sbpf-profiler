use crate::profiling::PROFILING_STATE;
use crate::{interpreter::Interpreter, vm::ContextObject};
use bs58;
use std::io::Write;

// solana_program_runtime::execution_budget::MAX_COMPUTE_UNIT_LIMIT
const MAX_COMPUTE_UNIT_LIMIT: u64 = 1_400_000;

// Encapsulate syscall execution context
pub struct SyscallProfilingCtx<'a> {
    name: &'a [u8],
    is_cpi: bool,
    program_id: Option<[u8; 32]>,
    cu_before: u64,
    cu_used_since_checkpoint: u64,
}

impl<'a> SyscallProfilingCtx<'a> {
    pub(crate) fn new<C: ContextObject>(
        function_name: &'a [u8],
        interpreter: &mut Interpreter<C>,
    ) -> Self {
        let is_cpi = matches!(
            function_name,
            b"sol_invoke_signed_c" | b"sol_invoke_signed_rust"
        );
        let program_id = if is_cpi {
            Some(interpreter.get_cpi_program_id(function_name))
        } else {
            None
        };

        let cu_remaining = interpreter.vm.context_object_pointer.get_remaining();
        let cu_used_not_subtracted = interpreter.vm.due_insn_count;

        Self {
            name: function_name,
            is_cpi,
            program_id,
            cu_before: cu_remaining.saturating_sub(cu_used_not_subtracted),
            cu_used_since_checkpoint: cu_used_not_subtracted,
        }
    }

    pub(crate) fn emit_start_event(&self) {
        PROFILING_STATE.with(|state_cell| {
            if let Ok(mut state) = state_cell.try_borrow_mut() {
                if self.is_cpi {
                    if let Some(program_id) = self.program_id {
                        let program_id_str = bs58::encode(program_id).into_string();
                        let is_symbolizable = state.is_program_symbolizable(&program_id_str);
                        if let Some(writer) = &mut state.writer {
                            let _ = writeln!(writer, "PROGRAM_START program_id={} symbolizable={} cu_since_last_checkpoint={} cu_checkpoint={}",
                                             program_id_str, is_symbolizable, self.cu_used_since_checkpoint,
                                             MAX_COMPUTE_UNIT_LIMIT.saturating_sub(self.cu_before.saturating_sub(self.cu_used_since_checkpoint)));
                        }
                    }
                }
            }
        });
    }

    pub(crate) fn emit_end_event(&self, cu_after: u64) {
        let cu_consumed = self.cu_before.saturating_sub(cu_after);

        PROFILING_STATE.with(|state_cell| {
            if let Ok(mut state) = state_cell.try_borrow_mut() {
                if self.is_cpi {
                    if let Some(program_id) = self.program_id {
                        let program_id_str = bs58::encode(program_id).into_string();
                        let is_symbolizable = state.is_program_symbolizable(&program_id_str);
                        if let Some(writer) = &mut state.writer {
                            let _ = writeln!(writer, "PROGRAM_END program_id={} symbolizable={} cu_consumed={} cu_since_last_checkpoint={} cu_checkpoint={}",
                                             program_id_str, is_symbolizable, cu_consumed, self.cu_used_since_checkpoint,
                                             MAX_COMPUTE_UNIT_LIMIT.saturating_sub(cu_after));
                        }
                    }
                } else if let Some(writer) = &mut state.writer {
                    let syscall_name = String::from_utf8_lossy(self.name);
                    let _ = writeln!(writer, "SYSCALL name={} cu_consumed={} cu_since_last_checkpoint={} cu_checkpoint={}",
                                     syscall_name, cu_consumed, self.cu_used_since_checkpoint,
                                     MAX_COMPUTE_UNIT_LIMIT.saturating_sub(cu_after));
                }
            }
        });
    }
}
