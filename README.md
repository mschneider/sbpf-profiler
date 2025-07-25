# sbpf-profiler

Drop-in fork of Solana's [SBPF VM](https://github.com/anza-xyz/sbpf) that adds execution profiling. Generates flame charts showing function-level compute unit usage across program and CPI boundaries.



## [Example output](https://793ea0d2.sbpf-profiler.pages.dev/)

---

## Guide

1. **Build your program with debug symbols**  
   You will need the unstripped version of the Solana program you want to profile.
   ```bash
   cargo build-sbf
   # produces:
   #   target/deploy/                          -> stripped .so ❌
   #   target/sbf-solana-solana/release/       -> unstripped .so - This is the one we need ✅
   ```

2. **Add the profiler to your project**  
   Wherever you run your Solana programs, configure `Cargo.toml` to use this fork instead of the original `sbpf`.
   ```toml
   [patch.crates-io]
   solana-sbpf = { git = "https://github.com/serbangv/sbpf-profiler" }     # v0.12.2
   ```

3. **Run with profiling enabled**  
   To enabled profiling for your run, you need to pass `SBPF_PROFILE` env variable, pointing to the unstripped .so file from the 1st step.

   For example, when using `mollusk`, the command looks like this:
   ```bash
   SBPF_PROFILE=/absolute/path/to/<unstripped_program>.so cargo test -p my-test -- --nocapture
   ```

   **NOTE:** If you have programs into which you're doing CPIs and you  want those programs' functions to also be present in the profile, you can include their **unstripped** .so files in the same directory as the file pointed to by the `SBPF_PROFILE` env var, use their pubkey as the file name and the profiler will load them.

   For example, if my program has CPI calls into the Token and Associated Token Programs, the directory that holds the **unstripped** .so files will look like:

   ```
   my_program_directory/
   ├── my_program.so # Main program
   ├── TokenkegQfeZyiNwAJbNbGKPFXCWuBvf9Ss623VQ5DA.so # Token Program
   └── ATokenGPvbdGVxr1b2hvZbsiqW5xWH25efTNsLJA8knL.so # Associated Token Program
   ```

4. **Final step**  
   On success you’ll see a log line like:
   ```
   [SBPF Profiler] Success! Flamechart written to: "/absolute/path/to/flamechart_<unique_id>.svg"
   ```
   You can now open the interactive SVG in your browser.

