/*
 * Copyright (C) 2025 The Android Open Source Project
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *      http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */

//! Functions to interact with BPF through C FFI.

use anyhow::{anyhow, ensure, Result};
use uprobestats_bpf_bindgen::{bpfPerfEventOpen, pollRingBuf};

use std::{
    ffi::{c_void, CString},
    fmt::Debug,
    mem::size_of,
};

/// Polls the BPF ring buffer at the passed `map_path`, collecting any values
/// emitted within `timeout_ms` into a `Vec<T>`, where `T` is expected to be
/// the type written to the ring buffer by a corresponding eBPF program.
///
/// # Safety
///   - `T` matches the type that is written to the BPF ring buffer at `map_path`.
pub unsafe fn poll_ring_buf<T: Copy + Debug>(map_path: String, timeout_ms: i32) -> Result<Vec<T>> {
    let map_path = c_string(&map_path)?;
    let mut data: Vec<T> = Vec::new();
    let data_ptr = &mut data as *mut _ as *mut c_void;
    // SAFETY:
    // - `map_path` is a valid pointer by virtue of coming from a `CString`.
    // - caller has guaranteed that `T` is the right type, which we use to derive its size.
    // - `callback` is a valid function pointer defined below.
    // - `data_ptr` is a valid pointer from the `Vec::new` construction above.
    // - due to all of the above, `callback` will be called with a valid pointer to a `T` and a
    //   valid pointer to a `Vec<T>`, which is safe to mutate because we have an exclusive
    //   reference to the `Vec`.
    let result = unsafe {
        pollRingBuf(map_path.as_ptr(), timeout_ms, size_of::<T>(), Some(callback::<T>), data_ptr)
    };
    ensure!(result >= 0, "Failed to poll ring buffer. Error code: {}", result);
    Ok(data)
}

/// Callback function for `pollRingBuf`.
///
/// # Safety
///   - `value` must be a valid, non-null pointer to a value of type `T` written to the BPF ring buffer.
///   - `cookie` must be a valid, non-null pointer to a `Vec<T>`.
unsafe extern "C" fn callback<T: Copy + Debug>(value: *const c_void, cookie: *mut c_void) {
    let value = value as *const T;
    // SAFETY: the caller has guaranteed a valid pointer to a `T`, which is `Copy`, so we can get an owned value.
    let value = unsafe { *value };
    // SAFETY: the caller has guaranteed a is a valid pointer to a `Vec<T>`.
    let cookie: &mut Vec<T> = unsafe { &mut *(cookie as *mut Vec<T>) };
    cookie.push(value);
}

/// Attaches the eBPF program specified at `bpf_program_path`
/// to the user space program for process `pid`, located by `filename` and `offset`.
pub fn bpf_perf_event_open(
    filename: String,
    offset: i32,
    pid: i32,
    bpf_program_path: String,
) -> Result<()> {
    let filename = c_string(&filename)?;
    let bpf_program_path = c_string(&bpf_program_path)?;
    let res =
        // SAFETY: `filename` and `bpf_program_path` are valid by virtue of being derived from a `CString`.
        unsafe { bpfPerfEventOpen(filename.as_ptr(), offset, pid, bpf_program_path.as_ptr()) };
    ensure!(res == 0, "Failed to attach BPF. Error code: {}", res);
    Ok(())
}

fn c_string(string: &str) -> Result<CString> {
    CString::new(string.as_bytes()).map_err(|e| anyhow!("Failed to create CString: {e}"))
}
