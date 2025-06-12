//! Deals with fetching data BPF ring buffers ("maps").
use crate::bpf_map::bitmap_allocation::{BitmapAllocationHandlerV0, BitmapAllocationHandlerV1};
use crate::bpf_map::disruptive_app::{BindServiceLockedHandler, ComponentEnabledSettingHandler};
use crate::bpf_map::generic_instrumentation::{CallResultHandler, CallTimestampHandler};
use crate::bpf_map::process_management::{
    SetUidTempAllowlistStateRecordHandler, UpdateDeviceIdleTempAllowlistRecordHandler,
};
use crate::config_resolver::ResolvedTask;
use crate::Timer;
use anyhow::{bail, Result};
use log::debug;
use std::{collections::HashMap, ffi::CStr, fmt::Debug, sync::LazyLock, time::Duration};
use uprobestats_bpf::poll_ring_buf;
use zerocopy::{Immutable, IntoBytes};

mod bitmap_allocation;
mod disruptive_app;
mod generic_instrumentation;
mod process_management;

/// Polls the given map_path based on the existing registry of handlers.
pub fn poll_registry(map_path: &str, task: &ResolvedTask, duration: Duration) -> Result<()> {
    let Some(poll_loop_fn) = HANDLER_REGISTRY.get(map_path) else {
        bail!("unsupported map_path: {}", map_path);
    };
    poll_loop_fn(map_path, task, duration)
}

const JAVA_ARGUMENT_REGISTER_OFFSET: i32 = 2;

fn poll_loop_generic<H: Handler + Default>(
    map_path: &str,
    task: &ResolvedTask,
    duration: Duration,
) -> Result<()> {
    if map_path != H::MAP_PATH {
        bail!("map_path mismatch: {} != {}", map_path, H::MAP_PATH)
    }
    let mut handler = H::default();
    let timer = Timer::new(duration);
    while let Some(remaining_millis) = timer.remaining_millis() {
        let remaining_millis: i32 = remaining_millis.try_into()?;
        debug!("polling {} for {} seconds", map_path, remaining_millis / 1000);
        // SAFETY: we've just checked that the passed `map_path` is the same as the one
        // expected by the `Handler` implementation, which encodes how the expected type is mapped to the
        // ring buffer's path.
        let result: Result<Vec<H::T>> = unsafe { poll_ring_buf(map_path, remaining_millis) };
        let result = result?;
        debug!("Done polling {}, event count: {}", map_path, result.len());
        for i in &result {
            handler.on_item(task, i)?;
        }
    }
    handler.on_finished()?;
    Ok(())
}

type HandlerRegistry = HashMap<&'static str, fn(&str, &ResolvedTask, Duration) -> Result<()>>;

/// Interface for reading items out of a BPF ring buffer.
/// # Safety
/// There *must* exist a BPF ring buffer at the path represented by `MAP_PATH`
/// which holds items of type `Handler::T`.
unsafe trait Handler {
    const MAP_PATH: &'static str;
    type T: Debug + Copy;
    fn on_item(&mut self, task: &ResolvedTask, data: &Self::T) -> Result<()>;
    fn on_finished(&mut self) -> Result<()> {
        Ok(())
    }
}

fn register_handler<H: Handler + Default>(handler_registry: &mut HandlerRegistry) {
    handler_registry.insert(H::MAP_PATH, poll_loop_generic::<H>);
}

static HANDLER_REGISTRY: LazyLock<HandlerRegistry> = LazyLock::new(|| {
    let mut map = HashMap::new();
    register_handler::<BindServiceLockedHandler>(&mut map);
    if uprobestats_mainline_flags_rust::enable_bitmap_snapshot() {
        register_handler::<BitmapAllocationHandlerV1>(&mut map);
    } else {
        register_handler::<BitmapAllocationHandlerV0>(&mut map);
    }
    register_handler::<CallTimestampHandler>(&mut map);
    register_handler::<CallResultHandler>(&mut map);
    register_handler::<ComponentEnabledSettingHandler>(&mut map);
    register_handler::<SetUidTempAllowlistStateRecordHandler>(&mut map);
    register_handler::<UpdateDeviceIdleTempAllowlistRecordHandler>(&mut map);
    map
});

pub(crate) fn bytes_as_str(bytes: &(impl IntoBytes + Immutable)) -> Result<&str> {
    let string = CStr::from_bytes_until_nul(bytes.as_bytes())?;
    Ok(string.to_str()?)
}

#[cfg(test)]
mod test {
    use log::debug;
    use zerocopy::{Immutable, IntoBytes};
    // local test only util
    #[allow(dead_code)]
    fn print_xxd_like(prefix: &str, data: &(impl IntoBytes + Immutable)) {
        let data = data.as_bytes();
        let mut offset = 0;
        debug!("{} hex:", prefix);
        for chunk in data.chunks(16) {
            // Format the offset
            let offset_str = format!("{:08x}:", offset);
            // Format the hexadecimal representation
            let hex_str = chunk
                .iter()
                .enumerate()
                .map(|(i, &byte)| {
                    let hex = format!("{:02x}", byte);
                    if (i + 1) % 2 == 0 && i != chunk.len() - 1 {
                        format!("{} ", hex)
                    } else {
                        hex
                    }
                })
                .collect::<Vec<String>>()
                .join(" ");
            let padded_hex_str = format!("{:<48}", hex_str); // Pad to align ASCII
                                                             // Format the ASCII representation
            let ascii_str = chunk
                .iter()
                .map(
                    |&byte| {
                        if byte.is_ascii_graphic() || byte == b' ' {
                            byte as char
                        } else {
                            '.'
                        }
                    },
                )
                .collect::<String>();
            debug!("{} {}  {}", offset_str, padded_hex_str, ascii_str);
            offset += chunk.len();
        }
    }
}
