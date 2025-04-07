use anyhow::{bail, Result};
use log::debug;
use std::{
    collections::HashMap,
    ffi::CStr,
    fmt::Debug,
    sync::LazyLock,
    time::{Duration, Instant},
};
use uprobestats_bpf::poll_ring_buf;
use uprobestats_bpf_bindgen::{
    BindServiceLocked, CallResult, CallTimestamp, ComponentEnabledSetting,
    SetUidTempAllowlistStateRecord, UpdateDeviceIdleTempAllowlistRecord,
};
use uprobestats_proto::config::uprobestats_config::Task;
use zerocopy::{Immutable, IntoBytes};

mod disruptive_app;
mod generic_instrumentation;
mod process_management;

pub(crate) fn poll_and_loop(
    map_path: &str,
    now: Instant,
    duration: Duration,
    task: Task,
) -> Result<()> {
    let duration_millis = duration.as_millis();
    let mut elapsed_millis = now.elapsed().as_millis();
    while elapsed_millis <= duration_millis {
        let timeout_millis = duration_millis - elapsed_millis;
        let timeout_millis: i32 = timeout_millis.try_into()?;
        debug!("polling {} for {} seconds", map_path, timeout_millis / 1000);
        let Some(do_poll) = REGISTRY.get(map_path) else {
            bail!("unsupported map_path: {}", map_path);
        };
        do_poll(map_path, timeout_millis, &task)?;
        elapsed_millis = now.elapsed().as_millis();
    }
    Ok(())
}

fn poll<T: OnItem + Debug + Copy>(map_path: &str, timeout_millis: i32, task: &Task) -> Result<()> {
    if map_path != T::MAP_PATH {
        bail!("map_path mismatch: {} != {}", map_path, T::MAP_PATH)
    }
    // SAFETY: we've just checked that the passed `map_path` is the same as the one
    // expected by the `OnItem` implementation, which encodes how the expected type is mapped to the
    // ring buffer's path.
    let result: Result<Vec<T>> = unsafe { poll_ring_buf(map_path, timeout_millis) };
    let result = result?;
    debug!("Done polling {}, event count: {}", map_path, result.len());
    for i in &result {
        i.on_item(task)?;
    }
    Ok(())
}

const JAVA_ARGUMENT_REGISTER_OFFSET: i32 = 2;

/// Interface for reading items out of a BPF ring buffer.
/// # Safety
/// There *must* exist a BPF ring buffer at the path represented by `MAP_PATH`
/// which holds items of type `T` implementing this trait.
unsafe trait OnItem {
    const MAP_PATH: &'static str;
    fn on_item(&self, task: &Task) -> Result<()>;
}

type Registry = HashMap<&'static str, fn(&str, i32, &Task) -> Result<()>>;

fn register<T: OnItem + Debug + Copy>(registry: &mut Registry) {
    registry.insert(T::MAP_PATH, poll::<T> as _);
}

static REGISTRY: LazyLock<Registry> = LazyLock::new(|| {
    let mut map = HashMap::new();
    register::<BindServiceLocked>(&mut map);
    register::<CallTimestamp>(&mut map);
    register::<CallResult>(&mut map);
    register::<ComponentEnabledSetting>(&mut map);
    register::<SetUidTempAllowlistStateRecord>(&mut map);
    register::<UpdateDeviceIdleTempAllowlistRecord>(&mut map);
    map
});

fn bytes_as_str(bytes: &(impl IntoBytes + Immutable)) -> Result<&str> {
    let string = CStr::from_bytes_until_nul(bytes.as_bytes())?;
    Ok(string.to_str()?)
}

#[cfg(test)]
mod test {
    // local test only util
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
