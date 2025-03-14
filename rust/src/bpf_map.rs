use anyhow::{anyhow, bail, Result};
use log::debug;
use protobuf::MessageField;
use statssocket::AStatsEvent;
use std::{
    collections::HashMap,
    fmt::Debug,
    sync::LazyLock,
    time::{Duration, Instant},
};
use uprobestats_bpf::poll_ring_buf;
use uprobestats_bpf_bindgen::CallTimestamp;
use uprobestats_proto::config::uprobestats_config::Task;

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
    register::<CallTimestamp>(&mut map);
    map
});

/// SAFETY: `CallTimestamp` is a struct defined in the given `MAP_PATH`, and is guaranteed to match the
/// layout of the corresponding C struct.
unsafe impl OnItem for CallTimestamp {
    const MAP_PATH: &str = "/sys/fs/bpf/uprobestats/map_GenericInstrumentation_call_timestamp_buf";
    fn on_item(&self, task: &Task) -> Result<()> {
        debug!("CallTimestamp - event: {}, timestamp_ns: {}", self.event, self.timestampNs,);

        let MessageField(Some(ref statsd_logging_config)) = task.statsd_logging_config else {
            return Ok(());
        };

        debug!("has logging config");
        let atom_id = statsd_logging_config
            .atom_id
            .ok_or(anyhow!("atom_id required if statsd_logging_config provided"))?;

        debug!("attempting to write atom id: {}", atom_id);
        let mut event = AStatsEvent::new(atom_id.try_into()?);
        event.write_int32(self.event.try_into()?);
        event.write_int64(self.timestampNs.try_into()?);
        event.write();
        debug!("successfully wrote atom id: {}", atom_id);

        Ok(())
    }
}
