use anyhow::{anyhow, ensure, Result};
use log::debug;
use protobuf::MessageField;
use statssocket::AStatsEvent;
use std::time::{Duration, Instant};
use uprobestats_bpf::poll_ring_buf;
use uprobestats_bpf_bindgen::CallTimestamp;
use uprobestats_proto::config::uprobestats_config::Task;

pub(crate) fn poll_and_loop(
    map_path: &str,
    now: Instant,
    duration: Duration,
    task: Task,
) -> Result<()> {
    ensure!(
        map_path.ends_with("GenericInstrumentation_call_timestamp_buf"),
        "unsupported map_path: {}",
        map_path
    );

    debug!("Polling for CallTimestamp events");

    let duration_millis = duration.as_millis();
    let mut elapsed_millis = now.elapsed().as_millis();
    while elapsed_millis <= duration_millis {
        let timeout_millis = duration_millis - elapsed_millis;
        let timeout_millis: i32 = timeout_millis.try_into()?;
        debug!("polling {} for {} seconds", map_path, timeout_millis / 1000);
        // SAFETY: only GenericInstrumentation_call_timestamp_buf currently supported,
        // which writes `CallTimestamp` structs.
        let result: Result<Vec<CallTimestamp>> = unsafe { poll_ring_buf(map_path, timeout_millis) };
        let result = result?;
        debug!("Done polling, event count: {}", result.len());
        for i in &result {
            debug!(
                "Ringbuf result callback. event: {} timestamp_ns: {} map_path: {}",
                i.event, i.timestampNs, map_path
            );
        }

        if let MessageField(Some(ref statsd_logging_config)) = task.statsd_logging_config {
            debug!("has logging config");
            let atom_id = statsd_logging_config
                .atom_id
                .ok_or(anyhow!("atom_id required if statsd_logging_config provided"))?;
            for i in &result {
                debug!("attempting to write atom id: {}", atom_id);
                let mut event = AStatsEvent::new(atom_id.try_into()?);
                event.write_int32(i.event.try_into()?);
                event.write_int64(i.timestampNs.try_into()?);
                event.write();
                debug!("successfully wrote atom id: {}", atom_id);
            }
        }

        elapsed_millis = now.elapsed().as_millis();
    }
    Ok(())
}
