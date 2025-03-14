//! UProbestats executable.
use anyhow::{anyhow, bail, ensure, Result};
use binder::ProcessState;
use log::{debug, error, LevelFilter};
use rustutils::system_properties;
use std::process::exit;
use std::{
    thread,
    time::{Duration, Instant},
};
use uprobestats_bpf::{bpf_perf_event_open, poll_ring_buf};
use uprobestats_bpf_bindgen::CallTimestamp;
use uprobestats_rs::config_resolver;

fn main() {
    logger::init(
        logger::Config::default()
            .with_tag_on_device("uprobestats")
            .with_max_level(if is_user_build() { LevelFilter::Info } else { LevelFilter::Trace }),
    );

    if let Err(e) = main_impl() {
        error!("{}", e);
        exit(1);
    };
}

/// Execute Uprobestats.
pub fn main_impl() -> Result<()> {
    debug!("started");

    ensure!(is_uprobestats_enabled(), "Uprobestats disabled by flag");
    ensure!(!is_user_build(), "Uprobestats disabled on user build");

    let config = config_resolver::read_config("/data/misc/uprobestats-configs/config")?;
    let task = config_resolver::resolve_single_task(config)?;

    ProcessState::start_thread_pool();

    let probes = config_resolver::resolve_probes(task.task)?;
    for probe in probes {
        bpf_perf_event_open(
            probe.filename.clone(),
            probe.offset,
            task.pid,
            probe.bpf_program_path.clone(),
        )?;
        debug!(
            "attached bpf {} to {} at {}",
            probe.bpf_program_path, &probe.filename, &probe.offset
        );
    }

    let duration_seconds: u64 = task.duration_seconds.try_into()?;
    let now = Instant::now();
    let duration = Duration::from_secs(duration_seconds);

    let results = task.bpf_map_paths.into_iter().map(|map_path| {
        debug!("Spawning thread for map_path: {}", map_path);
        match thread::spawn(move || poll_and_loop(map_path.clone(), now, duration)).join() {
            Ok(result) => result.map_err(|e| anyhow!("Thread error: {}", e)),
            Err(panic) => bail!("Thread panic: {:?}", panic),
        }
    });

    let errors: Vec<_> = results
        .filter_map(|r| match r {
            Ok(()) => None,
            Err(e) => Some(e),
        })
        .collect();

    if !errors.is_empty() {
        let msg = errors.into_iter().map(|e| e.to_string()).collect::<Vec<String>>().join(",");
        let msg = format!("At least one thread returned error: {}", msg);
        bail!("{}", msg);
    }

    debug!("done");

    Ok(())
}

fn poll_and_loop(map_path: String, now: Instant, duration: Duration) -> Result<()> {
    ensure!(
        &map_path.ends_with("GenericInstrumentation_call_timestamp_buf"),
        "unsupported map_path: {}",
        map_path
    );

    let duration_millis = duration.as_millis();
    let mut elapsed_millis = now.elapsed().as_millis();
    while elapsed_millis <= duration_millis {
        let timeout_millis = duration_millis - elapsed_millis;
        let timeout_millis: i32 = timeout_millis.try_into()?;
        debug!("polling {} for {} seconds", map_path, timeout_millis / 1000);
        // SAFETY: only GenericInstrumentation_call_timestamp_buf currently supported,
        // which writes `CallTimestamp` structs.
        let result: Result<Vec<CallTimestamp>> =
            unsafe { poll_ring_buf(map_path.clone(), timeout_millis) };
        let result = result?;
        debug!("Done polling, event count: {}", result.len());
        for i in result {
            debug!(
                "Ringbuf result callback. event: {} timestamp_ns: {} map_path: {}",
                i.event, i.timestampNs, map_path
            );
        }
        elapsed_millis = now.elapsed().as_millis();
    }
    Ok(())
}

fn is_user_build() -> bool {
    if let Ok(Some(val)) = system_properties::read("ro.build.type") {
        return val == "user";
    }
    true
}

fn is_uprobestats_enabled() -> bool {
    uprobestats_mainline_flags_rust::enable_uprobestats()
}
