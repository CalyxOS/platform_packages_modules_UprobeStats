//! UProbestats executable.
use anyhow::{anyhow, bail, ensure, Result};
use binder::ProcessState;
use log::{debug, error, LevelFilter};
use rustutils::system_properties;
use std::process::exit;
use std::{thread, time::Duration};
use uprobestats_bpf::bpf_perf_event_open;
use uprobestats_rs::{bpf_map, config_resolver, guardrail};

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

fn main_impl() -> Result<()> {
    debug!("started");

    ensure!(uprobestats_mainline_flags_rust::enable_uprobestats(), "enable_uprobestats disabled");
    ensure!(
        uprobestats_mainline_flags_rust::uprobestats_support_update_device_idle_temp_allowlist(),
        "uprobestats_support_update_device_idle_temp_allowlist disabled",
    );
    ensure!(
        uprobestats_mainline_flags_rust::executable_method_file_offsets(),
        "executable_method_file_offsets disabled",
    );

    let config = config_resolver::read_config("/data/misc/uprobestats-configs/config")?;
    ensure!(
        guardrail::is_allowed(&config, is_user_build(), true)?,
        "uprobestats probing config disallowed on this device"
    );

    ProcessState::start_thread_pool();

    let task = config_resolver::resolve_single_task(config)?;

    let probes = config_resolver::resolve_probes(&task)?;
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

    let duration = Duration::from_secs(task.duration_seconds.try_into()?);
    let results: Vec<_> = task
        .bpf_map_paths
        .into_iter()
        .map(|map_path| {
            debug!("Spawning thread for map_path: {}", map_path);
            let task_proto = task.task.clone();
            let map_path_clone = map_path.clone();
            let thr =
                thread::spawn(move || bpf_map::poll_registry(&map_path, task_proto, duration));
            debug!("Spawned thread for map_path: {}", map_path_clone);
            thr
        })
        .collect();

    let results = results.into_iter().map(|result| match result.join() {
        Ok(result) => result.map_err(|e| anyhow!("Thread error: {}", e)),
        Err(panic) => bail!("Thread panic: {:?}", panic),
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

fn is_user_build() -> bool {
    if let Ok(Some(val)) = system_properties::read("ro.build.type") {
        return val == "user";
    }
    true
}
