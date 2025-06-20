// use super::test::print_xxd_like;
use super::Handler;
use crate::config_resolver::ResolvedTask;
use anyhow::Result;
use log::debug;
use statssocket::AStatsEvent;
use uprobestats_bpf_bindgen::BinderTransaction;

#[derive(Default)]
pub struct BinderTransactionHandler {}

// SAFETY: `BpfDebug` is a struct defined in the given `MAP_PATH`, and is guaranteed to match the
// layout of the corresponding C struct.
unsafe impl Handler for BinderTransactionHandler {
    const MAP_PATH: &'static str =
        "/sys/fs/bpf/uprobestats/map_BinderExecTransactInternal_output_buf";
    type T = BinderTransaction;
    fn on_item(&mut self, _task: &ResolvedTask, item: &BinderTransaction) -> Result<()> {
        let calling_uid = item.calling_uid;
        debug!("ActivityTaskManager.startActivity called by calling_uid {calling_uid}");
        debug!("attempting to write test_uprobestats_atom_reported atom 915");
        let mut event = AStatsEvent::new(915); // test_uprobestats_atom_reported
        event.write_int32(calling_uid);
        event.write();
        debug!("successfully test_uprobestats_atom_reported");
        Ok(())
    }
}
