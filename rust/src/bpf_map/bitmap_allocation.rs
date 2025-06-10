use super::Handler;
use crate::config_resolver::ResolvedTask;
use anyhow::Result;
use log::debug;
use statslog_uprobestats::android_graphics_bitmap_allocated;
use uprobestats_bpf_bindgen::BitmapAllocation;

#[derive(Default)]
pub struct BitmapAllocationHandler {}

// SAFETY: `BitmapAllocation` is a struct defined in the given `MAP_PATH`, and is guaranteed to match the
// layout of the corresponding C struct.
unsafe impl Handler for BitmapAllocationHandler {
    const MAP_PATH: &'static str = "/sys/fs/bpf/uprobestats/map_BitmapAllocation_output";
    type T = BitmapAllocation;
    fn on_item(&mut self, task: &ResolvedTask, data: &BitmapAllocation) -> Result<()> {
        debug!("BitmapAllocation: {:?}", data);
        android_graphics_bitmap_allocated::stats_write(
            task.uid,
            data.width.try_into()?,
            data.height.try_into()?,
        )?;
        Ok(())
    }
}
