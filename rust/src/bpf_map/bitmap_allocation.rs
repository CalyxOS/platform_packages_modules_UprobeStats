use super::OnItem;
use anyhow::Result;
use log::debug;
use statslog_uprobestats::android_graphics_bitmap_allocated;
use uprobestats_bpf_bindgen::BitmapAllocation;
use uprobestats_proto::config::uprobestats_config::Task;

// SAFETY: `BitmapAllocation` is a struct defined in the given `MAP_PATH`, and is guaranteed to match the
// layout of the corresponding C struct.
unsafe impl OnItem for BitmapAllocation {
    const MAP_PATH: &'static str = "/sys/fs/bpf/uprobestats/map_BitmapAllocation_output";
    fn on_item(&self, _task: &Task) -> Result<()> {
        debug!("BitmapAllocation: {:?}", self);
        android_graphics_bitmap_allocated::stats_write(
            0, // TODO(b/400457896) actual UID
            self.width.try_into()?,
            self.height.try_into()?,
        )?;
        Ok(())
    }
}
