//! Bindings for AStatsEvent NDK API.
use anyhow::Result;
use statssocket_bindgen::{
    AStatsEvent as AStatsEvent_raw, AStatsEvent_obtain, AStatsEvent_release, AStatsEvent_setAtomId,
    AStatsEvent_write, AStatsEvent_writeBool, AStatsEvent_writeInt32, AStatsEvent_writeInt64,
    AStatsEvent_writeString,
};
use std::ptr::NonNull;

mod c_string;
use c_string::c_string;

/// Safe wrapper around raw `AStatsEvent`.
pub struct AStatsEvent {
    event_raw: NonNull<AStatsEvent_raw>,
}

impl AStatsEvent {
    /// Constructor for an `AStatsEvent` with the given `atom_id`.
    pub fn new(atom_id: u32) -> Self {
        // SAFETY: trivially safe
        let event_raw = unsafe {
            let event = AStatsEvent_obtain();
            AStatsEvent_setAtomId(event, atom_id);
            event
        };
        Self { event_raw: NonNull::new(event_raw).unwrap() }
    }

    /// Writes a `bool` value to the `AStatsEvent`.
    pub fn write_bool(&mut self, value: bool) {
        // SAFETY: `&mut self` is an exclusive reference to a non-null `AStatsEvent_raw`.
        unsafe { AStatsEvent_writeBool(self.as_ptr(), value) };
    }

    /// Writes an `i32` value to the `AStatsEvent`.
    pub fn write_int32(&mut self, value: i32) {
        // SAFETY: `&mut self` is an exclusive reference to a non-null `AStatsEvent_raw`.
        unsafe { AStatsEvent_writeInt32(self.as_ptr(), value) };
    }

    /// Writes an `i64` value to the `AStatsEvent`.
    pub fn write_int64(&mut self, value: i64) {
        // SAFETY: `&mut self` is an exclusive reference to a non-null `AStatsEvent_raw`.
        unsafe { AStatsEvent_writeInt64(self.as_ptr(), value) };
    }

    /// Writes a `str` value to the `AStatsEvent`.
    pub fn write_string(&mut self, value: &str) -> Result<()> {
        let value = c_string(value)?;
        // SAFETY:
        // - `&mut self` is an exclusive reference to a non-null `AStatsEvent_raw`.
        // - we've just created a valid &CStr from `value`.
        unsafe { AStatsEvent_writeString(self.as_ptr(), value.as_ptr()) };
        Ok(())
    }

    /// Write the event to statsd.
    pub fn write(mut self) {
        // SAFETY: `self` is an owned reference to a non-null `AStatsEvent_raw`.
        unsafe { AStatsEvent_write(self.as_ptr()) };
    }

    fn as_ptr(&mut self) -> *mut AStatsEvent_raw {
        self.event_raw.as_ptr()
    }
}

impl Drop for AStatsEvent {
    fn drop(&mut self) {
        // SAFETY: `&mut self` is an exclusive reference to a non-null `AStatsEvent_raw`.
        unsafe { AStatsEvent_release(self.as_ptr()) };
    }
}
