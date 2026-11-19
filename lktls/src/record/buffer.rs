//! Bounded contiguous storage with explicit consumption and amortized compaction.

pub struct RecordBuffer {
    bytes: Vec<u8>,
    start: usize,
    limit: usize,
}

impl RecordBuffer {
    pub fn new(limit: usize) -> Self {
        Self {
            bytes: Vec::new(),
            start: 0,
            limit,
        }
    }
    pub fn len(&self) -> usize {
        self.bytes.len() - self.start
    }
    pub fn is_empty(&self) -> bool {
        self.len() == 0
    }
    pub fn as_slice(&self) -> &[u8] {
        &self.bytes[self.start..]
    }
    pub fn remaining_capacity(&self) -> usize {
        self.limit.saturating_sub(self.len())
    }
    pub fn append(&mut self, bytes: &[u8]) -> usize {
        let accepted = bytes.len().min(self.remaining_capacity());
        if self.bytes.len() + accepted > self.limit || self.start >= self.bytes.len() / 2 {
            self.compact();
        }
        super::reserve_bounded(&mut self.bytes, accepted, self.limit);
        self.bytes.extend_from_slice(&bytes[..accepted]);
        #[cfg(test)]
        super::measurement::copied(super::measurement::CopySite::OutputAppend, accepted);
        accepted
    }
    pub fn consume(&mut self, count: usize) {
        assert!(count <= self.len(), "consumed unavailable record bytes");
        self.start += count;
        if self.is_empty() {
            self.clear();
        }
    }
    pub fn clear(&mut self) {
        self.bytes.clear();
        self.start = 0;
    }
    /// Discard unsent trailing bytes; length is relative to the pending slice.
    pub fn truncate_pending(&mut self, length: usize) {
        assert!(length <= self.len(), "cannot extend pending record bytes");
        self.bytes.truncate(self.start + length);
        if length == 0 {
            self.clear();
        }
    }
    pub fn compact(&mut self) {
        if self.start != 0 {
            #[cfg(test)]
            super::measurement::copied(super::measurement::CopySite::OutputCompact, self.len());
            self.bytes.copy_within(self.start.., 0);
            self.bytes.truncate(self.len());
            self.start = 0;
        }
    }
    /// Prepare the pending bytes for a write primitive with a total-length limit.
    pub fn output_storage(&mut self) -> (&mut Vec<u8>, usize) {
        self.compact();
        (&mut self.bytes, self.limit)
    }

    /// Reserve an amortized application-write tail in the same owned queue.
    /// Unlike `remaining_capacity`, this exposes physical tail capacity: a
    /// retained consumed prefix still counts toward the Vec's length limit.
    /// Writers may stop before logical pending capacity is exhausted. Once the
    /// consumed prefix covers the pending bytes, compaction costs no more than
    /// the transport progress since the previous compaction. Control records
    /// use `output_storage` to reclaim their reserved space immediately.
    pub(crate) fn application_output_storage(&mut self) -> (&mut Vec<u8>, usize) {
        if self.start >= self.len() {
            self.compact();
        }
        (&mut self.bytes, self.limit)
    }

    #[cfg(test)]
    pub(super) fn measurement_snapshot(&self) -> super::measurement::BufferSnapshot {
        super::measurement::BufferSnapshot::new(self.bytes.capacity(), self.bytes.len(), self.start)
    }
}
