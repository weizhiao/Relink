use alloc::vec::Vec;

pub(super) struct StringTable {
    data: Vec<u8>,
}

impl StringTable {
    #[inline]
    pub(super) fn new() -> Self {
        Self {
            data: Vec::from([0]),
        }
    }

    pub(super) fn add(&mut self, value: &str) -> usize {
        let offset = self.data.len();
        self.data.extend_from_slice(value.as_bytes());
        self.data.push(0);
        offset
    }

    #[inline]
    pub(super) fn len(&self) -> usize {
        self.data.len()
    }

    #[inline]
    pub(super) fn as_slice(&self) -> &[u8] {
        &self.data
    }
}
