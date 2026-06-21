//! ELF note header and note payload views.

use crate::{ParseNoteError, Result};
use core::mem::size_of;

const NOTE_ALIGN: usize = 4;
const NOTE_ALIGN_64: usize = 8;

/// ELF note header (`Elf_Nhdr`).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[repr(C)]
pub struct ElfNhdr {
    n_namesz: u32,
    n_descsz: u32,
    n_type: u32,
}

impl ElfNhdr {
    /// Creates an owned ELF note header.
    #[inline]
    pub const fn new(n_namesz: u32, n_descsz: u32, n_type: u32) -> Self {
        Self {
            n_namesz,
            n_descsz,
            n_type,
        }
    }

    /// Returns the note name size (`n_namesz`).
    #[inline]
    pub const fn n_namesz(&self) -> u32 {
        self.n_namesz
    }

    /// Returns the note descriptor size (`n_descsz`).
    #[inline]
    pub const fn n_descsz(&self) -> u32 {
        self.n_descsz
    }

    /// Returns the note type (`n_type`).
    ///
    /// The meaning of this value depends on the note name.
    #[inline]
    pub const fn n_type(&self) -> u32 {
        self.n_type
    }

    /// Sets the note name size (`n_namesz`).
    #[inline]
    pub const fn set_n_namesz(&mut self, n_namesz: u32) {
        self.n_namesz = n_namesz;
    }

    /// Sets the note descriptor size (`n_descsz`).
    #[inline]
    pub const fn set_n_descsz(&mut self, n_descsz: u32) {
        self.n_descsz = n_descsz;
    }

    /// Sets the note type (`n_type`).
    #[inline]
    pub const fn set_n_type(&mut self, n_type: u32) {
        self.n_type = n_type;
    }
}

/// A parsed ELF note view.
#[derive(Debug, Clone, Copy)]
pub struct ElfNote<'a> {
    header: ElfNhdr,
    name: &'a [u8],
    desc: &'a [u8],
}

impl<'a> ElfNote<'a> {
    /// Returns the parsed note header.
    #[inline]
    pub const fn header(&self) -> ElfNhdr {
        self.header
    }

    /// Returns the note name size (`n_namesz`).
    #[inline]
    pub const fn n_namesz(&self) -> u32 {
        self.header.n_namesz()
    }

    /// Returns the note descriptor size (`n_descsz`).
    #[inline]
    pub const fn n_descsz(&self) -> u32 {
        self.header.n_descsz()
    }

    /// Returns the note type (`n_type`).
    #[inline]
    pub const fn n_type(&self) -> u32 {
        self.header.n_type()
    }

    /// Returns the raw note name bytes, including any trailing null bytes.
    #[inline]
    pub const fn name_bytes(&self) -> &'a [u8] {
        self.name
    }

    /// Returns the note name bytes with trailing null bytes removed.
    #[inline]
    pub fn name(&self) -> &'a [u8] {
        let mut name = self.name;
        while let [rest @ .., 0] = name {
            name = rest;
        }
        name
    }

    /// Returns the note descriptor bytes.
    #[inline]
    pub const fn desc(&self) -> &'a [u8] {
        self.desc
    }
}

/// Iterator over ELF notes contained in a section or segment payload.
#[derive(Debug, Clone)]
pub struct ElfNotes<'a> {
    bytes: &'a [u8],
    offset: usize,
    align: usize,
}

impl<'a> ElfNotes<'a> {
    /// Creates an iterator over ELF notes using the standard 4-byte alignment.
    #[inline]
    pub const fn new(bytes: &'a [u8]) -> Self {
        Self {
            bytes,
            offset: 0,
            align: NOTE_ALIGN,
        }
    }

    /// Creates an iterator over ELF notes using a segment or section alignment.
    ///
    /// Values less than 4 are treated as 4. The supported alignments are 4 and 8.
    #[inline]
    pub fn with_align(bytes: &'a [u8], align: usize) -> Result<Self> {
        let align = match align {
            0..=NOTE_ALIGN => NOTE_ALIGN,
            NOTE_ALIGN_64 => NOTE_ALIGN_64,
            _ => return Err(ParseNoteError::InvalidAlign { align }.into()),
        };
        Ok(Self {
            bytes,
            offset: 0,
            align,
        })
    }

    #[inline]
    fn finish_with(&mut self, err: ParseNoteError) -> Option<Result<ElfNote<'a>>> {
        self.offset = self.bytes.len();
        Some(Err(err.into()))
    }
}

impl<'a> Iterator for ElfNotes<'a> {
    type Item = Result<ElfNote<'a>>;

    fn next(&mut self) -> Option<Self::Item> {
        let offset = self.offset;
        if offset == self.bytes.len() {
            return None;
        }

        let Some(header_end) = offset.checked_add(size_of::<ElfNhdr>()) else {
            return self.finish_with(ParseNoteError::Overflow { offset });
        };
        if header_end > self.bytes.len() {
            return self.finish_with(ParseNoteError::Header {
                offset,
                remaining: self.bytes.len().saturating_sub(offset),
            });
        }

        let mut raw = [0; size_of::<ElfNhdr>()];
        raw.copy_from_slice(&self.bytes[offset..header_end]);
        let header = ElfNhdr {
            n_namesz: u32::from_ne_bytes([raw[0], raw[1], raw[2], raw[3]]),
            n_descsz: u32::from_ne_bytes([raw[4], raw[5], raw[6], raw[7]]),
            n_type: u32::from_ne_bytes([raw[8], raw[9], raw[10], raw[11]]),
        };

        let name_start = header_end;
        let name_size = header.n_namesz() as usize;
        let Some(name_end) = name_start.checked_add(name_size) else {
            return self.finish_with(ParseNoteError::Overflow { offset });
        };
        if name_end > self.bytes.len() {
            return self.finish_with(ParseNoteError::Name {
                offset,
                size: name_size,
                remaining: self.bytes.len().saturating_sub(name_start),
            });
        }
        let name = &self.bytes[name_start..name_end];

        let Some(desc_start) = align_note(name_end, self.align) else {
            return self.finish_with(ParseNoteError::Overflow { offset });
        };
        let desc_size = header.n_descsz() as usize;
        let Some(desc_end) = desc_start.checked_add(desc_size) else {
            return self.finish_with(ParseNoteError::Overflow { offset });
        };
        if desc_end > self.bytes.len() {
            return self.finish_with(ParseNoteError::Desc {
                offset,
                size: desc_size,
                remaining: self.bytes.len().saturating_sub(desc_start),
            });
        }
        let desc = &self.bytes[desc_start..desc_end];

        let Some(next) = align_note(desc_end, self.align) else {
            return self.finish_with(ParseNoteError::Overflow { offset });
        };
        self.offset = next.min(self.bytes.len());

        Some(Ok(ElfNote { header, name, desc }))
    }
}

#[inline]
fn align_note(value: usize, align: usize) -> Option<usize> {
    debug_assert!(matches!(align, NOTE_ALIGN | NOTE_ALIGN_64));
    value
        .checked_add(align - 1)
        .map(|value| value & !(align - 1))
}

#[cfg(test)]
mod tests {
    use super::{ElfNhdr, ElfNotes};
    use alloc::vec::Vec;

    fn append_note(bytes: &mut Vec<u8>, align: usize, name: &[u8], desc: &[u8], n_type: u32) {
        bytes.extend_from_slice(&(name.len() as u32).to_ne_bytes());
        bytes.extend_from_slice(&(desc.len() as u32).to_ne_bytes());
        bytes.extend_from_slice(&n_type.to_ne_bytes());
        bytes.extend_from_slice(name);
        while bytes.len() % align != 0 {
            bytes.push(0);
        }
        bytes.extend_from_slice(desc);
        while bytes.len() % align != 0 {
            bytes.push(0);
        }
    }

    #[test]
    fn parses_single_note() {
        let mut bytes = Vec::new();
        append_note(&mut bytes, 4, b"GNU\0", &[1, 2, 3, 4], 3);

        let mut notes = ElfNotes::new(&bytes);
        let note = notes.next().unwrap().unwrap();
        assert_eq!(note.header(), ElfNhdr::new(4, 4, 3));
        assert_eq!(note.n_namesz(), 4);
        assert_eq!(note.n_descsz(), 4);
        assert_eq!(note.n_type(), 3);
        assert_eq!(note.name_bytes(), b"GNU\0");
        assert_eq!(note.name(), b"GNU");
        assert_eq!(note.desc(), &[1, 2, 3, 4]);
        assert!(notes.next().is_none());
    }

    #[test]
    fn parses_multiple_notes_with_padding() {
        let mut bytes = Vec::new();
        append_note(&mut bytes, 4, b"A\0", &[1, 2, 3], 1);
        append_note(&mut bytes, 4, b"BC\0", &[4], 2);

        let mut notes = ElfNotes::new(&bytes);
        let first = notes.next().unwrap().unwrap();
        assert_eq!(first.name(), b"A");
        assert_eq!(first.desc(), &[1, 2, 3]);

        let second = notes.next().unwrap().unwrap();
        assert_eq!(second.name(), b"BC");
        assert_eq!(second.desc(), &[4]);
        assert!(notes.next().is_none());
    }

    #[test]
    fn supports_eight_byte_alignment() {
        let mut bytes = Vec::new();
        append_note(&mut bytes, 8, b"GNU\0", &[1], 5);
        append_note(&mut bytes, 8, b"GNU\0", &[2], 5);

        let mut notes = ElfNotes::with_align(&bytes, 8).unwrap();
        assert_eq!(notes.next().unwrap().unwrap().desc(), &[1]);
        assert_eq!(notes.next().unwrap().unwrap().desc(), &[2]);
        assert!(notes.next().is_none());
    }

    #[test]
    fn reports_truncated_header() {
        let mut notes = ElfNotes::new(&[0; 4]);
        assert!(notes.next().unwrap().is_err());
        assert!(notes.next().is_none());
    }

    #[test]
    fn rejects_invalid_alignment() {
        assert!(ElfNotes::with_align(&[], 16).is_err());
    }
}
