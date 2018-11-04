use std::fmt;
use std::fmt::Write;

/// Hardware (Ethernet) address
#[derive(Debug, Copy, Clone, Default)]
pub struct HwAddr {
    pub(crate) len: u8,
    pub(crate) inner: [u8; 8],
}

impl AsRef<[u8]> for HwAddr {
    fn as_ref(&self) -> &[u8] {
        &self.inner[..self.len as usize]
    }
}

impl fmt::Display for HwAddr {
    fn fmt(&self, out: &mut fmt::Formatter) -> fmt::Result {
        let len = self.len as usize;
        if len == 0 {
            return Ok(());
        }
        // Two digits per byte, and 1 less colon than number of bytes
        let size = len * 2 + (len - 1);
        let s = self.inner[..len].iter().fold(
            String::with_capacity(size),
            |mut acc, &b| {
                if !acc.is_empty() {
                    acc.push(':');
                }
                write!(acc, "{:02x}", b);
                acc
            }
        );
        out.write_str(&s)
    }
}



