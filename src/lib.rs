//! A data type suitable for storing sensitive information such as passwords and private keys in memory, featuring constant time equality, mlock and zeroing out.
extern crate libc;
#[cfg(feature = "cbor-serialize")] extern crate cbor;
#[cfg(feature = "cbor-serialize")] extern crate rustc_serialize;
#[cfg(feature = "libsodium-sys")] extern crate libsodium_sys as sodium;
use std::fmt;
use std::borrow::Borrow;
use std::borrow::BorrowMut;
#[cfg(feature = "cbor-serialize")] use rustc_serialize::{Decoder, Encoder, Decodable, Encodable};

#[cfg(feature = "libsodium-sys")]
unsafe fn memzero(pnt: *mut u8, len: libc::size_t) {
    sodium::sodium_memzero(pnt, len);
}

#[inline(never)]
#[cfg(not(feature = "libsodium-sys"))]
unsafe fn memzero(pnt: *mut u8, len: libc::size_t) {
    for i in 0 .. len {
        std::ptr::write_volatile(pnt.offset(i as isize), 0);
    }
}

#[cfg(feature = "libsodium-sys")]
fn memcmp(us: &[u8], them: &[u8]) -> bool {
    if us.len() != them.len() {
        return false;
    }
    unsafe {
        sodium::sodium_memcmp(us.as_ptr(), them.as_ptr(), them.len()) == 0
    }
}

#[inline(never)]
#[cfg(not(feature = "libsodium-sys"))]
fn memcmp(us: &[u8], them: &[u8]) -> bool {
    if us.len() != them.len() {
        return false;
    }
    let mut result = 0;
    for i in 0..us.len() {
        result |= us[i] ^ them[i];
    }
    result == 0
}


/// A data type suitable for storing sensitive information such as passwords and private keys in memory, that implements:  
/// 
/// - Automatic zeroing in `Drop`  
/// - Constant time comparison in `PartialEq` (does not short circuit on the first different character; but terminates instantly if strings have different length)  
/// - Outputting `***SECRET***` to prevent leaking secrets into logs in `fmt::Debug` and `fmt::Display`  
/// - Automatic `mlock` to protect against leaking into swap  
/// 
/// Be careful with `SecStr::from`: if you have a borrowed string, it will be copied.  
/// Use `SecStr::new` if you have a `Vec<u8>`.
#[derive(Clone)]
pub struct SecStr {
    content: Vec<u8>
}

impl SecStr {
    pub fn new(cont: Vec<u8>) -> SecStr {
        memlock::mlock(&cont);
        SecStr { content: cont }
    }

    /// Borrow the contents of the string.
    pub fn unsecure(&self) -> &[u8] {
        self.borrow()
    }

    /// Mutably borrow the contents of the string.
    pub fn unsecure_mut(&mut self) -> &mut [u8] {
        self.borrow_mut()
    }

    /// Overwrite the string with zeros. This is automatically called in the destructor.
    pub fn zero_out(&mut self) {
        unsafe {
            memzero(self.content.as_ptr() as *mut u8, self.content.len());
        }
    }
}

// Creation
impl<T> From<T> for SecStr where T: Into<Vec<u8>> {
    fn from(s: T) -> SecStr {
        SecStr::new(s.into())
    }
}

// Borrowing
impl Borrow<[u8]> for SecStr {
    fn borrow(&self) -> &[u8] {
        self.content.borrow()
    }
}

impl BorrowMut<[u8]> for SecStr {
    fn borrow_mut(&mut self) -> &mut [u8] {
        self.content.borrow_mut()
    }
}

// Overwrite memory with zeros when we're done
impl Drop for SecStr {
    fn drop(&mut self) {
        self.zero_out();
        memlock::munlock(&self.content);
    }
}

// Constant time comparison
impl PartialEq for SecStr {
    fn eq(&self, other: &SecStr) -> bool {
        memcmp(&self.content, &other.content)
    }
}

// Make sure sensitive information is not logged accidentally
impl fmt::Debug for SecStr {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        f.write_str("***SECRET***").map_err(|_| { fmt::Error })
    }
}

impl fmt::Display for SecStr {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        f.write_str("***SECRET***").map_err(|_| { fmt::Error })
    }
}

#[cfg(feature = "cbor-serialize")]
impl Decodable for SecStr {
    fn decode<D: Decoder>(d: &mut D) -> Result<SecStr, D::Error> {
        let cbor::CborBytes(content) = try!(cbor::CborBytes::decode(d));
        Ok(SecStr::new(content))
    }
}

#[cfg(feature = "cbor-serialize")]
impl Encodable for SecStr {
    fn encode<E: Encoder>(&self, e: &mut E) -> Result<(), E::Error> {
        cbor::CborBytes(self.content.clone()).encode(e)
    }
}

#[cfg(unix)]
mod memlock {
    extern crate libc;

    pub fn mlock(cont: &Vec<u8>) {
        unsafe {
            libc::mlock(cont.as_ptr() as *const libc::c_void, cont.len() as libc::size_t);
        }
    }

    pub fn munlock(cont: &Vec<u8>) {
        unsafe {
            libc::munlock(cont.as_ptr() as *const libc::c_void, cont.len() as libc::size_t);
        }
    }
}

#[cfg(not(unix))]
mod memlock {
    fn mlock(cont: &Vec<u8>) {
    }

    fn munlock(cont: &Vec<u8>) {
    }
}

#[cfg(test)]
mod tests {
    use super::SecStr;

    #[test]
    fn test_basic() {
        let my_sec = SecStr::from("hello");
        assert_eq!(my_sec, SecStr::from("hello".to_string()));
        assert_eq!(my_sec.unsecure(), b"hello");
    }

    #[test]
    fn test_zero_out() {
        let mut my_sec = SecStr::from("hello");
        my_sec.zero_out();
        assert_eq!(my_sec.unsecure(), b"\x00\x00\x00\x00\x00");
    }

    #[test]
    fn test_comparison() {
        assert_eq!(SecStr::from("hello"),  SecStr::from("hello"));
        assert!(  SecStr::from("hello") != SecStr::from("yolo"));
        assert!(  SecStr::from("hello") != SecStr::from("olleh"));
        assert!(  SecStr::from("hello") != SecStr::from("helloworld"));
        assert!(  SecStr::from("hello") != SecStr::from(""));
    }

    #[test]
    fn test_show() {
        assert_eq!(format!("{}", SecStr::from("hello")), "***SECRET***".to_string());
    }

}
