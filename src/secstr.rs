//! A data type suitable for storing sensitive information such as passwords and private keys in memory, featuring constant time equality, mlock and zeroing out.
#![cfg_attr(feature = "benchmark", feature(test))]
extern crate libc;
#[cfg(feature = "benchmark")]
extern crate test;
use std::fmt;
use std::borrow::Borrow;
use std::borrow::BorrowMut;

/// A data type suitable for storing sensitive information such as passwords and private keys in memory, that implements:
///
/// - Automatic zeroing in `Drop`
/// - Constant time comparison in `PartialEq`
/// - Outputting `***SECRET***` to prevent leaking secrets into logs in `fmt::Debug` and `fmt::Display`
/// - Automatic `mlock` to protect against leaking into swap
///
/// Be careful with `SecStr::from`: if you have a borrowed string, it will be copied.
/// Use `SecStr::new` if you have a `Vec<u8>`.
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

    #[inline(never)]
    /// Overwrite the string with zeros. This is automatically called in the destructor.
    pub fn zero_out(&mut self) {
        unsafe {
            std::ptr::write_bytes(self.content.as_ptr() as *mut libc::c_void, 0, self.content.len());
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
    #[inline(never)]
    fn eq(&self, other: &SecStr) -> bool {
        let ref us = self.content;
        let ref them = other.content;
        let us_len = us.len();
        let them_len = them.len();
        let mut result = (us_len != them_len) as u8;
        for i in 0..them_len {
            if i < us_len {
                result |= us[i] ^ them[i];
            } else {
                //alternative them[i] ^ them[i] (us_len may be 0)
                //witch is SLOWER! then us[i] ^ them[i]
                //benched: 10 ^ them[i] is closest in speed
                result |= 10 ^ them[i];
            }
        }
        result == 0
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

#[cfg(unix)]
mod memlock {
    extern crate libc;
    use self::libc::funcs::posix88::mman;

    pub fn mlock(cont: &Vec<u8>) {
        unsafe {
            mman::mlock(cont.as_ptr() as *const libc::c_void, cont.len() as libc::size_t);
        }
    }

    pub fn munlock(cont: &Vec<u8>) {
        unsafe {
            mman::munlock(cont.as_ptr() as *const libc::c_void, cont.len() as libc::size_t);
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
    #[cfg(feature = "benchmark")]
    use test::{Bencher, black_box};

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
    }

    #[test]
    fn test_show() {
        assert_eq!(format!("{}", SecStr::from("hello")), "***SECRET***".to_string());
    }

    #[test]
    fn test_neq_same_start() {
        let secret = SecStr::from("txt");
        let new_secret = SecStr::from("txttxt");
        assert_eq!( secret == new_secret, false)
    }

    #[cfg(feature = "benchmark")]
    #[bench]
    fn bench_eq_same_len(b: &mut Bencher) {
        let secret = black_box(SecStr::from("hello more longe test needed here"));
        let new_secret = black_box(SecStr::from("hello more longe test needed here"));
        b.iter(|| {
            secret == new_secret
        });
    }

    #[cfg(feature = "benchmark")]
    #[bench]
    fn bench_not_eq_same_len(b: &mut Bencher) {
        let secret = black_box(SecStr::from("hello more longe test needed here"));
        let new_secret = black_box(SecStr::from("herro more longe test needed here"));
        b.iter(|| {
            secret == new_secret
        });
    }

    #[cfg(feature = "benchmark")]
    #[bench]
    fn bench_different_len(b: &mut Bencher) {
        let secret = black_box(SecStr::from("hello"));
        let new_secret = black_box(SecStr::from("hello more longe test needed here"));
        b.iter(|| {
            secret == new_secret
        });
    }

}
