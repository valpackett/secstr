//! A security wrapper around strings.
extern crate libc;
use std::fmt;
use libc::funcs::posix88::mman;

/// A security wrapper around strings that implements:  
/// 
/// - Automatic zeroing in `Drop`  
/// - Constant time comparison in `Equiv` and `PartialEq`  
/// - Always outputting `***SECRET***` to prevent logging in `Show`  
/// - Automatic `mlock` to protect against leaking into swap  
pub struct SecStr {
    content: String
}

impl SecStr {
    pub fn zero_out(&mut self) {
        unsafe {
            std::ptr::zero_memory(self.content.as_ptr() as *mut libc::c_void, self.content.len());
        }
    }

    pub fn new(cont: String) -> SecStr {
        unsafe {
            mman::mlock(cont.as_ptr() as *const libc::c_void, cont.len() as libc::size_t);
        }
        SecStr { content: cont }
    }

    pub fn new_from_slice(cont: &str) -> SecStr {
        SecStr::new(cont.to_string())
    }

    pub fn unsecure<'r>(&'r self) -> &'r str {
        self.content.as_slice()
    }
}

// Overwrite memory with zeros when we're done
impl Drop for SecStr {
    fn drop(&mut self) {
        self.zero_out()
    }
}

// Constant time comparison
impl Equiv<String> for SecStr {
    fn equiv(&self, other: &String) -> bool {
        let us = self.content.as_bytes();
        let them = other.as_bytes();
        if us.len() != them.len() {
            return false;
        }
        let mut result = 0;
        for i in range(0, us.len()) {
            result |= us[i] ^ them[i];
        }
        result == 0
    }
}

impl PartialEq for SecStr {
    fn eq(&self, other: &SecStr) -> bool {
        self.equiv(&other.content)
    }
}

// Make sure sensitive information is not logged accidentally
impl fmt::Show for SecStr {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        f.write_str("***SECRET***").map_err(|_| { fmt::WriteError })
    }
}

#[cfg(test)]
mod tests {
    use super::SecStr;

    #[test]
    fn test_basic() {
        let my_sec = SecStr::new_from_slice("hello");
        assert_eq!(my_sec, SecStr::new("hello".to_string()));
        assert_eq!(my_sec.content, "hello".to_string());
        assert_eq!(my_sec.unsecure(), "hello");
    }

    #[test]
    fn test_zero_out() {
        let mut my_sec = SecStr::new_from_slice("hello");
        my_sec.zero_out();
        assert_eq!(my_sec.content, "\x00\x00\x00\x00\x00".to_string());
        assert_eq!(my_sec.unsecure(), "\x00\x00\x00\x00\x00");
    }

    #[test]
    fn test_comparison() {
        assert_eq!(SecStr::new_from_slice("hello"), SecStr::new_from_slice("hello"));
        assert!( SecStr::new_from_slice("hello") != SecStr::new_from_slice("yolo"));
        assert!( SecStr::new_from_slice("hello") != SecStr::new_from_slice("olleh"));
        assert!( SecStr::new_from_slice("hello").equiv(&"hello".to_string()));
        assert!(!SecStr::new_from_slice("hello").equiv(&"olleh".to_string()));
    }

    #[test]
    fn test_show() {
        assert_eq!(format!("{}", SecStr::new_from_slice("hello")), "***SECRET***".to_string());
    }

}
