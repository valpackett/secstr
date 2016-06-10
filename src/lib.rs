//! A data type suitable for storing sensitive information such as passwords and private keys in memory, featuring constant time equality, mlock and zeroing out.
#[cfg(feature = "cbor-serialize")] extern crate cbor;
#[cfg(feature = "cbor-serialize")] extern crate rustc_serialize;
use std::fmt;
use std::borrow::{Borrow, BorrowMut};
#[cfg(feature = "cbor-serialize")] use rustc_serialize::{Decoder, Encoder, Decodable, Encodable};


/**
 * Obtain the number of bytes stored in the given byte slice
 */
fn size_of<T: Sized>(slice: &[T]) -> usize {
    slice.len() * std::mem::size_of::<T>()
}



#[cfg(feature = "libsodium-sys")]
mod mem {
    extern crate libsodium_sys as sodium;
    use ::size_of;
    
    pub fn zero<T: Sized + Copy>(slice: &mut [T]) {
        unsafe {
            sodium::sodium_memzero(slice.as_ptr() as *mut u8, size_of(slice));
        }
    }
    
    pub fn cmp<T: Sized + Copy>(us: &[T], them: &[T]) -> bool {
        if us.len() != them.len() {
            return false;
        }
        
        unsafe {
            sodium::sodium_memcmp(us.as_ptr() as *const u8, them.as_ptr() as *const u8, size_of(them)) == 0
        }
    }
}

#[cfg(not(feature = "libsodium-sys"))]
mod mem {
    use std;
    
    use ::size_of;
    
    #[inline(never)]
    pub fn zero<T: Sized + Copy>(slice: &mut [T]) {
        let ptr = slice.as_mut_ptr() as *mut u8;
        for i in 0 .. size_of(slice) {
            unsafe {
                std::ptr::write_volatile(ptr.offset(i as isize), 0);
            }
        }
    }
    
    #[inline(never)]
    pub fn cmp<T: Sized + Copy>(us: &[T], them: &[T]) -> bool {
        if us.len() != them.len() {
            return false;
        }
        
        let mut result: u8 = 0;
        
        let ptr_us   = us.as_ptr()   as *mut u8;
        let ptr_them = them.as_ptr() as *mut u8;
        for i in 0 .. size_of(us) {
            unsafe {
                result |= *(ptr_us.offset(i as isize)) ^ *(ptr_them.offset(i as isize));
            }
        }
        
        result == 0
    }
}



#[cfg(unix)]
mod memlock {
    extern crate libc;
    
    use ::size_of;
    
    pub fn mlock<T: Sized>(cont: &[T]) {
        unsafe {
            libc::mlock(cont.as_ptr() as *const libc::c_void, size_of(cont));
        }
    }
    
    pub fn munlock<T: Sized>(cont: &[T]) {
        unsafe {
            libc::munlock(cont.as_ptr() as *const libc::c_void, size_of(cont));
        }
    }
}

#[cfg(not(unix))]
mod memlock {
    fn mlock<T: Sized>(cont: &[T]) {
    }

    fn munlock<T: Sized>(cont: &[T]) {
    }
}



/// Type alias for a vector that stores just bytes
pub type SecStr = SecVec<u8>;


/// A data type suitable for storing sensitive information such as passwords and private keys in memory, that implements:  
/// 
/// - Automatic zeroing in `Drop`  
/// - Constant time comparison in `PartialEq` (does not short circuit on the first different character; but terminates instantly if strings have different length)  
/// - Outputting `***SECRET***` to prevent leaking secrets into logs in `fmt::Debug` and `fmt::Display`  
/// - Automatic `mlock` to protect against leaking into swap  
/// 
/// Be careful with `SecStr::from`: if you have a borrowed string, it will be copied.  
/// Use `SecStr::new` if you have a `Vec<u8>`.
#[derive(Clone, Eq)]
pub struct SecVec<T> where T: Sized + Copy {
    content: Vec<T>
}

impl<T> SecVec<T> where T: Sized + Copy {
    pub fn new(cont: Vec<T>) -> Self {
        memlock::mlock(&cont);
        SecVec { content: cont }
    }

    /// Borrow the contents of the string.
    pub fn unsecure(&self) -> &[T] {
        self.borrow()
    }

    /// Mutably borrow the contents of the string.
    pub fn unsecure_mut(&mut self) -> &mut [T] {
        self.borrow_mut()
    }

    /// Overwrite the string with zeros. This is automatically called in the destructor.
    pub fn zero_out(&mut self) {
        mem::zero(&mut self.content);
    }
}

// Creation
impl<T, U> From<U> for SecVec<T> where U: Into<Vec<T>>, T: Sized + Copy {
    fn from(s: U) -> SecVec<T> {
        SecVec::new(s.into())
    }
}

// Borrowing
impl<T> Borrow<[T]> for SecVec<T> where T: Sized + Copy {
    fn borrow(&self) -> &[T] {
        self.content.borrow()
    }
}

impl<T> BorrowMut<[T]> for SecVec<T> where T: Sized + Copy {
    fn borrow_mut(&mut self) -> &mut [T] {
        self.content.borrow_mut()
    }
}

// Overwrite memory with zeros when we're done
impl<T> Drop for SecVec<T> where T: Sized + Copy {
    fn drop(&mut self) {
        self.zero_out();
        memlock::munlock(&self.content);
    }
}

// Constant time comparison
impl<T> PartialEq for SecVec<T> where T: Sized + Copy {
    fn eq(&self, other: &SecVec<T>) -> bool {
        mem::cmp(&self.content, &other.content)
    }
}

// Make sure sensitive information is not logged accidentally
impl<T> fmt::Debug for SecVec<T> where T: Sized + Copy {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        f.write_str("***SECRET***").map_err(|_| { fmt::Error })
    }
}

impl<T> fmt::Display for SecVec<T> where T: Sized + Copy {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        f.write_str("***SECRET***").map_err(|_| { fmt::Error })
    }
}

#[cfg(feature = "cbor-serialize")]
impl<T> Decodable for SecVec<T> where T: Sized + Copy {
    fn decode<D: Decoder>(d: &mut D) -> Result<SecStr, D::Error> {
        let cbor::CborBytes(content) = try!(cbor::CborBytes::decode(d));
        Ok(SecVec::<T>::new(content))
    }
}

#[cfg(feature = "cbor-serialize")]
impl<T> Encodable for SecVec<T> where T: Sized + Copy {
    fn encode<E: Encoder>(&self, e: &mut E) -> Result<(), E::Error> {
        cbor::CborBytes(self.content.clone()).encode(e)
    }
}



#[cfg(test)]
mod tests {
    use super::{SecStr, SecVec};
    
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
    
    #[test]
    fn test_comparison_zero_out_mb() {
        let mbstring1 = SecVec::from(vec!['H','a','l','l','o',' ','🦄','!']);
        let mbstring2 = SecVec::from(vec!['H','a','l','l','o',' ','🦄','!']);
        let mbstring3 = SecVec::from(vec!['!','🦄',' ','o','l','l','a','H']);
        assert!(mbstring1 == mbstring2);
        assert!(mbstring1 != mbstring3);
        
        let mut mbstring = mbstring1.clone();
        mbstring.zero_out();
        assert_eq!(mbstring.unsecure(), &['\0','\0','\0','\0','\0','\0','\0','\0']);
    }
}
