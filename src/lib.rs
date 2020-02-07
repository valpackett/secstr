//! A data type suitable for storing sensitive information such as passwords and private keys in memory, featuring constant time equality, mlock and zeroing out.
#[cfg(feature = "serde")] extern crate serde;
use std::fmt;
use std::borrow::{Borrow, BorrowMut};
#[cfg(feature = "serde")] use serde::ser::{Serialize, Serializer};
#[cfg(feature = "serde")] use serde::de::{self, Deserialize, Deserializer, Visitor};
#[cfg(all(test, feature = "serde"))] extern crate serde_cbor;


/**
 * Obtain the number of bytes stored in the given byte slice
 */
fn size_of<T: Sized>(slice: &[T]) -> usize {
    slice.len() * std::mem::size_of::<T>()
}

/**
 * Create a slice reference from the given box reference
 */
fn box_as_slice<T: Sized>(reference: &Box<T>) -> &[T] {
    unsafe { std::slice::from_raw_parts(reference as &T, 1) }
}

/**
 * Create a slice reference from the given box reference
 */
fn box_as_slice_mut<T: Sized + Copy>(reference: &mut Box<T>) -> &mut [T] {
    unsafe { std::slice::from_raw_parts_mut(reference as &mut T, 1) }
}



#[cfg(feature = "libsodium-sys")]
mod mem {
    extern crate libsodium_sys as sodium;
    use std;
    use ::size_of;

    pub fn zero<T: Sized + Copy>(slice: &mut [T]) {
        unsafe {
            sodium::sodium_memzero(slice.as_ptr() as *mut _, size_of(slice));
        }
    }

    pub fn cmp<T: Sized + Copy>(us: &[T], them: &[T]) -> bool {
        if us.len() != them.len() {
            return false;
        }

        unsafe {
            sodium::sodium_memcmp(us.as_ptr() as *const _, them.as_ptr() as *const _, size_of(them)) == 0
        }
    }

    pub fn hash<T: Sized + Copy, H>(slice: &[T], state: &mut H) where H: std::hash::Hasher {
        // Hash the private data
        let mut hash = [0u8; sodium::crypto_hash_BYTES as _];
        unsafe {
            assert_eq!(sodium::crypto_hash(&mut hash[0] as *mut _, slice.as_ptr() as *const _, size_of(slice) as u64), 0);
        };

        // Hash again with the current internal state of the outer hasher added as "salt" (will include a per-thread random value for the default SipHasher)
        let mut round2 = Vec::new();
        unsafe {
            let salt = std::slice::from_raw_parts(state as *const H as *const u8, std::mem::size_of::<H>());
            round2.reserve_exact(hash.len() + salt.len());
            round2.extend_from_slice(&hash);
            round2.extend_from_slice(salt);
        };

        let mut hash2 = [0u8; sodium::crypto_hash_BYTES as _];
        unsafe {
            assert_eq!(sodium::crypto_hash(&mut hash2[0] as *mut _, round2.as_ptr(), round2.len() as u64), 0);
        };

        // Use this final value as state
        state.write(&hash2 as &[u8]);
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
            let ptr = cont.as_ptr() as *mut libc::c_void;
            libc::mlock(ptr, size_of(cont));
            #[cfg(any(target_os = "freebsd", target_os = "dragonfly"))]
            libc::madvise(ptr, size_of(cont), libc::MADV_NOCORE);
            #[cfg(target_os = "linux")]
            libc::madvise(ptr, size_of(cont), libc::MADV_DONTDUMP);
        }
    }

    pub fn munlock<T: Sized>(cont: &[T]) {
        unsafe {
            let ptr = cont.as_ptr() as *mut libc::c_void;
            libc::munlock(ptr, size_of(cont));
            #[cfg(any(target_os = "freebsd", target_os = "dragonfly"))]
            libc::madvise(ptr, size_of(cont), libc::MADV_CORE);
            #[cfg(target_os = "linux")]
            libc::madvise(ptr, size_of(cont), libc::MADV_DODUMP);
        }
    }
}

#[cfg(not(unix))]
mod memlock {
    pub fn mlock<T: Sized>(cont: &[T]) {
    }

    pub fn munlock<T: Sized>(cont: &[T]) {
    }
}



/// Type alias for a vector that stores just bytes
pub type SecStr = SecVec<u8>;

/// Wrapper for a vector that stores a valid UTF-8 string
#[derive(Clone, Eq)]
pub struct SecUtf8(SecVec<u8>);

impl SecUtf8 {
    pub fn unsecure(&self) -> &str {
        unsafe { std::str::from_utf8_unchecked(self.0.unsecure())}
    }

    pub fn into_unsecure(mut self) -> String {
        let content = std::mem::replace(&mut self.0.content, Vec::new());
        unsafe { String::from_utf8_unchecked(content) }
    }
}

impl PartialEq for SecUtf8 {
    fn eq(&self, other: &SecUtf8) -> bool {
        // use implementation of SecVec
        self.0 == other.0
    }
}

impl fmt::Debug for SecUtf8 {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        f.write_str("***SECRET***").map_err(|_| { fmt::Error })
    }
}

impl fmt::Display for SecUtf8 {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        f.write_str("***SECRET***").map_err(|_| { fmt::Error })
    }
}

impl<U> From<U> for SecUtf8 where U: Into<String> {
    fn from(s: U) -> SecUtf8 {
        SecUtf8(SecVec::new(s.into().into_bytes()))
    }
}

#[cfg(feature = "serde")]
impl serde::Serialize for SecUtf8 {
    fn serialize<S>(&self, serializer: S) -> Result<S::Ok, S::Error>
    where
        S: serde::Serializer,
    {
        serializer.serialize_str(self.unsecure())
    }
}

#[cfg(feature = "serde")]
impl<'de> serde::Deserialize<'de> for SecUtf8 {
    fn deserialize<D>(deserializer: D) -> Result<SecUtf8, D::Error>
    where
        D: serde::Deserializer<'de>,
    {
        struct SecUtf8Visitor;
        impl<'de> serde::de::Visitor<'de> for SecUtf8Visitor {
            type Value = SecUtf8;
            fn expecting(&self, formatter: &mut ::std::fmt::Formatter) -> ::std::fmt::Result {
                write!(formatter, "an utf-8 encoded string")
            }
            fn visit_str<E>(self, v: &str) -> Result<Self::Value, E>
            where
                E: serde::de::Error,
            {
                Ok(SecUtf8::from(v.to_string()))
            }
        }
        deserializer.deserialize_string(SecUtf8Visitor)
    }
}

/// A data type suitable for storing sensitive information such as passwords and private keys in memory, that implements:
///
/// - Automatic zeroing in `Drop`
/// - Constant time comparison in `PartialEq` (does not short circuit on the first different character; but terminates instantly if strings have different length)
/// - Outputting `***SECRET***` to prevent leaking secrets into logs in `fmt::Debug` and `fmt::Display`
/// - Automatic `mlock` to protect against leaking into swap (any unix)
/// - Automatic `madvise(MADV_NOCORE/MADV_DONTDUMP)` to protect against leaking into core dumps (FreeBSD, DragonflyBSD, Linux)
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

// Vec item indexing
impl<T, U> std::ops::Index<U> for SecVec<T> where T: Sized + Copy, Vec<T>: std::ops::Index<U> {
    type Output = <Vec<T> as std::ops::Index<U>>::Output;

    fn index(&self, index: U) -> &Self::Output {
        std::ops::Index::index(&self.content, index)
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

#[cfg(feature = "serde")]
struct BytesVisitor;

#[cfg(feature = "serde")]
impl<'de> Visitor<'de> for BytesVisitor {
    type Value = SecVec<u8>;

    fn expecting(&self, formatter: &mut fmt::Formatter) -> fmt::Result {
        formatter.write_str("a byte array")
    }

    fn visit_bytes<E>(self, value: &[u8]) -> Result<SecVec<u8>, E> where E: de::Error {
        Ok(SecStr::from(value))
    }
}

#[cfg(feature = "serde")]
impl<'de> Deserialize<'de> for SecVec<u8> {
    fn deserialize<D>(deserializer: D) -> Result<SecVec<u8>, D::Error> where D: Deserializer<'de> {
        deserializer.deserialize_bytes(BytesVisitor)
    }
}

#[cfg(feature = "libsodium-sys")]
impl<T> std::hash::Hash for SecVec<T> where T: Sized + Copy {
    fn hash<H>(&self, state: &mut H) where H: std::hash::Hasher {
        mem::hash(&self.content, state);
    }
}

#[cfg(feature = "serde")]
impl Serialize for SecVec<u8> {
    fn serialize<S>(&self, serializer: S) -> Result<S::Ok, S::Error> where S: Serializer {
        serializer.serialize_bytes(self.content.borrow())
    }
}


#[derive(Clone, Eq)]
pub struct SecBox<T> where T: Sized + Copy {
    content: Box<T>
}

impl<T> SecBox<T> where T: Sized + Copy {
    pub fn new(cont: Box<T>) -> Self {
        memlock::mlock(box_as_slice(&cont));
        SecBox { content: cont }
    }

    /// Borrow the contents of the string.
    pub fn unsecure(&self) -> &T {
        &self.content
    }

    /// Mutably borrow the contents of the string.
    pub fn unsecure_mut(&mut self) -> &mut T {
        &mut self.content
    }

    /// Overwrite the string with zeros. This is automatically called in the destructor.
    pub fn zero_out(&mut self) {
        mem::zero(box_as_slice_mut(&mut self.content));
    }
}

// Delegate indexing
impl<T, U> std::ops::Index<U> for SecBox<T> where T: std::ops::Index<U> + Sized + Copy {
    type Output = <T as std::ops::Index<U>>::Output;

    fn index(&self, index: U) -> &Self::Output {
        std::ops::Index::index(self.content.as_ref(), index)
    }
}

// Borrowing
impl<T> Borrow<T> for SecBox<T> where T: Sized + Copy {
    fn borrow(&self) -> &T {
        &self.content
    }
}
impl<T> BorrowMut<T> for SecBox<T> where T: Sized + Copy {
    fn borrow_mut(&mut self) -> &mut T {
        &mut self.content
    }
}

// Overwrite memory with zeros when we're done
impl<T> Drop for SecBox<T> where T: Sized + Copy {
    fn drop(&mut self) {
        self.zero_out();
        memlock::munlock(box_as_slice_mut(&mut self.content));
    }
}

// Constant time comparison
impl<T> PartialEq for SecBox<T> where T: Sized + Copy {
    fn eq(&self, other: &SecBox<T>) -> bool {
        mem::cmp(box_as_slice(&self.content), box_as_slice(&other.content))
    }
}

// Make sure sensitive information is not logged accidentally
impl<T> fmt::Debug for SecBox<T> where T: Sized + Copy {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        f.write_str("***SECRET***").map_err(|_| { fmt::Error })
    }
}
impl<T> fmt::Display for SecBox<T> where T: Sized + Copy {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        f.write_str("***SECRET***").map_err(|_| { fmt::Error })
    }
}

#[cfg(feature = "libsodium-sys")]
impl<T> std::hash::Hash for SecBox<T> where T: Sized + Copy {
    fn hash<H>(&self, state: &mut H) where H: std::hash::Hasher {
        mem::hash(box_as_slice(&self.content), state);
    }
}



#[cfg(test)]
mod tests {
    use super::{SecBox, SecStr, SecVec};

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
    fn test_indexing() {
        let string = SecStr::from("hello");
        assert_eq!(string[0],       'h' as u8);
        assert_eq!(&string[3 .. 5], "lo".as_bytes());
    }

    #[test]
    fn test_show() {
        assert_eq!(format!("{:?}", SecStr::from("hello")), "***SECRET***".to_string());
        assert_eq!(format!("{}",   SecStr::from("hello")), "***SECRET***".to_string());
    }

    #[cfg(feature = "libsodium-sys")]
    #[test]
    fn test_hashing() {
        use std::hash::*;

        let value = SecStr::from("hello");

        let mut hasher = SipHasher::new(); // Variant of SipHasher that does not use random values
        value.hash(&mut hasher);
        assert_eq!(hasher.finish(), 12960579610752219549);
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

    const PRIVATE_KEY_1: [u8; 32] = [
        0xb0, 0x3b, 0x34, 0xc3, 0x3a, 0x1c, 0x44, 0xf2,
        0x25, 0xb6, 0x62, 0xd2, 0xbf, 0x48, 0x59, 0xb8,
        0x13, 0x54, 0x11, 0xfa, 0x7b, 0x03, 0x86, 0xd4,
        0x5f, 0xb7, 0x5d, 0xc5, 0xb9, 0x1b, 0x44, 0x66];

    const PRIVATE_KEY_2: [u8; 32] = [
        0xc8, 0x06, 0x43, 0x9d, 0xc9, 0xd2, 0xc4, 0x76,
        0xff, 0xed, 0x8f, 0x25, 0x80, 0xc0, 0x88, 0x8d,
        0x58, 0xab, 0x40, 0x6b, 0xf7, 0xae, 0x36, 0x98,
        0x87, 0x90, 0x21, 0xb9, 0x6b, 0xb4, 0xbf, 0x59];

    #[test]
    fn test_secbox() {
        let key_1 = SecBox::new(Box::new(PRIVATE_KEY_1));
        let key_2 = SecBox::new(Box::new(PRIVATE_KEY_2));
        let key_3 = SecBox::new(Box::new(PRIVATE_KEY_1));
        assert!(key_1 == key_1);
        assert!(key_1 != key_2);
        assert!(key_2 != key_3);
        assert!(key_1 == key_3);

        let mut final_key = key_1.clone();
        final_key.zero_out();
        assert_eq!(final_key.unsecure(), &[0; 32]);
    }

    #[cfg(feature = "serde")]
    #[test]
    fn test_serialization() {
        use serde_cbor::{to_vec, from_slice};
        let my_sec = SecStr::from("hello");
        let my_cbor = to_vec(&my_sec).unwrap();
        assert_eq!(my_cbor, b"\x45hello");
        let my_sec2 = from_slice(&my_cbor).unwrap();
        assert_eq!(my_sec, my_sec2);
    }

}
