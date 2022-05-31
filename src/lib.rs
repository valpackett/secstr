//! A data type suitable for storing sensitive information such as passwords and private keys in memory, featuring constant time equality, mlock and zeroing out.
#[cfg(feature = "serde")]
use serde::{
    de::{self, Deserialize, Deserializer, Visitor},
    ser::{Serialize, Serializer},
};
use std::{
    borrow::{Borrow, BorrowMut},
    fmt,
    str::FromStr,
};

/**
 * Obtain the number of bytes stored in the given byte slice
 */
#[cfg(feature = "libsodium-sys")]
fn size_of<T: Sized>(slice: &[T]) -> usize {
    slice.len() * std::mem::size_of::<T>()
}

/**
 * Create a slice reference from the given box reference
 */
#[cfg(feature = "libsodium-sys")]
fn box_as_slice<T: Sized>(reference: &Box<T>) -> &[T] {
    std::slice::from_ref(reference)
}

#[cfg(feature = "libsodium-sys")]
mod mem {
    extern crate libsodium_sys as sodium;
    use crate::size_of;
    use std;

    #[cfg_attr(
        any(test, feature = "pre"),
        pre::pre(valid_ptr(ptr, w)),
        pre::pre("`ptr` points to a single allocation that is valid for at least `count` bytes"),
        pre::pre(count <= std::isize::MAX as usize)
    )]
    pub unsafe fn zero(ptr: *mut u8, count: usize) {
        sodium::sodium_memzero(ptr as *mut _, count);
    }

    #[inline(never)]
    #[cfg_attr(
        any(test, feature = "pre"),
        pre::pre(valid_ptr(us, r)),
        pre::pre("`us` points to a single allocated object of initialized `u8` values that is valid for `us_len` bytes"),
        pre::pre(us_len <= isize::MAX as usize),
        pre::pre(valid_ptr(them, r)),
        pre::pre("`them` points to a single allocated object of initialized `u8` values that is valid for `them_len` bytes"),
        pre::pre(them_len <= isize::MAX as usize)
    )]
    pub unsafe fn cmp(us: *const u8, us_len: usize, them: *const u8, them_len: usize) -> bool {
        if us_len != them_len {
            return false;
        }

        sodium::sodium_memcmp(us as *const _, them as *const _, them_len) == 0
    }

    #[cfg_attr(any(test, feature = "pre"), pre::pre)]
    pub fn hash<T: Sized + Copy, H>(slice: &[T], state: &mut H)
    where
        H: std::hash::Hasher,
    {
        // Hash the private data
        let mut hash = [0u8; sodium::crypto_hash_BYTES as _];
        unsafe {
            assert_eq!(
                sodium::crypto_hash(&mut hash[0] as *mut _, slice.as_ptr() as *const _, size_of(slice) as u64),
                0
            );
        };

        // Hash again with the current internal state of the outer hasher added as "salt" (will include a per-thread random value for the default SipHasher)
        let mut round2 = Vec::new();
        {
            #[cfg_attr(
                any(test, feature = "pre"),
                forward(pre),
                assure(
                    valid_ptr(data, r),
                    reason = "the pointer is created from the reference `state`, which is guaranteed to be valid for reads"
                ),
                assure(
                    proper_align(data),
                    reason = "the type of the pointer is `u8` with alignment `1`, which every pointer is guaranteed to have"
                ),
                assure(
                    "the allocated object at `data` is valid for `len * mem::size_of::<T>()` bytes",
                    reason = "since `mem::size_of::<u8>() == 1`, the allocated object must be valid for
                              `len == mem::size_of::<H>()` bytes, which it is guaranteed to be, because it is created from a
                              reference to a value of `H`"
                ),
                assure(
                    "the memory referenced by the returned slice is not mutated by any pointer for the duration of `'a`, except inside a contained `UnsafeCell`",
                    reason = "the pointer is created from a mutable reference, so we have exlusive access to the value here
                              and the returned slice is not modified either, so no pointer modifies the memory"
                ),
                assure(
                    len * ::core::mem::size_of::<T>() <= isize::MAX as usize,
                    reason = "`len * mem::size_of::<u8>() == mem::size_of::<H>()` and the compiler fails to compile types
                              with a size greater than `isize::MAX`"
                )
            )]
            let salt = unsafe { std::slice::from_raw_parts(state as *const H as *const u8, std::mem::size_of::<H>()) };
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

    #[cfg_attr(
        any(test, feature = "pre"),
        pre::pre(valid_ptr(ptr, w)),
        pre::pre("`ptr` points to a single allocation that is valid for at least `count` bytes"),
        pre::pre(count <= std::isize::MAX as usize)
    )]
    #[inline(never)]
    pub unsafe fn zero(ptr: *mut u8, count: usize) {
        for i in 0..count {
            #[cfg_attr(
                any(test, feature = "pre"),
                forward(impl pre::std::mut_pointer),
                assure(
                    "the starting and the resulting pointer are in bounds of the same allocated object",
                    reason = "this is guaranteed by the precondition to this function"
                ),
                assure(
                    "the computed offset, in bytes, does not overflow an `isize`",
                    reason = "`computed offset <= count <= isize::MAX`"
                ),
                assure(
                    "performing the offset does not result in overflow",
                    reason = "a single allocation does not rely on overflow to index all elements and `i as isize >= 0`"
                )
            )]
            let offset_ptr = ptr.offset(i as isize);

            #[cfg_attr(
                any(test, feature = "pre"),
                forward(pre),
                assure(
                    valid_ptr(dst, w),
                    reason = "the call to offset above produced a valid pointer into the allocation"
                ),
                assure(
                    proper_align(dst),
                    reason = "`align_of::<*mut u8>() == 1` and any pointer has an alignment of `1`"
                )
            )]
            std::ptr::write_volatile(offset_ptr, 0);
        }
    }

    #[inline(never)]
    #[cfg_attr(
        any(test, feature = "pre"),
        pre::pre(valid_ptr(us, r)),
        pre::pre("`us` points to a single allocated object of initialized `u8` values that is valid for `us_len` bytes"),
        pre::pre(us_len <= isize::MAX as usize),
        pre::pre(valid_ptr(them, r)),
        pre::pre("`them` points to a single allocated object of initialized `u8` values that is valid for `them_len` bytes"),
        pre::pre(them_len <= isize::MAX as usize)
    )]
    pub unsafe fn cmp(us: *const u8, us_len: usize, them: *const u8, them_len: usize) -> bool {
        if us_len != them_len {
            return false;
        }

        let mut result: u8 = 0;

        for i in 0..us_len {
            let us_val = {
                #[cfg_attr(
                    any(test, feature = "pre"),
                    forward(impl pre::std::const_pointer),
                    assure(
                        "the starting and the resulting pointer are in bounds of the same allocated object",
                        reason = "the offset is at most `us_len` bytes and the object at `us` is valid for `us_len` bytes"
                    ),
                    assure(
                        "the computed offset, in bytes, does not overflow an `isize`",
                        reason = "`us_len <= `isize::MAX as usize`"
                    ),
                    assure(
                        "performing the offset does not result in overflow",
                        reason = "a single allocation does not rely on overflow to index all elements and `i as isize >= 0`"
                    )
                )]
                let ptr = us.offset(i as isize);
                #[cfg_attr(
                    any(test, feature = "pre"),
                    forward(pre),
                    assure(
                        valid_ptr(src, r),
                        reason = "`ptr` is constructed from a valid pointer above with an offset that still fits the allocation"
                    ),
                    assure(
                        proper_align(src),
                        reason = "`T` is `u8`, which has an alignment of `1`, which every pointer has"
                    ),
                    assure(
                        "`src` points to a properly initialized value of type `T`",
                        reason = "`ptr` points to the object as `us`, which contains initialized `u8` values"
                    ),
                    assure("`T` is `Copy` or the value at `*src` isn't used after this call", reason = "`u8: Copy`")
                )]
                std::ptr::read_volatile(ptr)
            };
            let them_val = {
                #[cfg_attr(
                    any(test, feature = "pre"),
                    forward(impl pre::std::const_pointer),
                    assure(
                        "the starting and the resulting pointer are in bounds of the same allocated object",
                        reason = "the offset is at most `them_len == us_len` bytes and the object at `them` is valid for `them_len` bytes"
                    ),
                    assure(
                        "the computed offset, in bytes, does not overflow an `isize`",
                        reason = "`them_len == us_len <= `isize::MAX as usize`"
                    ),
                    assure(
                        "performing the offset does not result in overflow",
                        reason = "a single allocation does not rely on overflow to index all elements and `i as isize >= 0`"
                    )
                )]
                let ptr = them.offset(i as isize);
                #[cfg_attr(
                    any(test, feature = "pre"),
                    forward(pre),
                    assure(
                        valid_ptr(src, r),
                        reason = "`ptr` is constructed from a valid pointer above with an offset that still fits the allocation"
                    ),
                    assure(
                        proper_align(src),
                        reason = "`T` is `u8`, which has an alignment of `1`, which every pointer has"
                    ),
                    assure(
                        "`src` points to a properly initialized value of type `T`",
                        reason = "`ptr` points to the object as `them`, which contains initialized `u8` values"
                    ),
                    assure("`T` is `Copy` or the value at `*src` isn't used after this call", reason = "`u8: Copy`")
                )]
                std::ptr::read_volatile(ptr)
            };
            result |= us_val ^ them_val;
        }

        result == 0
    }
}

#[cfg(unix)]
mod memlock {
    extern crate libc;

    pub fn mlock<T: Sized>(cont: *mut T, count: usize) {
        let byte_num = count * std::mem::size_of::<T>();
        unsafe {
            let ptr = cont as *mut libc::c_void;
            libc::mlock(ptr, byte_num);
            #[cfg(any(target_os = "freebsd", target_os = "dragonfly"))]
            libc::madvise(ptr, byte_num, libc::MADV_NOCORE);
            #[cfg(target_os = "linux")]
            libc::madvise(ptr, byte_num, libc::MADV_DONTDUMP);
        }
    }

    pub fn munlock<T: Sized>(cont: *mut T, count: usize) {
        let byte_num = count * std::mem::size_of::<T>();
        unsafe {
            let ptr = cont as *mut libc::c_void;
            libc::munlock(ptr, byte_num);
            #[cfg(any(target_os = "freebsd", target_os = "dragonfly"))]
            libc::madvise(ptr, byte_num, libc::MADV_CORE);
            #[cfg(target_os = "linux")]
            libc::madvise(ptr, byte_num, libc::MADV_DODUMP);
        }
    }
}

#[cfg(not(unix))]
mod memlock {
    pub fn mlock<T: Sized>(cont: *mut T, count: usize) {}

    pub fn munlock<T: Sized>(cont: *mut T, count: usize) {}
}

mod private {
    // Private trait to prevent users from implementing `NoPaddingBytes`
    // This allows to change to a better implementation of `NoPaddingBytes` in the future,
    // without worrying about breaking backwards compatibility for users who implemented the trait.
    pub trait Sealed {}
}
/// Guarantees that there are no padding bytes in types implementing this trait.
///
/// This trait is sealed and cannot be implemented outside of this crate.
pub unsafe trait NoPaddingBytes: private::Sealed {}

macro_rules! impl_no_padding_bytes {
    ($($type:ty),*) => {
        $(
            impl private::Sealed for $type {}
            unsafe impl NoPaddingBytes for $type {}
        )*
    };
}

impl_no_padding_bytes! {
    u8, i8, u16, i16, u32, i32, u64, i64, u128, i128, usize, isize,
    char, f32, f64, ()
}

macro_rules! impl_no_paddding_bytes_array {
    ($($len:literal),*) => {
        $(
            impl<T> private::Sealed for [T; $len] {}
            unsafe impl<T> NoPaddingBytes for [T; $len] {}
        )*
    };
}

impl_no_paddding_bytes_array! {
    0, 1, 2, 3, 4, 5, 6, 7, 8, 9, 10,
    11, 12, 13, 14, 15, 16, 17, 18, 19, 20,
    21, 22, 23, 24, 25, 26, 27, 28, 29, 30,
    31, 32, 64, 128, 256, 512, 1024, 2048, 4096, 8192
}

/// Type alias for a vector that stores just bytes
pub type SecStr = SecVec<u8>;

/// Wrapper for a vector that stores a valid UTF-8 string
#[derive(Clone, Eq)]
pub struct SecUtf8(SecVec<u8>);

impl SecUtf8 {
    /// Borrow the contents of the string.
    #[cfg_attr(any(test, feature = "pre"), pre::pre)]
    pub fn unsecure(&self) -> &str {
        #[cfg_attr(
            any(test, feature = "pre"),
            forward(pre),
            assure(
                "the content of `v` is valid UTF-8",
                reason = "it is not possible to create a `SecUtf8` with invalid UTF-8 content
                and it is also not possible to modify the content as non-UTF-8 directly, so
                they must still be valid UTF-8 here"
            )
        )]
        unsafe {
            std::str::from_utf8_unchecked(self.0.unsecure())
        }
    }

    /// Mutably borrow the contents of the string.
    #[cfg_attr(any(test, feature = "pre"), pre::pre)]
    pub fn unsecure_mut(&mut self) -> &mut str {
        #[cfg_attr(
            any(test, feature = "pre"),
            forward(pre),
            assure(
                "the content of `v` is valid UTF-8",
                reason = "it is not possible to create a `SecUtf8` with invalid UTF-8 content
                and it is also not possible to modify the content as non-UTF-8 directly, so
                they must still be valid UTF-8 here"
            )
        )]
        unsafe {
            std::str::from_utf8_unchecked_mut(self.0.unsecure_mut())
        }
    }

    /// Turn the string into a regular `String` again.
    #[cfg_attr(any(test, feature = "pre"), pre::pre)]
    pub fn into_unsecure(mut self) -> String {
        memlock::munlock(self.0.content.as_mut_ptr(), self.0.content.capacity());
        let content = std::mem::replace(&mut self.0.content, Vec::new());
        std::mem::forget(self);
        #[cfg_attr(
            any(test, feature = "pre"),
            forward(impl pre::std::string::String),
            assure(
                "the content of `bytes` is valid UTF-8",
                reason = "it is not possible to create a `SecUtf8` with invalid UTF-8 content
                and it is also not possible to modify the content as non-UTF-8 directly, so
                they must still be valid UTF-8 here"
            )
        )]
        unsafe {
            String::from_utf8_unchecked(content)
        }
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
        f.write_str("***SECRET***").map_err(|_| fmt::Error)
    }
}

impl fmt::Display for SecUtf8 {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        f.write_str("***SECRET***").map_err(|_| fmt::Error)
    }
}

impl<U> From<U> for SecUtf8
where
    U: Into<String>,
{
    fn from(s: U) -> SecUtf8 {
        SecUtf8(SecVec::new(s.into().into_bytes()))
    }
}

impl FromStr for SecUtf8 {
    type Err = std::convert::Infallible;

    fn from_str(s: &str) -> Result<Self, Self::Err> {
        Ok(SecUtf8(SecVec::new(s.into())))
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
/// Comparisons using the `PartialEq` implementation are undefined behavior (and most likely wrong) if `T` has any padding bytes.
///
/// Be careful with `SecStr::from`: if you have a borrowed string, it will be copied.
/// Use `SecStr::new` if you have a `Vec<u8>`.
pub struct SecVec<T>
where
    T: Sized + Copy,
{
    content: Vec<T>,
}

impl<T> SecVec<T>
where
    T: Sized + Copy,
{
    pub fn new(mut cont: Vec<T>) -> Self {
        memlock::mlock(cont.as_mut_ptr(), cont.capacity());
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

    /// Resizes the `SecVec` in-place so that len is equal to `new_len`.
    ///
    /// If `new_len` is smaller the inner vector is truncated.
    /// If `new_len` is larger the inner vector will grow, placing `value` in all new cells.
    ///
    /// This ensures that the new memory region is secured if reallocation occurs.
    ///
    /// Similar to [`Vec::resize`](https://doc.rust-lang.org/std/vec/struct.Vec.html#method.resize)
    pub fn resize(&mut self, new_len: usize, value: T) {
        // Trucnate if shorter or same length
        if new_len <= self.content.len() {
            self.content.truncate(new_len);
            return;
        }

        // Allocate new vector, copy old data into it
        let mut new_vec = vec![value; new_len];
        memlock::mlock(new_vec.as_mut_ptr(), new_vec.capacity());
        new_vec[0..self.content.len()].copy_from_slice(&self.content);

        // Securely clear old vector, replace with new vector
        self.zero_out();
        memlock::munlock(self.content.as_mut_ptr(), self.content.capacity());
        self.content = new_vec;
    }

    /// Overwrite the string with zeros. This is automatically called in the destructor.
    ///
    /// This also sets the length to `0`.
    #[cfg_attr(any(test, feature = "pre"), pre::pre)]
    pub fn zero_out(&mut self) {
        // We zero the entire capacity, not just the currently initialized capacity
        let num_bytes = self.content.capacity() * std::mem::size_of::<T>();

        // We can set the length to zero without worrying about dropping, because `T: Copy` and
        // `Copy` types cannot implement `Drop`.
        #[cfg_attr(
            any(test, feature = "pre"),
            forward(impl pre::std::vec::Vec),
            assure(
                new_len <= self.capacity(),
                reason = "`0` is smaller or equal to any `usize` and `self.capacity()` is a `usize`"
            ),
            assure(
                "the elements at `old_len..new_len` are initialized",
                reason = "`new_len <= old_len`, so `old_len..new_len` is an empty range"
            )
        )]
        unsafe {
            self.content.set_len(0)
        };

        #[cfg_attr(
            any(test, feature = "pre"),
            assure(
                valid_ptr(ptr, w),
                reason = "the vector is a valid pointer or has length zero and any pointer is valid for zero bytes"
            ),
            assure(
                "`ptr` points to a single allocation that is valid for at least `count` bytes",
                reason = "a vector always points to a single allocation and `count` is the size of the allocation in bytes"
            ),
            assure(
                count <= std::isize::MAX as usize,
                reason = "a vector never allocates more than `isize::MAX` elements"
            )
        )]
        unsafe {
            mem::zero(self.content.as_mut_ptr() as *mut u8, num_bytes)
        };
    }
}

impl<T: Copy> Clone for SecVec<T> {
    fn clone(&self) -> Self {
        Self::new(self.content.clone())
    }
}

// Creation
impl<T, U> From<U> for SecVec<T>
where
    U: Into<Vec<T>>,
    T: Sized + Copy,
{
    fn from(s: U) -> SecVec<T> {
        SecVec::new(s.into())
    }
}

impl FromStr for SecVec<u8> {
    type Err = std::convert::Infallible;

    fn from_str(s: &str) -> Result<Self, Self::Err> {
        Ok(SecVec::new(s.into()))
    }
}

// Vec item indexing
impl<T, U> std::ops::Index<U> for SecVec<T>
where
    T: Sized + Copy,
    Vec<T>: std::ops::Index<U>,
{
    type Output = <Vec<T> as std::ops::Index<U>>::Output;

    fn index(&self, index: U) -> &Self::Output {
        std::ops::Index::index(&self.content, index)
    }
}

// Borrowing
impl<T> Borrow<[T]> for SecVec<T>
where
    T: Sized + Copy,
{
    fn borrow(&self) -> &[T] {
        self.content.borrow()
    }
}

impl<T> BorrowMut<[T]> for SecVec<T>
where
    T: Sized + Copy,
{
    fn borrow_mut(&mut self) -> &mut [T] {
        self.content.borrow_mut()
    }
}

// Overwrite memory with zeros when we're done
impl<T> Drop for SecVec<T>
where
    T: Sized + Copy,
{
    fn drop(&mut self) {
        self.zero_out();
        memlock::munlock(self.content.as_mut_ptr(), self.content.capacity());
    }
}

// Constant time comparison
impl<T> PartialEq for SecVec<T>
where
    T: Sized + Copy + NoPaddingBytes,
{
    #[cfg_attr(any(test, feature = "pre"), pre::pre)]
    fn eq(&self, other: &SecVec<T>) -> bool {
        #[cfg_attr(
            any(test, feature = "pre"),
            assure(
                valid_ptr(us, r),
                reason = "`us` is created from a reference"
            ),
            assure(
                "`us` points to a single allocated object of initialized `u8` values that is valid for `us_len` bytes",
                reason = "`T` has no padding bytes, because of the `NoPaddingBytes` bound and all other bytes are initialized,
                because all elements in a vec are initialized. They also all belong to a single allocation big enough to hold
                at least `vec.len()` elements of `T`."
            ),
            assure(
                us_len <= isize::MAX as usize,
                reason = "a slice is never larger than `isize::MAX` bytes"
            ),
            assure(
                valid_ptr(them, r),
                reason = "`them` is created from a reference"
            ),
            assure(
                "`them` points to a single allocated object of initialized `u8` values that is valid for `them_len` bytes",
                reason = "`T` has no padding bytes, because of the `NoPaddingBytes` bound and all other bytes are initialized,
                because all elements in a vec are initialized. They also all belong to a single allocation big enough to hold
                at least `vec.len()` elements of `T`."
            ),
            assure(
                them_len <= isize::MAX as usize,
                reason = "a slice is never larger than `isize::MAX` bytes"
            )
        )]
        unsafe {
            mem::cmp(
                self.content.as_ptr() as *const u8,
                self.content.len() * std::mem::size_of::<T>(),
                other.content.as_ptr() as *const u8,
                other.content.len() * std::mem::size_of::<T>(),
            )
        }
    }
}

impl<T> Eq for SecVec<T> where T: Sized + Copy + NoPaddingBytes {}

// Make sure sensitive information is not logged accidentally
impl<T> fmt::Debug for SecVec<T>
where
    T: Sized + Copy,
{
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        f.write_str("***SECRET***").map_err(|_| fmt::Error)
    }
}

impl<T> fmt::Display for SecVec<T>
where
    T: Sized + Copy,
{
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        f.write_str("***SECRET***").map_err(|_| fmt::Error)
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

    fn visit_bytes<E>(self, value: &[u8]) -> Result<SecVec<u8>, E>
    where
        E: de::Error,
    {
        Ok(SecStr::from(value))
    }
}

#[cfg(feature = "serde")]
impl<'de> Deserialize<'de> for SecVec<u8> {
    fn deserialize<D>(deserializer: D) -> Result<SecVec<u8>, D::Error>
    where
        D: Deserializer<'de>,
    {
        deserializer.deserialize_bytes(BytesVisitor)
    }
}

#[cfg(feature = "libsodium-sys")]
impl<T> std::hash::Hash for SecVec<T>
where
    T: Sized + Copy,
{
    fn hash<H>(&self, state: &mut H)
    where
        H: std::hash::Hasher,
    {
        mem::hash(&self.content, state);
    }
}

#[cfg(feature = "serde")]
impl Serialize for SecVec<u8> {
    fn serialize<S>(&self, serializer: S) -> Result<S::Ok, S::Error>
    where
        S: Serializer,
    {
        serializer.serialize_bytes(self.content.borrow())
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
/// Comparisons using the `PartialEq` implementation are undefined behavior (and most likely wrong) if `T` has any padding bytes.
pub struct SecBox<T>
where
    T: Sized + Copy,
{
    // This is an `Option` to avoid UB in the destructor, outside the destructor, it is always
    // `Some(_)`
    content: Option<Box<T>>,
}

impl<T> SecBox<T>
where
    T: Sized + Copy,
{
    pub fn new(mut cont: Box<T>) -> Self {
        memlock::mlock(&mut cont, std::mem::size_of::<T>());
        SecBox { content: Some(cont) }
    }

    /// Borrow the contents of the string.
    pub fn unsecure(&self) -> &T {
        self.content.as_ref().unwrap()
    }

    /// Mutably borrow the contents of the string.
    pub fn unsecure_mut(&mut self) -> &mut T {
        self.content.as_mut().unwrap()
    }
}

impl<T: Copy> Clone for SecBox<T> {
    fn clone(&self) -> Self {
        Self::new(self.content.clone().unwrap())
    }
}

/// Overwrite the contents with zeros. This is automatically done in the destructor.
///
/// # Safety
/// An all-zero byte-pattern must be a valid value of `T` in order for this function call to not be
/// undefined behavior.
#[cfg_attr(any(test, feature = "pre"), pre::pre("an all-zero byte-pattern is a valid value of `T`"))]
pub unsafe fn zero_out_secbox<T>(secbox: &mut SecBox<T>)
where
    T: Sized + Copy,
{
    #[cfg_attr(
        any(test, feature = "pre"),
        assure(
            valid_ptr(ptr, w),
            reason = "`ptr` comes from a valid box, which is guaranteed to be a valid pointer"
        ),
        assure(
            "`ptr` points to a single allocation that is valid for at least `count` bytes",
            reason = "a `Box<T>` points to an allocation of at least `mem::size_of::<T>()` bytes"
        ),
        assure(
            count <= std::isize::MAX as usize,
            reason = "`mem::size_of::<T>()` cannot return a value larger than `isize::MAX`"
        )
    )]
    mem::zero(&mut **secbox.content.as_mut().unwrap() as *mut T as *mut u8, std::mem::size_of::<T>());
}

// Delegate indexing
impl<T, U> std::ops::Index<U> for SecBox<T>
where
    T: std::ops::Index<U> + Sized + Copy,
{
    type Output = <T as std::ops::Index<U>>::Output;

    fn index(&self, index: U) -> &Self::Output {
        std::ops::Index::index(self.content.as_ref().unwrap().as_ref(), index)
    }
}

// Borrowing
impl<T> Borrow<T> for SecBox<T>
where
    T: Sized + Copy,
{
    fn borrow(&self) -> &T {
        self.content.as_ref().unwrap()
    }
}
impl<T> BorrowMut<T> for SecBox<T>
where
    T: Sized + Copy,
{
    fn borrow_mut(&mut self) -> &mut T {
        self.content.as_mut().unwrap()
    }
}

// Overwrite memory with zeros when we're done
impl<T> Drop for SecBox<T>
where
    T: Sized + Copy,
{
    #[cfg_attr(any(test, feature = "pre"), pre::pre)]
    fn drop(&mut self) {
        // Make sure that the box does not need to be dropped after this function, because it may
        // see an invalid type, if `T` does not support an all-zero byte-pattern
        // Instead we manually destruct the box and only handle the potentially invalid values
        // behind the pointer
        let ptr = Box::into_raw(self.content.take().unwrap());

        // There is no need to worry about dropping the contents, because `T: Copy` and `Copy`
        // types cannot implement `Drop`

        #[cfg_attr(
            any(test, feature = "pre"),
            assure(
                valid_ptr(ptr, w),
                reason = "`ptr` comes from a valid box, which is guaranteed to be a valid pointer"
            ),
            assure(
                "`ptr` points to a single allocation that is valid for at least `count` bytes",
                reason = "a `Box<T>` points to an allocation of at least `mem::size_of::<T>()` bytes"
            ),
            assure(
                count <= std::isize::MAX as usize,
                reason = "`mem::size_of::<T>()` cannot return a value larger than `isize::MAX`"
            )
        )]
        unsafe {
            mem::zero(ptr as *mut u8, std::mem::size_of::<T>())
        };
        memlock::munlock(ptr, std::mem::size_of::<T>());

        // Deallocate only non-zero-sized types, because otherwise it's UB
        if std::mem::size_of::<T>() != 0 {
            // Safety:
            // This way to manually deallocate is advertised in the documentation of `Box::into_raw`.
            // The box was allocated with the global allocator and a layout of `T` and is thus
            // deallocated using the same allocator and layout here.
            unsafe { std::alloc::dealloc(ptr as *mut u8, std::alloc::Layout::new::<T>()) };
        }
    }
}

// Constant time comparison
impl<T> PartialEq for SecBox<T>
where
    T: Sized + Copy + NoPaddingBytes,
{
    #[cfg_attr(any(test, feature = "pre"), pre::pre)]
    fn eq(&self, other: &SecBox<T>) -> bool {
        #[cfg_attr(
            any(test, feature = "pre"),
            assure(
                valid_ptr(us, r),
                reason = "`us` is created from a reference"
            ),
            assure(
                "`us` points to a single allocated object of initialized `u8` values that is valid for `us_len` bytes",
                reason = "`T` has no padding bytes, because of the `NoPaddingBytes` bound and all other bytes are initialized,
                because all elements in a vec are initialized. They also all belong to a single allocation big enough to hold
                at least `vec.len()` elements of `T`."
            ),
            assure(
                us_len <= isize::MAX as usize,
                reason = "`mem::size_of::<T>()` is never larger than `isize::MAX` bytes"
            ),
            assure(
                valid_ptr(them, r),
                reason = "`them` is created from a reference"
            ),
            assure(
                "`them` points to a single allocated object of initialized `u8` values that is valid for `them_len` bytes",
                reason = "`T` has no padding bytes, because of the `NoPaddingBytes` bound and all other bytes are initialized,
                because all elements in a vec are initialized. They also all belong to a single allocation big enough to hold
                at least `vec.len()` elements of `T`."
            ),
            assure(
                them_len <= isize::MAX as usize,
                reason = "`mem::size_of::<T>()` is never larger than `isize::MAX` bytes"
            )
        )]
        unsafe {
            mem::cmp(
                &**self.content.as_ref().unwrap() as *const T as *const u8,
                std::mem::size_of::<T>(),
                &**other.content.as_ref().unwrap() as *const T as *const u8,
                std::mem::size_of::<T>(),
            )
        }
    }
}

impl<T> Eq for SecBox<T> where T: Sized + Copy + NoPaddingBytes {}

// Make sure sensitive information is not logged accidentally
impl<T> fmt::Debug for SecBox<T>
where
    T: Sized + Copy,
{
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        f.write_str("***SECRET***").map_err(|_| fmt::Error)
    }
}
impl<T> fmt::Display for SecBox<T>
where
    T: Sized + Copy,
{
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        f.write_str("***SECRET***").map_err(|_| fmt::Error)
    }
}

#[cfg(feature = "libsodium-sys")]
impl<T> std::hash::Hash for SecBox<T>
where
    T: Sized + Copy,
{
    fn hash<H>(&self, state: &mut H)
    where
        H: std::hash::Hasher,
    {
        mem::hash(box_as_slice(self.content.as_ref().unwrap()), state);
    }
}

#[cfg(test)]
mod tests {
    use super::{zero_out_secbox, SecBox, SecStr, SecVec};

    #[test]
    fn test_basic() {
        let my_sec = SecStr::from("hello");
        assert_eq!(my_sec, SecStr::from("hello".to_string()));
        assert_eq!(my_sec.unsecure(), b"hello");
    }

    #[test]
    #[cfg_attr(any(test, feature = "pre"), pre::pre)]
    fn test_zero_out() {
        let mut my_sec = SecStr::from("hello");
        my_sec.zero_out();
        // `zero_out` sets the `len` to 0, here we reset it to check that the bytes were zeroed
        #[cfg_attr(
            any(test, feature = "pre"),
            forward(impl pre::std::vec::Vec),
            assure(
                new_len <= self.capacity(),
                reason = "the call to `zero_out` did not reduce the capacity and the length was `5` before,
                so the capacity must be greater or equal to `5`"
            ),
            assure(
                "the elements at `old_len..new_len` are initialized",
                reason = "they were initialized to `0` by the call to `zero_out`"
            )
        )]
        unsafe {
            my_sec.content.set_len(5)
        }
        assert_eq!(my_sec.unsecure(), b"\x00\x00\x00\x00\x00");
    }

    #[test]
    fn test_resize() {
        let mut my_sec = SecVec::from([0, 1]);
        assert_eq!(my_sec.unsecure().len(), 2);
        my_sec.resize(1, 0);
        assert_eq!(my_sec.unsecure().len(), 1);
        my_sec.resize(16, 2);
        assert_eq!(my_sec.unsecure(), &[0, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2]);
    }

    #[test]
    fn test_comparison() {
        assert_eq!(SecStr::from("hello"), SecStr::from("hello"));
        assert!(SecStr::from("hello") != SecStr::from("yolo"));
        assert!(SecStr::from("hello") != SecStr::from("olleh"));
        assert!(SecStr::from("hello") != SecStr::from("helloworld"));
        assert!(SecStr::from("hello") != SecStr::from(""));
    }

    #[test]
    fn test_indexing() {
        let string = SecStr::from("hello");
        assert_eq!(string[0], 'h' as u8);
        assert_eq!(&string[3..5], "lo".as_bytes());
    }

    #[test]
    fn test_show() {
        assert_eq!(format!("{:?}", SecStr::from("hello")), "***SECRET***".to_string());
        assert_eq!(format!("{}", SecStr::from("hello")), "***SECRET***".to_string());
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
    #[cfg_attr(any(test, feature = "pre"), pre::pre)]
    fn test_comparison_zero_out_mb() {
        let mbstring1 = SecVec::from(vec!['H', 'a', 'l', 'l', 'o', ' ', '🦄', '!']);
        let mbstring2 = SecVec::from(vec!['H', 'a', 'l', 'l', 'o', ' ', '🦄', '!']);
        let mbstring3 = SecVec::from(vec!['!', '🦄', ' ', 'o', 'l', 'l', 'a', 'H']);
        assert!(mbstring1 == mbstring2);
        assert!(mbstring1 != mbstring3);

        let mut mbstring = mbstring1.clone();
        mbstring.zero_out();
        // `zero_out` sets the `len` to 0, here we reset it to check that the bytes were zeroed
        #[cfg_attr(
            any(test, feature = "pre"),
            forward(impl pre::std::vec::Vec),
            assure(
                new_len <= self.capacity(),
                reason = "the call to `zero_out` did not reduce the capacity and the length was `8` before,
                so the capacity must be greater or equal to `8`"
            ),
            assure(
                "the elements at `old_len..new_len` are initialized",
                reason = "they were initialized to `0` by the call to `zero_out`"
            )
        )]
        unsafe {
            mbstring.content.set_len(8)
        }
        assert_eq!(mbstring.unsecure(), &['\0', '\0', '\0', '\0', '\0', '\0', '\0', '\0']);
    }

    const PRIVATE_KEY_1: [u8; 32] = [
        0xb0, 0x3b, 0x34, 0xc3, 0x3a, 0x1c, 0x44, 0xf2, 0x25, 0xb6, 0x62, 0xd2, 0xbf, 0x48, 0x59, 0xb8, 0x13, 0x54, 0x11, 0xfa,
        0x7b, 0x03, 0x86, 0xd4, 0x5f, 0xb7, 0x5d, 0xc5, 0xb9, 0x1b, 0x44, 0x66,
    ];

    const PRIVATE_KEY_2: [u8; 32] = [
        0xc8, 0x06, 0x43, 0x9d, 0xc9, 0xd2, 0xc4, 0x76, 0xff, 0xed, 0x8f, 0x25, 0x80, 0xc0, 0x88, 0x8d, 0x58, 0xab, 0x40, 0x6b,
        0xf7, 0xae, 0x36, 0x98, 0x87, 0x90, 0x21, 0xb9, 0x6b, 0xb4, 0xbf, 0x59,
    ];

    #[test]
    #[cfg_attr(any(test, feature = "pre"), pre::pre)]
    fn test_secbox() {
        let key_1 = SecBox::new(Box::new(PRIVATE_KEY_1));
        let key_2 = SecBox::new(Box::new(PRIVATE_KEY_2));
        let key_3 = SecBox::new(Box::new(PRIVATE_KEY_1));
        assert!(key_1 == key_1);
        assert!(key_1 != key_2);
        assert!(key_2 != key_3);
        assert!(key_1 == key_3);

        let mut final_key = key_1.clone();
        #[cfg_attr(
            any(test, feature = "pre"),
            assure(
                "an all-zero byte-pattern is a valid value of `T`",
                reason = "`T` is `i32`, for which an all-zero byte-pattern is valid"
            )
        )]
        unsafe {
            zero_out_secbox(&mut final_key)
        };
        assert_eq!(final_key.unsecure(), &[0; 32]);
    }

    #[cfg(feature = "serde")]
    #[test]
    fn test_serialization() {
        use serde_cbor::{from_slice, to_vec};
        let my_sec = SecStr::from("hello");
        let my_cbor = to_vec(&my_sec).unwrap();
        assert_eq!(my_cbor, b"\x45hello");
        let my_sec2 = from_slice(&my_cbor).unwrap();
        assert_eq!(my_sec, my_sec2);
    }
}
