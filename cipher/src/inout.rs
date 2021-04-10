use generic_array::{GenericArray, ArrayLength};
use core::marker::PhantomData;
use core::slice;

// TODO: rename to InOutRef
pub trait InOutVal<T> {
    fn get_in(&self) -> &T;

    fn get_out(&mut self) -> &mut T;
}

impl<T> InOutVal<T> for &mut T {
    fn get_in(&self) -> &T {
        self
    }
    fn get_out(&mut self) -> &mut T {
        self
    }
}

impl<T> InOutVal<T> for (&T, &mut T) {
    fn get_in(&self) -> &T {
        self.0
    }
    fn get_out(&mut self) -> &mut T {
        self.1
    }
}

// note: it would be nice to have:
// impl<T, C: InOutVal<T>> InOutVal<T> for &mut C { .. }
// but unfortunately it conflicts with the `&mut T` impl

/// Fat pointer type which references one immutable (input) slice and one mutable
/// (output) slice of equal length.
pub struct InOutBuf<'in_buf, 'out_buf, T> {
    in_ptr: *const T,
    out_ptr: *mut T,
    len: usize,
    _pd: PhantomData<(&'in_buf T, &'out_buf mut T)>,
}

impl<'a, T> From<&'a mut [T]> for InOutBuf<'a, 'a, T> {
    fn from(buf: &'a mut [T]) -> Self {
        Self {
            in_ptr: buf.as_ptr(),
            out_ptr: buf.as_mut_ptr(),
            len: buf.len(),
            _pd: PhantomData,
        }
    }
}

impl<'in_buf, 'out_buf, T> InOutBuf<'in_buf, 'out_buf, T> {
    /// Divides one buffer into two at an index.
    ///
    /// The first will contain all indices from `[0, mid)` (excluding
    /// the index `mid` itself) and the second will contain all
    /// indices from `[mid, len)` (excluding the index `len` itself).
    ///
    /// # Panics
    ///
    /// Panics if `mid > len`.
    #[inline]
    pub fn split_at(self, mid: usize) -> (
        InOutBuf<'in_buf, 'out_buf, T>,
        InOutBuf<'in_buf, 'out_buf, T>,
    ) {
        assert!(mid <= self.len);
        let (tail_in_ptr, tail_out_ptr) = unsafe {
            (self.in_ptr.add(mid), self.out_ptr.add(mid))
        };
        (
            InOutBuf {
                in_ptr: self.in_ptr,
                out_ptr: self.out_ptr,
                len: mid,
                _pd: PhantomData,
            },
            InOutBuf {
                in_ptr: tail_in_ptr,
                out_ptr: tail_out_ptr,
                len: self.len() - mid,
                _pd: PhantomData,
            }
        )
    }

    /// Partitions buffer into 2 parts: body of arrays and tail.
    #[inline]
    pub fn to_blocks<N: ArrayLength<T>>(self) -> (
        InOutBuf<'in_buf, 'out_buf, GenericArray<T, N>>,
        InOutBuf<'in_buf, 'out_buf, T>,
    ) {
        let nb = self.len() / N::USIZE;
        let body_len = nb * N::USIZE;
        let (tail_in_ptr, tail_out_ptr) = unsafe {
            (self.in_ptr.add(body_len), self.out_ptr.add(body_len))
        };
        (
            InOutBuf {
                in_ptr: self.in_ptr as *const GenericArray<T, N>,
                out_ptr: self.out_ptr as *mut GenericArray<T, N>,
                len: nb,
                _pd: PhantomData,
            },
            InOutBuf {
                in_ptr: tail_in_ptr,
                out_ptr: tail_out_ptr,
                len: self.len() - body_len,
                _pd: PhantomData,
            }
        )
    }

    /// Copy data from input buffer to output. Does nothing if input and
    /// output buffers point to the same memory.
    #[inline]
    pub fn copy_in2out(&mut self) {
        if self.in_ptr != self.out_ptr {
            // SAFETY: if pointers are not equal, then memory regions do not overlap
            unsafe {
                core::ptr::copy_nonoverlapping(self.in_ptr, self.out_ptr, self.len);
            }
        }
    }
}

impl<'in_buf, 'out_buf, T> InOutBuf<'in_buf, 'out_buf, T> {
    /// Create a new value from simple references.
    #[inline]
    pub fn from_refs(in_val: &'in_buf T, out_val: &'out_buf mut T) -> Self {
        Self {
            in_ptr: in_val as *const T,
            out_ptr: out_val as *mut T,
            len: 1,
            _pd: PhantomData,
        }

    }

    /// Create a new value from slices.
    ///
    /// Returns an error if length of slices is not equal to each other.
    // TODO: add error type
    #[inline]
    pub fn new(in_buf: &'in_buf [T], out_buf: &'out_buf mut [T]) -> Result<Self, ()> {
        if in_buf.len() != out_buf.len() {
            Err(())
        } else {
            Ok(Self {
                in_ptr: in_buf.as_ptr(),
                out_ptr: out_buf.as_mut_ptr(),
                len: in_buf.len(),
                _pd: Default::default(),
            })
        }

    }

    pub fn chunks<N, S, PC, PT, PR>(
        &mut self,
        state: S,
        mut proc_chunk: PC,
        mut proc_tail: PT,
        proc_res: PR,
    )
    where
        T: Clone + Default,
        N: ArrayLength<T> + 'static,
        PC: FnMut(&mut S, &GenericArray<T, N>, &mut GenericArray<T, N>),
        PT: FnMut(&mut S, &[T], &mut GenericArray<T, N>),
        PR: FnMut(InResOutBuf<'_, '_, 'out_buf, T>),
    {
        self.try_chunks::<N, (), _, _, _, _>(
            state,
            |state, inb, out| {
                proc_chunk(state, inb, out);
                Ok(())
            },
            |state, inb, out| {
                proc_tail(state, inb, out);
                Ok(())
            },
            proc_res,
        ).expect("closures always return Ok");
    }

    pub fn try_chunks<N, E, S, PC, PT, PR>(
        &mut self,
        mut state: S,
        mut proc_chunk: PC,
        mut proc_tail: PT,
        mut proc_res: PR,
    ) -> Result<(), E>
    where
        T: Clone + Default,
        N: ArrayLength<T> + 'static,
        PC: FnMut(&mut S, &GenericArray<T, N>, &mut GenericArray<T, N>) -> Result<(), E>,
        PT: FnMut(&mut S, &[T], &mut GenericArray<T, N>) -> Result<(), E>,
        PR: FnMut(InResOutBuf<'_, '_, 'out_buf, T>),
    {
        let mut pos = 0;
        let len = self.len;
        while len - pos >= N::USIZE {
            let mut res_chunk = GenericArray::<T, N>::default();
            unsafe {
                let in_chunk = &*(self.in_ptr.add(pos) as *const GenericArray<T, N>);
                proc_chunk(&mut state, in_chunk, &mut res_chunk)?;
                proc_res(InResOutBuf::from_raw(
                    in_chunk.as_ptr(),
                    res_chunk.as_mut_ptr(),
                    self.out_ptr.add(pos),
                    N::USIZE,
                ));
            }
            pos += N::USIZE
        }
        let rem = len - pos;
        if rem != 0 {
            let mut res_chunk = GenericArray::<T, N>::default();
            unsafe {
                let in_tail = slice::from_raw_parts(self.in_ptr.add(pos), rem);
                proc_tail(&mut state, in_tail, &mut res_chunk)?;
                proc_res(InResOutBuf::from_raw(
                    in_tail.as_ptr(),
                    res_chunk.as_mut_ptr(),
                    self.out_ptr.add(pos),
                    rem,
                ));
            }
        }
        Ok(())
    }

    /// Process elements in the inner buffers using the `f` callback.
    ///
    /// The first immutable reference passed to the callback is from the input
    /// buffer, while the second mutable one is from output buffer.
    pub fn process_pairs(&self, mut f: impl FnMut(&'in_buf T, &'out_buf mut T)) {
        for i in 0..self.len {
            // SAFETY: constructors guarantee that `in_ptr` and `out_ptr`
            // point to slices of length `len`
            unsafe {
                f(& *(self.in_ptr.add(i)), &mut *(self.out_ptr.add(i)));
            }
        }
    }

    /// Get lenght of the inner buffers.
    #[inline]
    pub fn len(&self) -> usize {
        self.len
    }

    pub fn get_in(&self) -> &'in_buf [T] {
        unsafe {
            slice::from_raw_parts(self.in_ptr, self.len)
        }
    }

    pub fn get_out(&mut self) -> &mut [T] {
        unsafe {
            slice::from_raw_parts_mut(self.out_ptr, self.len)
        }
    }
}

pub struct InResOutBuf<'in_buf, 'res_buf, 'out_buf, T> {
    in_ptr: *const T,
    res_ptr: *mut T,
    out_ptr: *mut T,
    len: usize,
    _pd: PhantomData<(&'in_buf T, &'res_buf T, &'out_buf mut T)>,
}

impl<'in_buf, 'res_buf, 'out_buf, T: Clone> InResOutBuf<'in_buf, 'res_buf, 'out_buf, T> {
    #[inline]
    pub unsafe fn from_raw(
        in_ptr: *const T,
        res_ptr: *mut T,
        out_ptr: *mut T,
        len: usize,
    ) -> Self {
        Self { in_ptr, res_ptr, out_ptr, len, _pd: PhantomData }
    }

    #[inline]
    pub fn from_slices(
        in_buf: &'in_buf [T],
        res_buf: &'res_buf mut [T],
        out_buf: &'out_buf mut [T]
    ) -> Result<Self, ()> {
        let len = in_buf.len();
        if len != res_buf.len() || len != out_buf.len() {
            Err(())
        } else {
            Ok(Self {
                in_ptr: in_buf.as_ptr(),
                res_ptr: res_buf.as_mut_ptr(),
                out_ptr: out_buf.as_mut_ptr(),
                len,
                _pd: PhantomData,
            })
        }

    }

    #[inline]
    pub fn from_arrays<N: ArrayLength<T>>(
        in_buf: &'in_buf GenericArray<T, N>,
        res_buf: &'res_buf mut GenericArray<T, N>,
        out_buf: &'out_buf mut GenericArray<T, N>,
    ) -> Self {
        Self {
            in_ptr: in_buf.as_ptr(),
            res_ptr: res_buf.as_mut_ptr(),
            out_ptr: out_buf.as_mut_ptr(),
            len: N::USIZE,
            _pd: PhantomData,
        }
    }

    #[inline]
    pub fn get_in_res(&mut self) -> (&'in_buf [T], &'res_buf mut [T]) {
        let n = self.len;
        unsafe {
            (
                slice::from_raw_parts(self.in_ptr, n),
                slice::from_raw_parts_mut(self.res_ptr, n),
            )
        }
    }

    #[inline]
    pub fn get_res_out(&mut self) -> (&'res_buf mut [T], &'out_buf mut [T]) {
        let n = self.len;
        unsafe {
            (
                slice::from_raw_parts_mut(self.res_ptr, n),
                slice::from_raw_parts_mut(self.out_ptr, n),
            )
        }
    }

    /// Get lenght of the inner buffers.
    #[inline]
    pub fn len(&self) -> usize {
        self.len
    }
}


#[inline(always)]
pub fn copy_res2out<T: Copy>(mut buf: InResOutBuf<'_, '_, '_, T>) {
    let (res, out) = buf.get_res_out();
    out.copy_from_slice(res);
}

#[inline(always)]
pub fn xor_inres2out<T: Copy, N: ArrayLength<u8>>(
    buf: InResOutBuf<'_, '_, '_, GenericArray<u8, N>>,
) {
    // length of bufers in bytes
    let n = N::USIZE * buf.len();
    let in_ptr = buf.in_ptr as *const u8;
    let res_ptr = buf.res_ptr as *const u8;
    let out_ptr = buf.out_ptr as *mut u8;
    for i in 0..n {
        unsafe {
            *(out_ptr.add(i)) = *(in_ptr.add(i)) ^ *(res_ptr.add(i));
        }
    }
}
