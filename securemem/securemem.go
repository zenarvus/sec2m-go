/*
sec2m-go: CLI based secure secrets manager
Copyright (C) 2026  zenarvus (rem)

This program is free software: you can redistribute it and/or modify
it under the terms of the GNU General Public License as published by
the Free Software Foundation, either version 3 of the License, or
(at your option) any later version.

This program is distributed in the hope that it will be useful,
but WITHOUT ANY WARRANTY; without even the implied warranty of
MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
GNU General Public License for more details.

You should have received a copy of the GNU General Public License
along with this program.  If not, see <https://www.gnu.org/licenses/>.
*/

package securemem

import "io"

////////////////////////////////////////////

// Options configure allocation behavior.
type Option func(*config)

type config struct { lock bool }

// WithLocking attempts to lock the allocated buffer in physical RAM using mlock.
func WithLocking(lock bool) Option {
	return func(c *config) { c.lock = lock }
}

//////////////////////////////////////////

// ZeroBytes explicitly zeroes out sensitive memory slices (for heap)
func ZeroBytes(b []byte) {
	if b == nil {return}
	for i := range b { b[i] = 0 }
}

//////////////////////////////////////////

// manually allocated byte slice with a fixed size and deallocator
type ByteSlice struct {
	Bytes []byte
	Dealloc func()error
	
	freed bool // did we already deallocated the slice? To make  Dealloc() run just for one time
}

// Convert a regular go heap []byte to ByteSlice and zero it
func ToByteSlice(b []byte) ByteSlice {
	bSlice, err := Alloc(len(b))
	if err != nil {return bSlice}
	copy(bSlice.Bytes, b)
	ZeroBytes(b)
	return bSlice
}

// Generate a clone of ByteSlice
func Clone(b ByteSlice) ByteSlice {
	clone,err := Alloc(len(b.Bytes))
	if err != nil {panic(err)}
	copy(clone.Bytes, b.Bytes)
	return clone
}

//////////////////////////////////////////

// A dynamic buffer that implements io.Reader and io.Writer
// It's size gets doubled when the underlying slice gets filled up
type Buffer struct {
	slice *ByteSlice // len(buf): capacity
	
	length int // write at buf[length]
	off int // read at buf[off]
}

// create a byte slice with double of the size of buf, copy the contents of buf and deallocate the old buf
func (buf *Buffer) grow(mincap int) error {
	newCap:= len(buf.slice.Bytes)*2 // new capacity which is the double of the size of the old one
	if mincap < 32 { mincap = 32 } // if mincap is smaller than 32, make it 32. It will be our minimum buffer size
	if newCap < mincap { newCap = mincap } // if new capacity is smaller than the mincap, make newCap mincap

	newBuf,err := Alloc(newCap)
	if err != nil {return err}
	copy(newBuf.Bytes,buf.slice.Bytes)
	if buf.slice.Dealloc != nil {buf.slice.Dealloc()} // deallocate the old slice
	buf.slice = &newBuf
	return nil
}
// return all the bytes written to the buffer
func (buf *Buffer) Bytes() ByteSlice {
	if buf.slice == nil {return ByteSlice{ Dealloc:func()error{return nil} } }

	if buf.slice.Dealloc == nil { buf.slice.Dealloc = func()error{return nil} }

	return ByteSlice{Bytes: buf.slice.Bytes[:buf.length], Dealloc: buf.slice.Dealloc}
}
func (buf *Buffer) Len() int { return buf.length }
// trim the last n bytes from the buffer. Do not if it results in length being less than zero
func (buf *Buffer) Trim(n int) { if buf.length-n > 0 { buf.length -= n } else { buf.length = 0 } }

// Write appends b to the buffer by copying it. Grows if necessary. Implements io.Writer
func (buf *Buffer) Write(b []byte) (n int, err error) {
	needed := buf.length + len(b) // the exact buffer capacity needed

	if buf.slice == nil {buf.slice = &ByteSlice{}}

	// if the capacity of the buffer smaller than the needed capacity, expand the size by needed
	if len(buf.slice.Bytes) < needed {
		err := buf.grow(needed)
		if err != nil { return 0,err }
	}

	n = copy(buf.slice.Bytes[buf.length:], b) // copy bytes to the buffer
	buf.length += n // increase the length of the buffer by bytes written
	return n, nil
}
func (buf *Buffer) WriteByte(b byte) error {
	bb := make([]byte,1); bb[0] = b
	_,err := buf.Write(bb)
	ZeroBytes(bb)
	return err
}

// Read reads the next len(b) bytes from the buffer or until the buffer is all read.
// n is the number of bytes read. If the buffer has no data, io.EOF is returned (if len(b) is not 0)
func (buf *Buffer) Read(b []byte) (n int, err error) {
	// return EOF if the buffer is empty or completely read
	if buf.off >= buf.length {
		buf.Reset() // Reset offsets to reclaim space
		if len(b) == 0 { return 0, nil }
		return 0, io.EOF
	}

	// Copy available unread bytes into b
	n = copy(b, buf.slice.Bytes[buf.off:buf.length])

	buf.off += n // increase the offset by bytes read

	// reset offsets if all data is read
	if buf.off >= buf.length { buf.Reset() }

	return n, nil
}

// Reset clears the buffer content without deallocating memory.
func (buf *Buffer) Reset() {
	ZeroBytes(buf.slice.Bytes)
	buf.length = 0
	buf.off = 0
}

// Dealloc deallocates the underlying ByteSlice.
func (buf *Buffer) Dealloc() error {
	if buf == nil {return nil}
	if buf.slice != nil {
		buf.slice.Dealloc();
	}
	buf.slice = nil
	buf.length = 0
	buf.off = 0
	return nil
}
