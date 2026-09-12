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

// Options configure allocation behavior.
type Option func(*config)

type config struct { lock bool }

// WithLocking attempts to lock the allocated buffer in physical RAM using mlock.
func WithLocking(lock bool) Option {
	return func(c *config) { c.lock = lock }
}

// ZeroBytes explicitly zeroes out sensitive memory slices
func ZeroBytes(b []byte) {
	if b == nil {return}
	for i := range b { b[i] = 0 }
}

// A dynamic buffer that implements io.Reader and io.Writer
// It's size gets doubled when the underlying slice gets filled up
type Buffer struct {
	buf []byte // len(buf): capacity
	dealloc func()
	
	length int // write at buf[length]
	off int // read at buf[off]
}

// create a byte slice with double of the size of buf, copy the contents of buf and deallocate the old buf
func (buf *Buffer) expand(mincap int) error {
	newCap:= len(buf.buf)*2 // new capacity which is the double of the size of the old one
	if mincap < 32 { mincap = 32 } // if mincap is smaller than 32, make it 32. It will be our minimum buffer size
	if newCap < mincap { newCap = mincap } // if new capacity is smaller than the mincap, make newCap mincap

	newBuf,newDealloc,err := Alloc(newCap)
	if err != nil {return err}
	copy(newBuf,buf.buf)
	if buf.dealloc != nil {buf.dealloc()} // deallocate the old slice
	buf.buf = newBuf
	buf.dealloc = newDealloc
	return nil
}
// return all the bytes written to the buffer
func (buf *Buffer) Bytes() []byte { return buf.buf[:buf.length] }
func (buf *Buffer) Len() int { return buf.length }

// Write appends b to the buffer. Grows if necessary. Implements io.Writer
func (buf *Buffer) Write(b []byte) (n int, err error) {
	needed := buf.length + len(b) // the exact buffer capacity needed

	// if the capacity of the buffer smaller than the needed capacity, expand the size by needed
	if len(buf.buf) < needed {
		err := buf.expand(needed)
		if err != nil { return 0,err }
	}

	n = copy(buf.buf[buf.length:], b) // copy bytes to the buffer
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
	n = copy(b, buf.buf[buf.off:buf.length])

	buf.off += n // increase the offset by bytes read

	// reset offsets if all data is read
	if buf.off >= buf.length { buf.Reset() }

	return n, nil
}

// Reset clears the buffer content without deallocating memory.
func (buf *Buffer) Reset() {
	ZeroBytes(buf.buf)
	buf.length = 0
	buf.off = 0
}

// Dealloc deallocates the underlying buffer.
func (buf *Buffer) Dealloc() error {
	if buf == nil {return nil}
	if buf.dealloc != nil {
		buf.dealloc();
	}
	buf.buf = nil
	buf.length = 0
	buf.off = 0
	return nil
}
