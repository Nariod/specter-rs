// Wire packer — port of the AdaptixC2 native `beacon_agent` pl_packer.go
// (tag v1.2), restricted to the kinds specter-rs uses. The beacon's Rust
// writer/reader (crates/core/src/wire.rs) is byte-compatible with this;
// docs/WIRE.md is the contract.
package main

import (
	"encoding/binary"
	"errors"
	"strings"
)

type Packer struct {
	buffer []byte
}

func CreatePacker(buffer []byte) *Packer {
	return &Packer{buffer: buffer}
}

// Size: bytes not yet parsed (the buffer shrinks as fields are read).
func (p *Packer) Size() uint {
	return uint(len(p.buffer))
}

// CheckPacker: can the remaining buffer satisfy the given field kinds?
func (p *Packer) CheckPacker(types []string) bool {
	packerSize := p.Size()
	for _, t := range types {
		switch t {
		case "byte":
			if packerSize < 1 {
				return false
			}
			packerSize -= 1
		case "word":
			if packerSize < 2 {
				return false
			}
			packerSize -= 2
		case "int":
			if packerSize < 4 {
				return false
			}
			packerSize -= 4
		case "long":
			if packerSize < 8 {
				return false
			}
			packerSize -= 8
		case "array":
			if packerSize < 4 {
				return false
			}
			index := p.Size() - packerSize
			length := uint(binary.BigEndian.Uint32(p.buffer[index : index+4]))
			packerSize -= 4
			if packerSize < length {
				return false
			}
			packerSize -= length
		}
	}
	return true
}

func (p *Packer) ParseInt8() uint8 {
	if len(p.buffer) < 1 {
		return 0
	}
	value := p.buffer[0]
	p.buffer = p.buffer[1:]
	return value
}

func (p *Packer) ParseInt16() uint16 {
	if len(p.buffer) < 2 {
		return 0
	}
	value := binary.BigEndian.Uint16(p.buffer[:2])
	p.buffer = p.buffer[2:]
	return value
}

func (p *Packer) ParseInt32() uint {
	if len(p.buffer) < 4 {
		return 0
	}
	value := uint(binary.BigEndian.Uint32(p.buffer[:4]))
	p.buffer = p.buffer[4:]
	return value
}

func (p *Packer) ParseInt64() uint64 {
	if len(p.buffer) < 8 {
		return 0
	}
	value := binary.BigEndian.Uint64(p.buffer[:8])
	p.buffer = p.buffer[8:]
	return value
}

// ParseBytes: u32 BE length || bytes.
func (p *Packer) ParseBytes() []byte {
	size := p.ParseInt32()
	if p.Size() < size {
		return []byte{}
	}
	b := p.buffer[:size]
	p.buffer = p.buffer[size:]
	return b
}

// ParseString: same as ParseBytes, NUL-trimmed.
func (p *Packer) ParseString() string {
	size := p.ParseInt32()
	if p.Size() < size {
		return ""
	}
	b := p.buffer[:size]
	p.buffer = p.buffer[size:]
	return strings.TrimRight(string(b), "\x00")
}

// PackArray — server-side writing (tasks): []byte raw, string u32 LE
// length-including-NUL, int u32 LE, bool 1 byte.
func PackArray(array []interface{}) ([]byte, error) {
	var packData []byte
	for i := range array {
		switch v := array[i].(type) {
		case []byte:
			packData = append(packData, v...)
		case string:
			if len(v) != 0 && !strings.HasSuffix(v, "\x00") {
				v += "\x00"
			}
			size := make([]byte, 4)
			binary.LittleEndian.PutUint32(size, uint32(len(v)))
			packData = append(packData, size...)
			packData = append(packData, []byte(v)...)
		case int:
			num := make([]byte, 4)
			binary.LittleEndian.PutUint32(num, uint32(v))
			packData = append(packData, num...)
		case bool:
			b := []byte{0}
			if v {
				b[0] = 1
			}
			packData = append(packData, b...)
		default:
			return nil, errors.New("PackArray unknown type")
		}
	}
	return packData, nil
}
