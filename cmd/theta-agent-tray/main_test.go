package main

import (
	"bytes"
	"runtime"
	"testing"
)

// pngToIco wraps a PNG in a Windows ICO with BMP (not PNG-compressed) entries,
// because LoadImage cannot read PNG-in-ICO. Verify the container is well-formed
// and every entry's DIB is a valid 32bpp bitmap with an AND mask.
func TestPNGToIco(t *testing.T) {
	ico := pngToIco(iconGreen)
	if len(ico) < 6+16 {
		t.Fatal("ico too short")
	}

	// ICONDIR
	if ico[0] != 0 || ico[1] != 0 {
		t.Errorf("reserved must be 0")
	}
	if ico[2] != 1 || ico[3] != 0 {
		t.Errorf("type must be 1 (icon)")
	}
	count := int(ico[4]) | int(ico[5])<<8
	if count != len(iconSizes) {
		t.Fatalf("expected %d icon entries, got %d", len(iconSizes), count)
	}

	// Each ICONDIRENTRY: valid size, planes=1, bpp=32, DIB with BITMAPINFOHEADER.
	for i := 0; i < count; i++ {
		e := 6 + i*16
		w := int(ico[e])
		h := int(ico[e+1])
		if w == 0 {
			w = 256
		}
		if h == 0 {
			h = 256
		}
		if w != iconSizes[i] || h != iconSizes[i] {
			t.Errorf("entry %d: encoded size %dx%d, want %dx%d", i, w, h, iconSizes[i], iconSizes[i])
		}
		planes := int(ico[e+4]) | int(ico[e+5])<<8
		bpp := int(ico[e+6]) | int(ico[e+7])<<8
		size := int(ico[e+8]) | int(ico[e+9])<<8 | int(ico[e+10])<<16 | int(ico[e+11])<<24
		offset := int(ico[e+12]) | int(ico[e+13])<<8 | int(ico[e+14])<<16 | int(ico[e+15])<<24

		if planes != 1 || bpp != 32 {
			t.Errorf("entry %d: want planes=1 bpp=32, got %d/%d", i, planes, bpp)
		}
		if offset+size > len(ico) {
			t.Fatalf("entry %d: DIB out of range", i)
		}

		dib := ico[offset : offset+size]
		// BITMAPINFOHEADER: biSize=40, biHeight = 2x for XOR+AND.
		biSize := int(dib[0]) | int(dib[1])<<8 | int(dib[2])<<16 | int(dib[3])<<24
		biW := int(dib[4]) | int(dib[5])<<8 | int(dib[6])<<16 | int(dib[7])<<24
		biH := int(dib[8]) | int(dib[9])<<8 | int(dib[10])<<16 | int(dib[11])<<24
		if biSize != 40 {
			t.Errorf("entry %d: expected BITMAPINFOHEADER (40), got %d", i, biSize)
		}
		if biW != w || biH != h*2 {
			t.Errorf("entry %d: DIB dims %dx%d, want %dx%d", i, biW, biH, w, h*2)
		}
	}
}

// toWindowsIcon passes the PNG through untouched on non-Windows and returns an
// ICO on Windows (whose validity TestPNGToIco covers).
func TestToWindowsIcon(t *testing.T) {
	pngMagic := []byte{0x89, 'P', 'N', 'G'}
	if runtime.GOOS == "windows" {
		if bytes.HasPrefix(toWindowsIcon(iconRed), pngMagic) {
			t.Error("windows must not receive a raw PNG")
		}
	} else {
		if !bytes.HasPrefix(toWindowsIcon(iconRed), pngMagic) {
			t.Error("non-windows must receive the PNG unchanged")
		}
	}
}

