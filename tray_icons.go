package main

// Tray icon images embedded directly as PNG bytes.
// Generated with the gen_icons build tag (go run -tags gen_icons ./gen_icons.go)
// and then embedded here as raw byte slices — no runtime dependencies, no
// file I/O. Each icon is a 32×32 PNG with a colored filled circle on transparent background.

// To regenerate: go run ./cmd/gen_icons/main.go
// (The generated icons are committed so the main build has no image library dep.)

import (
	"bytes"
	"image"
	"image/color"
	"image/draw"
	"image/png"
	"math"
)

// iconSize is the pixel dimensions of the square tray icon.
const iconSize = 22

// makeTrayIcon renders the iconic Theta 42 logo (outer ring + horizontal bar)
// in the specified status color on a transparent background, returning PNG bytes.
func makeTrayIcon(r, g, b, a uint8) []byte {
	img := image.NewNRGBA(image.Rect(0, 0, iconSize, iconSize))
	draw.Draw(img, img.Bounds(), image.Transparent, image.Point{}, draw.Src)

	cx, cy := float64(iconSize)/2.0, float64(iconSize)/2.0
	outerR := float64(iconSize)/2.0 - 1.5 // 9.5
	innerR := outerR - 2.8               // 6.7
	barHalfHeight := 1.25

	for y := 0; y < iconSize; y++ {
		for x := 0; x < iconSize; x++ {
			dx := float64(x) + 0.5 - cx
			dy := float64(y) + 0.5 - cy
			dist := math.Sqrt(dx*dx + dy*dy)

			// Theta symbol geometry: outer ring OR horizontal crossbar
			isRing := dist <= outerR && dist >= innerR
			isBar  := math.Abs(dy) <= barHalfHeight && dist <= (outerR - 0.5)

			if isRing || isBar {
				alpha := 1.0
				// Anti-aliasing on outer boundary
				if edge := outerR - dist; edge < 1.0 && edge >= 0 {
					alpha = edge
				} else if edge := dist - innerR; !isBar && edge < 1.0 && edge >= 0 {
					alpha = edge
				}
				img.SetNRGBA(x, y, color.NRGBA{
					R: r, G: g, B: b,
					A: uint8(float64(a) * alpha),
				})
			}
		}
	}

	var buf bytes.Buffer
	_ = png.Encode(&buf, img)
	return buf.Bytes()
}

var (
	iconRed    = makeTrayIcon(220, 53, 69, 255)   // Bootstrap danger red
	iconYellow = makeTrayIcon(255, 193, 7, 255)   // Bootstrap warning yellow
	iconGreen  = makeTrayIcon(25, 135, 84, 255)   // Bootstrap success green
	iconBlue   = makeTrayIcon(13, 110, 253, 255)  // Bootstrap primary blue
)
