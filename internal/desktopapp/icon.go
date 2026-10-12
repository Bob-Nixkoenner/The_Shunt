package desktopapp

import (
	"bytes"
	"image"
	"image/color"
	"image/png"
	"math"
)

// Icon draws the tray icon for a level: the Shunt "switch" glyph on a
// coloured disc. Drawn in code so no image files have to be shipped.
func Icon(l Level) []byte {
	const n = 64
	bg := map[Level]color.RGBA{
		OK:   {0x10, 0xb9, 0x81, 0xff},
		Warn: {0xf5, 0xb9, 0x42, 0xff},
		Bad:  {0xef, 0x44, 0x44, 0xff},
	}[l]
	img := image.NewRGBA(image.Rect(0, 0, n, n))
	c := float64(n-1) / 2
	for y := 0; y < n; y++ {
		for x := 0; x < n; x++ {
			d := math.Hypot(float64(x)-c, float64(y)-c)
			if a := clamp(c - d + 0.5); a > 0 { // anti-aliased disc edge
				img.SetRGBA(x, y, color.RGBA{bg.R, bg.G, bg.B, uint8(a * 255)})
			}
		}
	}
	white := color.RGBA{0xff, 0xff, 0xff, 0xff}
	// glyph: a line that branches off ("shunt"), as in the UI logo
	line(img, 12, 44, 26, 44, 5, white)
	line(img, 26, 44, 38, 22, 5, white)
	line(img, 38, 22, 52, 22, 5, white)
	line(img, 26, 44, 52, 44, 5, white)
	var b bytes.Buffer
	_ = png.Encode(&b, img)
	return b.Bytes()
}

func clamp(v float64) float64 { return math.Max(0, math.Min(1, v)) }

// line draws a thick anti-aliased segment.
func line(img *image.RGBA, x0, y0, x1, y1, w float64, col color.RGBA) {
	b := img.Bounds()
	for y := b.Min.Y; y < b.Max.Y; y++ {
		for x := b.Min.X; x < b.Max.X; x++ {
			px, py := float64(x), float64(y)
			dx, dy := x1-x0, y1-y0
			t := clamp(((px-x0)*dx + (py-y0)*dy) / (dx*dx + dy*dy))
			d := math.Hypot(px-(x0+t*dx), py-(y0+t*dy))
			a := clamp(w/2 - d + 0.5)
			if a <= 0 {
				continue
			}
			o := img.RGBAAt(x, y)
			blend := func(fg, bg uint8) uint8 { return uint8(float64(fg)*a + float64(bg)*(1-a)) }
			img.SetRGBA(x, y, color.RGBA{blend(col.R, o.R), blend(col.G, o.G), blend(col.B, o.B), uint8(math.Max(float64(o.A), a*255))})
		}
	}
}
