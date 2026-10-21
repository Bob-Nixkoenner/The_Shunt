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
func Icon(l Level) []byte { return IconN(l, 0) }

// IconN is Icon with the number of active tunnels as a badge (1-9, more
// show 9; none: no badge, the glyph keeps its full size).
func IconN(l Level, active int) []byte {
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
	// glyph: a line that branches off ("shunt"), as in the UI logo; with a
	// badge it moves up and left to make room
	sc, ox, oy := 1.0, 0.0, 0.0
	if active > 0 {
		sc, ox, oy = 0.72, 2, -3
	}
	g := func(x0, y0, x1, y1 float64) { line(img, x0*sc+ox, y0*sc+oy, x1*sc+ox, y1*sc+oy, 5*sc+0.8, white) }
	g(12, 44, 26, 44)
	g(26, 44, 38, 22)
	g(38, 22, 52, 22)
	g(26, 44, 52, 44)
	if active > 0 {
		badge(img, min(active, 9))
	}
	var b bytes.Buffer
	_ = png.Encode(&b, img)
	return b.Bytes()
}

// badge draws the digit n on a dark disc in the lower right corner.
func badge(img *image.RGBA, n int) {
	const cx, cy, r = 43.0, 43.0, 15.5
	dark := color.RGBA{0x0d, 0x11, 0x17, 0xff}
	white := color.RGBA{0xff, 0xff, 0xff, 0xff}
	b := img.Bounds()
	for y := b.Min.Y; y < b.Max.Y; y++ {
		for x := b.Min.X; x < b.Max.X; x++ {
			if a := clamp(r - math.Hypot(float64(x)-cx, float64(y)-cy) + 0.5); a > 0 {
				o := img.RGBAAt(x, y)
				mix := func(fg, bg uint8) uint8 { return uint8(float64(fg)*a + float64(bg)*(1-a)) }
				img.SetRGBA(x, y, color.RGBA{mix(dark.R, o.R), mix(dark.G, o.G), mix(dark.B, o.B), uint8(math.Max(float64(o.A), a*255))})
			}
		}
	}
	// seven segments a-g in a box of 12 x 20 around the middle of the disc
	const w, h = 9.0, 17.0
	x0, y0 := cx-w/2, cy-h/2
	pt := map[byte][4]float64{
		'a': {x0, y0, x0 + w, y0},
		'b': {x0 + w, y0, x0 + w, y0 + h/2},
		'c': {x0 + w, y0 + h/2, x0 + w, y0 + h},
		'd': {x0, y0 + h, x0 + w, y0 + h},
		'e': {x0, y0 + h/2, x0, y0 + h},
		'f': {x0, y0, x0, y0 + h/2},
		'g': {x0, y0 + h/2, x0 + w, y0 + h/2},
	}
	for _, sg := range []byte(digitSegments[n]) {
		p := pt[sg]
		line(img, p[0], p[1], p[2], p[3], 3.2, white)
	}
}

var digitSegments = [10]string{"abcdef", "bc", "abdeg", "abcdg", "bcfg", "acdfg", "acdefg", "abc", "abcdefg", "abcdfg"}

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
