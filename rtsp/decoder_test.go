package rtsp

import (
	"bytes"
	"image/jpeg"
	"testing"

	"github.com/Eyevinn/hi264/pkg/frame"
	"github.com/gen2brain/h265/hevc"
)

func TestNewJPEGDecoder(t *testing.T) {
	// 1. Test H.264 decoder initialization
	h264Dec, err := newJPEGDecoder("h264")
	if err != nil {
		t.Fatalf("newJPEGDecoder(h264) failed: %v", err)
	}
	if h264Dec == nil || h264Dec.h264Dec == nil {
		t.Fatal("newJPEGDecoder(h264) returned nil decoder")
	}

	// Feed dummy data (should not crash, should return nil, nil until valid IDR)
	out, err := h264Dec.feed([]byte{0, 0, 0, 1, 0x05, 0x88})
	if err != nil {
		t.Fatalf("feed dummy h264 returned error: %v", err)
	}
	if out != nil {
		t.Fatal("expected nil output for incomplete dummy slice")
	}

	h264Dec.close()
	// Test idempotency of close
	h264Dec.close()
	out, err = h264Dec.feed([]byte{0, 0, 0, 1})
	if out != nil || err != nil {
		t.Fatalf("feed after close should return nil, nil: got %v, %v", out, err)
	}

	// 2. Test HEVC decoder initialization
	hevcDec, err := newJPEGDecoder("hevc")
	if err != nil {
		t.Fatalf("newJPEGDecoder(hevc) failed: %v", err)
	}
	if hevcDec == nil || hevcDec.hevcDec == nil {
		t.Fatal("newJPEGDecoder(hevc) returned nil decoder")
	}

	out, err = hevcDec.feed([]byte{0, 0, 0, 1, 0x01, 0x02})
	if err != nil {
		t.Fatalf("feed dummy hevc returned error: %v", err)
	}
	if out != nil {
		t.Fatal("expected nil output for incomplete dummy slice")
	}

	hevcDec.close()

	// 3. Test unsupported codec
	_, err = newJPEGDecoder("vp9")
	if err == nil {
		t.Fatal("expected error for unsupported codec vp9")
	}
}

func TestEncodeH264(t *testing.T) {
	w, h := 64, 48
	f := frame.NewFrame(w, h)
	for i := range f.Y {
		f.Y[i] = 128
	}
	for i := range f.Cb {
		f.Cb[i] = 128
		f.Cr[i] = 128
	}

	jpg, err := encodeH264(f)
	if err != nil {
		t.Fatalf("encodeH264 failed: %v", err)
	}
	if len(jpg) < 10 {
		t.Fatalf("jpeg output too small: %d bytes", len(jpg))
	}
	// Verify JPEG magic bytes (FF D8)
	if jpg[0] != 0xFF || jpg[1] != 0xD8 {
		t.Fatalf("invalid JPEG magic bytes: %x %x", jpg[0], jpg[1])
	}

	// Verify standard jpeg decoder can parse it
	cfg, err := jpeg.DecodeConfig(bytes.NewReader(jpg))
	if err != nil {
		t.Fatalf("jpeg.DecodeConfig failed: %v", err)
	}
	if cfg.Width != w || cfg.Height != h {
		t.Fatalf("dimensions mismatch: got %dx%d, want %dx%d", cfg.Width, cfg.Height, w, h)
	}
}

func TestEncodeHEVC(t *testing.T) {
	w, h := 64, 48
	pic := &hevc.Picture{
		Width:   w,
		Height:  h,
		Y:       make([]uint8, w*h),
		Cb:      make([]uint8, (w/2)*(h/2)),
		Cr:      make([]uint8, (w/2)*(h/2)),
		StrideY: w,
		StrideC: w / 2,
	}
	for i := range pic.Y {
		pic.Y[i] = 128
	}
	for i := range pic.Cb {
		pic.Cb[i] = 128
		pic.Cr[i] = 128
	}

	jpg, err := encodeHEVC(pic)
	if err != nil {
		t.Fatalf("encodeHEVC failed: %v", err)
	}
	if len(jpg) < 10 {
		t.Fatalf("jpeg output too small: %d bytes", len(jpg))
	}
	if jpg[0] != 0xFF || jpg[1] != 0xD8 {
		t.Fatalf("invalid JPEG magic bytes: %x %x", jpg[0], jpg[1])
	}

	cfg, err := jpeg.DecodeConfig(bytes.NewReader(jpg))
	if err != nil {
		t.Fatalf("jpeg.DecodeConfig failed: %v", err)
	}
	if cfg.Width != w || cfg.Height != h {
		t.Fatalf("dimensions mismatch: got %dx%d, want %dx%d", cfg.Width, cfg.Height, w, h)
	}
}
