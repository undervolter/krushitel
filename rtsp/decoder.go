// decoder.go — декодирование H264/H265 и кодирование в JPEG через libavcodec
// (cgo, go-astiav, ffmpeg n8.0). Работает поверх доступ-юнитов из gortsplib:
// депакетизатор отдаёт NAL-юниты, мы собираем Annex-B и скармливаем
// декодеру напрямую, без демуксеров и файлов.

package rtsp

import (
	"errors"
	"fmt"
	"sync/atomic"

	"github.com/asticode/go-astiav"
)

func init() {
	// libav-log НЕ должен попадать в stderr: TUI живёт на altscreen, и
	// любая строка от av_log ("no frame!", "invalid NAL unit" и т.п.)
	// сдвигает консоль и рвёт кадр bubbletea в клочья. QUIET + пустой
	// колбэк = ноль вывода из libav, ошибки декодирования мы и так
	// проглатываем сами.
	astiav.SetLogLevel(astiav.LogLevelQuiet)
	astiav.SetLogCallback(func(astiav.Classer, astiav.LogLevel, string, string) {})
}

// jpegDecoder — H264/HEVC → пиксели → YUVJ420P → MJPEG (JPEG-байты).
// Кодировщик и sws инициализируются лениво — когда известны размеры кадра.
type jpegDecoder struct {
	decCC    *astiav.CodecContext
	decFrame *astiav.Frame
	pkt      *astiav.Packet

	encCC  *astiav.CodecContext
	encPkt *astiav.Packet
	dst    *astiav.Frame
	sws    *astiav.SoftwareScaleContext

	// closed — guard против гонки с RTP-горутиной: после close() любые
	// вызовы feed/encode не трогают cgo-объекты
	closed atomic.Bool
}

func newJPEGDecoder(codec string) (*jpegDecoder, error) {
	c := astiav.FindDecoderByName(codec)
	if c == nil {
		return nil, fmt.Errorf("astiav: декодер %q не найден в libavcodec", codec)
	}
	d := &jpegDecoder{
		decCC:    astiav.AllocCodecContext(c),
		decFrame: astiav.AllocFrame(),
		pkt:      astiav.AllocPacket(),
	}
	if d.decCC == nil || d.decFrame == nil || d.pkt == nil {
		d.close()
		return nil, errors.New("astiav: аллокация codec context вернула nil")
	}
	// один тред на декодер: для снапа (один кадр) многопоточность не даёт
	// ничего, а референс-буферы тредов раздували RAM в ~10 раз — при 30
	// параллельных декодерах это гигабайты впустую
	d.decCC.SetThreadCount(1)
	if err := d.decCC.Open(c, nil); err != nil {
		d.close()
		return nil, fmt.Errorf("astiav: open %s decoder: %w", codec, err)
	}
	return d, nil
}

func (d *jpegDecoder) close() {
	d.closed.Store(true)
	if d.pkt != nil {
		d.pkt.Free()
		d.pkt = nil
	}
	if d.decFrame != nil {
		d.decFrame.Free()
		d.decFrame = nil
	}
	if d.decCC != nil {
		d.decCC.Free()
		d.decCC = nil
	}
	if d.encPkt != nil {
		d.encPkt.Free()
		d.encPkt = nil
	}
	if d.dst != nil {
		d.dst.Free()
		d.dst = nil
	}
	if d.sws != nil {
		d.sws.Free()
		d.sws = nil
	}
	if d.encCC != nil {
		d.encCC.Free()
		d.encCC = nil
	}
}

// feed — один доступ-юнит в Annex-B. Возвращает JPEG, когда кадр декодирован.
// До первого ключевого кадра декодер держит EAGAIN — возвращаем nil, nil.
// Ошибка на отдельном AU не фатальна для снапа — ждём следующий.
func (d *jpegDecoder) feed(au []byte) ([]byte, error) {
	if d.closed.Load() || d.pkt == nil {
		return nil, nil
	}
	if len(au) == 0 {
		return nil, nil
	}
	if err := d.pkt.FromData(au); err != nil {
		return nil, fmt.Errorf("astiav: packet: %w", err)
	}
	if err := d.decCC.SendPacket(d.pkt); err != nil {
		d.pkt.Unref()
		return nil, nil
	}
	d.pkt.Unref()

	for {
		err := d.decCC.ReceiveFrame(d.decFrame)
		if err != nil {
			return nil, nil
		}
		jpeg, err := d.encode(d.decFrame)
		d.decFrame.Unref()
		if err != nil || jpeg != nil {
			return jpeg, err
		}
	}
}

// encode — конвертация кадра в YUVJ420P (sws) и сжатие mjpeg-энкодером.
func (d *jpegDecoder) encode(f *astiav.Frame) ([]byte, error) {
	if f.Width() <= 0 || f.Height() <= 0 {
		return nil, nil
	}
	if d.encCC == nil {
		if err := d.initEncoder(f); err != nil {
			return nil, err
		}
	}
	if err := d.sws.ScaleFrame(f, d.dst); err != nil {
		return nil, fmt.Errorf("astiav: sws_scale_frame: %w", err)
	}
	d.dst.SetPts(f.Pts())
	if err := d.encCC.SendFrame(d.dst); err != nil {
		return nil, fmt.Errorf("astiav: encoder send: %w", err)
	}
	for {
		err := d.encCC.ReceivePacket(d.encPkt)
		if err != nil {
			return nil, nil
		}
		out := make([]byte, d.encPkt.Size())
		copy(out, d.encPkt.Data())
		d.encPkt.Unref()
		if len(out) > 0 {
			return out, nil
		}
	}
}

func (d *jpegDecoder) initEncoder(f *astiav.Frame) error {
	c := astiav.FindEncoder(astiav.CodecIDMjpeg)
	if c == nil {
		return errors.New("astiav: mjpeg-энкодер не найден в libavcodec")
	}
	d.encCC = astiav.AllocCodecContext(c)
	d.encCC.SetPixelFormat(astiav.PixelFormatYuvj420P)
	d.encCC.SetWidth(f.Width())
	d.encCC.SetHeight(f.Height())
	d.encCC.SetTimeBase(astiav.NewRational(1, 1))
	if err := d.encCC.Open(c, nil); err != nil {
		return fmt.Errorf("astiav: open mjpeg encoder: %w", err)
	}
	var err error
	d.sws, err = astiav.CreateSoftwareScaleContext(
		f.Width(), f.Height(), f.PixelFormat(),
		f.Width(), f.Height(), astiav.PixelFormatYuvj420P,
		astiav.NewSoftwareScaleContextFlags(astiav.SoftwareScaleContextFlagBicubic),
	)
	if err != nil {
		return fmt.Errorf("astiav: sws: %w", err)
	}
	d.dst = astiav.AllocFrame()
	d.encPkt = astiav.AllocPacket()
	return nil
}
