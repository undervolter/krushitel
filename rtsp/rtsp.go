package rtsp

import (
	"errors"
	"fmt"
	"net/url"
	"time"

	"github.com/bluenviron/gortsplib/v5"
	"github.com/bluenviron/gortsplib/v5/pkg/base"
	"github.com/bluenviron/gortsplib/v5/pkg/description"
	"github.com/bluenviron/gortsplib/v5/pkg/format"
	"github.com/pion/rtp"
)

var (
	ErrNoVideoTrack = errors.New("rtsp: H264/H265-трек не обнаружен в SDP")
	ErrTimeout      = errors.New("rtsp: таймаут ожидания декодированного кадра")
)

// Snapshot — RTSP-снап: перебираем сабстримы (1 → 0), ищем H264/H265-трек,
// читаем RTP через gortsplib, декодируем первый кадр libavcodec'ом (cgo)
// и кодируем в JPEG.
func Snapshot(addr, user, pass string, timeout time.Duration) ([]byte, error) {
	var lastErr error
	for _, subtype := range []int{1, 0} {
		// креды НИКОГДА не конкатенируем в строку URL: пароль с '?'/@/':
		// ломает парсер (первый '?' отрезается как query ещё до authority).
		// url.UserPassword экранирует userinfo как положено.
		u, err := base.ParseURL(fmt.Sprintf("rtsp://%s/cam/realmonitor?channel=1&subtype=%d", addr, subtype))
		if err != nil {
			return nil, err
		}
		u.User = url.UserPassword(user, pass)

		data, err := snapshotSub(u, timeout)
		if err == nil {
			return data, nil
		}
		lastErr = err
	}
	if lastErr == nil {
		lastErr = errors.New("rtsp: не удалось")
	}
	return nil, lastErr
}

// rtpADecoder — общий интерфейс RTP-депакетизаторов H264/HEVC: Decode
// возвращает NAL-юниты (без Annex-B старт-кодов) собранного доступ-юнита.
type rtpADecoder interface {
	Decode(*rtp.Packet) ([][]byte, error)
}

func snapshotSub(u *base.URL, timeout time.Duration) ([]byte, error) {
	proto := gortsplib.ProtocolTCP
	c := &gortsplib.Client{
		Scheme:       u.Scheme,
		Host:         u.Host,
		ReadTimeout:  timeout,
		WriteTimeout: timeout,
		Protocol:     &proto,
		// дефолтный хендлер gortsplib логирует "N RTP packets lost" через
		// стандартный log — а тот в TUI уходит в ленту прогона. Для снапа
		// потери RTP (пропуски sequence number, обычно камера дропает
		// кадры) — шум, глушим
		OnPacketsLost: func(uint64) {},
	}

	if err := c.Start(); err != nil {
		return nil, err
	}
	// порядок закрытия важен: СНАЧАЛА c.Close() (останавливает RTP-горутину),
	// ПОТОМ jdec.close() — иначе callback может дернуть feed() по уже
	// освобожденному декодеру (nil deref / use-after-free на cgo)
	var jdec *jpegDecoder
	defer func() {
		c.Close()
		if jdec != nil {
			jdec.close()
		}
	}()

	session, _, err := c.Describe(u)
	if err != nil {
		return nil, err
	}

	// ищем H264 или H265 трек; параметр-сеты из SDP пойдут преамбулой
	var (
		media   *description.Media
		rtpFmt  format.Format
		rtpDec  rtpADecoder
		codec   string
		params  [][]byte // Annex-B: [VPS] SPS PPS
	)

	for _, m := range session.Medias {
		for _, f := range m.Formats {
			switch ff := f.(type) {
			case *format.H264:
				media, rtpFmt, codec = m, ff, "h264"
				if ff.SPS != nil {
					params = append(params, annexb(ff.SPS))
				}
				if ff.PPS != nil {
					params = append(params, annexb(ff.PPS))
				}
			case *format.H265:
				media, rtpFmt, codec = m, ff, "hevc"
				if ff.VPS != nil {
					params = append(params, annexb(ff.VPS))
				}
				if ff.SPS != nil {
					params = append(params, annexb(ff.SPS))
				}
				if ff.PPS != nil {
					params = append(params, annexb(ff.PPS))
				}
			}
			if media != nil {
				break
			}
		}
		if media != nil {
			break
		}
	}
	if media == nil {
		return nil, ErrNoVideoTrack
	}

	switch ff := rtpFmt.(type) {
	case *format.H264:
		rtpDec, err = ff.CreateDecoder()
	case *format.H265:
		rtpDec, err = ff.CreateDecoder()
	default:
		return nil, ErrNoVideoTrack
	}
	if err != nil {
		return nil, fmt.Errorf("create rtp decoder: %w", err)
	}

	jdec, err = newJPEGDecoder(codec)
	if err != nil {
		return nil, err
	}

	frameCh := make(chan []byte, 1)
	errCh := make(chan error, 1)
	sentParams := false

	_, err = c.Setup(session.BaseURL, media, 0, 0)
	if err != nil {
		return nil, err
	}

	c.OnPacketRTP(media, rtpFmt, func(pkt *rtp.Packet) {
		aus, err := rtpDec.Decode(pkt)
		if err != nil || len(aus) == 0 {
			return // ErrMorePacketsNeeded / битый пакет — не фатально
		}

		// первый AU: подкладываем параметр-сеты из SDP, чтобы декодер
		// стартовал даже если камера шлёт их только в SDP
		nalus := aus
		if !sentParams && len(params) > 0 {
			sentParams = true
			nalus = make([][]byte, 0, len(params)+len(aus))
			nalus = append(nalus, params...)
			nalus = append(nalus, aus...)
		}

		size := 4
		for _, n := range nalus {
			size += 4 + len(n)
		}
		au := make([]byte, 0, size)
		for _, n := range nalus {
			au = append(au, 0, 0, 0, 1)
			au = append(au, n...)
		}

		jpeg, err := jdec.feed(au)
		if err != nil {
			select {
			case errCh <- err:
			default:
			}
			return
		}
		if jpeg != nil {
			select {
			case frameCh <- jpeg:
			default:
			}
		}
	})

	_, err = c.Play(nil)
	if err != nil {
		return nil, err
	}

	select {
	case frame := <-frameCh:
		return frame, nil
	case <-time.After(timeout):
		// таймаут: если был декод — отдаём его ошибку, она информативнее
		select {
		case err := <-errCh:
			return nil, fmt.Errorf("rtsp: decode: %w", err)
		default:
			return nil, ErrTimeout
		}
	}
}

// annexb — NAL-юнит с Annex-B старт-кодом (00 00 00 01).
func annexb(nalu []byte) []byte {
	out := make([]byte, 4+len(nalu))
	out[0], out[1], out[2], out[3] = 0x00, 0x00, 0x00, 0x01
	copy(out[4:], nalu)
	return out
}
