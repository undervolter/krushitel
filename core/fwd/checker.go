package fwd

import (
	"context"
	"fmt"
	"math/rand"
	"strings"
	"sync"
	"time"
)

var checkReadTimeout = 8 * time.Second

// VerifyDevice проверяет, отвечает ли серийник, до подъёма туннеля.
//
// ctx обязателен и не декоративен: функция блокируется в чтениях облака, и без
// отменяемого контекста она висела до 16 секунд на серийник вслепую — /stop и
// Ctrl+C не могли её прервать.
func VerifyDevice(ctx context.Context, serial string, logf func(string, ...any)) (bool, bool, error) {
	return verifyDeviceOn(ctx, serial, smartpssProfile.mainServer, smartpssProfile.mainPort, smartpssProfile, logf)
}

func verifyDeviceOn(ctx context.Context, serial, host string, port int, prof *appProfile, logf func(string, ...any)) (bool, bool, error) {
	if prof == nil {
		prof = smartpssProfile
	}
	if logf == nil {
		logf = func(string, ...any) {}
	}
	if ctx == nil {
		ctx = context.Background()
	}
	if err := ctx.Err(); err != nil {
		return false, false, err
	}
	u := NewUDP(host, port, false, prof)
	defer u.Close()
	if u.initErr != nil {
		return false, false, fmt.Errorf("verify socket: %w", u.initErr)
	}

	u.RequestEx(prof.warmupPath, "", prof.warmupAuth, true, reqOpts{warmup: true})

	res, err := u.RequestEx(fmt.Sprintf("/online/p2psrv/%s", serial), "", true, true, reqOpts{})
	if err != nil {
		if strings.Contains(err.Error(), "404") {
			return false, false, nil
		}
		return false, false, fmt.Errorf("verify p2psrv silent: %w", err)
	}
	if res == nil {
		return false, false, fmt.Errorf("verify p2psrv: empty response")
	}
	if res.Code == 404 {
		return false, false, nil
	}
	if res.Body["body/US"] == "" {
		return false, false, fmt.Errorf("verify p2psrv: no route (US empty)")
	}

	aid := make([]byte, 8)
	rand.Read(aid)
	xchg := newChannelSender(u, serial, prof, 0, "", "", "", u.lport, 37777, aid)
	xchg.send(false)

	var ack *DHResponse
	if prof.channelRetransmit {
		ack = waitChannelEarlyAck(u, xchg, logf, channelAckWindow)
	}
	if ack == nil {
		var rerr error
		ack, rerr = u.ReadCtx(ctx, true, checkReadTimeout)
		if rerr == nil && ack.Code < 200 {
			ack, rerr = u.ReadCtx(ctx, true, checkReadTimeout)
		}
		if rerr != nil {
			if cerr := ctx.Err(); cerr != nil {
				return false, false, cerr
			}
			return false, false, fmt.Errorf("verify channel silent: %w", rerr)
		}
	}
	if err := ctx.Err(); err != nil {
		return false, false, err
	}
	if ack.Code == 404 {
		return false, false, nil
	}
	if ack.Code == 401 || ack.Code == 403 {
		return true, true, nil
	}
	if ack.Code >= 400 {
		return false, false, fmt.Errorf("verify channel: code=%d %s", ack.Code, ack.Status)
	}
	return true, false, nil
}

func CheckSerials(ctx context.Context, serials []string, concurrency int, onResult func(serial string, alive, needsAuth bool, err error)) {
	checkSerialsOn(ctx, serials, concurrency, smartpssProfile.mainServer, smartpssProfile.mainPort, onResult)
}

func checkSerialsOn(ctx context.Context, serials []string, concurrency int, host string, port int, onResult func(serial string, alive, needsAuth bool, err error)) {
	if concurrency < 1 {
		concurrency = 32
	}
	sem := make(chan struct{}, concurrency)
	var wg sync.WaitGroup
	for _, sn := range serials {
		if ctx.Err() != nil {
			break
		}
		sem <- struct{}{}
		wg.Add(1)
		go func(serial string) {
			defer wg.Done()
			defer func() { <-sem }()
			select {
			case <-ctx.Done():
				return
			case <-time.After(time.Duration(rand.Intn(50)) * time.Millisecond):
			}
			alive, needsAuth, err := verifyDeviceOn(ctx, serial, host, port, smartpssProfile, nil)
			onResult(serial, alive, needsAuth, err)
		}(sn)
	}
	wg.Wait()
}
