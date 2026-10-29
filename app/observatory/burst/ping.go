package burst

import (
	"context"
	"io"
	"net/http"
	"syscall"
	"time"

	"github.com/xtls/xray-core/common/net"
	"github.com/xtls/xray-core/common/utils"
	"github.com/xtls/xray-core/features/routing"
	"github.com/xtls/xray-core/transport/internet"
	"github.com/xtls/xray-core/transport/internet/tagged"
)

// directPingTransport matches net/http.DefaultTransport (30s dial, 30s
// keep-alive, nil TLSClientConfig, HTTP/2 still attempted). DialContext is
// not the default dialer: Control runs ApplyDialerControllers. A protect
// error fails this dial. It is not retried on http.DefaultTransport.
var directPingTransport = newProtectedHTTPTransport()

func newProtectedHTTPTransport() *http.Transport {
	dialer := &net.Dialer{
		Timeout:   30 * time.Second,
		KeepAlive: 30 * time.Second,
		Control: func(network, address string, c syscall.RawConn) error {
			return internet.ApplyDialerControllers(network, address, c)
		},
	}
	return &http.Transport{
		Proxy:                 http.ProxyFromEnvironment,
		DialContext:           dialer.DialContext,
		ForceAttemptHTTP2:     true,
		MaxIdleConns:          100,
		IdleConnTimeout:       90 * time.Second,
		TLSHandshakeTimeout:   10 * time.Second,
		ExpectContinueTimeout: 1 * time.Second,
	}
}

type pingClient struct {
	destination string
	httpClient  *http.Client
}

func newPingClient(ctx context.Context, dispatcher routing.Dispatcher, destination string, timeout time.Duration, handler string) *pingClient {
	return &pingClient{
		destination: destination,
		httpClient:  newHTTPClient(ctx, dispatcher, handler, timeout),
	}
}

func newDirectPingClient(destination string, timeout time.Duration) *pingClient {
	return &pingClient{
		destination: destination,
		httpClient: &http.Client{
			Timeout:   timeout,
			Transport: directPingTransport,
		},
	}
}

func newHTTPClient(ctxv context.Context, dispatcher routing.Dispatcher, handler string, timeout time.Duration) *http.Client {
	tr := &http.Transport{
		DisableKeepAlives: true,
		DialContext: func(ctx context.Context, network, addr string) (net.Conn, error) {
			dest, err := net.ParseDestination(network + ":" + addr)
			if err != nil {
				return nil, err
			}
			return tagged.Dialer(ctxv, dispatcher, dest, handler)
		},
	}
	return &http.Client{
		Transport: tr,
		Timeout:   timeout,
		// don't follow redirect
		CheckRedirect: func(req *http.Request, via []*http.Request) error {
			return http.ErrUseLastResponse
		},
	}
}

// MeasureDelay returns the delay time of the request to dest
func (s *pingClient) MeasureDelay(httpMethod string) (time.Duration, error) {
	if s.httpClient == nil {
		panic("pingClient not initialized")
	}

	req, err := http.NewRequest(httpMethod, s.destination, nil)
	if err != nil {
		return rttFailed, err
	}
	utils.TryDefaultHeadersWith(req.Header, "nav")

	start := time.Now()
	resp, err := s.httpClient.Do(req)
	if err != nil {
		return rttFailed, err
	}
	if httpMethod == http.MethodGet {
		_, err = io.Copy(io.Discard, resp.Body)
		if err != nil {
			return rttFailed, err
		}
	}
	resp.Body.Close()

	return time.Since(start), nil
}
