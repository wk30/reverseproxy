package reverseproxy

import (
	"crypto/tls"
	"io"
	"log"
	"net"
	"net/http"
	"net/http/httputil"
	"net/url"
	"time"
)

const (
	defaultTimeout = time.Minute * 5
)

// ReverseProxy is an HTTP Handler that takes an incoming request and
// sends it to another server, proxying the response back to the
// client, support http, also support https tunnel using http.hijacker
type ReverseProxy struct {
	// Set the timeout of the proxy server, default is 5 minutes
	Timeout time.Duration

	*httputil.ReverseProxy
}

// NewReverseProxy returns a new ReverseProxy that routes
// URLs to the scheme, host, and base path provided in target. If the
// target's path is "/base" and the incoming request was for "/dir",
// the target request will be for /base/dir. if the target's query is a=10
// and the incoming request's query is b=100, the target's request's query
// will be a=10&b=100.
// NewReverseProxy does not rewrite the Host header.
// To rewrite Host headers, use ReverseProxy directly with a custom
// Director policy.
func NewReverseProxy(target *url.URL, tlsClientConfig *tls.Config) *ReverseProxy {
	p := httputil.NewSingleHostReverseProxy(target)

	if p.Transport == nil {
		p.Transport = http.DefaultTransport
	}

	if tlsClientConfig != nil {
		transport := p.Transport.(*http.Transport)
		transport.TLSClientConfig = tlsClientConfig
		p.Transport = transport
	}

	return &ReverseProxy{ReverseProxy: p}
}

func (p *ReverseProxy) logf(format string, args ...interface{}) {
	if p.ErrorLog != nil {
		p.ErrorLog.Printf(format, args...)
	} else {
		log.Printf(format, args...)
	}
}

func (p *ReverseProxy) ProxyHTTP(rw http.ResponseWriter, req *http.Request) {
	p.ReverseProxy.ServeHTTP(rw, req)
}

func (p *ReverseProxy) ProxyHTTPS(rw http.ResponseWriter, req *http.Request) {
	hij, ok := rw.(http.Hijacker)
	if !ok {
		p.logf("http server does not support hijacker")
		return
	}

	clientConn, _, err := hij.Hijack()
	if err != nil {
		p.logf("http: proxy error: %v", err)
		return
	}

	proxyConn, err := net.Dial("tcp", req.URL.Host)
	if err != nil {
		p.logf("http: proxy error: %v", err)
		return
	}

	// The returned net.Conn may have read or write deadlines
	// already set, depending on the configuration of the
	// Server, to set or clear those deadlines as needed
	// we set timeout to 5 minutes
	deadline := time.Now()
	if p.Timeout == 0 {
		deadline = deadline.Add(defaultTimeout)
	} else {
		deadline = deadline.Add(p.Timeout)
	}

	err = clientConn.SetDeadline(deadline)
	if err != nil {
		p.logf("http: proxy error: %v", err)
		return
	}

	err = proxyConn.SetDeadline(deadline)
	if err != nil {
		p.logf("http: proxy error: %v", err)
		return
	}

	_, err = clientConn.Write([]byte("HTTP/1.0 200 OK\r\n\r\n"))
	if err != nil {
		p.logf("http: proxy error: %v", err)
		return
	}

	go func() {
		io.Copy(clientConn, proxyConn)
		clientConn.Close()
		proxyConn.Close()
	}()

	io.Copy(proxyConn, clientConn)
	proxyConn.Close()
	clientConn.Close()
}

func (p *ReverseProxy) ServeHTTP(rw http.ResponseWriter, req *http.Request) {
	if req.Method == "CONNECT" {
		p.ProxyHTTPS(rw, req)
	} else {
		p.ProxyHTTP(rw, req)
	}
}
