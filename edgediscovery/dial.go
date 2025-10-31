package edgediscovery

import (
	"context"
	"crypto/tls"
	"net"
	"net/url"
	"os"
	"time"

	"github.com/pkg/errors"
	"golang.org/x/net/proxy"
)

// DialEdge makes a TLS connection to a Cloudflare edge node
func DialEdge(
	ctx context.Context,
	timeout time.Duration,
	tlsConfig *tls.Config,
	edgeTCPAddr *net.TCPAddr,
	localIP net.IP,
) (net.Conn, error) {
	dialer := net.Dialer{}
	if localIP != nil {
		dialer.LocalAddr = &net.TCPAddr{IP: localIP, Port: 0}
	}

	var proxyDialer proxy.Dialer

	// 优先使用自定义环境变量 TUNNEL_PROXY
	// 这样只有隧道程序会使用代理，不影响其他工具
	tunnelProxy := os.Getenv("TUNNEL_PROXY")
	if tunnelProxy == "" {
		// 降级到标准环境变量（可选，如果不想支持可以删除这部分）
		tunnelProxy = os.Getenv("ALL_PROXY")
	}

	if tunnelProxy != "" {
		// 解析代理 URL
		proxyURL, err := url.Parse(tunnelProxy)
		if err != nil {
			return nil, newDialError(err, "Invalid TUNNEL_PROXY URL")
		}
		proxyDialer, err = proxy.FromURL(proxyURL, &dialer)
		if err != nil {
			return nil, newDialError(err, "Failed to create proxy dialer")
		}
	} else {
		// 没有设置代理，直接使用普通 dialer
		proxyDialer = &dialer
	}

	// Inherit from parent context so we can cancel (Ctrl-C) while dialing
	dialCtx, dialCancel := context.WithTimeout(ctx, timeout)
	defer dialCancel()

	var edgeConn net.Conn
	var err error

	// 尝试使用支持 context 的 DialContext
	if contextDialer, ok := proxyDialer.(interface {
		DialContext(context.Context, string, string) (net.Conn, error)
	}); ok {
		edgeConn, err = contextDialer.DialContext(dialCtx, "tcp", edgeTCPAddr.String())
	} else {
		// 降级到普通 Dial
		edgeConn, err = proxyDialer.Dial("tcp", edgeTCPAddr.String())
	}

	if err != nil {
		return nil, newDialError(err, "DialContext error")
	}

	tlsEdgeConn := tls.Client(edgeConn, tlsConfig)
	tlsEdgeConn.SetDeadline(time.Now().Add(timeout))

	if err = tlsEdgeConn.Handshake(); err != nil {
		edgeConn.Close() // 清理连接
		return nil, newDialError(err, "TLS handshake with edge error")
	}

	// clear the deadline on the conn; http2 has its own timeouts
	tlsEdgeConn.SetDeadline(time.Time{})
	return tlsEdgeConn, nil
}

// DialError is an error returned from DialEdge
type DialError struct {
	cause error
}

func newDialError(err error, message string) error {
	return DialError{cause: errors.Wrap(err, message)}
}

func (e DialError) Error() string {
	return e.cause.Error()
}

func (e DialError) Cause() error {
	return e.cause
}
