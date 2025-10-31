package edgediscovery

import (
	"context"
	"crypto/tls"
	"fmt"
	"net"
	"net/url"
	"os"
	"strings"
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

	// 获取代理配置
	tunnelProxy := os.Getenv("TUNNEL_PROXY")
	if tunnelProxy == "" {
		tunnelProxy = os.Getenv("ALL_PROXY")
	}

	// 解析多个代理地址（只使用空格分隔）
	var proxyList []string
	if tunnelProxy != "" {
		proxies := strings.Fields(tunnelProxy) // 自动处理多个空格和 trim
		for _, p := range proxies {
			if p != "" {
				proxyList = append(proxyList, p)
			}
		}
	}

	// 如果没有代理，直接使用普通 dialer
	if len(proxyList) == 0 {
		fmt.Println("No proxy configured, connecting directly...")
		conn, err := dialWithDialer(&dialer, ctx, timeout, tlsConfig, edgeTCPAddr)
		if err != nil {
			fmt.Printf("❌ Direct connection failed: %v\n", err)
			return nil, err
		}
		fmt.Println("✅ Direct connection successful")
		return conn, nil
	}

	fmt.Printf("Found %d proxy(s), starting rotation...\n", len(proxyList))

	// 持续轮询尝试每个代理，直到成功或 context 取消
	proxyIndex := 0
	attemptCount := 0
	roundCount := 0
	for {
		// 检查 context 是否已取消
		select {
		case <-ctx.Done():
			fmt.Printf("❌ Context cancelled after %d attempts (%d rounds)\n", attemptCount, roundCount)
			return nil, newDialError(ctx.Err(), fmt.Sprintf("Context cancelled after %d attempts", attemptCount))
		default:
		}

		// 新一轮开始
		if proxyIndex == 0 && attemptCount > 0 {
			roundCount++
			fmt.Printf("\n--- Round %d ---\n", roundCount)
		}

		proxyAddr := proxyList[proxyIndex]
		attemptCount++

		// 隐藏密码显示（安全考虑）
		displayAddr := maskPassword(proxyAddr)
		fmt.Printf("[%d/%d] Trying proxy: %s\n", proxyIndex+1, len(proxyList), displayAddr)

		proxyURL, err := url.Parse(proxyAddr)
		if err != nil {
			fmt.Printf("❌ Invalid proxy URL: %v\n", err)
			proxyIndex = (proxyIndex + 1) % len(proxyList)
			time.Sleep(100 * time.Millisecond)
			continue
		}

		proxyDialer, err := proxy.FromURL(proxyURL, &dialer)
		if err != nil {
			fmt.Printf("❌ Failed to create proxy dialer: %v\n", err)
			proxyIndex = (proxyIndex + 1) % len(proxyList)
			time.Sleep(100 * time.Millisecond)
			continue
		}

		conn, err := dialWithDialer(proxyDialer, ctx, timeout, tlsConfig, edgeTCPAddr)
		if err != nil {
			fmt.Printf("❌ Proxy failed: %v\n", err)
			proxyIndex = (proxyIndex + 1) % len(proxyList)
			
			// 如果已经尝试完一轮所有代理，稍微等待一下再继续
			if proxyIndex == 0 {
				fmt.Printf("All proxies tried, waiting 1 second before next round...\n")
				time.Sleep(time.Second)
			}
			continue
		}

		// 连接成功
		fmt.Printf("✅ Successfully connected via proxy: %s (after %d attempts)\n", displayAddr, attemptCount)
		return conn, nil
	}
}

// maskPassword 隐藏 URL 中的密码部分
func maskPassword(rawURL string) string {
	u, err := url.Parse(rawURL)
	if err != nil {
		return rawURL
	}
	if u.User != nil {
		if _, hasPassword := u.User.Password(); hasPassword {
			u.User = url.UserPassword(u.User.Username(), "****")
		}
	}
	return u.String()
}

// dialWithDialer 使用指定的 dialer 进行连接
func dialWithDialer(
	proxyDialer proxy.Dialer,
	ctx context.Context,
	timeout time.Duration,
	tlsConfig *tls.Config,
	edgeTCPAddr *net.TCPAddr,
) (net.Conn, error) {
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
		edgeConn.Close()
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
