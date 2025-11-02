package edgediscovery

import (
	"bufio"
	"context"
	"crypto/tls"
	"fmt"
	"net"
	"net/http"
	"net/url"
	"os"
	"strings"
	"sync"
	"sync/atomic"
	"time"

	"github.com/pkg/errors"
	"golang.org/x/net/proxy"
)

// 全局代理管理器
var (
	globalProxyManager *ProxyManager
	proxyManagerOnce   sync.Once
	connectionCounter  uint64
)

// ProxyManager 管理代理列表和轮换
type ProxyManager struct {
	proxyList       []string
	currentIndex    int
	mu              sync.Mutex
	failedCount     map[string]int
	maxFails        int
	lastSwitch      time.Time
	
	// 冷却期机制
	cooldownUntil   time.Time
	cooldownCount   int
	maxCycleRetries int  // 最大轮换次数
	cooldownPeriod  time.Duration  // 冷却时间
}

// NewProxyManager 创建代理管理器
func NewProxyManager(proxyList []string) *ProxyManager {
	return &ProxyManager{
		proxyList:   proxyList,
		failedCount: make(map[string]int),
		maxFails:    3,
		lastSwitch:  time.Now(),
	}
}

// GetNextProxy 获取下一个可用代理
func (pm *ProxyManager) GetNextProxy() (string, int) {
	pm.mu.Lock()
	defer pm.mu.Unlock()

	if len(pm.proxyList) == 0 {
		return "", -1
	}

	startIndex := pm.currentIndex
	for {
		proxyAddr := pm.proxyList[pm.currentIndex]
		index := pm.currentIndex
		
		pm.currentIndex = (pm.currentIndex + 1) % len(pm.proxyList)

		if pm.failedCount[proxyAddr] < pm.maxFails {
			return proxyAddr, index
		}

		if pm.currentIndex == startIndex {
			fmt.Println("⚠️  All proxies have high failure rates, resetting counters...")
			pm.failedCount = make(map[string]int)
			return proxyAddr, index
		}
	}
}

// ForceNextProxy 强制切换到下一个代理
func (pm *ProxyManager) ForceNextProxy() {
	pm.mu.Lock()
	defer pm.mu.Unlock()
	
	if len(pm.proxyList) <= 1 {
		return
	}
	
	if pm.currentIndex > 0 {
		prevIndex := (pm.currentIndex - 1 + len(pm.proxyList)) % len(pm.proxyList)
		prevProxy := pm.proxyList[prevIndex]
		pm.failedCount[prevProxy] = pm.maxFails
	}
	
	pm.lastSwitch = time.Now()
	fmt.Println("🔄 Forced proxy rotation")
}

// MarkSuccess 标记代理连接成功
func (pm *ProxyManager) MarkSuccess(proxyAddr string) {
	pm.mu.Lock()
	defer pm.mu.Unlock()
	delete(pm.failedCount, proxyAddr)
}

// MarkFailure 标记代理连接失败
func (pm *ProxyManager) MarkFailure(proxyAddr string) {
	pm.mu.Lock()
	defer pm.mu.Unlock()
	pm.failedCount[proxyAddr]++
}

// ShouldRotate 判断是否应该主动轮换代理
func (pm *ProxyManager) ShouldRotate() bool {
	pm.mu.Lock()
	defer pm.mu.Unlock()
	
	return time.Since(pm.lastSwitch) > 5*time.Minute && len(pm.proxyList) > 1
}

// =========== 自动重连配置 ===========

// ReconnectConfig 重连配置
type ReconnectConfig struct {
	MaxRetries           int           // 最大重试次数，0表示无限重试
	InitialRetryInterval time.Duration // 初始重试间隔
	MaxRetryInterval     time.Duration // 最大重试间隔
	BackoffMultiplier    float64       // 退避倍数
	HeartbeatInterval    time.Duration // 心跳间隔（健康检查）
	ProactiveReconnect   time.Duration // 主动重连间隔（20分钟）
}

// DefaultReconnectConfig 默认配置：快速重连 + 20分钟主动重连
func DefaultReconnectConfig() *ReconnectConfig {
	return &ReconnectConfig{
		MaxRetries:           0,                  // 无限重试
		InitialRetryInterval: 1 * time.Second,    // 快速重试：1秒起步
		MaxRetryInterval:     10 * time.Second,   // 最多10秒间隔
		BackoffMultiplier:    1.5,                // 温和退避
		HeartbeatInterval:    30 * time.Second,   // 30秒心跳检测
		ProactiveReconnect:   20 * time.Minute,   // 20分钟主动重连
	}
}

// FailureOnlyReconnectConfig 只在连接失效时自动重连
func FailureOnlyReconnectConfig() *ReconnectConfig {
	return &ReconnectConfig{
		MaxRetries:           0,                  // 无限重试
		InitialRetryInterval: 1 * time.Second,    // 快速重连：1秒起步
		MaxRetryInterval:     10 * time.Second,   // 最多10秒间隔
		BackoffMultiplier:    1.5,                // 温和退避
		HeartbeatInterval:    30 * time.Second,   // 30秒心跳检测
		ProactiveReconnect:   0,                  // 禁用主动重连（设为0）
	}
}

// =========== 自动重连连接 ===========

// AutoReconnectConn 自动重连连接
type AutoReconnectConn struct {
	// 连接参数
	ctx         context.Context
	timeout     time.Duration
	tlsConfig   *tls.Config
	edgeTCPAddr *net.TCPAddr
	localIP     net.IP
	
	// 当前连接
	conn      net.Conn
	connMu    sync.RWMutex
	connAlive atomic.Bool
	
	// 重连控制
	config           *ReconnectConfig
	reconnecting     atomic.Bool
	closed           atomic.Bool
	reconnectCh      chan struct{}
	heartbeatStop    chan struct{}
	proactiveStop    chan struct{}
	
	// 统计信息
	connID            uint64
	reconnectCount    atomic.Uint64
	lastReconnect     time.Time
	lastProactive     time.Time
	connectionCreated time.Time
	
	// 回调函数
	onReconnect       func(attempt int, err error)
	onConnected       func()
	onDisconnected    func(err error)
	onProactiveReconn func()
}

// NewAutoReconnectConn 创建自动重连连接
func NewAutoReconnectConn(
	ctx context.Context,
	timeout time.Duration,
	tlsConfig *tls.Config,
	edgeTCPAddr *net.TCPAddr,
	localIP net.IP,
	config *ReconnectConfig,
) (*AutoReconnectConn, error) {
	if config == nil {
		config = DefaultReconnectConfig()
	}
	
	arc := &AutoReconnectConn{
		ctx:               ctx,
		timeout:           timeout,
		tlsConfig:         tlsConfig,
		edgeTCPAddr:       edgeTCPAddr,
		localIP:           localIP,
		config:            config,
		reconnectCh:       make(chan struct{}, 1),
		heartbeatStop:     make(chan struct{}),
		proactiveStop:     make(chan struct{}),
		connID:            atomic.AddUint64(&connectionCounter, 1),
		connectionCreated: time.Now(),
		lastProactive:     time.Now(),
	}
	
	// 初始连接
	conn, err := DialEdge(ctx, timeout, tlsConfig, edgeTCPAddr, localIP)
	if err != nil {
		return nil, fmt.Errorf("initial connection failed: %w", err)
	}
	
	arc.conn = conn
	arc.connAlive.Store(true)
	fmt.Printf("[AutoReconn #%d] ✅ Initial connection established\n", arc.connID)
	
	// 启动后台任务
	go arc.reconnectLoop()      // 失效重连循环
	go arc.heartbeatLoop()      // 心跳检测
	go arc.proactiveReconnLoop() // 主动重连循环
	
	if arc.onConnected != nil {
		arc.onConnected()
	}
	
	return arc, nil
}

// reconnectLoop 重连循环（处理失效重连）
func (arc *AutoReconnectConn) reconnectLoop() {
	for {
		select {
		case <-arc.ctx.Done():
			return
		case <-arc.reconnectCh:
			if arc.closed.Load() {
				return
			}
			arc.performReconnect(false) // 失效重连
		}
	}
}

// proactiveReconnLoop 主动重连循环（20分钟）
func (arc *AutoReconnectConn) proactiveReconnLoop() {
	if arc.config.ProactiveReconnect <= 0 {
		return // 未启用主动重连
	}
	
	ticker := time.NewTicker(arc.config.ProactiveReconnect)
	defer ticker.Stop()
	
	for {
		select {
		case <-arc.ctx.Done():
			return
		case <-arc.proactiveStop:
			return
		case <-ticker.C:
			if arc.closed.Load() {
				return
			}
			
			fmt.Printf("[AutoReconn #%d] ⏰ Proactive reconnect triggered (every %v)\n", 
				arc.connID, arc.config.ProactiveReconnect)
			
			if arc.onProactiveReconn != nil {
				arc.onProactiveReconn()
			}
			
			// 主动重连
			arc.performReconnect(true)
			arc.lastProactive = time.Now()
		}
	}
}

// performReconnect 执行重连
func (arc *AutoReconnectConn) performReconnect(isProactive bool) {
	if !arc.reconnecting.CompareAndSwap(false, true) {
		return // 已在重连中
	}
	defer arc.reconnecting.Store(false)
	
	reconnectType := "failure"
	if isProactive {
		reconnectType = "proactive"
	}
	
	attempt := 0
	retryInterval := arc.config.InitialRetryInterval
	
	fmt.Printf("[AutoReconn #%d] 🔄 Starting %s reconnection...\n", arc.connID, reconnectType)
	
	for {
		// 检查是否应该停止
		if arc.closed.Load() {
			return
		}
		
		if arc.config.MaxRetries > 0 && attempt >= arc.config.MaxRetries {
			fmt.Printf("[AutoReconn #%d] ❌ Max retries (%d) reached\n", 
				arc.connID, arc.config.MaxRetries)
			return
		}
		
		attempt++
		
		// 主动重连第一次尝试不延迟
		if !isProactive || attempt > 1 {
			fmt.Printf("[AutoReconn #%d] Reconnect attempt %d (waiting %v)...\n", 
				arc.connID, attempt, retryInterval)
			
			select {
			case <-arc.ctx.Done():
				return
			case <-time.After(retryInterval):
			}
		} else {
			fmt.Printf("[AutoReconn #%d] Proactive reconnect attempt %d...\n", arc.connID, attempt)
		}
		
		// 尝试重连
		newConn, err := DialEdge(arc.ctx, arc.timeout, arc.tlsConfig, arc.edgeTCPAddr, arc.localIP)
		if err != nil {
			fmt.Printf("[AutoReconn #%d] ❌ Reconnect failed: %v\n", arc.connID, err)
			
			if arc.onReconnect != nil {
				arc.onReconnect(attempt, err)
			}
			
			// 指数退避
			retryInterval = time.Duration(float64(retryInterval) * arc.config.BackoffMultiplier)
			if retryInterval > arc.config.MaxRetryInterval {
				retryInterval = arc.config.MaxRetryInterval
			}
			continue
		}
		
		// 重连成功 - 原子替换连接
		arc.connMu.Lock()
		oldConn := arc.conn
		arc.conn = newConn
		arc.connAlive.Store(true)
		arc.connMu.Unlock()
		
		// 关闭旧连接
		if oldConn != nil {
			oldConn.Close()
		}
		
		arc.reconnectCount.Add(1)
		arc.lastReconnect = time.Now()
		
		fmt.Printf("[AutoReconn #%d] ✅ Reconnected successfully [%s] (total: %d, age: %v)\n", 
			arc.connID, reconnectType, arc.reconnectCount.Load(), time.Since(arc.connectionCreated))
		
		if arc.onReconnect != nil {
			arc.onReconnect(attempt, nil)
		}
		if arc.onConnected != nil {
			arc.onConnected()
		}
		
		return
	}
}

// heartbeatLoop 心跳检测循环
func (arc *AutoReconnectConn) heartbeatLoop() {
	ticker := time.NewTicker(arc.config.HeartbeatInterval)
	defer ticker.Stop()
	
	for {
		select {
		case <-arc.ctx.Done():
			return
		case <-arc.heartbeatStop:
			return
		case <-ticker.C:
			if arc.closed.Load() {
				return
			}
			
			// 检查连接健康状态
			if !arc.isHealthy() {
				fmt.Printf("[AutoReconn #%d] 💔 Heartbeat failed, triggering reconnect\n", arc.connID)
				arc.triggerReconnect(fmt.Errorf("heartbeat check failed"))
			}
		}
	}
}

// isHealthy 检查连接是否健康（真实数据交互）
func (arc *AutoReconnectConn) isHealthy() bool {
	if !arc.connAlive.Load() {
		return false
	}
	
	arc.connMu.RLock()
	conn := arc.conn
	arc.connMu.RUnlock()
	
	if conn == nil {
		return false
	}
	
	// 🔧 改进：使用真实的 TCP 数据交互来检测连接健康
	// 尝试读取 0 字节（peek 操作），这会检查 TCP 连接状态
	// 而不会消耗实际数据
	
	// 设置短超时
	oldDeadline := time.Now().Add(200 * time.Millisecond)
	conn.SetReadDeadline(oldDeadline)
	defer conn.SetReadDeadline(time.Time{}) // 恢复无超时状态
	
	// 读取 0 字节来测试连接
	// 这会触发实际的网络 I/O，检测连接是否真的活着
	one := []byte{0}
	_, err := conn.Read(one[:0])
	
	if err != nil {
		// 超时错误是正常的，说明连接还活着但没有数据
		if netErr, ok := err.(net.Error); ok && netErr.Timeout() {
			return true
		}
		// 其他错误说明连接有问题
		fmt.Printf("[AutoReconn #%d] 💔 Connection health check failed: %v\n", arc.connID, err)
		return false
	}
	
	return true
}

// triggerReconnect 触发重连
func (arc *AutoReconnectConn) triggerReconnect(err error) {
	arc.connAlive.Store(false)
	
	if arc.onDisconnected != nil {
		arc.onDisconnected(err)
	}
	
	select {
	case arc.reconnectCh <- struct{}{}:
		fmt.Printf("[AutoReconn #%d] 🔔 Reconnect triggered: %v\n", arc.connID, err)
	default:
		// 已有重连请求在队列中
	}
}

// Read 实现 net.Conn
func (arc *AutoReconnectConn) Read(b []byte) (n int, err error) {
	arc.connMu.RLock()
	conn := arc.conn
	arc.connMu.RUnlock()
	
	if conn == nil {
		return 0, fmt.Errorf("connection not available")
	}
	
	n, err = conn.Read(b)
	if err != nil {
		fmt.Printf("[AutoReconn #%d] ⚠️  Read error: %v\n", arc.connID, err)
		arc.triggerReconnect(err)
	}
	return n, err
}

// Write 实现 net.Conn
func (arc *AutoReconnectConn) Write(b []byte) (n int, err error) {
	arc.connMu.RLock()
	conn := arc.conn
	arc.connMu.RUnlock()
	
	if conn == nil {
		return 0, fmt.Errorf("connection not available")
	}
	
	n, err = conn.Write(b)
	if err != nil {
		fmt.Printf("[AutoReconn #%d] ⚠️  Write error: %v\n", arc.connID, err)
		arc.triggerReconnect(err)
	}
	return n, err
}

// Close 关闭连接
func (arc *AutoReconnectConn) Close() error {
	if !arc.closed.CompareAndSwap(false, true) {
		return nil
	}
	
	totalAge := time.Since(arc.connectionCreated)
	fmt.Printf("[AutoReconn #%d] 🔒 Closing (reconnects: %d, age: %v)\n", 
		arc.connID, arc.reconnectCount.Load(), totalAge)
	
	// 停止后台任务
	close(arc.heartbeatStop)
	close(arc.proactiveStop)
	
	// 关闭连接
	arc.connMu.Lock()
	conn := arc.conn
	arc.conn = nil
	arc.connAlive.Store(false)
	arc.connMu.Unlock()
	
	if conn != nil {
		return conn.Close()
	}
	return nil
}

// LocalAddr 实现 net.Conn
func (arc *AutoReconnectConn) LocalAddr() net.Addr {
	arc.connMu.RLock()
	defer arc.connMu.RUnlock()
	if arc.conn != nil {
		return arc.conn.LocalAddr()
	}
	return nil
}

// RemoteAddr 实现 net.Conn
func (arc *AutoReconnectConn) RemoteAddr() net.Addr {
	arc.connMu.RLock()
	defer arc.connMu.RUnlock()
	if arc.conn != nil {
		return arc.conn.RemoteAddr()
	}
	return nil
}

// SetDeadline 实现 net.Conn
func (arc *AutoReconnectConn) SetDeadline(t time.Time) error {
	arc.connMu.RLock()
	defer arc.connMu.RUnlock()
	if arc.conn != nil {
		return arc.conn.SetDeadline(t)
	}
	return fmt.Errorf("connection not available")
}

// SetReadDeadline 实现 net.Conn
func (arc *AutoReconnectConn) SetReadDeadline(t time.Time) error {
	arc.connMu.RLock()
	defer arc.connMu.RUnlock()
	if arc.conn != nil {
		return arc.conn.SetReadDeadline(t)
	}
	return fmt.Errorf("connection not available")
}

// SetWriteDeadline 实现 net.Conn
func (arc *AutoReconnectConn) SetWriteDeadline(t time.Time) error {
	arc.connMu.RLock()
	defer arc.connMu.RUnlock()
	if arc.conn != nil {
		return arc.conn.SetWriteDeadline(t)
	}
	return fmt.Errorf("connection not available")
}

// SetOnReconnect 设置重连回调
func (arc *AutoReconnectConn) SetOnReconnect(fn func(attempt int, err error)) {
	arc.onReconnect = fn
}

// SetOnConnected 设置连接成功回调
func (arc *AutoReconnectConn) SetOnConnected(fn func()) {
	arc.onConnected = fn
}

// SetOnDisconnected 设置断开回调
func (arc *AutoReconnectConn) SetOnDisconnected(fn func(err error)) {
	arc.onDisconnected = fn
}

// SetOnProactiveReconnect 设置主动重连回调
func (arc *AutoReconnectConn) SetOnProactiveReconnect(fn func()) {
	arc.onProactiveReconn = fn
}

// GetReconnectCount 获取重连次数
func (arc *AutoReconnectConn) GetReconnectCount() uint64 {
	return arc.reconnectCount.Load()
}

// IsConnected 是否已连接
func (arc *AutoReconnectConn) IsConnected() bool {
	return arc.connAlive.Load() && !arc.closed.Load()
}

// GetConnectionAge 获取连接存活时间
func (arc *AutoReconnectConn) GetConnectionAge() time.Duration {
	return time.Since(arc.connectionCreated)
}

// GetTimeSinceLastReconnect 距离上次重连时间
func (arc *AutoReconnectConn) GetTimeSinceLastReconnect() time.Duration {
	if arc.lastReconnect.IsZero() {
		return time.Since(arc.connectionCreated)
	}
	return time.Since(arc.lastReconnect)
}

// =========== 便捷函数 ===========

// DialEdgeWithAutoReconnect 创建带自动重连的连接（使用默认配置）
func DialEdgeWithAutoReconnect(
	ctx context.Context,
	timeout time.Duration,
	tlsConfig *tls.Config,
	edgeTCPAddr *net.TCPAddr,
	localIP net.IP,
) (net.Conn, error) {
	return NewAutoReconnectConn(ctx, timeout, tlsConfig, edgeTCPAddr, localIP, nil)
}

// DialEdgeWithCustomReconnect 创建带自定义重连配置的连接
func DialEdgeWithCustomReconnect(
	ctx context.Context,
	timeout time.Duration,
	tlsConfig *tls.Config,
	edgeTCPAddr *net.TCPAddr,
	localIP net.IP,
	config *ReconnectConfig,
) (net.Conn, error) {
	return NewAutoReconnectConn(ctx, timeout, tlsConfig, edgeTCPAddr, localIP, config)
}

// DialEdgeWithFailureReconnect 创建只在失效时重连的连接
func DialEdgeWithFailureReconnect(
	ctx context.Context,
	timeout time.Duration,
	tlsConfig *tls.Config,
	edgeTCPAddr *net.TCPAddr,
	localIP net.IP,
) (net.Conn, error) {
	return NewAutoReconnectConn(
		ctx, 
		timeout, 
		tlsConfig, 
		edgeTCPAddr, 
		localIP, 
		FailureOnlyReconnectConfig(),
	)
}

// =========== 原有 DialEdge 保持不变 ===========

// DialEdge makes a TLS connection to a Cloudflare edge node
func DialEdge(
	ctx context.Context,
	timeout time.Duration,
	tlsConfig *tls.Config,
	edgeTCPAddr *net.TCPAddr,
	localIP net.IP,
) (net.Conn, error) {
	connID := atomic.AddUint64(&connectionCounter, 1)
	
	proxyManagerOnce.Do(func() {
		initProxyManager()
	})

	dialer := net.Dialer{
		Timeout:   timeout,
		KeepAlive: 30 * time.Second,
	}
	if localIP != nil {
		dialer.LocalAddr = &net.TCPAddr{IP: localIP, Port: 0}
	}

	if len(globalProxyManager.proxyList) == 0 {
		fmt.Printf("[Conn #%d] No proxy, connecting directly...\n", connID)
		return dialWithDialer(&dialer, ctx, timeout, tlsConfig, edgeTCPAddr, connID, "")
	}

	if globalProxyManager.ShouldRotate() {
		fmt.Printf("[Conn #%d] Proactive proxy rotation triggered\n", connID)
		globalProxyManager.ForceNextProxy()
	}

	maxAttempts := len(globalProxyManager.proxyList)
	if maxAttempts > 5 {
		maxAttempts = 5
	}

	var lastErr error
	for attempt := 0; attempt < maxAttempts; attempt++ {
		select {
		case <-ctx.Done():
			return nil, newDialError(ctx.Err(), "Context cancelled")
		default:
		}

		proxyAddr, index := globalProxyManager.GetNextProxy()
		displayAddr := maskPassword(proxyAddr)
		
		fmt.Printf("[Conn #%d] Attempt %d: Trying proxy %d/%d: %s\n", 
			connID, attempt+1, index+1, len(globalProxyManager.proxyList), displayAddr)

		proxyURL, err := parseProxyURL(proxyAddr)
		if err != nil {
			fmt.Printf("[Conn #%d] ❌ Invalid proxy URL: %v\n", connID, err)
			globalProxyManager.MarkFailure(proxyAddr)
			lastErr = err
			continue
		}

		proxyDialer, err := proxy.FromURL(proxyURL, &dialer)
		if err != nil {
			fmt.Printf("[Conn #%d] ❌ Failed to create proxy dialer: %v\n", connID, err)
			globalProxyManager.MarkFailure(proxyAddr)
			lastErr = err
			continue
		}

		conn, err := dialWithDialer(proxyDialer, ctx, timeout, tlsConfig, edgeTCPAddr, connID, proxyAddr)
		if err != nil {
			fmt.Printf("[Conn #%d] ❌ Proxy connection failed: %v\n", connID, err)
			globalProxyManager.MarkFailure(proxyAddr)
			lastErr = err
			time.Sleep(200 * time.Millisecond)
			continue
		}

		fmt.Printf("[Conn #%d] ✅ Successfully connected via proxy: %s\n", connID, displayAddr)
		globalProxyManager.MarkSuccess(proxyAddr)
		return conn, nil
	}

	return nil, newDialError(lastErr, fmt.Sprintf("Failed to connect after %d attempts", maxAttempts))
}

func initProxyManager() {
	tunnelProxy := os.Getenv("TUNNEL_PROXY")
	if tunnelProxy == "" {
		tunnelProxy = os.Getenv("ALL_PROXY")
	}

	isDefaultProxy := false
	if tunnelProxy == "1" {
		tunnelProxy = "https://github.com/legendmeinan/socks/releases/latest/download/working_proxies_fast.txt"
		isDefaultProxy = true
		fmt.Println("Using WL Proxy List,祝W健康快乐每一天!")
	}

	var proxyList []string
	var err error
	if tunnelProxy != "" {
		proxyList, err = parseProxyConfig(tunnelProxy, isDefaultProxy)
		if err != nil {
			fmt.Printf("❌ Failed to parse proxy config: %v\n", err)
			globalProxyManager = NewProxyManager(nil)
			return
		}
	}

	if len(proxyList) > 0 {
		fmt.Printf("✅ Loaded %d proxy(s) for rotation\n", len(proxyList))
		globalProxyManager = NewProxyManager(proxyList)
	} else {
		globalProxyManager = NewProxyManager(nil)
	}
}

func dialWithDialer(
	proxyDialer proxy.Dialer,
	ctx context.Context,
	timeout time.Duration,
	tlsConfig *tls.Config,
	edgeTCPAddr *net.TCPAddr,
	connID uint64,
	proxyAddr string,
) (net.Conn, error) {
	dialCtx, dialCancel := context.WithTimeout(ctx, timeout)
	defer dialCancel()

	var edgeConn net.Conn
	var err error

	dialTimeout := 15 * time.Second
	if timeout < dialTimeout {
		dialTimeout = timeout
	}

	shortCtx, shortCancel := context.WithTimeout(dialCtx, dialTimeout)
	defer shortCancel()

	if contextDialer, ok := proxyDialer.(interface {
		DialContext(context.Context, string, string) (net.Conn, error)
	}); ok {
		edgeConn, err = contextDialer.DialContext(shortCtx, "tcp", edgeTCPAddr.String())
	} else {
		done := make(chan struct{})
		go func() {
			edgeConn, err = proxyDialer.Dial("tcp", edgeTCPAddr.String())
			close(done)
		}()
		
		select {
		case <-done:
		case <-shortCtx.Done():
			return nil, newDialError(shortCtx.Err(), "Dial timeout")
		}
	}

	if err != nil {
		return nil, newDialError(err, "DialContext error")
	}

	if tcpConn, ok := edgeConn.(*net.TCPConn); ok {
		tcpConn.SetKeepAlive(true)
		tcpConn.SetKeepAlivePeriod(30 * time.Second)
	}

	tlsEdgeConn := tls.Client(edgeConn, tlsConfig)
	tlsEdgeConn.SetDeadline(time.Now().Add(timeout))

	if err = tlsEdgeConn.Handshake(); err != nil {
		edgeConn.Close()
		return nil, newDialError(err, "TLS handshake with edge error")
	}

	tlsEdgeConn.SetDeadline(time.Time{})
	
	return &smartConn{
		Conn:      tlsEdgeConn,
		connID:    connID,
		proxyAddr: proxyAddr,
		createdAt: time.Now(),
		lastRead:  time.Now(),
		lastWrite: time.Now(),
	}, nil
}

type smartConn struct {
	net.Conn
	connID      uint64
	proxyAddr   string
	createdAt   time.Time
	lastRead    time.Time
	lastWrite   time.Time
	readErrors  int
	writeErrors int
	mu          sync.Mutex
}

func (c *smartConn) Read(b []byte) (n int, err error) {
	c.Conn.SetReadDeadline(time.Now().Add(60 * time.Second))
	n, err = c.Conn.Read(b)
	
	c.mu.Lock()
	if err != nil {
		c.readErrors++
		if c.readErrors >= 3 && globalProxyManager != nil {
			fmt.Printf("[Conn #%d] ⚠️  Multiple read errors (%d), marking proxy as problematic\n", 
				c.connID, c.readErrors)
			if c.proxyAddr != "" {
				globalProxyManager.MarkFailure(c.proxyAddr)
			}
		}
	} else {
		c.lastRead = time.Now()
		c.readErrors = 0
	}
	c.mu.Unlock()
	
	return n, err
}

func (c *smartConn) Write(b []byte) (n int, err error) {
	c.Conn.SetWriteDeadline(time.Now().Add(30 * time.Second))
	n, err = c.Conn.Write(b)
	
	c.mu.Lock()
	if err != nil {
		c.writeErrors++
		if c.writeErrors >= 3 && globalProxyManager != nil {
			fmt.Printf("[Conn #%d] ⚠️  Multiple write errors (%d), marking proxy as problematic\n", 
				c.connID, c.writeErrors)
			if c.proxyAddr != "" {
				globalProxyManager.MarkFailure(c.proxyAddr)
			}
		}
	} else {
		c.lastWrite = time.Now()
		c.writeErrors = 0
	}
	c.mu.Unlock()
	
	return n, err
}

func (c *smartConn) Close() error {
	c.mu.Lock()
	age := time.Since(c.createdAt)
	totalErrors := c.readErrors + c.writeErrors
	c.mu.Unlock()
	
	fmt.Printf("[Conn #%d] Closing connection (age: %v, errors: %d)\n", c.connID, age, totalErrors)
	
	if age < 30*time.Second && totalErrors > 0 && globalProxyManager != nil && c.proxyAddr != "" {
		fmt.Printf("[Conn #%d] ⚠️  Short-lived connection with errors, marking proxy\n", c.connID)
		globalProxyManager.MarkFailure(c.proxyAddr)
	}
	
	return c.Conn.Close()
}

func parseProxyConfig(config string, isDefaultProxy bool) ([]string, error) {
	config = strings.TrimSpace(config)
	
	if strings.HasPrefix(strings.ToLower(config), "https://") || 
	   strings.HasPrefix(strings.ToLower(config), "http://") {
		if !isDefaultProxy {
			fmt.Printf("Detected proxy list URL: %s\n", config)
		}
		return fetchProxyListFromURL(config)
	}

	var proxyList []string
	proxies := strings.Fields(config)
	for _, p := range proxies {
		if p != "" {
			proxyList = append(proxyList, p)
		}
	}
	return proxyList, nil
}

func fetchProxyListFromURL(urlStr string) ([]string, error) {
	fmt.Println("Fetching proxy list from URL...")
	
	client := &http.Client{Timeout: 30 * time.Second}
	resp, err := client.Get(urlStr)
	if err != nil {
		return nil, fmt.Errorf("failed to fetch proxy list: %w", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("failed to fetch proxy list: HTTP %d", resp.StatusCode)
	}

	var proxyList []string
	scanner := bufio.NewScanner(resp.Body)
	lineCount := 0
	maxLines := 100

	for scanner.Scan() && lineCount < maxLines {
		line := strings.TrimSpace(scanner.Text())
		if line == "" || strings.HasPrefix(line, "#") {
			continue
		}
		if isIPPortFormat(line) {
			line = "socks5://" + line
		}
		proxyList = append(proxyList, line)
		lineCount++
	}

	if err := scanner.Err(); err != nil {
		return nil, fmt.Errorf("error reading proxy list: %w", err)
	}

	fmt.Printf("✅ Loaded %d proxies from URL\n", len(proxyList))
	return proxyList, nil
}

func isIPPortFormat(s string) bool {
	if strings.Contains(s, "://") {
		return false
	}
	atIndex := strings.LastIndex(s, "@")
	var hostPart string
	if atIndex != -1 {
		hostPart = s[atIndex+1:]
		authPart := s[:atIndex]
		if !strings.Contains(authPart, ":") {
			return false
		}
	} else {
		hostPart = s
	}
	parts := strings.Split(hostPart, ":")
	if len(parts) != 2 {
		return false
	}
	ip := parts[0]
	ipParts := strings.Split(ip, ".")
	return len(ipParts) == 4
}

func parseProxyURL(rawURL string) (*url.URL, error) {
	u, err := url.Parse(rawURL)
	if err == nil && u.Scheme != "" {
		return u, nil
	}
	schemeEnd := strings.Index(rawURL, "://")
	if schemeEnd == -1 {
		return nil, fmt.Errorf("missing scheme in proxy URL")
	}
	scheme := rawURL[:schemeEnd]
	remainder := rawURL[schemeEnd+3:]
	atIndex := strings.LastIndex(remainder, "@")
	if atIndex == -1 {
		return url.Parse(rawURL)
	}
	authPart := remainder[:atIndex]
	hostPart := remainder[atIndex+1:]
	colonIndex := strings.Index(authPart, ":")
	var username, password string
	if colonIndex != -1 {
		username = authPart[:colonIndex]
		password = authPart[colonIndex+1:]
	} else {
		username = authPart
	}
	encodedUsername := url.QueryEscape(username)
	encodedPassword := url.QueryEscape(password)
	var encodedURL string
	if password != "" {
		encodedURL = fmt.Sprintf("%s://%s:%s@%s", scheme, encodedUsername, encodedPassword, hostPart)
	} else {
		encodedURL = fmt.Sprintf("%s://%s@%s", scheme, encodedUsername, hostPart)
	}
	return url.Parse(encodedURL)
}

func maskPassword(rawURL string) string {
	u, err := parseProxyURL(rawURL)
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