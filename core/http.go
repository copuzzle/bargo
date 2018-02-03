package core

import (
	"net/url"
	"net"
	"time"
	"regexp"
	"strings"
	"strconv"
	"encoding/binary"
	"io"
	"fmt"
	"net/http"

	"github.com/sinchie/bargo/util"
	"github.com/sinchie/bargo/util/pac"
)

// http服务
type HttpServer struct {
	cfg            *util.Config
	nomalTransport *http.Transport
	hideTransport  *http.Transport
	isAuto         bool
}

// 创建http服务
func NewHttpServer(cfg *util.Config) *HttpServer {
	h := new(HttpServer)
	h.cfg = cfg
	// 初始化Transport
	h.initTransport()
	// 设置系统http代理
	if h.cfg.ClientProxyMode != "socks5" && h.cfg.ClientSysproxy == "on" {
		go util.OpenSysproxy(cfg)
	}
	// 智能模式 初始化规则
	if h.cfg.ClientProxyMode == "http-auto" {
		h.isAuto = true
		pac.InitRule()
		// 添加用户自定义规则
		if len(h.cfg.ClientWhiteList) > 0 {
			pac.AddRules("white", h.cfg.ClientWhiteList)
		}
		if len(h.cfg.ClientBlackList) > 0 {
			pac.AddRules("black", h.cfg.ClientBlackList)
		}
	}


	return h
}

// 运行http服务
func (h *HttpServer) Run()  {
	http.ListenAndServe(h.cfg.ClientHost+":"+h.cfg.ClientHttpPort, h)
}

// 初始化Transport
func (h *HttpServer) initTransport() {
	// 正常http传输
	h.nomalTransport = h.newTransport(nil)

	// 隐藏http传输
	socks5String := "socks5://127.0.0.1:" + h.cfg.ClientSocksPort
	socks5Url, _ := url.Parse(socks5String)
	h.hideTransport = h.newTransport(socks5Url)
}

// 获得Transport实例
func (h *HttpServer) newTransport(proxyUrl *url.URL) *http.Transport {
	t := &http.Transport{
		Proxy: nil,
		DialContext: (&net.Dialer{
			Timeout:   30 * time.Second,
			KeepAlive: 30 * time.Second,
			DualStack: true,
		}).DialContext,
		MaxIdleConns:          100,
		IdleConnTimeout:       30 * time.Second,
		TLSHandshakeTimeout:   10 * time.Second,
		ExpectContinueTimeout: 1 * time.Second,
	}
	if proxyUrl != nil {
		t.Proxy = http.ProxyURL(proxyUrl)
	}

	return t
}

// 接收http请求
func (h *HttpServer) ServeHTTP(rw http.ResponseWriter, req *http.Request) {
	if h.isAuto { // 智能模式
		if pac.IsNeedProxy(req.URL.Hostname()) {
			h.hideProxy(rw, req)
		} else {
			h.nomalProxy(rw, req)
		}
	} else { // 全局模式
		h.hideProxy(rw, req)
	}
}

// 正常代理
func (h *HttpServer) nomalProxy(rw http.ResponseWriter, req *http.Request) {
	// https websocket 隧道代理
	if req.Method == http.MethodConnect {
		// 获得tcp连接
		hij, ok := rw.(http.Hijacker)
		if !ok {
			return
		}
		client, _, err := hij.Hijack()
		if err != nil {
			return
		}
		// 连接远端
		server, err := net.Dial("tcp", req.URL.Host)
		if err != nil {
			return
		}
		// 响应客户端远端连接成功可以开始通讯
		_, err = client.Write([]byte("HTTP/1.0 200 Connection Established\r\n\r\n"))
		if err != nil {
			return
		}
		// 开始转发
		go io.Copy(server, client)
		io.Copy(client, server)
		server.Close()
		client.Close()
		return
	} else {
		// http 代理
		req.Header.Del("Proxy-Connection")
		req.Header.Set("Connection", "keep-alive")
		// 请求远端获得响应
		res, err := h.nomalTransport.RoundTrip(req)
		if err != nil {
			return
		}
		// 补充响应header
		for key, value := range res.Header {
			for _, v := range value {
				rw.Header().Add(key, v)
			}
		}
		// 返回响应
		rw.WriteHeader(res.StatusCode)
		io.Copy(rw, res.Body)
		res.Body.Close()
	}
}

// 隐藏代理
func (h *HttpServer) hideProxy(rw http.ResponseWriter, req *http.Request) {
	// https websocket 隧道代理
	if req.Method == http.MethodConnect {
		// 获得tcp连接
		hij, ok := rw.(http.Hijacker)
		if !ok {
			return
		}
		client, _, err := hij.Hijack()
		if err != nil {
			return
		}
		// 连接远端
		socksConn, err := h.connectSocks(req.URL.Hostname(), req.URL.Port())
		if err != nil {
			return
		}
		// 响应客户端远端连接成功可以开始通讯
		_, err = client.Write([]byte("HTTP/1.0 200 Connection Established\r\n\r\n"))
		if err != nil {
			return
		}
		// 开始转发
		go io.Copy(socksConn, client)
		io.Copy(client, socksConn)
		socksConn.Close()
		client.Close()
		return
	} else {
		// http 代理
		req.Header.Del("Proxy-Connection")
		req.Header.Set("Connection", "keep-alive")
		// 请求远端获得响应
		res, err := h.hideTransport.RoundTrip(req)
		if err != nil {
			return
		}
		// 补充响应header
		for key, value := range res.Header {
			for _, v := range value {
				rw.Header().Add(key, v)
			}
		}
		// 返回响应
		rw.WriteHeader(res.StatusCode)
		io.Copy(rw, res.Body)
		res.Body.Close()
	}
}

// 连接socks5服务
func (h *HttpServer) connectSocks(addr, port string) (net.Conn, error) {
	socksConn, err := net.DialTimeout("tcp", "127.0.0.1:"+h.cfg.ClientSocksPort, 10*time.Second)
	if err != nil {
		return nil, err
	}
	// 模拟socks5客户端
	buf := make([]byte, 10)
	// 客户端第一次发送请求
	buf[0] = 0x05
	buf[1] = 0x01
	buf[2] = 0x00
	_, err = socksConn.Write(buf[:3])
	if err != nil {
		return nil, err
	}
	// 服务端第一次响应
	_, err = io.ReadFull(socksConn, buf[:2])
	if err != nil {
		return nil, err
	}
	// 客户端发送连接信息
	_, err = socksConn.Write(h.newSocks5Head(addr, port))
	if err != nil {
		return nil, err
	}
	// 服务端响应ok 转发信息
	_, err = socksConn.Read(buf)
	if err != nil || buf[1] != 0x00 {
		return nil, fmt.Errorf("conn socks fail")
	}

	return socksConn, nil
}

// 获得socks5头
func (h *HttpServer) newSocks5Head(addr, port string) []byte {
	socks5Header := make([]byte, 3, 300)
	socks5Header[0] = 0x05
	socks5Header[1] = 0x01
	socks5Header[2] = 0x00
	// 判断addr是ip地址还是字符串域名
	reg := regexp.MustCompile(`^(?:\d{1,3}\.){3}\d{1,3}$`)
	if reg.MatchString(addr) { // 是ip地址
		socks5Header = append(socks5Header, byte(0x01))
		dstAddr := new(net.IP)
		dstAddr.UnmarshalText([]byte(addr))
		socks5Header = append(socks5Header, *dstAddr...)
	} else if strings.Index(addr, ":") >= 0 { // ipv6地址
		socks5Header = append(socks5Header, byte(0x04))
		dstAddr := new(net.IP)
		dstAddr.UnmarshalText([]byte(addr))
		socks5Header = append(socks5Header, *dstAddr...)
	} else { // 域名
		socks5Header = append(socks5Header, byte(0x03))
		socks5Header = append(socks5Header, byte(len(addr)))
		socks5Header = append(socks5Header, []byte(addr)...)
	}
	// 组合端口到协议头
	dstPort, _ := strconv.Atoi(port)
	l := len(socks5Header)
	socks5Header = append(socks5Header, []byte{0x00, 0x00}...)
	binary.BigEndian.PutUint16(socks5Header[l:l+2], uint16(dstPort))

	return socks5Header
}
