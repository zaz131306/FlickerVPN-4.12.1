// Package socks5 — локальный SOCKS5-сервер (RFC 1928) поверх драйвера туннеля.
// Поддержка: NO-AUTH handshake, CONNECT (IPv4/IPv6/domain), UDP ASSOCIATE.
package socks5

import (
	"context"
	"encoding/binary"
	"errors"
	"fmt"
	"io"
	"log"
	"net"
	"sync"
	"time"

	"flicker-vpn/native/internal/tunnel"
)

const (
	ver5 = 0x05

	cmdConnect      = 0x01
	cmdBind         = 0x02
	cmdUDPAssociate = 0x03

	atypIPv4   = 0x01
	atypDomain = 0x03
	atypIPv6   = 0x04

	repOK          = 0x00
	repGeneral     = 0x01
	repNotAllowed  = 0x02
	repNetUnreach  = 0x03
	repHostUnreach = 0x04
	repConnRefused = 0x05
	repCmdNotSupp  = 0x07
	repAtypNotSupp = 0x08

	handshakeTimeout = 30 * time.Second
	maxDomainLen     = 255
)

// Tunnel — то, что нужно SOCKS5 от транспорта.
type Tunnel interface {
	DialTCP(ctx context.Context, addr string) (net.Conn, error)
	NewUDPSession(ctx context.Context) (tunnel.UDPSession, error)
}

// Server — SOCKS5 listener.
type Server struct {
	ln       net.Listener
	tun      Tunnel
	counters *tunnel.Counters
	logger   *log.Logger

	mu     sync.Mutex
	closed bool
	wg     sync.WaitGroup
	conns  map[net.Conn]struct{}
	udps   map[*udpSession]struct{}
}

func New(listenAddr string, tun Tunnel, counters *tunnel.Counters, logger *log.Logger) (*Server, error) {
	ln, err := net.Listen("tcp", listenAddr)
	if err != nil {
		return nil, fmt.Errorf("socks5: listen %s: %w", listenAddr, err)
	}
	s := &Server{
		ln:       ln,
		tun:      tun,
		counters: counters,
		logger:   logger,
		conns:    make(map[net.Conn]struct{}),
		udps:     make(map[*udpSession]struct{}),
	}
	s.wg.Add(1)
	go s.acceptLoop()
	return s, nil
}

func (s *Server) Addr() string { return s.ln.Addr().String() }

func (s *Server) Close() error {
	s.mu.Lock()
	if s.closed {
		s.mu.Unlock()
		return nil
	}
	s.closed = true
	for c := range s.conns {
		_ = c.Close()
	}
	for u := range s.udps {
		_ = u.close()
	}
	s.mu.Unlock()
	err := s.ln.Close()
	s.wg.Wait()
	return err
}

func (s *Server) acceptLoop() {
	defer s.wg.Done()
	for {
		conn, err := s.ln.Accept()
		if err != nil {
			s.mu.Lock()
			closed := s.closed
			s.mu.Unlock()
			if !closed && s.logger != nil {
				s.logger.Printf("socks5: accept: %v", err)
			}
			return
		}
		s.mu.Lock()
		if s.closed {
			s.mu.Unlock()
			_ = conn.Close()
			return
		}
		s.conns[conn] = struct{}{}
		s.mu.Unlock()
		s.wg.Add(1)
		go func() {
			defer s.wg.Done()
			defer func() {
				s.mu.Lock()
				delete(s.conns, conn)
				s.mu.Unlock()
			}()
			s.handle(conn)
		}()
	}
}

// ---------------- handshake + request ----------------

func (s *Server) handle(conn net.Conn) {
	defer conn.Close()
	_ = conn.SetDeadline(time.Now().Add(handshakeTimeout))

	// greeting
	var head [2]byte
	if _, err := io.ReadFull(conn, head[:]); err != nil {
		return
	}
	if head[0] != ver5 {
		return
	}
	methods := make([]byte, head[1])
	if _, err := io.ReadFull(conn, methods); err != nil {
		return
	}
	// поддерживаем только NO AUTH (0x00)
	hasNoAuth := false
	for _, m := range methods {
		if m == 0x00 {
			hasNoAuth = true
		}
	}
	if !hasNoAuth {
		_, _ = conn.Write([]byte{ver5, 0xFF})
		return
	}
	if _, err := conn.Write([]byte{ver5, 0x00}); err != nil {
		return
	}

	// request
	var req [4]byte
	if _, err := io.ReadFull(conn, req[:]); err != nil {
		return
	}
	if req[0] != ver5 {
		return
	}
	addr, err := readAddr(conn, req[3])
	if err != nil {
		writeReply(conn, repGeneral, nil)
		return
	}

	_ = conn.SetDeadline(time.Time{})

	switch req[1] {
	case cmdConnect:
		s.handleConnect(conn, addr)
	case cmdUDPAssociate:
		s.handleUDPAssociate(conn, addr)
	case cmdBind:
		writeReply(conn, repCmdNotSupp, nil)
	default:
		writeReply(conn, repCmdNotSupp, nil)
	}
}

func readAddr(r io.Reader, atyp byte) (string, error) {
	switch atyp {
	case atypIPv4:
		var b [4]byte
		if _, err := io.ReadFull(r, b[:]); err != nil {
			return "", err
		}
		port, err := readPort(r)
		if err != nil {
			return "", err
		}
		return net.JoinHostPort(net.IP(b[:]).String(), itoa(port)), nil
	case atypDomain:
		var l [1]byte
		if _, err := io.ReadFull(r, l[:]); err != nil {
			return "", err
		}
		if l[0] == 0 || l[0] > maxDomainLen {
			return "", errors.New("socks5: bad domain length")
		}
		domain := make([]byte, l[0])
		if _, err := io.ReadFull(r, domain); err != nil {
			return "", err
		}
		port, err := readPort(r)
		if err != nil {
			return "", err
		}
		return net.JoinHostPort(string(domain), itoa(port)), nil
	case atypIPv6:
		var b [16]byte
		if _, err := io.ReadFull(r, b[:]); err != nil {
			return "", err
		}
		port, err := readPort(r)
		if err != nil {
			return "", err
		}
		return net.JoinHostPort(net.IP(b[:]).String(), itoa(port)), nil
	default:
		return "", fmt.Errorf("socks5: unsupported atyp %d", atyp)
	}
}

func readPort(r io.Reader) (int, error) {
	var b [2]byte
	if _, err := io.ReadFull(r, b[:]); err != nil {
		return 0, err
	}
	return int(binary.BigEndian.Uint16(b[:])), nil
}

func itoa(port int) string { return fmt.Sprintf("%d", port) }

func writeReply(conn net.Conn, rep byte, bnd net.Addr) error {
	reply := []byte{ver5, rep, 0x00, atypIPv4, 0, 0, 0, 0, 0, 0}
	if bnd != nil {
		if tcp, ok := bnd.(*net.TCPAddr); ok && tcp.IP.To4() != nil {
			copy(reply[4:8], tcp.IP.To4())
			binary.BigEndian.PutUint16(reply[8:10], uint16(tcp.Port))
		}
	}
	_, err := conn.Write(reply)
	return err
}

// ---------------- CONNECT ----------------

func (s *Server) handleConnect(conn net.Conn, addr string) {
	ctx, cancel := context.WithTimeout(context.Background(), 15*time.Second)
	defer cancel()

	remote, err := s.tun.DialTCP(ctx, addr)
	if err != nil {
		var rep byte = repHostUnreach
		var ne net.Error
		if errors.As(err, &ne) && ne.Timeout() {
			rep = repNetUnreach
		}
		if isRefused(err) {
			rep = repConnRefused
		}
		_ = writeReply(conn, rep, nil)
		if s.logger != nil {
			s.logger.Printf("socks5: CONNECT %s: %v", addr, err)
		}
		return
	}
	defer remote.Close()

	if err := writeReply(conn, repOK, remote.LocalAddr()); err != nil {
		return
	}
	relay(conn, remote, s.counters)
}

func isRefused(err error) bool {
	var se *net.OpError
	if errors.As(err, &se) {
		return se.Op == "dial" || se.Op == "connect"
	}
	return false
}

// relay — двунаправленная перекачка со счётчиками.
// Как только одно из направлений завершилось (EOF/ошибка) — закрываем оба
// конца, иначе вторая горутина останется висеть в Read навсегда.
func relay(client net.Conn, remote net.Conn, counters *tunnel.Counters) {
	var wg sync.WaitGroup
	wg.Add(2)
	done := make(chan struct{}, 2)

	copyDir := func(dst, src net.Conn, add func(int64)) {
		defer wg.Done()
		defer func() { done <- struct{}{} }()
		buf := make([]byte, 32*1024)
		for {
			n, err := src.Read(buf)
			if n > 0 {
				if _, werr := dst.Write(buf[:n]); werr != nil {
					return
				}
				add(int64(n))
			}
			if err != nil {
				return
			}
		}
	}

	go copyDir(remote, client, counters.AddSent) // браузер -> туннель
	go copyDir(client, remote, counters.AddRecv) // туннель -> браузер

	<-done // первое завершившееся направление
	_ = client.Close()
	_ = remote.Close()
	wg.Wait()
}

// ---------------- UDP ASSOCIATE ----------------

type udpSession struct {
	clientUDP  *net.UDPConn      // сокет, смотрящий в браузер
	session    tunnel.UDPSession // сессия через туннель
	clientAddr *net.UDPAddr      // откуда браузер шлёт дейтаграммы

	mu     sync.Mutex
	closed bool
}

func (u *udpSession) close() error {
	u.mu.Lock()
	defer u.mu.Unlock()
	if u.closed {
		return nil
	}
	u.closed = true
	err := u.clientUDP.Close()
	_ = u.session.Close()
	return err
}

func (s *Server) handleUDPAssociate(conn net.Conn, clientAddrStr string) {
	// локальный UDP-сокет для обмена с браузером
	clientUDP, err := net.ListenUDP("udp", &net.UDPAddr{IP: net.IPv4(127, 0, 0, 1), Port: 0})
	if err != nil {
		_ = writeReply(conn, repGeneral, nil)
		return
	}

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	session, err := s.tun.NewUDPSession(ctx)
	if err != nil {
		_ = clientUDP.Close()
		_ = writeReply(conn, repHostUnreach, nil)
		if s.logger != nil {
			s.logger.Printf("socks5: UDP ASSOCIATE: %v", err)
		}
		return
	}

	u := &udpSession{clientUDP: clientUDP, session: session}
	s.mu.Lock()
	if s.closed {
		s.mu.Unlock()
		_ = u.close()
		return
	}
	s.udps[u] = struct{}{}
	s.mu.Unlock()
	defer func() {
		s.mu.Lock()
		delete(s.udps, u)
		s.mu.Unlock()
		_ = u.close()
	}()

	bnd := clientUDP.LocalAddr().(*net.UDPAddr)
	if err := writeReply(conn, repOK, &net.TCPAddr{IP: bnd.IP.To4(), Port: bnd.Port}); err != nil {
		return
	}

	// браузер -> туннель
	go func() {
		buf := make([]byte, 65535)
		for {
			n, from, err := clientUDP.ReadFromUDP(buf)
			if err != nil {
				return
			}
			u.mu.Lock()
			if u.clientAddr == nil {
				u.clientAddr = from
			}
			u.mu.Unlock()
			dst, payload, ok := parseUDPHeader(buf[:n])
			if !ok || len(payload) == 0 {
				continue
			}
			s.counters.AddSent(int64(len(payload)))
			if _, err := session.WriteTo(payload, dst); err != nil && s.logger != nil {
				s.logger.Printf("socks5: udp write %s: %v", dst, err)
			}
		}
	}()

	// туннель -> браузер
	go func() {
		for {
			data, src, err := session.ReadFrom()
			if err != nil {
				return
			}
			u.mu.Lock()
			to := u.clientAddr
			u.mu.Unlock()
			if to == nil {
				continue
			}
			pkt := buildUDPHeader(src)
			pkt = append(pkt, data...)
			if _, err := clientUDP.WriteToUDP(pkt, to); err != nil {
				return
			}
			s.counters.AddRecv(int64(len(data)))
		}
	}()

	// по RFC сессия живёт, пока жива управляющая TCP-сессия
	buf := make([]byte, 1)
	_, _ = conn.Read(buf) // блокирует до закрытия
}

// parseUDPHeader разбирает заголовок SOCKS5 UDP по RFC 1928:
//
//	+----+------+------+----------+----------+----------+
//	|RSV | FRAG | ATYP | DST.ADDR | DST.PORT |   DATA   |
//	| 2  |  1   |  1   | Variable |    2     | Variable |
//	+----+------+------+----------+----------+----------+
func parseUDPHeader(p []byte) (dst string, payload []byte, ok bool) {
	if len(p) < 4 {
		return "", nil, false
	}
	if p[2] != 0 { // фрагментацию не поддерживаем
		return "", nil, false
	}
	atyp := p[3]
	switch atyp {
	case atypIPv4:
		if len(p) < 4+4+2 {
			return "", nil, false
		}
		ip := net.IP(p[4:8])
		port := binary.BigEndian.Uint16(p[8:10])
		return net.JoinHostPort(ip.String(), itoa(int(port))), p[10:], true
	case atypDomain:
		if len(p) < 5 {
			return "", nil, false
		}
		dl := int(p[4])
		if dl == 0 || len(p) < 5+dl+2 {
			return "", nil, false
		}
		domain := string(p[5 : 5+dl])
		port := binary.BigEndian.Uint16(p[5+dl : 7+dl])
		return net.JoinHostPort(domain, itoa(int(port))), p[7+dl:], true
	case atypIPv6:
		if len(p) < 4+16+2 {
			return "", nil, false
		}
		ip := net.IP(p[4:20])
		port := binary.BigEndian.Uint16(p[20:22])
		return net.JoinHostPort(ip.String(), itoa(int(port))), p[22:], true
	default:
		return "", nil, false
	}
}

// buildUDPHeader строит ответный заголовок того же формата (RSV=0, FRAG=0).
func buildUDPHeader(src string) []byte {
	host, portStr, err := net.SplitHostPort(src)
	if err != nil {
		return []byte{0, 0, 0, atypIPv4, 0, 0, 0, 0, 0, 0}
	}
	port := 0
	fmt.Sscanf(portStr, "%d", &port)
	ip := net.ParseIP(host)
	if ip == nil {
		// домен в ответе не используется; Firefox принимает IPv4-форму —
		// Firefox принимает IPv4-форму; адрес источника важен только для ассоциации
		return []byte{0, 0, 0, atypIPv4, 0, 0, 0, 0, byte(port >> 8), byte(port)}
	}
	if v4 := ip.To4(); v4 != nil {
		out := []byte{0, 0, 0, atypIPv4}
		out = append(out, v4...)
		out = append(out, byte(port>>8), byte(port))
		return out
	}
	v6 := ip.To16()
	out := []byte{0, 0, 0, atypIPv6}
	out = append(out, v6...)
	out = append(out, byte(port>>8), byte(port))
	return out
}
