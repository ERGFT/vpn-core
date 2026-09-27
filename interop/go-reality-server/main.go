// SPDX-License-Identifier: GPL-3.0-or-later
// Интероп-стенд (PLAN.md, "План дальнейших действий", шаг 2): настоящий
// REALITY-сервер на библиотеке github.com/xtls/reality — той же, что
// использует Xray-core, — чтобы проверять клиента reality-core против
// ЧУЖОЙ серверной реализации, а не против собственного тестового сервера.
//
// Что поднимается:
//   - "сайт-приманка" (dest): обычный Go crypto/tls TLS 1.3 сервер с
//     самоподписанным сертификатом на loopback. REALITY пересылает ему
//     ClientHello и копирует параметры его ServerHello — ровно как в
//     бою с настоящим сайтом;
//   - REALITY-сервер: reality.Server(...) поверх каждого входящего TCP;
//   - после рукопожатия — "VLESS-lite": разбор заголовка запроса VLESS
//     (проверка UUID) и эхо данных. Заголовок ответа отправляется ТОЛЬКО
//     вместе с первыми данными, как у Xray-core (inbound.go:
//     EncodeResponseHeader + SetFlushNext), — чтобы этот же стенд ловил
//     дедлок, исправленный в шаге 1б.
//
// Это тестовый стенд, не прокси: наружу он никуда не ходит, эхо-ответ
// формируется локально.
//
// Протокол с тестом: при готовности печатает в stdout строку
// "READY <порт REALITY-сервера>"; каждое событие — строкой "EVENT ...".
package main

import (
	"bufio"
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/hex"
	"flag"
	"fmt"
	"io"
	"math/big"
	"net"
	"os"
	"strings"
	"time"

	"github.com/xtls/reality"
)

func must(err error) {
	if err != nil {
		fmt.Fprintln(os.Stderr, "FATAL:", err)
		os.Exit(1)
	}
}

func selfSigned(sni string) tls.Certificate {
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	must(err)
	tmpl := &x509.Certificate{
		SerialNumber: big.NewInt(1),
		Subject:      pkix.Name{CommonName: sni},
		DNSNames:     []string{sni},
		NotBefore:    time.Now().Add(-time.Hour),
		NotAfter:     time.Now().Add(24 * time.Hour),
	}
	der, err := x509.CreateCertificate(rand.Reader, tmpl, tmpl, &key.PublicKey, key)
	must(err)
	return tls.Certificate{Certificate: [][]byte{der}, PrivateKey: key}
}

// Сайт-приманка: TLS 1.3, после рукопожатия просто вычитывает всё.
func startDest(sni string) string {
	cfg := &tls.Config{
		Certificates: []tls.Certificate{selfSigned(sni)},
		MinVersion:   tls.VersionTLS13,
		NextProtos:   []string{"h2", "http/1.1"},
	}
	l, err := tls.Listen("tcp", "127.0.0.1:0", cfg)
	must(err)
	go func() {
		for {
			c, err := l.Accept()
			if err != nil {
				return
			}
			go func() {
				defer c.Close()
				io.Copy(io.Discard, c)
			}()
		}
	}()
	return l.Addr().String()
}

func main() {
	privHex := flag.String("private-key", "", "X25519 private key сервера, hex (32 байта)")
	shortIDHex := flag.String("short-id", "", "ShortId, hex (0-16 символов)")
	sni := flag.String("sni", "example.com", "разрешённое имя сервера")
	uuidHex := flag.String("uuid", "", "UUID пользователя VLESS, 32 hex-символа без дефисов")
	maxTimeDiff := flag.Duration("max-time-diff", time.Minute, "допустимое расхождение времени клиента")
	show := flag.Bool("show", false, "подробный лог REALITY")
	minVer := flag.String("min-client-ver", "", "minClientVer, например 26.0.0")
	maxVer := flag.String("max-client-ver", "", "maxClientVer, например 26.99.99")
	flag.Parse()

	priv, err := hex.DecodeString(*privHex)
	must(err)
	if len(priv) != 32 {
		must(fmt.Errorf("private-key: нужно 32 байта, получено %d", len(priv)))
	}
	var sid [8]byte
	sidBytes, err := hex.DecodeString(*shortIDHex)
	must(err)
	copy(sid[:], sidBytes)
	uuid, err := hex.DecodeString(strings.ReplaceAll(*uuidHex, "-", ""))
	must(err)
	if len(uuid) != 16 {
		must(fmt.Errorf("uuid: нужно 16 байт"))
	}

	dest := startDest(*sni)
	var dialer net.Dialer
	cfg := &reality.Config{
		DialContext: dialer.DialContext,
		Show:        *show,
		Type:        "tcp",
		Dest:        dest,
		ServerNames: map[string]bool{*sni: true},
		PrivateKey:  priv,
		MaxTimeDiff: *maxTimeDiff,
		ShortIds:    map[[8]byte]bool{sid: true},
		// Как в Xray-core (transport/internet/reality/config.go):
		SessionTicketsDisabled: true,
		MinClientVer:           parseVer(*minVer),
		MaxClientVer:           parseVer(*maxVer),
	}

	// Как reality.NewListener: заранее узнать длины post-handshake-записей
	// приманки. Без этого reality.Server ждёт результата в цикле с
	// паузами по 5 секунд — ждём здесь, до READY.
	reality.DetectPostHandshakeRecordsLens(cfg)
	deadline := time.Now().Add(20 * time.Second)
	for time.Now().Before(deadline) {
		done := true
		for alpn := range 3 {
			key := fmt.Sprintf("%s %s %d", dest, *sni, alpn)
			v, ok := reality.GlobalPostHandshakeRecordsLens.Load(key)
			if !ok {
				done = false
				break
			}
			if _, isBool := v.(bool); isBool {
				done = false
				break
			}
		}
		if done {
			break
		}
		time.Sleep(50 * time.Millisecond)
	}

	l, err := net.Listen("tcp", "127.0.0.1:0")
	must(err)
	out := bufio.NewWriter(os.Stdout)
	emit := func(format string, a ...any) {
		fmt.Fprintf(out, format+"\n", a...)
		out.Flush()
	}
	emit("READY %d", l.Addr().(*net.TCPAddr).Port)

	for {
		c, err := l.Accept()
		if err != nil {
			return
		}
		go func() {
			defer c.Close()
			conn, err := reality.Server(context.Background(), c, cfg)
			if err != nil {
				emit("EVENT reality-fail %v", err)
				return
			}
			st := conn.ConnectionState()
			emit("EVENT reality-ok version=%x cipher=%x", st.Version, st.CipherSuite)
			handleVlessLite(conn, uuid, emit)
		}()
	}
}

// "26.9.9" -> []byte{26, 9, 9}; пусто -> nil (без ограничения), как в
// Xray-core (infra/conf/transport_internet.go).
func parseVer(v string) []byte {
	if v == "" {
		return nil
	}
	out := make([]byte, 3)
	for i, part := range strings.SplitN(v, ".", 3) {
		var n int
		fmt.Sscanf(part, "%d", &n)
		out[i] = byte(n)
	}
	return out
}

func handleVlessLite(c net.Conn, uuid []byte, emit func(string, ...any)) {
	r := bufio.NewReader(c)
	hdr := make([]byte, 18) // версия + UUID + длина addons
	if _, err := io.ReadFull(r, hdr); err != nil {
		emit("EVENT vless-fail header: %v", err)
		return
	}
	if hdr[0] != 0 || string(hdr[1:17]) != string(uuid) {
		emit("EVENT vless-fail bad version/uuid")
		return
	}
	addons := make([]byte, hdr[17])
	if _, err := io.ReadFull(r, addons); err != nil {
		emit("EVENT vless-fail addons: %v", err)
		return
	}
	cmdPortAtyp := make([]byte, 4)
	if _, err := io.ReadFull(r, cmdPortAtyp); err != nil {
		emit("EVENT vless-fail cmd: %v", err)
		return
	}
	var addr string
	switch cmdPortAtyp[3] {
	case 1:
		b := make([]byte, 4)
		io.ReadFull(r, b)
		addr = net.IP(b).String()
	case 2:
		l, _ := r.ReadByte()
		b := make([]byte, l)
		io.ReadFull(r, b)
		addr = string(b)
	case 3:
		b := make([]byte, 16)
		io.ReadFull(r, b)
		addr = net.IP(b).String()
	}
	port := int(cmdPortAtyp[1])<<8 | int(cmdPortAtyp[2])
	emit("EVENT vless-ok cmd=%d target=%s:%d addons=%x", cmdPortAtyp[0], addr, port, addons)

	// Эхо; заголовок ответа [0, 0] уходит только с первыми данными
	// (SetFlushNext у Xray-core).
	buf := make([]byte, 16*1024)
	first := true
	for {
		n, err := r.Read(buf)
		if n > 0 {
			var msg []byte
			if first {
				msg = append([]byte{0, 0}, buf[:n]...)
				first = false
			} else {
				msg = buf[:n]
			}
			if _, werr := c.Write(msg); werr != nil {
				return
			}
		}
		if err != nil {
			return
		}
	}
}
