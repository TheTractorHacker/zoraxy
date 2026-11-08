// e2ehelper: small Go programs the python e2e harness needs because python's stdlib cannot do them.
//
//	e2ehelper h2c-server -addr 127.0.0.1:PORT       h2c (cleartext HTTP/2) gRPC-style server
//	e2ehelper h2c-client -url http://host:port/path  prior-knowledge h2c client, prints JSON result
//	e2ehelper ech-client -addr HOST:PORT -sni NAME [-ech BASE64] [-path /]   TLS client with Encrypted Client Hello
//	e2ehelper tls-client -addr HOST:PORT -sni NAME [-cert F -key F] [-http2]  plain TLS GET, prints JSON result
package main

import (
	"crypto/tls"
	"encoding/base64"
	"encoding/binary"
	"encoding/json"
	"errors"
	"flag"
	"fmt"
	"io"
	"net"
	"net/http"
	"os"
	"strings"
	"time"

	"golang.org/x/net/http2"
	"golang.org/x/net/http2/h2c"
)

func main() {
	if len(os.Args) < 2 {
		fmt.Fprintln(os.Stderr, "usage: e2ehelper h2c-server|h2c-client|ech-client|tls-client")
		os.Exit(2)
	}
	cmd := os.Args[1]
	fs := flag.NewFlagSet(cmd, flag.ExitOnError)
	addr := fs.String("addr", "127.0.0.1:0", "address")
	url := fs.String("url", "", "url")
	sni := fs.String("sni", "", "server name")
	echB64 := fs.String("ech", "", "base64 ECHConfigList")
	path := fs.String("path", "/", "request path")
	cert := fs.String("cert", "", "client cert")
	key := fs.String("key", "", "client key")
	useH2 := fs.Bool("http2", false, "offer h2")
	fs.Parse(os.Args[2:])
	switch cmd {
	case "h2c-server":
		h2cServer(*addr)
	case "h2c-client":
		runH2C(*url, *sni)
	case "ech-client":
		tlsClient(*addr, *sni, *echB64, *path, "", "", false)
	case "tls-client":
		tlsClient(*addr, *sni, "", *path, *cert, *key, *useH2)
	default:
		fmt.Fprintln(os.Stderr, "unknown command")
		os.Exit(2)
	}
}

// grpc frame: 1 byte flag, 4 bytes length, payload
func grpcFrame(p []byte) []byte {
	b := make([]byte, 5+len(p))
	binary.BigEndian.PutUint32(b[1:], uint32(len(p)))
	copy(b[5:], p)
	return b
}

func h2cServer(addr string) {
	mux := http.NewServeMux()
	// unary: replies with a framed payload and trailers like a real gRPC server
	mux.HandleFunc("/e2e.Svc/Unary", func(w http.ResponseWriter, r *http.Request) {
		body, _ := io.ReadAll(r.Body)
		w.Header().Set("Content-Type", "application/grpc")
		w.Header().Set("Trailer", "Grpc-Status, Grpc-Message, X-Proto")
		w.WriteHeader(200)
		w.Write(grpcFrame([]byte(fmt.Sprintf("unary proto=%d len=%d te=%s", r.ProtoMajor, len(body), r.Header.Get("Te")))))
		w.Header().Set("Grpc-Status", "0")
		w.Header().Set("Grpc-Message", "ok")
		w.Header().Set("X-Proto", fmt.Sprint(r.ProtoMajor))
	})
	// bidi: echoes every received chunk immediately (needs full duplex streaming)
	mux.HandleFunc("/e2e.Svc/Bidi", func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/grpc")
		w.Header().Set("Trailer", "Grpc-Status")
		w.WriteHeader(200)
		fl, _ := w.(http.Flusher)
		if fl != nil {
			fl.Flush()
		}
		buf := make([]byte, 4096)
		for {
			n, err := r.Body.Read(buf)
			if n > 0 {
				w.Write(append([]byte("echo:"), buf[:n]...))
				if fl != nil {
					fl.Flush()
				}
			}
			if err != nil {
				break
			}
		}
		w.Header().Set("Grpc-Status", "0")
	})
	mux.HandleFunc("/", func(w http.ResponseWriter, r *http.Request) {
		json.NewEncoder(w).Encode(map[string]any{"proto": r.Proto, "path": r.URL.Path, "host": r.Host})
	})
	ln, err := net.Listen("tcp", addr)
	if err != nil {
		fmt.Fprintln(os.Stderr, err)
		os.Exit(1)
	}
	fmt.Println("listening", ln.Addr())
	srv := &http.Server{Handler: h2c.NewHandler(mux, &http2.Server{})}
	srv.Serve(ln)
}

func report(v any) {
	json.NewEncoder(os.Stdout).Encode(v)
}

func tlsClient(addr, sni, echB64, path, cert, key string, h2 bool) {
	cfg := &tls.Config{ServerName: sni, InsecureSkipVerify: true, MinVersion: tls.VersionTLS13}
	if !h2 {
		cfg.NextProtos = []string{"http/1.1"}
	} else {
		cfg.NextProtos = []string{"h2", "http/1.1"}
	}
	if echB64 != "" {
		raw, err := base64.StdEncoding.DecodeString(echB64)
		if err != nil {
			report(map[string]any{"error": "bad ech b64: " + err.Error()})
			return
		}
		cfg.EncryptedClientHelloConfigList = raw
		cfg.MinVersion = tls.VersionTLS13
	}
	if cert != "" {
		c, err := tls.LoadX509KeyPair(cert, key)
		if err != nil {
			report(map[string]any{"error": err.Error()})
			return
		}
		cfg.Certificates = []tls.Certificate{c}
		cfg.MinVersion = tls.VersionTLS12
	}
	d := net.Dialer{Timeout: 5 * time.Second}
	raw, err := d.Dial("tcp", addr)
	if err != nil {
		report(map[string]any{"error": err.Error()})
		return
	}
	defer raw.Close()
	c := tls.Client(raw, cfg)
	c.SetDeadline(time.Now().Add(10 * time.Second))
	if err := c.Handshake(); err != nil {
		out := map[string]any{"error": err.Error()}
		var re *tls.ECHRejectionError
		if errors.As(err, &re) {
			out["ech_rejected"] = true
			out["retry_config_len"] = len(re.RetryConfigList)
			out["retry_config_b64"] = base64.StdEncoding.EncodeToString(re.RetryConfigList)
		}
		report(out)
		return
	}
	st := c.ConnectionState()
	out := map[string]any{"ech_accepted": st.ECHAccepted, "alpn": st.NegotiatedProtocol, "version": st.Version}
	if len(st.PeerCertificates) > 0 {
		out["peer_cn"] = st.PeerCertificates[0].Subject.CommonName
	}
	if st.NegotiatedProtocol != "h2" {
		fmt.Fprintf(c, "GET %s HTTP/1.1\r\nHost: %s\r\nConnection: close\r\n\r\n", path, sni)
		b, _ := io.ReadAll(c)
		s := string(b)
		if i := strings.Index(s, "\r\n"); i > 0 {
			out["status_line"] = s[:i]
		}
		if i := strings.Index(s, "\r\n\r\n"); i > 0 {
			out["body"] = s[i+4:]
		}
	}
	report(out)
}
