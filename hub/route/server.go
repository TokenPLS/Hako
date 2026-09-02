package route

import (
	"bytes"
	"context"
	"crypto/subtle"
	"encoding/json"
	"net"
	"os"
	"path/filepath"
	"runtime/debug"
	"strings"
	"sync"
	"syscall"
	"time"

	"github.com/TokenPLS/Hako/adapter/inbound"
	"github.com/TokenPLS/Hako/common/utils"
	"github.com/TokenPLS/Hako/component/ca"
	"github.com/TokenPLS/Hako/component/ech"
	C "github.com/TokenPLS/Hako/constant"
	"github.com/TokenPLS/Hako/log"
	"github.com/TokenPLS/Hako/ntp"
	"github.com/TokenPLS/Hako/tunnel/statistic"

	"github.com/metacubex/chi"
	"github.com/metacubex/chi/cors"
	"github.com/metacubex/chi/middleware"
	"github.com/metacubex/chi/render"
	"github.com/metacubex/http"
	"github.com/metacubex/tls"
)

var (
	uiPath = ""

	httpServer *http.Server
	tlsServer  *http.Server
	unixServer *http.Server
	pipeServer *http.Server

	httpListener net.Listener
	tlsListener  net.Listener
	unixListener net.Listener
	pipeListener net.Listener
	serverMu     sync.Mutex

	embedMode = false
)

func SetEmbedMode(embed bool) {
	embedMode = embed
}

// geoUpdaterAllowed decides whether the two routes that download geo databases inside the
// process are served. It is separate from embedMode because the reason for closing them is
// separate: not "an embedded core must not reconfigure itself", but a measured memory ceiling
// that belongs to ONE platform.
//
// An iOS packet tunnel was measured dying at 49.5 MiB, and GeoIP.dat is 17 MB to fetch and
// unpack. A macOS app extension was measured living steadily at 62.4 MiB with no limit
// configured, which does not prove the download fits -- it proves the iOS ceiling is not there.
// The product rule this follows is explicit: implement every upstream capability, and where iOS
// cannot, implementing it on macOS alone is an acceptable outcome.
//
// Default false, so a caller that never speaks keeps today's behaviour on every platform.
var geoUpdaterAllowed = false

// SetGeoUpdaterAllowed permits the in-process geo updater routes. The binding sets it from the
// runtime profile.
func SetGeoUpdaterAllowed(allowed bool) {
	geoUpdaterAllowed = allowed
}

type Traffic struct {
	Up        int64 `json:"up"`
	Down      int64 `json:"down"`
	UpTotal   int64 `json:"upTotal"`
	DownTotal int64 `json:"downTotal"`
}

type Memory struct {
	Inuse   uint64 `json:"inuse"`
	OSLimit uint64 `json:"oslimit"` // maybe we need it in the future
}

type Config struct {
	Addr           string
	TLSAddr        string
	UnixAddr       string
	PipeAddr       string
	RoutingMark    int
	Secret         string
	Certificate    string
	PrivateKey     string
	ClientAuthType string
	ClientAuthCert string
	EchKey         string
	DohServer      string
	IsDebug        bool
	Cors           Cors
}

type Cors struct {
	AllowOrigins        []string
	AllowPrivateNetwork bool
}

func (c Cors) Apply(r chi.Router) {
	r.Use(cors.New(cors.Options{
		AllowedOrigins:      c.AllowOrigins,
		AllowedMethods:      []string{"GET", "POST", "PUT", "PATCH", "DELETE"},
		AllowedHeaders:      []string{"Content-Type", "Authorization"},
		AllowPrivateNetwork: c.AllowPrivateNetwork,
		MaxAge:              300,
	}).Handler)
}

func ReCreateServer(cfg *Config) {
	// Listener replacement is one synchronous control-plane transaction. Each
	// start helper only launches Serve after publishing its new server, so a
	// following recreate cannot race an older stop goroutine over the global
	// pointers or Unix pathname (important for in-process NE restart).
	serverMu.Lock()
	defer serverMu.Unlock()
	start(cfg)
	startTLS(cfg)
	startUnix(cfg)
	if inbound.SupportNamedPipe {
		startPipe(cfg)
	}
}

func SetUIPath(path string) {
	uiPath = C.Path.Resolve(path)
}

func router(isDebug bool, secret string, dohServer string, cors Cors) *chi.Mux {
	r := chi.NewRouter()
	cors.Apply(r)
	r.Group(func(r chi.Router) {
		if secret != "" {
			r.Use(authentication(secret))
		}
		// Inside the authenticated group, not beside it. A pprof heap profile
		// carries proxy server addresses, subscription URLs and whatever
		// credential material is resident, and this fork wires isDebug to the
		// configuration's own log-level (bind/hako/external_controller.go) --
		// so leaving it outside meant a subscription could write `log-level:
		// debug` plus an external-controller on 0.0.0.0 and publish a profiler
		// to the local network, secret or no secret. It stays exactly as
		// available to whoever holds the secret as it was.
		if isDebug {
			r.Mount("/debug", func() http.Handler {
				r := chi.NewRouter()
				r.Put("/gc", func(w http.ResponseWriter, r *http.Request) {
					debug.FreeOSMemory()
				})
				handler := middleware.Profiler
				r.Mount("/", handler())
				return r
			}())
		}
		r.Get("/", hello)
		r.Get("/logs", getLogs)
		r.Get("/traffic", traffic)
		r.Get("/memory", memory)
		r.Get("/version", version)
		r.Mount("/configs", configRouter())
		r.Mount("/proxies", proxyRouter())
		r.Mount("/group", groupRouter())
		r.Mount("/rules", ruleRouter())
		r.Mount("/connections", connectionRouter())
		r.Mount("/providers/proxies", proxyProviderRouter())
		r.Mount("/providers/rules", ruleProviderRouter())
		r.Mount("/cache", cacheRouter())
		r.Mount("/dns", dnsRouter())
		r.Mount("/storage", storageRouter())
		if !embedMode { // disallow restart in embed mode
			r.Mount("/restart", restartRouter())
		}
		r.Mount("/upgrade", upgradeRouter())
		addExternalRouters(r)

	})

	if uiPath != "" {
		r.Group(func(r chi.Router) {
			uiFS := http.FileSystem(http.Dir(uiPath))
			if embedMode {
				// A sandboxed extension answers EPERM to the sendfile upgrade
				// and Go kills the copy mid-file; see hako_ui_fs.go. Ordinary
				// mihomo keeps the upstream fast path.
				uiFS = hakoUserspaceFileSystem{uiFS}
			}
			fs := http.StripPrefix("/ui", http.FileServer(uiFS))
			r.Get("/ui", http.RedirectHandler("/ui/", http.StatusTemporaryRedirect).ServeHTTP)
			r.Get("/ui/*", func(w http.ResponseWriter, r *http.Request) {
				fs.ServeHTTP(w, r)
			})
		})
	}
	if len(dohServer) > 0 && dohServer[0] == '/' {
		r.Mount(dohServer, dohRouter())
	}

	return r
}

func start(cfg *Config) {
	// first stop existing server
	if httpListener != nil {
		_ = httpListener.Close()
		httpListener = nil
	}
	if httpServer != nil {
		_ = httpServer.Close()
		httpServer = nil
	}

	// handle addr
	if len(cfg.Addr) > 0 {
		lc := inbound.NewListenConfig()
		lc.SetRouteMark(cfg.RoutingMark)
		l, err := lc.Listen(context.Background(), "tcp", cfg.Addr)
		if err != nil {
			log.Errorln("External controller listen error: %s", err)
			return
		}
		log.Infoln("RESTful API listening at: %s", l.Addr().String())

		server := &http.Server{
			Handler: router(cfg.IsDebug, cfg.Secret, cfg.DohServer, cfg.Cors),
		}
		httpServer = server
		httpListener = l
		go func() {
			if serveErr := server.Serve(l); serveErr != nil {
				log.Errorln("External controller serve error: %s", serveErr)
			}
		}()
	}
}

func startTLS(cfg *Config) {
	// first stop existing server
	if tlsListener != nil {
		_ = tlsListener.Close()
		tlsListener = nil
	}
	if tlsServer != nil {
		_ = tlsServer.Close()
		tlsServer = nil
	}

	// handle tlsAddr
	if len(cfg.TLSAddr) > 0 {
		certLoader, err := ca.NewTLSKeyPairLoader(cfg.Certificate, cfg.PrivateKey)
		if err != nil {
			log.Errorln("External controller tls listen error: %s", err)
			return
		}

		lc := inbound.NewListenConfig()
		lc.SetRouteMark(cfg.RoutingMark)
		l, err := lc.Listen(context.Background(), "tcp", cfg.TLSAddr)
		if err != nil {
			log.Errorln("External controller tls listen error: %s", err)
			return
		}

		log.Infoln("RESTful API tls listening at: %s", l.Addr().String())
		tlsConfig := &tls.Config{Time: ntp.Now}
		tlsConfig.NextProtos = []string{"h2", "http/1.1"}
		tlsConfig.GetCertificate = func(*tls.ClientHelloInfo) (*tls.Certificate, error) {
			return certLoader()
		}
		tlsConfig.ClientAuth = ca.ClientAuthTypeFromString(cfg.ClientAuthType)
		if len(cfg.ClientAuthCert) > 0 {
			if tlsConfig.ClientAuth == tls.NoClientCert {
				tlsConfig.ClientAuth = tls.RequireAndVerifyClientCert
			}
		}
		if tlsConfig.ClientAuth == tls.VerifyClientCertIfGiven || tlsConfig.ClientAuth == tls.RequireAndVerifyClientCert {
			pool, err := ca.LoadCertificates(cfg.ClientAuthCert)
			if err != nil {
				log.Errorln("External controller tls listen error: %s", err)
				return
			}
			tlsConfig.ClientCAs = pool
		}

		if cfg.EchKey != "" {
			err = ech.LoadECHKey(cfg.EchKey, tlsConfig)
			if err != nil {
				log.Errorln("External controller tls serve error: %s", err)
				return
			}
		}
		server := &http.Server{
			Handler: router(cfg.IsDebug, cfg.Secret, cfg.DohServer, cfg.Cors),
		}
		tlsServer = server
		tlsListener = tls.NewListener(l, tlsConfig)
		listener := tlsListener
		go func() {
			if serveErr := server.Serve(listener); serveErr != nil {
				log.Errorln("External controller tls serve error: %s", serveErr)
			}
		}()
	}
}

func startUnix(cfg *Config) {
	// first stop existing server
	if unixListener != nil {
		_ = unixListener.Close()
		unixListener = nil
	}
	if unixServer != nil {
		_ = unixServer.Close()
		unixServer = nil
	}

	// handle addr
	if len(cfg.UnixAddr) > 0 {
		addr := C.Path.Resolve(cfg.UnixAddr)

		dir := filepath.Dir(addr)
		if _, err := os.Stat(dir); os.IsNotExist(err) {
			if err := os.MkdirAll(dir, 0o755); err != nil {
				log.Errorln("External controller unix listen error: %s", err)
				return
			}
		}

		// https://devblogs.microsoft.com/commandline/af_unix-comes-to-windows/
		//
		// Note: As mentioned above in the ‘security’ section, when a socket binds a socket to a valid pathname address,
		// a socket file is created within the filesystem. On Linux, the application is expected to unlink
		// (see the notes section in the man page for AF_UNIX) before any other socket can be bound to the same address.
		// The same applies to Windows unix sockets, except that, DeleteFile (or any other file delete API)
		// should be used to delete the socket file prior to calling bind with the same path.
		_ = syscall.Unlink(addr)

		lc := inbound.NewListenConfig()
		lc.SetRouteMark(0) // don't set route mark for unix socket
		l, err := lc.Listen(context.Background(), "unix", addr)
		if err != nil {
			log.Errorln("External controller unix listen error: %s", err)
			return
		}
		_ = os.Chmod(addr, 0o666)
		log.Infoln("RESTful API unix listening at: %s", l.Addr().String())

		server := &http.Server{
			Handler: router(cfg.IsDebug, "", cfg.DohServer, cfg.Cors),
		}
		unixServer = server
		unixListener = l
		go func() {
			if serveErr := server.Serve(l); serveErr != nil {
				log.Errorln("External controller unix serve error: %s", serveErr)
			}
		}()
	}
}

func startPipe(cfg *Config) {
	// first stop existing server
	if pipeListener != nil {
		_ = pipeListener.Close()
		pipeListener = nil
	}
	if pipeServer != nil {
		_ = pipeServer.Close()
		pipeServer = nil
	}

	// handle addr
	if len(cfg.PipeAddr) > 0 {
		if !strings.HasPrefix(cfg.PipeAddr, "\\\\.\\pipe\\") { // windows namedpipe must start with "\\.\pipe\"
			log.Errorln("External controller pipe listen error: windows namedpipe must start with \"\\\\.\\pipe\\\"")
			return
		}

		l, err := inbound.ListenNamedPipe(cfg.PipeAddr)
		if err != nil {
			log.Errorln("External controller pipe listen error: %s", err)
			return
		}
		log.Infoln("RESTful API pipe listening at: %s", l.Addr().String())

		server := &http.Server{
			Handler: router(cfg.IsDebug, "", cfg.DohServer, cfg.Cors),
		}
		pipeServer = server
		pipeListener = l
		go func() {
			if serveErr := server.Serve(l); serveErr != nil {
				log.Errorln("External controller pipe serve error: %s", serveErr)
			}
		}()
	}
}

func safeEqual(a, b string) bool {
	aBuf := utils.ImmutableBytesFromString(a)
	bBuf := utils.ImmutableBytesFromString(b)
	return subtle.ConstantTimeCompare(aBuf, bBuf) == 1
}

func authentication(secret string) func(http.Handler) http.Handler {
	return func(next http.Handler) http.Handler {
		fn := func(w http.ResponseWriter, r *http.Request) {
			// Browser websocket not support custom header
			if r.Header.Get("Upgrade") == "websocket" && r.URL.Query().Get("token") != "" {
				token := r.URL.Query().Get("token")
				if !safeEqual(token, secret) {
					render.Status(r, http.StatusUnauthorized)
					render.JSON(w, r, ErrUnauthorized)
					return
				}
				next.ServeHTTP(w, r)
				return
			}

			header := r.Header.Get("Authorization")
			bearer, token, found := strings.Cut(header, " ")

			hasInvalidHeader := bearer != "Bearer"
			hasInvalidSecret := !found || !safeEqual(token, secret)
			if hasInvalidHeader || hasInvalidSecret {
				render.Status(r, http.StatusUnauthorized)
				render.JSON(w, r, ErrUnauthorized)
				return
			}
			next.ServeHTTP(w, r)
		}
		return http.HandlerFunc(fn)
	}
}

func hello(w http.ResponseWriter, r *http.Request) {
	render.JSON(w, r, render.M{"hello": "mihomo"})
}

func traffic(w http.ResponseWriter, r *http.Request) {
	var wsConn net.Conn
	if r.Header.Get("Upgrade") == "websocket" {
		var err error
		wsConn, _, err = wsUpgrade(r, w)
		if err != nil {
			return
		}
	}

	if wsConn == nil {
		w.Header().Set("Content-Type", "application/json")
		render.Status(r, http.StatusOK)
	}

	tick := time.NewTicker(time.Second)
	defer tick.Stop()
	t := statistic.DefaultManager
	onlyProxy := r.URL.Query().Get("only-proxy") == "true"
	buf := &bytes.Buffer{}
	var err error
	for range tick.C {
		buf.Reset()
		up, down := t.NowTraffic(onlyProxy)
		upTotal, downTotal := t.TotalTraffic(onlyProxy)
		if err := json.NewEncoder(buf).Encode(Traffic{
			Up:        up,
			Down:      down,
			UpTotal:   upTotal,
			DownTotal: downTotal,
		}); err != nil {
			break
		}

		if wsConn == nil {
			_, err = w.Write(buf.Bytes())
			w.(http.Flusher).Flush()
		} else {
			err = wsWriteServerText(wsConn, buf.Bytes())
		}

		if err != nil {
			break
		}
	}
}

func memory(w http.ResponseWriter, r *http.Request) {
	var wsConn net.Conn
	if r.Header.Get("Upgrade") == "websocket" {
		var err error
		wsConn, _, err = wsUpgrade(r, w)
		if err != nil {
			return
		}
	}

	if wsConn == nil {
		w.Header().Set("Content-Type", "application/json")
		render.Status(r, http.StatusOK)
	}

	tick := time.NewTicker(time.Second)
	defer tick.Stop()
	t := statistic.DefaultManager
	buf := &bytes.Buffer{}
	var err error
	first := true
	for range tick.C {
		buf.Reset()

		inuse := t.Memory()
		// make chat.js begin with zero
		// this is shit var,but we need output 0 for first time
		if first {
			inuse = 0
			first = false
		}
		if err := json.NewEncoder(buf).Encode(Memory{
			Inuse:   inuse,
			OSLimit: 0,
		}); err != nil {
			break
		}
		if wsConn == nil {
			_, err = w.Write(buf.Bytes())
			w.(http.Flusher).Flush()
		} else {
			err = wsWriteServerText(wsConn, buf.Bytes())
		}

		if err != nil {
			break
		}
	}
}

type Log struct {
	Type    string `json:"type"`
	Payload string `json:"payload"`
}
type LogStructuredField struct {
	Key   string `json:"key"`
	Value string `json:"value"`
}
type LogStructured struct {
	Time    string               `json:"time"`
	Level   string               `json:"level"`
	Message string               `json:"message"`
	Fields  []LogStructuredField `json:"fields"`
}

func getLogs(w http.ResponseWriter, r *http.Request) {
	levelText := r.URL.Query().Get("level")
	if levelText == "" {
		levelText = "info"
	}

	formatText := r.URL.Query().Get("format")
	isStructured := false
	if formatText == "structured" {
		isStructured = true
	}

	level, ok := log.LogLevelMapping[levelText]
	if !ok {
		render.Status(r, http.StatusBadRequest)
		render.JSON(w, r, ErrBadRequest)
		return
	}

	var wsConn net.Conn
	if r.Header.Get("Upgrade") == "websocket" {
		var err error
		wsConn, _, err = wsUpgrade(r, w)
		if err != nil {
			return
		}
	}

	if wsConn == nil {
		w.Header().Set("Content-Type", "application/json")
		render.Status(r, http.StatusOK)
	}

	ch := make(chan log.Event, 1024)
	sub := log.Subscribe()
	defer log.UnSubscribe(sub)
	buf := &bytes.Buffer{}

	go func() {
		for logM := range sub {
			select {
			case ch <- logM:
			default:
			}
		}
		close(ch)
	}()

	for logM := range ch {
		if logM.LogLevel < level {
			continue
		}
		buf.Reset()

		if !isStructured {
			if err := json.NewEncoder(buf).Encode(Log{
				Type:    logM.Type(),
				Payload: logM.Payload,
			}); err != nil {
				break
			}
		} else {
			newLevel := logM.Type()
			if newLevel == "warning" {
				newLevel = "warn"
			}
			if err := json.NewEncoder(buf).Encode(LogStructured{
				Time:    time.Now().Format(time.TimeOnly),
				Level:   newLevel,
				Message: logM.Payload,
				Fields:  []LogStructuredField{},
			}); err != nil {
				break
			}
		}

		var err error
		if wsConn == nil {
			_, err = w.Write(buf.Bytes())
			w.(http.Flusher).Flush()
		} else {
			err = wsWriteServerText(wsConn, buf.Bytes())
		}

		if err != nil {
			break
		}
	}
}

func version(w http.ResponseWriter, r *http.Request) {
	render.JSON(w, r, render.M{"meta": C.Meta, "version": C.Version})
}
