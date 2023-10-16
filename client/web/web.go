// Copyright (c) Tailscale Inc & AUTHORS
// SPDX-License-Identifier: BSD-3-Clause

// Package web provides the Tailscale client for web.
package web

import (
	"bytes"
	"context"
	"crypto/rand"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"log"
	"net/http"
	"net/netip"
	"os"
	"path/filepath"
	"slices"
	"strings"
	"sync"
	"sync/atomic"
	"time"

	"github.com/gorilla/csrf"
	"tailscale.com/client/tailscale"
	"tailscale.com/client/tailscale/apitype"
	"tailscale.com/envknob"
	"tailscale.com/ipn"
	"tailscale.com/ipn/ipnstate"
	"tailscale.com/licenses"
	"tailscale.com/net/netutil"
	"tailscale.com/tailcfg"
	"tailscale.com/util/httpm"
	"tailscale.com/version/distro"
)

// Server is the backend server for a Tailscale web client.
type Server struct {
	lc *tailscale.LocalClient

	devMode     bool
	tsDebugMode string

	cgiMode    bool
	pathPrefix string

	assetsHandler http.Handler // serves frontend assets
	apiHandler    http.Handler // serves api endpoints; csrf-protected

	// browserSessions is an in-memory cache of browser sessions for the
	// full management web client, which is only accessible over Tailscale.
	//
	// Users obtain a valid browser session by connecting to the web client
	// over Tailscale and verifying their identity by authenticating on the
	// control server.
	//
	// browserSessions get reset on every Server restart.
	//
	// The map provides a lookup of the session by cookie value
	// (browserSession.ID => browserSession).
	browserSessions  sync.Map
	controlServerURL atomic.Value // access through getControlServerURL
}

const (
	sessionCookieName   = "TS-Web-Session"
	sessionCookieExpiry = time.Hour * 24 * 30 // 30 days
)

var (
	exitNodeRouteV4 = netip.MustParsePrefix("0.0.0.0/0")
	exitNodeRouteV6 = netip.MustParsePrefix("::/0")
)

// browserSession holds data about a user's browser session
// on the full management web client.
type browserSession struct {
	// ID is the unique identifier for the session.
	// It is passed in the user's "TS-Web-Session" browser cookie.
	ID            string
	SrcNode       tailcfg.NodeID
	SrcUser       tailcfg.UserID
	AuthURL       string // control server URL for user to authenticate the session
	Created       time.Time
	Authenticated bool
}

// isAuthorized reports true if the given session is authorized
// to be used by its associated user to access the full management
// web client.
//
// isAuthorized is true only when s.Authenticated is true (i.e.
// the user has authenticated the session) and the session is not
// expired.
// 2023-10-05: Sessions expire by default 30 days after creation.
func (s *browserSession) isAuthorized() bool {
	switch {
	case s == nil:
		return false
	case !s.Authenticated:
		return false // awaiting auth
	case s.isExpired(): // TODO: add time field to server?
		return false // expired
	}
	return true
}

// isExpired reports true if s is expired.
// 2023-10-05: Sessions expire by default 30 days after creation.
func (s *browserSession) isExpired() bool {
	return !s.Created.IsZero() && s.Created.Before(time.Now().Add(-sessionCookieExpiry)) // TODO: add time field to server?
}

// expires reports when the given session expires.
func (s *browserSession) expires() time.Time {
	return s.Created.Add(sessionCookieExpiry)
}

// ServerOpts contains options for constructing a new Server.
type ServerOpts struct {
	DevMode bool

	// LoginOnly indicates that the server should only serve the minimal
	// login client and not the full web client.
	LoginOnly bool

	// CGIMode indicates if the server is running as a CGI script.
	CGIMode bool

	// PathPrefix is the URL prefix added to requests by CGI or reverse proxy.
	PathPrefix string

	// LocalClient is the tailscale.LocalClient to use for this web server.
	// If nil, a new one will be created.
	LocalClient *tailscale.LocalClient
}

// NewServer constructs a new Tailscale web client server.
func NewServer(opts ServerOpts) (s *Server, cleanup func()) {
	if opts.LocalClient == nil {
		opts.LocalClient = &tailscale.LocalClient{}
	}
	s = &Server{
		devMode:    opts.DevMode,
		lc:         opts.LocalClient,
		pathPrefix: opts.PathPrefix,
	}
	s.tsDebugMode = s.debugMode()
	s.assetsHandler, cleanup = assetsHandler(opts.DevMode)

	// Create handler for "/api" requests with CSRF protection.
	// We don't require secure cookies, since the web client is regularly used
	// on network appliances that are served on local non-https URLs.
	// The client is secured by limiting the interface it listens on,
	// or by authenticating requests before they reach the web client.
	csrfProtect := csrf.Protect(s.csrfKey(), csrf.Secure(false))
	if s.tsDebugMode == "login" {
		// For the login client, we don't serve the full web client API,
		// only the login endpoints.
		s.apiHandler = csrfProtect(http.HandlerFunc(s.serveLoginAPI))
		s.lc.IncrementCounter(context.Background(), "web_login_client_initialization", 1)
	} else {
		s.apiHandler = csrfProtect(http.HandlerFunc(s.serveAPI))
		s.lc.IncrementCounter(context.Background(), "web_client_initialization", 1)
	}

	return s, cleanup
}

// debugMode returns the debug mode the web client is being run in.
// The empty string is returned in the case that this instance is
// not running in any debug mode.
func (s *Server) debugMode() string {
	if !s.devMode {
		return "" // debug modes only available in dev
	}
	switch mode := os.Getenv("TS_DEBUG_WEB_CLIENT_MODE"); mode {
	case "login", "full": // valid debug modes
		return mode
	}
	return ""
}

// ServeHTTP processes all requests for the Tailscale web client.
func (s *Server) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	handler := s.serve

	// if path prefix is defined, strip it from requests.
	if s.pathPrefix != "" {
		handler = enforcePrefix(s.pathPrefix, handler)
	}

	handler(w, r)
}

func (s *Server) serve(w http.ResponseWriter, r *http.Request) {
	if strings.HasPrefix(r.URL.Path, "/api/") {
		// Pass API requests through to the API handler.
		s.apiHandler.ServeHTTP(w, r)
		return
	}
	if !s.devMode {
		s.lc.IncrementCounter(r.Context(), "web_client_page_load", 1)
	}
	s.assetsHandler.ServeHTTP(w, r)
}

// authorizePlatformRequest reports whether the request from the web client
// is authorized to access the client for those platforms that support it.
// It reports true if the request is authorized, and false otherwise.
// authorizePlatformRequest manages writing out any relevant authorization
// errors to the ResponseWriter itself.
func authorizePlatformRequest(w http.ResponseWriter, r *http.Request) (ok bool) {
	switch distro.Get() {
	case distro.Synology:
		return authorizeSynology(w, r)
	case distro.QNAP:
		return authorizeQNAP(w, r)
	}
	return true
}

// serveLoginAPI serves requests for the web login client.
// It should only be called by Server.ServeHTTP, via Server.apiHandler,
// which protects the handler using gorilla csrf.
func (s *Server) serveLoginAPI(w http.ResponseWriter, r *http.Request) {
	// The login client is run directly from client plugins,
	// so first authenticate and authorize the request for the host platform.
	if ok := authorizePlatformRequest(w, r); !ok {
		return
	}

	w.Header().Set("X-CSRF-Token", csrf.Token(r))
	if r.URL.Path != "/api/data" { // only endpoint allowed for login client
		http.Error(w, "invalid endpoint", http.StatusNotFound)
		return
	}
	switch r.Method {
	case httpm.GET:
		// TODO(soniaappasamy): we may want a minimal node data response here
		s.serveGetNodeData(w, r)
	case httpm.POST:
		// TODO(soniaappasamy): implement
	default:
		http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
	}
	return
}

var (
	errNoSession         = errors.New("no-browser-session")
	errNotUsingTailscale = errors.New("not-using-tailscale")
	errTaggedSource      = errors.New("tagged-source")
	errNotOwner          = errors.New("not-owner")
)

// getTailscaleBrowserSession retrieves the browser session associated with
// the request, if one exists.
//
// An error is returned in any of the following cases:
//
//   - (errNotUsingTailscale) The request was not made over tailscale.
//
//   - (errNoSession) The request does not have a session.
//
//   - (errTaggedSource) The source is a tagged node. Users must use their
//     own user-owned devices to manage other nodes' web clients.
//
//   - (errNotOwner) The source is not the owner of this client (if the
//     client is user-owned). Only the owner is allowed to manage the
//     node via the web client.
//
// If no error is returned, the browserSession is always non-nil.
// getTailscaleBrowserSession does not check whether the session has been
// authorized by the user. Callers can use browserSession.isAuthorized.
//
// The WhoIsResponse is always populated, with a non-nil Node and UserProfile,
// unless getTailscaleBrowserSession reports errNotUsingTailscale.
func (s *Server) getTailscaleBrowserSession(r *http.Request) (*browserSession, *apitype.WhoIsResponse, error) {
	whoIs, err := s.lc.WhoIs(r.Context(), r.RemoteAddr)
	switch {
	case err != nil:
		return nil, nil, errNotUsingTailscale
	case whoIs.Node.IsTagged():
		return nil, whoIs, errTaggedSource
	}
	srcNode := whoIs.Node.ID
	srcUser := whoIs.UserProfile.ID

	status, err := s.lc.StatusWithoutPeers(r.Context())
	switch {
	case err != nil:
		return nil, whoIs, err
	case status.Self == nil:
		return nil, whoIs, errors.New("missing self node in tailscale status")
	case !status.Self.IsTagged() && status.Self.UserID != srcUser:
		return nil, whoIs, errNotOwner
	}

	cookie, err := r.Cookie(sessionCookieName)
	if errors.Is(err, http.ErrNoCookie) {
		return nil, whoIs, errNoSession
	} else if err != nil {
		return nil, whoIs, err
	}
	v, ok := s.browserSessions.Load(cookie.Value)
	if !ok {
		return nil, whoIs, errNoSession
	}
	session := v.(*browserSession)
	if session.SrcNode != srcNode || session.SrcUser != srcUser {
		// In this case the browser cookie is associated with another tailscale node.
		// Maybe the source browser's machine was logged out and then back in as a different node.
		// Return errNoSession because there is no session for this user.
		return nil, whoIs, errNoSession
	} else if session.isExpired() {
		// Session expired, remove from session map and return errNoSession.
		s.browserSessions.Delete(session.ID)
		return nil, whoIs, errNoSession
	}
	return session, whoIs, nil
}

type authResponse struct {
	OK      bool   `json:"ok"`                // true when user has valid auth session
	AuthURL string `json:"authUrl,omitempty"` // filled when user has control auth action to take
	Error   string `json:"error,omitempty"`   // when filled, error was hit during auth
}

func (s *Server) serveTailscaleAuth(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodGet {
		http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
		return
	}
	var resp authResponse

	session, whois, err := s.getTailscaleBrowserSession(r)
	switch {
	case err != nil && !errors.Is(err, errNoSession):
		resp = authResponse{OK: false, Error: err.Error()}
	case session == nil:
		// Create a new session.
		d, err := s.getOrAwaitAuthURL(r.Context(), "", whois.Node.ID)
		if err != nil {
			http.Error(w, err.Error(), http.StatusInternalServerError)
			return
		}
		cookie, err := s.newSessionCookie()
		if err != nil {
			http.Error(w, err.Error(), http.StatusInternalServerError)
			return
		}
		session := &browserSession{
			ID:      cookie,
			SrcNode: whois.Node.ID,
			SrcUser: whois.UserProfile.ID,
			AuthURL: d.URL,
			Created: time.Now(),
		}
		s.browserSessions.Store(cookie, session)
		// Set the cookie on browser.
		http.SetCookie(w, &http.Cookie{
			Name:    sessionCookieName,
			Value:   cookie,
			Raw:     cookie,
			Path:    "/",
			Expires: session.expires(),
			// TODO: any other fields here?
		})
		resp = authResponse{OK: false, AuthURL: d.URL}
	case !session.isAuthorized():
		if r.URL.Query().Get("wait") == "true" {
			// Client requested we block until user completes auth.
			d, err := s.getOrAwaitAuthURL(r.Context(), session.AuthURL, whois.Node.ID)
			if err != nil {
				http.Error(w, err.Error(), http.StatusInternalServerError)
				return
			}
			// TODO: if error was reported with auth,
			// maybe we delete the auth session, otherwise user may
			// get stuck
			if d.Complete {
				session.Authenticated = d.Complete
				s.browserSessions.Store(session.ID, session)
			}
		}
		resp = authResponse{OK: session.isAuthorized(), AuthURL: session.AuthURL}
	default:
		resp = authResponse{OK: true}
	}

	if err := json.NewEncoder(w).Encode(resp); err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}
	w.Header().Set("Content-Type", "application/json")
}

func (s *Server) newSessionCookie() (string, error) {
	raw := make([]byte, 16)
	for i := 0; i < 5; i++ {
		if _, err := rand.Read(raw); err != nil {
			return "", err
		}
		cookie := "ts-web-" + base64.RawURLEncoding.EncodeToString(raw)
		if _, ok := s.browserSessions.Load(cookie); !ok {
			return cookie, nil
		}
	}
	return "", errors.New("too many collisions generating new session; please refresh page")
}

func (s *Server) getControlServerURL(ctx context.Context) (string, error) {
	if v := s.controlServerURL.Load(); v != nil {
		v, _ := v.(string)
		return v, nil
	}
	prefs, err := s.lc.GetPrefs(ctx)
	if err != nil {
		return "", err
	}
	url := prefs.ControlURLOrDefault()
	s.controlServerURL.Store(url)
	return url, nil
}

// getOrAwaitAuthURL connects to the control server for user auth,
// with the following behavior:
//
//  1. If authURL is provided empty, a new auth URL is created on the
//     control server and reported back here, which can then be used
//     to redirect the user on the frontend.
//  2. If authURL is provided non-empty, the connection to control
//     blocks until the user has completed the URL. getOrAwaitAuthURL
//     terminates when either the URL is completed, or ctx is canceled.
func (s *Server) getOrAwaitAuthURL(ctx context.Context, authURL string, src tailcfg.NodeID) (*tailcfg.WebClientAuthResponse, error) {
	serverURL, err := s.getControlServerURL(ctx)
	if err != nil {
		return nil, err
	}
	type data struct {
		ID  string
		Src tailcfg.NodeID
	}
	var b bytes.Buffer
	if err := json.NewEncoder(&b).Encode(data{
		ID:  strings.TrimPrefix(authURL, serverURL),
		Src: src,
	}); err != nil {
		return nil, err
	}
	url := "http://" + apitype.LocalAPIHost + "/localapi/v0/debug-web-client"
	req, err := http.NewRequestWithContext(ctx, "POST", url, &b)
	if err != nil {
		return nil, err
	}
	resp, err := s.lc.DoLocalRequest(req)
	if err != nil {
		return nil, err
	}
	body, _ := io.ReadAll(resp.Body)
	resp.Body.Close()
	if resp.StatusCode != 200 {
		return nil, fmt.Errorf("failed request: %s", body)
	}
	var authResp *tailcfg.WebClientAuthResponse
	if err := json.Unmarshal(body, &authResp); err != nil {
		return nil, err
	}
	return authResp, nil
}

// serveAPI serves requests for the web client api.
// It should only be called by Server.ServeHTTP, via Server.apiHandler,
// which protects the handler using gorilla csrf.
func (s *Server) serveAPI(w http.ResponseWriter, r *http.Request) {
	if s.tsDebugMode == "full" {
		// tailscale/corp#14335: Only restrict to tailscale auth in debug "full" web client mode.
		// TODO(sonia,will): Switch serveAPI over to always require TS auth when we're ready
		// to remove the debug flags.
		// For now, existing client uses platform auth (else case below).
		switch {
		case r.URL.Path == "/api/auth":
			// Serve auth, which creates a new session for the user to authenticate,
			// in the case that the request doesn't already have one.
			s.serveTailscaleAuth(w, r)
			return
		case r.URL.Path == "/api/data" && r.Method == http.MethodGet:
			// The readonly "data" endpoint is okay as long as it's accessed over
			// tailscale. No authenticated session required.
			_, err := s.lc.WhoIs(r.Context(), r.RemoteAddr)
			if err != nil {
				http.Error(w, "must access over tailscale", http.StatusUnauthorized)
				return
			}
		default:
			// For all other endpoints, require a valid session to proceed.
			session, _, err := s.getTailscaleBrowserSession(r)
			if err != nil || !session.isAuthorized() {
				http.Error(w, "no valid session", http.StatusUnauthorized)
				return
			}
		}
	} else if ok := authorizePlatformRequest(w, r); !ok {
		return
	}

	w.Header().Set("X-CSRF-Token", csrf.Token(r))
	path := strings.TrimPrefix(r.URL.Path, "/api")
	switch {
	case path == "/data":
		switch r.Method {
		case httpm.GET:
			s.serveGetNodeData(w, r)
		case httpm.POST:
			s.servePostNodeUpdate(w, r)
		default:
			http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
		}
		return
	case strings.HasPrefix(path, "/local/"):
		s.proxyRequestToLocalAPI(w, r)
		return
	}
	http.Error(w, "invalid endpoint", http.StatusNotFound)
}

type nodeData struct {
	Profile           tailcfg.UserProfile
	Status            string
	DeviceName        string
	IP                string
	AdvertiseExitNode bool
	AdvertiseRoutes   string
	LicensesURL       string
	TUNMode           bool
	IsSynology        bool
	DSMVersion        int // 6 or 7, if IsSynology=true
	IsUnraid          bool
	UnraidToken       string
	IPNVersion        string
	DebugMode         string // empty when not running in any debug mode
}

func (s *Server) serveGetNodeData(w http.ResponseWriter, r *http.Request) {
	st, err := s.lc.Status(r.Context())
	if err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}
	prefs, err := s.lc.GetPrefs(r.Context())
	if err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}
	profile := st.User[st.Self.UserID]
	deviceName := strings.Split(st.Self.DNSName, ".")[0]
	versionShort := strings.Split(st.Version, "-")[0]
	data := &nodeData{
		Profile:     profile,
		Status:      st.BackendState,
		DeviceName:  deviceName,
		LicensesURL: licenses.LicensesURL(),
		TUNMode:     st.TUN,
		IsSynology:  distro.Get() == distro.Synology || envknob.Bool("TS_FAKE_SYNOLOGY"),
		DSMVersion:  distro.DSMVersion(),
		IsUnraid:    distro.Get() == distro.Unraid,
		UnraidToken: os.Getenv("UNRAID_CSRF_TOKEN"),
		IPNVersion:  versionShort,
		DebugMode:   s.tsDebugMode,
	}
	for _, r := range prefs.AdvertiseRoutes {
		if r == exitNodeRouteV4 || r == exitNodeRouteV6 {
			data.AdvertiseExitNode = true
		} else {
			if data.AdvertiseRoutes != "" {
				data.AdvertiseRoutes += ","
			}
			data.AdvertiseRoutes += r.String()
		}
	}
	if len(st.TailscaleIPs) != 0 {
		data.IP = st.TailscaleIPs[0].String()
	}
	if err := json.NewEncoder(w).Encode(*data); err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}
	w.Header().Set("Content-Type", "application/json")
}

type nodeUpdate struct {
	AdvertiseRoutes   string
	AdvertiseExitNode bool
	Reauthenticate    bool
	ForceLogout       bool
}

func (s *Server) servePostNodeUpdate(w http.ResponseWriter, r *http.Request) {
	defer r.Body.Close()

	st, err := s.lc.Status(r.Context())
	if err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}

	var postData nodeUpdate
	type mi map[string]any
	if err := json.NewDecoder(r.Body).Decode(&postData); err != nil {
		w.WriteHeader(400)
		json.NewEncoder(w).Encode(mi{"error": err.Error()})
		return
	}

	prefs, err := s.lc.GetPrefs(r.Context())
	if err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}

	isCurrentlyExitNode := slices.Contains(prefs.AdvertiseRoutes, exitNodeRouteV4) || slices.Contains(prefs.AdvertiseRoutes, exitNodeRouteV6)

	if postData.AdvertiseExitNode != isCurrentlyExitNode {
		if postData.AdvertiseExitNode {
			s.lc.IncrementCounter(r.Context(), "web_client_advertise_exitnode_enable", 1)
		} else {
			s.lc.IncrementCounter(r.Context(), "web_client_advertise_exitnode_disable", 1)
		}
	}

	routes, err := netutil.CalcAdvertiseRoutes(postData.AdvertiseRoutes, postData.AdvertiseExitNode)
	if err != nil {
		w.WriteHeader(http.StatusInternalServerError)
		json.NewEncoder(w).Encode(mi{"error": err.Error()})
		return
	}
	mp := &ipn.MaskedPrefs{
		AdvertiseRoutesSet: true,
		WantRunningSet:     true,
	}
	mp.Prefs.WantRunning = true
	mp.Prefs.AdvertiseRoutes = routes
	log.Printf("Doing edit: %v", mp.Pretty())

	if _, err := s.lc.EditPrefs(r.Context(), mp); err != nil {
		w.WriteHeader(http.StatusInternalServerError)
		json.NewEncoder(w).Encode(mi{"error": err.Error()})
		return
	}

	w.Header().Set("Content-Type", "application/json")
	var reauth, logout bool
	if postData.Reauthenticate {
		reauth = true
	}
	if postData.ForceLogout {
		logout = true
	}
	log.Printf("tailscaleUp(reauth=%v, logout=%v) ...", reauth, logout)
	url, err := s.tailscaleUp(r.Context(), st, postData)
	log.Printf("tailscaleUp = (URL %v, %v)", url != "", err)
	if err != nil {
		w.WriteHeader(http.StatusInternalServerError)
		json.NewEncoder(w).Encode(mi{"error": err.Error()})
		return
	}
	if url != "" {
		json.NewEncoder(w).Encode(mi{"url": url})
	} else {
		io.WriteString(w, "{}")
	}
}

func (s *Server) tailscaleUp(ctx context.Context, st *ipnstate.Status, postData nodeUpdate) (authURL string, retErr error) {
	if postData.ForceLogout {
		if err := s.lc.Logout(ctx); err != nil {
			return "", fmt.Errorf("Logout error: %w", err)
		}
		return "", nil
	}

	origAuthURL := st.AuthURL
	isRunning := st.BackendState == ipn.Running.String()

	forceReauth := postData.Reauthenticate
	if !forceReauth {
		if origAuthURL != "" {
			return origAuthURL, nil
		}
		if isRunning {
			return "", nil
		}
	}

	// printAuthURL reports whether we should print out the
	// provided auth URL from an IPN notify.
	printAuthURL := func(url string) bool {
		return url != origAuthURL
	}

	watchCtx, cancelWatch := context.WithCancel(ctx)
	defer cancelWatch()
	watcher, err := s.lc.WatchIPNBus(watchCtx, 0)
	if err != nil {
		return "", err
	}
	defer watcher.Close()

	go func() {
		if !isRunning {
			s.lc.Start(ctx, ipn.Options{})
		}
		if forceReauth {
			s.lc.StartLoginInteractive(ctx)
		}
	}()

	for {
		n, err := watcher.Next()
		if err != nil {
			return "", err
		}
		if n.ErrMessage != nil {
			msg := *n.ErrMessage
			return "", fmt.Errorf("backend error: %v", msg)
		}
		if url := n.BrowseToURL; url != nil && printAuthURL(*url) {
			return *url, nil
		}
	}
}

// proxyRequestToLocalAPI proxies the web API request to the localapi.
//
// The web API request path is expected to exactly match a localapi path,
// with prefix /api/local/ rather than /localapi/.
//
// If the localapi path is not included in localapiAllowlist,
// the request is rejected.
func (s *Server) proxyRequestToLocalAPI(w http.ResponseWriter, r *http.Request) {
	path := strings.TrimPrefix(r.URL.Path, "/api/local")
	if r.URL.Path == path { // missing prefix
		http.Error(w, "invalid request", http.StatusBadRequest)
		return
	}
	if !slices.Contains(localapiAllowlist, path) {
		http.Error(w, fmt.Sprintf("%s not allowed from localapi proxy", path), http.StatusForbidden)
		return
	}

	localAPIURL := "http://" + apitype.LocalAPIHost + "/localapi" + path
	req, err := http.NewRequestWithContext(r.Context(), r.Method, localAPIURL, r.Body)
	if err != nil {
		http.Error(w, "failed to construct request", http.StatusInternalServerError)
		return
	}

	// Make request to tailscaled localapi.
	resp, err := s.lc.DoLocalRequest(req)
	if err != nil {
		http.Error(w, err.Error(), resp.StatusCode)
		return
	}
	defer resp.Body.Close()

	// Send response back to web frontend.
	w.Header().Set("Content-Type", resp.Header.Get("Content-Type"))
	w.WriteHeader(resp.StatusCode)
	if _, err := io.Copy(w, resp.Body); err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
	}
}

// localapiAllowlist is an allowlist of localapi endpoints the
// web client is allowed to proxy to the client's localapi.
//
// Rather than exposing all localapi endpoints over the proxy,
// this limits to just the ones actually used from the web
// client frontend.
//
// TODO(sonia,will): Shouldn't expand this beyond the existing
// localapi endpoints until the larger web client auth story
// is worked out (tailscale/corp#14335).
var localapiAllowlist = []string{
	"/v0/logout",
}

// csrfKey returns a key that can be used for CSRF protection.
// If an error occurs during key creation, the error is logged and the active process terminated.
// If the server is running in CGI mode, the key is cached to disk and reused between requests.
// If an error occurs during key storage, the error is logged and the active process terminated.
func (s *Server) csrfKey() []byte {
	csrfFile := filepath.Join(os.TempDir(), "tailscale-web-csrf.key")

	// if running in CGI mode, try to read from disk, but ignore errors
	if s.cgiMode {
		key, _ := os.ReadFile(csrfFile)
		if len(key) == 32 {
			return key
		}
	}

	// create a new key
	key := make([]byte, 32)
	if _, err := rand.Read(key); err != nil {
		log.Fatalf("error generating CSRF key: %v", err)
	}

	// if running in CGI mode, try to write the newly created key to disk, and exit if it fails.
	if s.cgiMode {
		if err := os.WriteFile(csrfFile, key, 0600); err != nil {
			log.Fatalf("unable to store CSRF key: %v", err)
		}
	}

	return key
}

// enforcePrefix returns a HandlerFunc that enforces a given path prefix is used in requests,
// then strips it before invoking h.
// Unlike http.StripPrefix, it does not return a 404 if the prefix is not present.
// Instead, it returns a redirect to the prefix path.
func enforcePrefix(prefix string, h http.HandlerFunc) http.HandlerFunc {
	if prefix == "" {
		return h
	}

	// ensure that prefix always has both a leading and trailing slash so
	// that relative links for JS and CSS assets work correctly.
	if !strings.HasPrefix(prefix, "/") {
		prefix = "/" + prefix
	}
	if !strings.HasSuffix(prefix, "/") {
		prefix += "/"
	}

	return func(w http.ResponseWriter, r *http.Request) {
		if !strings.HasPrefix(r.URL.Path, prefix) {
			http.Redirect(w, r, prefix, http.StatusFound)
			return
		}
		prefix = strings.TrimSuffix(prefix, "/")
		http.StripPrefix(prefix, h).ServeHTTP(w, r)
	}
}
