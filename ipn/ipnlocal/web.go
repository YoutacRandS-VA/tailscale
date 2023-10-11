// Copyright (c) Tailscale Inc & AUTHORS
// SPDX-License-Identifier: BSD-3-Clause

package ipnlocal

import (
	"context"
	"errors"
	"fmt"
	"net/http"
	"sync"

	"tailscale.com/client/tailscale"
	"tailscale.com/client/web"
	"tailscale.com/envknob"
)

// webServer holds state for the web interface for managing
// this tailscale instance. The web interface is not used by
// default, but initialized by calling LocalBackend.WebOrInit.
type webServer struct {
	ws         *web.Server  // or nil, initialized lazily
	httpServer *http.Server // or nil, initialized lazily

	// lc optionally specifies a LocalClient to use to connect
	// to the localapi for this tailscaled instance.
	// If nil, a default is used.
	lc *tailscale.LocalClient

	wg sync.WaitGroup
}

// SetWebLocalClient sets the b.web.lc function.
// If lc is provided as nil, b.web.lc is cleared out.
func (b *LocalBackend) SetWebLocalClient(lc *tailscale.LocalClient) {
	b.mu.Lock()
	defer b.mu.Unlock()
	b.web.lc = lc
}

// WebOrInit gets or initializes the web interface for
// managing this tailscaled instance.
func (b *LocalBackend) WebOrInit() (_ *web.Server, err error) {
	if !envknob.Bool("TS_DEBUG_WEB_UI") {
		return nil, errors.New("web ui flag unset")
	}

	b.mu.Lock()
	defer b.mu.Unlock()
	if b.web.ws != nil {
		return b.web.ws, nil
	}

	b.logf("WebOrInit: initializing web ui")
	if b.web.ws, err = web.NewServer(web.ServerOpts{
		// TODO(sonia): allow passing back dev mode flag
		LocalClient:    b.web.lc,
		DoNoiseRequest: b.DoNoiseRequest,
		Logf:           b.logf,
	}); err != nil {
		return nil, fmt.Errorf("web.NewServer: %w", err)
	}

	// Start up the server.
	b.web.wg.Add(1)
	go func() {
		defer b.web.wg.Done()
		addr := ":5252"
		b.web.httpServer = &http.Server{
			Addr:    addr,
			Handler: http.HandlerFunc(b.web.ws.ServeHTTP),
		}
		b.logf("WebOrInit: serving web ui on %s", addr)
		if err := b.web.httpServer.ListenAndServe(); err != nil {
			if err != http.ErrServerClosed {
				b.logf("[unexpected] WebOrInit: %v", err)
			}
		}
	}()

	b.logf("WebOrInit: started web ui")
	return b.web.ws, nil
}

// WebShutdown shuts down any running b.web servers and
// clears out b.web state (besides the b.web.lc field,
// which is left untouched because required for future
// web startups).
func (b *LocalBackend) WebShutdown() {
	b.mu.Lock()
	defer b.mu.Unlock()
	b.webShutdownLocked()
}

// webShutdownLocked shuts down any running b.web servers
// and clears out b.web state (besides the b.web.lc field,
// which is left untouched because required for future web
// startups).
//
// b.mu must be held.
func (b *LocalBackend) webShutdownLocked() {
	if b.web.ws != nil {
		b.web.ws.Shutdown()
	}
	if b.web.httpServer != nil {
		if err := b.web.httpServer.Shutdown(context.Background()); err != nil {
			b.logf("[unexpected] webShutdownLocked: %v", err)
		}
	}
	b.web.ws = nil
	b.web.httpServer = nil
	b.web.wg.Wait()
	b.logf("webShutdownLocked: shut down web ui")
}
