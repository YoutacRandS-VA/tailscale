// Copyright (c) Tailscale Inc & AUTHORS
// SPDX-License-Identifier: BSD-3-Clause

package appc

import (
	"context"
	"fmt"
	"log"
	"math/rand"
	"net"
	"net/netip"
	"slices"

	"inet.af/tcpproxy"
	"tailscale.com/net/netutil"
)

type tcpRoundRobinHandler struct {
	// To is a list of destination addresses to forward to.
	// An entry may be either an IP address or a DNS name.
	To []string

	// DialContext is used to make the outgoing TCP connection.
	DialContext func(ctx context.Context, network, address string) (net.Conn, error)

	// ReachableIPs enumerates the IP addresses this handler is reachable on.
	ReachableIPs []netip.Addr
}

// ReachableOn returns the IP addresses this handler is reachable on.
func (h *tcpRoundRobinHandler) ReachableOn() []netip.Addr {
	return h.ReachableIPs
}

func (h *tcpRoundRobinHandler) Handle(c net.Conn) {
	addrPortStr := c.LocalAddr().String()
	_, port, err := net.SplitHostPort(addrPortStr)
	if err != nil {
		log.Printf("bogus addrPort %q", addrPortStr)
		// s.numBadAddrPort.Add(1)
		c.Close()
		return
	}

	var p tcpproxy.Proxy
	p.ListenFunc = func(net, laddr string) (net.Listener, error) {
		return netutil.NewOneConnListener(c, nil), nil
	}

	dest := h.To[rand.Intn(len(h.To))]
	dial := &tcpproxy.DialProxy{
		Addr:        fmt.Sprintf("%s:%s", dest, port),
		DialContext: h.DialContext,
	}

	p.AddRoute(addrPortStr, dial)
	// h.numTCPsessions.Add(portNumberToName(forw), 1)
	p.Start()
}

type tcpSNIHandler struct {
	// Allowlist enumerates the FQDNs which may be proxied via SNI. An
	// empty slice means all domains are permitted.
	Allowlist []string

	// DialContext is used to make the outgoing TCP connection.
	DialContext func(ctx context.Context, network, address string) (net.Conn, error)

	// ReachableIPs enumerates the IP addresses this handler is reachable on.
	ReachableIPs []netip.Addr
}

// ReachableOn returns the IP addresses this handler is reachable on.
func (h *tcpSNIHandler) ReachableOn() []netip.Addr {
	return h.ReachableIPs
}

func (h *tcpSNIHandler) Handle(c net.Conn) {
	addrPortStr := c.LocalAddr().String()
	_, port, err := net.SplitHostPort(addrPortStr)
	if err != nil {
		log.Printf("bogus addrPort %q", addrPortStr)
		// s.numBadAddrPort.Add(1)
		c.Close()
		return
	}

	var p tcpproxy.Proxy
	p.ListenFunc = func(net, laddr string) (net.Listener, error) {
		return netutil.NewOneConnListener(c, nil), nil
	}
	p.AddSNIRouteFunc(addrPortStr, func(ctx context.Context, sniName string) (t tcpproxy.Target, ok bool) {
		if len(h.Allowlist) > 0 {
			// TODO(tom): handle subdomains
			if slices.Index(h.Allowlist, sniName) < 0 {
				return nil, false
			}
		}

		// s.numTLSsessions.Add(1)
		return &tcpproxy.DialProxy{
			Addr:        net.JoinHostPort(sniName, port),
			DialContext: h.DialContext,
		}, true
	})
	p.Start()
}
