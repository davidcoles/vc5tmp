/*
 * VC5 load balancer. Copyright (C) 2021-present David Coles
 *
 * This program is free software; you can redistribute it and/or modify
 * it under the terms of the GNU General Public License as published by
 * the Free Software Foundation; either version 2 of the License, or
 * (at your option) any later version.
 *
 * This program is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU General Public License for more details.
 *
 * You should have received a copy of the GNU General Public License along
 * with this program; if not, write to the Free Software Foundation, Inc.,
 * 51 Franklin Street, Fifth Floor, Boston, MA 02110-1301 USA.
 */

package mon

import (
	"crypto/tls"
	"fmt"
	"io/ioutil"
	"net"
	"net/http"
	"net/netip"
	"sync"
	"time"
)

var client *http.Client

func init() {
	transport := &http.Transport{
		Dial: (&net.Dialer{
			Timeout: 2 * time.Second,
		}).Dial,
		TLSHandshakeTimeout: 1 * time.Second,
		TLSClientConfig:     &tls.Config{InsecureSkipVerify: true},
	}

	client = &http.Client{
		Timeout:   time.Second * 3,
		Transport: transport,
		CheckRedirect: func(req *http.Request, via []*http.Request) error {
			return http.ErrUseLastResponse
		},
	}
}

type Service struct {
	Address  netip.Addr
	Port     uint16
	Protocol uint8
}

type Destination struct {
	Address netip.Addr
	Port    uint16
}

const (
	GET  method = false
	HEAD method = true
	UDP  method = false
	TCP  method = true
)

type Instance struct {
	Service     Service
	Destination Destination
}

type Services map[Instance]Checks

type state struct {
	mutex  sync.Mutex
	checks chan Checks
	status status
}

type status = Status
type Status struct {
	OK         bool
	Diagnostic string
	Time       time.Duration
	Last       time.Time
	When       time.Time
}

type Mon struct {
	C        chan bool
	services map[Instance]*state
	syn      *SYN
	prober   Prober
}

func New(addr netip.Addr, services Services) (*Mon, error) {
	return Custom(addr, services, nil, false)
}

func Custom(addr netip.Addr, services Services, p Prober, resets bool) (*Mon, error) {

	m := &Mon{C: make(chan bool, 1), services: make(map[Instance]*state), prober: p}

	if m.prober == nil {
		m.prober = prober{m: m}
	}

	var err error
	m.syn, err = Syn(addr, resets) // OS will handle resets in usual case, but behind VC5 NAT this needs to be true

	if m.syn == nil {
		return nil, err
	}

	m.Update(services)

	return m, nil
}

func (m *Mon) Dump() map[Instance]Status {

	r := map[Instance]Status{}

	for k, v := range m.services {
		v.mutex.Lock()
		r[k] = v.status
		v.mutex.Unlock()
	}

	return r
}

func (m *Mon) Stop() {
	m.Update(map[Instance]Checks{})
}

func (m *Mon) Update(checks map[Instance]Checks) {

	for instance, state := range m.services {
		if new, ok := checks[instance]; ok {
			state.checks <- new
			delete(checks, instance)
		} else {
			close(state.checks) // no longer exists
			delete(m.services, instance)
		}
	}

	for instance, c := range checks {
		now := time.Now()
		state := &state{status: status{OK: false, Diagnostic: "Initialising ...", Last: now, When: now}}
		state.checks = m.monitor(instance.Service.Address, instance.Destination.Address, instance.Destination.Port, state, c)
		m.services[instance] = state
	}

	select {
	case m.C <- true:
	default:
	}
}

// need to add some sort of history, 4-out-of-5 or something
// start with service ok:  history[1 1 1 1 0]
// rotate to: history[1 1 1 0 x]
// first check either keeps service ok, or marks it as down
// once down then all last 5 checks need to pass to bring back up

func (m *Mon) monitor(vip, rip netip.Addr, port uint16, state *state, c Checks) chan Checks {
	C := make(chan Checks, 10)

	go func() {

		ticker := time.NewTicker(2 * time.Second)
		defer ticker.Stop()

		for {
			var ok bool
			state.mutex.Lock()
			was := state.status
			state.mutex.Unlock()

			now := was

			t := time.Now()
			now.OK, now.Diagnostic = m.prober.Probe(vip, rip, port, c)
			now.Last = t
			now.Time = time.Now().Sub(t)

			if was.OK != now.OK {
				now.When = t
				select {
				case m.C <- true:
				default:
				}
			}

			state.mutex.Lock()
			state.status = now
			state.mutex.Unlock()

			select {
			case <-ticker.C:

			case c, ok = <-C:
				if !ok {
					return
				}
			}
		}
	}()

	return C
}

type Checks = []Check

type Check struct {
	//Type string `json:"type,omitempty"`
	Type string `json:"type,omitempty"`

	// TCP/UDP port to use for L4/L7 checks
	Port uint16 `json:"port,omitempty"`

	// HTTP Host header to send in healthcheck
	Host string `json:"host,omitempty"`

	// Path of resource to use when building a URI for HTTP/HTTPS healthchecks
	Path string `json:"path,omitempty"`

	// Expected HTTP status code to allow check to succeed
	Expect uint16 `json:"expect,omitempty"`

	// Method - HTTP: GET=false, HEAD=true DNS: UDP=false TCP=true
	Method bool `json:"method,omitempty"`
}

type method = bool

type Prober interface {
	Probe(netip.Addr, netip.Addr, uint16, Checks) (bool, string)
}

type prober struct {
	m *Mon
}

func (p prober) Probe(vip netip.Addr, rip netip.Addr, port uint16, checks Checks) (bool, string) {
	return p.m.Probe(rip, port, checks)
}

func (m *Mon) Probe(addr netip.Addr, port uint16, checks Checks) (bool, string) {
	for _, c := range checks {
		var ok bool
		var s string
		switch c.Type {
		case "http":
			ok, s = m.HTTP(addr, port, c)
		case "https":
			ok, s = m.HTTP(addr, port, c)
		case "syn":
			ok, s = m.SYN(addr, port, c)
		case "dns":
			ok, s = m.DNS(addr, port, c)
		default:
			s = "Unknown check type"
		}

		if !ok {
			return ok, c.Type + ": " + s
		}
	}

	return true, "OK"
}

func (m *Mon) DNS(addr netip.Addr, port uint16, check Check) (bool, string) {

	if check.Port != 0 {
		port = check.Port
	}

	if check.Method == TCP {
		return DNSTCP(addr.String(), port)
	}

	return DNSUDP(addr.String(), port)
}

func (m *Mon) SYN(addr netip.Addr, port uint16, check Check) (bool, string) {

	if !addr.Is4() {
		return false, "Not an IPv4 address"
	}

	ip := addr.As4()

	if check.Port != 0 {
		port = check.Port
	}

	return m.syn.Check(ip, port)
}

func (m *Mon) HTTP(addr netip.Addr, port uint16, check Check) (bool, string) {

	if check.Port != 0 {
		port = check.Port
	}

	if port == 0 {
		return false, "Port is 0"
	}

	method := "GET"

	if check.Method == HEAD {
		method = "HEAD"
	}

	defer client.CloseIdleConnections()

	path := check.Path

	if len(path) > 0 && path[0] == '/' {
		path = path[1:]
	}

	url := fmt.Sprintf("%s://%s:%d/%s", check.Type, addr.String(), port, path)
	req, err := http.NewRequest(method, url, nil)

	if err != nil {
		return false, err.Error()
	}

	if check.Host != "" {
		req.Host = check.Host
	}

	resp, err := client.Do(req)

	if err != nil {
		return false, err.Error()
	}

	defer resp.Body.Close()

	ioutil.ReadAll(resp.Body)

	exp := int(check.Expect)

	if exp == 0 {
		exp = 200
	}

	return resp.StatusCode == exp, resp.Status
}
