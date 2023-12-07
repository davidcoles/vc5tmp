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

package vc5tmp

import (
	"bufio"
	_ "embed"
	"errors"
	"fmt"
	"net"
	"net/netip"
	"os"
	"regexp"
	"sort"
	"sync"
	"unsafe"

	"github.com/davidcoles/vc5tmp/bpf"
	"github.com/davidcoles/vc5tmp/maglev"
	"github.com/davidcoles/vc5tmp/xdp"
)

//go:embed bpf/bpf.o
var BPF_O []byte

type IP4 [4]byte
type MAC [6]byte

func (i IP4) String() string { return fmt.Sprintf("%d.%d.%d.%d", i[0], i[1], i[2], i[3]) }
func (i *IP4) IsNil() bool   { return i[0] == 0 && i[1] == 0 && i[2] == 0 && i[3] == 0 }

func (m MAC) String() string {
	return fmt.Sprintf("%02x:%02x:%02x:%02x:%02x:%02x", m[0], m[1], m[2], m[3], m[4], m[5])
}

func (m *MAC) IsNil() bool {
	return m[0] == 0 && m[1] == 0 && m[2] == 0 && m[3] == 0 && m[4] == 0 && m[5] == 0
}

type uP = unsafe.Pointer

func nltoh(n [4]byte) uint32 {
	return uint32(n[0])<<24 | uint32(n[1])<<16 | uint32(n[2])<<8 | uint32(n[0])
}

var mutex sync.Mutex

const (
	TCP protocol = 0x06
	UDP protocol = 0x11
)

type protocol uint8

type svc struct {
	IP       IP4
	Port     uint16
	Protocol protocol
}

type nat_map map[[2]IP4]uint16

func (n *nat_map) set(tuples map[[2]IP4]bool) {
	mutex.Lock()
	defer mutex.Unlock()

	nm := natmap(tuples, *n)

	*n = nm
}

func (n *nat_map) get() map[[2]IP4]uint16 {
	mutex.Lock()
	defer mutex.Unlock()

	r := map[[2]IP4]uint16{}

	for k, v := range *n {
		r[k] = v
	}

	return r
}

func (n *nat_map) rip() (r []IP4) {
	mutex.Lock()
	defer mutex.Unlock()

	m := map[IP4]bool{}

	for k, _ := range *n {
		m[k[1]] = true
	}

	for k, _ := range m {
		r = append(r, k)
	}

	return r
}

func (n *nat_map) ent(vip, rip IP4) uint16 {
	mutex.Lock()
	defer mutex.Unlock()

	x := (map[[2]IP4]uint16)(*n)

	i, _ := x[[2]IP4{vip, rip}]

	return i
}

type tag_map map[IP4]uint16

func (t tag_map) set(ip IP4, id uint16) {
	mutex.Lock()
	defer mutex.Unlock()
	x := (map[IP4]uint16)(t)
	x[ip] = id
}

func (n *tag_map) get() map[IP4]uint16 {
	mutex.Lock()
	defer mutex.Unlock()

	r := map[IP4]uint16{}

	for k, v := range *n {
		r[k] = v
	}

	return r
}

func (t tag_map) ent(ip IP4) (uint16, bool) {
	mutex.Lock()
	defer mutex.Unlock()

	x := (map[IP4]uint16)(t)

	r, ok := x[ip]

	return r, ok
}

type vc struct {
	vid uint16
	net prefix
}

func (c *Client) targets() (r []IP4) {

	t := map[IP4]bool{}

	nm := c.nat_map.get()

	for k, _ := range nm {
		rip := k[1]
		t[rip] = true
	}

	for k, _ := range t {
		r = append(r, k)
	}

	return
}

type x_service struct {
	VIP      IP4
	Port     uint16
	Protocol protocol

	Scheduler        uint8
	Sticky           bool
	Leastconns       bool
	LeastconnsIP     IP4
	LeastconnsWeight uint8

	backend map[IP4]*Destination
	state   *be_state
}

func (s *Service) Service(x svc) Service {
	var r Service
	r.Address = s.Address //netip.AddrFrom4(s.VIP)
	r.Port = s.Port
	r.Protocol = s.Protocol
	r.backend = map[IP4]*Destination{}
	return r
}

type Service struct {
	Address  netip.Addr
	Port     uint16
	Protocol protocol

	//Scheduler uint8
	Sticky bool
	//Leastconns       bool
	//LeastconnsIP     IP4
	//LeastconnsWeight uint8

	backend map[IP4]*Destination
	state   *be_state
}
type ServiceExtended struct {
	Service Service
	Stats   Stats
}

func (s *Service) update(u Service) {
	//s.Scheduler = u.Scheduler
	s.Sticky = u.Sticky
	//s.Leastconns = u.Leastconns
	//s.LeastconnsIP = u.LeastconnsIP
	//s.LeastconnsWeight = u.LeastconnsWeight
}

func (s *Service) svc() (svc, error) {
	if !s.Address.Is4() {
		return svc{}, errors.New("Not IPv4")
		panic("Oops")
	}
	ip := s.Address.As4()
	return svc{IP: ip, Port: s.Port, Protocol: s.Protocol}, nil
}

type Destination struct {
	Address netip.Addr
	Weight  uint8
}

func (d *Destination) rip() (IP4, error) {
	if !d.Address.Is4() {
		return IP4{}, errors.New("Not IPv4")
	}

	return d.Address.As4(), nil
}

func (d *Destination) extend(ip IP4) DestinationExtended {
	var de DestinationExtended
	de.Destination.Address = netip.AddrFrom4(ip)
	de.Destination.Weight = d.Weight
	return de
}

type Stats struct {
	Packets uint64
	Octets  uint64
	Flows   uint64
}

func (s Stats) String() string { return fmt.Sprintf("p:%d o:%d f:%d", s.Packets, s.Octets, s.Flows) }

type DestinationExtended struct {
	Destination Destination
	MAC         MAC
	Stats       Stats
}

func natmap(tuples map[[2]IP4]bool, previous map[[2]IP4]uint16) (mapping map[[2]IP4]uint16) {

	mapping = map[[2]IP4]uint16{}
	inverse := map[uint16][2]IP4{}

	for k, v := range previous {
		if _, ok := tuples[k]; ok {
			if _, exists := inverse[v]; !exists {
				inverse[v] = k
				mapping[k] = v
			}
		}
	}

	var n uint16
	for k, _ := range tuples {
		if _, ok := mapping[k]; ok {
			continue
		}

	find:
		n++
		if n > 65000 {
			return
		}

		if _, ok := inverse[n]; ok {
			goto find
		}

		mapping[k] = n
	}

	return
}

func (c *Client) vlanIDs() []vc {
	var vlans []vc

	for k, v := range c.vlans {
		vlans = append(vlans, vc{k, v})
	}
	sort.SliceStable(vlans, func(i, j int) bool {
		return vlans[i].vid < vlans[j].vid
	})

	return vlans
}

func (c *Client) tag(ips []IP4) map[IP4]uint16 {
	vlans := c.vlanIDs()
	r := map[IP4]uint16{}

outer:
	for _, i := range ips {
		ip := net.IP(i[:])
		for _, v := range vlans {
			if v.net.Contains(ip) {
				r[i] = v.vid
				continue outer
			}
		}
	}

	return r
}

func (c *Client) tag1(i IP4) uint16 {
	vlans := c.vlanIDs()

	ip := net.IP(i[:])
	for _, v := range vlans {
		if v.net.Contains(ip) {
			return v.vid
		}
	}

	return 0
}

type maps = Maps
type Maps struct {
	x           *xdp.XDP
	m           map[string]int
	setting     bpf_setting
	features    bpf.Features
	defcon      uint8
	distributed bool
}

type bpf_real struct {
	rip  [4]byte //__be32
	vid  [2]byte //__be16
	mac  [6]byte
	flag [4]byte
}

type bpf_vrpp struct {
	vip      [4]byte //__be32 vip;
	rip      [4]byte //__be32 rip;
	port     [2]byte //__be16 port;
	protocol byte    //__u8 protocol;
	pad      byte    //__u8 pad;
}

type bpf_counter struct {
	packets uint64
	octets  uint64
	flows   uint64
	_pad    uint64
}

type bpf_setting struct {
	heartbeat uint32
	era       uint8
	features  uint8
	pad1      uint8
	pad2      uint8
}

type bpf_natkey struct {
	src_ip  IP4 //__be32 src_ip;
	dst_ip  IP4 //__be32 dst_ip;
	src_mac MAC //__u8 src_mac[6];
	dst_mac MAC //__u8 dst_mac[6];
}

type bpf_natval struct {
	ifindex uint32  //__u32 ifindex;
	src_ip  IP4     //__be32 src_ip;
	dst_ip  IP4     //__be32 dst_ip;
	vlan    uint16  //__u16 vlan;
	_pad    [2]byte //__u8 _pad[2];
	src_mac MAC     //__u8 src_mac[6];
	dst_mac MAC     //__u8 dst_mac[6];
}

//var SETTINGS bpf_setting = bpf_setting{defcon: 5, distributed: 1}

type bpf_global struct {
	rx_packets     uint64
	rx_octets      uint64
	perf_packets   uint64
	perf_timens    uint64
	perf_timer     uint64
	settings_timer uint64
	new_flows      uint64
	dropped        uint64
	qfailed        uint64
	blocked        uint64
}

func (g *bpf_global) add(a bpf_global) {
	g.rx_packets += a.rx_packets
	g.rx_octets += a.rx_octets
	g.perf_packets += a.perf_packets
	g.perf_timens += a.perf_timens
	g.new_flows += a.new_flows
	g.qfailed += a.qfailed
	g.dropped += a.dropped
	g.blocked += a.blocked
}

func (g *bpf_global) latency() uint64 {
	var latency uint64 = 500 // 500ns target value
	if g.perf_packets > 0 {
		latency = g.perf_timens / g.perf_packets
	}
	return latency
}

type bpf_service struct {
	vip      [4]byte
	port     [2]byte
	protocol uint8
	_pad     uint8
}

type bpf_backend struct {
	real [256]bpf_real
	hash [8192]byte
}

type bpf_active struct {
	_total  uint64
	current int64
}

type real_info struct {
	idx uint16
	mac MAC
}

type Target struct {
	VIP      IP4
	RIP      IP4
	Port     uint16
	Protocol uint8
}

func (c *bpf_counter) add(a bpf_counter) {
	c.octets += a.octets
	c.packets += a.packets
	c.flows += a.flows
}

const (
	_SERVICE_BACKEND = "service_backend"
	_NAT             = "nat"
	_GLOBALS         = "globals"
	_VRPP_COUNTER    = "vrpp_counter"
	_VRPP_CONCURRENT = "vrpp_concurrent"
	_SETTINGS        = "settings"
	_REDIRECT_MAP    = "redirect_map"
	_REDIRECT_MAC    = "redirect_mac"
	_PREFIX_COUNTERS = "prefix_counters"
	_PREFIX_DROP     = "prefix_drop"
	_FLOW_QUEUE      = "flow_queue"
	_FLOW_SHARE      = "flow_share"
)

func (m *maps) service_backend() int { return m.m[_SERVICE_BACKEND] }
func (m *maps) vrpp_counter() int    { return m.m[_VRPP_COUNTER] }
func (m *maps) vrpp_concurrent() int { return m.m[_VRPP_CONCURRENT] }
func (m *maps) globals() int         { return m.m[_GLOBALS] }
func (m *maps) settings() int        { return m.m[_SETTINGS] }
func (m *maps) nat() int             { return m.m[_NAT] }
func (m *maps) prefix_counters() int { return m.m[_PREFIX_COUNTERS] }
func (m *maps) prefix_drop() int     { return m.m[_PREFIX_DROP] }
func (m *maps) redirect_map() int    { return m.m[_REDIRECT_MAP] }
func (m *maps) redirect_mac() int    { return m.m[_REDIRECT_MAC] }
func (m *maps) flow_queue() int      { return m.m[_FLOW_QUEUE] }
func (m *maps) flow_share() int      { return m.m[_FLOW_SHARE] }

const PREFIXES = 1048576

func (m *maps) ReadPrefixCounters() [PREFIXES]uint64 {

	var prefixes [PREFIXES]uint64

	for i, _ := range prefixes {

		j := uint32(i)
		c := make([]uint64, xdp.BpfNumPossibleCpus())

		xdp.BpfMapLookupElem(m.prefix_counters(), uP(&j), uP(&(c[0])))

		var x uint64

		for _, v := range c {
			x += v
		}

		prefixes[i] = x
	}

	return prefixes
}

func (m *maps) update_redirect(vid uint16, mac MAC, idx uint32) {
	vid32 := uint32(vid)
	xdp.BpfMapUpdateElem(m.redirect_mac(), uP(&vid32), uP(&(mac)), xdp.BPF_ANY)
	xdp.BpfMapUpdateElem(m.redirect_map(), uP(&vid32), uP(&(idx)), xdp.BPF_ANY)

}

func (m *maps) update_service_backend(key *bpf_service, b *bpf_backend, flag uint64) int {

	all := make([]bpf_backend, xdp.BpfNumPossibleCpus())

	for n, _ := range all {
		all[n] = *b
	}

	return xdp.BpfMapUpdateElem(m.service_backend(), uP(key), uP(&(all[0])), flag)
}

func (m *maps) update_drop_map(drop [PREFIXES / 64]uint64) int {

	var key uint32
	val := make([]uint64, xdp.BpfNumPossibleCpus())

	for i, v := range drop {

		key = uint32(i)

		for n, _ := range val {
			val[n] = v
		}

		xdp.BpfMapUpdateElem(m.prefix_drop(), uP(&key), uP(&(val[0])), xdp.BPF_ANY)
	}

	return 0
}

func (m *maps) update_vrpp_counter(v *bpf_vrpp, c *bpf_counter, flag uint64) int {

	all := make([]bpf_counter, xdp.BpfNumPossibleCpus())

	for n, _ := range all {
		all[n] = *c
	}

	return xdp.BpfMapUpdateElem(m.vrpp_counter(), uP(v), uP(&(all[0])), flag)
}

func (m *maps) lookup_vrpp_counter(v *bpf_vrpp, c *bpf_counter) int {

	co := make([]bpf_counter, xdp.BpfNumPossibleCpus())

	ret := xdp.BpfMapLookupElem(m.vrpp_counter(), uP(v), uP(&(co[0])))

	var x bpf_counter

	for _, v := range co {
		x.add(v)
	}

	*c = x

	return ret
}

func (m *maps) update_vrpp_concurrent(era bool, v *bpf_vrpp, a *bpf_active, flag uint64) int {

	all := make([]bpf_active, xdp.BpfNumPossibleCpus())

	for n, _ := range all {
		if a != nil {
			all[n] = *a
		}
	}

	if era {
		v.pad = 1
	} else {
		v.pad = 0
	}

	return xdp.BpfMapUpdateElem(m.vrpp_concurrent(), uP(v), uP(&(all[0])), flag)
}

func (m *maps) lookup_vrpp_concurrent(era bool, v *bpf_vrpp, a *bpf_active) int {

	co := make([]bpf_active, xdp.BpfNumPossibleCpus())

	if era {
		v.pad = 1
	} else {
		v.pad = 0
	}

	ret := xdp.BpfMapLookupElem(m.vrpp_concurrent(), uP(v), uP(&(co[0])))

	var x bpf_active

	for _, v := range co {
		if v.current > 0 {
			x.current += v.current
		}
	}

	*a = x

	return ret
}

/*
#define DEFCON0 0 // LB disabled - XDP_PASS all traffic
#define DEFCON1 1 // only global stats and stateless forwarding done
#define DEFCON2 2 // per backend stats recorded
#define DEFCON3 3 // flow state table consulted
#define DEFCON4 4 // flow state table written to
#define DEFCON5 5 // flows shared via flow_queue/flow_shared
*/

func (m *maps) write_settings() int {
	var zero uint32
	m.setting.heartbeat = 0

	m.features.DISABLED = false

	switch m.defcon {
	case 5:
		m.features.SKIP_STATS = false
		m.features.SKIP_STATE = false
		m.features.SKIP_CONNS = false
		m.features.SKIP_QUEUE = !m.distributed
	case 4:
		m.features.SKIP_STATS = false
		m.features.SKIP_STATE = false
		m.features.SKIP_CONNS = false
		m.features.SKIP_QUEUE = true
	case 3:
		m.features.SKIP_STATS = false
		m.features.SKIP_STATE = false
		m.features.SKIP_CONNS = true
		m.features.SKIP_QUEUE = true
	case 2:
		m.features.SKIP_STATS = false
		m.features.SKIP_STATE = true
		m.features.SKIP_CONNS = true
		m.features.SKIP_QUEUE = true
	case 1:
		m.features.SKIP_STATS = true
		m.features.SKIP_STATE = true
		m.features.SKIP_CONNS = true
		m.features.SKIP_QUEUE = true
	case 0:
		m.features.DISABLED = true
	}

	m.setting.features = m.features.Render()

	all := make([]bpf_setting, xdp.BpfNumPossibleCpus())

	for n, _ := range all {
		all[n] = m.setting
	}

	return xdp.BpfMapUpdateElem(m.settings(), uP(&zero), uP(&(all[0])), xdp.BPF_ANY)
}

func (m *maps) MultiNIC(mode bool) {
	m.features.MULTINIC = mode
	m.write_settings()
}

func (m *maps) Distributed(d bool) {
	m.distributed = d
	m.write_settings()
}

func (m *maps) Era(era uint8) {
	m.setting.era = era
	m.write_settings()
}

func (m *maps) DEFCON(d uint8) uint8 {
	if d > 5 {
		return m.defcon
	}

	m.defcon = d
	m.write_settings()

	return m.defcon
}

func (m *maps) lookup_globals() bpf_global { //(g *bpf_global) int {

	all := make([]bpf_global, xdp.BpfNumPossibleCpus())
	var zero uint32

	xdp.BpfMapLookupElem(m.globals(), uP(&zero), uP(&(all[0])))

	var g bpf_global

	for _, v := range all {
		g.add(v)
	}

	return g
}

func natAddress(n uint16, ip IP4) IP4 {
	hl := htons(n)
	var nat IP4
	if n != 0 {
		nat[0] = ip[0]
		nat[1] = ip[1]
		nat[2] = hl[0]
		nat[3] = hl[1]
	}
	return nat
}

func find_map(x *xdp.XDP, name string, ks int, rs int) (int, error) {
	m := x.FindMap(name)

	if m == -1 {
		return 0, errors.New(name + " not found")
	}

	if !x.CheckMap(m, ks, rs) {
		return 0, errors.New(name + " incorrect size")
	}

	return m, nil
}

func htons(p uint16) [2]byte {
	var hl [2]byte
	hl[0] = byte(p >> 8)
	hl[1] = byte(p & 0xff)
	return hl
}

func arp() map[IP4]MAC {

	ip2mac := make(map[IP4]MAC)
	ip2nic := make(map[IP4]*net.Interface)

	re := regexp.MustCompile(`^(\S+)\s+0x1\s+0x[26]\s+(\S+)\s+\S+\s+(\S+)$`)

	file, err := os.OpenFile("/proc/net/arp", os.O_RDONLY, os.ModePerm)
	if err != nil {
		return nil
	}
	defer file.Close()

	s := bufio.NewScanner(file)
	for s.Scan() {
		line := s.Text()

		m := re.FindStringSubmatch(line)

		if len(m) > 3 {

			ip := net.ParseIP(m[1])

			if ip == nil {
				continue
			}

			ip = ip.To4()

			if ip == nil || len(ip) != 4 {
				continue
			}

			hw, err := net.ParseMAC(m[2])

			if err != nil || len(hw) != 6 {
				continue
			}

			iface, err := net.InterfaceByName(m[3])

			if err != nil {
				continue
			}

			var ip4 IP4
			var mac [6]byte

			copy(ip4[:], ip[:])
			copy(mac[:], hw[:])

			if ip4.String() == "0.0.0.0" {
				continue
			}

			if mac == [6]byte{0, 0, 0, 0, 0, 0} {
				continue
			}

			ip2mac[ip4] = mac
			ip2nic[ip4] = iface
		}
	}

	return ip2mac
}

func maglev8192(m map[[4]byte]uint8) (r [8192]uint8, b bool) {

	if len(m) < 1 {
		return r, false
	}

	//a := IP4s(make([]IP4, len(m)))
	a := make([]IP4, len(m))

	n := 0
	for k, _ := range m {
		a[n] = k
		n++
	}

	//sort.Sort(a)

	sort.SliceStable(a, func(i, j int) bool {
		return nltoh(a[i]) < nltoh(a[j])
	})

	h := make([][]byte, len(a))

	for k, v := range a {
		b := make([]byte, 4)
		copy(b[:], v[:])
		h[k] = b
	}

	t := maglev.Maglev8192(h)

	for k, v := range t {
		ip := a[v]
		x, ok := m[ip]
		if !ok {
			return r, false
		}
		r[k] = x
	}

	return r, true
}

func pow(x int) uint64 {
	switch x {
	case 0:
		return 0x0000000000000001
	case 1:
		return 0x0000000000000002
	case 2:
		return 0x0000000000000004
	case 3:
		return 0x0000000000000008
	case 4:
		return 0x0000000000000010
	case 5:
		return 0x0000000000000020
	case 6:
		return 0x0000000000000040
	case 7:
		return 0x0000000000000080
	case 8:
		return 0x0000000000000100
	case 9:
		return 0x0000000000000200
	case 10:
		return 0x0000000000000400
	case 11:
		return 0x0000000000000800
	case 12:
		return 0x0000000000001000
	case 13:
		return 0x0000000000002000
	case 14:
		return 0x0000000000004000
	case 15:
		return 0x0000000000008000
	case 16:
		return 0x0000000000010000
	case 17:
		return 0x0000000000020000
	case 18:
		return 0x0000000000040000
	case 19:
		return 0x0000000000080000
	case 20:
		return 0x0000000000100000
	case 21:
		return 0x0000000000200000
	case 22:
		return 0x0000000000400000
	case 23:
		return 0x0000000000800000
	case 24:
		return 0x0000000001000000
	case 25:
		return 0x0000000002000000
	case 26:
		return 0x0000000004000000
	case 27:
		return 0x0000000008000000
	case 28:
		return 0x0000000010000000
	case 29:
		return 0x0000000020000000
	case 30:
		return 0x0000000040000000
	case 31:
		return 0x0000000080000000
	case 32:
		return 0x0000000100000000
	case 33:
		return 0x0000000200000000
	case 34:
		return 0x0000000400000000
	case 35:
		return 0x0000000800000000
	case 36:
		return 0x0000001000000000
	case 37:
		return 0x0000002000000000
	case 38:
		return 0x0000004000000000
	case 39:
		return 0x0000008000000000
	case 40:
		return 0x0000010000000000
	case 41:
		return 0x0000020000000000
	case 42:
		return 0x0000040000000000
	case 43:
		return 0x0000080000000000
	case 44:
		return 0x0000100000000000
	case 45:
		return 0x0000200000000000
	case 46:
		return 0x0000400000000000
	case 47:
		return 0x0000800000000000
	case 48:
		return 0x0001000000000000
	case 49:
		return 0x0002000000000000
	case 50:
		return 0x0004000000000000
	case 51:
		return 0x0008000000000000
	case 52:
		return 0x0010000000000000
	case 53:
		return 0x0020000000000000
	case 54:
		return 0x0040000000000000
	case 55:
		return 0x0080000000000000
	case 56:
		return 0x0100000000000000
	case 57:
		return 0x0200000000000000
	case 58:
		return 0x0400000000000000
	case 59:
		return 0x0800000000000000
	case 60:
		return 0x1000000000000000
	case 61:
		return 0x2000000000000000
	case 62:
		return 0x4000000000000000
	case 63:
		return 0x8000000000000000
	}
	return 0
}
