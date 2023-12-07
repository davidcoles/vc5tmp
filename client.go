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
	"encoding/json"
	"io/ioutil"
	"os"

	"errors"
	"fmt"
	"log"
	"net"
	"sort"
	"sync"
	"syscall"
	"time"
	"unsafe"

	"github.com/davidcoles/vc5tmp/bpf"
	"github.com/davidcoles/vc5tmp/xdp"
)

const (
	A = false
	B = true
)

type be_state struct {
	sticky      bool
	fallback    bool
	leastconns  IP4
	weight      uint8
	bpf_backend bpf_backend
	bpf_reals   map[IP4]bpf_real
}

type Client struct {
	mutex sync.Mutex

	service map[svc]*Service

	netns netns
	maps  *maps
	icmp  *ICMPs
	nat   []natkeyval

	hwaddr map[IP4]MAC

	update chan bool

	tag_map tag_map
	nat_map nat_map
	vlans   map[uint16]prefix // only get updated by config change
}

func (b *Client) arp() map[IP4]MAC {
	return arp()
}

func (b *Client) Start(address string, nic string, phy ...string) error {
	b.vlans = map[uint16]prefix{}
	b.nat_map = map[[2]IP4]uint16{}
	b.tag_map = map[IP4]uint16{}
	b.service = map[svc]*Service{}
	b.hwaddr = map[IP4]MAC{}

	b.update = make(chan bool, 1)

	ip := net.ParseIP(address).To4()

	if ip == nil || len(ip) != 4 {
		return errors.New("Invalid IP address: " + address)
	}

	if nic == "" {
		nic = phy[0]
	}

	iface, err := net.InterfaceByName(nic)
	if err != nil {
		return err
	}

	err = b.netns.Init(IP4{ip[0], ip[1], ip[2], ip[3]}, iface)

	if err != nil {
		return err
	}

	fmt.Println(b.netns)

	b.maps, err = open(false, true, b.netns.IfA, b.netns.IfB, phy...)

	if err != nil {
		return err
	}

	err = b.netns.Open()

	if err != nil {
		return err
	}

	b.icmp = ICMP()

	go b.background()

	return nil
}

func (b *Client) ping() {
	b.mutex.Lock()
	defer b.mutex.Unlock()

	addr := map[IP4]bool{}

	for _, service := range b.service {
		for ip, _ := range service.backend {
			addr[ip] = true
		}
	}

	for ip, _ := range addr {
		b.icmp.Ping(ip.String())
	}
}

func (b *Client) background() {
	var era uint8
	b.maps.Era(era)

	ticker := time.NewTicker(2 * time.Second)
	defer ticker.Stop()

	arp := time.NewTicker(2 * time.Second)
	defer arp.Stop()

	for {
		select {
		case <-ticker.C:
			b.ping()

			era++
			b.maps.Era(era)

		case <-arp.C:
			b.update_arp()

		case <-b.update:
			b.update_nat()
			b.update_services()
		}
	}
}

func (b *Client) update_arp() {
	b.mutex.Lock()
	defer b.mutex.Unlock()

	hwaddr := map[IP4]MAC{}

	var changed bool

	arp := b.arp()

	for _, ip := range b.nat_map.rip() {

		new, ok := arp[ip]

		if !ok {
			continue
		}

		old, ok := b.hwaddr[ip]

		if !ok || new != old {
			changed = true
		}

		hwaddr[ip] = new

		delete(b.hwaddr, ip)
	}

	if len(b.hwaddr) != 0 {
		changed = true
	}

	b.hwaddr = hwaddr

	if changed {
		fmt.Println("ARP CHANGED", hwaddr)
		select {
		case b.update <- true:
		default:
		}
	}
}

func (b *Client) update_nat() {

	b.mutex.Lock()
	defer b.mutex.Unlock()

	nat_map := b.nat_map.get()
	tag_map := b.tag_map.get()

	old := map[bpf_natkey]bpf_natval{}

	for _, e := range b.nat {
		old[e.key] = e.val
	}

	var changed bool

	nat := b.nat_entries(nat_map, tag_map, b.hwaddr)

	var updated, deleted int

	// apply all entries
	for _, e := range nat {
		k := e.key
		v := e.val

		if x, ok := old[k]; !ok || v != x {
			changed = true
			updated++
			xdp.BpfMapUpdateElem(b.maps.nat(), uP(&(e.key)), uP(&(e.val)), xdp.BPF_ANY)
		}

		delete(old, k)
	}

	for k, _ := range old {
		deleted++
		xdp.BpfMapDeleteElem(b.maps.nat(), uP(&(k)))
	}

	b.nat = nat

	fmt.Println("NAT: entries", len(nat), "updated", updated, "deleted", deleted)

	// should determine if anything has changed (eg. MAC)

	if changed {

		fmt.Println("NAT CHANGED")
		select {
		case b.update <- true: // trigger rebuild of forwarding
		default:
		}
	}
}

func (b *Client) update_services() {
	b.mutex.Lock()
	defer b.mutex.Unlock()

	for svc, service := range b.service {
		b.update_service(svc, service, b.hwaddr, false)
	}
}

func (b *Client) update_nat_map() {

	nm := map[[2]IP4]bool{}

	for svc, service := range b.service {
		for rip, _ := range service.backend {
			vip := svc.IP
			nm[[2]IP4{vip, rip}] = true
		}
	}

	b.nat_map.set(nm)

	go func() {
		time.Sleep(time.Second)
		select {
		case b.update <- true:
		default:
		}
	}()
}

/********************************************************************************/

func (b *Client) Services() ([]ServiceExtended, error) {
	b.mutex.Lock()
	defer b.mutex.Unlock()

	var services []ServiceExtended

	for svc, service := range b.service {
		var se ServiceExtended
		se.Service = service.Service(svc)

		for rip, _ := range service.backend {
			v := bpf_vrpp{vip: svc.IP, rip: rip, port: htons(svc.Port), protocol: uint8(svc.Protocol)}
			c := bpf_counter{}
			b.maps.lookup_vrpp_counter(&v, &c)
			se.Stats.Packets += c.packets
			se.Stats.Octets += c.octets
			se.Stats.Flows += c.flows
		}

		services = append(services, se)
	}

	return services, nil
}

func (b *Client) CreateService(s Service) error {
	b.mutex.Lock()
	defer b.mutex.Unlock()

	svc, err := s.svc()

	if err != nil {
		return err
	}

	_, ok := b.service[svc]

	if ok {
		return errors.New("Exists")
	}

	s.backend = map[IP4]*Destination{}
	s.state = nil

	b.service[svc] = &s

	b.maps.update_vrpp_counter(&bpf_vrpp{vip: svc.IP}, &bpf_counter{}, xdp.BPF_NOEXIST)

	b.update_service(svc, &s, b.hwaddr, true)

	return nil
}

func (b *Client) UpdateService(s Service) error {
	b.mutex.Lock()
	defer b.mutex.Unlock()

	svc, err := s.svc()

	if err != nil {
		return err
	}

	service, ok := b.service[svc]

	if !ok {
		return errors.New("Service does not exist")
	}

	service.update(s)

	b.update_service(svc, service, b.hwaddr, false)

	return nil
}

func (b *Client) RemoveService(s Service) error {
	b.mutex.Lock()
	defer b.mutex.Unlock()

	svc, err := s.svc()

	if err != nil {
		return err
	}

	service, ok := b.service[svc]

	if !ok {
		return errors.New("Service does not exist")
	}

	for ip, _ := range service.backend {
		b.removeDestination(svc, service, ip, true)
	}

	sb := bpf_service{vip: svc.IP, port: htons(s.Port), protocol: uint8(s.Protocol)}
	xdp.BpfMapDeleteElem(b.maps.service_backend(), uP(&sb))
	xdp.BpfMapDeleteElem(b.maps.vrpp_counter(), uP(&bpf_vrpp{vip: svc.IP}))

	delete(b.service, svc)

	b.update_nat_map()

	return nil
}

func (b *Client) CreateDestination(s Service, d Destination) error {
	b.mutex.Lock()
	defer b.mutex.Unlock()

	svc, err := s.svc()

	if err != nil {
		return err
	}

	service, ok := b.service[svc]

	if !ok {
		return errors.New("Service does not exist")
	}

	rip, err := d.rip()

	if err != nil {
		return err
	}

	_, ok = service.backend[rip]

	if ok {
		return errors.New("Destination exists")
	}

	vid := b.tag1(rip)

	b.tag_map.set(rip, vid)

	service.backend[rip] = &d

	b.icmp.Ping(rip.String())

	b.update_service(svc, service, b.hwaddr, false)

	vr := bpf_vrpp{vip: svc.IP, rip: rip, port: htons(svc.Port), protocol: uint8(svc.Protocol)}
	b.maps.update_vrpp_counter(&vr, &bpf_counter{}, xdp.BPF_NOEXIST)
	b.maps.update_vrpp_concurrent(A, &vr, nil, xdp.BPF_NOEXIST) // create 'A' counter if it does not exist
	b.maps.update_vrpp_concurrent(B, &vr, nil, xdp.BPF_NOEXIST) // create 'B' counter if it does not exist

	b.update_nat_map()

	return nil
}

func (b *Client) Destinations(s Service) ([]DestinationExtended, error) {
	b.mutex.Lock()
	defer b.mutex.Unlock()

	var destinations []DestinationExtended

	svc, err := s.svc()

	if err != nil {
		return destinations, err
	}

	service, ok := b.service[svc]

	if !ok {
		return destinations, errors.New("Service does not exist")
	}

	vip := svc.IP
	port := htons(svc.Port)
	protocol := uint8(svc.Protocol)

	for rip, d := range service.backend {
		de := d.extend(rip)
		v := bpf_vrpp{vip: vip, rip: rip, port: port, protocol: protocol}
		c := bpf_counter{}
		b.maps.lookup_vrpp_counter(&v, &c)
		de.Stats.Packets = c.packets
		de.Stats.Octets = c.octets
		de.Stats.Flows = c.flows
		de.MAC = b.hwaddr[rip]
		destinations = append(destinations, de)
	}

	return destinations, nil
}

func (b *Client) UpdateDestination(s Service, d Destination) error {
	b.mutex.Lock()
	defer b.mutex.Unlock()

	svc, err := s.svc()

	if err != nil {
		return err
	}

	service, ok := b.service[svc]

	if !ok {
		return errors.New("Service does not exist")
	}

	rip, err := d.rip()

	if err != nil {
		return err
	}

	dest, ok := service.backend[rip]

	if !ok {
		return errors.New("Destination does not exist")
	}

	dest.Weight = d.Weight

	select {
	case b.update <- true:
	default:
	}

	return nil
}

func (b *Client) RemoveDestination(s Service, d Destination) error {
	b.mutex.Lock()
	defer b.mutex.Unlock()

	svc, err := s.svc()

	if err != nil {
		return err
	}

	service, ok := b.service[svc]

	if !ok {
		return errors.New("Service does not exist")
	}

	rip, err := d.rip()

	if err != nil {
		return err
	}

	_, ok = service.backend[rip]

	if !ok {
		return errors.New("Destination does not exist")
	}

	b.removeDestination(svc, service, rip, false)

	b.update_service(svc, service, b.hwaddr, false)

	b.update_nat_map()

	return nil
}

/********************************************************************************/

func (b *Client) removeDestination(svc svc, s *Service, rip IP4, bulk bool) {

	delete(s.backend, rip)

	if !bulk {
		b.update_service(svc, s, b.hwaddr, false)
	}

	vr := bpf_vrpp{vip: svc.IP, rip: rip, port: htons(svc.Port), protocol: uint8(svc.Protocol)}
	xdp.BpfMapDeleteElem(b.maps.vrpp_counter(), uP(&vr))
	xdp.BpfMapDeleteElem(b.maps.vrpp_concurrent(), uP(&vr))
	vr.pad = 1
	xdp.BpfMapDeleteElem(b.maps.vrpp_concurrent(), uP(&vr))
}

func (b *Client) update_service(svc svc, s *Service, arp map[IP4]MAC, force bool) {

	bpf_reals := map[IP4]bpf_real{}

	for ip, real := range s.backend {
		mac := arp[ip]
		vid := b.tag1(ip)
		if !ip.IsNil() && !mac.IsNil() && real.Weight > 0 && vid < 4095 {
			bpf_reals[ip] = bpf_real{rip: ip, mac: mac, vid: htons(vid)}
		}
	}

	key := &bpf_service{vip: svc.IP, port: htons(svc.Port), protocol: uint8(svc.Protocol)}
	val := &be_state{fallback: false, sticky: s.Sticky, bpf_reals: bpf_reals}

	//if s.Leastconns {
	//	val.leastconns = s.LeastconnsIP
	//	val.weight = s.LeastconnsWeight
	//}

	now := time.Now()

	if force || update_backend(val, s.state) {
		b.maps.update_service_backend(key, &(val.bpf_backend), xdp.BPF_ANY)
		fmt.Println("Updated table for ", svc, val.bpf_backend.hash[:32], time.Now().Sub(now))
		s.state = val
	}
}

func (m *Maps) set_map(name string, k, v int) (err error) {
	m.m[name], err = find_map(m.x, name, k, v)
	return err
}

func open(native, multi bool, vetha, vethb string, eth ...string) (*Maps, error) {

	ulimit_l()

	var m maps
	m.m = make(map[string]int)
	m.defcon = 5

	x, err := xdp.LoadBpfProgram(BPF_O)
	m.x = x

	if err != nil {
		return nil, err
	}

	if vetha != "" {
		err = x.LoadBpfSection("outgoing", false, vetha)
		if err != nil {
			return nil, err
		}
	}

	if vethb != "" {
		err = x.LoadBpfSection("outgoing", true, vethb)
		if err != nil {
			return nil, err
		}
	}

	for _, e := range eth {
		err = x.LoadBpfSection("incoming", native, e)
		if err != nil {
			return nil, err
		}
	}

	var global bpf_global
	var vrpp bpf_vrpp
	var counter bpf_counter
	var active bpf_active

	global_s := int(unsafe.Sizeof(global))
	vrpp_s := int(unsafe.Sizeof(vrpp))
	counter_s := int(unsafe.Sizeof(counter))
	active_s := int(unsafe.Sizeof(active))

	type mi struct {
		name string
		klen int
		vlen int
	}

	maps := []mi{
		mi{_SERVICE_BACKEND, 8, (256 * 16) + 8192},
		mi{_NAT, 20, 28},
		mi{_GLOBALS, 4, global_s},
		mi{_VRPP_COUNTER, vrpp_s, counter_s},
		mi{_VRPP_CONCURRENT, vrpp_s, active_s},
		mi{_SETTINGS, 4, 8},
		mi{_REDIRECT_MAP, 4, 4},
		mi{_REDIRECT_MAC, 4, 6},
		mi{_PREFIX_COUNTERS, 4, 8},
		mi{_PREFIX_DROP, 4, 8},
		mi{_FLOW_QUEUE, 0, bpf.FLOW_S + bpf.STATE_S},
		mi{_FLOW_SHARE, bpf.FLOW_S, bpf.STATE_S},
	}

	for _, x := range maps {
		if err = m.set_map(x.name, x.klen, x.vlen); err != nil {
			return nil, err
		}
	}

	m.MultiNIC(multi)

	if m.write_settings() != 0 {
		return nil, errors.New("Failed to write settings")
	}

	return &m, nil
}

func ulimit_l() {
	const RLIMIT_MEMLOCK = 8

	var resource int = RLIMIT_MEMLOCK

	var rLimit syscall.Rlimit
	if err := syscall.Getrlimit(resource, &rLimit); err != nil {
		log.Fatal("Error Getting Rlimit ", err)
	}
	rLimit.Max = 0xffffffffffffffff
	rLimit.Cur = 0xffffffffffffffff
	if err := syscall.Setrlimit(resource, &rLimit); err != nil {
		log.Fatal("Error Setting Rlimit ", err)
	}
}

// func update_backend(curr, prev *be_state, l types.Logger) bool {
func update_backend(curr, prev *be_state) bool {

	if !curr.diff(prev) {
		return false
	}

	var flag [4]byte

	if curr.sticky {
		flag[0] |= bpf.F_STICKY
	}

	if curr.fallback {
		flag[0] |= bpf.F_FALLBACK
	}

	mapper := map[[4]byte]uint8{}

	var list []IP4

	for ip, _ := range curr.bpf_reals {
		list = append(list, ip)
	}

	sort.SliceStable(list, func(i, j int) bool {
		return nltoh(list[i]) < nltoh(list[j])
	})

	var real [256]bpf_real

	for i, ip := range list {
		if i < 255 {
			idx := uint8(i) + 1
			mapper[ip] = idx
			real[idx] = curr.bpf_reals[ip]
		} else {
			fmt.Println("more than 255 hosts", ip, i)
		}
	}

	curr.bpf_backend.real = real
	curr.bpf_backend.hash, _ = maglev8192(mapper)

	var rip IP4
	var mac MAC
	var vid [2]byte

	if !curr.leastconns.IsNil() {
		if n, ok := mapper[curr.leastconns]; ok {
			flag[1] = curr.weight
			rip = real[n].rip
			mac = real[n].mac
			vid = real[n].vid
		}
	}

	curr.bpf_backend.real[0] = bpf_real{rip: rip, mac: mac, vid: vid, flag: flag}

	return true
}

func (curr *be_state) diff(prev *be_state) bool {

	if prev == nil {
		return true
	}

	if curr.sticky != prev.sticky ||
		curr.fallback != prev.fallback ||
		curr.leastconns != prev.leastconns ||
		curr.weight != prev.weight {
		return true
	}

	if bpf_reals_differ(curr.bpf_reals, prev.bpf_reals) {
		return true
	}

	return false
}

func bpf_reals_differ(a, b map[IP4]bpf_real) bool {
	for k, v := range a {
		if x, ok := b[k]; !ok {
			return true
		} else {
			if x != v {
				return true
			}
		}
	}

	for k, _ := range b {
		if _, ok := a[k]; !ok {
			return true
		}
	}

	return false
}

type iface struct {
	idx uint32
	ip4 IP4
	mac MAC
}

func (b *Client) ifaces() map[uint16]iface {
	return VlanInterfaces(b.vlans)
}

func (b *Client) nat_entries(nat_map nat_map, tag_map tag_map, arp map[IP4]MAC) (nkv []natkeyval) {

	ifaces := VlanInterfaces(b.vlans)

	for vid, iface := range ifaces {
		b.maps.update_redirect(vid, iface.mac, iface.idx)
	}

	for k, v := range nat_map {
		vip := k[0]
		rip := k[1]
		nat := b.natAddr(v)
		mac := arp[rip]
		vid := tag_map[rip]
		idx := ifaces[vid]

		if mac.IsNil() {
			continue
		}

		if (len(b.vlans) != 0 && vid == 0) || (len(b.vlans) == 0 && vid != 0) {
			continue
		}

		if vid == 0 {
			idx = b.netns.phys
		}

		nkv = append(nkv, b.natEntry(vip, rip, nat, mac, vid, idx)...)
	}

	return
}

func (b *Client) VLANs(vlans map[uint16]prefix) {
	b.vlans = vlans
}

type natkeyval struct {
	key bpf_natkey
	val bpf_natval
}

func (b *Client) NATAddr(vip, rip IP4) (r IP4, _ bool) {
	i := b.nat_map.ent(vip, rip)

	if i == 0 {
		return r, false
	}

	return b.natAddr(i), true
}

func (b *Client) natAddr(i uint16) IP4 {
	ns := htons(i)
	return IP4{10, 255, ns[0], ns[1]}
}

func (b *Client) natEntry(vip, rip, nat IP4, realhw MAC, vlanid uint16, idx iface) (ret []natkeyval) {

	vlanip := idx.ip4
	vlanhw := idx.mac
	vlanif := idx.idx

	var vc5bip IP4 = b.netns.IpB
	var vc5bhw MAC = b.netns.HwB
	var vc5ahw MAC = b.netns.HwA
	var vethif uint32 = uint32(b.netns.Index)

	if realhw.IsNil() {
		return
	}

	key := bpf_natkey{src_ip: vc5bip, dst_ip: nat, src_mac: vc5bhw, dst_mac: vc5ahw}
	val := bpf_natval{src_ip: vlanip, dst_ip: vip, src_mac: vlanhw, dst_mac: realhw, ifindex: vlanif, vlan: vlanid}

	ret = append(ret, natkeyval{key: key, val: val})

	key = bpf_natkey{src_ip: vip, src_mac: realhw, dst_ip: vlanip, dst_mac: vlanhw}
	val = bpf_natval{src_ip: nat, src_mac: vc5ahw, dst_ip: vc5bip, dst_mac: vc5bhw, ifindex: vethif}

	ret = append(ret, natkeyval{key: key, val: val})

	return
}

func (b *Client) _natEntry(vip, rip, nat IP4, realhw MAC, vlanid uint16, idx iface) (ret []natkeyval) {

	var physif uint32 = b.netns.Physif
	var physhw MAC = b.netns.Physhw

	var vc5bip IP4 = b.netns.IpB
	var vc5bhw MAC = b.netns.HwB
	var vc5ahw MAC = b.netns.HwA

	fmt.Println("********************", physif, physhw)

	var vethif uint32 = uint32(b.netns.Index)

	vlanip := idx.ip4

	if realhw.IsNil() {
		return
	}

	key := bpf_natkey{src_ip: vc5bip, dst_ip: nat, src_mac: vc5bhw, dst_mac: vc5ahw}
	val := bpf_natval{src_ip: vlanip, dst_ip: vip, src_mac: physhw, dst_mac: realhw, ifindex: physif, vlan: vlanid}

	ret = append(ret, natkeyval{key: key, val: val})

	key = bpf_natkey{src_ip: vip, src_mac: realhw, dst_ip: vlanip, dst_mac: physhw}
	val = bpf_natval{src_ip: nat, src_mac: vc5ahw, dst_ip: vc5bip, dst_mac: vc5bhw, ifindex: vethif}

	ret = append(ret, natkeyval{key: key, val: val})

	return
}

func VlanInterfaces(in map[uint16]prefix) map[uint16]iface {
	out := map[uint16]iface{}

	for vid, pref := range in {
		if iface, ok := VlanInterface(pref); ok {
			out[vid] = iface
		}
	}

	return out
}

func VlanInterface(prefix prefix) (ret iface, _ bool) {
	ifaces, err := net.Interfaces()

	if err != nil {
		return
	}

	for _, i := range ifaces {

		if i.Flags&net.FlagLoopback != 0 {
			continue
		}

		if i.Flags&net.FlagUp == 0 {
			continue
		}

		if i.Flags&net.FlagBroadcast == 0 {
			continue
		}

		if len(i.HardwareAddr) != 6 {
			continue
		}

		var mac MAC
		copy(mac[:], i.HardwareAddr[:])

		addr, err := i.Addrs()

		if err == nil {
			for _, a := range addr {
				cidr := a.String()
				ip, ipnet, err := net.ParseCIDR(cidr)

				if err == nil && ipnet.String() == prefix.String() {
					ip4 := ip.To4()
					if len(ip4) == 4 && ip4 != nil {
						//return iface{idx: uint32(i.Index), ip4: IP4{ip4[0], ip4[1], ip4[2], ip4[3]}, mac: mac}, true
						return iface{idx: uint32(i.Index), ip4: IP4(ip4), mac: mac}, true
					}
				}
			}
		}
	}

	return
}

type prefix net.IPNet

func (p *prefix) String() string {
	return (*net.IPNet)(p).String()
}

func (p *prefix) Contains(i net.IP) bool {
	return (*net.IPNet)(p).Contains(i)
}

func (p *prefix) UnmarshalJSON(data []byte) error {

	l := len(data)

	if l < 3 || data[0] != '"' || data[l-1] != '"' {
		return errors.New("CIDR address should be a string: " + string(data))
	}

	cidr := string(data[1 : l-1])

	ip, ipnet, err := net.ParseCIDR(cidr)

	if err != nil {
		return err
	}

	if ip.String() != ipnet.IP.String() {
		return errors.New("CIDR address contains host portion: " + cidr)
	}

	*p = prefix(*ipnet)

	return nil
}

func Load(file string) (map[uint16]prefix, error) {

	f, err := os.Open(file)

	if err != nil {
		return nil, err
	}

	defer f.Close()

	b, err := ioutil.ReadAll(f)

	if err != nil {
		return nil, err
	}

	var foo map[uint16]prefix

	err = json.Unmarshal(b, &foo)

	if err != nil {
		return nil, err
	}

	return foo, nil
}
