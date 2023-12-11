package main

import (
	"flag"
	"log"
	"net/netip"
	"time"

	"github.com/davidcoles/vc5tmp"
	"github.com/davidcoles/vc5tmp/bgp"
	"github.com/davidcoles/vc5tmp/mon"
)

type strings []string

func (i *strings) String() string {
	return "my string representation"
}

func (i *strings) Set(value string) error {
	*i = append(*i, value)
	return nil
}

var extra strings

func main() {

	peer := flag.String("peer", "", "BGP peer")
	asn := flag.Int("asn", 65000, "Local Autonomous System Number")
	port := flag.Int("port", 80, "Port to run service on")
	udp := flag.Bool("udp", false, "Use UDP instead of TCP")
	monit := flag.Bool("mon", false, "Test monitoring code")

	protocol := vc5tmp.TCP

	if *udp {
		protocol = vc5tmp.UDP
	}

	flag.Var(&extra, "e", "extra interfaces")
	flag.Parse()

	args := flag.Args()

	if *monit {
		monitor(args[0], args[1:])
		return
	}

	if *port < 1 || *port > 65535 {
		log.Fatal("Port not in range 1-65535")
	}

	file := args[0]
	addr := netip.MustParseAddr(args[1])
	link := args[2]

	vip := netip.MustParseAddr(args[3])
	rip := args[4:]

	links := append([]string{link}, extra...)

	client := &vc5tmp.Client{}

	err := client.Start(addr.String(), "", links...)

	if err != nil {
		log.Fatal(err)
	}

	vlans, err := vc5tmp.Load(file)

	if err != nil {
		log.Fatal(err, vlans)
	}

	client.VLANs(vlans)

	svc := vc5tmp.Service{Address: vip, Port: uint16(*port), Protocol: protocol}
	err = client.CreateService(svc)

	if err != nil {
		log.Fatal(err)
	}

	defer client.RemoveService(svc)

	conf := map[mon.Instance]mon.Checks{}

	for _, r := range rip {
		dst := vc5tmp.Destination{Address: netip.MustParseAddr(r), Weight: 0}
		client.CreateDestination(svc, dst)

		ms := mon.Service{Address: svc.Address, Port: svc.Port, Protocol: uint8(svc.Protocol)}
		md := mon.Destination{Address: dst.Address, Port: svc.Port}
		conf[mon.Instance{Service: ms, Destination: md}] = []mon.Check{mon.Check{Type: "http", Path: "/alive"}}
	}

	if *peer != "" {
		params := bgp.Parameters{ASNumber: uint16(*asn), SourceIP: addr.As4()}
		session := bgp.NewSession(addr.As4(), *peer, params, [][4]byte{vip.As4()})
		defer func() {
			session.Close()
			sleep(3)
		}()
	}

	sleep(10)

	ds, _ := client.Destinations(svc)
	for _, d := range ds {
		d.Destination.Weight = 1
		client.UpdateDestination(svc, d.Destination)
		sleep(5)
	}

	sleep(10)

	ss, _ := client.Services()

	for _, s := range ss {

		log.Println(s)

		ds, _ := client.Destinations(svc)

		for _, d := range ds {
			log.Println(d)
		}
	}
}

func sleep(t time.Duration) {
	time.Sleep(t * time.Second)
}

func monitor(addr string, args []string) {

	check1 := mon.Check{Type: "http", Port: 80, Path: "/alive", Expect: nil}
	check2 := mon.Check{Type: "syn", Port: 80}
	check3 := mon.Check{Type: "dns", Port: 53, Method: mon.UDP}

	vip := netip.MustParseAddr(args[0])
	svc := mon.Service{Address: vip, Port: 80, Protocol: 6}
	conf1 := map[mon.Instance]mon.Checks{}
	conf2 := map[mon.Instance]mon.Checks{}

	for n, r := range args[1:] {

		rip := netip.MustParseAddr(r)
		dst := mon.Destination{Address: rip, Port: 80}
		inst := mon.Instance{Service: svc, Destination: dst}

		if n < len(args[1:])-1 {
			conf1[inst] = []mon.Check{check1}
		}

		if n > 0 {
			conf2[inst] = []mon.Check{check2, check3}
		}
	}

	ip := netip.MustParseAddr(addr)
	//ip := netip.MustParseAddr("fe80::250:56ff:fe90:7c3f")

	monitor, err := mon.New(ip, conf1)

	if err != nil {
		log.Fatal(err)
	}

	defer monitor.Stop()

	watch(monitor, 20*time.Second)

	monitor.Update(conf2)

	watch(monitor, 20*time.Second)
}

func watch(monitor *mon.Mon, t time.Duration) {
	timer := time.NewTimer(t)
	defer timer.Stop()

	for {
		select {
		case <-timer.C:
			return
		case <-monitor.C:
			log.Println("Something changed")
			for instance, status := range monitor.Dump() {
				log.Println(instance, status)
			}
		}
	}
}
