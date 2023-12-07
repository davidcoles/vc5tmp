package main

import (
	"flag"
	"log"
	"net/netip"
	"time"

	"github.com/davidcoles/vc5tmp"
	"github.com/davidcoles/vc5tmp/bgp"
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

	protocol := vc5tmp.TCP

	if *udp {
		protocol = vc5tmp.UDP
	}

	flag.Var(&extra, "e", "extra interfaces")
	flag.Parse()

	if *port < 1 || *port > 65535 {
		log.Fatal("Port not in range 1-65535")
	}

	args := flag.Args()

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

	for _, r := range rip {
		dst := vc5tmp.Destination{Address: netip.MustParseAddr(r), Weight: 1}
		client.CreateDestination(svc, dst)
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
