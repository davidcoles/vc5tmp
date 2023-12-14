package main

import (
	"flag"
	"fmt"
	"log"
	"net"
	"net/netip"
	"time"

	"github.com/davidcoles/vc5tmp"
	//"github.com/davidcoles/vc5tmp/bgp"
	//"github.com/davidcoles/vc5tmp/mon"
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

/*

First argument needs to be a file which contains something like:

{
    "10": "10.1.10.0/24",
    "20": "10.1.20.0/24",
    "30": "10.1.30.0/24"
}

*/

func main() {

	file := flag.String("v", "", "JSON file to read VLAN info from")
	port := flag.Int("p", 80, "Port to run service on")
	udp := flag.Bool("u", false, "Use UDP instead of TCP")
	multi := flag.Bool("m", false, "Multi NIC mode")
	nat := flag.Bool("n", false, "NAT (creates a network namespace and interfaces)")
	flag.Var(&extra, "i", "extra interfaces")
	flag.Parse()

	args := flag.Args()

	protocol := vc5tmp.TCP

	if *udp {
		protocol = vc5tmp.UDP
	}

	if *port < 1 || *port > 65535 {
		log.Fatal("Port not in range 1-65535")
	}

	link := args[0]
	addr := netip.MustParseAddr(args[1])

	vip := netip.MustParseAddr(args[2])
	rip := args[3:]

	links := append([]string{link}, extra...)

	var vlans map[uint16]net.IPNet

	var err error

	if *file != "" {
		vlans, err = vc5tmp.Load(*file)

		if err != nil {
			log.Fatal(err)
		}
	}

	client := &vc5tmp.Client{
		Interfaces: links,
		VLANs:      vlans,
		NAT:        *nat,
		MultiNIC:   *multi,
	}

	err = client.Start(addr, "")

	if err != nil {
		log.Fatal(err)
	}

	fmt.Println(vlans)

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

	sleep(10)

	ss, _ := client.Services()

	for _, s := range ss {

		log.Println(s)

		ds, _ := client.Destinations(svc)

		for _, d := range ds {
			log.Println(d)
		}
	}

	sleep(60)

}

func sleep(t time.Duration) {
	time.Sleep(t * time.Second)
}
