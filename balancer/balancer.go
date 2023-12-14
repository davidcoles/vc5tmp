package main

import (
	"flag"
	"fmt"
	"log"
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

	port := flag.Int("port", 80, "Port to run service on")
	udp := flag.Bool("udp", false, "Use UDP instead of TCP")

	protocol := vc5tmp.TCP

	if *udp {
		protocol = vc5tmp.UDP
	}

	flag.Var(&extra, "e", "extra interfaces")
	flag.Parse()

	args := flag.Args()

	if *port < 1 || *port > 65535 {
		log.Fatal("Port not in range 1-65535")
	}

	file := args[0]
	link := args[1]
	addr := netip.MustParseAddr(args[2])

	vip := netip.MustParseAddr(args[3])
	rip := args[4:]

	links := append([]string{link}, extra...)

	client := &vc5tmp.Client{
		Interfaces: links,
	}

	err := client.Start(addr, "")

	if err != nil {
		log.Fatal(err)
	}

	vlans, err := vc5tmp.Load(file)

	if err != nil {
		log.Fatal(err, vlans)
	}

	fmt.Println(vlans)

	client.VLANs(vlans)

	svc := vc5tmp.Service{Address: vip, Port: uint16(*port), Protocol: protocol}
	err = client.CreateService(svc)

	if err != nil {
		log.Fatal(err)
	}

	defer client.RemoveService(svc)

	for _, r := range rip {
		dst := vc5tmp.Destination{Address: netip.MustParseAddr(r), Weight: 0}
		client.CreateDestination(svc, dst)
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

	sleep(60)

}

func sleep(t time.Duration) {
	time.Sleep(t * time.Second)
}
