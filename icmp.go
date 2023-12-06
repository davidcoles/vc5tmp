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
	"net"
	"time"
)

type ICMPs struct {
	submit chan string
}

func ICMP() *ICMPs {

	var icmp ICMPs

	c, err := net.ListenPacket("ip4:icmp", "")
	if err != nil {
		//log.Fatalf("listen err, %s", err)
		return nil
	}

	icmp.submit = make(chan string, 1000)
	go icmp.probe(c)

	return &icmp
}

func (s *ICMPs) Ping(target string) {
	select {
	case s.submit <- target:
	default:
	}
}

func (s *ICMPs) Close() {
	close(s.submit)
}

func (s *ICMPs) echoRequest() []byte {

	var csum uint32
	wb := make([]byte, 8)

	wb[0] = 8
	wb[1] = 0

	for n := 0; n < 8; n += 2 {
		csum += uint32(uint16(wb[n])<<8 | uint16(wb[n+1]))
	}

	var cs uint16

	cs = uint16(csum>>16) + uint16(csum&0xffff)
	cs = ^cs

	wb[2] = byte(cs >> 8)
	wb[3] = byte(cs & 0xff)

	return wb
}

func (s *ICMPs) probe(socket net.PacketConn) {

	defer socket.Close()

	for target := range s.submit {
		go func() {
			socket.SetWriteDeadline(time.Now().Add(1 * time.Second))
			socket.WriteTo(s.echoRequest(), &net.IPAddr{IP: net.ParseIP(target)})
		}()
	}
}
