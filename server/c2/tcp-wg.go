package c2

import (
	"bytes"
	"encoding/binary"
	"fmt"
	"net"
	"sync"

	"github.com/bishopfox/sliver/protobuf/sliverpb"
	"github.com/bishopfox/sliver/server/core"
	serverHandlers "github.com/bishopfox/sliver/server/handlers"
	"github.com/bishopfox/sliver/server/log"
	"github.com/golang/protobuf/proto"
	"golang.zx2c4.com/wireguard/conn"
	"golang.zx2c4.com/wireguard/device"
	"golang.zx2c4.com/wireguard/tun/netstack"
)

var (
	wgLog = log.NamedLogger("c2", "wg")
)

func StartWGListener(bindIface string, port uint16) (net.Listener, *device.Device, error) {
	StartPivotListener()
	wgLog.Infof("Starting Wireguard listener on %s:%d", bindIface, port)
	// host := bindIface

	tun, tnet, err := netstack.CreateNetTUN(
		[]net.IP{net.ParseIP("192.168.2.1")},
		[]net.IP{net.ParseIP("8.8.8.8"), net.ParseIP("8.8.4.4")},
		1420,
	)
	if err != nil {
		wgLog.Panic(err)
	}
	dev := device.NewDevice(tun, conn.NewDefaultBind(), device.NewLogger(device.LogLevelVerbose, ""))
	dev.IpcSet(`private_key=b8055828ad81690bcc015f32cd1c42caf247ffa7eed164356336df11a233a045
listen_port=53
public_key=508f17a2c841c152fc926e986690aa5ea81e44504bea68e52b6fb5c65201de77
allowed_ip=192.168.2.2/32
`)
	dev.Up()

	listener, err := tnet.ListenTCP(&net.TCPAddr{IP: net.ParseIP("192.168.2.1"), Port: 8888})
	if err != nil {
		wgLog.Panic(err)
	}

	go acceptWGSliverConnections(listener)
	return listener, dev, nil
}

func acceptWGSliverConnections(ln net.Listener) {
	for {
		conn, err := ln.Accept()
		if err != nil {
			if errType, ok := err.(*net.OpError); ok && errType.Op == "accept" {
				break
			}
			mtlsLog.Errorf("Accept failed: %v", err)
			continue
		}
		go handleWGSliverConnection(conn)
	}
}

func handleWGSliverConnection(conn net.Conn) {
	mtlsLog.Infof("Accepted incoming connection: %s", conn.RemoteAddr())

	session := &core.Session{
		Transport:     "wg",
		RemoteAddress: fmt.Sprintf("%s", conn.RemoteAddr()),
		Send:          make(chan *sliverpb.Envelope),
		RespMutex:     &sync.RWMutex{},
		Resp:          map[uint64]chan *sliverpb.Envelope{},
	}
	session.UpdateCheckin()

	defer func() {
		mtlsLog.Debugf("Cleaning up for %s", session.Name)
		core.Sessions.Remove(session.ID)
		conn.Close()
	}()

	done := make(chan bool)

	go func() {
		defer func() {
			done <- true
		}()
		handlers := serverHandlers.GetSessionHandlers()
		for {
			envelope, err := socketWGReadEnvelope(conn)
			if err != nil {
				mtlsLog.Errorf("Socket read error %v", err)
				return
			}
			session.UpdateCheckin()
			if envelope.ID != 0 {
				session.RespMutex.RLock()
				if resp, ok := session.Resp[envelope.ID]; ok {
					resp <- envelope // Could deadlock, maybe want to investigate better solutions
				}
				session.RespMutex.RUnlock()
			} else if handler, ok := handlers[envelope.Type]; ok {
				go handler.(func(*core.Session, []byte))(session, envelope.Data)
			}
		}
	}()

Loop:
	for {
		select {
		case envelope := <-session.Send:
			err := socketWGWriteEnvelope(conn, envelope)
			if err != nil {
				mtlsLog.Errorf("Socket write failed %v", err)
				break Loop
			}
		case <-done:
			break Loop
		}
	}
	mtlsLog.Infof("Closing connection to session %s", session.Name)
}

// socketWGWriteEnvelope - Writes a message to the TLS socket using length prefix framing
// which is a fancy way of saying we write the length of the message then the message
// e.g. [uint32 length|message] so the receiver can delimit messages properly
func socketWGWriteEnvelope(connection net.Conn, envelope *sliverpb.Envelope) error {
	data, err := proto.Marshal(envelope)
	if err != nil {
		mtlsLog.Errorf("Envelope marshaling error: %v", err)
		return err
	}
	dataLengthBuf := new(bytes.Buffer)
	binary.Write(dataLengthBuf, binary.LittleEndian, uint32(len(data)))
	connection.Write(dataLengthBuf.Bytes())
	connection.Write(data)
	return nil
}

// socketWGReadEnvelope - Reads a message from the TLS connection using length prefix framing
// returns messageType, message, and error
func socketWGReadEnvelope(connection net.Conn) (*sliverpb.Envelope, error) {

	// Read the first four bytes to determine data length
	dataLengthBuf := make([]byte, 4) // Size of uint32
	_, err := connection.Read(dataLengthBuf)
	if err != nil {
		mtlsLog.Errorf("Socket error (read msg-length): %v", err)
		return nil, err
	}
	dataLength := int(binary.LittleEndian.Uint32(dataLengthBuf))

	// Read the length of the data, keep in mind each call to .Read() may not
	// fill the entire buffer length that we specify, so instead we use two buffers
	// readBuf is the result of each .Read() operation, which is then concatinated
	// onto dataBuf which contains all of data read so far and we keep calling
	// .Read() until the running total is equal to the length of the message that
	// we're expecting or we get an error.
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
			mtlsLog.Errorf("Read error: %s", err)
			break
		}
	}

	if err != nil {
		mtlsLog.Errorf("Socket error (read data): %v", err)
		return nil, err
	}
	// Unmarshal the protobuf envelope
	envelope := &sliverpb.Envelope{}
	err = proto.Unmarshal(dataBuf, envelope)
	if err != nil {
		mtlsLog.Errorf("Un-marshaling envelope error: %v", err)
		return nil, err
	}
	return envelope, nil
}
