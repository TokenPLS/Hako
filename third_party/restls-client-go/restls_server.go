package tls

import (
	"bytes"
	"context"
	"crypto/rand"
	"encoding/binary"
	"errors"
	"fmt"
	"hash"
	"io"
	mathrand "math/rand"
	"net"
	"sync"
	"time"

	"github.com/metacubex/blake3"
)

// RestlsServerConfig configures a Restls server connection.
type RestlsServerConfig struct {
	// ServerHostname is the camouflage target contacted and relayed during the
	// Restls handshake. If no port is present, :443 is used.
	ServerHostname string

	// Password is the shared Restls password. It is expanded into the traffic
	// authentication key with the same derivation used by NewRestlsConfig.
	Password string

	// RestlsScript controls the server-to-client record sizing and fake response
	// behavior. If empty, the package default script is used.
	RestlsScript string

	// MinRecordLen is the minimum server-to-client Restls record target length
	// used after the script is exhausted. If zero, RestlsServer uses 15.
	MinRecordLen int

	// RateLimit limits fallback relay traffic in bits per second in each
	// direction. If zero, fallback traffic is not rate limited.
	RateLimit uint64

	// DialContext opens the outbound connection to ServerHostname. If nil,
	// RestlsServer uses a zero-value net.Dialer.
	DialContext func(ctx context.Context, network, address string) (net.Conn, error)
}

var errInvalidTargetRecord = errors.New("restls: invalid target TLS record")
var errInvalidTLSRecordHeader = errors.New("restls: invalid TLS record header")
var errRawRelayClosed = errors.New("restls: raw relay closed without Restls connection")
var restlsServerScriptCache sync.Map

const (
	restlsServerCloseDrainTimeout = time.Second
	bitsPerByte                   = 8
	rateLimitCycle                = 10 * time.Millisecond
	maxRateLimitBurstBytes        = 64 * 1024
)

// RestlsServer completes the Restls handshake and returns the authenticated
// plaintext connection.
func RestlsServer(ctx context.Context, inbound net.Conn, config *RestlsServerConfig) (net.Conn, error) {
	success := false
	defer func() {
		if !success {
			inbound.Close()
		}
	}()
	if config == nil {
		return nil, errors.New("restls: nil server config")
	}
	if config.MinRecordLen <= 0 {
		configCopy := *config
		configCopy.MinRecordLen = 15
		config = &configCopy
	}
	targetAddr := restlsHostPort(config.ServerHostname)
	dialContext := config.DialContext
	if dialContext == nil {
		var dialer net.Dialer
		dialContext = dialer.DialContext
	}

	target, err := dialContext(ctx, "tcp", targetAddr)
	if err != nil {
		return nil, err
	}
	defer func() {
		if !success {
			target.Close()
		}
	}()

	state, err := newRestlsServerState(config)
	if err != nil {
		return nil, err
	}
	defer func() {
		if !success {
			state.stopTargetRecordReader()
		}
	}()

	firstClientRecord, err := readTLSRecord(inbound)
	if err != nil {
		if len(firstClientRecord) > 0 {
			if _, writeErr := target.Write(firstClientRecord); writeErr != nil {
				return nil, writeErr
			}
			return nil, relayRaw(inbound, target, config.RateLimit)
		}
		return nil, err
	}
	clientHello, err := parseClientHelloRecord(firstClientRecord)
	if err != nil {
		if _, writeErr := target.Write(firstClientRecord); writeErr != nil {
			return nil, writeErr
		}
		return nil, relayRaw(inbound, target, config.RateLimit)
	}
	state.clientHello = clientHello
	if _, err := target.Write(firstClientRecord); err != nil {
		return nil, err
	}

	firstServerRecord, err := readTLSRecord(target)
	if err != nil {
		if len(firstServerRecord) > 0 {
			if _, writeErr := inbound.Write(firstServerRecord); writeErr != nil {
				return nil, writeErr
			}
			return nil, relayRaw(inbound, target, config.RateLimit)
		}
		return nil, err
	}
	serverHello, err := parseServerHelloRecord(firstServerRecord)
	if err != nil {
		if _, writeErr := inbound.Write(firstServerRecord); writeErr != nil {
			return nil, writeErr
		}
		return nil, relayRaw(inbound, target, config.RateLimit)
	}
	if bytes.Equal(serverHello.random, helloRetryRequestRandom) {
		if _, writeErr := inbound.Write(firstServerRecord); writeErr != nil {
			return nil, writeErr
		}
		return nil, relayRaw(inbound, target, config.RateLimit)
	}
	state.serverRandom = serverHello.random
	state.isTLS13 = serverHello.supportedVersion == VersionTLS13
	state.isTLS12GCM = isRestlsTLS12GCMCipher(serverHello.cipherSuite)
	state.tls13DidResume = serverHello.selectedIdentityPresent
	if _, err := inbound.Write(firstServerRecord); err != nil {
		return nil, err
	}

	if state.isTLS13 {
		if err := state.checkTLS13ClientAuth(); err != nil {
			return nil, relayRaw(inbound, target, config.RateLimit)
		}
		if err := state.handshakeTLS13(inbound, target); err != nil {
			return nil, err
		}
	} else {
		if err := state.handshakeTLS12(inbound, target, firstServerRecord); err != nil {
			if state.tls12Authenticated {
				return nil, err
			}
			return nil, relayRaw(inbound, target, config.RateLimit)
		}
	}

	conn := &restlsServerConn{
		ctx:     ctx,
		inbound: inbound,
		target:  target,
		state:   state,
	}
	conn.start()
	success = true
	return conn, nil
}

func restlsHostPort(host string) string {
	if _, _, err := net.SplitHostPort(host); err == nil {
		return host
	}
	return net.JoinHostPort(host, "443")
}

type restlsServerState struct {
	clientHello *clientHelloMsg

	secret       []byte
	serverRandom []byte
	script       []Line
	minRecordLen int

	isTLS13             bool
	isTLS12GCM          bool
	tls12Authenticated  bool
	tls13DidResume      bool
	tls13TargetRawCount int
	parrotGCM           bool
	clientFinRaw        []byte
	pendingClientRecord []byte
	closeNotifyCache    []byte

	toClientCounter uint64
	toServerCounter uint64

	targetRecords    <-chan restlsServerRecordResult
	targetRecordDone chan struct{}
	targetRecordStop sync.Once

	writeMu sync.Mutex

	awaitMu           sync.Mutex
	awaitCond         *sync.Cond
	awaitClientRecord bool
	closed            bool
}

type restlsServerRecordResult struct {
	record []byte
	err    error
}

func newRestlsServerState(config *RestlsServerConfig) (state *restlsServerState, err error) {
	key := make([]byte, 32)
	blake3.DeriveKey(key, "restls-traffic-key", []byte(config.Password))
	script := config.RestlsScript
	if script == "" {
		script = defaultRestlsScript
	}
	parsedScript, err := cachedRestlsServerScript(script)
	if err != nil {
		return nil, err
	}
	state = &restlsServerState{
		secret:       key,
		script:       parsedScript,
		minRecordLen: config.MinRecordLen,
	}
	state.awaitCond = sync.NewCond(&state.awaitMu)
	return state, nil
}

func cachedRestlsServerScript(script string) ([]Line, error) {
	if cached, ok := restlsServerScriptCache.Load(script); ok {
		return cached.([]Line), nil
	}
	parsed, err := parseRecordScript(script)
	if err != nil {
		return nil, err
	}
	cached, _ := restlsServerScriptCache.LoadOrStore(script, parsed)
	return cached.([]Line), nil
}

func readTLSRecord(conn net.Conn) ([]byte, error) {
	hdr := make([]byte, recordHeaderLen)
	n, err := io.ReadFull(conn, hdr)
	if err != nil {
		return hdr[:n], err
	}
	payloadLen := int(hdr[3])<<8 | int(hdr[4])
	version := uint16(hdr[1])<<8 | uint16(hdr[2])
	if !isTLSRecordType(recordType(hdr[0])) || version < VersionSSL30 || version > VersionTLS13 || payloadLen > maxCiphertext {
		return hdr, errInvalidTLSRecordHeader
	}
	record := make([]byte, recordHeaderLen+payloadLen)
	copy(record, hdr)
	n, err = io.ReadFull(conn, record[recordHeaderLen:])
	return record[:recordHeaderLen+n], err
}

func isTLSRecordType(typ recordType) bool {
	switch typ {
	case recordTypeChangeCipherSpec, recordTypeAlert, recordTypeHandshake, recordTypeApplicationData:
		return true
	default:
		return false
	}
}

func isValidTargetTLSRecord(record []byte) bool {
	if len(record) < recordHeaderLen {
		return false
	}
	if !isTLSRecordType(recordType(record[0])) {
		return false
	}
	vers := uint16(record[1])<<8 | uint16(record[2])
	if vers < VersionTLS10 || vers > VersionTLS13 {
		return false
	}
	n := int(record[3])<<8 | int(record[4])
	return len(record) == recordHeaderLen+n
}

func parseClientHelloRecord(record []byte) (*clientHelloMsg, error) {
	if len(record) <= recordHeaderLen || recordType(record[0]) != recordTypeHandshake {
		return nil, errors.New("restls: expected ClientHello record")
	}
	msg, err := firstHandshakeMessage(record)
	if err != nil {
		return nil, err
	}
	ch := new(clientHelloMsg)
	if !ch.unmarshal(msg) {
		return nil, errors.New("restls: failed to parse ClientHello")
	}
	return ch, nil
}

func parseServerHelloRecord(record []byte) (*serverHelloMsg, error) {
	if len(record) <= recordHeaderLen || recordType(record[0]) != recordTypeHandshake {
		return nil, errors.New("restls: expected ServerHello record")
	}
	msg, err := firstHandshakeMessage(record)
	if err != nil {
		return nil, err
	}
	sh := new(serverHelloMsg)
	if !sh.unmarshal(msg) {
		return nil, errors.New("restls: failed to parse ServerHello")
	}
	return sh, nil
}

func firstHandshakeMessage(record []byte) ([]byte, error) {
	if len(record) < recordHeaderLen+4 {
		return nil, errors.New("restls: short handshake record")
	}
	payload := record[recordHeaderLen:]
	n := int(payload[1])<<16 | int(payload[2])<<8 | int(payload[3])
	if len(payload) < 4+n {
		return nil, errors.New("restls: fragmented first handshake message")
	}
	return payload[:4+n], nil
}

func isRestlsTLS12GCMCipher(id uint16) bool {
	for _, candidate := range tls12GCMCiphers {
		if id == candidate {
			return true
		}
	}
	return false
}

func (s *restlsServerState) checkTLS13ClientAuth() error {
	if len(s.clientHello.sessionId) != 32 {
		return errors.New("restls: TLS 1.3 session id must be 32 bytes")
	}
	hmac := RestlsHmac(s.secret)
	for _, ks := range s.clientHello.keyShares {
		hmac.Write([]byte{byte(ks.group >> 8), byte(ks.group)})
		hmac.Write(ks.data)
	}
	for _, psk := range s.clientHello.pskIdentities {
		hmac.Write(psk.label)
	}
	expect := hmac.Sum(nil)[:restlsHandshakeMACLength]
	if !bytes.Equal(expect, s.clientHello.sessionId[:restlsHandshakeMACLength]) {
		return errors.New("restls: bad TLS 1.3 client auth")
	}
	return nil
}

func (s *restlsServerState) handshakeTLS13(inbound, target net.Conn) error {
	s.startTargetRecordReader(target)
	seenServerCCS := false
	for {
		record, err := s.readTargetRecord(target)
		if err != nil {
			return err
		}
		switch recordType(record[0]) {
		case recordTypeChangeCipherSpec:
			if seenServerCCS {
				return errors.New("restls: duplicate TLS 1.3 server CCS")
			}
			seenServerCCS = true
			if _, err := inbound.Write(record); err != nil {
				return err
			}
		case recordTypeApplicationData:
			if !seenServerCCS {
				return errors.New("restls: TLS 1.3 encrypted server flight before CCS")
			}
			s.maskServerAuth(record)
			if _, err := inbound.Write(record); err != nil {
				return err
			}
			return s.finishTLS13Handshake(inbound, target)
		default:
			return fmt.Errorf("restls: unexpected TLS 1.3 server record type %d", record[0])
		}
	}
}

func (s *restlsServerState) startTargetRecordReader(target net.Conn) {
	records := make(chan restlsServerRecordResult, 1)
	done := make(chan struct{})
	s.targetRecords = records
	s.targetRecordDone = done
	go func() {
		defer close(records)
		for {
			record, err := readTLSRecord(target)
			select {
			case records <- restlsServerRecordResult{record: record, err: err}:
			case <-done:
				return
			}
			if err != nil {
				return
			}
		}
	}()
}

func (s *restlsServerState) stopTargetRecordReader() {
	if s.targetRecordDone == nil {
		return
	}
	s.targetRecordStop.Do(func() {
		close(s.targetRecordDone)
	})
}

func (s *restlsServerState) readTargetRecord(target net.Conn) ([]byte, error) {
	if s.targetRecords == nil {
		return readTLSRecord(target)
	}
	result, ok := <-s.targetRecords
	if !ok {
		return nil, io.ErrUnexpectedEOF
	}
	return result.record, result.err
}

func readTLSRecordAsync(conn net.Conn) <-chan restlsServerRecordResult {
	result := make(chan restlsServerRecordResult, 1)
	go func() {
		record, err := readTLSRecord(conn)
		result <- restlsServerRecordResult{record: record, err: err}
		close(result)
	}()
	return result
}

func (s *restlsServerState) finishTLS13Handshake(inbound, target net.Conn) error {
	seenClientCCS := false
	var clientRecord <-chan restlsServerRecordResult
	for {
		if clientRecord == nil {
			clientRecord = readTLSRecordAsync(inbound)
		}
		select {
		case result, ok := <-s.targetRecords:
			if !ok {
				return io.ErrUnexpectedEOF
			}
			if result.err != nil {
				return result.err
			}
			if recordType(result.record[0]) != recordTypeApplicationData {
				return fmt.Errorf("restls: unexpected TLS 1.3 server flight record type %d", result.record[0])
			}
			if _, err := inbound.Write(result.record); err != nil {
				return err
			}
			s.tls13TargetRawCount++
		case result := <-clientRecord:
			clientRecord = nil
			if result.err != nil {
				return result.err
			}
			switch recordType(result.record[0]) {
			case recordTypeChangeCipherSpec:
				if seenClientCCS {
					return errors.New("restls: duplicate TLS 1.3 client CCS")
				}
				if !isRestlsCCSRecord(result.record) {
					return errors.New("restls: incorrect TLS 1.3 client CCS")
				}
				seenClientCCS = true
				if _, err := target.Write(result.record); err != nil {
					return err
				}
			case recordTypeApplicationData:
				return s.readTLS13ClientHandshake(inbound, target, result.record)
			default:
				return fmt.Errorf("restls: unexpected TLS 1.3 client record type %d", result.record[0])
			}
		}
	}
}

func (s *restlsServerState) readTLS13ClientHandshake(inbound, target net.Conn, record []byte) error {
	var previousClientRecord []byte
	clientHandshakeRecords := 0
	for {
		switch recordType(record[0]) {
		case recordTypeChangeCipherSpec:
			return errors.New("restls: unexpected TLS 1.3 client CCS after encrypted client flight")
		case recordTypeApplicationData:
			if previousClientRecord != nil && s.isFirstRestlsClientRecord(record, previousClientRecord) {
				s.clientFinRaw = previousClientRecord
				s.pendingClientRecord = record
				s.accountTLS13EarlyTargetRecords(clientHandshakeRecords)
				return nil
			}
			previousClientRecord = append(previousClientRecord[:0], record...)
			if _, err := target.Write(record); err != nil {
				return err
			}
			clientHandshakeRecords++
		default:
			return fmt.Errorf("restls: unexpected TLS 1.3 client record type %d", record[0])
		}
		var err error
		record, err = readTLSRecord(inbound)
		if err != nil {
			return err
		}
	}
}

func (s *restlsServerState) accountTLS13EarlyTargetRecords(clientHandshakeRecords int) {
	expectedServerFlightRecords := 3
	if s.tls13DidResume {
		expectedServerFlightRecords = 1
	} else if clientHandshakeRecords > 1 {
		expectedServerFlightRecords = 4
	}
	if extraRecords := s.tls13TargetRawCount - expectedServerFlightRecords; extraRecords > 0 {
		s.toClientCounter += uint64(extraRecords)
	}
}

func (s *restlsServerState) isFirstRestlsClientRecord(record, clientFinished []byte) bool {
	if len(record) < recordHeaderLen+restlsAppDataAuthHeaderLength || recordType(record[0]) != recordTypeApplicationData {
		return false
	}
	header := record[:recordHeaderLen]
	payloadOffset := recordHeaderLen
	if s.isTLS12GCM {
		if len(record) < recordHeaderLen+8+restlsAppDataAuthHeaderLength {
			return false
		}
		if binary.BigEndian.Uint64(record[recordHeaderLen:recordHeaderLen+8]) != s.toServerCounter+1 {
			return false
		}
		header = record[:recordHeaderLen+8]
		payloadOffset += 8
	}
	payload := append([]byte(nil), record[payloadOffset:]...)

	hmacAuth := s.authHeaderHash(false)
	hmacAuth.Write(clientFinished)
	hmacAuth.Write(header)
	hmacAuth.Write(payload[restlsAppDataLenOffset:])
	expect := hmacAuth.Sum(nil)[:restlsAppDataMACLength]
	if !bytes.Equal(expect, payload[:restlsAppDataMACLength]) {
		return false
	}

	hmacMask := s.authHeaderHash(false)
	sampleSize := 32
	if sampleSize > len(payload[restlsAppDataOffset:]) {
		sampleSize = len(payload[restlsAppDataOffset:])
	}
	hmacMask.Write(payload[restlsAppDataOffset : restlsAppDataOffset+sampleSize])
	mask := hmacMask.Sum(nil)[:restlsMaskLength]
	xorWithMac(payload[restlsAppDataLenOffset:], mask)
	dataLen := int(binary.BigEndian.Uint16(payload[restlsAppDataLenOffset:]))
	if _, err := parseCommand(payload[restlsAppDataLenOffset+2:]); err != nil {
		return false
	}
	return dataLen <= len(payload)-restlsAppDataOffset
}

func (s *restlsServerState) handshakeTLS12(inbound, target net.Conn, firstServerRecord []byte) error {
	var selectedCurve CurveID
	serverHelloDone := false
	var messages handshakeMessageReader
	processHandshakeRecord := func(record []byte) error {
		return messages.addRecord(record, func(msg []byte) bool {
			if len(msg) >= 7 && msg[0] == typeServerKeyExchange && msg[4] == 3 {
				selectedCurve = CurveID(msg[5])<<8 | CurveID(msg[6])
			}
			if len(msg) > 0 && msg[0] == typeServerHelloDone {
				serverHelloDone = true
				return false
			}
			return true
		})
	}
	if err := processHandshakeRecord(firstServerRecord); err != nil {
		return err
	}
	if serverHelloDone {
		return s.finishTLS12FullHandshake(inbound, target, selectedCurve)
	}
	for {
		record, err := readTLSRecord(target)
		if err != nil {
			if len(record) > 0 {
				if _, writeErr := inbound.Write(record); writeErr != nil {
					return writeErr
				}
			}
			return err
		}
		switch recordType(record[0]) {
		case recordTypeHandshake:
			if _, err := inbound.Write(record); err != nil {
				return err
			}
			if err := processHandshakeRecord(record); err != nil {
				return err
			}
			if serverHelloDone {
				return s.finishTLS12FullHandshake(inbound, target, selectedCurve)
			}
		case recordTypeChangeCipherSpec:
			if _, err := inbound.Write(record); err != nil {
				return err
			}
			if err := s.checkTLS12SessionTicket(); err != nil {
				return err
			}
			s.tls12Authenticated = true
			return s.finishTLS12ResumedHandshake(inbound, target)
		default:
			if _, err := inbound.Write(record); err != nil {
				return err
			}
			return fmt.Errorf("restls: unexpected TLS 1.2 server record type before client flight: %d", record[0])
		}
	}
}

func (s *restlsServerState) finishTLS12FullHandshake(inbound, target net.Conn, selectedCurve CurveID) error {
	seenClientCCS := false
	var messages handshakeMessageReader
	for {
		record, err := readTLSRecord(inbound)
		if err != nil {
			if len(record) > 0 {
				if _, writeErr := target.Write(record); writeErr != nil {
					return writeErr
				}
			}
			return err
		}
		var authenticationErr error
		if recordType(record[0]) == recordTypeHandshake && !seenClientCCS && !s.tls12Authenticated && selectedCurve != 0 {
			parseErr := messages.addRecord(record, func(msg []byte) bool {
				if len(msg) == 0 || msg[0] != typeClientKeyExchange {
					return true
				}
				ckx := new(clientKeyExchangeMsg)
				if !ckx.unmarshal(msg) {
					authenticationErr = errors.New("restls: malformed TLS 1.2 ClientKeyExchange")
					return false
				}
				authenticationErr = s.checkTLS12ClientKeyExchange(ckx, selectedCurve)
				if authenticationErr == nil {
					s.tls12Authenticated = true
				}
				return false
			})
			if parseErr != nil {
				authenticationErr = parseErr
			}
		}
		var recordErr error
		if recordType(record[0]) == recordTypeChangeCipherSpec {
			if seenClientCCS {
				recordErr = errors.New("restls: duplicate TLS 1.2 client CCS")
			} else if !isRestlsCCSRecord(record) {
				recordErr = errors.New("restls: incorrect TLS 1.2 client CCS")
			} else {
				seenClientCCS = true
			}
		}
		if _, err := target.Write(record); err != nil {
			return err
		}
		if authenticationErr != nil {
			return authenticationErr
		}
		if recordErr != nil {
			return recordErr
		}
		if seenClientCCS && recordType(record[0]) != recordTypeChangeCipherSpec {
			break
		}
	}
	if !s.tls12Authenticated {
		return errors.New("restls: TLS 1.2 ClientKeyExchange was not authenticated")
	}

	for {
		record, err := readTLSRecord(target)
		if err != nil {
			return err
		}
		if recordType(record[0]) == recordTypeChangeCipherSpec {
			if _, err := inbound.Write(record); err != nil {
				return err
			}
			break
		}
		if recordType(record[0]) != recordTypeHandshake {
			return errors.New("restls: expected TLS 1.2 server CCS")
		}
		if _, err := inbound.Write(record); err != nil {
			return err
		}
	}

	record, err := readTLSRecord(target)
	if err != nil {
		return err
	}
	if recordType(record[0]) != recordTypeHandshake {
		return errors.New("restls: expected TLS 1.2 ServerFinished")
	}
	s.maskServerAuth(record)
	_, err = inbound.Write(record)
	return err
}

func (s *restlsServerState) finishTLS12ResumedHandshake(inbound, target net.Conn) error {
	record, err := readTLSRecord(target)
	if err != nil {
		return err
	}
	if recordType(record[0]) != recordTypeHandshake {
		return errors.New("restls: expected TLS 1.2 resumed ServerFinished")
	}
	s.maskServerAuth(record)
	if _, err := inbound.Write(record); err != nil {
		return err
	}
	return s.readTLS12ClientFinished(inbound, target)
}

func (s *restlsServerState) readTLS12ClientFinished(inbound, target net.Conn) error {
	seenClientCCS := false
	for {
		record, err := readTLSRecord(inbound)
		if err != nil {
			return err
		}
		switch recordType(record[0]) {
		case recordTypeChangeCipherSpec:
			if seenClientCCS {
				return errors.New("restls: duplicate TLS 1.2 client CCS")
			}
			if !isRestlsCCSRecord(record) {
				return errors.New("restls: incorrect TLS 1.2 client CCS")
			}
			seenClientCCS = true
			if _, err := target.Write(record); err != nil {
				return err
			}
		case recordTypeHandshake:
			if !seenClientCCS {
				return errors.New("restls: TLS 1.2 client Finished before CCS")
			}
			s.clientFinRaw = append([]byte(nil), record...)
			_, err := target.Write(record)
			return err
		default:
			return fmt.Errorf("restls: unexpected TLS 1.2 client record type %d", record[0])
		}
	}
}

func (s *restlsServerState) checkTLS12ClientKeyExchange(ckx *clientKeyExchangeMsg, curveID CurveID) error {
	if len(s.clientHello.sessionId) != 32 {
		return errors.New("restls: TLS 1.2 session id must be 32 bytes")
	}
	curveIndex, ok := curveIDMap[curveID]
	if !ok {
		return fmt.Errorf("restls: unsupported TLS 1.2 curve %d", curveID)
	}
	if len(ckx.ciphertext) == 0 || int(ckx.ciphertext[0]) != len(ckx.ciphertext)-1 {
		return errors.New("restls: malformed TLS 1.2 ClientKeyExchange")
	}
	layout := restls12ClientAuthLayout3
	if len(s.clientHello.sessionTicket) > 0 {
		layout = restls12ClientAuthLayout4
	}
	actual := s.clientHello.sessionId[layout[curveIndex]:layout[curveIndex+1]]
	hmac := RestlsHmac(s.secret)
	hmac.Write(ckx.ciphertext[1:])
	expect := hmac.Sum(nil)
	if !bytes.Equal(expect[:len(actual)], actual) {
		return errors.New("restls: bad TLS 1.2 client auth")
	}
	return nil
}

func (s *restlsServerState) checkTLS12SessionTicket() error {
	if len(s.clientHello.sessionId) != 32 {
		return errors.New("restls: TLS 1.2 session id must be 32 bytes")
	}
	if len(s.clientHello.sessionTicket) == 0 {
		return errors.New("restls: TLS 1.2 resumption requires a session ticket")
	}
	layout := restls12ClientAuthLayout4
	actual := s.clientHello.sessionId[layout[3]:layout[4]]
	hmac := RestlsHmac(s.secret)
	hmac.Write(s.clientHello.sessionTicket)
	expect := hmac.Sum(nil)
	if !bytes.Equal(expect[:len(actual)], actual) {
		return errors.New("restls: bad TLS 1.2 session ticket auth")
	}
	return nil
}

func (s *restlsServerState) maskServerAuth(record []byte) {
	hmac := RestlsHmac(s.secret)
	hmac.Write(s.serverRandom)
	mask := hmac.Sum(nil)[:restlsHandshakeMACLength]
	offset := recordHeaderLen
	if s.isTLS12GCM && len(record) >= recordHeaderLen+8 && binary.BigEndian.Uint64(record[recordHeaderLen:recordHeaderLen+8]) == 0 {
		offset += 8
		s.parrotGCM = true
	}
	xorWithMac(record[offset:], mask)
}

func isRestlsCCSRecord(record []byte) bool {
	return bytes.Equal(record, []byte{byte(recordTypeChangeCipherSpec), 0x03, 0x03, 0x00, 0x01, 0x01})
}

type handshakeMessageReader struct {
	pending []byte
}

func (r *handshakeMessageReader) addRecord(record []byte, fn func([]byte) bool) error {
	if len(record) < recordHeaderLen || recordType(record[0]) != recordTypeHandshake {
		return errors.New("restls: expected TLS handshake record")
	}
	r.pending = append(r.pending, record[recordHeaderLen:]...)
	for len(r.pending) >= 4 {
		n := int(r.pending[1])<<16 | int(r.pending[2])<<8 | int(r.pending[3])
		if n > maxHandshake {
			return fmt.Errorf("restls: TLS handshake message length %d exceeds maximum %d", n, maxHandshake)
		}
		if len(r.pending) < 4+n {
			return nil
		}
		msg := r.pending[:4+n]
		r.pending = r.pending[4+n:]
		if !fn(msg) {
			return nil
		}
	}
	if len(r.pending) == 0 {
		r.pending = nil
	}
	return nil
}

func relayRaw(a, b net.Conn, rateLimit uint64) error {
	b = newRateLimitedConn(b, rateLimit)
	errc := make(chan error, 2)
	go func() {
		_, err := io.Copy(a, b)
		errc <- err
	}()
	go func() {
		_, err := io.Copy(b, a)
		errc <- err
	}()
	err := <-errc
	_ = a.Close()
	_ = b.Close()
	if err != nil {
		return err
	}
	return errRawRelayClosed
}

type rateLimitedConn struct {
	net.Conn
	ctx          context.Context
	cancel       context.CancelFunc
	readLimiter  *bitRateLimiter
	writeLimiter *bitRateLimiter
	burst        int
}

func newRateLimitedConn(conn net.Conn, rateBps uint64) net.Conn {
	if rateBps == 0 {
		return conn
	}
	burst := rateBps / bitsPerByte / uint64(time.Second/rateLimitCycle)
	if burst == 0 {
		burst = 1
	} else if burst > maxRateLimitBurstBytes {
		burst = maxRateLimitBurstBytes
	}
	limitCtx, cancel := context.WithCancel(context.Background())
	return &rateLimitedConn{
		Conn:         conn,
		ctx:          limitCtx,
		cancel:       cancel,
		readLimiter:  &bitRateLimiter{rateBps: rateBps},
		writeLimiter: &bitRateLimiter{rateBps: rateBps},
		burst:        int(burst),
	}
}

func (c *rateLimitedConn) Read(p []byte) (n int, err error) {
	if len(p) > c.burst {
		p = p[:c.burst]
	}
	n, err = c.Conn.Read(p)
	if n > 0 {
		if limitErr := c.readLimiter.WaitN(c.ctx, n); err == nil {
			err = limitErr
		}
	}
	return
}

func (c *rateLimitedConn) Write(p []byte) (n int, err error) {
	for len(p) > 0 {
		chunkSize := len(p)
		if chunkSize > c.burst {
			chunkSize = c.burst
		}
		if err = c.writeLimiter.WaitN(c.ctx, chunkSize); err != nil {
			return n, err
		}
		var written int
		written, err = c.Conn.Write(p[:chunkSize])
		n += written
		p = p[written:]
		if err != nil {
			return n, err
		}
		if written != chunkSize {
			return n, io.ErrShortWrite
		}
	}
	return n, nil
}

func (c *rateLimitedConn) Close() error {
	c.cancel()
	return c.Conn.Close()
}

func (c *rateLimitedConn) CloseWrite() error {
	if conn, ok := c.Conn.(interface{ CloseWrite() error }); ok {
		return conn.CloseWrite()
	}
	return c.Close()
}

type bitRateLimiter struct {
	mu      sync.Mutex
	rateBps uint64
	next    time.Time
}

func (l *bitRateLimiter) WaitN(ctx context.Context, n int) error {
	delay := l.reserveN(time.Now(), n)
	if delay <= 0 {
		return nil
	}
	timer := time.NewTimer(delay)
	defer timer.Stop()
	select {
	case <-timer.C:
		return nil
	case <-ctx.Done():
		return ctx.Err()
	}
}

func (l *bitRateLimiter) reserveN(now time.Time, n int) time.Duration {
	interval := time.Duration(uint64(n) * bitsPerByte * uint64(time.Second) / l.rateBps)

	l.mu.Lock()
	ready := l.next
	if ready.Before(now) {
		ready = now
	}
	l.next = ready.Add(interval)
	l.mu.Unlock()
	return ready.Sub(now)
}

type restlsServerConn struct {
	ctx     context.Context
	inbound net.Conn
	target  net.Conn
	state   *restlsServerState

	readMu  sync.Mutex
	readBuf []byte

	closeOnce sync.Once
	closed    chan struct{}
}

func (c *restlsServerConn) start() {
	c.closed = make(chan struct{})
	go c.relayTargetPostHandshake()
	if c.ctx != nil {
		go func() {
			select {
			case <-c.ctx.Done():
				c.Close()
			case <-c.closed:
			}
		}()
	}
}

func (s *restlsServerState) writeTargetRecord(inbound net.Conn, record []byte) error {
	if !isValidTargetTLSRecord(record) {
		return errInvalidTargetRecord
	}
	s.writeMu.Lock()
	s.parrotTLS12GCMNonce(record)
	_, err := inbound.Write(record)
	if err == nil {
		s.toClientCounter++
	}
	s.writeMu.Unlock()
	return err
}

func (c *restlsServerConn) Read(p []byte) (int, error) {
	if len(p) == 0 {
		return 0, nil
	}
	c.readMu.Lock()
	defer c.readMu.Unlock()
	if c.isClosed() {
		return 0, net.ErrClosed
	}
	if len(c.readBuf) > 0 {
		n := copy(p, c.readBuf)
		c.readBuf = c.readBuf[n:]
		return n, nil
	}
	for {
		record := c.state.pendingClientRecord
		c.state.pendingClientRecord = nil
		if record == nil {
			var err error
			record, err = readTLSRecord(c.inbound)
			if err != nil {
				if c.isClosed() {
					return 0, net.ErrClosed
				}
				return 0, err
			}
		}
		if c.isClosed() {
			return 0, net.ErrClosed
		}
		if recordType(record[0]) == recordTypeAlert {
			return 0, io.EOF
		}
		data, command, err := c.state.readRestlsAppData(record)
		if err != nil {
			return 0, err
		}
		c.state.noteClientRecord()
		if response, ok := command.(ActResponse); ok && response > 0 {
			for i := 0; i < int(response); i++ {
				if err := c.state.writeRestlsRecords(c.inbound, nil); err != nil {
					return 0, err
				}
			}
		}
		if len(data) == 0 {
			continue
		}
		n := copy(p, data)
		if n < len(data) {
			c.readBuf = append(c.readBuf[:0], data[n:]...)
		}
		return n, nil
	}
}

func (c *restlsServerConn) Write(p []byte) (int, error) {
	if len(p) == 0 {
		return 0, nil
	}
	if c.isClosed() {
		return 0, net.ErrClosed
	}
	if err := c.state.writeRestlsRecords(c.inbound, p); err != nil {
		return 0, err
	}
	return len(p), nil
}

func (c *restlsServerConn) isClosed() bool {
	select {
	case <-c.closed:
		return true
	default:
		return false
	}
}

func (c *restlsServerConn) Close() error {
	var err error
	c.closeOnce.Do(func() {
		close(c.closed)
		c.state.close()
		c.state.stopTargetRecordReader()
		if closeNotifyErr := c.state.writeCachedCloseNotify(c.inbound); err == nil {
			err = closeNotifyErr
		}
		if targetErr := c.target.Close(); err == nil {
			err = targetErr
		}
		if inbound, ok := c.inbound.(interface{ CloseWrite() error }); ok {
			_ = c.inbound.SetReadDeadline(time.Now().Add(restlsServerCloseDrainTimeout))
			if inboundErr := inbound.CloseWrite(); err == nil {
				err = inboundErr
			}
			go func() {
				c.readMu.Lock()
				defer c.readMu.Unlock()
				_, _ = io.Copy(io.Discard, c.inbound)
				_ = c.inbound.Close()
			}()
			return
		}
		if inboundErr := c.inbound.Close(); err == nil {
			err = inboundErr
		}
	})
	return err
}

func (s *restlsServerState) close() {
	s.awaitMu.Lock()
	s.closed = true
	s.awaitCond.Broadcast()
	s.awaitMu.Unlock()
}

func (c *restlsServerConn) LocalAddr() net.Addr {
	return c.inbound.LocalAddr()
}

func (c *restlsServerConn) RemoteAddr() net.Addr {
	return c.inbound.RemoteAddr()
}

func (c *restlsServerConn) SetDeadline(t time.Time) error {
	return c.inbound.SetDeadline(t)
}

func (c *restlsServerConn) SetReadDeadline(t time.Time) error {
	return c.inbound.SetReadDeadline(t)
}

func (c *restlsServerConn) SetWriteDeadline(t time.Time) error {
	return c.inbound.SetWriteDeadline(t)
}

func (c *restlsServerConn) relayTargetPostHandshake() {
	for {
		record, err := c.state.readTargetRecord(c.target)
		if err != nil {
			return
		}
		if len(record) < 50 {
			c.state.cacheCloseNotify(record)
			continue
		}
		if err := c.state.writeTargetRecord(c.inbound, record); err != nil {
			c.Close()
			return
		}
	}
}

func (s *restlsServerState) authHeaderHash(isToClient bool) hash.Hash {
	h := RestlsHmac(s.secret)
	h.Write(s.serverRandom)
	counterBytes := make([]byte, 8)
	if isToClient {
		h.Write([]byte("server-to-client"))
		binary.BigEndian.PutUint64(counterBytes, s.toClientCounter)
	} else {
		h.Write([]byte("client-to-server"))
		binary.BigEndian.PutUint64(counterBytes, s.toServerCounter)
	}
	h.Write(counterBytes)
	return h
}

func (s *restlsServerState) readRestlsAppData(record []byte) ([]byte, restlsCommand, error) {
	if len(record) < recordHeaderLen+restlsAppDataAuthHeaderLength || recordType(record[0]) != recordTypeApplicationData {
		return nil, nil, alertBadRecordMAC
	}
	if record[1] != 0x03 || record[2] != 0x03 {
		return nil, nil, alertBadRecordMAC
	}
	header := record[:recordHeaderLen]
	payloadOffset := recordHeaderLen
	if s.isTLS12GCM {
		if len(record) < recordHeaderLen+8+restlsAppDataAuthHeaderLength {
			return nil, nil, alertBadRecordMAC
		}
		if binary.BigEndian.Uint64(record[recordHeaderLen:recordHeaderLen+8]) != s.toServerCounter+1 {
			return nil, nil, alertBadRecordMAC
		}
		header = record[:recordHeaderLen+8]
		payloadOffset += 8
	}
	payload := record[payloadOffset:]

	hmacAuth := s.authHeaderHash(false)
	if len(s.clientFinRaw) > 0 {
		hmacAuth.Write(s.clientFinRaw)
		s.clientFinRaw = nil
	}
	hmacAuth.Write(header)
	hmacAuth.Write(payload[restlsAppDataLenOffset:])
	expect := hmacAuth.Sum(nil)[:restlsAppDataMACLength]
	if !bytes.Equal(expect, payload[:restlsAppDataMACLength]) {
		return nil, nil, alertBadRecordMAC
	}

	hmacMask := s.authHeaderHash(false)
	sampleSize := 32
	if sampleSize > len(payload[restlsAppDataOffset:]) {
		sampleSize = len(payload[restlsAppDataOffset:])
	}
	hmacMask.Write(payload[restlsAppDataOffset : restlsAppDataOffset+sampleSize])
	mask := hmacMask.Sum(nil)[:restlsMaskLength]
	xorWithMac(payload[restlsAppDataLenOffset:], mask)
	dataLen := int(binary.BigEndian.Uint16(payload[restlsAppDataLenOffset:]))
	command, err := parseCommand(payload[restlsAppDataLenOffset+2:])
	if err != nil || dataLen > len(payload)-restlsAppDataOffset {
		return nil, nil, alertBadRecordMAC
	}
	s.toServerCounter++
	return payload[restlsAppDataOffset : restlsAppDataOffset+dataLen], command, nil
}

func (s *restlsServerState) writeRestlsRecords(inbound net.Conn, data []byte) error {
	s.writeMu.Lock()
	defer s.writeMu.Unlock()

	if len(data) == 0 {
		_, _, err := s.writeOneRestlsRecord(inbound, nil, true)
		return err
	}
	for len(data) > 0 {
		if err := s.waitToClientWritable(); err != nil {
			return err
		}
		n, command, err := s.writeOneRestlsRecord(inbound, data, false)
		if err != nil {
			return err
		}
		data = data[n:]
		s.maybeAwaitClientRecord(command)
	}
	return nil
}

func (s *restlsServerState) waitToClientWritable() error {
	s.awaitMu.Lock()
	defer s.awaitMu.Unlock()
	for s.awaitClientRecord && !s.closed {
		s.awaitCond.Wait()
	}
	if s.closed {
		return net.ErrClosed
	}
	return nil
}

func (s *restlsServerState) setAwaitingClientRecord() {
	s.awaitMu.Lock()
	s.awaitClientRecord = true
	s.awaitMu.Unlock()
}

func (s *restlsServerState) maybeAwaitClientRecord(command restlsCommand) {
	if response, ok := command.(ActResponse); ok && response > 0 {
		s.setAwaitingClientRecord()
	}
}

func (s *restlsServerState) noteClientRecord() {
	s.awaitMu.Lock()
	if s.awaitClientRecord {
		s.awaitClientRecord = false
		s.awaitCond.Broadcast()
	}
	s.awaitMu.Unlock()
}

func (s *restlsServerState) writeOneRestlsRecord(inbound net.Conn, data []byte, fake bool) (int, restlsCommand, error) {
	targetLen, command := s.nextToClientTarget(len(data))
	headerLen := recordHeaderLen + restlsAppDataAuthHeaderLength
	payloadOverhead := restlsAppDataAuthHeaderLength
	if s.parrotGCM {
		headerLen += 8
		payloadOverhead += 8
	}
	maxTargetLen := maxPlaintext - payloadOverhead
	if targetLen > maxTargetLen {
		targetLen = maxTargetLen
	}
	dataLen := len(data)
	if dataLen > targetLen {
		dataLen = targetLen
	}
	paddingLen := targetLen - dataLen
	if fake && targetLen < restlsAppDataAuthHeaderLength+s.minRecordLen {
		paddingLen = s.minRecordLen
		if paddingLen > maxTargetLen {
			paddingLen = maxTargetLen
		}
	}
	payloadLen := restlsAppDataAuthHeaderLength + dataLen + paddingLen
	if s.parrotGCM {
		payloadLen += 8
	}
	record := make([]byte, headerLen+dataLen+paddingLen)
	record[0] = byte(recordTypeApplicationData)
	record[1] = 0x03
	record[2] = 0x03
	record[3] = byte(payloadLen >> 8)
	record[4] = byte(payloadLen)
	payloadOffset := recordHeaderLen
	if s.parrotGCM {
		binary.BigEndian.PutUint64(record[recordHeaderLen:recordHeaderLen+8], s.toClientCounter+1)
		payloadOffset += 8
	}
	copy(record[payloadOffset+restlsAppDataOffset:], data[:dataLen])
	if paddingLen > 0 {
		if _, err := rand.Read(record[payloadOffset+restlsAppDataOffset+dataLen:]); err != nil {
			return 0, nil, err
		}
	}
	s.writeAuthHeader(record, payloadOffset, dataLen, command)
	if _, err := inbound.Write(record); err != nil {
		return 0, nil, err
	}
	s.toClientCounter++
	return dataLen, command, nil
}

func (s *restlsServerState) nextToClientTarget(dataLen int) (int, restlsCommand) {
	command := restlsCommand(ActNoop{})
	if int(s.toClientCounter) < len(s.script) {
		line := s.script[s.toClientCounter]
		target := line.targetLen.Len()
		return target, line.command
	}
	minRecordLen := s.minRecordLen + mathrand.Intn(100)
	if dataLen < minRecordLen {
		return minRecordLen, command
	}
	return dataLen, command
}

func (s *restlsServerState) writeAuthHeader(record []byte, payloadOffset int, dataLen int, command restlsCommand) {
	payload := record[payloadOffset:]
	hmacMask := s.authHeaderHash(true)
	sampleSize := 32
	if sampleSize > len(payload[restlsAppDataOffset:]) {
		sampleSize = len(payload[restlsAppDataOffset:])
	}
	hmacMask.Write(payload[restlsAppDataOffset : restlsAppDataOffset+sampleSize])
	mask := hmacMask.Sum(nil)[:restlsMaskLength]
	binary.BigEndian.PutUint16(payload[restlsAppDataLenOffset:], uint16(dataLen))
	commandBytes := command.toBytes()
	copy(payload[restlsAppDataLenOffset+2:], commandBytes[:])
	xorWithMac(payload[restlsAppDataLenOffset:], mask)

	hmacAuth := s.authHeaderHash(true)
	hmacAuth.Write(record[:payloadOffset])
	hmacAuth.Write(payload[restlsAppDataLenOffset:])
	auth := hmacAuth.Sum(nil)[:restlsAppDataMACLength]
	copy(payload[:restlsAppDataMACLength], auth)
}

func (s *restlsServerState) parrotTLS12GCMNonce(record []byte) {
	if s.parrotGCM && len(record) >= recordHeaderLen+8 {
		binary.BigEndian.PutUint64(record[recordHeaderLen:recordHeaderLen+8], s.toClientCounter+1)
	}
}

func (s *restlsServerState) cacheCloseNotify(record []byte) {
	s.writeMu.Lock()
	s.closeNotifyCache = append(s.closeNotifyCache, record...)
	s.writeMu.Unlock()
}

func (s *restlsServerState) writeCachedCloseNotify(inbound net.Conn) error {
	s.writeMu.Lock()
	defer s.writeMu.Unlock()
	if len(s.closeNotifyCache) == 0 {
		return nil
	}
	closeNotify := s.closeNotifyCache
	s.closeNotifyCache = nil
	s.parrotTLS12GCMNonce(closeNotify)
	_, err := inbound.Write(closeNotify)
	return err
}
