package mmdb

import (
	"sync"

	mihomoOnce "github.com/TokenPLS/Hako/common/once"
	C "github.com/TokenPLS/Hako/constant"
	"github.com/TokenPLS/Hako/log"

	"github.com/oschwald/maxminddb-golang"
)

type databaseType = uint8

const (
	typeMaxmind databaseType = iota
	typeSing
	typeMetaV0
)

var (
	ipReader  IPReader
	asnReader ASNReader
	ipOnce    sync.Once
	asnOnce   sync.Once
)

// Unavailable geodata must not take the process with it.
//
// These three loaders called log.Fatalln, which is os.Exit — on a phone that
// means the packet tunnel vanishes with no crash report, no error, and no way
// for the app to say what happened; the reader is told only "the VPN tunnel
// provider stopped unexpectedly", which is the system guessing. A database
// that will not open is a reason for GEOIP rules not to match. It is not a
// reason to stop.
func (r IPReader) available() bool  { return r.Reader != nil }
func (r ASNReader) available() bool { return r.Reader != nil }

func LoadFromBytes(buffer []byte) {
	ipOnce.Do(func() {
		mmdb, err := maxminddb.FromBytes(buffer)
		if err != nil {
			log.Errorln("Can't load mmdb: %s; GEOIP rules will not match", err.Error())
			return
		}
		ipReader = IPReader{Reader: mmdb}
		switch mmdb.Metadata.DatabaseType {
		case "sing-geoip":
			ipReader.databaseType = typeSing
		case "Meta-geoip0":
			ipReader.databaseType = typeMetaV0
		default:
			ipReader.databaseType = typeMaxmind
		}
	})
}

func Verify(path string) bool {
	instance, err := maxminddb.Open(path)
	if err == nil {
		instance.Close()
	}
	return err == nil
}

func IPInstance() IPReader {
	ipOnce.Do(func() {
		mmdbPath := C.Path.MMDB()
		log.Infoln("Load MMDB file: %s", mmdbPath)
		mmdb, err := maxminddb.Open(mmdbPath)
		if err != nil {
			log.Errorln("Can't load MMDB: %s; GEOIP rules will not match", err.Error())
			return
		}
		ipReader = IPReader{Reader: mmdb}
		switch mmdb.Metadata.DatabaseType {
		case "sing-geoip":
			ipReader.databaseType = typeSing
		case "Meta-geoip0":
			ipReader.databaseType = typeMetaV0
		default:
			ipReader.databaseType = typeMaxmind
		}
	})

	return ipReader
}

func ASNInstance() ASNReader {
	asnOnce.Do(func() {
		ASNPath := C.Path.ASN()
		log.Infoln("Load ASN file: %s", ASNPath)
		asn, err := maxminddb.Open(ASNPath)
		if err != nil {
			log.Errorln("Can't load ASN: %s; IP-ASN rules will not match", err.Error())
			return
		}
		asnReader = ASNReader{Reader: asn}
	})

	return asnReader
}

func ReloadIP() {
	mihomoOnce.Reset(&ipOnce)
}

func ReloadASN() {
	mihomoOnce.Reset(&asnOnce)
}
