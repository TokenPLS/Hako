package common

import (
	"github.com/TokenPLS/Hako/component/geodata"
	"github.com/TokenPLS/Hako/component/mmdb"
	C "github.com/TokenPLS/Hako/constant"
	"github.com/TokenPLS/Hako/log"
)

type ASN struct {
	Base
	asn         string
	adapter     string
	noResolveIP bool
	isSourceIP  bool
}

func (a *ASN) Match(metadata *C.Metadata, helper C.RuleMatchHelper) (bool, string) {
	if !a.noResolveIP && !a.isSourceIP && helper.ResolveIP != nil {
		helper.ResolveIP()
	}

	ip := metadata.DstIP
	if a.isSourceIP {
		ip = metadata.SrcIP
	}
	if !ip.IsValid() {
		return false, ""
	}

	asn, aso := mmdb.ASNInstance().LookupASN(ip.AsSlice())
	if a.isSourceIP {
		metadata.SrcIPASN = asn + " " + aso
	} else {
		metadata.DstIPASN = asn + " " + aso
	}

	return a.asn == asn, a.adapter
}

func (a *ASN) RuleType() C.RuleType {
	if a.isSourceIP {
		return C.SrcIPASN
	}
	return C.IPASN
}

func (a *ASN) Adapter() string {
	return a.adapter
}

func (a *ASN) Payload() string {
	return a.asn
}

func (a *ASN) GetASN() string {
	return a.asn
}

func NewIPASN(asn string, adapter string, isSrc, noResolveIP bool) (*ASN, error) {
	if err := geodata.InitASN(); err != nil {
		log.Errorln("can't initial ASN: %s", err)
		return nil, err
	}

	return &ASN{
		Base:        Base{},
		asn:         asn,
		adapter:     adapter,
		noResolveIP: noResolveIP,
		isSourceIP:  isSrc,
	}, nil
}

var _ C.Rule = (*ASN)(nil)
