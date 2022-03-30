package main

import (
	"encoding/hex"
	"net"

	"github.com/miekg/dns"
)

type RFC8427Message struct {
	// https://datatracker.ietf.org/doc/html/rfc8427#section-2.1
	ID              uint16                   `json:",omitempty"`
	QR              bool                     `json:",omitempty"`
	Opcode          uint8                    `json:",omitempty"`
	AA              bool                     `json:",omitempty"`
	TC              bool                     `json:",omitempty"`
	RD              bool                     `json:",omitempty"`
	RA              bool                     `json:",omitempty"`
	AD              bool                     `json:",omitempty"`
	CD              bool                     `json:",omitempty"`
	RCODE           uint8                    `json:",omitempty"`
	QDCOUNT         uint16                   `json:",omitempty"`
	ANCOUNT         uint16                   `json:",omitempty"`
	NSCOUNT         uint16                   `json:",omitempty"`
	ARCOUNT         uint16                   `json:",omitempty"`
	QNAME           string                   `json:",omitempty"`
	CompressedQNAME *RFC8427Compressed       `json:"compressedQNAME,omitempty"`
	QTYPE           uint16                   `json:",omitempty"`
	QTYPEname       string                   `json:",omitempty"`
	QCLASS          uint16                   `json:",omitempty"`
	QCLASSname      string                   `json:",omitempty"`
	QuestionRRs     []*RFC8427ResourceRecord `json:"questionRRs,omitempty"`
	AnswerRRs       []*RFC8427ResourceRecord `json:"answerRRs,omitempty"`
	AuthorityRRs    []*RFC8427ResourceRecord `json:"authorityRRs,omitempty"`
	AdditionalRRs   []*RFC8427ResourceRecord `json:"additionalRRs,omitempty"`

	// These members are all encoded in base16 encoding, described in [RFC4648].
	// https://datatracker.ietf.org/doc/html/rfc8427#section-2.4
	MessageOctetsHEX    string `json:"messageOctetsHEX,omitempty"`
	HeaderOctetsHEX     string `json:"headerOctetsHEX,omitempty"`
	QuestionOctetsHEX   string `json:"questionOctetsHEX,omitempty"`
	AnswerOctetsHEX     string `json:"answerOctetsHEX,omitempty"`
	AuthorityOctetsHEX  string `json:"authorityOctetsHEX,omitempty"`
	AdditionalOctetsHEX string `json:"additionalOctetsHEX,omitempty"`

	// Additional Message Object Members
	// https://datatracker.ietf.org/doc/html/rfc8427#section-2.5
	DateString  string  `json:"dateString,omitempty"`
	DateSeconds float64 `json:"dateSeconds,omitempty"`
	Comment     string  `json:"comment,omitempty"`
}

type RFC8427ResourceRecord struct {
	// https://datatracker.ietf.org/doc/html/rfc8427#section-2.2
	NAME           string             `json:",omitempty"`
	CompressedNAME *RFC8427Compressed `json:"compressedNAME,omitempty"`
	TYPE           uint16             `json:",omitempty"`
	TYPEname       string             `json:",omitempty"`
	CLASS          uint16             `json:",omitempty"`
	CLASSname      string             `json:",omitempty"`
	TTL            int32              `json:",omitempty"`
	RDLENGTH       uint16             `json:",omitempty"`
	RDATAHEX       string             `json:",omitempty"`
	RRSet          []*RFC8427Rdata    `json:"rrSet,omitempty"`

	// These members are all encoded in base16 encoding, described in [RFC4648].
	// https://datatracker.ietf.org/doc/html/rfc8427#section-2.4
	RROctetsHEX string `json:"rrOctetsHEX,omitempty"`
}

type RFC8427Rdata struct {
	// https://datatracker.ietf.org/doc/html/rfc8427#section-2.3
	RdataA     string `json:"rdataA,omitempty"`
	RdataAAAA  string `json:"rdataAAAA,omitempty"`
	RdataCNAME string `json:"rdataCNAME,omitempty"`
	RdataDNAME string `json:"rdataDNAME,omitempty"`
	RdataNS    string `json:"rdataNS,omitempty"`
	RdataPTR   string `json:"rdataPTR,omitempty"`
	RdataTXT   string `json:"rdataTXT,omitempty"`

	/*
		In addition, each of the following members has a value that is a
		space-separated string that matches the display format definition in
		the RFC that defines that RDATA type.  It is not expected that every
		receiving application will know how to parse these values.
	*/
	RdataCDNSKEY    string `json:"rdataCDNSKEY,omitempty"`
	RdataCDS        string `json:"rdataCDS,omitempty"`
	RdataCSYNC      string `json:"rdataCSYNC,omitempty"`
	RdataDNSKEY     string `json:"rdataDNSKEY,omitempty"`
	RdataHIP        string `json:"rdataHIP,omitempty"`
	RdataIPSECKEY   string `json:"rdataIPSECKEY,omitempty"`
	RdataKEY        string `json:"rdataKEY,omitempty"`
	RdataMX         string `json:"rdataMX,omitempty"`
	RdataNSEC       string `json:"rdataNSEC,omitempty"`
	RdataNSEC3      string `json:"rdataNSEC3,omitempty"`
	RdataNSEC3PARAM string `json:"rdataNSEC3PARAM,omitempty"`
	RdataOPENPGPKEY string `json:"rdataOPENPGPKEY,omitempty"`
	RdataRRSIG      string `json:"rdataRRSIG,omitempty"`
	RdataSMIMEA     string `json:"rdataSMIMEA,omitempty"`
	RdataSPF        string `json:"rdataSPF,omitempty"`
	RdataSRV        string `json:"rdataSRV,omitempty"`
	RdataSSHFP      string `json:"rdataSSHFP,omitempty"`
	RdataTLSA       string `json:"rdataTLSA,omitempty"`

	// By the complete semantics and the example in RFC8427,
	// RDATAHEX should also be defined as a "RDATA Field Member"
	RDATAHEX string `json:",omitempty"`
}

type RFC8427Compressed struct {
	IsCompressed uint `json:"isCompressed,omitempty"`
	Length       uint `json:"length,omitempty"`
}

func NewRFC8427Message(msg *dns.Msg, bufferSize uint16) (*RFC8427Message, error) {
	v := &RFC8427Message{
		ID:      msg.Id,
		QR:      msg.Response,
		Opcode:  uint8(msg.Opcode),
		AA:      msg.Authoritative,
		TC:      msg.Truncated,
		RD:      msg.RecursionDesired,
		RA:      msg.RecursionAvailable,
		AD:      msg.AuthenticatedData,
		CD:      msg.CheckingDisabled,
		RCODE:   uint8(msg.Rcode),
		QDCOUNT: uint16(len(msg.Question)),
		ANCOUNT: uint16(len(msg.Answer)),
		NSCOUNT: uint16(len(msg.Ns)),
		ARCOUNT: uint16(len(msg.Extra)),
	}

	if v.QDCOUNT == 1 {
		q := msg.Question[0]
		v.QNAME = q.Name
		v.QTYPE = q.Qtype
		v.QCLASS = q.Qclass
	} else if v.QDCOUNT > 1 {
		for _, x := range msg.Question {
			v.QuestionRRs = append(v.QuestionRRs, &RFC8427ResourceRecord{
				NAME:  x.Name,
				TYPE:  x.Qtype,
				CLASS: x.Qclass,
			})
		}
	}

	if v.ANCOUNT+v.NSCOUNT+v.ARCOUNT == 0 {
		return v, nil
	}

	buffer := make([]byte, bufferSize)

	for _, x := range msg.Answer {
		y, err := NewRFC8427ResourceRecord(x, buffer)
		if err != nil {
			return nil, err
		}
		v.AnswerRRs = append(v.AnswerRRs, y)
	}

	for _, x := range msg.Ns {
		y, err := NewRFC8427ResourceRecord(x, buffer)
		if err != nil {
			return nil, err
		}
		v.AuthorityRRs = append(v.AuthorityRRs, y)
	}

	for _, x := range msg.Extra {
		y, err := NewRFC8427ResourceRecord(x, buffer)
		if err != nil {
			return nil, err
		}
		v.AdditionalRRs = append(v.AdditionalRRs, y)
	}

	return v, nil
}

func (self *RFC8427Message) Msg() (*dns.Msg, error) {
	msg := &dns.Msg{}

	msg.Id = self.ID
	msg.Response = self.QR
	msg.Opcode = int(self.Opcode)
	msg.Authoritative = self.AA
	msg.Truncated = self.TC
	msg.RecursionDesired = self.RD
	msg.RecursionAvailable = self.RA
	msg.AuthenticatedData = self.AD
	msg.CheckingDisabled = self.CD
	msg.Rcode = int(self.RCODE)

	if len(self.QuestionRRs) > 0 {
		for _, rr := range self.QuestionRRs {
			msg.Question = append(msg.Question, dns.Question{
				Name:   rr.NAME,
				Qtype:  rr.TYPE,
				Qclass: rr.CLASS,
			})
		}
	} else if len(self.QNAME) > 0 {
		msg.Question = append(msg.Question, dns.Question{
			Name:   self.QNAME,
			Qtype:  self.QTYPE,
			Qclass: self.QCLASS,
		})
	}

	for _, rr := range self.AnswerRRs {
		v, err := rr.RR()
		if err != nil {
			return nil, err
		}
		msg.Answer = append(msg.Answer, v...)
	}

	for _, rr := range self.AuthorityRRs {
		v, err := rr.RR()
		if err != nil {
			return nil, err
		}
		msg.Ns = append(msg.Ns, v...)
	}

	for _, rr := range self.AdditionalRRs {
		v, err := rr.RR()
		if err != nil {
			return nil, err
		}
		msg.Extra = append(msg.Extra, v...)
	}

	return msg, nil
}

func NewRFC8427ResourceRecord(rr dns.RR, buffer []byte) (*RFC8427ResourceRecord, error) {
	if buffer == nil {
		buffer = make([]byte, 4096)
	}

	rdataHex, err := hexEncodeRdata(buffer, rr)
	if err != nil {
		return nil, err
	}

	hdr := rr.Header()
	return &RFC8427ResourceRecord{
		NAME:     hdr.Name,
		TYPE:     hdr.Rrtype,
		CLASS:    hdr.Class,
		TTL:      int32(hdr.Ttl),
		RDATAHEX: rdataHex,
	}, nil
}

func (self *RFC8427ResourceRecord) RR() ([]dns.RR, error) {
	hdr := dns.RR_Header{
		Name:   self.NAME,
		Rrtype: self.TYPE,
		Class:  self.CLASS,
		Ttl:    uint32(self.TTL),
	}

	var rrSet []dns.RR

	if len(self.RRSet) > 0 {
		for _, x := range self.RRSet {
			if len(x.RDATAHEX) > 0 {
				rr, err := hexDecodeRR(&hdr, self.RDATAHEX)
				if err != nil {
					return nil, err
				}
				rrSet = append(rrSet, rr)
			}

			switch hdr.Rrtype {
			case dns.TypeA:
				rrSet = append(rrSet, &dns.A{
					Hdr: hdr,
					A:   net.ParseIP(x.RdataA),
				})
			case dns.TypeAAAA:
				rrSet = append(rrSet, &dns.AAAA{
					Hdr:  hdr,
					AAAA: net.ParseIP(x.RdataAAAA),
				})
			case dns.TypeCNAME:
				rrSet = append(rrSet, &dns.CNAME{
					Hdr:    hdr,
					Target: x.RdataCNAME,
				})
			case dns.TypeDNAME:
				rrSet = append(rrSet, &dns.DNAME{
					Hdr:    hdr,
					Target: x.RdataDNAME,
				})
			case dns.TypeNS:
				rrSet = append(rrSet, &dns.NS{
					Hdr: hdr,
					Ns:  x.RdataNS,
				})
			case dns.TypePTR:
				rrSet = append(rrSet, &dns.PTR{
					Hdr: hdr,
					Ptr: x.RdataPTR,
				})
			case dns.TypeTXT:
				rrSet = append(rrSet, &dns.TXT{
					Hdr: hdr,
					Txt: []string{x.RdataTXT}, // TODO: split TXT to []string
				})
				// TODO:
				// case dns.TypeCDNSKEY:
				// case dns.TypeCDS:
				// case dns.TypeCSYNC:
				// case dns.TypeDNSKEY:
				// case dns.TypeHIP:
				// case dns.TypeKEY:
				// case dns.TypeMX:
				// case dns.TypeNSEC:
				// case dns.TypeNSEC3:
				// case dns.TypeNSEC3PARAM:
				// case dns.TypeRRSIG:
				// case dns.TypeSMIMEA:
				// case dns.TypeSPF:
				// case dns.TypeSSHFP:
				// case dns.TypeTLSA:
			}
		}
	} else if len(self.RDATAHEX) > 0 {
		rr, err := hexDecodeRR(&hdr, self.RDATAHEX)
		if err != nil {
			return nil, err
		}
		rrSet = append(rrSet, rr)
	}

	return rrSet, nil
}

func hexDecodeRR(hdr *dns.RR_Header, rdataHex string) (dns.RR, error) {
	rdata, err := hex.DecodeString(rdataHex)
	if err != nil {
		return nil, err
	}
	hdr.Rdlength = uint16(len(rdata))
	rr, _, err := dns.UnpackRRWithHeader(*hdr, rdata, 0)
	return rr, err
}

func hexEncodeRdata(buffer []byte, rr dns.RR) (string, error) {
	n, err := dns.PackRR(rr, buffer, 0, nil, false)
	if err != nil {
		return "", err
	}

	rdLength := rr.Header().Rdlength
	i := uint16(n) - rdLength
	return hex.EncodeToString(buffer[i:n]), nil
}
