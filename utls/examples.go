package main

import (
	"bufio"
	"fmt"
	"net"
	"net/http"
	"net/http/httputil"
	"net/url"
	"time"

	"github.com/refraction-networking/utls"
	"golang.org/x/net/http2"
)

var (
	dialTimeout   = time.Duration(15) * time.Second
)

var requestHostname = "facebook.com" // speaks http2 and TLS 1.3
var requestAddr = "31.13.72.36:443"

func HttpGetCustomExfil(hostname string, addr string) (*http.Response, error) {
	config := tls.Config{ServerName: hostname, InsecureSkipVerify: true}
	dialConn, err := net.DialTimeout("tcp", addr, dialTimeout)
	if err != nil {
		return nil, fmt.Errorf("net.DialTimeout error: %+v", err)
	}
	uTlsConn := tls.UClient(dialConn, &config, tls.HelloCustom)
	defer uTlsConn.Close()

	// do not use this particular spec in production
	// make sure to generate a separate copy of ClientHelloSpec for every connection
	spec := tls.ClientHelloSpec{
		TLSVersMax: tls.VersionTLS13,
		TLSVersMin: tls.VersionTLS10,
		CipherSuites: []uint16{
			0x1302, 0x1303, 0x1301, 0xC02C, 0xC030, 0x009F, 0xCCA9, 0xCCA8, 0xCCAA, 0xC02B, 0xC02F, 0x009E, 0xC024, 0xC028, 0x006B, 0xC023, 0xC027, 0x0067, 0xC00A, 0xC014, 0x0039, 0xC009, 0xC013, 0x0033, 0x009D, 0x009C, 0x003D, 0x003C, 0x0035, 0x002F, 0x00FF,
		},
		Extensions: []tls.TLSExtension{
			//0x000B
			&tls.SupportedPointsExtension{SupportedPoints: []byte{0x00, 0x01, 0x02}},
			//0x000A
			&tls.SupportedCurvesExtension{Curves: []tls.CurveID{0x001D, 0x0017, 0x001E, 0x0019, 0x0018 }},
			//0x3374
			&tls.NPNExtension{},
			//0x0010
			&tls.ALPNExtension{AlpnProtocols: []string{"http/1.1"}},
			//0x0016
			&tls.EncThenMacExtension{},
			//0x0017
			&tls.UtlsExtendedMasterSecretExtension{},
			//0x000D
			&tls.SignatureAlgorithmsExtension{SupportedSignatureAlgorithms: []tls.SignatureScheme{
				0x0403, 0x0503, 0x0603, 0x0807, 0x0808, 0x0809, 0x080A, 0x080B, 0x0804, 0x0805, 0x0806, 0x0401, 0x0501, 0x0601, 0x0303, 0x0203, 0x0301, 0x0201, 0x0302, 0x0202, 0x0402, 0x0502, 0x0602,
			}},
			//0x002B
			&tls.SupportedVersionsExtension{[]uint16{
				tls.VersionTLS13,
				tls.VersionTLS12,
				tls.VersionTLS11,
				tls.VersionTLS10,
			}},
			//0x002D
			&tls.PSKKeyExchangeModesExtension{[]uint8{1}}, // pskModeDHE
			//0x0033
			&tls.KeyShareExtension{[]tls.KeyShare{
				{Group: tls.CurveID(tls.GREASE_PLACEHOLDER), Data: []byte{0}},
				{Group: tls.X25519},

			}},
			&tls.UtlsPaddingExtension{GetPaddingLen: tls.BoringPaddingStyle},
		},
		GetSessionID: nil,
	}
	err = uTlsConn.ApplyPreset(&spec)

	if err != nil {
		return nil, fmt.Errorf("uTlsConn.Handshake() error: %+v", err)
	}

	err = uTlsConn.Handshake()
	if err != nil {
		return nil, fmt.Errorf("uTlsConn.Handshake() error: %+v", err)
	}

	return httpGetOverConn(uTlsConn, uTlsConn.HandshakeState.ServerHello.AlpnProtocol)
}

func main() {
	var response *http.Response
	var err error

	response, err = HttpGetCustomExfil(requestHostname, requestAddr)
	if err != nil {
		fmt.Printf("#> HttpGetCustomExfil() failed: %+v\n", err)
	} else {
		fmt.Printf("#> HttpGetCustomExfil() response: %+s\n", dumpResponseNoBody(response))
	}

	return
}

func httpGetOverConn(conn net.Conn, alpn string) (*http.Response, error) {
	req := &http.Request{
		Method: "GET",
		//URL:    &url.URL{Host: "www." + requestHostname + "/"},
		URL:    &url.URL{Host: "/"},
		Header: make(http.Header),
		//Host:   "www." + requestHostname,
		Host:   "216.58.215.78",
	}

	switch alpn {
	case "h2":
		req.Proto = "HTTP/2.0"
		req.ProtoMajor = 2
		req.ProtoMinor = 0

		tr := http2.Transport{}
		cConn, err := tr.NewClientConn(conn)
		if err != nil {
			return nil, err
		}
		return cConn.RoundTrip(req)
	case "http/1.1", "":
		req.Proto = "HTTP/1.1"
		req.ProtoMajor = 1
		req.ProtoMinor = 1

		err := req.Write(conn)
		if err != nil {
			return nil, err
		}
		return http.ReadResponse(bufio.NewReader(conn), req)
	default:
		return nil, fmt.Errorf("unsupported ALPN: %v", alpn)
	}
}

func dumpResponseNoBody(response *http.Response) string {
	resp, err := httputil.DumpResponse(response, false)
	if err != nil {
		return fmt.Sprintf("failed to dump response: %v", err)
	}
	return string(resp)
}
