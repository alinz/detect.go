// Majority of the logic of this file is copied from
// https://github.com/perkeep/perkeep/blob/master/internal/magic/magic.go
// some of the fucntions and structs are modified to fit my needs
//
// Please refer to Perkeep's license at https://github.com/perkeep/perkeep/blob/master/COPYING

package detect

import (
	"bytes"
	"io"
	"net/http"
	"strings"
)

type Match struct {
	Offset int
	Prefix []byte
	Type   string
}

var matches = []Match{
	{Prefix: []byte("GIF87a"), Type: "image/gif"},
	{Prefix: []byte("GIF89a"), Type: "image/gif"}, // TODO: Others?
	{Prefix: []byte("\xff\xd8\xff\xe2"), Type: "image/jpeg"},
	{Prefix: []byte("\xff\xd8\xff\xe1"), Type: "image/jpeg"},
	{Prefix: []byte("\xff\xd8\xff\xe0"), Type: "image/jpeg"},
	{Prefix: []byte("\xff\xd8\xff\xdb"), Type: "image/jpeg"},
	{Prefix: []byte("\x49\x49\x2a\x00\x10\x00\x00\x00\x43\x52\x02"), Type: "image/cr2"},
	{Prefix: []byte{137, 'P', 'N', 'G', '\r', '\n', 26, 10}, Type: "image/png"},
	{Prefix: []byte{0x49, 0x20, 0x49}, Type: "image/tiff"},
	{Prefix: []byte{0x49, 0x49, 0x2A, 0}, Type: "image/tiff"},
	{Prefix: []byte{0x4D, 0x4D, 0, 0x2A}, Type: "image/tiff"},
	{Prefix: []byte{0x4D, 0x4D, 0, 0x2B}, Type: "image/tiff"},
	{Prefix: []byte("8BPS"), Type: "image/vnd.adobe.photoshop"},
	{Prefix: []byte("gimp xcf "), Type: "image/x-xcf"},
	{Prefix: []byte("-----BEGIN PGP PUBLIC KEY BLOCK---"), Type: "text/x-openpgp-public-key"},
	{Prefix: []byte("fLaC\x00\x00\x00"), Type: "audio/x-flac"},
	{Prefix: []byte{'I', 'D', '3'}, Type: "audio/mpeg"},
	{Prefix: []byte{0, 0, 1, 0xB7}, Type: "video/mpeg"},
	{Prefix: []byte{0, 0, 0, 0x14, 0x66, 0x74, 0x79, 0x70, 0x71, 0x74, 0x20, 0x20}, Type: "video/quicktime"},
	{Prefix: []byte{0, 0x6E, 0x1E, 0xF0}, Type: "application/vnd.ms-powerpoint"},
	{Prefix: []byte{0x1A, 0x45, 0xDF, 0xA3}, Type: "video/webm"},
	{Prefix: []byte("FLV\x01"), Type: "application/vnd.adobe.flash.video"},
	{Prefix: []byte{0x1F, 0x8B, 0x08}, Type: "application/x-gzip"},
	{Prefix: []byte{0x37, 0x7A, 0xBC, 0xAF, 0x27, 0x1C}, Type: "application/x-7z-compressed"},
	{Prefix: []byte("BZh"), Type: "application/x-bzip2"},
	{Prefix: []byte{0xFD, 0x37, 0x7A, 0x58, 0x5A, 0}, Type: "application/x-xz"},
	{Prefix: []byte{'P', 'K', 3, 4, 0x0A, 0, 2, 0}, Type: "application/epub+zip"},
	{Prefix: []byte{0xD0, 0xCF, 0x11, 0xE0, 0xA1, 0xB1, 0x1A, 0xE1}, Type: "application/vnd.ms-word"},
	{Prefix: []byte{'P', 'K', 3, 4, 0x0A, 0x14, 0, 6, 0}, Type: "application/vnd.openxmlformats-officedocument.custom-properties+xml"},
	{Prefix: []byte{'P', 'K', 3, 4}, Type: "application/zip"},
	{Prefix: []byte("%PDF"), Type: "application/pdf"},
	{Prefix: []byte("{rtf"), Type: "text/rtf1"},
	{Prefix: []byte("BEGIN:VCARD\x0D\x0A"), Type: "text/vcard"},
	{Prefix: []byte("Return-Path: "), Type: "message/rfc822"},

	// Definition data extracted automatically from the file utility source code.
	// See: http://darwinsys.com/file/ (version used: 5.19)
	{Offset: 4, Prefix: []byte("moov"), Type: "video/quicktime"},                // Apple QuickTime
	{Offset: 4, Prefix: []byte("mdat"), Type: "video/quicktime"},                // Apple QuickTime movie (unoptimized)
	{Offset: 8, Prefix: []byte("isom"), Type: "video/mp4"},                      // MPEG v4 system, version 1
	{Offset: 8, Prefix: []byte("mp41"), Type: "video/mp4"},                      // MPEG v4 system, version 1
	{Offset: 8, Prefix: []byte("mp42"), Type: "video/mp4"},                      // MPEG v4 system, version 2
	{Offset: 8, Prefix: []byte("mmp4"), Type: "video/mp4"},                      // MPEG v4 system, 3GPP Mobile
	{Offset: 8, Prefix: []byte("3ge"), Type: "video/3gpp"},                      // MPEG v4 system, 3GPP
	{Offset: 8, Prefix: []byte("3gg"), Type: "video/3gpp"},                      // MPEG v4 system, 3GPP
	{Offset: 8, Prefix: []byte("3gp"), Type: "video/3gpp"},                      // MPEG v4 system, 3GPP
	{Offset: 8, Prefix: []byte("3gs"), Type: "video/3gpp"},                      // MPEG v4 system, 3GPP
	{Offset: 8, Prefix: []byte("3g2"), Type: "video/3gpp2"},                     // MPEG v4 system, 3GPP2
	{Offset: 8, Prefix: []byte("avc1"), Type: "video/3gpp"},                     // MPEG v4 system, 3GPP JVT AVC
	{Prefix: []byte("MThd"), Type: "audio/midi"},                                // Standard MIDI data
	{Prefix: []byte(".RMF\000\000\000"), Type: "application/vnd.rn-realmedia"},  // RealMedia file
	{Prefix: []byte("MAC\040"), Type: "audio/ape"},                              // Monkey's Audio compressed format
	{Prefix: []byte("MP+"), Type: "audio/musepack"},                             // Musepack audio
	{Prefix: []byte("II\x1a\000\000\000HEAPCCDR"), Type: "image/x-canon-crw"},   // Canon CIFF raw image data
	{Prefix: []byte("II\x2a\000\x10\000\000\000CR"), Type: "image/x-canon-cr2"}, // Canon CR2 raw image data
	{Prefix: []byte("MMOR"), Type: "image/x-olympus-orf"},                       // Olympus ORF raw image data, big-endian
	{Prefix: []byte("IIRO"), Type: "image/x-olympus-orf"},                       // Olympus ORF raw image data, little-endian
	{Prefix: []byte("IIRS"), Type: "image/x-olympus-orf"},                       // Olympus ORF raw image data, little-endian
	{Offset: 12, Prefix: []byte("DJVM"), Type: "image/vnd.djvu"},                // DjVu multiple page document
	{Offset: 12, Prefix: []byte("DJVU"), Type: "image/vnd.djvu"},                // DjVu image or single page document
	{Offset: 12, Prefix: []byte("DJVI"), Type: "image/vnd.djvu"},                // DjVu shared document
	{Offset: 12, Prefix: []byte("THUM"), Type: "image/vnd.djvu"},                // DjVu page thumbnails
	{Offset: 8, Prefix: []byte("WAVE"), Type: "audio/x-wav"},                    // WAVE audio
	{Offset: 8, Prefix: []byte("AVI\040"), Type: "video/x-msvideo"},             // AVI
	{Prefix: []byte("OggS"), Type: "application/ogg"},                           // Ogg data
	{Offset: 8, Prefix: []byte("AIFF"), Type: "audio/x-aiff"},                   // AIFF audio
	{Offset: 8, Prefix: []byte("AIFC"), Type: "audio/x-aiff"},                   // AIFF-C compressed audio
	{Offset: 8, Prefix: []byte("8SVX"), Type: "audio/x-aiff"},                   // 8SVX 8-bit sampled sound voice
	{Prefix: []byte("\000\001\000\000\000"), Type: "application/x-font-ttf"},    // TrueType font data
	{Prefix: []byte("d8:announce"), Type: "application/x-bittorrent"},           // BitTorrent file
}

func Register(m Match) {
	matches = append([]Match{m}, matches...)
}

func Check(hdr []byte) string {
	hlen := len(hdr)
	for _, match := range matches {
		plen := match.Offset + len(match.Prefix)
		if hlen > plen && bytes.Equal(hdr[match.Offset:plen], match.Prefix) {
			return match.Type
		}
	}

	t := http.DetectContentType(hdr)
	t = strings.Replace(t, "; charset=utf-8", "", 1)
	if t != "application/octet-stream" && t != "text/plain" {
		return t
	}

	return ""
}

func CheckReader(r io.Reader) (string, io.Reader) {
	var buf bytes.Buffer
	_, err := io.Copy(&buf, io.LimitReader(r, 1024))
	mime := Check(buf.Bytes())
	if err != nil {
		return mime, io.MultiReader(&buf, &errReader{err})
	}
	return mime, io.MultiReader(&buf, r)
}

func CheckReadCloser(rc io.ReadCloser) (string, io.ReadCloser) {
	mime, r := CheckReader(rc)
	return mime, &readCloser{
		r:        r,
		original: rc,
	}
}

type errReader struct{ err error }

func (er *errReader) Read([]byte) (int, error) { return 0, er.err }

type readCloser struct {
	original io.ReadCloser
	r        io.Reader
}

func (rc *readCloser) Read(b []byte) (int, error) {
	return rc.r.Read(b)
}

func (rc *readCloser) Close() error {
	return rc.original.Close()
}
