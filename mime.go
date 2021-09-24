// Majority of the logic of this file is copied from
// https://github.com/perkeep/perkeep/blob/master/internal/magic/magic.go
// some of the fucntions and structs are modified to fit my needs
//
// Please refer to Perkeep's license at https://github.com/perkeep/perkeep/blob/master/COPYING

package detect

import (
	"bytes"
	"fmt"
	"io"
	"net/http"
	"strings"
)

type Match struct {
	Offset int
	Prefix []byte
	MIME   string
}

func (m Match) String() string {
	return fmt.Sprintf("%d:%x:%s", m.Offset, m.Prefix, m.MIME)
}

func RegisterImageFormats() {
	Register(
		Match{Prefix: []byte("GIF87a"), MIME: "image/gif"},
		Match{Prefix: []byte("GIF89a"), MIME: "image/gif"}, // TODO: Others?
		Match{Prefix: []byte("\xff\xd8\xff\xe2"), MIME: "image/jpeg"},
		Match{Prefix: []byte("\xff\xd8\xff\xe1"), MIME: "image/jpeg"},
		Match{Prefix: []byte("\xff\xd8\xff\xe0"), MIME: "image/jpeg"},
		Match{Prefix: []byte("\xff\xd8\xff\xdb"), MIME: "image/jpeg"},
		Match{Prefix: []byte("\x49\x49\x2a\x00\x10\x00\x00\x00\x43\x52\x02"), MIME: "image/cr2"},
		Match{Prefix: []byte{137, 'P', 'N', 'G', '\r', '\n', 26, 10}, MIME: "image/png"},
		Match{Prefix: []byte{0x49, 0x20, 0x49}, MIME: "image/tiff"},
		Match{Prefix: []byte{0x49, 0x49, 0x2A, 0}, MIME: "image/tiff"},
		Match{Prefix: []byte{0x4D, 0x4D, 0, 0x2A}, MIME: "image/tiff"},
		Match{Prefix: []byte{0x4D, 0x4D, 0, 0x2B}, MIME: "image/tiff"},
		Match{Prefix: []byte("8BPS"), MIME: "image/vnd.adobe.photoshop"},
		Match{Prefix: []byte("gimp xcf "), MIME: "image/x-xcf"},
		Match{Prefix: []byte("II\x1a\000\000\000HEAPCCDR"), MIME: "image/x-canon-crw"},   // Canon CIFF raw image data
		Match{Prefix: []byte("II\x2a\000\x10\000\000\000CR"), MIME: "image/x-canon-cr2"}, // Canon CR2 raw image data
		Match{Prefix: []byte("MMOR"), MIME: "image/x-olympus-orf"},                       // Olympus ORF raw image data, big-endian
		Match{Prefix: []byte("IIRO"), MIME: "image/x-olympus-orf"},                       // Olympus ORF raw image data, little-endian
		Match{Prefix: []byte("IIRS"), MIME: "image/x-olympus-orf"},                       // Olympus ORF raw image data, little-endian
		Match{Offset: 12, Prefix: []byte("DJVM"), MIME: "image/vnd.djvu"},                // DjVu multiple page document
		Match{Offset: 12, Prefix: []byte("DJVU"), MIME: "image/vnd.djvu"},                // DjVu image or single page document
		Match{Offset: 12, Prefix: []byte("DJVI"), MIME: "image/vnd.djvu"},                // DjVu shared document
		Match{Offset: 12, Prefix: []byte("THUM"), MIME: "image/vnd.djvu"},                // DjVu page thumbnails
	)
}

func RegisterAudioFormats() {
	Register(
		Match{Prefix: []byte("fLaC\x00\x00\x00"), MIME: "audio/x-flac"},
		Match{Prefix: []byte{'I', 'D', '3'}, MIME: "audio/mpeg"},
		Match{Prefix: []byte("MThd"), MIME: "audio/midi"},              // Standard MIDI data
		Match{Prefix: []byte("MAC\040"), MIME: "audio/ape"},            // Monkey's Audio compressed format
		Match{Prefix: []byte("MP+"), MIME: "audio/musepack"},           // Musepack audio
		Match{Offset: 8, Prefix: []byte("WAVE"), MIME: "audio/x-wav"},  // WAVE audio
		Match{Offset: 8, Prefix: []byte("AIFF"), MIME: "audio/x-aiff"}, // AIFF audio
		Match{Offset: 8, Prefix: []byte("AIFC"), MIME: "audio/x-aiff"}, // AIFF-C compressed audio
		Match{Offset: 8, Prefix: []byte("8SVX"), MIME: "audio/x-aiff"}, // 8SVX 8-bit sampled sound voice
	)
}

func RegisterVideoFormats() {
	Register(
		// Definition data extracted automatically from the file utility source code.
		// See: http://darwinsys.com/file/ (version used: 5.19)
		Match{Prefix: []byte{0, 0, 1, 0xB7}, MIME: "video/mpeg"},
		Match{Prefix: []byte{0, 0, 0, 0x14, 0x66, 0x74, 0x79, 0x70, 0x71, 0x74, 0x20, 0x20}, MIME: "video/quicktime"},
		Match{Prefix: []byte{0x1A, 0x45, 0xDF, 0xA3}, MIME: "video/webm"},
		Match{Prefix: []byte("FLV\x01"), MIME: "application/vnd.adobe.flash.video"},
		Match{Offset: 4, Prefix: []byte("moov"), MIME: "video/quicktime"},    // Apple QuickTime
		Match{Offset: 4, Prefix: []byte("mdat"), MIME: "video/quicktime"},    // Apple QuickTime movie (unoptimized)
		Match{Offset: 8, Prefix: []byte("isom"), MIME: "video/mp4"},          // MPEG v4 system, version 1
		Match{Offset: 8, Prefix: []byte("mp41"), MIME: "video/mp4"},          // MPEG v4 system, version 1
		Match{Offset: 8, Prefix: []byte("mp42"), MIME: "video/mp4"},          // MPEG v4 system, version 2
		Match{Offset: 8, Prefix: []byte("mmp4"), MIME: "video/mp4"},          // MPEG v4 system, 3GPP Mobile
		Match{Offset: 8, Prefix: []byte("3ge"), MIME: "video/3gpp"},          // MPEG v4 system, 3GPP
		Match{Offset: 8, Prefix: []byte("3gg"), MIME: "video/3gpp"},          // MPEG v4 system, 3GPP
		Match{Offset: 8, Prefix: []byte("3gp"), MIME: "video/3gpp"},          // MPEG v4 system, 3GPP
		Match{Offset: 8, Prefix: []byte("3gs"), MIME: "video/3gpp"},          // MPEG v4 system, 3GPP
		Match{Offset: 8, Prefix: []byte("3g2"), MIME: "video/3gpp2"},         // MPEG v4 system, 3GPP2
		Match{Offset: 8, Prefix: []byte("avc1"), MIME: "video/3gpp"},         // MPEG v4 system, 3GPP JVT AVC
		Match{Offset: 8, Prefix: []byte("AVI\040"), MIME: "video/x-msvideo"}, // AVI
	)
}

func RegisterApplicationFormats() {
	Register(
		Match{Prefix: []byte("FLV\x01"), MIME: "application/vnd.adobe.flash.video"},
		Match{Prefix: []byte{0, 0x6E, 0x1E, 0xF0}, MIME: "application/vnd.ms-powerpoint"},
		Match{Prefix: []byte{0x1F, 0x8B, 0x08}, MIME: "application/x-gzip"},
		Match{Prefix: []byte{0x37, 0x7A, 0xBC, 0xAF, 0x27, 0x1C}, MIME: "application/x-7z-compressed"},
		Match{Prefix: []byte("BZh"), MIME: "application/x-bzip2"},
		Match{Prefix: []byte{0xFD, 0x37, 0x7A, 0x58, 0x5A, 0}, MIME: "application/x-xz"},
		Match{Prefix: []byte{'P', 'K', 3, 4, 0x0A, 0, 2, 0}, MIME: "application/epub+zip"},
		Match{Prefix: []byte{0xD0, 0xCF, 0x11, 0xE0, 0xA1, 0xB1, 0x1A, 0xE1}, MIME: "application/vnd.ms-word"},
		Match{Prefix: []byte{'P', 'K', 3, 4, 0x0A, 0x14, 0, 6, 0}, MIME: "application/vnd.openxmlformats-officedocument.custom-properties+xml"},
		Match{Prefix: []byte{'P', 'K', 3, 4}, MIME: "application/zip"},
		Match{Prefix: []byte("%PDF"), MIME: "application/pdf"},
		Match{Prefix: []byte(".RMF\000\000\000"), MIME: "application/vnd.rn-realmedia"}, // RealMedia file
		Match{Prefix: []byte("OggS"), MIME: "application/ogg"},                          // Ogg data
		Match{Prefix: []byte("\000\001\000\000\000"), MIME: "application/x-font-ttf"},   // TrueMIME font data
		Match{Prefix: []byte("d8:announce"), MIME: "application/x-bittorrent"},          // BitTorrent file
	)
}

func RegisterMiscFormats() {
	Register(
		Match{Prefix: []byte("-----BEGIN PGP PUBLIC KEY BLOCK---"), MIME: "text/x-openpgp-public-key"},
		Match{Prefix: []byte("{rtf"), MIME: "text/rtf1"},
		Match{Prefix: []byte("BEGIN:VCARD\x0D\x0A"), MIME: "text/vcard"},
		Match{Prefix: []byte("Return-Path: "), MIME: "message/rfc822"},
	)
}

var registeredMatches = []Match{}

func Register(matches ...Match) {
	// rebuild the map of all registered formats
	alreadyRegistred := make(map[string]struct{})
	for _, m := range registeredMatches {
		alreadyRegistred[m.String()] = struct{}{}
	}

	for _, m := range matches {
		if _, ok := alreadyRegistred[m.String()]; ok {
			continue
		}
		registeredMatches = append(registeredMatches, m)
	}
}

func Check(hdr []byte) string {
	hlen := len(hdr)
	for _, match := range registeredMatches {
		plen := match.Offset + len(match.Prefix)
		if hlen > plen && bytes.Equal(hdr[match.Offset:plen], match.Prefix) {
			return match.MIME
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
