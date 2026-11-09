package waf

import (
	"bytes"
	"encoding/xml"
	"fmt"
	"io"
)

/*
	apiparse_xml.go

	Bounded XML structure checker on top of encoding/xml's token reader. Go's
	decoder never expands custom entities, but a DOCTYPE is still rejected by
	default (XXE, billion laughs, parameter entities) and entity declarations
	are rejected even when DOCTYPE is allowed. No tree is built.
*/

func checkXML(b []byte, lim APILimits) (v *violation, syntax bool) {
	if len(bytes.TrimSpace(b)) == 0 {
		return nil, false
	}
	d := xml.NewDecoder(bytes.NewReader(b))
	d.Strict = true
	d.CharsetReader = func(_ string, in io.Reader) (io.Reader, error) { return in, nil }
	depth, elements := 0, 0
	for {
		tok, err := d.RawToken()
		if err == io.EOF {
			if depth != 0 || elements == 0 {
				return &violation{Code: codeSyntax, Detail: "unclosed XML element"}, true
			}
			return nil, false
		}
		if err != nil {
			return &violation{Code: codeSyntax, Detail: "malformed XML"}, true
		}
		switch t := tok.(type) {
		case xml.StartElement:
			depth++
			elements++
			if lim.XMLMaxDepth > 0 && depth > lim.XMLMaxDepth {
				return &violation{Code: codeXMLDepth, Detail: fmt.Sprintf("nesting deeper than %d", lim.XMLMaxDepth)}, false
			}
			if lim.XMLMaxElements > 0 && elements > lim.XMLMaxElements {
				return &violation{Code: codeXMLElements, Detail: fmt.Sprintf("more than %d elements", lim.XMLMaxElements)}, false
			}
			if lim.XMLMaxAttrs > 0 && len(t.Attr) > lim.XMLMaxAttrs {
				return &violation{Code: codeXMLAttrs, Detail: fmt.Sprintf("more than %d attributes on an element", lim.XMLMaxAttrs)}, false
			}
		case xml.EndElement:
			depth--
			if depth < 0 {
				return &violation{Code: codeSyntax, Detail: "unexpected closing tag"}, true
			}
		case xml.CharData:
			if depth == 0 && len(bytes.TrimSpace(t)) > 0 {
				return &violation{Code: codeSyntax, Detail: "text outside the root element"}, true
			}
		case xml.Directive:
			if !lim.AllowDoctype {
				return &violation{Code: codeXMLDoctype, Detail: "DOCTYPE / directive not allowed"}, false
			}
			if bytes.Contains(bytes.ToUpper(t), []byte("ENTITY")) {
				return &violation{Code: codeXMLDoctype, Detail: "entity declaration not allowed"}, false
			}
		}
	}
}
