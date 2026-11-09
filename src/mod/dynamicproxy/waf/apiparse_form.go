package waf

import (
	"bytes"
	"fmt"
	"io"
	"mime/multipart"
)

/*
	apiparse_form.go

	Form bodies: application/x-www-form-urlencoded is counted without
	decoding, multipart bodies are walked part by part (headers only, the
	part content is skipped, not stored).
*/

// checkParams counts the &-separated parameters of a query string / urlencoded body
// and returns a violation if a limit is exceeded.
func checkParams(s string, maxN, maxLen int, countCode, lenCode, what string) *violation {
	n := 0
	start := 0
	for i := 0; i <= len(s); i++ {
		if i == len(s) || s[i] == '&' {
			if i > start {
				n++
				if maxN > 0 && n > maxN {
					return &violation{Code: countCode, Detail: fmt.Sprintf("more than %d %s", maxN, what)}
				}
				if maxLen > 0 && i-start > maxLen {
					return &violation{Code: lenCode, Detail: fmt.Sprintf("a parameter is longer than %d bytes", maxLen)}
				}
			}
			start = i + 1
		}
	}
	return nil
}

func checkURLEncoded(b []byte, lim APILimits) *violation {
	return checkParams(string(b), lim.FormMaxFields, lim.QueryMaxParamLen, codeFormFields, codeQueryParamLen, "form fields")
}

func checkMultipart(b []byte, boundary string, lim APILimits) (v *violation, syntax bool) {
	if boundary == "" {
		return &violation{Code: codeSyntax, Detail: "multipart boundary missing"}, true
	}
	mr := multipart.NewReader(bytes.NewReader(b), boundary)
	parts, files, fields := 0, 0, 0
	for {
		p, err := mr.NextRawPart()
		if err == io.EOF {
			return nil, false
		}
		if err != nil {
			return &violation{Code: codeSyntax, Detail: "malformed multipart body"}, true
		}
		parts++
		if lim.MultipartMaxParts > 0 && parts > lim.MultipartMaxParts {
			return &violation{Code: codeMultipartParts, Detail: fmt.Sprintf("more than %d parts", lim.MultipartMaxParts)}, false
		}
		if p.FileName() != "" {
			files++
			if lim.MultipartMaxFiles > 0 && files > lim.MultipartMaxFiles {
				return &violation{Code: codeMultipartFiles, Detail: fmt.Sprintf("more than %d files", lim.MultipartMaxFiles)}, false
			}
		} else {
			fields++
			if lim.FormMaxFields > 0 && fields > lim.FormMaxFields {
				return &violation{Code: codeFormFields, Detail: fmt.Sprintf("more than %d form fields", lim.FormMaxFields)}, false
			}
		}
	}
}
