// (c) Copyright 2016 Hewlett Packard Enterprise Development LP
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//     http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.

package rules

import (
	"fmt"
	"go/ast"
	"strings"

	"github.com/securego/gosec"
)

type blacklistedImport struct {
	gosec.MetaData
	Blacklisted map[string]string
}

func unquote(original string) string {
	copy := strings.TrimSpace(original)
	copy = strings.TrimLeft(copy, `"`)
	return strings.TrimRight(copy, `"`)
}

func (r *blacklistedImport) ID() string {
	return r.MetaData.ID
}

func (r *blacklistedImport) Match(n ast.Node, c *gosec.Context) (*gosec.Issue, error) {
	if node, ok := n.(*ast.ImportSpec); ok {
		if description, ok := r.Blacklisted[unquote(node.Path.Value)]; ok {
			return gosec.NewIssue(c, node, r.ID(), description, r.Severity, r.Confidence), nil
		}
	}
	return nil, nil
}

// NewBlacklistedImports reports when a blacklisted import is being used.
// Typically when a deprecated technology is being used.
func NewBlacklistedImports(id string, conf gosec.Config, blacklist map[string]string) (gosec.Rule, []ast.Node) {
	return &blacklistedImport{
		MetaData: gosec.MetaData{
			ID:         id,
			Severity:   gosec.Medium,
			Confidence: gosec.High,
		},
		Blacklisted: blacklist,
	}, []ast.Node{(*ast.ImportSpec)(nil)}
}

// NewBlacklistedImport fails if any of the paths specified in conf are imported.
func NewBlacklistedImport(id string, conf gosec.Config) (gosec.Rule, []ast.Node) {
	var blacklist map[string]string
	customBlacklist, err := conf.Get(id)
	if err == nil {
		blacklist = customBlacklist.(map[string]string) // TODO catch conversion err?
	} else {
		blacklist = defaultBlacklistedImports()
	}
	if configured, ok := conf[id]; ok {
		if blacklisted, ok := configured.(map[string]string); ok {
			for path, reason := range blacklisted {
				blacklist[path] = fmt.Sprintf("Blacklisted import %s: %s", path, reason)
			}
		}
	}

	return NewBlacklistedImports(id, conf, blacklist)
}

// defaultBlacklistedImports returns a blacklist containing import paths that
// will be blacklisted by default.
func defaultBlacklistedImports() map[string]string {
	return map[string]string{
		"crypto/md5":   "weak cryptographic primitive",
		"crypto/des":   "weak cryptographic primitive",
		"crypto/rc4":   "weak cryptographic primitive",
		"net/http/cgi": "Go versions < 1.6.3 are vulnerable to Httpoxy attack: (CVE-2016-5386)",
		"crypto/sha1":  "weak cryptographic primitive",
	}
}
