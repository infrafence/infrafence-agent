// Package opnsense reads an OPNsense firewall without changing it: its
// configuration (/conf/config.xml), its logs and its firmware status. The
// agent uses it for the addresses it must never block, the log events it
// reports and the configuration findings it sends to the dashboard.
package opnsense

import (
	"encoding/xml"
	"errors"
	"io"
	"os"
	"strings"
)

// Node is an XML element: config.xml has elements named after interfaces
// (wan, lan, opt1) and many optional sections, so a generic tree reads it
// better than fixed structs.
type Node struct {
	Name     string
	Attr     map[string]string
	Text     string
	Children []*Node
}

// maxConfigBytes bounds config.xml (a large one with many aliases is a few
// MB).
const maxConfigBytes = 64 << 20

// ParseXML reads a document into a tree.
func ParseXML(r io.Reader) (*Node, error) {
	dec := xml.NewDecoder(io.LimitReader(r, maxConfigBytes))
	dec.Strict = false
	var stack []*Node
	var root *Node
	for {
		tok, err := dec.Token()
		if err == io.EOF {
			break
		}
		if err != nil {
			return nil, err
		}
		switch t := tok.(type) {
		case xml.StartElement:
			n := &Node{Name: t.Name.Local}
			for _, a := range t.Attr {
				if n.Attr == nil {
					n.Attr = map[string]string{}
				}
				n.Attr[a.Name.Local] = a.Value
			}
			if len(stack) > 0 {
				p := stack[len(stack)-1]
				p.Children = append(p.Children, n)
			} else if root == nil {
				root = n
			}
			stack = append(stack, n)
			if len(stack) > 64 {
				return nil, errors.New("config.xml nested too deep")
			}
		case xml.EndElement:
			if len(stack) > 0 {
				n := stack[len(stack)-1]
				n.Text = strings.TrimSpace(n.Text)
				stack = stack[:len(stack)-1]
			}
		case xml.CharData:
			if len(stack) > 0 {
				stack[len(stack)-1].Text += string(t)
			}
		}
	}
	if root == nil {
		return nil, errors.New("empty document")
	}
	return root, nil
}

// LoadXML reads the file at path.
func LoadXML(path string) (*Node, error) {
	f, err := os.Open(path)
	if err != nil {
		return nil, err
	}
	defer f.Close()
	return ParseXML(f)
}

// Child returns the first child named name (nil: none).
func (n *Node) Child(name string) *Node {
	if n == nil {
		return nil
	}
	for _, c := range n.Children {
		if c.Name == name {
			return c
		}
	}
	return nil
}

// Get follows a slash-separated path of first children.
func (n *Node) Get(path string) *Node {
	cur := n
	for _, p := range strings.Split(path, "/") {
		if cur == nil {
			return nil
		}
		cur = cur.Child(p)
	}
	return cur
}

// Has: the element at path exists (an empty <any/> counts).
func (n *Node) Has(path string) bool { return n.Get(path) != nil }

// Str is the text at path ("" when missing).
func (n *Node) Str(path string) string {
	if c := n.Get(path); c != nil {
		return c.Text
	}
	return ""
}

// All returns every element matching path, where only the last step may
// match several (e.g. "system/user").
func (n *Node) All(path string) []*Node {
	i := strings.LastIndexByte(path, '/')
	parent := n
	last := path
	if i >= 0 {
		parent = n.Get(path[:i])
		last = path[i+1:]
	}
	if parent == nil {
		return nil
	}
	var out []*Node
	for _, c := range parent.Children {
		if c.Name == last {
			out = append(out, c)
		}
	}
	return out
}

// Walk calls fn for n and every descendant.
func (n *Node) Walk(fn func(*Node)) {
	if n == nil {
		return
	}
	fn(n)
	for _, c := range n.Children {
		c.Walk(fn)
	}
}
