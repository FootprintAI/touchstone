package discover

import (
	"bytes"
	"net/url"
	"path"
	"strings"

	"golang.org/x/net/html"
)

// forgeHosts are the hosts whose repo links are extracted, by the name the
// link is normalized to.
var forgeHosts = map[string]string{
	"github.com":     "github.com",
	"www.github.com": "github.com",
	"gitlab.com":     "gitlab.com",
	"www.gitlab.com": "gitlab.com",
}

// reservedOwners are first path segments on GitHub and GitLab that are
// site pages, not accounts: login and share targets, marketing pages,
// settings, search.
var reservedOwners = map[string]bool{
	"-": true, "about": true, "apps": true, "collections": true, "contact": true,
	"dashboard": true, "enterprise": true, "explore": true, "features": true,
	"help": true, "join": true, "login": true, "logout": true, "marketplace": true,
	"new": true, "notifications": true, "orgs": true, "pricing": true, "search": true,
	"security": true, "sessions": true, "settings": true, "share": true, "signup": true,
	"site": true, "sponsors": true, "topics": true, "trending": true, "users": true,
	"users_sign_in": true,
}

// RepoLinks returns the GitHub and GitLab repositories the page links to
// with <a href>, normalized to https://host/owner/repo (GitLab keeps its
// subgroups), each once, in page order. Badge links (an image-only link
// to a badge image, or a link to a badge itself) and links to site pages
// such as login or share targets are ignored.
func RepoLinks(page *url.URL, body []byte) ([]string, error) {
	doc, err := html.Parse(bytes.NewReader(body))
	if err != nil {
		return nil, err
	}
	var out []string
	seen := map[string]bool{}
	var walk func(*html.Node)
	walk = func(n *html.Node) {
		if n.Type == html.ElementNode && n.Data == "a" && !isBadge(n) {
			if repo, ok := repoURL(page, attr(n, "href")); ok && !seen[strings.ToLower(repo)] {
				seen[strings.ToLower(repo)] = true
				out = append(out, repo)
			}
		}
		for c := n.FirstChild; c != nil; c = c.NextSibling {
			walk(c)
		}
	}
	walk(doc)
	return out, nil
}

// repoURL normalizes href to a repository URL, if it names one.
func repoURL(page *url.URL, href string) (string, bool) {
	ref, err := url.Parse(strings.TrimSpace(href))
	if err != nil {
		return "", false
	}
	u := page.ResolveReference(ref)
	host, ok := forgeHosts[strings.ToLower(u.Hostname())]
	if !ok || (u.Scheme != "http" && u.Scheme != "https") {
		return "", false
	}
	p := strings.ToLower(u.Path)
	if strings.Contains(p, "badge") || path.Ext(p) == ".svg" || path.Ext(p) == ".png" {
		return "", false
	}
	var segs []string
	for _, s := range strings.Split(u.Path, "/") {
		if s == "" {
			continue
		}
		// GitLab puts every page under a project after a "-" segment.
		if s == "-" {
			break
		}
		segs = append(segs, s)
	}
	if host == "github.com" && len(segs) > 2 {
		segs = segs[:2]
	}
	if len(segs) < 2 || reservedOwners[strings.ToLower(segs[0])] {
		return "", false
	}
	segs[len(segs)-1] = strings.TrimSuffix(segs[len(segs)-1], ".git")
	return "https://" + host + "/" + strings.Join(segs, "/"), true
}

// isBadge reports whether the link a shows only an image (no text) and
// that image is a badge, such as a shields.io status badge.
func isBadge(a *html.Node) bool {
	badge := false
	var walk func(*html.Node) bool
	walk = func(n *html.Node) bool {
		for c := n.FirstChild; c != nil; c = c.NextSibling {
			switch {
			case c.Type == html.TextNode && strings.TrimSpace(c.Data) != "":
				return false
			case c.Type == html.ElementNode && c.Data == "img":
				src := strings.ToLower(attr(c, "src"))
				if strings.Contains(src, "badge") || strings.Contains(src, "shields.io") {
					badge = true
				}
			case c.Type == html.ElementNode:
				if !walk(c) {
					return false
				}
			}
		}
		return true
	}
	return walk(a) && badge
}

func attr(n *html.Node, name string) string {
	for _, a := range n.Attr {
		if a.Key == name {
			return a.Val
		}
	}
	return ""
}
