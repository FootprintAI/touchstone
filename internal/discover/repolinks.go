package discover

import (
	"bytes"
	"net/url"
	"strings"

	"golang.org/x/net/html"
)

// notOwners are GitHub and GitLab path prefixes that are site pages, not
// a repo owner (share buttons, login links, marketing pages).
var notOwners = map[string]bool{
	"sharer": true, "share": true, "intent": true, "login": true, "signup": true, "join": true,
	"features": true, "pricing": true, "about": true, "orgs": true, "sponsors": true,
	"topics": true, "marketplace": true, "settings": true, "apps": true, "enterprise": true,
	"explore": true, "users": true, "groups": true, "help": true, "search": true,
}

// notRepoPaths are path segments after owner/repo that mark a badge or
// share link rather than a link to the repo itself.
var notRepoPaths = map[string]bool{
	"badge": true, "badges": true, "actions": true, "workflows": true, "sharer": true, "share": true,
}

// RepoLinks returns the GitHub and GitLab repository URLs the page links
// to with <a href> or <link href>, normalized to https://host/owner/repo,
// in document order and without duplicates. Badge images and their
// links, share buttons and site pages are ignored.
func RepoLinks(page *url.URL, body []byte) []string {
	doc, err := html.Parse(bytes.NewReader(body))
	if err != nil {
		return nil
	}
	seen := map[string]bool{}
	var out []string
	var walk func(*html.Node)
	walk = func(n *html.Node) {
		if n.Type == html.ElementNode && (n.Data == "a" || n.Data == "link") && !hasBadgeImage(n) {
			for _, a := range n.Attr {
				if a.Key != "href" {
					continue
				}
				if repo, ok := repoURL(page, a.Val); ok && !seen[repo] {
					seen[repo] = true
					out = append(out, repo)
				}
				break
			}
		}
		for c := n.FirstChild; c != nil; c = c.NextSibling {
			walk(c)
		}
	}
	walk(doc)
	return out
}

// hasBadgeImage reports whether n wraps an <img> that is a status badge.
func hasBadgeImage(n *html.Node) bool {
	for c := n.FirstChild; c != nil; c = c.NextSibling {
		if c.Type == html.ElementNode && c.Data == "img" {
			for _, a := range c.Attr {
				if a.Key == "src" && isBadgeSrc(a.Val) {
					return true
				}
			}
		}
		if hasBadgeImage(c) {
			return true
		}
	}
	return false
}

func isBadgeSrc(src string) bool {
	u, err := url.Parse(src)
	if err != nil {
		return false
	}
	host := strings.ToLower(u.Hostname())
	return strings.HasSuffix(host, "shields.io") || strings.Contains(host, "badge") ||
		strings.Contains(strings.ToLower(u.Path), "badge")
}

func repoURL(page *url.URL, href string) (string, bool) {
	ref, err := url.Parse(strings.TrimSpace(href))
	if err != nil {
		return "", false
	}
	u := page.ResolveReference(ref)
	host := strings.TrimPrefix(strings.ToLower(u.Hostname()), "www.")
	if (u.Scheme != "http" && u.Scheme != "https") || (host != "github.com" && host != "gitlab.com") {
		return "", false
	}
	var segs []string
	for _, s := range strings.Split(u.Path, "/") {
		if s != "" {
			segs = append(segs, s)
		}
	}
	if len(segs) < 2 || notOwners[strings.ToLower(segs[0])] {
		return "", false
	}
	if len(segs) > 2 && notRepoPaths[strings.ToLower(segs[2])] {
		return "", false
	}
	if len(segs) > 3 && segs[2] == "-" && notRepoPaths[strings.ToLower(segs[3])] {
		return "", false
	}
	if strings.HasSuffix(strings.ToLower(segs[len(segs)-1]), "badge.svg") {
		return "", false
	}
	return "https://" + host + "/" + segs[0] + "/" + strings.TrimSuffix(segs[1], ".git"), true
}
