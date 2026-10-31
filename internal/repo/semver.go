package repo

import (
	"strconv"
	"strings"
)

// semver is a parsed MAJOR.MINOR.PATCH version. Prerelease is true when the
// tag carries a "-suffix"; build metadata ("+x") is ignored.
type semver struct {
	major, minor, patch int
	prerelease          bool
}

// parseSemver accepts "v1.2.3" and "1.2.3". Anything else (including
// two-part versions and non-numeric tags) is not a semver tag.
func parseSemver(tag string) (semver, bool) {
	s := strings.TrimPrefix(tag, "v")
	if i := strings.IndexByte(s, '+'); i >= 0 {
		s = s[:i]
	}
	var v semver
	if i := strings.IndexByte(s, '-'); i >= 0 {
		v.prerelease = true
		s = s[:i]
	}
	parts := strings.Split(s, ".")
	if len(parts) != 3 {
		return semver{}, false
	}
	nums := [3]int{}
	for i, p := range parts {
		n, err := strconv.Atoi(p)
		if err != nil || n < 0 || p != strconv.Itoa(n) {
			return semver{}, false
		}
		nums[i] = n
	}
	v.major, v.minor, v.patch = nums[0], nums[1], nums[2]
	return v, true
}

func (a semver) less(b semver) bool {
	if a.major != b.major {
		return a.major < b.major
	}
	if a.minor != b.minor {
		return a.minor < b.minor
	}
	return a.patch < b.patch
}

// LatestSemverTag returns the highest non-prerelease semver tag, or "" and
// false when there is none.
func LatestSemverTag(tags []string) (string, bool) {
	best, bestTag := semver{}, ""
	for _, t := range tags {
		v, ok := parseSemver(t)
		if !ok || v.prerelease {
			continue
		}
		if bestTag == "" || best.less(v) {
			best, bestTag = v, t
		}
	}
	return bestTag, bestTag != ""
}
