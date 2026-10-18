package desktop

import (
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"regexp"
	"sort"
	"strings"
)

// ChromiumProfile is a profile of a Chromium-family browser (Chrome, Chromium,
// Brave, Vivaldi, Opera, Opera GX, Edge) of the current user.
type ChromiumProfile struct {
	Browser string `json:"browser"` // key from chromiumBrowsers
	Root    string `json:"root"`    // user data directory
	Dir     string `json:"dir"`     // folder inside Root ("Default", "Profile 2")
	Name    string `json:"name"`
}

type chromiumBrowser struct {
	key   string
	label string
	apps  *regexp.Regexp // menu entry ids of this browser
	roots []string       // user data directories, relative to $HOME
}

var chromiumBrowsers = []chromiumBrowser{
	{"chrome", "Chrome", regexp.MustCompile(`^(google-chrome(-stable)?|com\.google\.Chrome)$`),
		[]string{".config/google-chrome", ".var/app/com.google.Chrome/config/google-chrome"}},
	{"chromium", "Chromium", regexp.MustCompile(`^(chromium(-browser)?|chromium_chromium|org\.chromium\.Chromium)$`),
		[]string{".config/chromium", "snap/chromium/current/.config/chromium", "snap/chromium/common/chromium", ".var/app/org.chromium.Chromium/config/chromium"}},
	{"brave", "Brave", regexp.MustCompile(`^(brave(-browser)?|brave_brave|com\.brave\.Browser)$`),
		[]string{".config/BraveSoftware/Brave-Browser", "snap/brave/current/.config/BraveSoftware/Brave-Browser", ".var/app/com.brave.Browser/config/BraveSoftware/Brave-Browser"}},
	{"vivaldi", "Vivaldi", regexp.MustCompile(`^(vivaldi(-stable)?|vivaldi_vivaldi-stable|com\.vivaldi\.Vivaldi)$`),
		[]string{".config/vivaldi", "snap/vivaldi/current/.config/vivaldi", ".var/app/com.vivaldi.Vivaldi/config/vivaldi"}},
	{"opera", "Opera", regexp.MustCompile(`^(opera(-stable)?|opera_opera|com\.opera\.Opera)$`),
		[]string{".config/opera", "snap/opera/current/.config/opera", ".var/app/com.opera.Opera/config/opera"}},
	{"opera-gx", "Opera GX", regexp.MustCompile(`^(opera-gx|opera-gx_opera-gx)$`),
		[]string{".config/opera-gx", "snap/opera-gx/current/.config/opera-gx"}},
	{"edge", "Edge", regexp.MustCompile(`^(microsoft-edge(-stable)?|com\.microsoft\.Edge)$`),
		[]string{".config/microsoft-edge", ".var/app/com.microsoft.Edge/config/microsoft-edge"}},
}

// ChromiumBrowserOf returns the browser key of a menu entry id ("" = not a
// Chromium-family browser).
func ChromiumBrowserOf(appID string) string {
	for _, b := range chromiumBrowsers {
		if b.apps.MatchString(appID) {
			return b.key
		}
	}
	return ""
}

// ChromiumProfiles lists the profiles of every installed Chromium-family
// browser, found through each user data directory's "Local State".
func ChromiumProfiles() []ChromiumProfile {
	home, err := os.UserHomeDir()
	if err != nil {
		return nil
	}
	return chromiumProfilesIn(home)
}

func chromiumProfilesIn(home string) []ChromiumProfile {
	var out []ChromiumProfile
	for _, b := range chromiumBrowsers {
		seen := map[string]bool{}
		for _, rel := range b.roots {
			root := filepath.Join(home, filepath.FromSlash(rel))
			real, err := filepath.EvalSymlinks(root)
			if err != nil || seen[real] {
				continue
			}
			seen[real] = true
			for dir, name := range localStateProfiles(root) {
				if st, err := os.Stat(filepath.Join(root, dir)); err == nil && st.IsDir() {
					out = append(out, ChromiumProfile{Browser: b.key, Root: root, Dir: dir, Name: name})
				}
			}
		}
	}
	sort.Slice(out, func(i, j int) bool {
		if out[i].Browser != out[j].Browser {
			return out[i].Browser < out[j].Browser
		}
		return out[i].Dir < out[j].Dir
	})
	return out
}

// localStateProfiles reads profile.info_cache of a user data directory: folder -> name.
func localStateProfiles(root string) map[string]string {
	out := map[string]string{}
	b, err := os.ReadFile(filepath.Join(root, "Local State"))
	if err != nil {
		return out
	}
	var ls struct {
		Profile struct {
			InfoCache map[string]struct {
				Name string `json:"name"`
			} `json:"info_cache"`
		} `json:"profile"`
	}
	if json.Unmarshal(b, &ls) != nil {
		return out
	}
	for dir, p := range ls.Profile.InfoCache {
		if strings.ContainsAny(dir, `/\`) || dir == ".." || dir == "." {
			continue
		}
		name := p.Name
		if name == "" {
			name = dir
		}
		out[dir] = name
	}
	return out
}

// InstanceDir is where a profile launcher keeps its own user data directory.
// It is not hidden: snap-confined browsers may only write to visible folders in $HOME.
func InstanceDir(home, launcherName string) string {
	return filepath.Join(home, "ShuntProfiles", slug(launcherName))
}

// ChromiumInstance makes a user data directory for one existing profile and
// returns its path. A browser process serves every profile of its data
// directory, so a profile can only get its own route when it runs in a
// directory of its own: this one holds a link to the profile's folder.
func ChromiumInstance(home string, p ChromiumProfile, launcherName string) (string, error) {
	known := false
	for _, k := range chromiumProfilesIn(home) {
		if k == p {
			known = true
		}
	}
	if !known {
		return "", errors.New("unknown browser profile")
	}
	dir := InstanceDir(home, launcherName)
	if filepath.Base(dir) == "" || filepath.Base(dir) == "." {
		return "", errors.New("name needed")
	}
	if err := os.MkdirAll(dir, 0o700); err != nil {
		return "", err
	}
	link := filepath.Join(dir, "Default")
	target := filepath.Join(p.Root, p.Dir)
	if cur, err := os.Readlink(link); err == nil {
		if cur == target {
			return dir, nil
		}
		return "", fmt.Errorf("%s already belongs to another profile (%s)", dir, cur)
	} else if _, err := os.Lstat(link); err == nil {
		return "", fmt.Errorf("%s exists and is not a link", link)
	}
	if err := os.Symlink(target, link); err != nil {
		return "", err
	}
	return dir, nil
}
