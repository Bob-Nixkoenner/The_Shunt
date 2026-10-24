package desktop

import (
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"regexp"
	"runtime"
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
	// Windows: the program (lower-case path) and the user data directories,
	// relative to %LOCALAPPDATA% or, with "roaming/", to %APPDATA%
	winExe   *regexp.Regexp
	winRoots []string
}

var chromiumBrowsers = []chromiumBrowser{
	{"chrome", "Chrome", regexp.MustCompile(`^(google-chrome(-stable)?|com\.google\.Chrome)$`),
		[]string{".config/google-chrome", ".var/app/com.google.Chrome/config/google-chrome"},
		regexp.MustCompile(`\\google\\chrome\\application\\chrome\.exe$`), []string{"Google/Chrome/User Data"}},
	{"chromium", "Chromium", regexp.MustCompile(`^(chromium(-browser)?|chromium_chromium|org\.chromium\.Chromium)$`),
		[]string{".config/chromium", "snap/chromium/current/.config/chromium", "snap/chromium/common/chromium", ".var/app/org.chromium.Chromium/config/chromium"},
		regexp.MustCompile(`\\chromium\\application\\chrome\.exe$`), []string{"Chromium/User Data"}},
	{"brave", "Brave", regexp.MustCompile(`^(brave(-browser)?|brave_brave|com\.brave\.Browser)$`),
		[]string{".config/BraveSoftware/Brave-Browser", "snap/brave/current/.config/BraveSoftware/Brave-Browser", ".var/app/com.brave.Browser/config/BraveSoftware/Brave-Browser"},
		regexp.MustCompile(`\\brave\.exe$`), []string{"BraveSoftware/Brave-Browser/User Data"}},
	{"vivaldi", "Vivaldi", regexp.MustCompile(`^(vivaldi(-stable)?|vivaldi_vivaldi-stable|com\.vivaldi\.Vivaldi)$`),
		[]string{".config/vivaldi", "snap/vivaldi/current/.config/vivaldi", ".var/app/com.vivaldi.Vivaldi/config/vivaldi"},
		regexp.MustCompile(`\\vivaldi\.exe$`), []string{"Vivaldi/User Data"}},
	{"opera", "Opera", regexp.MustCompile(`^(opera(-stable)?|opera_opera|com\.opera\.Opera)$`),
		[]string{".config/opera", "snap/opera/current/.config/opera", ".var/app/com.opera.Opera/config/opera"},
		regexp.MustCompile(`\\opera\\(launcher|opera)\.exe$`), []string{"roaming/Opera Software/Opera Stable"}},
	{"opera-gx", "Opera GX", regexp.MustCompile(`^(opera-gx|opera-gx_opera-gx)$`),
		[]string{".config/opera-gx", "snap/opera-gx/current/.config/opera-gx"},
		regexp.MustCompile(`\\opera gx\\(launcher|opera)\.exe$`), []string{"roaming/Opera Software/Opera GX Stable"}},
	{"edge", "Edge", regexp.MustCompile(`^(microsoft-edge(-stable)?|com\.microsoft\.Edge)$`),
		[]string{".config/microsoft-edge", ".var/app/com.microsoft.Edge/config/microsoft-edge"},
		regexp.MustCompile(`\\microsoft\\edge\\application\\msedge\.exe$`), []string{"Microsoft/Edge/User Data"}},
}

// goos and appData are variables for the tests.
var (
	goos    = runtime.GOOS
	appData = func() (local, roaming string) { return os.Getenv("LOCALAPPDATA"), os.Getenv("APPDATA") }
)

// dataDirs lists where the browser may keep its user data directory.
func (b chromiumBrowser) dataDirs(home string) []string {
	var out []string
	if goos != "windows" {
		for _, rel := range b.roots {
			out = append(out, filepath.Join(home, filepath.FromSlash(rel)))
		}
		return out
	}
	local, roaming := appData()
	for _, rel := range b.winRoots {
		base := local
		if r, ok := strings.CutPrefix(rel, "roaming/"); ok {
			base, rel = roaming, r
		}
		if base != "" {
			out = append(out, filepath.Join(base, filepath.FromSlash(rel)))
		}
	}
	return out
}

// ChromiumBrowserOfExe returns the browser key of a Windows program path
// ("" = not a Chromium-family browser).
func ChromiumBrowserOfExe(path string) string {
	p := strings.ToLower(strings.ReplaceAll(path, "/", `\`))
	for _, b := range chromiumBrowsers {
		if b.winExe.MatchString(p) {
			return b.key
		}
	}
	return ""
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
		for _, root := range b.dataDirs(home) {
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
		if samePath(cur, target) {
			return dir, keyFile(p.Root, dir)
		}
		return "", fmt.Errorf("%s already belongs to another profile (%s)", dir, cur)
	} else if _, err := os.Lstat(link); err == nil {
		return "", fmt.Errorf("%s exists and is not a link", link)
	}
	if err := dirLink(target, link); err != nil {
		return "", err
	}
	return dir, keyFile(p.Root, dir)
}

// keyFile: on Windows, Chromium encrypts cookies and saved passwords with a
// key kept in "Local State" of the user data directory. A new directory
// would make a new key and the linked profile could not read its own data
// (logged out everywhere, passwords gone), so the instance starts with a
// copy of the original's. Linux keeps that key in the keyring instead.
func keyFile(root, dir string) error {
	if goos != "windows" {
		return nil
	}
	dst := filepath.Join(dir, "Local State")
	if _, err := os.Stat(dst); err == nil {
		return nil // the browser keeps it up to date from now on
	}
	b, err := os.ReadFile(filepath.Join(root, "Local State"))
	if err != nil {
		return fmt.Errorf("the browser's key file: %w", err)
	}
	return os.WriteFile(dst, b, 0o600)
}
