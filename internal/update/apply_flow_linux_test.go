package update

import (
	"context"
	"errors"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

// fakePkexec puts a pkexec on PATH that, instead of asking for a password
// and switching to root, records that it was called and runs its arguments
// as the test user. With FAKE_SWAP set it first overwrites the downloaded
// installer (its 5th argument), like a process that swaps the file between
// the check in the app and the run as root.
func fakePkexec(t *testing.T) (called string) {
	t.Helper()
	bin := t.TempDir()
	called = filepath.Join(t.TempDir(), "pkexec-called")
	fake := "#!/bin/bash\necho \"$@\" >>" + called + "\n" +
		"if [[ -n ${FAKE_SWAP:-} ]]; then printf '%s' \"$FAKE_SWAP\" >\"$5\"; fi\n" +
		"exec \"$@\"\n"
	if err := os.WriteFile(filepath.Join(bin, "pkexec"), []byte(fake), 0o755); err != nil {
		t.Fatal(err)
	}
	t.Setenv("PATH", bin+string(os.PathListSeparator)+os.Getenv("PATH"))
	t.Setenv("XDG_CONFIG_HOME", t.TempDir()) // LogFile
	t.Setenv("TMPDIR", t.TempDir())          // downloads
	return called
}

// installer writes its environment to ran: proof that it was executed.
func installer(ran string) string {
	return "#!/bin/bash\necho \"ref=$SHUNT_REF yes=$SHUNT_YES rel=$SHUNT_RELEASE_INSTALLER\" >" + ran + "\n"
}

// The whole Linux update path without root: only an install.sh that the
// release key signed reaches pkexec, and pkexec's side runs only that one.
func TestApplyFlow(t *testing.T) {
	ctx := context.Background()

	t.Run("signed installer runs", func(t *testing.T) {
		called := fakePkexec(t)
		ran := filepath.Join(t.TempDir(), "ran")
		s := installer(ran)
		release(t, map[string]string{"install.sh": s}, map[string]string{"install.sh": s}, true)
		if err := Apply(ctx, "v1.2.3"); err != nil {
			t.Fatal(err)
		}
		if _, err := os.Stat(called); err != nil {
			t.Fatal("pkexec was not called")
		}
		b, err := os.ReadFile(ran)
		if err != nil || strings.TrimSpace(string(b)) != "ref=v1.2.3 yes=1 rel=1" {
			t.Fatalf("installer ran with %q (%v)", b, err)
		}
	})

	// every manipulation must stop before pkexec, so nothing runs as root
	for _, c := range []struct {
		name   string
		served string            // install.sh as served
		sums   map[string]string // what SHA256SUMS lists (hash of the content)
		sign   bool              // signed with the release key
		sig    *string           // replaces SHA256SUMS.sig; "" = missing
		want   string
	}{
		{name: "tampered install.sh", served: "rm -rf ~\n", sums: map[string]string{"install.sh": "good"}, sign: true, want: "does not match"},
		{name: "wrong checksum in the list", served: "good", sums: map[string]string{"install.sh": "other"}, sign: true, want: "does not match"},
		{name: "install.sh not listed", served: "good", sums: map[string]string{"shunt_linux_amd64.tar.gz": "x"}, sign: true, want: "has no install.sh"},
		{name: "signed by another key", served: "good", sums: map[string]string{"install.sh": "good"}, sign: false, want: "another key"},
		{name: "signature missing", served: "good", sums: map[string]string{"install.sh": "good"}, sign: true, sig: ptr(""), want: "404"},
		{name: "old release under a new tag", served: "good", sums: map[string]string{"install.sh": "good", "# tag": "v1.2.2"}, sign: true, want: "belong to release v1.2.2"},
		{name: "release not named", served: "good", sums: map[string]string{"install.sh": "good", "# tag": ""}, sign: true, want: "do not name release v1.2.3"},
		{name: "signature garbage", served: "good", sums: map[string]string{"install.sh": "good"}, sign: true, sig: ptr("-----BEGIN SSH SIGNATURE-----\nAAAA\n-----END SSH SIGNATURE-----\n"), want: "not an SSH signature"},
	} {
		t.Run(c.name, func(t *testing.T) {
			called := fakePkexec(t)
			ran := filepath.Join(t.TempDir(), "ran")
			files := map[string]string{"install.sh": installer(ran) + c.served}
			sums := map[string]string{}
			for k, v := range c.sums {
				if k == "install.sh" {
					v = installer(ran) + v
				}
				sums[k] = v
			}
			release(t, files, sums, c.sign)
			if c.sig != nil {
				if *c.sig == "" {
					delete(files, "SHA256SUMS.sig")
				} else {
					files["SHA256SUMS.sig"] = *c.sig
				}
			}
			err := Apply(ctx, "v1.2.3")
			if err == nil || !strings.Contains(err.Error(), c.want) || !strings.Contains(err.Error(), "nothing was installed") {
				t.Fatalf("err %v, want %q", err, c.want)
			}
			if _, err := os.Stat(called); err == nil {
				t.Fatal("pkexec was called")
			}
			if _, err := os.Stat(ran); err == nil {
				t.Fatal("installer ran")
			}
			if left, _ := os.ReadDir(os.Getenv("TMPDIR")); len(left) != 0 {
				t.Fatalf("download left behind: %v", left)
			}
		})
	}

	// the file is swapped after the app checked it: the root side hashes its
	// own copy and refuses
	t.Run("swapped after the check", func(t *testing.T) {
		called := fakePkexec(t)
		ran := filepath.Join(t.TempDir(), "ran")
		evil := filepath.Join(t.TempDir(), "evil")
		s := installer(ran)
		release(t, map[string]string{"install.sh": s}, map[string]string{"install.sh": s}, true)
		t.Setenv("FAKE_SWAP", "#!/bin/bash\ntouch "+evil+"\n")
		err := Apply(ctx, "v1.2.3")
		if err == nil || !strings.Contains(err.Error(), "does not match the signed checksum") {
			t.Fatalf("err %v", err)
		}
		if _, err := os.Stat(called); err != nil {
			t.Fatal("pkexec was not called")
		}
		for _, f := range []string{ran, evil} {
			if _, err := os.Stat(f); err == nil {
				t.Fatalf("%s ran", filepath.Base(f))
			}
		}
	})

	// a branch or a sha is not a release: no download, no pkexec
	t.Run("not a release tag", func(t *testing.T) {
		called := fakePkexec(t)
		for _, tag := range []string{"main", "HEAD", "v1.2.3/../../x", "v1.2.3;id", ""} {
			if err := Apply(ctx, tag); !errors.Is(err, ErrNotSupported) {
				t.Fatalf("%q: err %v", tag, err)
			}
		}
		if _, err := os.Stat(called); err == nil {
			t.Fatal("pkexec was called")
		}
	})
}

func ptr(s string) *string { return &s }
