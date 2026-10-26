package i18n

import "testing"

func TestResolve(t *testing.T) {
	for want, got := range map[string]string{
		"de": "de", "de_DE.UTF-8": "de", "de-AT": "de", "DE_de@euro": "de",
		"en_US.UTF-8": "en", "fr": "en", "": "en", "C": "en", "xx": "xx",
	} {
		if r := Resolve(want); r != got {
			t.Errorf("Resolve(%q) = %q, want %q", want, r, got)
		}
	}
}

func TestTranslate(t *testing.T) {
	mu.Lock()
	load()
	catalogs["de"].Strings["Hello {name}"] = "Hallo {name}"
	catalogs["de"].Strings["{n} rule"] = "{n} Regel"
	catalogs["de"].Strings["{n} rules"] = "{n} Regeln"
	mu.Unlock()
	defer func() {
		mu.Lock()
		delete(catalogs["de"].Strings, "Hello {name}")
		delete(catalogs["de"].Strings, "{n} rule")
		delete(catalogs["de"].Strings, "{n} rules")
		mu.Unlock()
		Set("")
	}()
	Set("de")
	if g := T("Hello {name}", "name", "Bob"); g != "Hallo Bob" {
		t.Errorf("T = %q", g)
	}
	if g := T("no translation for this {x}", "x", 5); g != "no translation for this 5" {
		t.Errorf("fallback = %q (English text, placeholders filled)", g)
	}
	if g := Tn(1, "{n} rule", "{n} rules"); g != "1 Regel" {
		t.Errorf("Tn(1) = %q", g)
	}
	if g := Tn(3, "{n} rule", "{n} rules"); g != "3 Regeln" {
		t.Errorf("Tn(3) = %q", g)
	}
	Set("en")
	if g := Tn(3, "{n} rule", "{n} rules"); g != "3 rules" {
		t.Errorf("English = %q", g)
	}
}

func TestDetect(t *testing.T) {
	t.Setenv("XDG_CONFIG_HOME", t.TempDir()) // no ui-state file
	for _, c := range []struct{ env, lang, want string }{
		{"", "de_DE.UTF-8", "de"},
		{"", "en_GB.UTF-8", "en"},
		{"", "C", "en"},
		{"en", "de_DE.UTF-8", "en"}, // SHUNT_LANG wins
		{"de", "en_US.UTF-8", "de"},
		{"auto", "de_DE.UTF-8", "de"},
	} {
		t.Setenv("SHUNT_LANG", c.env)
		t.Setenv("LANGUAGE", "")
		t.Setenv("LC_ALL", "")
		t.Setenv("LC_MESSAGES", "")
		t.Setenv("LANG", c.lang)
		if g := Detect(); g != c.want {
			t.Errorf("SHUNT_LANG=%q LANG=%q: %q, want %q", c.env, c.lang, g, c.want)
		}
	}
}

func TestLanguagesAndPseudo(t *testing.T) {
	ls := Languages()
	if ls[0].Code != "en" || ls[0].Name != "English" {
		t.Errorf("first language %+v", ls[0])
	}
	for _, l := range ls {
		if l.Code == pseudo {
			t.Error("the test language must not be offered")
		}
	}
	if g := pseudoText("Save {n} rules"); g[0] != '[' || !contains(g, "{n}") {
		t.Errorf("pseudo = %q (placeholders must stay)", g)
	}
}

func contains(s, sub string) bool {
	for i := 0; i+len(sub) <= len(s); i++ {
		if s[i:i+len(sub)] == sub {
			return true
		}
	}
	return false
}
