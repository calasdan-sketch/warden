package main

import (
	"encoding/json"
	"os"
	"os/exec"
	"path/filepath"
	"regexp"
	"strings"
	"testing"
)

// These tests pin the facts a release depends on: who the maintainer is, and
// that the version is the same everywhere it is written. A mismatch here is
// what a publish would otherwise carry out to the registry.

func repoFile(t *testing.T, rel string) string {
	t.Helper()
	b, err := os.ReadFile(filepath.Join("..", "..", rel))
	if err != nil {
		t.Fatal(err)
	}
	return string(b)
}

func TestMaintainerNameIsPinned(t *testing.T) {
	if maintainer != "Calas Automations Inc." {
		t.Fatalf("maintainer constant changed: %q", maintainer)
	}
	if !strings.Contains(repoFile(t, "LICENSE"), "Copyright (c) 2026 Calas Automations Inc.\n") {
		t.Error("LICENSE copyright line must read exactly: Copyright (c) 2026 Calas Automations Inc.")
	}
	var pkg struct {
		Author  string            `json:"author"`
		Version string            `json:"version"`
		Deps    map[string]string `json:"optionalDependencies"`
		Publish struct {
			Access string `json:"access"`
		} `json:"publishConfig"`
	}
	if err := json.Unmarshal([]byte(repoFile(t, "npm/warden/package.json")), &pkg); err != nil {
		t.Fatal(err)
	}
	if pkg.Author != maintainer {
		t.Errorf("npm/warden/package.json author = %q", pkg.Author)
	}
	if pkg.Publish.Access != "public" {
		t.Error("scoped npm packages are private unless publishConfig.access is public")
	}
	build := repoFile(t, "scripts/build-npm.sh")
	if !strings.Contains(build, `"author": "Calas Automations Inc."`) || !strings.Contains(build, `"publishConfig": { "access": "public" }`) {
		t.Error("scripts/build-npm.sh must write the author and public access into every platform package")
	}
	if !strings.Contains(repoFile(t, "README.md"), "© Calas Automations Inc.") {
		t.Error("README license line must name the maintainer")
	}

	// The CLI says it too.
	exe := filepath.Join(t.TempDir(), "warden-test")
	if out, err := exec.Command("go", "build", "-o", exe, ".").CombinedOutput(); err != nil {
		t.Fatalf("build: %v\n%s", err, out)
	}
	out, err := exec.Command(exe, "about").Output()
	if err != nil || !strings.Contains(string(out), "Maintained by Calas Automations Inc.") {
		t.Fatalf("about output: %q (%v)", out, err)
	}
}

func TestNoStrayAuthorLabels(t *testing.T) {
	// Author or owner labels must use the company name. (GitHub URLs under
	// calasdan-sketch and the @decnutz npm scope are real addresses, not labels.)
	bad := regexp.MustCompile(`(?i)(dan calas|dan\s+calas|author[": =]+\s*"?(dan|decnutz|calasdan))`)
	root := filepath.Join("..", "..")
	_ = filepath.Walk(root, func(p string, info os.FileInfo, err error) error {
		if err != nil {
			return nil
		}
		if info.IsDir() {
			switch info.Name() {
			case ".git", "dist", "reviews", "testdata":
				return filepath.SkipDir
			}
			return nil
		}
		if info.Size() > 2<<20 || strings.HasSuffix(p, "release_test.go") {
			return nil
		}
		b, err := os.ReadFile(p)
		if err != nil || strings.ContainsRune(string(b[:min(len(b), 512)]), 0) {
			return nil
		}
		if m := bad.Find(b); m != nil {
			t.Errorf("%s: stray author label %q", p, m)
		}
		return nil
	})
}

func TestVersionIsTheSameEverywhere(t *testing.T) {
	var pkg struct {
		Version string            `json:"version"`
		Deps    map[string]string `json:"optionalDependencies"`
	}
	if err := json.Unmarshal([]byte(repoFile(t, "npm/warden/package.json")), &pkg); err != nil {
		t.Fatal(err)
	}
	if pkg.Version != version {
		t.Errorf("package.json version %s != main.version %s", pkg.Version, version)
	}
	if len(pkg.Deps) != 6 {
		t.Errorf("expected 6 platform packages, got %d", len(pkg.Deps))
	}
	for name, v := range pkg.Deps {
		if v != version {
			t.Errorf("%s pinned to %s, want %s", name, v, version)
		}
	}
	if !strings.Contains(repoFile(t, "CHANGELOG.md"), "## "+version+" ") {
		t.Errorf("CHANGELOG.md has no heading for %s", version)
	}
	if !strings.Contains(repoFile(t, "README.md"), version) {
		t.Errorf("README.md never mentions %s", version)
	}
}
