package resolve

import (
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"errors"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/spin-stack/go-tools/catalog"
)

// sums is a test's signer: a bundle is "signed:<sha256 hex>" of the bytes it signs, and the
// checker takes exactly that.
type sums struct{}

func (sums) Check(bundle, sum []byte) error {
	if string(bundle) != "signed:"+hex.EncodeToString(sum) {
		return errors.New("not signed")
	}
	return nil
}

func sign(t *testing.T, v any) catalog.Signed {
	t.Helper()
	raw, err := json.Marshal(v)
	if err != nil {
		t.Fatal(err)
	}
	s := sha256.Sum256(raw)
	return catalog.Signed{Statement: raw, Bundle: []byte("signed:" + hex.EncodeToString(s[:]))}
}

func pcr(c byte) string { return strings.Repeat(string(c), 96) }

func build(t *testing.T, release, role string, c byte, images map[string]string) catalog.Build {
	t.Helper()
	var s catalog.Statement
	s.FormatVersion, s.Release, s.Role = 1, release, role
	s.Measurements.PCR4, s.Measurements.PCR7, s.Measurements.PCR12 = pcr(c), pcr('7'), pcr('0')
	signed := sign(t, s)
	return catalog.Build{PCR4: pcr(c), PCR7: pcr('7'), PCR12: pcr('0'), Statement: signed.Statement, Bundle: signed.Bundle, Images: images}
}

const rel = "v20261117.01"

// published is a release with each role built once and the runner twice, its first build revoked.
func published(t *testing.T) catalog.Release {
	t.Helper()
	r := catalog.Release{Format: catalog.Format, Release: rel, Roles: map[string]catalog.Role{}}
	for _, role := range catalog.Roles {
		r.Roles[role] = catalog.Role{Builds: map[string]catalog.Build{
			"r1": build(t, rel, role, 'a', map[string]string{"us-west-2": "ami-0aaaaaaaaaaaaaaaa"}),
		}}
	}
	runner := r.Roles["runner"]
	runner.Builds["r2"] = build(t, rel, "runner", 'b', map[string]string{"us-west-2": "ami-0bbbbbbbbbbbbbbbb", "us-east-1": "ami-0cccccccccccccccc"})
	runner.Revocations = map[string]catalog.Signed{"r1": sign(t, catalog.Revocation{FormatVersion: 1, Release: rel, Role: "runner", Revision: "r1", Reason: "CVE-2026-1"})}
	r.Roles["runner"] = runner
	return r
}

// served is a catalog of files by path, and the paths asked.
func served(t *testing.T, files map[string]any) (Catalog, *[]string) {
	t.Helper()
	var asked []string
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		asked = append(asked, r.URL.Path)
		f, ok := files[strings.TrimPrefix(r.URL.Path, "/catalog/")]
		if !ok {
			http.NotFound(w, r)
			return
		}
		if raw, isRaw := f.([]byte); isRaw {
			_, _ = w.Write(raw)
			return
		}
		_ = json.NewEncoder(w).Encode(f)
	}))
	t.Cleanup(srv.Close)
	return Catalog{URL: srv.URL + "/catalog/", Client: srv.Client(), Check: sums{}}, &asked
}

// A release named is its newest builds' images and every build not revoked, each with its
// statement as the control plane is handed it.
func TestAReleaseIsItsImagesAndTrustedBuilds(t *testing.T) {
	c, _ := served(t, map[string]any{catalog.ReleasePath(rel): published(t)})
	got, err := c.Resolve(t.Context(), rel)
	if err != nil {
		t.Fatal(err)
	}
	runner := got.Roles["runner"]
	if got.Version != rel || runner.Revision != "r2" || runner.Images["us-east-1"] != "ami-0cccccccccccccccc" || runner.Revoked != "" {
		t.Fatalf("runner = %+v", runner)
	}
	if len(runner.Builds) != 1 || runner.Builds[0].Revision != "r2" || runner.Builds[0].PCR4 != pcr('b') {
		t.Fatalf("runner's builds = %+v: the revoked r1 is not trusted", runner.Builds)
	}
	statement, err := base64.StdEncoding.DecodeString(runner.Builds[0].Statement)
	if err != nil || !strings.Contains(string(statement), `"role":"runner"`) {
		t.Fatalf("statement = %s, %v", statement, err)
	}
	if bundle, err := base64.StdEncoding.DecodeString(runner.Builds[0].Bundle); err != nil || !strings.HasPrefix(string(bundle), "signed:") {
		t.Fatalf("bundle = %s, %v", bundle, err)
	}
	if len(got.Roles) != len(catalog.Roles) {
		t.Fatalf("roles = %v", got.Roles)
	}
}

// A release whose newest build of a role is revoked says why, for the module to refuse it.
func TestARevokedNewestBuildIsSaid(t *testing.T) {
	r := published(t)
	proxy := r.Roles["proxy"]
	proxy.Revocations = map[string]catalog.Signed{"r1": sign(t, catalog.Revocation{FormatVersion: 1, Release: rel, Role: "proxy", Revision: "r1", Reason: "a wrong PCR"})}
	r.Roles["proxy"] = proxy
	c, _ := served(t, map[string]any{catalog.ReleasePath(rel): r})
	got, err := c.Resolve(t.Context(), rel)
	if err != nil {
		t.Fatal(err)
	}
	if got.Roles["proxy"].Revoked != "a wrong PCR" || len(got.Roles["proxy"].Builds) != 0 {
		t.Fatalf("proxy = %+v", got.Roles["proxy"])
	}
}

// A channel is the release its signed statement names, read from the catalog after it.
func TestAChannelIsTheReleaseItNames(t *testing.T) {
	c, asked := served(t, map[string]any{
		catalog.ChannelPath("edge"): catalog.Channel{Format: catalog.Format, Signed: sign(t, catalog.ChannelStatement{FormatVersion: 1, Channel: "edge", Release: rel})},
		catalog.ReleasePath(rel):    published(t),
	})
	got, err := c.Resolve(t.Context(), "edge")
	if err != nil || got.Version != rel {
		t.Fatalf("edge is %q, %v", got.Version, err)
	}
	if strings.Join(*asked, " ") != "/catalog/channels/edge.json /catalog/releases/v20261117.01.json" {
		t.Fatalf("asked %v", *asked)
	}
}

// What the catalog cannot answer, or answers unsigned, is an error, never a release.
func TestWhatIsNotBelievedIsRefused(t *testing.T) {
	forged := published(t)
	b := forged.Roles["control-plane"].Builds["r1"]
	b.PCR4 = pcr('f')
	forged.Roles["control-plane"].Builds["r1"] = b
	for name, tc := range map[string]struct {
		files   map[string]any
		version string
		says    string
	}{
		"not a name":                     {version: "Latest!", says: "neither a release"},
		"a release not there":            {files: map[string]any{}, version: rel, says: "no such file"},
		"a channel not there":            {files: map[string]any{}, version: "stable", says: "no such file"},
		"a PCR the release did not sign": {files: map[string]any{catalog.ReleasePath(rel): forged}, version: rel, says: "other PCRs"},
		"a channel not signed": {files: map[string]any{
			catalog.ChannelPath("edge"): catalog.Channel{Format: catalog.Format, Signed: catalog.Signed{Statement: []byte(`{}`), Bundle: []byte("forged")}},
			catalog.ReleasePath(rel):    published(t),
		}, version: "edge", says: "its signature"},
		"a channel naming a release not there": {files: map[string]any{
			catalog.ChannelPath("edge"): catalog.Channel{Format: catalog.Format, Signed: sign(t, catalog.ChannelStatement{FormatVersion: 1, Channel: "edge", Release: "v20261001.01"})},
		}, version: "edge", says: "no such file"},
		"too large": {files: map[string]any{catalog.ReleasePath(rel): make([]byte, maxFile+1)}, version: rel, says: "larger than any"},
	} {
		t.Run(name, func(t *testing.T) {
			c, _ := served(t, tc.files)
			if _, err := c.Resolve(t.Context(), tc.version); err == nil || !strings.Contains(err.Error(), tc.says) {
				t.Fatalf("err = %v, want one that says %q", err, tc.says)
			}
		})
	}
}

// A catalog that answers something other than the file or its absence is not read as either.
func TestACatalogThatFailsIsSaid(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		http.Error(w, "down", http.StatusBadGateway)
	}))
	t.Cleanup(srv.Close)
	c := Catalog{URL: srv.URL, Client: srv.Client(), Check: sums{}}
	if _, err := c.Resolve(t.Context(), rel); err == nil || !strings.Contains(err.Error(), "502") || errors.Is(err, ErrNotPublished) {
		t.Fatalf("err = %v", err)
	}
	srv.Close()
	if _, err := c.Resolve(t.Context(), rel); err == nil || !strings.Contains(err.Error(), "reading the catalog") {
		t.Fatalf("err = %v", err)
	}
	if _, err := (Catalog{URL: "http://\x00", Client: http.DefaultClient}).Resolve(t.Context(), rel); err == nil {
		t.Fatal("a URL that is none was read")
	}
}
