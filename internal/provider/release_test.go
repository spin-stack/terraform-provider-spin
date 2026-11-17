package provider

import (
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"net/http"
	"net/http/httptest"

	"os/exec"
	"regexp"
	"strings"
	"testing"

	"github.com/hashicorp/terraform-plugin-framework/providerserver"
	"github.com/hashicorp/terraform-plugin-go/tfprotov6"
	"github.com/hashicorp/terraform-plugin-testing/helper/resource"
	"github.com/hashicorp/terraform-plugin-testing/tfversion"
	"github.com/spin-stack/go-tools/catalog"

	"github.com/spin-stack/terraform-provider-spin/internal/resolve"
)

// sums is a test's signer: a bundle is "signed:<sha256 hex>" of the bytes it signs.
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

const rel = "v20261117.01"

func testCatalog(t *testing.T) *httptest.Server {
	t.Helper()
	r := catalog.Release{Format: catalog.Format, Release: rel, Roles: map[string]catalog.Role{}}
	for i, role := range catalog.Roles {
		var s catalog.Statement
		s.FormatVersion, s.Release, s.Role = 1, rel, role
		p := strings.Repeat(string(rune('a'+i)), 96)
		s.Measurements.PCR4, s.Measurements.PCR7, s.Measurements.PCR12 = p, p, p
		signed := sign(t, s)
		r.Roles[role] = catalog.Role{Builds: map[string]catalog.Build{"r1": {
			PCR4: p, PCR7: p, PCR12: p, Statement: signed.Statement, Bundle: signed.Bundle,
			Images: map[string]string{"us-west-2": "ami-0aaaaaaaaaaaaaaa" + string(rune('a'+i))},
		}}}
	}
	files := map[string]any{
		catalog.ReleasePath(rel):    r,
		catalog.ChannelPath("edge"): catalog.Channel{Format: catalog.Format, Signed: sign(t, catalog.ChannelStatement{FormatVersion: 1, Channel: "edge", Release: rel})},
	}
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, req *http.Request) {
		f, ok := files[strings.TrimPrefix(req.URL.Path, "/")]
		if !ok {
			http.NotFound(w, req)
			return
		}
		_ = json.NewEncoder(w).Encode(f)
	}))
	t.Cleanup(srv.Close)
	return srv
}

// factories serve the provider with the test's signer in place of the release workflow's.
func factories(srv *httptest.Server) map[string]func() (tfprotov6.ProviderServer, error) {
	return map[string]func() (tfprotov6.ProviderServer, error){
		"spin": providerserver.NewProtocol6WithError(&Spin{version: "test", signers: func() (resolve.Catalog, error) {
			return resolve.Catalog{URL: "unused", Client: srv.Client(), Check: sums{}}, nil
		}}),
	}
}

// tofu is OpenTofu, which runs the configuration as an installation would; a host without it skips.
func tofu(t *testing.T) {
	t.Helper()
	bin, err := exec.LookPath("tofu")
	if err != nil {
		t.Skip("no tofu on PATH")
	}
	t.Setenv("TF_ACC_TERRAFORM_PATH", bin)
	t.Setenv("TF_ACC_PROVIDER_NAMESPACE", "hashicorp")
	t.Setenv("TF_ACC_PROVIDER_HOST", "registry.opentofu.org")
}

// An installation names a channel and is answered its release: the images, the newest revision and
// the trusted builds of each role, as Terraform reads them.
func TestAnInstallationNamesAChannel(t *testing.T) {
	tofu(t)
	srv := testCatalog(t)
	resource.UnitTest(t, resource.TestCase{
		ProtoV6ProviderFactories: factories(srv),
		TerraformVersionChecks:   []tfversion.TerraformVersionCheck{tfversion.SkipBelow(tfversion.Version1_0_0)},
		Steps: []resource.TestStep{{
			Config: `
provider "spin" { catalog_url = "` + srv.URL + `" }
data "spin_release" "this" { version = "edge" }
output "runner" { value = data.spin_release.this.images["runner"]["us-west-2"] }`,
			Check: resource.ComposeAggregateTestCheckFunc(
				resource.TestCheckResourceAttr("data.spin_release.this", "release", rel),
				resource.TestCheckResourceAttr("data.spin_release.this", "revisions.control-plane", "r1"),
				resource.TestCheckResourceAttr("data.spin_release.this", "builds.runner.#", "1"),
				resource.TestCheckResourceAttr("data.spin_release.this", "builds.runner.0.pcr4", strings.Repeat("c", 96)),
				resource.TestCheckResourceAttr("data.spin_release.this", "revoked.%", "0"),
				resource.TestCheckOutput("runner", "ami-0aaaaaaaaaaaaaaac"),
			),
		}},
	})
}

// A release the catalog cannot answer as signed fails the plan, and says which.
func TestAReleaseNotPublishedFailsThePlan(t *testing.T) {
	tofu(t)
	srv := testCatalog(t)
	resource.UnitTest(t, resource.TestCase{
		ProtoV6ProviderFactories: factories(srv),
		Steps: []resource.TestStep{{
			Config: `
provider "spin" { catalog_url = "` + srv.URL + `" }
data "spin_release" "this" { version = "v20261001.01" }`,
			ExpectError: regexp.MustCompile(`no such file`),
		}},
	})
}

// The provider as it runs reads the catalog's branch, held to the release workflows' signatures.
func TestTheProviderReadsTheCatalogAsItRuns(t *testing.T) {
	c, err := defaultCatalog()
	if err != nil {
		t.Fatal(err)
	}
	if c.URL != catalog.BranchURL || c.Check == nil || c.Client == nil {
		t.Fatalf("catalog = %+v", c)
	}
}
