// Package resolve turns what an installation names - a spin release, or a channel - into the
// images it boots and the builds a machine of it may prove it booted, read from the Spin OS image
// catalog and believed only as its release's signatures say (go-tools' catalog). The provider's
// data source is this and nothing more, so what an installation is told is decided here, and
// tested here, with no Terraform in the way.
package resolve

import (
	"context"
	"encoding/base64"
	"errors"
	"fmt"
	"io"
	"net/http"
	"strings"
	"time"

	"github.com/spin-stack/go-tools/catalog"
	"github.com/spin-stack/go-tools/sigcheck"
)

// maxFile is more than any release's file: a catalog that answers more is not read whole.
const maxFile = 16 << 20

// Release is a release as an installation is told it.
type Release struct {
	// Version is the release: what was named, or what the channel named.
	Version string
	// Roles is each role's.
	Roles map[string]Role
}

// Role is one role of a Release.
type Role struct {
	// Images is the image the role boots in each region: its newest build's.
	Images map[string]string
	// Revision is that build's, r<N>.
	Revision string
	// Builds is every build not revoked, oldest first: what a machine of the role may prove it
	// booted, the control plane's key policy and a host's join held to it.
	Builds []Build
	// Revoked, when set, is why the newest build is not to be run.
	Revoked string
}

// Build is one trusted build, as the modules hand it to the control plane: every value a string,
// the statement and its bundle in base64.
type Build struct {
	Revision, PCR4, PCR7, PCR12, Statement, Bundle string
}

// Catalog is where the catalog is read and what its signatures are held to.
type Catalog struct {
	// URL is the catalog's root: catalog.BranchURL, or a mirror of it.
	URL    string
	Client *http.Client
	Check  sigcheck.Checker
}

// Resolve is what version - a release v<YYYYMMDD>.<N>, or a channel's name - is in the catalog.
func (c Catalog) Resolve(ctx context.Context, version string) (Release, error) {
	release := version
	switch {
	case catalog.IsRelease(version):
	case catalog.IsChannel(version):
		raw, err := c.get(ctx, catalog.ChannelPath(version))
		if err != nil {
			return Release{}, err
		}
		if release, err = catalog.VerifyChannel(raw, version, c.Check); err != nil {
			return Release{}, err
		}
	default:
		return Release{}, fmt.Errorf("%q is neither a release, v<YYYYMMDD>.<N>, nor a channel's name", version)
	}
	raw, err := c.get(ctx, catalog.ReleasePath(release))
	if err != nil {
		return Release{}, err
	}
	v, err := catalog.Verify(raw, release, c.Check)
	if err != nil {
		return Release{}, err
	}
	out := Release{Version: release, Roles: map[string]Role{}}
	for name, r := range v.Roles {
		role := Role{Images: r.Newest.Images, Revision: r.Newest.Revision, Revoked: r.Revoked}
		for _, b := range r.Trusted {
			role.Builds = append(role.Builds, Build{
				Revision: b.Revision, PCR4: b.PCR4, PCR7: b.PCR7, PCR12: b.PCR12,
				Statement: base64.StdEncoding.EncodeToString(b.Statement),
				Bundle:    base64.StdEncoding.EncodeToString(b.Bundle),
			})
		}
		out.Roles[name] = role
	}
	return out, nil
}

// ErrNotPublished is a file the catalog does not have: a release not published, a channel never
// moved.
var ErrNotPublished = errors.New("the catalog has no such file")

func (c Catalog) get(ctx context.Context, path string) ([]byte, error) {
	url := strings.TrimSuffix(c.URL, "/") + "/" + path
	ctx, cancel := context.WithTimeout(ctx, time.Minute)
	defer cancel()
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, url, nil)
	if err != nil {
		return nil, err
	}
	resp, err := c.Client.Do(req)
	if err != nil {
		return nil, fmt.Errorf("reading the catalog: %w", err)
	}
	defer func() { _ = resp.Body.Close() }() // a read body; nothing to say of its close
	switch {
	case resp.StatusCode == http.StatusNotFound:
		return nil, fmt.Errorf("%w: %s", ErrNotPublished, url)
	case resp.StatusCode != http.StatusOK:
		return nil, fmt.Errorf("reading the catalog: %s answered %s", url, resp.Status)
	}
	raw, err := io.ReadAll(io.LimitReader(resp.Body, maxFile+1))
	if err != nil {
		return nil, fmt.Errorf("reading the catalog: %s: %w", url, err)
	}
	if len(raw) > maxFile {
		return nil, fmt.Errorf("reading the catalog: %s is larger than any release's file", url)
	}
	return raw, nil
}
