// Package provider is the Terraform provider: the spin_release data source, over package resolve.
package provider

import (
	"context"
	"net/http"
	"time"

	"github.com/hashicorp/terraform-plugin-framework/datasource"
	"github.com/hashicorp/terraform-plugin-framework/provider"
	"github.com/hashicorp/terraform-plugin-framework/provider/schema"
	"github.com/hashicorp/terraform-plugin-framework/resource"
	"github.com/hashicorp/terraform-plugin-framework/types"
	"github.com/spin-stack/go-tools/catalog"

	"github.com/spin-stack/terraform-provider-spin/internal/resolve"
)

// Spin is the provider.
type Spin struct {
	version string
	// signers is what the catalog is held to: go-tools' catalog.Signers, a test's own.
	signers func() (resolve.Catalog, error)
}

// New is the provider at version, as main serves it.
func New(version string) func() provider.Provider {
	return func() provider.Provider {
		return &Spin{version: version, signers: defaultCatalog}
	}
}

func defaultCatalog() (resolve.Catalog, error) {
	policy, err := catalog.Signers()
	if err != nil {
		return resolve.Catalog{}, err
	}
	return resolve.Catalog{URL: catalog.BranchURL, Client: &http.Client{Timeout: 2 * time.Minute}, Check: policy}, nil
}

type config struct {
	CatalogURL types.String `tfsdk:"catalog_url"`
}

// Metadata names the provider: data sources are spin_<name>.
func (p *Spin) Metadata(_ context.Context, _ provider.MetadataRequest, resp *provider.MetadataResponse) {
	resp.TypeName = "spin"
	resp.Version = p.version
}

// Schema is the provider's one setting: where the catalog is read, when it is a mirror.
func (p *Spin) Schema(_ context.Context, _ provider.SchemaRequest, resp *provider.SchemaResponse) {
	resp.Schema = schema.Schema{
		Description: "Resolves a spin release, or a channel, to the Spin OS images an installation boots, verified with the release's signatures.",
		Attributes: map[string]schema.Attribute{
			"catalog_url": schema.StringAttribute{
				Optional: true,
				Description: "Where the image catalog is read: spin-stack/spin-terraform-aws's catalog branch, " + catalog.BranchURL +
					", unless a mirror of it is named. What is read is believed only as its release signed it, wherever it comes from.",
			},
		},
	}
}

// Configure hands the data sources the catalog, as configured.
func (p *Spin) Configure(ctx context.Context, req provider.ConfigureRequest, resp *provider.ConfigureResponse) {
	var cfg config
	resp.Diagnostics.Append(req.Config.Get(ctx, &cfg)...)
	if resp.Diagnostics.HasError() {
		return
	}
	c, err := p.signers()
	if err != nil {
		resp.Diagnostics.AddError("The catalog's signers could not be read", err.Error())
		return
	}
	if u := cfg.CatalogURL.ValueString(); u != "" {
		c.URL = u
	}
	resp.DataSourceData = c
}

// DataSources is spin_release.
func (p *Spin) DataSources(context.Context) []func() datasource.DataSource {
	return []func() datasource.DataSource{newReleaseDataSource}
}

// Resources is none: the provider reads, it makes nothing.
func (p *Spin) Resources(context.Context) []func() resource.Resource { return nil }
