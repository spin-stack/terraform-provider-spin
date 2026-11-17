package provider

import (
	"context"
	"fmt"

	"github.com/hashicorp/terraform-plugin-framework/attr"
	"github.com/hashicorp/terraform-plugin-framework/datasource"
	"github.com/hashicorp/terraform-plugin-framework/datasource/schema"
	"github.com/hashicorp/terraform-plugin-framework/diag"
	"github.com/hashicorp/terraform-plugin-framework/path"
	"github.com/hashicorp/terraform-plugin-framework/types"

	"github.com/spin-stack/terraform-provider-spin/internal/resolve"
)

type releaseDataSource struct {
	catalog resolve.Catalog
}

func newReleaseDataSource() datasource.DataSource { return &releaseDataSource{} }

// buildType is one trusted build as the modules hand it to the control plane: every value a string.
var buildType = types.ObjectType{AttrTypes: map[string]attr.Type{
	"revision": types.StringType, "pcr4": types.StringType, "pcr7": types.StringType, "pcr12": types.StringType,
	"statement": types.StringType, "bundle": types.StringType,
}}

type releaseModel struct {
	Version   types.String `tfsdk:"version"`
	Release   types.String `tfsdk:"release"`
	Images    types.Map    `tfsdk:"images"`
	Revisions types.Map    `tfsdk:"revisions"`
	Builds    types.Map    `tfsdk:"builds"`
	Revoked   types.Map    `tfsdk:"revoked"`
}

func (d *releaseDataSource) Metadata(_ context.Context, req datasource.MetadataRequest, resp *datasource.MetadataResponse) {
	resp.TypeName = req.ProviderTypeName + "_release"
}

func (d *releaseDataSource) Schema(_ context.Context, _ datasource.SchemaRequest, resp *datasource.SchemaResponse) {
	resp.Schema = schema.Schema{
		Description: "A spin release, or the release a channel names, as the image catalog has it and its release signed it: " +
			"each role's image by region, and the builds a machine of each role may prove it booted. " +
			"Nothing the release did not sign is answered; the read fails instead.",
		Attributes: map[string]schema.Attribute{
			"version": schema.StringAttribute{
				Required:    true,
				Description: "A release, v<YYYYMMDD>.<N>, or a channel: edge (every release once its images are published and checked) or stable (a release a person promoted). A channel is read at every plan, so the release it names may move between two plans.",
			},
			"release": schema.StringAttribute{
				Computed:    true,
				Description: "The release: the one named, or the one the channel names now.",
			},
			"images": schema.MapAttribute{
				Computed:    true,
				ElementType: types.MapType{ElemType: types.StringType},
				Description: "Each role's image (control-plane, runner, proxy) in each region it is published in: its newest build's.",
			},
			"revisions": schema.MapAttribute{
				Computed:    true,
				ElementType: types.StringType,
				Description: "Each role's newest build, r<N>: the one images names.",
			},
			"builds": schema.MapAttribute{
				Computed:    true,
				ElementType: types.ListType{ElemType: buildType},
				Description: "Each role's builds not revoked, oldest first, as a machine of the role may prove it booted: pcr4, pcr7 and pcr12, and the statement of them its release signed with the bundle that signs it, both base64.",
			},
			"revoked": schema.MapAttribute{
				Computed:    true,
				ElementType: types.StringType,
				Description: "For each role whose newest build is revoked, why: an installation is not to install the release while it is.",
			},
		},
	}
}

func (d *releaseDataSource) Configure(_ context.Context, req datasource.ConfigureRequest, resp *datasource.ConfigureResponse) {
	if req.ProviderData == nil {
		return // the framework asks before the provider is configured
	}
	c, ok := req.ProviderData.(resolve.Catalog)
	if !ok {
		resp.Diagnostics.AddError("The provider handed spin_release no catalog", fmt.Sprintf("it handed %T", req.ProviderData))
		return
	}
	d.catalog = c
}

func (d *releaseDataSource) Read(ctx context.Context, req datasource.ReadRequest, resp *datasource.ReadResponse) {
	var m releaseModel
	resp.Diagnostics.Append(req.Config.Get(ctx, &m)...)
	if resp.Diagnostics.HasError() {
		return
	}
	r, err := d.catalog.Resolve(ctx, m.Version.ValueString())
	if err != nil {
		resp.Diagnostics.AddAttributeError(pathVersion, "The release could not be resolved", err.Error())
		return
	}
	model, diags := modelOf(m.Version, r)
	resp.Diagnostics.Append(diags...)
	if resp.Diagnostics.HasError() {
		return
	}
	resp.Diagnostics.Append(resp.State.Set(ctx, &model)...)
}

// modelOf is r as the data source answers it.
func modelOf(version types.String, r resolve.Release) (releaseModel, diag.Diagnostics) {
	var diags diag.Diagnostics
	images, revisions, builds, revoked := map[string]attr.Value{}, map[string]attr.Value{}, map[string]attr.Value{}, map[string]attr.Value{}
	for name, role := range r.Roles {
		byRegion := map[string]attr.Value{}
		for region, image := range role.Images {
			byRegion[region] = types.StringValue(image)
		}
		v, d := types.MapValue(types.StringType, byRegion)
		diags.Append(d...)
		images[name] = v
		revisions[name] = types.StringValue(role.Revision)
		var list []attr.Value
		for _, b := range role.Builds {
			o, d := types.ObjectValue(buildType.AttrTypes, map[string]attr.Value{
				"revision": types.StringValue(b.Revision), "pcr4": types.StringValue(b.PCR4), "pcr7": types.StringValue(b.PCR7),
				"pcr12": types.StringValue(b.PCR12), "statement": types.StringValue(b.Statement), "bundle": types.StringValue(b.Bundle),
			})
			diags.Append(d...)
			list = append(list, o)
		}
		l, d := types.ListValue(buildType, list)
		diags.Append(d...)
		builds[name] = l
		if role.Revoked != "" {
			revoked[name] = types.StringValue(role.Revoked)
		}
	}
	m := releaseModel{Version: version, Release: types.StringValue(r.Version)}
	var d diag.Diagnostics
	m.Images, d = types.MapValue(types.MapType{ElemType: types.StringType}, images)
	diags.Append(d...)
	m.Revisions, d = types.MapValue(types.StringType, revisions)
	diags.Append(d...)
	m.Builds, d = types.MapValue(types.ListType{ElemType: buildType}, builds)
	diags.Append(d...)
	m.Revoked, d = types.MapValue(types.StringType, revoked)
	diags.Append(d...)
	return m, diags
}

var pathVersion = path.Root("version")
