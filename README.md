# terraform-provider-spin

The Terraform provider for Spinbox: it resolves a spin release, or a channel, to the Spin OS images
an installation boots and the builds a machine of it may prove it booted - each verified with the
release's signatures before Terraform sees it.

```hcl
terraform {
  required_providers {
    spin = { source = "spin-stack/spin" }
  }
}

data "spin_release" "this" {
  version = "edge" # or "stable", or a release: "v20261117.01"
}

# data.spin_release.this.images["runner"]["us-west-2"], .builds["control-plane"], .revoked
```

The catalog is spin-stack/spin-terraform-aws's `catalog` branch, written by spin-stack/ami's
release, revoke and promote workflows. Nothing in it is believed for where it is: a build only when
its statement is signed by ami's release workflow and says its PCRs, a revocation and a channel
only as statements signed by theirs (go-tools' `catalog`), under Sigstore's root as go-tools pins it.
A read that fails any of that fails the plan.
