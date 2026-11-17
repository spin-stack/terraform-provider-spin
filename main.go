// Command terraform-provider-spin is the Spinbox Terraform provider, as Terraform runs it.
package main

import (
	"context"
	"flag"
	"log"

	"github.com/hashicorp/terraform-plugin-framework/providerserver"

	"github.com/spin-stack/terraform-provider-spin/internal/provider"
)

// version is the release's, set by its build.
var version = "dev"

func main() {
	var debug bool
	flag.BoolVar(&debug, "debug", false, "serve for a debugger, as Terraform's provider development describes")
	flag.Parse()
	if err := providerserver.Serve(context.Background(), provider.New(version), providerserver.ServeOpts{
		Address: "registry.terraform.io/spin-stack/spin",
		Debug:   debug,
	}); err != nil {
		log.Fatal(err)
	}
}
