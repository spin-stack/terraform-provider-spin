#!/usr/bin/env bash
# THIRD_PARTY_NOTICES for a release's archives: the licence of every module the provider links, and
# the NOTICE an Apache module ships beside it, as each ships them - what the MIT, BSD and Apache
# licences ask to go with every copy, a binary one too - and Go's own, which every binary carries.
# go-licenses (go-tools' pin) says which modules and where their licences are.
set -euo pipefail
cd "$(dirname "$0")/.."
out=${1:?the file to write}
mkdir -p "$(dirname "${out}")"
{
  echo "The licence and copyright notices of the third-party software compiled into"
  echo "terraform-provider-spin, as each ships them. The provider itself is under the Apache"
  echo "License 2.0 (LICENSE)."
  echo
  go run github.com/google/go-licenses/v2@v2.0.1 report --template hack/notices.tmpl \
    --ignore github.com/spin-stack/terraform-provider-spin . 2> /dev/null |
    sort -u | while IFS=$'\t' read -r name version license file; do
      # A licence go-licenses could not classify has no path it names: the module's own is the one.
      if [ ! -f "${file}" ]; then
        file=$(find "$(go list -f '{{.Module.Dir}}' "${name}")" -maxdepth 1 -iname 'LICEN[CS]E*' | head -n 1)
      fi
      if [ -z "${file}" ]; then
        echo "notices: ${name} ships no licence" >&2
        exit 1
      fi
      printf '\n================================================================\n%s %s (%s)\n\n' "${name}" "${version}" "${license}"
      cat "${file}"
      dir=$(dirname "${file}")
      if [ -f "${dir}/NOTICE" ]; then printf '\n'; cat "${dir}/NOTICE"; fi
    done
  printf '\n================================================================\nGo %s (BSD-3-Clause)\n\n' "$(go env GOVERSION)"
  cat "$(go env GOROOT)/LICENSE"
  if [ -f "$(go env GOROOT)/PATENTS" ]; then printf '\n'; cat "$(go env GOROOT)/PATENTS"; fi
} > "${out}"
