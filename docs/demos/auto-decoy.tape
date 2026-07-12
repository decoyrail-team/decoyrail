# Auto-decoying demo: `decoyrail run` replaces credential env vars with
# decoys before the child process ever sees them.
# Regenerate with scripts/render-demos.sh (run from the repo root).

# Invisible setup: fresh throwaway state, no inherited proxies or real keys,
# and one warmup run so CA generation doesn't stall the visible part.
Hide
Type `export PATH="$PWD/target/release:$PATH"; export DECOYRAIL_HOME="$(mktemp -d)"; unset SSL_CERT_FILE HTTP_PROXY HTTPS_PROXY http_proxy https_proxy ALL_PROXY all_proxy NO_PROXY no_proxy; for v in $(env | cut -d= -f1 | grep -iE 'api_key|token|secret|password'); do unset "$v"; done; decoyrail run -- true >/dev/null 2>&1; clear`
Enter
Sleep 4s
Show

Type "AWS_ACCESS_KEY_ID=AKIAIOSFODNN7EXAMPLE AWS_SECRET_ACCESS_KEY=wJalrXUtnFEMI/K7MDENG/bPxRfiCYEXAMPLEKEY decoyrail run -- bash -c 'env | grep AWS'"
Sleep 1s
Enter
Sleep 6s
