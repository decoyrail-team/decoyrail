# Policy integrity demo: a hand edit to policy.toml never loads on its own —
# the proxy fails closed until a human reviews the diff and blesses it with
# `decoyrail policy sign`. Runs fully offline, no upstream needed.
# Regenerate with scripts/render-demos.sh (run from the repo root).

# Frame matches decoyrail.com (paper-and-ink theme), overriding the preset's
# purple margin and rounded corners.
Set MarginFill "#171914"
Set BorderRadius 0

# Invisible setup: fresh throwaway state and one CLI policy write so a
# trusted policy exists to tamper with. A fixed home (not mktemp) so the
# path in the proxy's refusal error reads cleanly on screen.
Hide
Type `export PATH="$PWD/target/release:$PATH"; export DECOYRAIL_HOME="/tmp/decoyrail-demo"; rm -rf "$DECOYRAIL_HOME"; unset SSL_CERT_FILE HTTP_PROXY HTTPS_PROXY http_proxy https_proxy ALL_PROXY all_proxy NO_PROXY no_proxy; for v in $(env | cut -d= -f1 | grep -iE 'api_key|token|secret|password'); do unset "$v"; done; decoyrail policy add github-api --host api.github.com --action allow >/dev/null; clear`
Enter
Sleep 4s
Show

Type `printf '\n[[rule]]\nname = "internal-git"\nhosts = ["git.corp.internal"]\naction = "allow"\n' >> "$(decoyrail policy path)"`
Sleep 1s
Enter
Sleep 1s

Type "decoyrail policy ls"
Sleep 1s
Enter
Sleep 5s

Type "decoyrail proxy"
Sleep 1s
Enter
Sleep 5s

Type "decoyrail policy sign"
Sleep 1s
Enter
Sleep 6s
Type "y"
Sleep 1s
Enter
Sleep 3s

Type "decoyrail policy ls"
Sleep 1s
Enter
Sleep 5s

# Invisible teardown so nothing outlives the recording.
Hide
Type `rm -rf "$DECOYRAIL_HOME"`
Enter
Sleep 1s
