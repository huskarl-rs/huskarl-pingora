#!/usr/bin/env bash
# Prime a bolero target's live corpus from the committed seeds, then fuzz it.
#
# The live corpus (src/__fuzz__/) is gitignored and may be cold (fresh checkout) or
# cache-evicted, so we always copy the committed seeds in first to start warm. Used by
# both `mise run fuzz` and the CI discovery job so local and CI prime identically.
#
#   scripts/fuzz.sh <full::target::name> [extra cargo-bolero args, e.g. -T 600s]
set -euo pipefail

target="${1:?usage: scripts/fuzz.sh <full::target::name> [extra cargo-bolero args]}"
shift

# Run from the repo root regardless of caller cwd.
cd "$(dirname "$0")/.."

# bolero names its corpus dir after the target with `::` -> `__`.
dir=$(printf '%s' "$target" | sed 's/::/__/g')
mkdir -p "src/__fuzz__/$dir/corpus"
if [ -d "fuzz-corpus/$dir" ]; then
  cp -f "fuzz-corpus/$dir/"* "src/__fuzz__/$dir/corpus/" 2>/dev/null || true
fi

exec cargo +nightly bolero test "$target" --features resource "$@"
