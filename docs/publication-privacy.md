# Publication privacy checks

`scripts/check_publication.py` checks tracked source files and, when requested,
wheel/sdist contents. Its explicit metadata mode also checks every commit newly
reachable from `HEAD` after a reviewed ancestor, including merged side-branch
commits. It reads complete raw author/committer headers and messages rather than
only subjects. Existing public history is excluded, not rewritten or certified.

```sh
python scripts/check_publication.py --base-revision "$REVIEWED_BASE_SHA"
```

Use an existing interpreter for concurrent review; do not synchronize another
task's installed-artifact environment. The base must resolve to a commit and be
an ancestor of the pinned HEAD. Missing/shallow history, an invalid base, malformed
commit encoding or limits fail the metadata check. Fetch the reviewed objects
deliberately before checking; the scanner does not fetch or access a remote.
Without `--base-revision`, `scanned_commits` is `null`: no metadata check occurred.
The base-selection decision is an operator/CI trust input, not something the
scanner can prove from a revision string. Selecting HEAD checks an empty range.

## Email identities and private policy

The bounded metadata policy permits reserved `.invalid` addresses and the exact
GitHub `noreply.github.com` and `users.noreply.github.com` domains. This is an
admission policy; the exact GitHub system committer (`noreply` at `github.com`)
is also admitted, without allowing other addresses on that domain. This is not
proof of account ownership, signature validity or anonymity.
Author/committer names and free-form text can still identify people. Email
admission also applies to detected addresses in messages, including coauthor
trailers; it is not a complete RFC email-address parser.

An operator may explicitly inherit the exact author/committer email addresses
from the resolved base commit itself:

```sh
python scripts/check_publication.py --base-revision "$REVIEWED_BASE_SHA" --allow-base-identities
```

Use that option only when the base is independently reviewed public history and
reusing those identities is intentional for this repository/change. It admits
neither all historical addresses nor a general future identity preference. Exact
matching is required; a changed address is not inherited. New personal email
addresses require a separate deliberate policy decision; they are not silently
admitted because a contributor or connector supplied them.

Maintainers may supply `OW_PRIVATE_DENYLIST` as an external private UTF-8 JSON
array of exact strings. Matching is case-insensitive over the original text and
overrides email admission, including inherited base identities. Keep this file
outside Git and public CI; do not upload it in support logs or artifacts. Public
CI uses generic pattern/email checks, never the private catalogue. The private
check remains a separately required local publication responsibility.
The final path component must be a regular file, opened without following a
symlink and with nonblocking admission. FIFOs, devices, directories and oversized
files fail before content reading. The opened descriptor is closed on rejection
and success; parent-directory custody remains the operator's responsibility.

Findings contain categories and commit object IDs, not matched names, addresses,
messages, Git stderr or the private-policy path/content. Git failures and invalid
private-policy files produce fixed failure categories. Existing source/archive
findings retain their ordinary relative-path diagnostics. Successful output is
not evidence that arbitrary text is anonymous or that every secret format is
recognized.

## Bounds and evidence

Metadata scanning admits at most 1000 new commits, 256 KiB per commit and 16 MiB
of total new raw metadata. Each native Git invocation has a ten-second timeout;
this is not a ten-second whole-command guarantee. Object size is checked before
reading raw content. Commit objects must decode as UTF-8 and contain no NUL byte;
unsupported objects fail instead of silently hiding message suffixes. The
external policy is bounded to 1 MiB, 10000 strings and 4096 characters per string.

Synthetic native-Git tests exercise new versus excluded historical metadata,
merged side commits, author/committer names and emails, full messages/trailers,
base-identity opt-in and exactness, denylist precedence, malformed commits,
invalid/nonancestor revisions, limits and redacted CLI failures. Those tests do
not establish a review of this repository's actual private identifiers.

This increment does not scan annotated tag text, Git notes, PR bodies, remote
settings or all prior reachable history. It neither removes already published
metadata nor authorizes history rewriting. Wider history/identity remediation
requires its own reviewed scope and trusted inputs.

Foundation PR CI explicitly selects the PR base SHA and fetches complete history.
Push CI uses the event's previous SHA; manual runs select `HEAD^`. A manual check
therefore covers only that selected range, not all unpublished branch history,
and cannot trigger the main-push signing job.
