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

This increment does not automatically scan annotated tag text, Git notes, PR
bodies, remote settings or all prior reachable history. It neither removes already published
metadata nor authorizes history rewriting. Wider history/identity remediation
requires its own reviewed scope and trusted inputs.

Foundation PR CI explicitly selects the PR base SHA and fetches complete history.
Push CI uses the event's previous SHA; manual runs select `HEAD^`. A manual check
therefore covers only that selected range, not all unpublished branch history,
and cannot trigger the main-push signing job.

## Preflight planned public messages

Agent session/conversation links belong outside public Git metadata and PR
descriptions. A PR head can pass while a later merge message introduces new
metadata, as recorded in [the integration incident](testing/audit-remediation-2026-10-18.md).
Before creating a commit, PR or merge, scan its exact planned public text:

```sh
python scripts/check_publication.py --message-file "$PLANNED_MESSAGE_FILE"
```

The selected file must be a regular UTF-8 file of at most 256 KiB without NUL.
It is opened without following the final symlink and without blocking on special
files. Parent-directory custody and stability through publication remain the
operator's responsibility; the reader does not lock the selected file against
edits. Findings contain a fixed label and categories, never its path or content.
The external private denylist applies. Optional email trailers must use the
reserved public identities admitted by the metadata policy; base-identity
inheritance does not apply to this preflight. Public documentation URLs still
follow the existing host policy; this is not a ban on all reference links.

Pass an explicit reviewed subject and body when merging. Scan the title and body
together, then use those exact bytes for publication; scanner success does not
bind a later file edit or a server-generated message. Preserve custody of the
file through use. Recheck the resulting merge metadata and main-push CI.
Preflight does not replace the full commit-range scan or automatically intercept
GitHub UI edits. Existing public history remains unchanged, and a passing new
range does not clear an earlier finding.

PR #23 also introduced public upstream release-note URLs in merge `02685c13`
when GitHub copied its PR body. The [settings receipt](testing/merge-message-settings-2026-10-19.json)
records their host categories and the exact message digest without reproducing
the body. Main-push repository policy failed as intended. Merge and squash
defaults now select a blank body; explicit overrides and already queued
auto-merge messages still need review. This does not clear that historical
finding, permit new URL hosts or change the scanner.

## Generated assurance files

After producer verification, scan the exact supplementary and final receipt sets:

```sh
.venv/bin/python scripts/check_publication.py --evidence assurance --evidence build-evidence
```

Each selected directory must contain exactly its four supplementary files or its
two final receipt files. Reads are bounded, no-follow and nonblocking; unknown,
missing, oversized, nonregular or invalid UTF-8 inputs fail. This scan checks
public-content policy; producer verifiers still own SBOM, native and receipt
semantics. Trusted operator-selected parent directories remain required.

The two literal Apache URLs in the notice supplement receive a generated-file
allowance only after the entire bundle matches independently rebuilt content
from the pinned source texts and current reviewed policy. Matching a filename
alone grants no allowance. Substituted content fails provenance and is still
scanned for private identifiers. No private-value file is uploaded to public CI.


The maintainer explicitly approved the verified GitHub connector author identity
for publishing the security-controls review. The commit-metadata scanner admits
that exact account email, recorded in its metadata-only policy. This does not
admit other addresses at the same provider, relax source or artifact email checks,
or override the private-value denylist. Recheck connector author and committer
metadata before attaching new publication commits to a branch.
