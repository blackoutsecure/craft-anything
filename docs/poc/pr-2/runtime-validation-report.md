# Package-link POC runtime validation

Date: 2026-11-19

PR: [blackoutsecure/craft-anything#2](https://github.com/blackoutsecure/craft-anything/pull/2)

Tested implementation: `694929b0f62396c17aa3d211b30d649660f51484`.

## Result

**165 targeted tests passed, zero failed, final exit codes 0.** Both real frontends built.
This is successful scoped POC evidence, **not full-suite or merge sign-off**.
No production code, implementation-branch commit, or merge was needed for this evidence.

The pictures are actual native egui widgets rendered offscreen with wgpu at 2160 x 1860.
The test driver clicks, types, and scrolls the controls; the normal UI jobs dispatch into
the actual engine and public HTTPS downloader. No package cache was preseeded, no publisher
response was mocked, and no success/evidence card was fabricated. The configured project
folder shown behind the Clean room dialog is a generic display setting, not a personal path.
This is not a manual OS-window mouse session, browser emulation of the app, or device test.

## Executed checks

All commands used the PR's existing lockfile, Rust/Cargo 1.100.0 on macOS arm64,
four Cargo build jobs, and at most two test threads (one for the live evidence driver).

| Scope | Final exit code | Passed | Failed |
|---|---:|---:|---:|
| Build desktop and CLI frontends | 0 | n/a | 0 |
| Engine import contract | 0 | 11 | 0 |
| Existing native import GUI workflows | 0 | 5 | 0 |
| Existing native GUI smoke suite | 0 | 119 | 0 |
| Public HTTPS downloader, including real TLS fixtures | 0 | 11 | 0 |
| Source lookup and immutable-cache resolver | 0 | 6 | 0 |
| Stale prior-target UI result regression | 0 | 1 | 0 |
| MCP package-link permission/preview contract | 0 | 1 | 0 |
| Built CLI package-link permission/preview contract | 0 | 1 | 0 |
| Existing HTML scanner tests | 0 | 5 | 0 |
| New live proof journeys in three test files | 0 | 5 | 0 |
| **Total tests** | **0** | **165** | **0** |

Repository test selections:

```sh
cargo build --locked -j 4 -p craft-anything-cli -p craft-anything
cargo test --locked -j 4 -p craft-anything-engine --test package_link_import -p craft-anything-ui-egui --test package_links --test smoke --no-fail-fast -- --test-threads=2
cargo test --locked -j 4 -p craft-anything-engines --lib public_download:: -- --test-threads=2
cargo test --locked -j 4 -p craft-anything-engine -p craft-anything-ui-egui -p craft-anything-mcp --lib package_link --no-fail-fast -- --test-threads=2
cargo test --locked -j 4 -p craft-anything-cli --test cli package_link_tools -- --test-threads=2
cargo test --locked -j 4 -p craft-anything-js --lib html:: -- --test-threads=2
```

### Live journeys

1. **Publisher to import proof:** open Import from link; verify suggestions have not
   downloaded anything; read the actual public publisher release; verify seven IPA
   candidates and still no package cache; select UTM Remote; preview that direct link
   offline; review license and publisher digest; explicitly confirm permission; press
   Download and Study; verify the rendered proof, active target, retained evidence, and
   one immutable cached IPA with no extracted app.
2. **Permission failures:** three incomplete confirmation/authorization combinations
   return `consent_required`, preserve the previous target, and create no download cache.
3. **Clean room:** the dialog explains that Deep mode is needed, does not expose
   Download and Study, does not silently change modes, and creates no package cache.
4. **Private address:** previewing a loopback URL shows the real error, creates no cache
   or active target, and cancellation returns to the unchanged local-input choices.
5. **Persistence and cache reuse:** independently import the real publisher package,
   hash the cached bytes, close the engine, reopen the saved project, read back the
   retained evidence, import through the MCP caller using the verified cache, and assert
   identical evidence ID, unchanged modification time, the same byte hash, and active target.

All test configurations and downloaded samples were isolated in owned temporary folders
and cleaned up. No IPA was uploaded, extracted, installed, or executed.

### Publisher and observed output

- [Official release](https://github.com/utmapp/UTM/releases/tag/v5.0.9-2):
  UTM Remote 5.0.9, Apache-2.0 at the release tag; the UI retains the publisher-terms warning.
- Asset: `UTM-Remote.ipa`, 37,685,697 bytes.
- Publisher SHA-256, checked against the live release API and downloaded bytes:
  `1b0911ebb7675312518c6e592a9d8d478688f893b5d500125ed2d5d434f69c0b`.
- Observed primary app: `Payload/UTM Remote.app`.
- Observed bundle identifier: `com.utmapp.UTM-Remote`.
- [Live GUI assertions](live-gui-result.json),
  [publisher preview](publisher-preview.json),
  [permission assertions](permission-result.json),
  [reopen/cache assertions](persistence-result.json).

## Screenshot sequence

1. [Study entry](01-study-entry.png).
2. [Source suggestion before any download](02-source-review-no-download.png).
3. [Live publisher preview](03-live-publisher-preview.png).
4. [Expected digest, explicit permission, and enabled Download and Study](04-checksum-and-explicit-permission.png).
5. [Actual completed import proof and active local package](05-live-import-proof.png).
6. [Clean room refusal](06-clean-room-refusal.png).
7. [Private-link error and unavailable download](07-private-link-refusal.png).

The publisher list is scrollable; the preview picture shows its first visible entry.
The importer selected and downloaded **UTM Remote**, not that first entry.
The single-line digest field is horizontally clipped in the picture; the complete
64-character digest was asserted in the test and is recorded above.

## Repeat the additional live proof

From a checkout of this evidence snapshot, use the original workspace and lockfile.
The driver is deliberately separate from the implementation branch and canonical tests.
The files under `validation/` are the actual driver used, not example pseudocode.

```sh
test ! -e crates/ui-egui/tests/pr2_poc_evidence.rs
cp docs/poc/pr-2/validation/runner.rs crates/ui-egui/tests/pr2_poc_evidence.rs
POC_PROOF_SOURCE="$PWD/docs/poc/pr-2/validation" \
POC_EVIDENCE_DIR="$PWD/target/pr-2-poc-evidence" \
cargo test --locked -j 4 -p craft-anything-ui-egui --test pr2_poc_evidence -- --test-threads=1 --nocapture
# After collecting the exit code, remove only the temporary launcher created above.
rm crates/ui-egui/tests/pr2_poc_evidence.rs
```

The first standalone scratch-package attempt could not resolve a yanked transitive
dependency offline. Using the existing workspace lockfile fixed that setup problem.
An initial driver run also needed explicit scrolling to offscreen controls and the
same Clean room starting state as the existing tests. The corrected driver passed
all five tests twice; no production implementation was changed to obtain these results.

## Review boundaries

- The [outstanding concurrent-import completion review](https://github.com/blackoutsecure/craft-anything/pull/2#discussion_r4631019560)
  remains open. This run serializes imports and does not establish that overlapping
  UI target changes display the correct final package's proof.
- The earlier PR description records a full-selected-suite exit 101 caused by the
  unchanged macOS/APFS non-text-folder fixture. That suite was not rerun here, and
  these focused successes do not replace or waive that failure.
- No hosted CI success, manual desktop mouse session, Windows/Linux/device runtime,
  application execution, installation, or simulator support is claimed.

## Environment and verdict

```text
environment:
  docker: AVAILABLE - docker info returned server 29.9.3; not needed by this native app flow
  node: AVAILABLE - v24.15.0; not needed for native egui execution
  playwright: NOT_APPLICABLE - this application flow is native egui, not rendered HTML
  infra-tier: PRIMARY - real public HTTPS, filesystem cache and saved project; real TLS regression fixtures
  browser-tier: NOT_APPLICABLE - actual egui controls tested with egui_kittest and wgpu
startup: PASS - both frontends build; first rendered native UI and controls verified by the driver
integration: PASS - exit_code: 0; passed: 160, failed: 0; targeted repository checks only
e2e: PASS - exit_code: 0; passed: 5, failed: 0; automated native UI/live HTTPS plus reopen/cache and refusal flows
overall: NEEDS_SIGNOFF - scoped POC works; open concurrent-import review and earlier full-suite caveat remain
```
