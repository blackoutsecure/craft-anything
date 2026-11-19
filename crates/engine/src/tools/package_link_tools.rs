//! Explicitly confirmed public package links. Discovery remains the existing local tool.

use super::artifact_tools::fresh_dir_in;
use super::native_common::spec;
use super::static_input::builder;
use crate::target::Target;
use crate::tool::{Ctx, Effects, Requires, ToolOutput, ToolSpec, Toolset, parse_params, schema_of};
use craft_anything_engines::public_download;
use craft_anything_evidence::{Authority, Confidence, Coverage, ErrorCode, Limitation, Subject, ToolError, sha256_hex};
use craft_anything_platform::fs::ReadOnlyDirectory;
use schemars::JsonSchema;
use serde::{Deserialize, Serialize};
use serde_json::{Value, json};
use std::collections::BTreeSet;
use std::path::{Path, PathBuf};

const PAGE_BYTES: u64 = 2 << 20;
const CANDIDATES: usize = 32;

pub fn specs() -> Vec<ToolSpec> {
    let effects = Effects::EVIDENCE | Effects::ACCESSES_NETWORK | Effects::CARRIES_TARGET_CONTENT;
    vec![
        spec(
            "apple_package_sources",
            "Find package download links",
            "Preview a direct public HTTPS IPA link, list suggested publisher downloads without network access, or explicitly read a publisher page for static IPA links. GitHub release pages use their public release API. No package is downloaded or run; page reads require read_page=true. Deep mode only.",
            "Choose a package link without installing or running the app.",
            Toolset::Apple,
            effects,
            Requires::Nothing,
            schema_of::<SourceParams>,
            package_sources,
        ),
        spec(
            "apple_package_import",
            "Import an iOS package from a link",
            "After confirmed=true and authorized=true, download a public HTTPS IPA to a private content-addressed cache, optionally verify an expected SHA-256, then run existing strict package discovery and open the local package as the active target. Public destinations only on every redirect; bounded bytes/deadline, cancellation, no browser credentials, installation or execution. Deep mode only.",
            "Download an app package you are allowed to inspect, then look inside it without running it.",
            Toolset::Apple,
            effects | Effects::WRITES_FILESYSTEM,
            Requires::Nothing,
            schema_of::<ImportParams>,
            package_import,
        ),
    ]
}

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct PackageLink {
    pub name: String,
    pub url: String,
    pub source_page: Option<String>,
    pub expected_sha256: Option<String>,
    pub license: Option<String>,
}

#[derive(Debug, Clone, Default, PartialEq, Serialize, Deserialize)]
pub struct SourcePreview {
    pub candidates: Vec<PackageLink>,
    pub network_used: bool,
    pub needs_page_confirmation: bool,
    pub rejected_links: usize,
}

#[derive(Debug, Deserialize, JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct SourceParams {
    /// Direct HTTPS IPA or publisher page; omit to list suggested official downloads offline.
    #[serde(default)]
    pub url: Option<String>,
    /// Explicit permission to read the publisher page (not to download or execute any app).
    #[serde(default)]
    pub read_page: bool,
}

fn default_bytes() -> u64 {
    256 << 20
}

#[derive(Debug, Deserialize, JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct ImportParams {
    /// Stable public HTTPS IPA link; credentials, signed queries and fragments are not accepted.
    pub url: String,
    /// Expected SHA-256 from a source you trust. Without it only a local fingerprint is recorded.
    #[serde(default)]
    pub expected_sha256: Option<String>,
    /// Explicit approval to download and inspect this package for this call.
    #[serde(default)]
    pub confirmed: bool,
    /// You own the package or have permission to download and inspect it.
    #[serde(default)]
    pub authorized: bool,
    /// Optional public publisher page to retain as provenance, not fetched during import.
    #[serde(default)]
    pub source_page: Option<String>,
    /// Compressed download limit (1-536870912); default 256 MiB.
    #[serde(default = "default_bytes")]
    pub max_bytes: u64,
}

pub fn suggestions() -> Vec<PackageLink> {
    vec![PackageLink {
        name: "UTM Remote 5.0.9 (iPhone/iPad)".into(),
        url: "https://github.com/utmapp/UTM/releases/download/v5.0.9-2/UTM-Remote.ipa".into(),
        source_page: Some("https://github.com/utmapp/UTM/releases/tag/v5.0.9-2".into()),
        expected_sha256: Some("1b0911ebb7675312518c6e592a9d8d478688f893b5d500125ed2d5d434f69c0b".into()),
        license: Some("Apache-2.0 at the published release tag; review the publisher's terms and included notices.".into()),
    }]
}

fn direct_link(url: &str) -> PackageLink {
    if let Some(known) = suggestions().into_iter().find(|candidate| candidate.url == url) {
        return known;
    }
    let name = public_download::validate_url(url)
        .ok()
        .and_then(|url| url.path_segments().and_then(|mut segments| segments.next_back()).map(str::to_string))
        .unwrap_or_else(|| "IPA package".into());
    PackageLink { name, url: url.into(), source_page: None, expected_sha256: None, license: None }
}

fn github_api(url: &str) -> Option<String> {
    let parsed = public_download::validate_url(url).ok()?;
    if parsed.host_str()? != "github.com" {
        return None;
    }
    let parts: Vec<_> = parsed.path_segments()?.collect();
    let owner = *parts.first()?;
    let repo = *parts.get(1)?;
    if *parts.get(2)? != "releases" || owner.is_empty() || repo.is_empty() || parts.iter().any(|part| part.contains('%')) {
        return None;
    }
    match parts.get(3).copied() {
        Some("latest") | None => Some(format!("https://api.github.com/repos/{owner}/{repo}/releases/latest")),
        Some("tag") if parts.len() > 4 => {
            let mut api = public_download::validate_url(&format!("https://api.github.com/repos/{owner}/{repo}/releases/tags/")).ok()?;
            api.path_segments_mut().ok()?.pop_if_empty().push(&parts.get(4..)?.join("/"));
            Some(api.into())
        }
        _ => None,
    }
}

fn html_candidates(page: &str, body: &str) -> SourcePreview {
    let mut result = SourcePreview { network_used: true, ..Default::default() };
    let mut seen = BTreeSet::new();
    for href in craft_anything_js::html::scan_html(body).links {
        match public_download::resolve_link(page, &href) {
            Ok(url) if public_download::is_ipa(&url) && seen.insert(url.clone()) => {
                if result.candidates.len() < CANDIDATES {
                    let mut candidate = direct_link(&url);
                    candidate.source_page = Some(page.into());
                    result.candidates.push(candidate);
                } else {
                    result.rejected_links += 1;
                }
            }
            _ => result.rejected_links += 1,
        }
    }
    result
}

fn release_candidates(page: &str, body: &[u8]) -> Result<SourcePreview, ToolError> {
    #[derive(Deserialize)]
    struct Release {
        assets: Vec<Asset>,
    }
    #[derive(Deserialize)]
    struct Asset {
        name: String,
        browser_download_url: String,
        #[serde(default)]
        digest: Option<String>,
    }
    let release: Release =
        serde_json::from_slice(body).map_err(|_| ToolError::new(ErrorCode::GarbledOutput, "The publisher release reply is not a readable asset list."))?;
    let mut result = SourcePreview { network_used: true, ..Default::default() };
    for asset in release.assets {
        if result.candidates.len() >= CANDIDATES || !public_download::is_ipa(&asset.browser_download_url) {
            result.rejected_links += 1;
            continue;
        }
        let mut candidate = direct_link(&asset.browser_download_url);
        candidate.name = asset.name.chars().take(200).collect();
        candidate.source_page = Some(page.into());
        if let Some(hash) = asset.digest.and_then(|digest| digest.strip_prefix("sha256:").map(str::to_string)) {
            candidate.expected_sha256 = Some(valid_hash(&hash)?);
        }
        result.candidates.push(candidate);
    }
    Ok(result)
}

fn package_sources(ctx: &mut Ctx<'_>, params: Value) -> Result<ToolOutput, ToolError> {
    let p: SourceParams = parse_params(params)?;
    ctx.cancel.check()?;
    let preview = match p.url.as_deref().map(str::trim).filter(|url| !url.is_empty()) {
        None => SourcePreview { candidates: suggestions(), ..Default::default() },
        Some(input) => {
            let url = public_download::validate_url(input)?.to_string();
            if public_download::is_ipa(&url) {
                SourcePreview { candidates: vec![direct_link(&url)], ..Default::default() }
            } else if !p.read_page {
                SourcePreview { needs_page_confirmation: true, ..Default::default() }
            } else {
                let api = github_api(&url);
                let mut bytes = Vec::new();
                ctx.report(None, "Reading public publisher links; no app is downloaded");
                let cancel = ctx.cancel.clone();
                let cancelled: craft_anything_platform::process::Cancel = std::sync::Arc::new(move || cancel.is_cancelled());
                let receipt = public_download::download_to(api.as_deref().unwrap_or(&url), &mut bytes, PAGE_BYTES, Some(&cancelled), &|_, _| {})?;
                ctx.cancel.check()?;
                if api.is_some() {
                    release_candidates(&url, &bytes)?
                } else {
                    let text =
                        std::str::from_utf8(&bytes).map_err(|_| ToolError::unsupported("The publisher page is not UTF-8 HTML; use its direct IPA link."))?;
                    html_candidates(&receipt.final_url, text)
                }
            }
        }
    };
    let network = preview.network_used;
    let count = preview.candidates.len();
    let evidence = builder(ctx, "apple_package_sources", Subject { kind: "package-source".into(), name: p.url.clone(), sha256: None }, json!({"url":p.url,"read_page":p.read_page}))
        .result(serde_json::to_value(&preview).map_err(|error| ToolError::internal(error.to_string()))?)
        .summary(format!("{} package link candidate(s); no app was downloaded.", count))
        .confidence(Confidence::Derived)
        .authority(if network { Authority::OutsideService } else { Authority::Reasoning })
        .coverage(if network { super::static_input::partial(count as u64) } else { Coverage::complete(count as u64) })
        .target_content(true)
        .limitation(Limitation::new("source_not_permission", "A suggested link or catalog entry is not permission or a trust guarantee. Review the publisher's terms and confirm you may inspect the package."))
        .limitation(Limitation::new("static_links_only", "Only direct IPA links, public GitHub release assets and bounded static HTML anchors are considered. No page code, login, App Store, crawler or installer is used."))
        .build()?;
    Ok(ToolOutput::evidence(evidence))
}

fn valid_hash(value: &str) -> Result<String, ToolError> {
    let value = value.trim();
    if value.len() != 64 || !value.bytes().all(|byte| byte.is_ascii_hexdigit()) {
        return Err(ToolError::invalid("expected_sha256 must contain exactly 64 hexadecimal characters."));
    }
    Ok(value.to_ascii_lowercase())
}

fn read_cached(base: &Path, hash: &str, max_bytes: u64) -> Result<Option<Vec<u8>>, ToolError> {
    let directory = base.join(hash);
    match std::fs::symlink_metadata(&directory) {
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => Ok(None),
        Err(error) => Err(ToolError::io("package cache", error)),
        Ok(metadata) if metadata.file_type().is_symlink() || !metadata.is_dir() => {
            Err(ToolError::invalid("The managed package cache is not a regular directory."))
        }
        Ok(_) => {
            let physical = std::fs::canonicalize(base).map_err(|error| ToolError::io("package cache", error))?;
            let bytes = ReadOnlyDirectory::open(&physical)?.open_dir(Path::new(hash))?.read_file_capped(Path::new("package.ipa"), max_bytes)?;
            if sha256_hex(&bytes) != hash {
                return Err(ToolError::new(ErrorCode::FileHashMismatch, "The cached package changed; it was not inspected or overwritten.")
                    .with_remediation("Remove only this managed cache entry, then retry from a verified publisher source."));
            }
            Ok(Some(bytes))
        }
    }
}

struct Incoming {
    path: PathBuf,
    keep: bool,
}

impl Incoming {
    fn new(path: PathBuf) -> Self {
        Self { path, keep: false }
    }

    fn keep(mut self) {
        self.keep = true;
    }
}

impl Drop for Incoming {
    fn drop(&mut self) {
        if self.keep {
            return;
        }
        for name in ["package.ipa", "package.download"] {
            match std::fs::remove_file(self.path.join(name)) {
                Ok(()) => {}
                Err(error) if error.kind() == std::io::ErrorKind::NotFound => {}
                Err(error) => log::warn!("Could not clean the owned package download: {error}"),
            }
        }
        if let Err(error) = std::fs::remove_dir(&self.path) {
            log::warn!("Could not remove the owned package download directory: {error}");
        }
    }
}

fn package_import(ctx: &mut Ctx<'_>, params: Value) -> Result<ToolOutput, ToolError> {
    let p: ImportParams = parse_params(params)?;
    if !p.confirmed || !p.authorized {
        return Err(ToolError::new(ErrorCode::ConsentRequired, "Downloading and inspecting this package needs your explicit confirmation and permission.")
            .with_remediation("Review the publisher source and license, then pass confirmed=true and authorized=true for this call."));
    }
    ctx.cancel.check()?;
    let url = public_download::validate_url(p.url.trim())?.to_string();
    if !public_download::is_ipa(&url) {
        return Err(ToolError::invalid("Choose a direct HTTPS .ipa download link. Use apple_package_sources to inspect a publisher page first."));
    }
    if p.max_bytes == 0 || p.max_bytes > public_download::MAX_DOWNLOAD_BYTES {
        return Err(ToolError::invalid(format!("max_bytes must be 1-{}.", public_download::MAX_DOWNLOAD_BYTES)));
    }
    let source_page = p.source_page.as_deref().map(public_download::validate_url).transpose()?.map(String::from);
    let expected = p.expected_sha256.as_deref().map(valid_hash).transpose()?;
    let base = ctx.session.config_dir().join("package-imports");
    if std::fs::symlink_metadata(&base).is_ok_and(|metadata| metadata.file_type().is_symlink()) {
        return Err(ToolError::invalid("The managed package cache cannot be a symbolic link."));
    }
    let mut created_cache = None;
    let cached = expected.as_deref().map(|hash| read_cached(&base, hash, p.max_bytes)).transpose()?.flatten();
    let bytes = if let Some(bytes) = cached {
        ctx.report(None, "Reusing the SHA-256-verified local package");
        bytes
    } else {
        let incoming = Incoming::new(fresh_dir_in(&base, "incoming")?);
        let path = incoming.path.join("package.ipa");
        let cancel = ctx.cancel.clone();
        let cancelled: craft_anything_platform::process::Cancel = std::sync::Arc::new(move || cancel.is_cancelled());
        let progress = |received: u64, total: Option<u64>| {
            ctx.report(
                total.filter(|total| *total > 0).map(|total| (received as f64 / total as f64).min(1.0) as f32),
                format!("Downloading package: {received} bytes"),
            );
        };
        public_download::download_file(&url, &path, expected.as_deref(), p.max_bytes, Some(&cancelled), &progress)?;
        ctx.cancel.check()?;
        let bytes = ReadOnlyDirectory::open(&std::fs::canonicalize(&incoming.path).map_err(|error| ToolError::io("package download", error))?)?
            .read_file_capped(Path::new("package.ipa"), p.max_bytes)?;
        let hash = sha256_hex(&bytes);
        let destination = base.join(&hash);
        match std::fs::create_dir(&destination) {
            Ok(()) => {
                created_cache = Some(Incoming::new(destination.clone()));
                craft_anything_platform::fs::set_private_dir(&destination)?;
                std::fs::hard_link(&path, destination.join("package.ipa")).map_err(|error| ToolError::io("package cache", error))?;
            }
            Err(error) if error.kind() == std::io::ErrorKind::AlreadyExists => {
                read_cached(&base, &hash, p.max_bytes)?.ok_or_else(|| ToolError::internal("The package cache disappeared."))?;
            }
            Err(error) => return Err(ToolError::io("package cache", error)),
        }
        bytes
    };
    ctx.cancel.check()?;
    let hash = sha256_hex(&bytes);
    let path = base.join(&hash).join("package.ipa");
    let discovered = super::apple_package_tools::apple_package_discover(ctx, json!({"path":path}))?;
    let ToolOutput::Evidence(discovery) = discovered else { return Err(ToolError::internal("Package discovery did not return evidence.")) };
    if discovery.result.get("recognized").and_then(Value::as_bool) != Some(true) {
        return Err(ToolError::unsupported("The downloaded file did not contain a valid top-level iOS app; it was not opened.")
            .with_details(json!({"reason":"package_not_recognized","parse_failures":discovery.result.get("parse_failures")})));
    }
    let target = Target::from_bytes(path.clone(), "package.ipa".into(), bytes);
    let target_id = target.id.clone();
    ctx.session.record((*discovery).clone())?;
    let evidence = builder(ctx, "apple_package_import", target.subject(), json!({"url":url,"source_page":source_page,"expected_sha256":expected,"max_bytes":p.max_bytes}))
        .result(json!({
            "path":path,"target_id":target_id,
            "download":{"url":url,"source_page":source_page,"sha256":hash,"checksum_verified":expected.is_some(),"authorization":"confirmed_by_caller"},
            "package":discovery.result,"discovery_evidence":discovery.id,
        }))
        .summary(format!("Imported an authorized package; primary app: {}. Nothing was installed or run.", discovery.result.get("primary_app").and_then(Value::as_str).unwrap_or("unknown")))
        .confidence(Confidence::Derived)
        .authority(Authority::OriginalFiles)
        .coverage(discovery.coverage)
        .limitations(discovery.limitations.clone())
        .limitations(expected.is_none().then(|| Limitation::new("checksum_unverified", "No trusted expected checksum was supplied. The computed SHA-256 is a local fingerprint, not publisher verification.")))
        .limitation(Limitation::new("permission_asserted", "The caller confirmed permission; Craft Anything does not determine legal rights or authenticate the publisher. A checksum match verifies bytes against the supplied digest, not safety or ownership."))
        .target_content(true)
        .link(discovery.id.clone())
        .build()?;
    ctx.session.add_target(target);
    if let Some(created) = created_cache {
        created.keep();
    }
    Ok(ToolOutput::evidence(evidence))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn static_page_candidates_reuse_the_html_scanner_without_following_scripts_or_unsafe_links() {
        let result = html_candidates(
            "https://publisher.example.com/releases/",
            r#"
            <script>const text = '<a href="not-real.ipa">';</script>
            <!-- <a href="comment.ipa"> -->
            <a href="../build/App.ipa">Download</a>
            <a href="https://127.0.0.1/escape.ipa">private</a>
            <a href="javascript:run()">script</a>
            <a href="../build/App.ipa">duplicate</a>
        "#,
        );
        assert_eq!(result.candidates.len(), 1);
        assert_eq!(result.candidates[0].url, "https://publisher.example.com/build/App.ipa");
        assert_eq!(result.rejected_links, 3);
    }

    #[test]
    fn github_release_pages_use_a_bounded_public_asset_reply_with_digests() {
        assert_eq!(github_api("https://github.com/owner/repo/releases/tag/v1").as_deref(), Some("https://api.github.com/repos/owner/repo/releases/tags/v1"));
        let reply = json!({"assets":[{"name":"App.ipa","browser_download_url":"https://github.com/owner/repo/releases/download/v1/App.ipa","digest":format!("sha256:{}","a".repeat(64))},{"name":"other.txt","browser_download_url":"https://github.com/owner/repo/other.txt"}]});
        let result = release_candidates("https://github.com/owner/repo/releases/tag/v1", &serde_json::to_vec(&reply).unwrap()).unwrap();
        assert_eq!(result.candidates.len(), 1);
        assert_eq!(result.candidates[0].expected_sha256.as_deref(), Some("a".repeat(64).as_str()));
    }
}
