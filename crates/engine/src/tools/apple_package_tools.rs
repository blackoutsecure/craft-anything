//! Metadata-first discovery of user-supplied iOS packages. Only candidate Info.plists are read;
//! executables and other members are neither decompressed nor executed.

use super::artifact_tools::{WalkLimits, WalkOptions, safe_components, target_path, walk_dir_contained};
use super::native_common::spec;
use super::static_input;
use super::{Detail, detailed};
use crate::tool::{Ctx, Effects, Requires, ToolOutput, ToolSpec, Toolset, parse_params, schema_of};
use craft_anything_analysis::js_inventory::{InvEntry, InvLimits, Inventory, path_role, sniff_kind};
use craft_anything_evidence::{Authority, Confidence, Coverage, CoverageStatus, ErrorCode, Limitation, Location, Subject, ToolError, sha256_hex};
use craft_anything_formats::{plist, zip};
use craft_anything_platform::fs::ReadOnlyDirectory;
use schemars::JsonSchema;
use serde::{Deserialize, Serialize};
use serde_json::{Value, json};
use std::collections::{BTreeMap, BTreeSet};
use std::path::Path;
use std::sync::Arc;

pub fn specs() -> Vec<ToolSpec> {
    vec![spec(
        "apple_package_discover",
        "Discover an iOS package",
        "Discover top-level apps in a user-supplied IPA, .app bundle or extracted Payload directory. Inventory metadata with existing archive limits, parse XML/binary Info.plists, resolve bundle-contained executable paths and select the first valid app in path order. Deep mode only; no extraction or execution.",
        "Find the apps inside an iPhone package without installing or running them.",
        Toolset::Apple,
        Effects::EVIDENCE | Effects::CARRIES_TARGET_CONTENT,
        Requires::Nothing,
        schema_of::<PackageParams>,
        apple_package_discover,
    )]
}

fn default_entries() -> usize {
    InvLimits::default().max_entries
}

fn default_bytes() -> u64 {
    InvLimits::default().max_total_bytes
}

#[derive(Debug, Deserialize, Serialize, JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct PackageParams {
    /// Absolute path of an .ipa file, .app directory or extracted Payload directory; the active target when omitted.
    #[serde(default)]
    pub path: Option<String>,
    /// complete (default) or a compact summary retaining the full evidence for core_evidence_browse.
    #[serde(default)]
    pub detail: Detail,
    /// Most members inventoried, including directories (1-200000). May lower, not raise, the existing archive limit.
    #[serde(default = "default_entries")]
    pub max_entries: usize,
    /// Most declared uncompressed bytes in total. May lower, not raise, the existing archive limit.
    #[serde(default = "default_bytes")]
    pub max_total_bytes: u64,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize)]
#[serde(rename_all = "snake_case")]
enum PackageForm {
    Ipa,
    AppBundle,
    PayloadDirectory,
}

impl PackageForm {
    fn detect(path: &Path, metadata: &std::fs::Metadata) -> Result<Self, ToolError> {
        if metadata.file_type().is_symlink() {
            return Err(unsafe_member("symlink_member", &path.display().to_string(), "symbolic links are not followed"));
        }
        let extension = path.extension().and_then(|part| part.to_str()).unwrap_or_default();
        if metadata.is_file() && extension.eq_ignore_ascii_case("ipa") {
            Ok(Self::Ipa)
        } else if metadata.is_dir() && extension.eq_ignore_ascii_case("app") {
            Ok(Self::AppBundle)
        } else if metadata.is_dir() && path.file_name().is_some_and(|name| name.eq_ignore_ascii_case("Payload")) {
            Ok(Self::PayloadDirectory)
        } else {
            Err(ToolError::unsupported("Package discovery needs an .ipa file, an .app directory or an extracted Payload directory.")
                .with_remediation("Pass a user-supplied package with --path; this tool does not download apps."))
        }
    }
}

#[derive(Debug, Serialize)]
struct Candidate {
    bundle_path: String,
    info_plist: String,
    bundle_identifier: Option<String>,
    bundle_name: Option<String>,
    executable_name: Option<String>,
    executable_path: Option<String>,
    valid: bool,
}

#[derive(Debug, Serialize)]
struct ParseFailure {
    path: String,
    error: ToolError,
}

#[derive(Debug, Serialize)]
struct Discovery {
    form: PackageForm,
    recognized: bool,
    primary_app: Option<String>,
    candidates: Vec<Candidate>,
    inventory: Inventory,
    parse_failures: Vec<ParseFailure>,
}

enum PackageSource {
    Ipa { bytes: Arc<[u8]>, members: BTreeMap<String, zip::ZipEntry> },
    Directory { root: ReadOnlyDirectory },
}

impl PackageSource {
    fn read_plist(&self, bundle: &str, member: &str, max: u64) -> Result<Vec<u8>, ToolError> {
        match self {
            Self::Ipa { bytes, members } => {
                let entry = members.get(member).ok_or_else(|| ToolError::internal("The inventoried plist member is missing."))?;
                zip::read_entry(bytes, entry, max).map_err(|error| {
                    let (code, reason) = match error {
                        zip::ZipError::TooLarge(_) => (ErrorCode::OverLimit, "plist_read_limit"),
                        zip::ZipError::CrcMismatch { .. } => (ErrorCode::FileHashMismatch, "plist_crc_mismatch"),
                        _ => (ErrorCode::GarbledOutput, "plist_read_failed"),
                    };
                    ToolError::new(code, error.to_string()).with_details(json!({"reason": reason, "path": member}))
                })
            }
            Self::Directory { root } => root.open_dir(Path::new(bundle))?.read_file_capped(Path::new(bundle_relative_member(bundle, member)?), max),
        }
    }

    fn check_executable(&self, bundle: &str, member: &str) -> Result<(), ToolError> {
        if let Self::Directory { root } = self {
            let metadata = root.open_dir(Path::new(bundle))?.symlink_metadata(Path::new(bundle_relative_member(bundle, member)?))?;
            if metadata.file_type().is_symlink() {
                return Err(unsafe_member("symlink_member", member, "symbolic links are not followed"));
            }
            if !metadata.is_file() {
                return Err(unsafe_member("non_regular_member", member, "not a regular file"));
            }
        }
        Ok(())
    }
}

fn unsafe_member(reason: &str, path: &str, message: &str) -> ToolError {
    ToolError::invalid(format!("Refused package member {path:?}: {message}."))
        .with_remediation("Supply a package with unambiguous relative paths and regular files/directories, without links.")
        .with_details(json!({"reason": reason, "path": path}))
}

fn member_path(path: &str) -> Result<String, ToolError> {
    safe_components(path).map(|parts| parts.join("/")).map_err(|reason| unsafe_member("unsafe_member_path", path, reason))
}

fn over_limit(reason: &str, message: impl Into<String>) -> ToolError {
    ToolError::new(ErrorCode::OverLimit, message)
        .with_remediation("Supply a smaller package or raise a lowered limit, without exceeding the existing archive limits.")
        .with_details(json!({"reason": reason}))
}

fn check_size(path: &str, size: u64, total: &mut u64, limits: InvLimits) -> Result<(), ToolError> {
    if size > limits.max_entry_bytes {
        return Err(over_limit("archive_entry_limit", format!("{path:?} declares {size} bytes; the entry limit is {}.", limits.max_entry_bytes)));
    }
    *total = total
        .checked_add(size)
        .filter(|value| *value <= limits.max_total_bytes)
        .ok_or_else(|| over_limit("archive_total_limit", format!("The package exceeds the {}-byte uncompressed inventory limit.", limits.max_total_bytes)))?;
    Ok(())
}

fn metadata_entry(path: String, size: u64, directory: bool) -> InvEntry {
    InvEntry {
        role: path_role(&path).map(str::to_string),
        path,
        size,
        kind: if directory { "directory" } else { "unread" }.into(),
        note: (!directory).then(|| "Contents not inspected; size comes from member metadata.".into()),
        ..Default::default()
    }
}

fn invalid_zip(message: impl Into<String>) -> ToolError {
    ToolError::new(ErrorCode::GarbledOutput, message).with_details(json!({"reason": "invalid_zip"}))
}

fn package_archive(bytes: &[u8], limits: InvLimits) -> Result<zip::ZipArchive, ToolError> {
    let directory = zip::preflight::preflight(
        bytes,
        zip::preflight::Limits { max_entries: limits.max_entries as u64, max_central_directory_bytes: bytes.len() as u64, max_name_bytes: u16::MAX },
    )
    .map_err(|error| match error {
        zip::preflight::Error::TooManyEntries { .. } => over_limit("archive_member_limit", error.to_string()),
        zip::preflight::Error::CentralDirectoryTooLarge { .. } | zip::preflight::Error::NameTooLong { .. } => {
            over_limit("archive_listing_limit", error.to_string())
        }
        _ => invalid_zip(error.to_string()),
    })?;
    let archive = zip::parse(bytes, limits.max_entries).map_err(|error| match error {
        zip::ZipError::TooLarge(max) => over_limit("archive_listing_limit", format!("ZIP inventory reached its {max}-byte parser limit.")),
        _ => invalid_zip(error.to_string()),
    })?;
    if archive.truncated || archive.entries.len() as u64 != directory.entries || archive.declared_entries != directory.entries {
        return Err(invalid_zip("The ZIP listing disagrees with its validated central directory."));
    }
    if !archive.warnings.is_empty() {
        return Err(invalid_zip(archive.warnings.join("; ")));
    }
    Ok(archive)
}

fn inventory_member_metadata(members: &BTreeMap<String, zip::ZipEntry>, check_cancel: &impl Fn() -> Result<(), ToolError>) -> Result<Vec<InvEntry>, ToolError> {
    use std::ops::Bound::{Included, Unbounded};

    let mut entries = Vec::new();
    for (path, entry) in members {
        check_cancel()?;
        if !entry.is_dir {
            let prefix = format!("{path}/");
            if let Some((descendant, _)) = members.range::<str, _>((Included(prefix.as_str()), Unbounded)).next()
                && descendant.starts_with(&prefix)
            {
                return Err(unsafe_member("ambiguous_member", descendant, "a parent member is not a directory"));
            }
        }
        entries.push(metadata_entry(path.clone(), entry.uncompressed_size, entry.is_dir));
    }
    Ok(entries)
}

fn archive_source(ctx: &Ctx<'_>, bytes: Arc<[u8]>, archive: zip::ZipArchive, inventory: &mut Inventory, limits: InvLimits) -> Result<PackageSource, ToolError> {
    let mut members = BTreeMap::new();
    let mut total = 0;
    for entry in archive.entries {
        ctx.cancel.check()?;
        let path = member_path(&entry.name)?;
        if let Some(kind) = entry.special_kind() {
            return Err(unsafe_member(if kind == "symlink" { "symlink_member" } else { "non_regular_member" }, &entry.name, kind));
        }
        check_size(&path, entry.uncompressed_size, &mut total, limits)?;
        if members.insert(path.clone(), entry).is_some() {
            return Err(unsafe_member("ambiguous_member", &path, "duplicate normalized member path"));
        }
    }
    inventory.entries = inventory_member_metadata(&members, &|| ctx.cancel.check())?;
    inventory.containers.push(json!({"path": "", "kind": "ipa", "entries": members.len(), "declared": archive.declared_entries, "zip64": archive.zip64}));
    Ok(PackageSource::Ipa { bytes, members })
}

fn directory_source(ctx: &Ctx<'_>, path: &Path, inventory: &mut Inventory, limits: InvLimits) -> Result<PackageSource, ToolError> {
    let parent = path.parent().ok_or_else(|| ToolError::invalid("A package directory needs a parent path."))?;
    let name = path.file_name().ok_or_else(|| ToolError::invalid("A package directory needs a filename."))?;
    let root = std::fs::canonicalize(parent).map_err(|error| ToolError::io(parent.display(), error))?.join(name);
    let reader = ReadOnlyDirectory::open(&root)?;
    let skip = |_: &str| false;
    let walked = walk_dir_contained(
        &root,
        &reader,
        &WalkOptions { max_files: limits.max_entries, max_depth: 64, skip_dir: &skip, gitignore: false, include_hidden: true },
        WalkLimits { max_entries: limits.max_entries, ..WalkLimits::for_files(limits.max_entries) },
        &ctx.cancel,
    )?;
    if let Some(link) = walked.links.first() {
        return Err(unsafe_member("symlink_member", link, "symbolic links are not followed"));
    }
    if !walked.unlisted.is_empty() {
        return Err(ToolError::new(ErrorCode::FileError, "The package directory could not be inventoried completely.")
            .with_details(json!({"reason": "directory_inventory_failed", "unlisted": walked.unlisted})));
    }
    if walked.truncated {
        return Err(over_limit("archive_member_limit", "A member, path-length or depth limit stopped the package directory inventory."));
    }
    let mut seen = BTreeSet::new();
    let mut total = 0;
    for directory in walked.dirs {
        ctx.cancel.check()?;
        let normalized = member_path(&directory)?;
        if !seen.insert(normalized.clone()) {
            return Err(unsafe_member("ambiguous_member", &directory, "duplicate normalized member path"));
        }
        inventory.entries.push(metadata_entry(normalized, 0, true));
    }
    for file in walked.files {
        ctx.cancel.check()?;
        let normalized = member_path(&file.rel)?;
        check_size(&normalized, file.size, &mut total, limits)?;
        if !seen.insert(normalized.clone()) {
            return Err(unsafe_member("ambiguous_member", &file.rel, "duplicate normalized member path"));
        }
        inventory.entries.push(metadata_entry(normalized, file.size, false));
    }
    inventory.entries.sort_by(|left, right| left.path.cmp(&right.path));
    Ok(PackageSource::Directory { root: reader })
}

fn bundle_relative_member<'a>(bundle: &str, member: &'a str) -> Result<&'a str, ToolError> {
    if bundle == "." {
        return Ok(member);
    }
    member
        .strip_prefix(bundle)
        .and_then(|tail| tail.strip_prefix('/'))
        .filter(|tail| !tail.is_empty())
        .ok_or_else(|| unsafe_member("unsafe_member_path", member, "member is not inside this candidate bundle"))
}

fn candidate_roots(inventory: &Inventory, form: PackageForm) -> Vec<String> {
    if form == PackageForm::AppBundle {
        return vec![".".into()];
    }
    let mut roots = BTreeSet::new();
    for entry in &inventory.entries {
        let mut parts = entry.path.split('/');
        if form == PackageForm::Ipa && parts.next() != Some("Payload") {
            continue;
        }
        let Some(name) = parts.next() else { continue };
        let is_app = Path::new(name).extension().is_some_and(|extension| extension.eq_ignore_ascii_case("app"));
        if is_app && (parts.next().is_some() || entry.kind == "directory") {
            roots.insert(if form == PackageForm::Ipa { format!("Payload/{name}") } else { name.into() });
        }
    }
    roots.into_iter().collect()
}

fn in_bundle(bundle: &str, relative: &str) -> String {
    if bundle == "." { relative.to_string() } else { format!("{bundle}/{relative}") }
}

fn package_error(reason: &str, message: impl Into<String>) -> ToolError {
    ToolError::invalid(message).with_details(json!({"reason": reason}))
}

fn inspect_candidates(ctx: &Ctx<'_>, discovery: &mut Discovery, source: &PackageSource, limits: InvLimits) -> Result<(), ToolError> {
    let regular: BTreeMap<String, usize> = discovery
        .inventory
        .entries
        .iter()
        .enumerate()
        .filter(|(_, entry)| entry.kind != "directory")
        .map(|(index, entry)| (entry.path.clone(), index))
        .collect();
    for bundle in candidate_roots(&discovery.inventory, discovery.form) {
        ctx.cancel.check()?;
        ctx.report(None, format!("Reading {}", in_bundle(&bundle, "Info.plist")));
        let mut candidate = Candidate {
            info_plist: in_bundle(&bundle, "Info.plist"),
            bundle_path: bundle,
            bundle_identifier: None,
            bundle_name: None,
            executable_name: None,
            executable_path: None,
            valid: false,
        };
        let mut failure_path = candidate.info_plist.clone();
        let inspected = (|| {
            let index =
                regular.get(&candidate.info_plist).copied().ok_or_else(|| package_error("missing_info_plist", "The candidate has no regular Info.plist."))?;
            let cap = limits.max_entry_bytes.min(plist::MAX_EXPANDED_BYTES as u64).min(limits.max_total_bytes.saturating_sub(discovery.inventory.hashed_bytes));
            let bytes = source.read_plist(&candidate.bundle_path, &candidate.info_plist, cap)?;
            let entry = discovery.inventory.entries.get_mut(index).ok_or_else(|| ToolError::internal("The inventoried plist entry is missing."))?;
            if bytes.len() as u64 != entry.size {
                return Err(ToolError::new(ErrorCode::FileChanged, "Info.plist changed size after the directory inventory.")
                    .with_details(json!({"reason": "file_changed"})));
            }
            entry.sha256 = Some(sha256_hex(&bytes));
            entry.kind = sniff_kind(&bytes, &entry.path).into();
            entry.note = None;
            discovery.inventory.hashed_bytes = discovery.inventory.hashed_bytes.saturating_add(bytes.len() as u64);
            let value =
                plist::parse(&bytes).map_err(|error| static_input::format_err(error, "an Info.plist").with_details(json!({"reason": "plist_parse_failed"})))?;
            if !matches!(value, plist::Value::Dict(_)) {
                return Err(package_error("plist_parse_failed", "Info.plist must contain a dictionary."));
            }
            candidate.bundle_identifier = value.get("CFBundleIdentifier").and_then(plist::Value::as_str).map(str::to_string);
            candidate.bundle_name = value.get("CFBundleName").and_then(plist::Value::as_str).map(str::to_string);
            let executable = value.get("CFBundleExecutable").and_then(plist::Value::as_str).filter(|name| !name.is_empty()).ok_or_else(|| {
                package_error("missing_bundle_executable", "Info.plist has no non-empty string CFBundleExecutable; no filename fallback is used.")
            })?;
            candidate.executable_name = Some(executable.into());
            let parts =
                safe_components(executable).map_err(|reason| package_error("executable_path_escape", format!("Refused CFBundleExecutable: {reason}.")))?;
            let member = in_bundle(&candidate.bundle_path, &parts.join("/"));
            failure_path = member.clone();
            if !regular.contains_key(&member) {
                return Err(package_error("executable_not_found", "CFBundleExecutable does not name a regular file inside this candidate."));
            }
            source.check_executable(&candidate.bundle_path, &member)?;
            candidate.executable_path = Some(member);
            candidate.valid = true;
            Ok(())
        })();
        if let Err(error) = inspected {
            discovery.parse_failures.push(ParseFailure { path: failure_path, error });
        }
        discovery.candidates.push(candidate);
    }
    if discovery.candidates.is_empty() {
        let has_payload = discovery.form != PackageForm::Ipa
            || discovery.inventory.entries.iter().any(|entry| entry.path.starts_with("Payload/") || entry.path == "Payload" && entry.kind == "directory");
        discovery.parse_failures.push(ParseFailure {
            path: if discovery.form == PackageForm::Ipa { "Payload" } else { "." }.into(),
            error: package_error(
                if has_payload { "no_app_candidates" } else { "missing_payload" },
                if has_payload { "No top-level .app candidates were found." } else { "The IPA has no Payload directory." },
            ),
        });
    }
    discovery.primary_app = discovery.candidates.iter().find(|candidate| candidate.valid).map(|candidate| candidate.bundle_path.clone());
    discovery.recognized = discovery.primary_app.is_some();
    Ok(())
}

fn apple_package_discover(ctx: &mut Ctx<'_>, params: Value) -> Result<ToolOutput, ToolError> {
    let p: PackageParams = parse_params(params)?;
    let defaults = InvLimits::default();
    if p.max_entries == 0 || p.max_entries > defaults.max_entries || p.max_total_bytes == 0 || p.max_total_bytes > defaults.max_total_bytes {
        return Err(ToolError::invalid(format!("max_entries must be 1-{} and max_total_bytes 1-{}.", defaults.max_entries, defaults.max_total_bytes)));
    }
    let limits = InvLimits { max_entries: p.max_entries, max_total_bytes: p.max_total_bytes, max_depth: 0, ..defaults };
    let path = target_path(ctx, p.path.as_deref())?;
    ctx.cancel.check()?;
    let metadata = std::fs::symlink_metadata(&path).map_err(|error| ToolError::io(path.display(), error))?;
    let form = PackageForm::detect(&path, &metadata)?;
    let name = path.file_name().unwrap_or_default().to_string_lossy().into_owned();
    let mut subject = Subject { kind: "directory".into(), name: Some(name.clone()), sha256: None };
    let mut discovery = Discovery {
        form,
        recognized: false,
        primary_app: None,
        candidates: Vec::new(),
        inventory: Inventory { root: name, root_kind: if form == PackageForm::Ipa { "ipa" } else { "directory" }.into(), ..Default::default() },
        parse_failures: Vec::new(),
    };
    ctx.report(None, "Inventorying iOS package metadata");
    let source = if form == PackageForm::Ipa {
        let input = static_input::load_path(&path.to_string_lossy(), crate::target::MAX_TARGET_BYTES)?;
        subject = input.subject;
        match package_archive(&input.bytes, limits) {
            Ok(archive) => Some(archive_source(ctx, input.bytes, archive, &mut discovery.inventory, limits)?),
            Err(error) if error.code == ErrorCode::OverLimit => return Err(error),
            Err(error) => {
                discovery.inventory.truncated = true;
                discovery.parse_failures.push(ParseFailure { path: discovery.inventory.root.clone(), error });
                None
            }
        }
    } else {
        Some(directory_source(ctx, &path, &mut discovery.inventory, limits)?)
    };
    if let Some(source) = source {
        inspect_candidates(ctx, &mut discovery, &source, limits)?;
    }
    ctx.cancel.check()?;
    let mut limitations = vec![
        Limitation::new(
            "discovery_only",
            "Only package metadata and candidate Info.plists were inspected. Executable formats, contents, CRCs, encryption, signatures, platform compatibility and runtime behavior were not checked. Nothing was extracted, downloaded, decrypted, signed, installed, launched or built.",
        ),
        Limitation::new(
            "top_level_apps",
            "Only direct Payload/*.app candidates (or the selected .app) are considered; nested apps and extensions are not separate primary candidates. Links and special archive members are refused.",
        ),
    ];
    if form != PackageForm::Ipa {
        limitations.push(Limitation::new(
            "directory_snapshot",
            "Directory metadata is a live, non-atomic snapshot using the existing bounded walker, which skips .git directories. Directory subjects do not claim a whole-tree content hash.",
        ));
    }
    if discovery.candidates.iter().filter(|candidate| candidate.valid).count() > 1 {
        limitations.push(Limitation::new(
            "multiple_apps",
            "The primary is the first valid candidate in normalized, case-sensitive path order, not a claim about the publisher's intent.",
        ));
    }
    let partial = discovery.inventory.truncated || !discovery.parse_failures.is_empty();
    if partial {
        limitations.push(Limitation::new(
            "package_incomplete",
            "Package discovery is incomplete or a candidate failed inspection; consult parse_failures. Invalid candidates cannot be primary.",
        ));
    }
    let coverage = Coverage {
        status: if partial { CoverageStatus::Partial } else { CoverageStatus::Complete },
        examined: Some(discovery.candidates.len() as u64),
        total: (!discovery.inventory.truncated).then_some(discovery.candidates.len() as u64),
        next_offset: None,
    };
    let summary = format!(
        "Discovered {} top-level app candidate(s); primary: {}. {} inspection failure(s).",
        discovery.candidates.len(),
        discovery.primary_app.as_deref().unwrap_or("none"),
        discovery.parse_failures.len()
    );
    let evidence = static_input::builder(
        ctx,
        "apple_package_discover",
        subject,
        json!({"path": path, "max_entries": limits.max_entries, "max_total_bytes": limits.max_total_bytes}),
    )
    .result(serde_json::to_value(&discovery).map_err(|error| ToolError::internal(error.to_string()))?)
    .summary(summary)
    .confidence(Confidence::Derived)
    .authority(Authority::OriginalFiles)
    .limitations(limitations)
    .coverage(coverage)
    .target_content(true)
    .location(Location::new("path", path.display().to_string()))
    .build()?;
    detailed(
        ctx,
        evidence,
        p.detail,
        json!({
            "form": discovery.form, "recognized": discovery.recognized, "primary_app": discovery.primary_app,
            "counts": {
                "candidates": discovery.candidates.len(),
                "valid_candidates": discovery.candidates.iter().filter(|candidate| candidate.valid).count(),
                "parse_failures": discovery.parse_failures.len(), "members": discovery.inventory.entries.len(),
            },
        }),
    )
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn deep_member_metadata_remains_cancellable_between_members() {
        use std::cell::Cell;

        let prefix = "directory/".repeat(4_000);
        let first = format!("{prefix}first");
        let second = format!("{prefix}second");
        let bytes = craft_anything_testkit::electron::zip_stored(&[(&first, b""), (&second, b"")]);
        let members = zip::parse(&bytes, 10).unwrap().entries.into_iter().map(|entry| (entry.name.clone(), entry)).collect();
        let cancel = crate::CancelToken::default();
        let checks = Cell::new(0);
        let result = inventory_member_metadata(&members, &|| {
            checks.set(checks.get() + 1);
            if checks.get() == 2 {
                cancel.cancel();
            }
            cancel.check()
        });
        assert_eq!(result.unwrap_err().code, ErrorCode::Cancelled);
        assert_eq!(checks.get(), 2);
    }

    #[test]
    fn candidate_roots_include_empty_apps_but_not_nested_or_unrelated_bundles() {
        let inventory = Inventory {
            entries: vec![
                metadata_entry("Payload/Z.app/Info.plist".into(), 1, false),
                metadata_entry("Payload/Z.app/Watch/Nested.app/Info.plist".into(), 1, false),
                metadata_entry("Payload/A.APP".into(), 0, true),
                metadata_entry("Elsewhere/Other.app/Info.plist".into(), 1, false),
                metadata_entry("Payload/NotABundle.app".into(), 1, false),
            ],
            ..Default::default()
        };
        assert_eq!(candidate_roots(&inventory, PackageForm::Ipa), ["Payload/A.APP", "Payload/Z.app"]);
    }
}
