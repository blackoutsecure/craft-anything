use craft_anything_engine::{CallOptions, Caller, Engine, ToolOutput};
use craft_anything_evidence::{ErrorCode, Evidence, ToolError};
use craft_anything_testkit::{apple as plist, electron::zip_stored};
use serde_json::{Value, json};
use std::path::Path;

const EXECUTABLE: &[u8] = b"not executed or decoded by package discovery";

fn info(executable: Option<&str>, binary: bool) -> Vec<u8> {
    let mut fields = vec![("CFBundleIdentifier", plist::s("test.example.discovery")), ("CFBundleName", plist::s("Example"))];
    if let Some(name) = executable {
        fields.push(("CFBundleExecutable", plist::s(name)));
    }
    let value = plist::dict(fields);
    if binary { plist::to_bplist(&value) } else { plist::to_xml(&value).into_bytes() }
}

fn discover(params: Value) -> Result<Evidence, ToolError> {
    let engine = Engine::new(craft_anything_engine::testing::session());
    let ToolOutput::Evidence(record) = engine.call("apple_package_discover", params, CallOptions::new(Caller::Mcp))? else {
        panic!("package discovery must return evidence")
    };
    assert!(record.verify());
    assert!(!record.environment.clean_room);
    assert!(record.carries_target_content);
    Ok(*record)
}

fn write_ipa(root: &Path, members: &[(&str, &[u8])]) -> std::path::PathBuf {
    let path = root.join("Example.ipa");
    std::fs::write(&path, zip_stored(members)).unwrap();
    path
}

fn write_app(root: &Path, name: &str, binary: bool) -> std::path::PathBuf {
    let app = root.join(name);
    std::fs::create_dir_all(&app).unwrap();
    std::fs::write(app.join("Info.plist"), info(Some("Main"), binary)).unwrap();
    std::fs::write(app.join("Main"), EXECUTABLE).unwrap();
    app
}

fn failure(record: &Evidence, reason: &str) {
    assert!(record.result["parse_failures"].as_array().unwrap().iter().any(|entry| entry["error"]["details"]["reason"] == reason), "{record:?}");
    assert_eq!(record.coverage.status, craft_anything_evidence::CoverageStatus::Partial);
    assert!(record.limitations.iter().any(|limit| limit.code == "package_incomplete"));
}

#[test]
fn minimal_ipa_discovers_the_bundle_without_extracting_or_reading_its_executable() {
    let root = tempfile::tempdir().unwrap();
    let xml = info(Some("Main"), false);
    let path = write_ipa(root.path(), &[("Payload/Example.app/Info.plist", &xml), ("Payload/Example.app/Main", EXECUTABLE)]);
    let before = std::fs::read(&path).unwrap();
    let first = discover(json!({"path": path})).unwrap();
    let second = discover(json!({"path": path})).unwrap();
    assert_eq!(first.id, second.id);
    assert_eq!(first.result["form"], "ipa");
    assert_eq!(first.result["recognized"], true);
    assert_eq!(first.result["primary_app"], "Payload/Example.app");
    assert_eq!(first.result["candidates"][0]["executable_path"], "Payload/Example.app/Main");
    assert_eq!(first.result["candidates"][0]["bundle_identifier"], "test.example.discovery");
    assert_eq!(first.result["inventory"]["hashed_bytes"], xml.len());
    assert_eq!(first.coverage.status, craft_anything_evidence::CoverageStatus::Complete);
    assert!(first.result["parse_failures"].as_array().unwrap().is_empty());
    assert!(first.limitations.iter().any(|limit| limit.code == "discovery_only"));
    assert_eq!(std::fs::read_dir(root.path()).unwrap().count(), 1);
    assert_eq!(std::fs::read(path).unwrap(), before);
}

#[test]
fn executable_compression_and_crc_are_not_inspected_during_discovery() {
    let root = tempfile::tempdir().unwrap();
    let xml = info(Some("Main"), false);
    let mut bytes = zip_stored(&[("Payload/Example.app/Info.plist", &xml), ("Payload/Example.app/Main", EXECUTABLE)]);
    let central = bytes.windows(4).enumerate().filter(|(_, signature)| *signature == b"PK\x01\x02").nth(1).unwrap().0;
    bytes[central + 10..central + 12].copy_from_slice(&99_u16.to_le_bytes());
    bytes[central + 16..central + 20].copy_from_slice(&0_u32.to_le_bytes());
    let path = root.path().join("metadata-only.ipa");
    std::fs::write(&path, bytes).unwrap();
    let record = discover(json!({"path": path})).unwrap();
    assert_eq!(record.result["primary_app"], "Payload/Example.app");
    assert_eq!(record.result["inventory"]["hashed_bytes"], xml.len());
    assert!(record.limitations.iter().any(|limit| limit.code == "discovery_only" && limit.message.contains("CRCs")));
}

#[test]
fn direct_app_bundles_use_the_existing_xml_and_binary_plist_parser() {
    for binary in [false, true] {
        let root = tempfile::tempdir().unwrap();
        let app = write_app(root.path(), "Example.app", binary);
        let record = discover(json!({"path": app})).unwrap();
        assert_eq!(record.result["form"], "app_bundle");
        assert_eq!(record.result["primary_app"], ".");
        assert_eq!(record.result["candidates"][0]["info_plist"], "Info.plist");
        assert_eq!(record.result["candidates"][0]["executable_path"], "Main");
        assert_eq!(std::fs::read_dir(&app).unwrap().count(), 2);
    }
}

#[test]
fn extracted_payload_lists_apps_relative_to_the_selected_directory() {
    let root = tempfile::tempdir().unwrap();
    let payload = root.path().join("Payload");
    write_app(&payload, "Zulu.app", false);
    write_app(&payload, "Alpha.app", false);
    let record = discover(json!({"path": payload})).unwrap();
    assert_eq!(record.result["form"], "payload_directory");
    assert_eq!(record.result["primary_app"], "Alpha.app");
    assert_eq!(record.result["candidates"].as_array().unwrap().len(), 2);
}

#[test]
fn summary_mode_retains_every_candidate_for_later_evidence_browsing() {
    let root = tempfile::tempdir().unwrap();
    let payload = root.path().join("Payload");
    write_app(&payload, "Zulu.app", false);
    write_app(&payload, "Alpha.app", false);
    let engine = Engine::new(craft_anything_engine::testing::session());
    let complete = engine.call("apple_package_discover", json!({"path": payload}), CallOptions::new(Caller::Mcp)).unwrap();
    let output = engine.call("apple_package_discover", json!({"path": payload, "detail": "summary"}), CallOptions::new(Caller::Mcp)).unwrap();
    let ToolOutput::Value(summary) = output else { panic!("expected a compact summary") };
    assert_eq!(summary["counts"]["candidates"], 2);
    assert_eq!(summary["primary_app"], "Alpha.app");
    assert_eq!(summary["continue_with"], "core_evidence_browse");
    assert_eq!(summary["saved_evidence"]["evidence_id"], complete.to_json()["id"]);
    assert!(summary.get("inventory").is_none());
    let session = engine.session();
    let retained = session.resolve_evidence(summary["saved_evidence"]["evidence_id"].as_str().unwrap()).unwrap();
    assert!(retained.verify());
    assert_eq!(retained.result["candidates"].as_array().unwrap().len(), 2);
    assert_eq!(retained.result["inventory"]["entries"].as_array().unwrap().len(), 6);
}

#[test]
fn every_top_level_candidate_is_reported_and_primary_selection_ignores_archive_order() {
    let root = tempfile::tempdir().unwrap();
    let xml = info(Some("Main"), false);
    let mut members: Vec<(&str, &[u8])> = vec![
        ("Payload/Zulu.app/Info.plist", &xml),
        ("Payload/Zulu.app/Main", EXECUTABLE),
        ("Payload/Alpha.app/Info.plist", &xml),
        ("Payload/Alpha.app/Main", EXECUTABLE),
        ("Payload/Alpha.app/Watch/Nested.app/Info.plist", &xml),
        ("Elsewhere/Other.app/Info.plist", &xml),
        ("Payload/Empty.app/", b""),
    ];
    for _ in 0..2 {
        let path = write_ipa(root.path(), &members);
        let record = discover(json!({"path": path})).unwrap();
        assert_eq!(record.result["primary_app"], "Payload/Alpha.app");
        let candidates = record.result["candidates"].as_array().unwrap();
        assert_eq!(
            candidates.iter().map(|app| app["bundle_path"].as_str().unwrap()).collect::<Vec<_>>(),
            ["Payload/Alpha.app", "Payload/Empty.app", "Payload/Zulu.app"]
        );
        failure(&record, "missing_info_plist");
        members.reverse();
    }
}

#[test]
fn an_invalid_earlier_app_does_not_hide_a_valid_primary() {
    let root = tempfile::tempdir().unwrap();
    let xml = info(Some("Main"), false);
    let path = write_ipa(root.path(), &[("Payload/A.app/Main", EXECUTABLE), ("Payload/B.app/Info.plist", &xml), ("Payload/B.app/Main", EXECUTABLE)]);
    let record = discover(json!({"path": path})).unwrap();
    assert_eq!(record.result["primary_app"], "Payload/B.app");
    assert_eq!(record.result["candidates"][0]["valid"], false);
    assert_eq!(record.result["candidates"][1]["valid"], true);
}

#[test]
fn missing_payload_is_not_reported_as_a_successful_ios_package() {
    let root = tempfile::tempdir().unwrap();
    let path = write_ipa(root.path(), &[("Example.app/Main", EXECUTABLE)]);
    let record = discover(json!({"path": path})).unwrap();
    assert_eq!(record.result["recognized"], false);
    assert!(record.result["primary_app"].is_null());
    assert!(record.result["candidates"].as_array().unwrap().is_empty());
    failure(&record, "missing_payload");
}

#[test]
fn missing_info_plist_keeps_the_candidate_and_explains_the_failure() {
    let root = tempfile::tempdir().unwrap();
    let path = write_ipa(root.path(), &[("Payload/Example.app/Main", EXECUTABLE)]);
    let record = discover(json!({"path": path})).unwrap();
    assert_eq!(record.result["candidates"].as_array().unwrap().len(), 1);
    assert!(record.result["primary_app"].is_null());
    failure(&record, "missing_info_plist");
}

#[test]
fn missing_bundle_executable_never_falls_back_to_the_bundle_name() {
    let root = tempfile::tempdir().unwrap();
    let xml = info(None, false);
    let path = write_ipa(root.path(), &[("Payload/Example.app/Info.plist", &xml), ("Payload/Example.app/Example", EXECUTABLE)]);
    let record = discover(json!({"path": path})).unwrap();
    assert!(record.result["primary_app"].is_null());
    failure(&record, "missing_bundle_executable");
}

#[test]
fn a_named_executable_must_exist_as_a_regular_member() {
    let root = tempfile::tempdir().unwrap();
    let xml = info(Some("Main"), false);
    for members in
        [vec![("Payload/Example.app/Info.plist", xml.as_slice())], vec![("Payload/Example.app/Info.plist", xml.as_slice()), ("Payload/Example.app/Main/", b"")]]
    {
        let path = write_ipa(root.path(), &members);
        let record = discover(json!({"path": path})).unwrap();
        assert!(record.result["primary_app"].is_null());
        failure(&record, "executable_not_found");
    }
}

#[test]
fn malformed_plists_are_parse_failures_not_silent_missing_fields() {
    let root = tempfile::tempdir().unwrap();
    let path = write_ipa(root.path(), &[("Payload/Example.app/Info.plist", b"not a plist"), ("Payload/Example.app/Main", EXECUTABLE)]);
    let record = discover(json!({"path": path})).unwrap();
    failure(&record, "plist_parse_failed");
    assert!(record.result["primary_app"].is_null());
}

#[test]
fn a_plist_crc_failure_keeps_the_existing_integrity_error_contract() {
    let root = tempfile::tempdir().unwrap();
    let xml = info(Some("Main"), false);
    let mut bytes = zip_stored(&[("Payload/Example.app/Info.plist", &xml), ("Payload/Example.app/Main", EXECUTABLE)]);
    let central = bytes.windows(4).position(|signature| signature == b"PK\x01\x02").unwrap();
    bytes[central + 16..central + 20].copy_from_slice(&0_u32.to_le_bytes());
    let path = root.path().join("bad-crc.ipa");
    std::fs::write(&path, bytes).unwrap();
    let record = discover(json!({"path": path})).unwrap();
    failure(&record, "plist_crc_mismatch");
    assert_eq!(record.result["parse_failures"][0]["error"]["code"], "file_hash_mismatch");
    assert!(record.result["primary_app"].is_null());
}

#[test]
fn executable_names_cannot_escape_their_candidate_bundle() {
    let root = tempfile::tempdir().unwrap();
    for name in ["../outside", "/outside", "C:/outside", "C:outside", "..\\outside", "bin/../../outside"] {
        let xml = info(Some(name), false);
        let path = write_ipa(root.path(), &[("Payload/Example.app/Info.plist", &xml), ("Payload/outside", EXECUTABLE), ("outside", EXECUTABLE)]);
        let record = discover(json!({"path": path})).unwrap();
        failure(&record, "executable_path_escape");
        assert!(record.result["primary_app"].is_null(), "{name}");
    }
}

#[test]
fn direct_app_executable_resolution_cannot_use_a_sibling_file() {
    let root = tempfile::tempdir().unwrap();
    let app = write_app(root.path(), "Example.app", false);
    std::fs::write(root.path().join("outside"), EXECUTABLE).unwrap();
    std::fs::write(app.join("Info.plist"), info(Some("../outside"), false)).unwrap();
    let record = discover(json!({"path": app})).unwrap();
    failure(&record, "executable_path_escape");
    assert!(record.result["primary_app"].is_null());
}

#[cfg(unix)]
#[test]
fn executable_resolution_does_not_require_reading_executable_contents() {
    use std::os::unix::fs::PermissionsExt;

    let root = tempfile::tempdir().unwrap();
    let app = write_app(root.path(), "Example.app", false);
    std::fs::set_permissions(app.join("Main"), std::fs::Permissions::from_mode(0o111)).unwrap();
    let record = discover(json!({"path": app})).unwrap();
    assert_eq!(record.result["primary_app"], ".");
    assert_eq!(record.result["candidates"][0]["executable_path"], "Main");
}

#[test]
fn a_contained_executable_subdirectory_is_allowed() {
    let root = tempfile::tempdir().unwrap();
    let xml = info(Some("bin/Main"), false);
    let path = write_ipa(root.path(), &[("Payload/Example.app/Info.plist", &xml), ("Payload/Example.app/bin/Main", EXECUTABLE)]);
    let record = discover(json!({"path": path})).unwrap();
    assert_eq!(record.result["candidates"][0]["executable_path"], "Payload/Example.app/bin/Main");
}

#[test]
fn traversal_absolute_and_drive_prefix_archive_members_are_refused() {
    let root = tempfile::tempdir().unwrap();
    for name in ["../outside", "Payload/../outside", "/outside", "\\outside", "C:/outside", "C:outside", "Payload\\..\\outside"] {
        let path = write_ipa(root.path(), &[(name, b"untrusted")]);
        let error = discover(json!({"path": path})).unwrap_err();
        assert_eq!(error.code, ErrorCode::BadInput, "{name}: {error}");
        assert_eq!(error.details.as_ref().unwrap()["reason"], "unsafe_member_path");
        assert_eq!(error.details.as_ref().unwrap()["path"], name.replace('\\', "/"));
        assert!(!root.path().join("outside").exists());
    }
}

#[test]
fn duplicate_normalized_members_and_file_directory_conflicts_are_refused() {
    let root = tempfile::tempdir().unwrap();
    let xml = info(Some("Main"), false);
    for members in [
        vec![("Payload/Example.app/Info.plist", xml.as_slice()), ("Payload/Example.app/./Info.plist", xml.as_slice())],
        vec![("Payload/Example.app", b"not a directory".as_slice()), ("Payload/Example.app/Info.plist", xml.as_slice())],
        vec![
            ("Payload/Example.app", b"not a directory".as_slice()),
            ("Payload/Example.app-other/Main", EXECUTABLE),
            ("Payload/Example.app/Info.plist", xml.as_slice()),
        ],
    ] {
        let path = write_ipa(root.path(), &members);
        let error = discover(json!({"path": path})).unwrap_err();
        assert_eq!(error.details.as_ref().unwrap()["reason"], "ambiguous_member");
    }
}

#[test]
fn archive_symlinks_are_refused_without_reading_their_destination() {
    let root = tempfile::tempdir().unwrap();
    let mut bytes = zip_stored(&[("Payload/Example.app/Main", b"../../../outside")]);
    let central = bytes.windows(4).position(|signature| signature == b"PK\x01\x02").unwrap();
    bytes[central + 5] = 3;
    bytes[central + 38..central + 42].copy_from_slice(&(0o120777_u32 << 16).to_le_bytes());
    let path = root.path().join("linked.ipa");
    std::fs::write(&path, bytes).unwrap();
    let error = discover(json!({"path": path})).unwrap_err();
    assert_eq!(error.details.as_ref().unwrap()["reason"], "symlink_member");
}

#[cfg(unix)]
#[test]
fn directory_symlinks_cannot_escape_through_plists_executables_or_candidate_bundles() {
    use std::os::unix::fs::symlink;
    for member in ["Info.plist", "Main"] {
        let root = tempfile::tempdir().unwrap();
        let app = write_app(root.path(), "Example.app", false);
        let outside = root.path().join("outside");
        std::fs::write(&outside, info(Some("Main"), false)).unwrap();
        std::fs::remove_file(app.join(member)).unwrap();
        symlink(&outside, app.join(member)).unwrap();
        let error = discover(json!({"path": app})).unwrap_err();
        assert_eq!(error.details.as_ref().unwrap()["reason"], "symlink_member");
    }
    let root = tempfile::tempdir().unwrap();
    let outside = write_app(root.path(), "Outside.app", false);
    let payload = root.path().join("Payload");
    std::fs::create_dir(&payload).unwrap();
    symlink(outside, payload.join("Example.app")).unwrap();
    let error = discover(json!({"path": payload})).unwrap_err();
    assert_eq!(error.details.as_ref().unwrap()["reason"], "symlink_member");
}

#[cfg(unix)]
#[test]
fn a_root_bundle_symlink_is_refused_even_with_a_trailing_separator() {
    let root = tempfile::tempdir().unwrap();
    let app = write_app(root.path(), "Outside.app", false);
    let link = root.path().join("Linked.app");
    std::os::unix::fs::symlink(app, &link).unwrap();
    assert!(discover(json!({"path": format!("{}/", link.display())})).is_err());
}

#[test]
fn corrupt_zip_returns_structured_parse_failure_and_unknown_inventory_coverage() {
    let root = tempfile::tempdir().unwrap();
    let path = root.path().join("broken.ipa");
    std::fs::write(&path, b"PK\x03\x04broken").unwrap();
    let record = discover(json!({"path": path})).unwrap();
    assert_eq!(record.result["form"], "ipa");
    assert_eq!(record.result["recognized"], false);
    assert!(record.result["primary_app"].is_null());
    assert!(record.coverage.total.is_none());
    failure(&record, "invalid_zip");
}

#[test]
fn under_declared_zip_members_cannot_hide_apps_or_unsafe_paths() {
    let root = tempfile::tempdir().unwrap();
    let xml = info(Some("Main"), false);
    for hidden_path in [None, Some("../outside")] {
        let mut members: Vec<(&str, &[u8])> = vec![
            ("Payload/A.app/Info.plist", &xml),
            ("Payload/A.app/Main", EXECUTABLE),
            ("Payload/B.app/Info.plist", &xml),
            ("Payload/B.app/Main", EXECUTABLE),
        ];
        if let Some(path) = hidden_path {
            members.push((path, b"not inspected"));
        }
        for declared in [2_u16, 0] {
            let mut bytes = zip_stored(&members);
            let end = bytes.len() - 22;
            bytes[end + 8..end + 10].copy_from_slice(&declared.to_le_bytes());
            bytes[end + 10..end + 12].copy_from_slice(&declared.to_le_bytes());
            let path = root.path().join("under-declared.ipa");
            std::fs::write(&path, bytes).unwrap();
            let record = discover(json!({"path": path})).unwrap();
            failure(&record, "invalid_zip");
            assert_eq!(record.result["recognized"], false);
            assert!(record.result["primary_app"].is_null());
            assert!(record.coverage.total.is_none());
        }
    }
}

#[test]
fn archive_member_and_decompressed_size_limits_are_checked_before_plist_reads() {
    let root = tempfile::tempdir().unwrap();
    let xml = info(Some("Main"), false);
    let path = write_ipa(root.path(), &[("Payload/Example.app/Info.plist", &xml), ("Payload/Example.app/Main", EXECUTABLE)]);
    let bytes = xml.len() + EXECUTABLE.len();
    for params in [json!({"path": path, "max_entries": 1}), json!({"path": path, "max_total_bytes": bytes - 1})] {
        let error = discover(params).unwrap_err();
        assert_eq!(error.code, ErrorCode::OverLimit);
        assert!(error.details.is_some());
    }
    let record = discover(json!({"path": path, "max_entries": 2, "max_total_bytes": bytes})).unwrap();
    assert_eq!(record.result["primary_app"], "Payload/Example.app");
}

#[test]
fn a_single_member_cannot_exceed_the_existing_inventory_entry_limit() {
    let root = tempfile::tempdir().unwrap();
    let mut bytes = zip_stored(&[("Payload/Example.app/Info.plist", b"small")]);
    let central = bytes.windows(4).position(|signature| signature == b"PK\x01\x02").unwrap();
    let oversized = u32::try_from(craft_anything_analysis::js_inventory::InvLimits::default().max_entry_bytes + 1).unwrap();
    bytes[central + 24..central + 28].copy_from_slice(&oversized.to_le_bytes());
    let path = root.path().join("oversized.ipa");
    std::fs::write(&path, bytes).unwrap();
    assert_eq!(discover(json!({"path": path})).unwrap_err().code, ErrorCode::OverLimit);
}

#[test]
fn clean_room_refuses_before_parameter_validation_or_filesystem_and_archive_access() {
    let root = tempfile::tempdir().unwrap();
    let mut session = craft_anything_engine::testing::session();
    session.settings.deep_mode = false;
    let engine = Engine::new(session);
    for caller in [Caller::Cli, Caller::Mcp] {
        let error = engine
            .call("apple_package_discover", json!({"path": root.path().join("does-not-exist.ipa"), "unknown": true}), CallOptions::new(caller))
            .unwrap_err();
        assert!(craft_anything_engine::clean_room::is_refusal(&error), "{error}");
        assert_eq!(std::fs::read_dir(root.path()).unwrap().count(), 0);
    }
}
