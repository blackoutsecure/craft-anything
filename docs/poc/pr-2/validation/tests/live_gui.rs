use craft_anything_pr2_proof::{PACKAGE, RELEASE, SHA256, capture, harness, save_json, wait};
use craft_anything_ui_egui::state::{ChatItem, Modal, Screen};
use egui_kittest::kittest::Queryable;
use serde_json::json;

#[test]
fn live_publisher_preview_permission_download_and_evidence() {
    let root = tempfile::Builder::new()
        .prefix("craft-anything-pr2-live-")
        .tempdir_in("/tmp")
        .unwrap();
    let mut h = harness(root.path(), true);
    h.run_steps(24);
    h.get_by_label("Import from link");
    capture(&mut h, "01-study-entry.png");

    h.get_by_label("Import from link").click();
    h.run_steps(8);
    assert_eq!(h.state().state.modal, Some(Modal::PackageLink));
    assert!(!h.state().state.package_link.authorized);
    assert!(!root.path().join("package-imports").exists());
    capture(&mut h, "02-source-review-no-download.png");

    h.get_by_label("Package or publisher link").focus();
    h.run_steps(2);
    h.get_by_label("Package or publisher link")
        .type_text(RELEASE);
    h.run_steps(2);
    h.get_by_label("Preview link").click();
    wait(&mut h, |app| app.state.package_link.job.is_none());
    assert!(
        h.state().state.package_link.error.is_none(),
        "{:?}",
        h.state().state.package_link.error
    );
    let preview = &h.state().state.package_link.preview;
    assert!(preview.network_used);
    assert_eq!(preview.candidates.len(), 7);
    assert!(!root.path().join("package-imports").exists());
    assert!(h.state().engine.session().active().is_err());
    save_json(
        "publisher-preview.json",
        &serde_json::to_value(preview).unwrap(),
    );
    capture(&mut h, "03-live-publisher-preview.png");

    h.get_by_label("UTM-Remote.ipa").scroll_to_me();
    h.run_steps(8);
    h.get_by_label("UTM-Remote.ipa").click();
    h.run_steps(4);
    assert_eq!(h.state().state.package_link.url, PACKAGE);
    assert_eq!(h.state().state.package_link.checksum, SHA256);
    assert!(!h.state().state.package_link.authorized);
    h.get_by_label("Preview link").scroll_to_me();
    h.run_steps(8);
    h.get_by_label("Preview link").click();
    wait(&mut h, |app| app.state.package_link.job.is_none());
    assert_eq!(h.state().state.package_link.preview.candidates.len(), 1);
    assert!(!h.state().state.package_link.preview.network_used);
    h.get_by_label("UTM Remote 5.0.9 (iPhone/iPad)")
        .scroll_to_me();
    h.run_steps(4);
    h.get_by_label("UTM Remote 5.0.9 (iPhone/iPad)").click();
    h.run_steps(4);
    assert_eq!(h.state().state.package_link.url, PACKAGE);
    assert_eq!(h.state().state.package_link.checksum, SHA256);
    h.get_by_label("I have permission to download and inspect this package")
        .scroll_to_me();
    h.run_steps(4);
    h.get_by_label("I have permission to download and inspect this package")
        .click();
    h.run_steps(4);
    assert!(h.state().state.package_link.authorized);
    assert!(!root.path().join("package-imports").exists());
    capture(&mut h, "04-checksum-and-explicit-permission.png");

    h.get_by_label("Download and Study").scroll_to_me();
    h.run_steps(4);
    h.get_by_label("Download and Study").click();
    wait(&mut h, |app| {
        app.state.chat.iter().any(|entry| {
            matches!(entry, ChatItem::Proof { evidence, .. } if evidence.operation == "apple_package_import")
                || matches!(entry, ChatItem::Error { .. })
        })
    });
    let evidence = h
        .state()
        .state
        .chat
        .iter()
        .find_map(|entry| match entry {
            ChatItem::Proof { evidence, .. } if evidence.operation == "apple_package_import" => {
                Some((**evidence).clone())
            }
            _ => None,
        })
        .unwrap_or_else(|| {
            panic!(
                "The live UI import failed: {}",
                serde_json::to_string(&h.state().state.chat).unwrap()
            )
        });
    assert_eq!(h.state().state.screen, Screen::Ask);
    assert!(h.state().state.modal.is_none());
    assert!(evidence.verify());
    assert_eq!(evidence.result["download"]["sha256"], SHA256);
    assert_eq!(evidence.result["download"]["checksum_verified"], true);
    assert_eq!(evidence.result["package"]["recognized"], true);
    assert_eq!(
        h.state().engine.session().active().unwrap().target.sha256,
        SHA256
    );
    assert_eq!(
        std::fs::read_dir(root.path().join("package-imports"))
            .unwrap()
            .count(),
        1
    );
    let cache = root.path().join("package-imports").join(SHA256);
    assert_eq!(std::fs::read_dir(&cache).unwrap().count(), 1);
    let stored =
        craft_anything_engine::project::Project::open(&root.path().join("proof.cany")).unwrap();
    assert_eq!(stored.load_evidence(&evidence.id).unwrap(), evidence);
    h.get_by_label_contains("Imported an authorized package; primary app:");
    capture(&mut h, "05-live-import-proof.png");

    save_json(
        "live-gui-result.json",
        &json!({
            "version": 1,
            "source_revision": "694929b0f62396c17aa3d211b30d649660f51484",
            "ui": "actual egui controls, offscreen wgpu rendering",
            "network": "live public HTTPS, no mock or seeded package cache",
            "publisher_preview_candidates": 7,
            "preview_created_no_package_cache": true,
            "permission_required_and_confirmed": true,
            "evidence_id": evidence.id,
            "evidence_integrity_verified": evidence.verify(),
            "download": evidence.result["download"],
            "primary_app": evidence.result["package"]["primary_app"],
            "candidates": evidence.result["package"]["candidates"],
            "active_target_sha256": SHA256,
            "project_evidence_read_back": true,
            "cache_entries": 1,
            "files_in_cache_entry": 1,
            "installed_or_executed": false
        }),
    );
    drop(h);
    root.close().unwrap();
}
