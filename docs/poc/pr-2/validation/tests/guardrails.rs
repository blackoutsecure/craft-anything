use craft_anything_engine::evidence::ErrorCode;
use craft_anything_engine::{CallOptions, Caller};
use craft_anything_pr2_proof::{PACKAGE, capture, engine, harness, save_json, wait};
use egui_kittest::kittest::Queryable;
use serde_json::json;

#[test]
fn permission_failures_leave_the_previous_target_unchanged() {
    let root = tempfile::Builder::new()
        .prefix("craft-anything-pr2-permission-")
        .tempdir_in("/tmp")
        .unwrap();
    let engine = engine(root.path(), true);
    let previous = craft_anything_engine::Target::from_bytes(
        root.path().join("previous.txt"),
        "previous.txt".into(),
        b"previous target".to_vec(),
    );
    let hash = previous.sha256.clone();
    engine.session().add_target(previous);
    for (confirmed, authorized) in [(false, false), (true, false), (false, true)] {
        let error = engine
            .call(
                "apple_package_import",
                json!({"url": PACKAGE, "confirmed": confirmed, "authorized": authorized}),
                CallOptions::new(Caller::Ui),
            )
            .unwrap_err();
        assert_eq!(error.code, ErrorCode::ConsentRequired);
        assert_eq!(engine.session().active().unwrap().target.sha256, hash);
        assert!(!root.path().join("package-imports").exists());
    }
    save_json(
        "permission-result.json",
        &json!({
            "version": 1, "permission_combinations_refused": 3,
            "error": "consent_required", "previous_target_preserved": true, "downloads": 0
        }),
    );
    drop(engine);
    root.close().unwrap();
}

#[test]
fn clean_room_keeps_import_controls_unavailable() {
    let root = tempfile::Builder::new()
        .prefix("craft-anything-pr2-clean-")
        .tempdir_in("/tmp")
        .unwrap();
    let mut h = harness(root.path(), false);
    h.state_mut().state.make.look = false;
    h.run_steps(24);
    h.get_by_label("Import from link").click();
    h.run_steps(8);
    h.get_by_label("Looking inside needs Deep mode");
    assert!(h.query_by_label("Download and Study").is_none());
    assert!(!h.state().settings.deep_mode);
    assert!(!root.path().join("package-imports").exists());
    capture(&mut h, "06-clean-room-refusal.png");
    drop(h);
    root.close().unwrap();
}

#[test]
fn private_address_preview_shows_an_error_without_downloading() {
    let root = tempfile::Builder::new()
        .prefix("craft-anything-pr2-private-")
        .tempdir_in("/tmp")
        .unwrap();
    let mut h = harness(root.path(), true);
    h.run_steps(24);
    h.get_by_label("Import from link").click();
    h.run_steps(8);
    h.get_by_label("Package or publisher link").focus();
    h.run_steps(2);
    h.get_by_label("Package or publisher link")
        .type_text("https://127.0.0.1/Example.ipa");
    h.run_steps(2);
    h.get_by_label("Preview link").click();
    wait(&mut h, |app| app.state.package_link.job.is_none());
    assert!(h.state().state.package_link.error.is_some());
    assert!(h.state().engine.session().active().is_err());
    assert!(!root.path().join("package-imports").exists());
    let error = h.state().state.package_link.error.clone().unwrap();
    h.get_by_label(&error).scroll_to_me();
    h.run_steps(8);
    capture(&mut h, "07-private-link-refusal.png");
    h.get_by_label("Cancel").click();
    h.run_steps(4);
    assert!(h.state().state.modal.is_none());
    h.get_by_label("An app or a file");
    drop(h);
    root.close().unwrap();
}
