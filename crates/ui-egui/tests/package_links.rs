use craft_anything_engine::{Engine, Mode};
use craft_anything_testkit::{apple, electron::zip_stored};
use craft_anything_ui_egui::state::{ChatItem, Modal, Screen};
use craft_anything_ui_egui::{CraftApp, demo};
use egui_kittest::Harness;
use egui_kittest::kittest::Queryable;
use std::path::Path;
use std::sync::Arc;
use std::time::{Duration, Instant};

fn harness(config: &Path, deep: bool) -> Harness<'static, CraftApp> {
    let mut session = craft_anything_engine::Session::isolated(config);
    session.settings.deep_mode = deep;
    session.settings.first_run_done = true;
    session.settings.mode = Mode::Beginner;
    session.settings.language = "en".into();
    let engine = Arc::new(Engine::new(session));
    Harness::builder().with_size(egui::vec2(1280.0, 1000.0)).with_max_steps(32).build_eframe(move |context| {
        CraftApp::setup_context(&context.egui_ctx);
        let mut app = demo::app(engine);
        app.state.make.look = true;
        app
    })
}

fn wait(harness: &mut Harness<'static, CraftApp>, done: impl Fn(&CraftApp) -> bool) {
    let start = Instant::now();
    while start.elapsed() < Duration::from_secs(10) {
        harness.step();
        if done(harness.state()) {
            return;
        }
        std::thread::sleep(Duration::from_millis(10));
    }
    panic!("the expected UI worker result did not arrive");
}

#[test]
fn import_dialog_previews_selects_confirms_and_studies_through_the_shared_engine() {
    let root = tempfile::tempdir().unwrap();
    let plist = apple::to_xml(&apple::dict(vec![("CFBundleIdentifier", apple::s("test.example.ui-import")), ("CFBundleExecutable", apple::s("Main"))]));
    let bytes = zip_stored(&[("Payload/Example.app/Info.plist", plist.as_bytes()), ("Payload/Example.app/Main", b"never executed")]);
    let hash = craft_anything_engine::evidence::sha256_hex(&bytes);
    let directory = root.path().join("package-imports").join(&hash);
    std::fs::create_dir_all(&directory).unwrap();
    std::fs::write(directory.join("package.ipa"), bytes).unwrap();
    let mut h = harness(root.path(), true);
    h.run_steps(3);
    h.get_by_label("An app or a file");
    h.get_by_label("Import from link").click();
    h.run_steps(3);
    assert_eq!(h.state().state.modal, Some(Modal::PackageLink));
    assert!(!h.state().state.package_link.authorized);
    assert!(h.state().engine.session().active().is_err());
    h.get_by_label("Package or publisher link").focus();
    h.run_steps(2);
    h.get_by_label("Package or publisher link").type_text("https://downloads.example.com/Example.ipa");
    h.run_steps(2);
    h.get_by_label("Preview link").click();
    wait(&mut h, |app| app.state.package_link.job.is_none() && !app.state.package_link.preview.candidates.is_empty());
    assert!(!h.state().state.package_link.preview.network_used);
    h.get_by_label("License not verified. Review the publisher's terms.");
    h.get_by_label("Example.ipa").click();
    h.run();
    h.get_by_label("Expected package SHA-256").scroll_to_me();
    h.run();
    h.get_by_label("Expected package SHA-256").focus();
    h.run();
    h.get_by_label("Expected package SHA-256").type_text(&hash);
    h.run();
    assert_eq!(h.state().state.package_link.checksum, hash);
    h.get_by_label("I have permission to download and inspect this package").scroll_to_me();
    h.run();
    h.get_by_label("I have permission to download and inspect this package").click();
    h.run();
    assert_eq!(h.state().state.modal, Some(Modal::PackageLink));
    assert!(h.state().state.package_link.authorized);
    h.get_by_label("Download and Study").scroll_to_me();
    h.run();
    h.get_by_label("Download and Study").click();
    wait(&mut h, |app| app.state.chat.iter().any(|entry| matches!(entry, ChatItem::Proof { evidence, .. } if evidence.operation == "apple_package_import")));
    assert_eq!(h.state().state.screen, Screen::Ask);
    assert!(h.state().state.modal.is_none());
    assert_eq!(h.state().engine.session().active().unwrap().target.sha256, hash);
    assert_eq!(std::fs::read_dir(&directory).unwrap().count(), 1);
}

#[test]
fn cancelling_a_suggestion_does_not_download_or_replace_the_local_input_flow() {
    let root = tempfile::tempdir().unwrap();
    let mut h = harness(root.path(), true);
    h.run_steps(3);
    h.get_by_label("Import from link").click();
    h.run_steps(2);
    h.get_by_label("UTM Remote 5.0.9 (iPhone/iPad)").click();
    h.run_steps(2);
    assert!(!h.state().state.package_link.authorized);
    h.get_by_label("Cancel").click();
    h.run_steps(2);
    assert!(h.state().state.modal.is_none());
    assert!(h.state().engine.session().active().is_err());
    assert!(!root.path().join("package-imports").exists());
    h.get_by_label("An app or a file");
    h.get_by_label("A website");
}

#[test]
fn clean_room_does_not_offer_download_controls_or_enable_deep_mode_implicitly() {
    let root = tempfile::tempdir().unwrap();
    let mut h = harness(root.path(), false);
    h.state_mut().state.make.look = false;
    h.run_steps(3);
    h.get_by_label("Import from link").click();
    h.run_steps(2);
    h.get_by_label("Looking inside needs Deep mode");
    assert!(h.query_by_label("Download and Study").is_none());
    assert!(!h.state().settings.deep_mode);
    assert!(!root.path().join("package-imports").exists());
}

#[test]
fn a_private_link_preview_reports_the_error_without_a_download() {
    let root = tempfile::tempdir().unwrap();
    let mut h = harness(root.path(), true);
    h.run_steps(3);
    h.get_by_label("Import from link").click();
    h.run_steps(2);
    h.get_by_label("Package or publisher link").focus();
    h.run_steps(2);
    h.get_by_label("Package or publisher link").type_text("https://127.0.0.1/Example.ipa");
    h.run_steps(2);
    h.get_by_label("Preview link").click();
    wait(&mut h, |app| app.state.package_link.job.is_none() && app.state.package_link.error.is_some());
    assert!(h.state().state.package_link.preview.candidates.is_empty());
    assert!(!root.path().join("package-imports").exists());
    assert!(h.state().engine.session().active().is_err());
}
