//! Thin package-link controls; preview and import both dispatch through the shared engine tools.

use crate::state::{Modal, Screen};
use crate::theme::{self, Tokens};
use crate::{CraftApp, Route, tr, widgets};
use craft_anything_engine::tools::package_link_tools::{PackageLink, SourcePreview};
use craft_anything_engine::{Consent, evidence::ToolError};
use egui::{RichText, Ui};
use serde::{Deserialize, Serialize};
use serde_json::{Value, json};

#[derive(Debug, Clone, Default, PartialEq, Serialize, Deserialize)]
pub struct LinkDraft {
    pub url: String,
    pub checksum: String,
    pub authorized: bool,
    pub preview: SourcePreview,
    pub selected: Option<usize>,
    pub job: Option<u64>,
    pub error: Option<String>,
}

pub fn open(app: &mut CraftApp) {
    app.state.package_link = LinkDraft {
        preview: SourcePreview { candidates: craft_anything_engine::tools::package_link_tools::suggestions(), ..Default::default() },
        ..Default::default()
    };
    app.state.modal = Some(Modal::PackageLink);
}

pub fn preview_done(app: &mut CraftApp, job: u64, result: Result<Value, ToolError>) {
    if app.state.package_link.job != Some(job) {
        return;
    }
    let draft = &mut app.state.package_link;
    draft.job = None;
    match result.and_then(|value| serde_json::from_value::<SourcePreview>(value).map_err(|error| ToolError::internal(error.to_string()))) {
        Ok(preview) => {
            draft.preview = preview;
            draft.selected = None;
            draft.error = None;
        }
        Err(error) => draft.error = Some(error.for_people()),
    }
}

fn select(draft: &mut LinkDraft, index: usize, candidate: &PackageLink) {
    draft.url.clone_from(&candidate.url);
    draft.checksum = candidate.expected_sha256.clone().unwrap_or_default();
    draft.authorized = false;
    draft.selected = Some(index);
    draft.error = None;
}

pub fn show(app: &mut CraftApp, ui: &mut Ui, close: &mut bool) {
    let tokens = Tokens::get(ui.ctx());
    ui.label(theme::heading(tr("Import from link"), theme::SECTION));
    if !app.settings.deep_mode {
        crate::engine_ui::deep_needed(app, ui);
        return;
    }
    let height = (ui.ctx().content_rect().height() - 180.0).max(200.0);
    egui::ScrollArea::vertical().max_height(height).show(ui, |ui| {
        ui.label(RichText::new(tr("Use a direct IPA link or a public publisher page. Nothing is installed or run.")).color(tokens.text_dim));
        ui.add_space(theme::space::SM);
        let busy = app.state.package_link.job.is_some();
        ui.add_enabled_ui(!busy, |ui| {
            let response = ui.add(
                egui::TextEdit::singleline(&mut app.state.package_link.url)
                    .hint_text("https://publisher.example.com/App.ipa")
                    .desired_width(f32::INFINITY)
                    .frame(widgets::text_field_frame(&tokens)),
            );
            widgets::named(response.clone(), "Package or publisher link");
            if response.changed() {
                let draft = &mut app.state.package_link;
                draft.selected = None;
                draft.checksum.clear();
                draft.authorized = false;
                draft.preview = SourcePreview::default();
                draft.error = None;
            }
            if widgets::secondary(ui, Some("search"), "Preview link").clicked() {
                let url = app.state.package_link.url.trim().to_string();
                app.state.package_link.error = None;
                let job = app.act("apple_package_sources", json!({"url":url,"read_page":true}), tr("Find package download links"));
                app.state.package_link.job = Some(job);
            }
            ui.label(
                RichText::new(tr("Preview reads public page links only; suggested packages are not downloaded.")).size(theme::SMALL).color(tokens.text_dim),
            );
            let candidates = app.state.package_link.preview.candidates.clone();
            if !candidates.is_empty() {
                ui.add_space(theme::space::SM);
                ui.label(theme::heading(tr("Choose a package"), theme::BODY));
                for (index, candidate) in candidates.iter().enumerate() {
                    if ui.selectable_label(app.state.package_link.selected == Some(index), &candidate.name).clicked() {
                        select(&mut app.state.package_link, index, candidate);
                    }
                    ui.add(egui::Label::new(RichText::new(&candidate.url).size(theme::SMALL).color(tokens.text_dim)).wrap());
                    if let Some(license) = &candidate.license {
                        ui.label(RichText::new(license).size(theme::SMALL).color(tokens.text_dim));
                    } else {
                        ui.label(RichText::new(tr("License not verified. Review the publisher's terms.")).size(theme::SMALL).color(tokens.text_dim));
                    }
                }
            } else if app.state.package_link.preview.network_used {
                ui.label(RichText::new(tr("No static IPA links were found. Use a direct publisher download link.")).size(theme::SMALL).color(tokens.text_dim));
            } else if app.state.package_link.error.is_none() && !app.state.package_link.url.is_empty() {
                ui.label(RichText::new(tr("Preview the link, then select an available IPA package.")).size(theme::SMALL).color(tokens.text_dim));
            }
            ui.add_space(theme::space::SM);
            ui.label(tr("Expected SHA-256 (optional)"));
            let response =
                ui.add(egui::TextEdit::singleline(&mut app.state.package_link.checksum).desired_width(f32::INFINITY).frame(widgets::text_field_frame(&tokens)));
            widgets::named(response, "Expected package SHA-256");
            ui.label(RichText::new(tr("Without a trusted checksum, only a local fingerprint is recorded.")).size(theme::SMALL).color(tokens.text_dim));
            ui.checkbox(&mut app.state.package_link.authorized, tr("I have permission to download and inspect this package"));
            let draft = &app.state.package_link;
            let candidate = draft.selected.and_then(|index| draft.preview.candidates.get(index)).filter(|candidate| candidate.url == draft.url);
            let hash = draft.checksum.trim();
            let hash_ok = hash.is_empty() || hash.len() == 64 && hash.bytes().all(|byte| byte.is_ascii_hexdigit());
            if !hash_ok {
                ui.label(RichText::new(tr("Enter a 64-character hexadecimal SHA-256, or leave it empty.")).color(tokens.danger));
            }
            let target_busy = app.target_change_busy();
            if target_busy {
                ui.label(RichText::new(tr("Wait for the current target change to finish, then try again.")).color(tokens.text_dim));
            }
            let ready = candidate.is_some() && draft.authorized && hash_ok && !target_busy;
            if widgets::primary_icon(ui, Some("download"), "Download and Study", ready).clicked() {
                let source_page = candidate.and_then(|candidate| candidate.source_page.clone());
                let params = json!({
                    "url":draft.url,
                    "source_page":source_page,
                    "expected_sha256":(!hash.is_empty()).then_some(hash),
                    "confirmed":true,"authorized":true,
                });
                app.state.screen = Screen::Ask;
                app.run_tool("apple_package_import", params, Route::Chat { intro: tr("Package discovery"), cta: false }, Consent::Granted);
                *close = true;
            }
        });
        if let Some(error) = &app.state.package_link.error {
            ui.label(RichText::new(error).color(tokens.danger));
        }
        ui.add_space(theme::space::SM);
        if let Some(job) = app.state.package_link.job {
            widgets::working(ui, "Reading publisher links", None);
            if widgets::secondary(ui, None, "Cancel").clicked() {
                app.jobs.cancel(job);
            }
        } else if widgets::secondary(ui, None, "Cancel").clicked() {
            *close = true;
        }
    });
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::{Done, Route, jobs};
    use craft_anything_engine::{Engine, Mode, Session};
    use craft_anything_testkit::{apple, electron::zip_stored};
    use std::path::Path;
    use std::sync::Arc;
    use std::time::{Duration, Instant};

    fn cached_package(root: &Path, name: &str) -> (String, Value) {
        let plist = apple::to_xml(&apple::dict(vec![("CFBundleExecutable", apple::s("Main"))]));
        let bytes = zip_stored(&[(&format!("Payload/{name}.app/Info.plist"), plist.as_bytes()), (&format!("Payload/{name}.app/Main"), b"never executed")]);
        let hash = craft_anything_engine::evidence::sha256_hex(&bytes);
        let directory = root.join("package-imports").join(&hash);
        std::fs::create_dir_all(&directory).unwrap();
        std::fs::write(directory.join("package.ipa"), bytes).unwrap();
        let params = json!({"url":format!("https://example.com/{name}.ipa"),"expected_sha256":hash,"confirmed":true,"authorized":true});
        (hash, params)
    }

    fn wait_for_completion(app: &mut CraftApp) -> jobs::Finished<Done> {
        let deadline = Instant::now() + Duration::from_secs(5);
        while Instant::now() < deadline {
            let mut finished = app.jobs.poll();
            if let Some(done) = finished.pop() {
                assert!(finished.is_empty());
                return done;
            }
            std::thread::sleep(Duration::from_millis(5));
        }
        panic!("target-changing worker did not finish");
    }

    #[test]
    fn another_import_or_local_open_cannot_overtake_a_completed_unhandled_import() {
        let root = tempfile::tempdir().unwrap();
        let (first_hash, first) = cached_package(root.path(), "First");
        let (second_hash, second) = cached_package(root.path(), "Second");
        let local = root.path().join("local.txt");
        std::fs::write(&local, b"local target").unwrap();
        let mut session = Session::isolated(root.path());
        session.settings.deep_mode = true;
        session.settings.mode = Mode::Beginner;
        let mut app = crate::demo::app(Arc::new(Engine::new(session)));
        let route = Route::Chat { intro: "Import".into(), cta: false };
        app.run_tool("apple_package_import", first, route.clone(), Consent::Granted);
        let done = wait_for_completion(&mut app);
        assert_eq!(app.engine.session().active().unwrap().target.sha256, first_hash);

        // Even a late Stop cannot roll back a commit the worker already made.
        app.jobs.cancel(done.job);
        app.run_tool("apple_package_import", second.clone(), route.clone(), Consent::Granted);
        app.open_path(local);
        app.run_tool("core_target_close", json!({}), Route::Silent, Consent::NotAsked);
        assert_eq!(app.jobs.list.len(), 1);
        app.handle_done(done);
        assert_proof_matches_target(&app, &first_hash);

        app.run_tool("apple_package_import", second, route, Consent::Granted);
        let done = wait_for_completion(&mut app);
        app.handle_done(done);
        assert_proof_matches_target(&app, &second_hash);
    }

    fn assert_proof_matches_target(app: &CraftApp, hash: &str) {
        let [crate::state::ChatItem::Proof { evidence, .. }] = app.state.chat.as_slice() else {
            panic!("expected exactly one import proof");
        };
        assert_eq!(evidence.subject.sha256.as_deref(), Some(hash));
        assert_eq!(app.engine.session().active().unwrap().target.sha256, hash);
    }

    #[test]
    fn import_can_retry_after_a_worker_failure() {
        let root = tempfile::tempdir().unwrap();
        let (hash, params) = cached_package(root.path(), "Retry");
        let mut session = Session::isolated(root.path());
        session.settings.deep_mode = true;
        let mut app = crate::demo::app(Arc::new(Engine::new(session)));
        let job = app.jobs.spawn("Failed target change", true, |_| Err("worker failed".into()));
        app.target_change_job = Some(job);
        let done = wait_for_completion(&mut app);
        app.handle_done(done);
        app.run_tool("apple_package_import", params, Route::Chat { intro: "Import".into(), cta: false }, Consent::Granted);
        let done = wait_for_completion(&mut app);
        app.handle_done(done);
        assert_proof_matches_target(&app, &hash);
    }

    #[test]
    fn completed_results_from_the_previous_target_do_not_repopulate_new_target_views() {
        let mut app = crate::demo::app(crate::demo::engine(craft_anything_engine::Mode::Beginner, true));
        let previous = app.target_generation;
        app.reset_target_context(true);
        for route in [Route::Chat { intro: "Old target".into(), cta: false }, Route::View(crate::state::CenterTab::Result)] {
            app.handle_done(crate::jobs::Finished {
                job: 7,
                result: Ok(crate::Done::Tool {
                    tool: "old_target_tool".into(),
                    params: json!({}),
                    route,
                    target_generation: previous,
                    result: Ok(craft_anything_engine::ToolOutput::Value(json!({"old_target":true}))),
                }),
            });
        }
        assert!(app.state.chat.is_empty());
        assert!(app.state.views.is_empty());
    }
}
