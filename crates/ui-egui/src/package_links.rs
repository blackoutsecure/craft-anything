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
            let ready = candidate.is_some() && draft.authorized && hash_ok;
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
