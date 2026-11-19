use craft_anything_engine::project::Project;
use craft_anything_engine::{Engine, Mode, Session};
use craft_anything_ui_egui::{CraftApp, demo};
use egui_kittest::Harness;
use std::path::{Path, PathBuf};
use std::sync::Arc;
use std::time::{Duration, Instant};

pub const RELEASE: &str = "https://github.com/utmapp/UTM/releases/tag/v5.0.9-2";
pub const PACKAGE: &str = "https://github.com/utmapp/UTM/releases/download/v5.0.9-2/UTM-Remote.ipa";
pub const SHA256: &str = "1b0911ebb7675312518c6e592a9d8d478688f893b5d500125ed2d5d434f69c0b";

pub fn engine(config: &Path, deep: bool) -> Engine {
    let mut session = Session::isolated(config);
    session.settings.deep_mode = deep;
    session.settings.first_run_done = true;
    session.settings.mode = Mode::Beginner;
    session.settings.language = "en".into();
    session.settings.engines.only_configured = true;
    let project = Project::create(
        &config.join("proof.cany"),
        "Package link POC",
        Default::default(),
    )
    .unwrap();
    session.open_project(project).unwrap();
    Engine::new(session)
}

pub fn harness(config: &Path, deep: bool) -> Harness<'static, CraftApp> {
    let engine = Arc::new(engine(config, deep));
    Harness::builder()
        .with_size(egui::vec2(1440.0, 1240.0))
        .with_pixels_per_point(1.5)
        .with_max_steps(64)
        .wgpu()
        .build_eframe(move |context| {
            CraftApp::setup_context(&context.egui_ctx);
            let mut app = demo::app(engine);
            app.backends.clear();
            app.settings.recent.clear();
            app.settings.projects_dir = Some(PathBuf::from("~/Documents/Craft Anything"));
            app.state.backend = None;
            app.state.make.look = true;
            app
        })
}

pub fn wait(h: &mut Harness<'static, CraftApp>, done: impl Fn(&CraftApp) -> bool) {
    let start = Instant::now();
    while start.elapsed() < Duration::from_secs(150) {
        h.step();
        if done(h.state()) {
            h.run_steps(12);
            return;
        }
        std::thread::sleep(Duration::from_millis(10));
    }
    panic!(
        "UI worker timed out; chat={}",
        serde_json::to_string(&h.state().state.chat).unwrap()
    );
}

pub fn output(name: &str) -> PathBuf {
    let directory =
        PathBuf::from(std::env::var_os("POC_EVIDENCE_DIR").expect("POC_EVIDENCE_DIR must be set"));
    std::fs::create_dir_all(&directory).unwrap();
    directory.join(name)
}

pub fn capture(h: &mut Harness<'static, CraftApp>, name: &str) {
    h.run_steps(16);
    let image = h.render().expect("The actual egui scene must render");
    image
        .save(output(name))
        .expect("The screenshot must be saved");
    println!("SCREENSHOT {name}: {}x{}", image.width(), image.height());
}

pub fn save_json(name: &str, value: &serde_json::Value) {
    std::fs::write(output(name), serde_json::to_vec_pretty(value).unwrap()).unwrap();
}
