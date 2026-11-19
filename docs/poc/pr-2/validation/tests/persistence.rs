use craft_anything_engine::evidence::sha256_hex;
use craft_anything_engine::project::Project;
use craft_anything_engine::{CallOptions, Caller, Engine, Session};
use craft_anything_pr2_proof::{PACKAGE, RELEASE, SHA256, engine, save_json};
use serde_json::json;

#[test]
fn live_import_survives_project_reopen_and_reuses_immutable_cache() {
    let root = tempfile::Builder::new()
        .prefix("craft-anything-pr2-persist-")
        .tempdir_in("/tmp")
        .unwrap();
    let engine = engine(root.path(), true);
    let params = json!({
        "url": PACKAGE, "source_page": RELEASE, "expected_sha256": SHA256,
        "confirmed": true, "authorized": true
    });
    let first = engine
        .call(
            "apple_package_import",
            params.clone(),
            CallOptions::new(Caller::Cli),
        )
        .unwrap()
        .to_json();
    assert_eq!(first["result"]["download"]["checksum_verified"], true);
    let id = first["id"].as_str().unwrap().to_string();
    let cache = root
        .path()
        .join("package-imports")
        .join(SHA256)
        .join("package.ipa");
    let before = std::fs::metadata(&cache).unwrap().modified().unwrap();
    assert_eq!(sha256_hex(&std::fs::read(&cache).unwrap()), SHA256);
    drop(engine);

    let mut reopened = Session::isolated(root.path());
    reopened.settings.deep_mode = true;
    reopened
        .open_project(Project::open(&root.path().join("proof.cany")).unwrap())
        .unwrap();
    assert_eq!(
        reopened.resolve_evidence(&id).unwrap().result["download"]["sha256"],
        SHA256
    );
    let engine = Engine::new(reopened);
    let second = engine
        .call(
            "apple_package_import",
            params,
            CallOptions::new(Caller::Mcp),
        )
        .unwrap()
        .to_json();
    assert_eq!(first["id"], second["id"]);
    assert_eq!(
        before,
        std::fs::metadata(&cache).unwrap().modified().unwrap()
    );
    assert_eq!(sha256_hex(&std::fs::read(&cache).unwrap()), SHA256);
    assert_eq!(engine.session().active().unwrap().target.sha256, SHA256);
    assert_eq!(
        std::fs::read_dir(cache.parent().unwrap()).unwrap().count(),
        1
    );
    save_json(
        "persistence-result.json",
        &json!({
            "version": 1, "network": "first import uses live public HTTPS",
            "project_reopened": true, "evidence_read_back": true,
            "same_evidence_id": first["id"], "same_sha256": SHA256,
            "cache_mtime_unchanged": true, "cache_bytes_hash_verified_twice": true,
            "cache_files": 1, "installed_or_executed": false
        }),
    );
    drop(engine);
    root.close().unwrap();
}
