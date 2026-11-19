use craft_anything_engine::{CallOptions, Caller, Engine};
use craft_anything_evidence::{ErrorCode, sha256_hex};
use craft_anything_testkit::{apple, electron::zip_stored};
use serde_json::{Value, json};

fn package() -> Vec<u8> {
    let plist = apple::to_xml(&apple::dict(vec![("CFBundleIdentifier", apple::s("test.example.import")), ("CFBundleExecutable", apple::s("Main"))]));
    zip_stored(&[("Payload/Example.app/Info.plist", plist.as_bytes()), ("Payload/Example.app/Main", b"never executed")])
}

fn engine_with_cache(bytes: &[u8]) -> (Engine, String) {
    let session = craft_anything_engine::testing::session();
    let hash = sha256_hex(bytes);
    let cache = session.config_dir().join("package-imports").join(&hash);
    std::fs::create_dir_all(&cache).unwrap();
    std::fs::write(cache.join("package.ipa"), bytes).unwrap();
    (Engine::new(session), hash)
}

#[test]
fn import_requires_both_download_confirmation_and_permission_even_with_cached_bytes() {
    let (engine, hash) = engine_with_cache(&package());
    for (confirmed, authorized) in [(false, false), (true, false), (false, true)] {
        let error = engine
            .call(
                "apple_package_import",
                json!({"url":"https://downloads.example.com/Example.ipa","expected_sha256":hash,"confirmed":confirmed,"authorized":authorized}),
                CallOptions::new(Caller::Cli),
            )
            .unwrap_err();
        assert_eq!(error.code, ErrorCode::ConsentRequired);
        assert!(engine.session().active().is_err());
    }
}

#[test]
fn confirmed_cached_package_is_discovered_and_opened_without_extraction_or_execution() {
    let bytes = package();
    let (engine, hash) = engine_with_cache(&bytes);
    let params = json!({"url":"https://downloads.example.com/Example.ipa","expected_sha256":hash,"confirmed":true,"authorized":true});
    let first = engine.call("apple_package_import", params.clone(), CallOptions::new(Caller::Mcp)).unwrap().to_json();
    let second = engine.call("apple_package_import", params, CallOptions::new(Caller::Mcp)).unwrap().to_json();
    assert_eq!(first["id"], second["id"]);
    assert_eq!(first["result"]["download"]["sha256"], hash);
    assert_eq!(first["result"]["download"]["checksum_verified"], true);
    assert_eq!(first["result"]["package"]["primary_app"], "Payload/Example.app");
    assert_eq!(first["result"]["package"]["candidates"][0]["bundle_identifier"], "test.example.import");
    assert!(first["links"].as_array().unwrap().iter().any(Value::is_string));
    let session = engine.session();
    let active = &session.active().unwrap().target;
    assert_eq!(active.bytes.as_ref(), bytes);
    assert_eq!(std::fs::read_dir(active.path.parent().unwrap()).unwrap().count(), 1);
}

#[test]
fn source_preview_is_offline_for_direct_links_and_suggestions_never_start_downloads() {
    let engine = Engine::new(craft_anything_engine::testing::session());
    let sources = engine.call("apple_package_sources", json!({}), CallOptions::new(Caller::Mcp)).unwrap().to_json();
    assert!(!sources["result"]["candidates"].as_array().unwrap().is_empty());
    let direct =
        engine.call("apple_package_sources", json!({"url":"https://downloads.example.com/Example.ipa"}), CallOptions::new(Caller::Cli)).unwrap().to_json();
    assert_eq!(direct["result"]["candidates"][0]["url"], "https://downloads.example.com/Example.ipa");
    assert_eq!(direct["result"]["network_used"], false);
    assert!(!engine.session().config_dir().join("package-imports").exists());
    assert!(engine.session().active().is_err());
}

#[test]
fn publisher_page_requires_an_explicit_read_request_before_network_access() {
    let engine = Engine::new(craft_anything_engine::testing::session());
    let result =
        engine.call("apple_package_sources", json!({"url":"https://publisher.example.com/releases"}), CallOptions::new(Caller::Mcp)).unwrap().to_json();
    assert_eq!(result["result"]["needs_page_confirmation"], true);
    assert_eq!(result["result"]["network_used"], false);
    assert!(!engine.session().config_dir().join("package-imports").exists());
}

#[test]
fn invalid_or_private_links_are_refused_before_reusing_a_cached_package() {
    let (engine, hash) = engine_with_cache(&package());
    for url in [
        "http://downloads.example.com/Example.ipa",
        "file:///Example.ipa",
        "https://127.0.0.1/Example.ipa",
        "https://[::1]/Example.ipa",
        "https://10.1.2.3/Example.ipa",
        "https://localhost/Example.ipa",
        "https://user:password@downloads.example.com/Example.ipa",
    ] {
        let error = engine
            .call("apple_package_import", json!({"url":url,"expected_sha256":hash,"confirmed":true,"authorized":true}), CallOptions::new(Caller::Cli))
            .unwrap_err();
        assert_eq!(error.code, ErrorCode::BadInput, "{url}: {error}");
        assert_eq!(error.details.as_ref().unwrap()["reason"], "public_https_required");
        assert!(engine.session().active().is_err());
    }
}

#[test]
fn changed_cache_and_lowered_size_limit_are_not_successful_imports() {
    let (engine, hash) = engine_with_cache(&package());
    let path = engine.session().config_dir().join("package-imports").join(&hash).join("package.ipa");
    let params = json!({"url":"https://downloads.example.com/Example.ipa","expected_sha256":hash,"confirmed":true,"authorized":true});
    let mut limited = params.clone();
    limited["max_bytes"] = json!(1);
    let error = engine.call("apple_package_import", limited, CallOptions::new(Caller::Cli));
    assert_eq!(error.unwrap_err().code, ErrorCode::OverLimit);
    std::fs::write(&path, b"changed").unwrap();
    let error = engine.call("apple_package_import", params, CallOptions::new(Caller::Cli)).unwrap_err();
    assert_eq!(error.code, ErrorCode::FileHashMismatch);
    assert_eq!(std::fs::read(path).unwrap(), b"changed");
    assert!(engine.session().active().is_err());
}

#[test]
fn unrecognized_downloaded_content_is_not_opened_as_a_target() {
    let (engine, hash) = engine_with_cache(b"not an IPA");
    let error = engine
        .call(
            "apple_package_import",
            json!({"url":"https://downloads.example.com/Example.ipa","expected_sha256":hash,"confirmed":true,"authorized":true}),
            CallOptions::new(Caller::Cli),
        )
        .unwrap_err();
    assert_eq!(error.code, ErrorCode::NotSupported);
    assert!(engine.session().active().is_err());
}

#[test]
fn clean_room_refuses_source_reads_and_imports_before_any_parameters_or_io() {
    let mut session = craft_anything_engine::testing::session();
    session.settings.deep_mode = false;
    let engine = Engine::new(session);
    for tool in ["apple_package_sources", "apple_package_import"] {
        let error = engine.call(tool, json!({"unknown":true}), CallOptions::new(Caller::Mcp)).unwrap_err();
        assert!(craft_anything_engine::clean_room::is_refusal(&error));
    }
}

#[test]
fn rejected_credential_links_are_not_written_to_the_project_journal() {
    let root = tempfile::tempdir().unwrap();
    let mut session = craft_anything_engine::testing::session();
    let project = craft_anything_engine::project::Project::create(root.path(), "Link import", Default::default()).unwrap();
    session.open_project(project).unwrap();
    let engine = Engine::new(session);
    let error = engine
        .call(
            "apple_package_sources",
            json!({"url":"https://fake-user:fake-private-value@downloads.example.com/Example.ipa?token=fake-query-value"}),
            CallOptions::new(Caller::Cli),
        )
        .unwrap_err();
    assert_eq!(error.code, ErrorCode::BadInput);
    for entry in std::fs::read_dir(root.path().join("journal")).unwrap() {
        let contents = std::fs::read_to_string(entry.unwrap().path()).unwrap();
        for secret in ["fake-user", "fake-private-value", "fake-query-value"] {
            assert!(!contents.contains(secret));
        }
        assert!(contents.contains("package_link_request"));
    }
}

#[test]
fn cancelled_imports_do_not_create_a_download_or_change_the_active_target() {
    let engine = Engine::new(craft_anything_engine::testing::session());
    let cancel = craft_anything_engine::CancelToken::default();
    cancel.cancel();
    let error = engine
        .call(
            "apple_package_import",
            json!({"url":"https://downloads.example.com/Example.ipa","confirmed":true,"authorized":true}),
            CallOptions::new(Caller::Cli).with_cancel(cancel),
        )
        .unwrap_err();
    assert_eq!(error.code, ErrorCode::Cancelled);
    assert!(!engine.session().config_dir().join("package-imports").exists());
    assert!(engine.session().active().is_err());
}

#[cfg(unix)]
#[test]
fn symlinked_cache_roots_are_not_followed_even_when_the_expected_hash_exists() {
    let (engine, hash) = engine_with_cache(&package());
    let base = engine.session().config_dir().join("package-imports");
    let moved = engine.session().config_dir().join("outside");
    std::fs::rename(&base, &moved).unwrap();
    std::os::unix::fs::symlink(&moved, &base).unwrap();
    let error = engine
        .call(
            "apple_package_import",
            json!({"url":"https://downloads.example.com/Example.ipa","expected_sha256":hash,"confirmed":true,"authorized":true}),
            CallOptions::new(Caller::Mcp),
        )
        .unwrap_err();
    assert_eq!(error.code, ErrorCode::BadInput);
    assert!(engine.session().active().is_err());
}
