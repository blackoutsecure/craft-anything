//! Downloads chosen by a person, with a stricter network boundary than pinned engine installs.

use crate::install::{read_download_response, write_checked};
use craft_anything_evidence::{ErrorCode, ToolError};
use craft_anything_platform::process::Cancel;
use serde::{Deserialize, Serialize};
use std::io::Write;
use std::net::{IpAddr, Ipv4Addr};
use std::path::Path;
use std::time::{Duration, Instant};
use ureq::unversioned::resolver::{DefaultResolver, ResolvedSocketAddrs, Resolver};
use ureq::unversioned::transport::{DefaultConnector, NextTimeout};
use url::Url;

pub const MAX_DOWNLOAD_BYTES: u64 = 512 << 20;
pub const DEADLINE: Duration = Duration::from_secs(120);
const REDIRECTS: usize = 5;

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Download {
    pub bytes: u64,
    /// Public destination identity; transient signed redirect queries are never retained.
    pub final_url: String,
}

fn refused() -> ToolError {
    ToolError::invalid("Use a public HTTPS publisher link without credentials, query parameters, fragments or a nonstandard port.")
        .with_remediation("Copy the publisher's stable download or release-page link, not an authenticated or signed browser URL.")
        .with_details(serde_json::json!({"reason":"public_https_required"}))
}

/// Validate the submitted public link without DNS or any other network access.
pub fn validate_url(input: &str) -> Result<Url, ToolError> {
    let url = validated_url(input, false)?;
    if url.query().is_some() || url.fragment().is_some() {
        return Err(refused());
    }
    Ok(url)
}

fn validated_url(input: &str, redirect: bool) -> Result<Url, ToolError> {
    if input.len() > 8192 || input.chars().any(|c| c.is_control() || c.is_whitespace()) {
        return Err(refused());
    }
    let url = Url::parse(input).map_err(|_| refused())?;
    if url.scheme() != "https" || !url.username().is_empty() || url.password().is_some() || url.port().is_some_and(|port| port != 443) {
        return Err(refused());
    }
    let host = url.host_str().ok_or_else(refused)?.trim_matches(['[', ']']);
    if let Ok(ip) = host.parse::<IpAddr>() {
        if !public_ip(ip) {
            return Err(refused());
        }
    } else {
        let host = host.trim_end_matches('.').to_ascii_lowercase();
        if !host.contains('.') || [".localhost", ".local", ".internal", ".home", ".test", ".invalid", ".onion"].iter().any(|suffix| host.ends_with(suffix)) {
            return Err(refused());
        }
    }
    if !redirect && url.fragment().is_some() {
        return Err(refused());
    }
    Ok(url)
}

/// Resolve one publisher link without executing page code or fetching it.
pub fn resolve_link(base: &str, relative: &str) -> Result<String, ToolError> {
    let base = validate_url(base)?;
    let joined = base.join(relative).map_err(|_| refused())?;
    validate_url(joined.as_str()).map(|url| url.to_string())
}

pub fn is_ipa(url: &str) -> bool {
    validate_url(url).is_ok_and(|url| url.path().to_ascii_lowercase().ends_with(".ipa"))
}

fn public_ip(ip: IpAddr) -> bool {
    match ip {
        IpAddr::V4(ip) => {
            let value = u32::from(ip);
            let blocked = [
                (Ipv4Addr::new(0, 0, 0, 0), 8),
                (Ipv4Addr::new(10, 0, 0, 0), 8),
                (Ipv4Addr::new(100, 64, 0, 0), 10),
                (Ipv4Addr::new(127, 0, 0, 0), 8),
                (Ipv4Addr::new(169, 254, 0, 0), 16),
                (Ipv4Addr::new(172, 16, 0, 0), 12),
                (Ipv4Addr::new(192, 0, 0, 0), 24),
                (Ipv4Addr::new(192, 0, 2, 0), 24),
                (Ipv4Addr::new(192, 88, 99, 0), 24),
                (Ipv4Addr::new(192, 168, 0, 0), 16),
                (Ipv4Addr::new(198, 18, 0, 0), 15),
                (Ipv4Addr::new(198, 51, 100, 0), 24),
                (Ipv4Addr::new(203, 0, 113, 0), 24),
                (Ipv4Addr::new(224, 0, 0, 0), 4),
                (Ipv4Addr::new(240, 0, 0, 0), 4),
            ];
            !blocked.into_iter().any(|(network, bits)| value >> (32 - bits) == u32::from(network) >> (32 - bits))
        }
        IpAddr::V6(ip) => {
            let parts = ip.segments();
            let first = parts.first().copied().unwrap_or_default();
            let second = parts.get(1).copied().unwrap_or_default();
            first & 0xe000 == 0x2000
                && first != 0x2002
                && !(first == 0x2001 && (second <= 0x01ff || second == 0x0db8))
                && !(first == 0x3fff && second & 0xf000 == 0)
        }
    }
}

#[derive(Debug, Default)]
struct PublicResolver(DefaultResolver);

impl Resolver for PublicResolver {
    fn resolve(&self, uri: &ureq::http::Uri, config: &ureq::config::Config, timeout: NextTimeout) -> Result<ResolvedSocketAddrs, ureq::Error> {
        validated_url(&uri.to_string(), true).map_err(|error| ureq::Error::Other(Box::new(error)))?;
        let addresses = self.0.resolve(uri, config, timeout)?;
        check_addresses(&addresses)?;
        Ok(addresses)
    }
}

fn check_addresses(addresses: &ResolvedSocketAddrs) -> Result<(), ureq::Error> {
    if addresses.is_empty() || addresses.iter().any(|address| !public_ip(address.ip())) {
        return Err(ureq::Error::Other(Box::new(refused())));
    }
    Ok(())
}

fn agent() -> ureq::Agent {
    let config = ureq::Agent::config_builder()
        .https_only(true)
        .proxy(None)
        .max_redirects(0)
        .http_status_as_error(false)
        .user_agent("CraftAnything-dev")
        .timeout_global(Some(DEADLINE))
        .timeout_connect(Some(Duration::from_secs(10)))
        .timeout_recv_response(Some(Duration::from_secs(15)))
        .build();
    ureq::Agent::with_parts(config, DefaultConnector::default(), PublicResolver::default())
}

/// Stream through the existing bounded response reader. No proxy or browser credentials are used.
pub fn download_to(
    url: &str,
    sink: &mut dyn Write,
    max_bytes: u64,
    cancel: Option<&Cancel>,
    progress: &dyn Fn(u64, Option<u64>),
) -> Result<Download, ToolError> {
    download_with_agent(url, sink, max_bytes, cancel, progress, &agent())
}

fn download_with_agent(
    url: &str,
    sink: &mut dyn Write,
    max_bytes: u64,
    cancel: Option<&Cancel>,
    progress: &dyn Fn(u64, Option<u64>),
    agent: &ureq::Agent,
) -> Result<Download, ToolError> {
    if max_bytes == 0 || max_bytes > MAX_DOWNLOAD_BYTES {
        return Err(ToolError::invalid(format!("max_bytes must be 1-{MAX_DOWNLOAD_BYTES}.")));
    }
    let mut current = validate_url(url)?;
    let start = Instant::now();
    for hop in 0..=REDIRECTS {
        if cancel.is_some_and(|cancel| cancel()) {
            return Err(ToolError::cancelled());
        }
        let left = DEADLINE
            .checked_sub(start.elapsed())
            .filter(|duration| !duration.is_zero())
            .ok_or_else(|| ToolError::new(ErrorCode::TimedOut, "The package download reached its deadline."))?;
        let response = agent.get(current.as_str()).config().timeout_global(Some(left)).build().call().map_err(|error| {
            if let ureq::Error::Other(cause) = &error
                && let Some(error) = cause.downcast_ref::<ToolError>()
            {
                return error.clone();
            }
            let code = if matches!(error, ureq::Error::Timeout(_)) { ErrorCode::TimedOut } else { ErrorCode::FileError };
            ToolError::new(code, "The public HTTPS source could not be read.")
                .with_remediation("Check the public publisher link and your connection; authenticated links and implicit proxies are not used.")
        })?;
        let status = response.status().as_u16();
        if matches!(status, 301 | 302 | 303 | 307 | 308) {
            if hop == REDIRECTS {
                return Err(ToolError::new(ErrorCode::OverLimit, "The source exceeded the five-redirect limit."));
            }
            let location = response
                .headers()
                .get("location")
                .and_then(|value| value.to_str().ok())
                .ok_or_else(|| ToolError::new(ErrorCode::GarbledOutput, "The download redirect has no readable destination."))?;
            let next = current.join(location).map_err(|_| refused())?;
            current = validated_url(next.as_str(), true)?;
            continue;
        }
        if !(200..300).contains(&status) {
            return Err(ToolError::new(ErrorCode::FileError, format!("The publisher source answered HTTP {status}."))
                .with_remediation("Check the direct public link or try the publisher again later.")
                .with_details(serde_json::json!({"reason":"source_http_status","status":status})));
        }
        let mut identity = current.clone();
        identity.set_query(None);
        identity.set_fragment(None);
        let final_url = identity.to_string();
        let bytes = read_download_response(response, sink, max_bytes, cancel, progress, &final_url).map_err(|error| {
            ToolError::new(
                if error.code == ErrorCode::EngineMissing { ErrorCode::FileError } else { error.code },
                match error.code {
                    ErrorCode::OverLimit => "The source exceeds the chosen byte limit.",
                    ErrorCode::Cancelled => "The download was cancelled.",
                    _ => "The source response could not be downloaded completely.",
                },
            )
            .with_remediation("Use a public publisher download that fits the limit, or choose a local package.")
        })?;
        return Ok(Download { bytes, final_url });
    }
    Err(ToolError::internal("The bounded redirect loop ended without a response."))
}

/// Use the existing checked file transaction inside a fresh, private caller-owned directory.
pub fn download_file(
    url: &str,
    destination: &Path,
    expected_sha256: Option<&str>,
    max_bytes: u64,
    cancel: Option<&Cancel>,
    progress: &dyn Fn(u64, Option<u64>),
) -> Result<Download, ToolError> {
    validate_url(url)?;
    let mut downloaded = None;
    write_checked(destination, expected_sha256, url, &mut |sink| {
        let result = download_to(url, sink, max_bytes, cancel, progress)?;
        let size = result.bytes;
        downloaded = Some(result);
        Ok(size)
    })?;
    downloaded.ok_or_else(|| ToolError::internal("The download completed without a receipt."))
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::install::download_tests::{Server, Tls};
    use std::net::SocketAddr;
    use std::sync::Arc;
    use std::sync::atomic::{AtomicBool, Ordering};

    #[derive(Debug)]
    struct FixtureResolver(SocketAddr);

    impl Resolver for FixtureResolver {
        fn resolve(&self, _: &ureq::http::Uri, _: &ureq::config::Config, _: NextTimeout) -> Result<ResolvedSocketAddrs, ureq::Error> {
            let mut addresses = self.empty();
            addresses.push(self.0);
            Ok(addresses)
        }
    }

    fn fixture_agent(server: &Server, tls: &Tls) -> ureq::Agent {
        let address: SocketAddr = format!("127.0.0.1:{}", Url::parse(&server.url).unwrap().port().unwrap()).parse().unwrap();
        let config = ureq::Agent::config_builder()
            .proxy(None)
            .https_only(true)
            .max_redirects(0)
            .http_status_as_error(false)
            .tls_config(tls.client.clone())
            .timeout_connect(Some(Duration::from_secs(2)))
            .timeout_recv_response(Some(Duration::from_millis(100)))
            .build();
        ureq::Agent::with_parts(config, DefaultConnector::default(), FixtureResolver(address))
    }

    fn payload(_: &str) -> String {
        "HTTP/1.1 200 OK\r\nContent-Length: 7\r\nConnection: close\r\n\r\npackage".into()
    }

    fn redirect(target: &str) -> String {
        format!("HTTP/1.1 302 Found\r\nLocation: {target}\r\nContent-Length: 0\r\nConnection: close\r\n\r\n")
    }

    #[test]
    fn submitted_links_refuse_local_alternate_ip_credentials_queries_and_non_https_urls() {
        for value in [
            "http://example.com/a.ipa",
            "file:///a.ipa",
            "https://127.1/a.ipa",
            "https://2130706433/a.ipa",
            "https://0x7f000001/a.ipa",
            "https://[::1]/a.ipa",
            "https://[::ffff:127.0.0.1]/a.ipa",
            "https://10.2.3.4/a.ipa",
            "https://100.64.1.1/a.ipa",
            "https://169.254.169.254/latest",
            "https://example.local/a.ipa",
            "https://user:password@example.com/a.ipa",
            "https://example.com:8443/a.ipa",
            "https://example.com/a.ipa?signature=private",
            "https://example.com/a.ipa#secret",
        ] {
            assert!(validate_url(value).is_err(), "{value}");
        }
        assert!(validate_url("https://github.com/owner/repo/releases/download/v1/Test.ipa").is_ok());
    }

    #[test]
    fn address_policy_excludes_nonpublic_v4_and_v6_ranges() {
        for address in [
            "0.0.0.0",
            "127.0.0.1",
            "192.168.1.2",
            "198.18.0.1",
            "192.0.2.1",
            "224.1.2.3",
            "::",
            "::1",
            "fc00::1",
            "fe80::1",
            "2001:db8::1",
            "2002:7f00:1::",
            "::ffff:8.8.8.8",
        ] {
            assert!(!public_ip(address.parse().unwrap()), "{address}");
        }
        for address in ["8.8.8.8", "1.1.1.1", "2606:4700:4700::1111"] {
            assert!(public_ip(address.parse().unwrap()), "{address}");
        }
    }

    #[test]
    fn cancellation_and_invalid_links_do_not_write_any_bytes() {
        let mut sink = Vec::new();
        let cancelled: Cancel = std::sync::Arc::new(|| true);
        assert_eq!(download_to("https://example.com/a.ipa", &mut sink, 1024, Some(&cancelled), &|_, _| {}).unwrap_err().code, ErrorCode::Cancelled);
        assert!(download_to("https://127.0.0.1/a.ipa", &mut sink, 1024, None, &|_, _| {}).is_err());
        assert!(sink.is_empty());
    }

    #[test]
    fn real_tls_redirects_are_checked_and_signed_queries_are_not_retained() {
        let tls = Tls::new();
        let server = Server::start(Some(tls.server.clone()), |request| {
            assert!(!request.to_ascii_lowercase().contains("authorization:"));
            assert!(!request.to_ascii_lowercase().contains("cookie:"));
            if request.starts_with("GET /start ") { redirect("/package.ipa?signature=not-for-evidence") } else { payload(request) }
        });
        let mut bytes = Vec::new();
        let result = download_with_agent("https://packages.example.com/start", &mut bytes, 4096, None, &|_, _| {}, &fixture_agent(&server, &tls)).unwrap();
        assert_eq!(bytes, b"package");
        assert_eq!(result.final_url, "https://packages.example.com/package.ipa");
        assert_eq!(server.seen.load(Ordering::SeqCst), 2);
    }

    #[test]
    fn downgrade_private_and_credential_redirects_are_refused_before_a_second_request() {
        for target in ["http://packages.example.com/secret", "https://127.0.0.1/private", "https://user:password@packages.example.com/private"] {
            let tls = Tls::new();
            let target = target.to_string();
            let server = Server::start(Some(tls.server.clone()), move |_| redirect(&target));
            let mut bytes = Vec::new();
            let error =
                download_with_agent("https://packages.example.com/start", &mut bytes, 4096, None, &|_, _| {}, &fixture_agent(&server, &tls)).unwrap_err();
            assert_eq!(error.code, ErrorCode::BadInput);
            assert_eq!(server.seen.load(Ordering::SeqCst), 1);
            assert!(bytes.is_empty());
            assert!(!format!("{error:?}").contains("password"));
        }
    }

    #[test]
    fn dns_results_must_all_be_public_before_any_of_them_can_be_used() {
        let resolver = PublicResolver::default();
        let mut addresses = resolver.empty();
        addresses.push("8.8.8.8:443".parse().unwrap());
        assert!(check_addresses(&addresses).is_ok());
        addresses.push("127.0.0.1:443".parse().unwrap());
        assert!(check_addresses(&addresses).is_err());
    }

    #[test]
    fn body_limits_and_checksum_failures_remove_only_the_owned_partial_download() {
        let tls = Tls::new();
        let server = Server::start(Some(tls.server.clone()), payload);
        let agent = fixture_agent(&server, &tls);
        let root = tempfile::tempdir().unwrap();
        let destination = root.path().join("package.ipa");
        std::fs::write(&destination, b"existing").unwrap();
        for (limit, expected, code) in [(3, None, ErrorCode::OverLimit), (4096, Some("0".repeat(64)), ErrorCode::FileHashMismatch)] {
            let result = write_checked(&destination, expected.as_deref(), "https://packages.example.com/package.ipa", &mut |sink| {
                download_with_agent("https://packages.example.com/package.ipa", sink, limit, None, &|_, _| {}, &agent).map(|result| result.bytes)
            });
            assert_eq!(result.unwrap_err().code, code);
            assert_eq!(std::fs::read(&destination).unwrap(), b"existing");
            assert!(!destination.with_extension("download").exists());
        }
    }

    #[test]
    fn cancellation_during_transfer_and_redirect_cycles_stop_with_explicit_errors() {
        let tls = Tls::new();
        let server = Server::start(Some(tls.server.clone()), payload);
        let cancelled = Arc::new(AtomicBool::new(false));
        let flag = cancelled.clone();
        let cancel: Cancel = Arc::new(move || flag.load(Ordering::SeqCst));
        let result = download_with_agent(
            "https://packages.example.com/package.ipa",
            &mut Vec::new(),
            4096,
            Some(&cancel),
            &|bytes, _| {
                if bytes > 0 {
                    cancelled.store(true, Ordering::SeqCst);
                }
            },
            &fixture_agent(&server, &tls),
        );
        assert_eq!(result.unwrap_err().code, ErrorCode::Cancelled);
        let looped = Server::start(Some(tls.server.clone()), |_| redirect("/again"));
        let error =
            download_with_agent("https://packages.example.com/again", &mut Vec::new(), 4096, None, &|_, _| {}, &fixture_agent(&looped, &tls)).unwrap_err();
        assert_eq!(error.code, ErrorCode::OverLimit);
        assert_eq!(looped.seen.load(Ordering::SeqCst), REDIRECTS + 1);
    }

    #[test]
    fn slow_responses_and_untrusted_certificates_are_not_accepted() {
        let tls = Tls::new();
        let slow = Server::start(Some(tls.server.clone()), |request| {
            std::thread::sleep(Duration::from_millis(250));
            payload(request)
        });
        let error =
            download_with_agent("https://packages.example.com/package.ipa", &mut Vec::new(), 4096, None, &|_, _| {}, &fixture_agent(&slow, &tls)).unwrap_err();
        assert_eq!(error.code, ErrorCode::TimedOut);
        let other_tls = Tls::new();
        let server = Server::start(Some(tls.server.clone()), payload);
        let error =
            download_with_agent("https://packages.example.com/package.ipa", &mut Vec::new(), 4096, None, &|_, _| {}, &fixture_agent(&server, &other_tls))
                .unwrap_err();
        assert_eq!(error.code, ErrorCode::FileError);
        assert_eq!(server.seen.load(Ordering::SeqCst), 0);
    }

    #[test]
    fn publisher_http_errors_keep_the_status_without_claiming_an_engine_is_missing() {
        let tls = Tls::new();
        let server = Server::start(Some(tls.server.clone()), |_| "HTTP/1.1 404 Not Found\r\nContent-Length: 0\r\nConnection: close\r\n\r\n".into());
        let error = download_with_agent("https://packages.example.com/package.ipa", &mut Vec::new(), 4096, None, &|_, _| {}, &fixture_agent(&server, &tls))
            .unwrap_err();
        assert_eq!(error.code, ErrorCode::FileError);
        assert_eq!(error.details.as_ref().unwrap()["status"], 404);
    }
}
