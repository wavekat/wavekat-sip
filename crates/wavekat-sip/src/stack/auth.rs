//! Digest authentication orchestration — RFC 3261 §22, RFC 2617 / 8760.
//!
//! The digest *math* (HA1/HA2, MD5/SHA-256/SHA-512, `qop=auth` with
//! `cnonce`/`nc`) is `rsip`'s [`DigestGenerator`]; reimplementing it carries
//! no product value and is easy to get subtly wrong. What we own is the
//! **orchestration**: read a `401`/`407` challenge, compute the response, and
//! build the retried request — a fresh transaction with a new `Via` branch, an
//! incremented `CSeq`, and the right `Authorization` / `Proxy-Authorization`
//! header.

use rsip::headers::auth::{Algorithm, AuthQop, Scheme};
use rsip::headers::typed::{Authorization, WwwAuthenticate};
use rsip::headers::ToTypedHeader;
use rsip::message::HeadersExt;
use rsip::services::DigestGenerator;
use rsip::{Header, Method, Request, Response, Uri};

use std::sync::atomic::{AtomicU64, Ordering};

use super::transaction::gen_branch;

/// The username/password a challenge is answered with.
pub(crate) struct Credentials<'a> {
    pub username: &'a str,
    pub password: &'a str,
}

/// Which header carries the answer, set by the challenge's status code.
#[derive(Clone, Copy, PartialEq, Eq)]
enum ChallengeKind {
    /// `401 Unauthorized` → `WWW-Authenticate` answered with `Authorization`.
    Www,
    /// `407 Proxy Authentication Required` → `Proxy-Authenticate` answered
    /// with `Proxy-Authorization`.
    Proxy,
}

/// Build the retried request that answers a `401`/`407`, or `None` if the
/// response carries no usable challenge.
///
/// The retry is a brand-new transaction: it gets a fresh `Via` branch and an
/// incremented `CSeq`, copies the original request otherwise, and adds the
/// credential header. Per RFC 3261 §22.2 the request-URI is reused as the
/// digest `uri`.
pub(crate) fn build_retry(
    original: &Request,
    response: &Response,
    creds: Credentials,
) -> Option<Request> {
    let (kind, challenge) = extract_challenge(response)?;
    let authorization = build_authorization(&challenge, &creds, original.method(), &original.uri);

    let mut retry = original.clone();
    bump_via_branch(&mut retry)?;
    bump_cseq(&mut retry)?;

    let header = match kind {
        ChallengeKind::Www => Header::Authorization(authorization.into()),
        ChallengeKind::Proxy => {
            let proxy = rsip::headers::typed::ProxyAuthorization(authorization);
            Header::ProxyAuthorization(proxy.into())
        }
    };
    retry.headers.unique_push(header);
    Some(retry)
}

/// Pull the digest challenge out of a `401`/`407`.
fn extract_challenge(response: &Response) -> Option<(ChallengeKind, WwwAuthenticate)> {
    match response.status_code().code() {
        401 => {
            let www = response.www_authenticate_header()?.typed().ok()?;
            Some((ChallengeKind::Www, www))
        }
        407 => {
            // `HeadersExt` has no proxy-authenticate accessor; find it directly.
            let proxy = response.headers.iter().find_map(|h| match h {
                Header::ProxyAuthenticate(p) => Some(p.clone()),
                _ => None,
            })?;
            let typed = proxy.typed().ok()?;
            Some((ChallengeKind::Proxy, typed.0))
        }
        _ => None,
    }
}

/// Compute the `Authorization` payload that answers `challenge`.
fn build_authorization(
    challenge: &WwwAuthenticate,
    creds: &Credentials,
    method: &Method,
    uri: &Uri,
) -> Authorization {
    let algorithm = challenge.algorithm.unwrap_or(Algorithm::Md5);
    // If the server offered a quality-of-protection, answer with `qop=auth`
    // and a fresh client nonce. `nc` is 1: each retry is a new nonce here, so
    // we never reuse a server nonce across counts.
    let qop = challenge.qop.as_ref().map(|_| AuthQop::Auth {
        cnonce: gen_cnonce(),
        nc: 1,
    });

    let response = DigestGenerator {
        username: creds.username,
        password: creds.password,
        nonce: &challenge.nonce,
        uri,
        realm: &challenge.realm,
        method,
        qop: qop.as_ref(),
        algorithm,
    }
    .compute();

    Authorization {
        scheme: Scheme::Digest,
        username: creds.username.to_string(),
        realm: challenge.realm.clone(),
        nonce: challenge.nonce.clone(),
        uri: uri.clone(),
        response,
        algorithm: Some(algorithm),
        opaque: challenge.opaque.clone(),
        qop,
    }
}

/// Replace the top `Via`'s branch with a fresh one (the retry is a new
/// transaction).
fn bump_via_branch(request: &mut Request) -> Option<()> {
    use rsip::common::uri::param::{Branch, Param};

    let mut via = request.via_header().ok()?.typed().ok()?;
    via.params.retain(|p| !matches!(p, Param::Branch(_)));
    via.params.push(Param::Branch(Branch::new(gen_branch())));
    request.headers.unique_push(Header::Via(via.into()));
    Some(())
}

/// Increment the request's `CSeq` sequence number, keeping the method.
fn bump_cseq(request: &mut Request) -> Option<()> {
    let cseq = request.cseq_header().ok()?.typed().ok()?;
    let next = rsip::typed::CSeq {
        seq: cseq.seq + 1,
        method: cseq.method,
    };
    request.headers.unique_push(Header::CSeq(next.into()));
    Some(())
}

/// Process-wide counter feeding [`gen_cnonce`].
static CNONCE_COUNTER: AtomicU64 = AtomicU64::new(0);

/// Generate a client nonce: a hard-to-predict hex token, unique per call.
/// Same randomly-seeded-hash trick as branch generation — no `rand` dep.
fn gen_cnonce() -> String {
    use std::hash::BuildHasher;
    let n = CNONCE_COUNTER.fetch_add(1, Ordering::Relaxed);
    let seed = std::collections::hash_map::RandomState::new().hash_one(n);
    format!("{n:x}{seed:016x}")
}

#[cfg(test)]
mod tests {
    use super::*;

    fn register() -> Request {
        let raw = "REGISTER sip:example.com SIP/2.0\r\n\
             Via: SIP/2.0/UDP 10.0.0.1:5060;branch=z9hG4bK-orig\r\n\
             From: <sip:alice@example.com>;tag=alice\r\n\
             To: <sip:alice@example.com>\r\n\
             Call-ID: call-reg\r\n\
             CSeq: 1 REGISTER\r\n\
             Content-Length: 0\r\n\r\n";
        Request::try_from(raw.as_bytes()).unwrap()
    }

    fn challenge_401(qop: &str, algorithm: &str) -> Response {
        let qop_param = if qop.is_empty() {
            String::new()
        } else {
            format!(", qop=\"{qop}\"")
        };
        let raw = format!(
            "SIP/2.0 401 Unauthorized\r\n\
             Via: SIP/2.0/UDP 10.0.0.1:5060;branch=z9hG4bK-orig\r\n\
             From: <sip:alice@example.com>;tag=alice\r\n\
             To: <sip:alice@example.com>;tag=srv\r\n\
             Call-ID: call-reg\r\n\
             CSeq: 1 REGISTER\r\n\
             WWW-Authenticate: Digest realm=\"example.com\", \
             nonce=\"abc123\", algorithm={algorithm}{qop_param}\r\n\
             Content-Length: 0\r\n\r\n"
        );
        Response::try_from(raw.as_bytes()).unwrap()
    }

    fn creds() -> Credentials<'static> {
        Credentials {
            username: "alice",
            password: "secret",
        }
    }

    #[test]
    fn retry_adds_authorization_and_freshens_transaction() {
        let retry = build_retry(&register(), &challenge_401("auth", "MD5"), creds()).unwrap();

        // CSeq bumped, method preserved.
        let cseq = retry.cseq_header().unwrap().typed().unwrap();
        assert_eq!(cseq.seq, 2);
        assert_eq!(cseq.method, Method::Register);

        // Fresh branch (new transaction).
        let branch = retry
            .via_header()
            .unwrap()
            .typed()
            .unwrap()
            .branch()
            .unwrap()
            .to_string();
        assert!(branch.starts_with("z9hG4bK"));
        assert_ne!(branch, "z9hG4bK-orig");

        // Authorization present, realm/nonce copied from the challenge.
        let auth = retry.authorization_header().unwrap().typed().unwrap();
        assert_eq!(auth.realm, "example.com");
        assert_eq!(auth.nonce, "abc123");
        assert!(!auth.response.is_empty());
    }

    #[test]
    fn computed_response_verifies_against_rsip() {
        // Self-consistency: the response we emit must be what rsip recomputes
        // from the same Authorization (this catches qop/cnonce/algorithm mixups).
        // We verify at the typed level. NB: rsip spells the algorithm token
        // "SHA256" (no hyphen) for both parse and Display, unlike RFC 7616's
        // "SHA-256"; MD5 — the near-universal SIP digest — is unaffected.
        let (_, challenge) = extract_challenge(&challenge_401("auth", "SHA256")).unwrap();
        let uri = register().uri;
        let auth = build_authorization(&challenge, &creds(), &Method::Register, &uri);
        assert_eq!(auth.algorithm, Some(Algorithm::Sha256));
        let generator = DigestGenerator::from(&auth, "secret", &Method::Register);
        assert!(generator.verify(&auth.response));
    }

    #[test]
    fn no_qop_still_authorizes() {
        let (_, challenge) = extract_challenge(&challenge_401("", "MD5")).unwrap();
        let uri = register().uri;
        let auth = build_authorization(&challenge, &creds(), &Method::Register, &uri);
        assert!(auth.qop.is_none());
        let generator = DigestGenerator::from(&auth, "secret", &Method::Register);
        assert!(generator.verify(&auth.response));
    }

    #[test]
    fn authorization_header_serializes_with_expected_params() {
        // The on-the-wire form the server will parse (rsip emits it via Display).
        let (_, challenge) = extract_challenge(&challenge_401("auth", "SHA256")).unwrap();
        let uri = register().uri;
        let auth = build_authorization(&challenge, &creds(), &Method::Register, &uri);
        let wire = auth.to_string();
        assert!(wire.contains("Digest username=\"alice\""));
        assert!(wire.contains("realm=\"example.com\""));
        assert!(wire.contains("algorithm=SHA256"));
        assert!(wire.contains("qop=\"auth\""));
        assert!(wire.contains("cnonce="));
    }

    #[test]
    fn proxy_challenge_uses_proxy_authorization() {
        let raw = "SIP/2.0 407 Proxy Authentication Required\r\n\
             Via: SIP/2.0/UDP 10.0.0.1:5060;branch=z9hG4bK-orig\r\n\
             From: <sip:alice@example.com>;tag=alice\r\n\
             To: <sip:alice@example.com>;tag=srv\r\n\
             Call-ID: call-reg\r\n\
             CSeq: 1 REGISTER\r\n\
             Proxy-Authenticate: Digest realm=\"proxy\", nonce=\"xyz\", qop=\"auth\"\r\n\
             Content-Length: 0\r\n\r\n";
        let response = Response::try_from(raw.as_bytes()).unwrap();
        let retry = build_retry(&register(), &response, creds()).unwrap();

        let has_proxy_auth = retry
            .headers
            .iter()
            .any(|h| matches!(h, Header::ProxyAuthorization(_)));
        assert!(has_proxy_auth);
        assert!(!retry
            .headers
            .iter()
            .any(|h| matches!(h, Header::Authorization(_))));
    }

    #[test]
    fn non_challenge_response_yields_no_retry() {
        let raw = "SIP/2.0 200 OK\r\n\
             Via: SIP/2.0/UDP 10.0.0.1:5060;branch=z9hG4bK-orig\r\n\
             From: <sip:alice@example.com>;tag=alice\r\n\
             To: <sip:alice@example.com>;tag=srv\r\n\
             Call-ID: call-reg\r\n\
             CSeq: 1 REGISTER\r\n\
             Content-Length: 0\r\n\r\n";
        let response = Response::try_from(raw.as_bytes()).unwrap();
        assert!(build_retry(&register(), &response, creds()).is_none());
    }

    #[test]
    fn cnonce_is_unique_per_call() {
        assert_ne!(gen_cnonce(), gen_cnonce());
    }
}
