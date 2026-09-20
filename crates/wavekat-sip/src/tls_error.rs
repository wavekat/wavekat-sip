//! What we report about a certificate we refused.
//!
//! A rejected certificate drops the connection — there is no continue-anyway
//! path at any layer. What a consumer gets instead is the fingerprint it would
//! be pinning and the reason the chain failed, which is what a
//! trust-on-first-use prompt needs in order to be honest.

use std::fmt;

/// Why a server's certificate was refused.
#[derive(Debug, Clone, PartialEq, Eq)]
#[non_exhaustive]
pub enum CertFailure {
    /// The certificate's validity period has ended.
    Expired,
    /// The certificate's validity period has not begun.
    NotYetValid,
    /// The certificate is valid, but for other names. RFC 5922 §7.3 requires
    /// the account's SIP domain, not the host an SRV record named.
    NameMismatch {
        /// The names the certificate did present.
        presented: Vec<String>,
    },
    /// The chain did not reach a trusted root.
    UnknownIssuer,
    /// The issuer has revoked the certificate.
    Revoked,
    /// The certificate's signature does not verify against its issuer's key.
    BadSignature,
    /// The chain was fine, but the leaf is not the certificate pinned by
    /// [`TlsPolicy::Pinned`](crate::TlsPolicy::Pinned).
    PinMismatch,
    /// The certificate could not be parsed.
    ///
    /// Unlikely to reach a consumer in practice: a failure this early — before
    /// the verifier is even entered — leaves no fingerprint recorded and
    /// surfaces as an opaque `io::Error`, not a typed [`UntrustedCertificate`].
    /// Don't build a branch that assumes this arm fires.
    Malformed,
    /// A TLS failure this enum has no dedicated variant for. This can still
    /// be a certificate problem — one of the less common
    /// `rustls::CertificateError` variants this crate has not given its own
    /// case — in which case the message is prefixed `"certificate: "`, or it
    /// can be a non-certificate TLS failure (a protocol error, no shared
    /// cipher suite) reported as-is.
    Other(String),
}

impl fmt::Display for CertFailure {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Expired => write!(f, "certificate has expired"),
            Self::NotYetValid => write!(f, "certificate is not yet valid"),
            Self::NameMismatch { presented } => {
                write!(f, "certificate is not valid for this SIP domain")?;
                if !presented.is_empty() {
                    write!(f, " (presented: {})", presented.join(", "))?;
                }
                Ok(())
            }
            Self::UnknownIssuer => write!(f, "certificate is not signed by a trusted issuer"),
            Self::Revoked => write!(f, "certificate has been revoked"),
            Self::BadSignature => write!(f, "certificate signature does not verify"),
            Self::PinMismatch => write!(f, "certificate does not match the pinned fingerprint"),
            Self::Malformed => write!(f, "certificate could not be parsed"),
            Self::Other(msg) => write!(f, "TLS failure: {msg}"),
        }
    }
}

/// A certificate we refused, and enough about it for a consumer to decide what
/// to do next.
///
/// The fingerprint is the SHA-256 of the leaf's DER encoding — the same value
/// [`TlsPolicy::Pinned`](crate::TlsPolicy::Pinned) takes, so a consumer can
/// offer to pin exactly what it just saw. A consumer that does so is making a
/// trust-on-first-use decision, and its own UI should say plainly that an
/// attacker present at that moment is the thing being pinned.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct UntrustedCertificate {
    /// SHA-256 of the leaf certificate's DER encoding.
    pub sha256: [u8; 32],
    /// Why it was refused.
    pub reason: CertFailure,
}

impl UntrustedCertificate {
    /// The fingerprint as lowercase hex, the form a user is shown and compares.
    pub fn fingerprint_hex(&self) -> String {
        self.sha256.iter().map(|b| format!("{b:02x}")).collect()
    }
}

impl fmt::Display for UntrustedCertificate {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{} (sha256:{})", self.reason, self.fingerprint_hex())
    }
}

impl std::error::Error for UntrustedCertificate {}

/// Find an [`UntrustedCertificate`] inside an error returned by this crate.
///
/// TLS failures surface as `io::Error`s wrapping this type, which in turn reach
/// a consumer inside a boxed error. Walking the `source()` chain by hand to find
/// it is fiddly enough that the crate should just do it.
pub fn untrusted_certificate<'a>(
    err: &'a (dyn std::error::Error + 'static),
) -> Option<&'a UntrustedCertificate> {
    let mut cur = Some(err);
    while let Some(e) = cur {
        if let Some(u) = e.downcast_ref::<UntrustedCertificate>() {
            return Some(u);
        }
        if let Some(io) = e.downcast_ref::<std::io::Error>() {
            if let Some(inner) = io.get_ref() {
                if let Some(u) = inner.downcast_ref::<UntrustedCertificate>() {
                    return Some(u);
                }
            }
        }
        cur = e.source();
    }
    None
}

#[cfg(test)]
mod tests {
    use super::*;

    fn untrusted() -> UntrustedCertificate {
        UntrustedCertificate {
            sha256: [0xab; 32],
            reason: CertFailure::UnknownIssuer,
        }
    }

    #[test]
    fn fingerprint_is_lowercase_hex_of_the_full_digest() {
        let hex = untrusted().fingerprint_hex();
        assert_eq!(hex.len(), 64);
        assert!(hex.starts_with("abab"));
    }

    #[test]
    fn display_carries_the_reason_and_the_fingerprint() {
        let s = untrusted().to_string();
        assert!(s.contains("trusted issuer"), "{s}");
        assert!(s.contains("sha256:abab"), "{s}");
    }

    #[test]
    fn name_mismatch_lists_what_was_presented() {
        let f = CertFailure::NameMismatch {
            presented: vec!["edge-3.example.net".to_string()],
        };
        assert!(f.to_string().contains("edge-3.example.net"));
    }

    #[test]
    fn found_through_an_io_error_wrapper() {
        let io = std::io::Error::new(std::io::ErrorKind::InvalidData, untrusted());
        let boxed: Box<dyn std::error::Error + Send + Sync> = Box::new(io);
        let found = untrusted_certificate(boxed.as_ref()).expect("found");
        assert_eq!(found.reason, CertFailure::UnknownIssuer);
    }

    #[test]
    fn absent_from_an_unrelated_error() {
        let io = std::io::Error::other("something else");
        assert!(untrusted_certificate(&io).is_none());
    }
}
