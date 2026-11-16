use std::fmt;
use thiserror::Error;
use url::Url;

#[derive(Debug, Error)]
pub enum SecurityError {
    #[error("Invalid URL: {0}")]
    InvalidUrl(#[from] url::ParseError),
    #[error("Blocked URL scheme: {0}")]
    BlockedScheme(String),
    #[error("Cross-origin violation: expected {expected}, got {actual}")]
    CrossOrigin { expected: String, actual: String },
}

/// Canonical Site Isolation key: `(scheme, host, port)` or internal opaque origin.
#[derive(Debug, Clone, PartialEq, Eq, Hash)]
pub struct OriginKey {
    pub scheme: String,
    pub host: String,
    pub port: Option<u16>,
    pub opaque: bool,
}

impl fmt::Display for OriginKey {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        if self.opaque {
            write!(f, "null")
        } else if let Some(port) = self.port {
            write!(f, "{}://{}:{}", self.scheme, self.host, port)
        } else {
            write!(f, "{}://{}", self.scheme, self.host)
        }
    }
}

/// Validates URL scheme and extracts a Site Isolation origin key.
pub fn validate_and_extract_origin(raw_url: &str) -> Result<OriginKey, SecurityError> {
    let trimmed = raw_url.trim();
    if trimmed == "about:blank" {
        return Ok(OriginKey {
            scheme: "about".to_string(),
            host: "blank".to_string(),
            port: None,
            opaque: true,
        });
    }
    if trimmed.starts_with("rustchrome://") {
        let parsed = Url::parse(trimmed)?;
        return Ok(OriginKey {
            scheme: "rustchrome".to_string(),
            host: parsed.host_str().unwrap_or("internal").to_string(),
            port: None,
            opaque: false,
        });
    }

    let parsed = Url::parse(trimmed)?;
    match parsed.scheme() {
        "https" | "http" => {
            let host = parsed.host_str().unwrap_or("").to_ascii_lowercase();
            let port = parsed.port();
            Ok(OriginKey {
                scheme: parsed.scheme().to_string(),
                host,
                port,
                opaque: false,
            })
        }
        "data" => Ok(OriginKey {
            scheme: "data".to_string(),
            host: String::new(),
            port: None,
            opaque: true,
        }),
        other => Err(SecurityError::BlockedScheme(other.to_string())),
    }
}

/// Minimal Content-Security-Policy evaluator for script execution.
#[derive(Debug, Clone, Default)]
pub struct CspPolicy {
    pub allow_inline_script: bool,
    pub allow_eval: bool,
    pub raw_header: Option<String>,
}

impl CspPolicy {
    /// Permissive default when no CSP header is present (matches browser default).
    pub fn permissive() -> Self {
        Self {
            allow_inline_script: true,
            allow_eval: true,
            raw_header: None,
        }
    }

    /// Parses a `Content-Security-Policy` header string.
    pub fn parse(header: &str) -> Self {
        let mut script_directive: Option<&str> = None;
        let mut default_directive: Option<&str> = None;

        for part in header.split(';') {
            let trimmed = part.trim();
            if let Some(rest) = trimmed.strip_prefix("script-src") {
                script_directive = Some(rest.trim());
            } else if let Some(rest) = trimmed.strip_prefix("default-src") {
                default_directive = Some(rest.trim());
            }
        }

        let effective = script_directive.or(default_directive);
        match effective {
            None => Self {
                allow_inline_script: true,
                allow_eval: true,
                raw_header: Some(header.to_string()),
            },
            Some(tokens) => {
                let allow_inline_script = tokens.contains("'unsafe-inline'");
                let allow_eval = tokens.contains("'unsafe-eval'");
                Self {
                    allow_inline_script,
                    allow_eval,
                    raw_header: Some(header.to_string()),
                }
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn blocks_javascript_scheme() {
        assert!(matches!(
            validate_and_extract_origin("javascript:alert(1)"),
            Err(SecurityError::BlockedScheme(_))
        ));
    }

    #[test]
    fn extracts_https_origin() {
        let origin = validate_and_extract_origin("https://Example.COM:8443/path?a=1").unwrap();
        assert_eq!(origin.to_string(), "https://example.com:8443");
    }

    #[test]
    fn parses_strict_csp() {
        let csp = CspPolicy::parse("default-src 'self'; script-src 'self'");
        assert!(!csp.allow_inline_script);
        assert!(!csp.allow_eval);
    }

    #[test]
    fn parses_unsafe_inline_csp() {
        let csp = CspPolicy::parse("script-src 'self' 'unsafe-inline'");
        assert!(csp.allow_inline_script);
        assert!(!csp.allow_eval);
    }
}
