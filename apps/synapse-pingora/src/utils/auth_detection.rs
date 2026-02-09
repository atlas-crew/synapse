use pingora::http::RequestHeader;

/// Common auth header names to check
const AUTH_HEADERS: &[&str] = &[
    "authorization",
    "x-api-key",
    "x-auth-token",
    "x-access-token",
];

/// Session cookie names that indicate auth
const SESSION_COOKIES: &[&str] = &[
    "session",
    "sessionid",
    "sid",
    "token",
    "access_token",
    "auth",
];

/// Check if request contains any authentication headers or cookies
pub fn has_auth_header(headers: &RequestHeader) -> bool {
    // Check standard auth headers
    for header_name in AUTH_HEADERS {
        if headers.headers.get(*header_name).is_some() {
            return true;
        }
    }

    // Check for auth-related cookies
    if let Some(cookie_header) = headers.headers.get("cookie") {
        if let Ok(cookie_str) = cookie_header.to_str() {
            // Note: This is a simplistic check. Ideally we should parse cookies properly.
            // But for detection it might be enough if we just check for presence of keys.
            // Using to_lowercase on the whole string for case-insensitive check
            // and then checking if it contains "key=".
            // The spec says "Case-insensitive matching".
            // The spec implementation just does `cookie_lower.contains(session_name)`.
            // This is loose (e.g. "mysession" would match "session").
            // But adhering to the spec provided.
            let cookie_lower = cookie_str.to_lowercase();
            for session_name in SESSION_COOKIES {
                if cookie_lower.contains(session_name) {
                    return true;
                }
            }
        }
    }

    false
}

#[cfg(test)]
mod tests {
    use super::*;
    use pingora::http::RequestHeader;

    fn make_headers(pairs: &[(&'static str, &'static str)]) -> RequestHeader {
        let mut headers = RequestHeader::build("GET", b"/", None).unwrap();
        for (name, value) in pairs {
            headers.insert_header(*name, *value).unwrap();
        }
        headers
    }

    #[test]
    fn test_bearer_token() {
        let headers = make_headers(&[("authorization", "Bearer xyz123")]);
        assert!(has_auth_header(&headers));
    }

    #[test]
    fn test_api_key() {
        let headers = make_headers(&[("x-api-key", "sk-test-123")]);
        assert!(has_auth_header(&headers));
    }

    #[test]
    fn test_session_cookie() {
        let headers = make_headers(&[("cookie", "sessionid=abc123; other=value")]);
        assert!(has_auth_header(&headers));
    }

    #[test]
    fn test_no_auth() {
        let headers = make_headers(&[("content-type", "application/json")]);
        assert!(!has_auth_header(&headers));
    }

    #[test]
    fn test_unrelated_cookie() {
        let headers = make_headers(&[("cookie", "theme=dark; lang=en")]);
        assert!(!has_auth_header(&headers));
    }
}
