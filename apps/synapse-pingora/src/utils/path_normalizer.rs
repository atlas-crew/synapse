use lazy_static::lazy_static;
use regex::Regex;

lazy_static! {
    // UUID: 8-4-4-4-12 hex pattern
    static ref UUID_REGEX: Regex = Regex::new(
        r"^[0-9a-fA-F]{8}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{12}$"
    ).unwrap();

    // Numeric IDs: pure digits, 1+ chars
    static ref NUMERIC_ID_REGEX: Regex = Regex::new(
        r"^\d+$"
    ).unwrap();

    // Base64-ish IDs: alphanumeric with possible padding, 16+ chars
    static ref BASE64_ID_REGEX: Regex = Regex::new(
        r"^[A-Za-z0-9_-]{16,}$"
    ).unwrap();

    // MongoDB ObjectId: 24 hex chars
    static ref OBJECTID_REGEX: Regex = Regex::new(
        r"^[0-9a-fA-F]{24}$"
    ).unwrap();
}

/// Normalize a URL path by replacing dynamic segments with {id}
pub fn normalize_path(path: &str) -> String {
    if path == "/" || path.is_empty() {
        return path.to_string();
    }

    let mut path_str = path.to_string();
    // Remove trailing slash
    if path_str.len() > 1 && path_str.ends_with('/') {
        path_str.pop();
    }

    let parts: Vec<&str> = path_str.split('/').collect();
    let mut normalized_parts = Vec::new();

    for part in parts {
        if part.is_empty() {
            normalized_parts.push(part.to_string());
            continue;
        }

        if UUID_REGEX.is_match(part) {
            normalized_parts.push("{id}".to_string());
        } else if OBJECTID_REGEX.is_match(part) {
            normalized_parts.push("{id}".to_string());
        } else if NUMERIC_ID_REGEX.is_match(part) {
            normalized_parts.push("{id}".to_string());
        } else if BASE64_ID_REGEX.is_match(part) {
            normalized_parts.push("{id}".to_string());
        } else {
            normalized_parts.push(part.to_string());
        }
    }

    normalized_parts.join("/")
}

/// Create endpoint key combining method and normalized path
pub fn endpoint_key(method: &str, path: &str) -> String {
    format!("{} {}", method.to_uppercase(), normalize_path(path))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_normalize_numeric_ids() {
        assert_eq!(normalize_path("/api/users/123"), "/api/users/{id}");
        assert_eq!(
            normalize_path("/api/users/123/posts/456"),
            "/api/users/{id}/posts/{id}"
        );
    }

    #[test]
    fn test_normalize_uuids() {
        assert_eq!(
            normalize_path("/api/orders/550e8400-e29b-41d4-a716-446655440000"),
            "/api/orders/{id}"
        );
    }

    #[test]
    fn test_normalize_objectids() {
        assert_eq!(
            normalize_path("/api/docs/507f1f77bcf86cd799439011"),
            "/api/docs/{id}"
        );
    }

    #[test]
    fn test_preserve_static_paths() {
        assert_eq!(normalize_path("/api/health"), "/api/health");
        assert_eq!(normalize_path("/api/v1/config"), "/api/v1/config");
    }

    #[test]
    fn test_root_and_empty() {
        assert_eq!(normalize_path("/"), "/");
        assert_eq!(normalize_path(""), "");
    }

    #[test]
    fn test_trailing_slash() {
        assert_eq!(normalize_path("/api/users/123/"), "/api/users/{id}");
        assert_eq!(normalize_path("/api/health/"), "/api/health");
    }

    #[test]
    fn test_endpoint_key() {
        assert_eq!(endpoint_key("GET", "/api/users/123"), "GET /api/users/{id}");
    }
}
