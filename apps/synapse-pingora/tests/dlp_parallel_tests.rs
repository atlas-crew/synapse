//! Parallel execution stress tests for DLP scanner
//!
//! These tests verify thread-safety and correctness under concurrent load.

use std::sync::Arc;
use std::thread;

use synapse_pingora::{DlpScanner, DlpConfig};

// ============================================================================
// Test Helpers
// ============================================================================

fn create_test_scanner() -> DlpScanner {
    DlpScanner::new(DlpConfig::default())
}

fn create_scanner_with_config(enabled: bool) -> DlpScanner {
    DlpScanner::new(DlpConfig {
        enabled,
        ..Default::default()
    })
}

// Sample content with sensitive data
const CREDIT_CARD_CONTENT: &str = "Payment details: 4111111111111111";
const SSN_CONTENT: &str = "SSN: 123-45-6789";
const MIXED_CONTENT: &str = "Card: 4111111111111111, SSN: 123-45-6789, Email: test@example.com";
const CLEAN_CONTENT: &str = "This is a clean document with no sensitive data.";

// ============================================================================
// Basic Thread Safety Tests
// ============================================================================

#[test]
fn test_concurrent_scans_no_panic() {
    let scanner = Arc::new(create_test_scanner());
    let mut handles = vec![];

    // Spawn 10 threads, each performing 100 scans
    for thread_id in 0..10 {
        let scanner = Arc::clone(&scanner);
        handles.push(thread::spawn(move || {
            for i in 0..100 {
                let content = match i % 4 {
                    0 => CREDIT_CARD_CONTENT,
                    1 => SSN_CONTENT,
                    2 => MIXED_CONTENT,
                    _ => CLEAN_CONTENT,
                };
                let result = scanner.scan(content);
                assert!(result.scanned, "Thread {} scan {} should complete", thread_id, i);
            }
        }));
    }

    // Wait for all threads to complete
    for handle in handles {
        handle.join().expect("Thread should not panic");
    }

    // Verify total scans counted correctly
    let stats = scanner.stats();
    assert_eq!(stats.total_scans, 1000, "Should have counted 1000 total scans");
}

#[test]
fn test_concurrent_scans_match_count_consistency() {
    let scanner = Arc::new(create_test_scanner());
    let mut handles = vec![];

    // All threads scan the same content with known matches
    for _ in 0..10 {
        let scanner = Arc::clone(&scanner);
        handles.push(thread::spawn(move || {
            for _ in 0..100 {
                let result = scanner.scan(CREDIT_CARD_CONTENT);
                assert!(result.has_matches, "Should find credit card");
                assert!(result.match_count > 0, "Match count should be positive");
            }
        }));
    }

    for handle in handles {
        handle.join().expect("Thread should not panic");
    }

    let stats = scanner.stats();
    assert!(stats.total_matches > 0, "Should have accumulated matches");
}

// ============================================================================
// Race Condition Tests
// ============================================================================

#[test]
fn test_stats_atomic_updates() {
    let scanner = Arc::new(create_test_scanner());
    let mut handles = vec![];

    // Many threads incrementing stats concurrently
    for _ in 0..20 {
        let scanner = Arc::clone(&scanner);
        handles.push(thread::spawn(move || {
            for _ in 0..50 {
                scanner.scan(CREDIT_CARD_CONTENT);
            }
        }));
    }

    for handle in handles {
        handle.join().expect("Thread should not panic");
    }

    let stats = scanner.stats();
    assert_eq!(stats.total_scans, 1000, "Atomic counter should equal exact number of scans");
}

#[test]
fn test_concurrent_mixed_workload() {
    let scanner = Arc::new(create_test_scanner());
    let mut handles = vec![];

    // Different threads doing different operations
    for thread_id in 0..8 {
        let scanner = Arc::clone(&scanner);
        handles.push(thread::spawn(move || {
            match thread_id % 4 {
                0 => {
                    // Heavy scan workload
                    for _ in 0..200 {
                        let _ = scanner.scan(MIXED_CONTENT);
                    }
                }
                1 => {
                    // Clean content workload
                    for _ in 0..300 {
                        let _ = scanner.scan(CLEAN_CONTENT);
                    }
                }
                2 => {
                    // Stats reading workload
                    for _ in 0..500 {
                        let _ = scanner.stats();
                    }
                }
                _ => {
                    // Mixed scan and stats
                    for i in 0..100 {
                        if i % 2 == 0 {
                            let _ = scanner.scan(SSN_CONTENT);
                        } else {
                            let _ = scanner.stats();
                        }
                    }
                }
            }
        }));
    }

    for handle in handles {
        handle.join().expect("Thread should not panic");
    }
}

// ============================================================================
// Edge Case Tests
// ============================================================================

#[test]
fn test_empty_content_concurrent() {
    let scanner = Arc::new(create_test_scanner());
    let mut handles = vec![];

    for _ in 0..10 {
        let scanner = Arc::clone(&scanner);
        handles.push(thread::spawn(move || {
            for _ in 0..100 {
                let result = scanner.scan("");
                assert!(result.scanned);
                assert!(!result.has_matches);
            }
        }));
    }

    for handle in handles {
        handle.join().expect("Thread should not panic");
    }
}

#[test]
fn test_large_content_concurrent() {
    let scanner = Arc::new(create_test_scanner());
    let large_content: String = "x".repeat(10_000) + " 4111111111111111 " + &"y".repeat(10_000);
    let large_content = Arc::new(large_content);
    let mut handles = vec![];

    for _ in 0..5 {
        let scanner = Arc::clone(&scanner);
        let content = Arc::clone(&large_content);
        handles.push(thread::spawn(move || {
            for _ in 0..20 {
                let result = scanner.scan(&content);
                assert!(result.scanned);
            }
        }));
    }

    for handle in handles {
        handle.join().expect("Thread should not panic");
    }
}

#[test]
fn test_disabled_scanner_concurrent() {
    let scanner = Arc::new(create_scanner_with_config(false));
    let mut handles = vec![];

    for _ in 0..10 {
        let scanner = Arc::clone(&scanner);
        handles.push(thread::spawn(move || {
            for _ in 0..100 {
                let result = scanner.scan(CREDIT_CARD_CONTENT);
                assert!(!result.scanned, "Disabled scanner should not scan");
                assert!(!result.has_matches);
            }
        }));
    }

    for handle in handles {
        handle.join().expect("Thread should not panic");
    }
}

// ============================================================================
// Stress Tests
// ============================================================================

#[test]
fn test_high_concurrency_stress() {
    let scanner = Arc::new(create_test_scanner());
    let mut handles = vec![];

    // 50 threads, 200 scans each = 10,000 total scans
    for _ in 0..50 {
        let scanner = Arc::clone(&scanner);
        handles.push(thread::spawn(move || {
            for _ in 0..200 {
                let _ = scanner.scan(MIXED_CONTENT);
            }
        }));
    }

    for handle in handles {
        handle.join().expect("Thread should not panic");
    }

    let stats = scanner.stats();
    assert_eq!(stats.total_scans, 10_000, "All scans should be counted");
}

#[test]
fn test_rapid_scanner_creation() {
    // Test that creating many scanners concurrently doesn't cause issues
    let mut handles = vec![];

    for _ in 0..10 {
        handles.push(thread::spawn(|| {
            for _ in 0..50 {
                let scanner = create_test_scanner();
                let result = scanner.scan(CREDIT_CARD_CONTENT);
                assert!(result.scanned);
            }
        }));
    }

    for handle in handles {
        handle.join().expect("Thread should not panic");
    }
}

// ============================================================================
// Determinism Tests
// ============================================================================

#[test]
fn test_scan_results_deterministic() {
    let scanner = Arc::new(create_test_scanner());
    let mut handles = vec![];
    let results = Arc::new(std::sync::Mutex::new(Vec::new()));

    // Multiple threads scan same content, collect results
    for _ in 0..10 {
        let scanner = Arc::clone(&scanner);
        let results = Arc::clone(&results);
        handles.push(thread::spawn(move || {
            let result = scanner.scan(MIXED_CONTENT);
            results.lock().unwrap().push(result.match_count);
        }));
    }

    for handle in handles {
        handle.join().expect("Thread should not panic");
    }

    // All results should be identical
    let collected = results.lock().unwrap();
    let first = collected[0];
    for &count in collected.iter() {
        assert_eq!(count, first, "All threads should get same match count");
    }
}
