//! Pipeline benchmarks for hot-path modules not covered by detection.rs or goblins.rs.
//!
//! Covers:
//! 1. Rate limiting (token bucket atomic operations)
//! 2. Access control (CIDR matching at various list sizes)
//! 3. Tarpit delay calculation

use criterion::{black_box, criterion_group, criterion_main, BenchmarkId, Criterion, Throughput};
use std::fs;
use std::net::IpAddr;
use std::path::Path;
use std::time::Duration;
use synapse_pingora::ratelimit::TokenBucket;
use synapse_pingora::access::AccessList;
use synapse_pingora::tarpit::{TarpitConfig, TarpitManager};
use synapse_pingora::waf::{Synapse, Request as SynapseRequest, Header as SynapseHeader};
use synapse_pingora::{EntityManager, EntityConfig};

// ============================================================================
// 1. Rate Limiting — Token Bucket
// ============================================================================

fn bench_rate_limit_acquire(c: &mut Criterion) {
    let mut group = c.benchmark_group("ratelimit/token_bucket");
    group.measurement_time(Duration::from_secs(5));
    group.sample_size(10000);
    group.noise_threshold(0.02);

    // High-RPS bucket (should always allow)
    let bucket_high = TokenBucket::new(1_000_000, 2_000_000);

    group.bench_function("try_acquire_high_rps", |b| {
        b.iter(|| {
            black_box(bucket_high.try_acquire())
        })
    });

    // Low-RPS bucket (will exhaust quickly, measuring the "denied" fast-path)
    let bucket_low = TokenBucket::new(1, 1);
    // Exhaust the single token
    bucket_low.try_acquire();

    group.bench_function("try_acquire_exhausted", |b| {
        b.iter(|| {
            black_box(bucket_low.try_acquire())
        })
    });

    // Production-typical bucket (1000 RPS, 2000 burst)
    let bucket_prod = TokenBucket::new(1000, 2000);

    group.bench_function("try_acquire_1000rps", |b| {
        b.iter(|| {
            black_box(bucket_prod.try_acquire())
        })
    });

    group.finish();
}

// ============================================================================
// 2. Access Control — CIDR Matching
// ============================================================================

fn bench_access_control(c: &mut Criterion) {
    let mut group = c.benchmark_group("access_control/cidr_match");
    group.measurement_time(Duration::from_secs(5));
    group.sample_size(10000);
    group.noise_threshold(0.02);

    // Test IPs
    let allowed_ip: IpAddr = "192.168.1.100".parse().unwrap();
    let denied_ip: IpAddr = "10.0.0.50".parse().unwrap();
    let nomatch_ip: IpAddr = "203.0.113.42".parse().unwrap();

    // Small ACL (5 rules) — typical per-site config
    let mut small_acl = AccessList::new();
    small_acl.allow("192.168.1.0/24").unwrap();
    small_acl.deny("10.0.0.0/8").unwrap();
    small_acl.allow("172.16.0.0/12").unwrap();
    small_acl.deny("192.168.100.0/24").unwrap();
    small_acl.allow("127.0.0.1/32").unwrap();

    group.bench_function("small_acl_5_rules_hit_first", |b| {
        b.iter(|| {
            black_box(small_acl.check(black_box(&allowed_ip)))
        })
    });

    group.bench_function("small_acl_5_rules_hit_second", |b| {
        b.iter(|| {
            black_box(small_acl.check(black_box(&denied_ip)))
        })
    });

    group.bench_function("small_acl_5_rules_no_match", |b| {
        b.iter(|| {
            black_box(small_acl.check(black_box(&nomatch_ip)))
        })
    });

    // Large ACL (100 rules) — enterprise config with many CIDR blocks
    let mut large_acl = AccessList::new();
    for i in 0..50u8 {
        large_acl.allow(&format!("192.168.{}.0/24", i)).unwrap();
    }
    for i in 0..50u8 {
        large_acl.deny(&format!("10.{}.0.0/16", i)).unwrap();
    }

    // IP that matches rule #99 (worst case — linear scan to end)
    let last_match_ip: IpAddr = "10.49.0.1".parse().unwrap();

    group.bench_function("large_acl_100_rules_first_match", |b| {
        let ip: IpAddr = "192.168.0.1".parse().unwrap();
        b.iter(|| {
            black_box(large_acl.check(black_box(&ip)))
        })
    });

    group.bench_function("large_acl_100_rules_last_match", |b| {
        b.iter(|| {
            black_box(large_acl.check(black_box(&last_match_ip)))
        })
    });

    group.bench_function("large_acl_100_rules_no_match", |b| {
        b.iter(|| {
            black_box(large_acl.check(black_box(&nomatch_ip)))
        })
    });

    // IPv6 matching
    let mut ipv6_acl = AccessList::new();
    ipv6_acl.allow("2001:db8::/32").unwrap();
    ipv6_acl.deny("fe80::/10").unwrap();
    ipv6_acl.allow("::1/128").unwrap();

    let ipv6_addr: IpAddr = "2001:db8::1".parse().unwrap();
    let ipv6_nomatch: IpAddr = "2607:f8b0::1".parse().unwrap();

    group.bench_function("ipv6_acl_match", |b| {
        b.iter(|| {
            black_box(ipv6_acl.check(black_box(&ipv6_addr)))
        })
    });

    group.bench_function("ipv6_acl_no_match", |b| {
        b.iter(|| {
            black_box(ipv6_acl.check(black_box(&ipv6_nomatch)))
        })
    });

    group.finish();
}

// ============================================================================
// 3. Tarpit — Delay Calculation
// ============================================================================

fn bench_tarpit_calculation(c: &mut Criterion) {
    let mut group = c.benchmark_group("tarpit/delay_calc");
    group.measurement_time(Duration::from_secs(5));
    group.sample_size(10000);
    group.noise_threshold(0.02);

    let config = TarpitConfig::default();
    let manager = TarpitManager::new(config);

    // Prime the tarpit with some entities at various levels
    for i in 0..100u32 {
        let ip = format!("192.168.1.{}", i);
        for _ in 0..i {
            manager.tarpit(&ip); // Increments level each call
        }
    }

    // Read-only delay check for a known entity at high level
    group.bench_function("peek_delay_high_level", |b| {
        b.iter(|| {
            black_box(manager.peek_delay(black_box("192.168.1.99")))
        })
    });

    // Read-only delay check for unknown entity (DashMap miss)
    group.bench_function("peek_delay_unknown", |b| {
        b.iter(|| {
            black_box(manager.peek_delay(black_box("203.0.113.1")))
        })
    });

    // Tarpit call with state mutation (DashMap write + level increment + LRU touch)
    group.bench_function("tarpit_mutating", |b| {
        b.iter(|| {
            black_box(manager.tarpit(black_box("10.0.0.1")))
        })
    });

    group.finish();
}

/// Full request pipeline: access_check → rate_limit → WAF.analyze → entity.touch_entity
/// This measures the complete hot-path cost for a single request.
/// Performance budget target: < 50μs total for a clean request.
fn bench_full_pipeline(c: &mut Criterion) {
    let mut group = c.benchmark_group("pipeline/full_request");
    group.measurement_time(Duration::from_secs(10));
    group.sample_size(200);
    group.noise_threshold(0.02);
    group.throughput(Throughput::Elements(1));

    // Setup components
    let mut acl = AccessList::new();
    acl.allow("0.0.0.0/0").unwrap(); // Allow all for pipeline test

    let bucket = TokenBucket::new(100_000, 200_000); // High limit to avoid exhaustion

    // Load WAF rules
    let rules_path = Path::new("data/rules.json");
    let mut synapse = Synapse::new();
    if rules_path.exists() {
        if let Ok(rules_json) = fs::read(rules_path) {
            let _ = synapse.load_rules(&rules_json);
        }
    }

    let entity_config = EntityConfig {
        max_entities: 50_000,
        ..Default::default()
    };
    let entity_mgr = EntityManager::new(entity_config);

    let test_ip: IpAddr = "192.168.1.100".parse().unwrap();
    let test_ip_str = "192.168.1.100";

    let request = SynapseRequest {
        method: "GET",
        path: "/api/users/123?page=1&limit=20",
        query: None,
        headers: vec![
            SynapseHeader::new("user-agent", "Mozilla/5.0 (Windows NT 10.0; Win64; x64)"),
            SynapseHeader::new("accept", "application/json"),
            SynapseHeader::new("cookie", "session=abc123"),
        ],
        body: None,
        client_ip: test_ip_str,
        is_static: false,
    };

    group.bench_function("clean_get_full_chain", |b| {
        b.iter(|| {
            // Step 1: Access control check
            let access = acl.check(black_box(&test_ip));
            black_box(access);

            // Step 2: Rate limit check
            let allowed = bucket.try_acquire();
            black_box(allowed);

            // Step 3: WAF analysis
            let verdict = synapse.analyze(black_box(&request));
            black_box(&verdict);

            // Step 4: Entity tracking
            let snapshot = entity_mgr.touch_entity(black_box(test_ip_str));
            black_box(snapshot)
        })
    });

    // Also test with an attack request for comparison
    let attack_request = SynapseRequest {
        method: "GET",
        path: "/api/search?q=1'+UNION+SELECT+username,password+FROM+users--",
        query: None,
        headers: vec![
            SynapseHeader::new("user-agent", "Mozilla/5.0"),
        ],
        body: None,
        client_ip: test_ip_str,
        is_static: false,
    };

    group.bench_function("attack_get_full_chain", |b| {
        b.iter(|| {
            let access = acl.check(black_box(&test_ip));
            black_box(access);
            let allowed = bucket.try_acquire();
            black_box(allowed);
            let verdict = synapse.analyze(black_box(&attack_request));
            black_box(&verdict);
            let snapshot = entity_mgr.touch_entity(black_box(test_ip_str));
            black_box(snapshot)
        })
    });

    group.finish();
}

fn bench_access_control_scaling(c: &mut Criterion) {
    let mut group = c.benchmark_group("access_control/rule_scaling");
    group.measurement_time(Duration::from_secs(5));
    group.sample_size(1000);
    group.noise_threshold(0.02);

    let test_ip: IpAddr = "203.0.113.42".parse().unwrap(); // Will not match any rule

    for rule_count in [100, 1000, 10000] {
        let mut acl = AccessList::new();
        for i in 0..rule_count {
            let o2 = (i >> 16) & 0xFF;
            let o3 = (i >> 8) & 0xFF;
            let o4 = i & 0xFF;
            // Alternate allow/deny to exercise both paths
            if i % 2 == 0 {
                acl.allow(&format!("10.{}.{}.{}/32", o2, o3, o4)).unwrap();
            } else {
                acl.deny(&format!("10.{}.{}.{}/32", o2, o3, o4)).unwrap();
            }
        }

        group.bench_with_input(
            BenchmarkId::new("check_no_match", rule_count),
            &acl,
            |b, acl| {
                b.iter(|| black_box(acl.check(black_box(&test_ip))))
            },
        );
    }

    group.finish();
}

criterion_group!(
    pipeline,
    bench_rate_limit_acquire,
    bench_access_control,
    bench_tarpit_calculation,
    bench_full_pipeline,
    bench_access_control_scaling,
);

criterion_main!(pipeline);
