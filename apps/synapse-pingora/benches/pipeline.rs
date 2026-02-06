//! Pipeline benchmarks for hot-path modules not covered by detection.rs or goblins.rs.
//!
//! Covers:
//! 1. Rate limiting (token bucket atomic operations)
//! 2. Access control (CIDR matching at various list sizes)
//! 3. Tarpit delay calculation

use criterion::{black_box, criterion_group, criterion_main, Criterion};
use std::net::IpAddr;
use std::time::Duration;
use synapse_pingora::ratelimit::TokenBucket;
use synapse_pingora::access::AccessList;
use synapse_pingora::tarpit::{TarpitConfig, TarpitManager};

// ============================================================================
// 1. Rate Limiting — Token Bucket
// ============================================================================

fn bench_rate_limit_acquire(c: &mut Criterion) {
    let mut group = c.benchmark_group("ratelimit");
    group.measurement_time(Duration::from_secs(5));
    group.sample_size(10000);

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
    let mut group = c.benchmark_group("access_control");
    group.measurement_time(Duration::from_secs(5));
    group.sample_size(10000);

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
    let mut group = c.benchmark_group("tarpit");
    group.measurement_time(Duration::from_secs(5));
    group.sample_size(10000);

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

criterion_group!(
    pipeline,
    bench_rate_limit_acquire,
    bench_access_control,
    bench_tarpit_calculation,
);

criterion_main!(pipeline);
