//! Benchmarks for jwk-simple operations.

use criterion::{Criterion, Throughput, criterion_group, criterion_main};
use jwk_simple::{Algorithm, KeySet, KeyType};
use std::hint::black_box;

/// Sample JWKS with multiple keys for benchmarking.
const SAMPLE_JWKS: &str = r#"{
    "keys": [
        {
            "kty": "RSA",
            "kid": "rsa-key-1",
            "use": "sig",
            "alg": "RS256",
            "n": "0vx7agoebGcQSuuPiLJXZptN9nndrQmbXEps2aiAFbWhM78LhWx4cbbfAAtVT86zwu1RK7aPFFxuhDR1L6tSoc_BJECPebWKRXjBZCiFV4n3oknjhMstn64tZ_2W-5JsGY4Hc5n9yBXArwl93lqt7_RN5w6Cf0h4QyQ5v-65YGjQR0_FDW2QvzqY368QQMicAtaSqzs8KJZgnYb9c7d0zgdAZHzu6qMQvRL5hajrn1n91CbOpbISD08qNLyrdkt-bFTWhAI4vMQFh6WeZu0fM4lFd2NcRwr3XPksINHaQ-G_xBniIqbw0Ls1jF44-csFCur-kEgU8awapJzKnqDKgw",
            "e": "AQAB"
        },
        {
            "kty": "EC",
            "kid": "ec-key-1",
            "use": "sig",
            "alg": "ES256",
            "crv": "P-256",
            "x": "MKBCTNIcKUSDii11ySs3526iDZ8AiTo7Tu6KPAqv7D4",
            "y": "4Etl6SRW2YiLUrN5vfvVHuhp7x8PxltmWWlbbM4IFyM"
        },
        {
            "kty": "OKP",
            "kid": "ed-key-1",
            "use": "sig",
            "alg": "EdDSA",
            "crv": "Ed25519",
            "x": "11qYAYKxCrfVS_7TyWQHOg7hcvPapiMlrwIaaPcHURo"
        },
        {
            "kty": "oct",
            "kid": "sym-key-1",
            "use": "sig",
            "alg": "HS256",
            "k": "AyM32w-8yCLE_hLK_OjuJw"
        }
    ]
}"#;

fn bench_parsing(c: &mut Criterion) {
    let mut group = c.benchmark_group("parsing");
    group.throughput(Throughput::Bytes(SAMPLE_JWKS.len() as u64));

    group.bench_function("parse_jwks", |b| {
        b.iter(|| {
            let jwks = serde_json::from_str::<KeySet>(black_box(SAMPLE_JWKS)).unwrap();
            black_box(jwks)
        })
    });

    group.finish();
}

fn bench_serialization(c: &mut Criterion) {
    let jwks = serde_json::from_str::<KeySet>(SAMPLE_JWKS).unwrap();

    let mut group = c.benchmark_group("serialization");

    group.bench_function("serialize_jwks", |b| {
        b.iter(|| {
            let json = serde_json::to_string(&jwks).unwrap();
            black_box(json)
        })
    });

    group.bench_function("serialize_jwks_pretty", |b| {
        b.iter(|| {
            let json = serde_json::to_string_pretty(&jwks).unwrap();
            black_box(json)
        })
    });

    group.finish();
}

fn bench_thumbprint(c: &mut Criterion) {
    let jwks = serde_json::from_str::<KeySet>(SAMPLE_JWKS).unwrap();
    let rsa_key = jwks.find_by_kid("rsa-key-1").unwrap();
    let ec_key = jwks.find_by_kid("ec-key-1").unwrap();
    let okp_key = jwks.find_by_kid("ed-key-1").unwrap();

    let mut group = c.benchmark_group("thumbprint");

    group.bench_function("rsa_thumbprint", |b| {
        b.iter(|| {
            let tp = rsa_key.thumbprint();
            black_box(tp)
        })
    });

    group.bench_function("ec_thumbprint", |b| {
        b.iter(|| {
            let tp = ec_key.thumbprint();
            black_box(tp)
        })
    });

    group.bench_function("okp_thumbprint", |b| {
        b.iter(|| {
            let tp = okp_key.thumbprint();
            black_box(tp)
        })
    });

    group.finish();
}

fn bench_lookup(c: &mut Criterion) {
    let jwks = serde_json::from_str::<KeySet>(SAMPLE_JWKS).unwrap();

    let mut group = c.benchmark_group("lookup");

    group.bench_function("find_by_kid", |b| {
        b.iter(|| {
            let key = jwks.find_by_kid(black_box("rsa-key-1"));
            black_box(key)
        })
    });

    group.bench_function("find_by_alg", |b| {
        b.iter(|| {
            let keys = jwks.find_by_alg(black_box(&Algorithm::Rs256)).count();
            black_box(keys)
        })
    });

    group.bench_function("find_by_kty", |b| {
        b.iter(|| {
            let keys = jwks.find_by_kty(black_box(KeyType::Rsa)).count();
            black_box(keys)
        })
    });

    group.bench_function("signing_keys", |b| {
        b.iter(|| {
            let keys = jwks.signing_keys().count();
            black_box(keys)
        })
    });

    group.bench_function("find_by_thumbprint", |b| {
        let thumbprint = jwks.find_by_kid("rsa-key-1").unwrap().thumbprint();
        b.iter(|| {
            let key = jwks.find_by_thumbprint(black_box(&thumbprint));
            black_box(key)
        })
    });

    group.finish();
}

fn bench_validation(c: &mut Criterion) {
    let jwks = serde_json::from_str::<KeySet>(SAMPLE_JWKS).unwrap();

    let mut group = c.benchmark_group("validation");

    group.bench_function("validate_jwks", |b| {
        b.iter(|| {
            let result = jwks.validate();
            black_box(result)
        })
    });

    group.bench_function("validate_single_key", |b| {
        let key = jwks.find_by_kid("rsa-key-1").unwrap();
        b.iter(|| {
            let result = key.validate_structure();
            black_box(result)
        })
    });

    group.finish();
}

criterion_group!(
    benches,
    bench_parsing,
    bench_serialization,
    bench_thumbprint,
    bench_lookup,
    bench_validation,
);
criterion_main!(benches);
