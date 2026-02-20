//! Development-related functionality.
//!
//! Helpers and types for writing tests against concrete implementations of
//! the traits in this crate.

pub mod mock_curve;

/// Write a series of `criterion`-based benchmarks for arithmetic on a projective curve point.
#[macro_export]
macro_rules! bench_projective {
    ($name:ident, $desc:expr, $point_a:expr, $point_b:expr, $scalar:expr) => {
        fn bench_add<M: ::criterion::measurement::Measurement>(
            group: &mut ::criterion::BenchmarkGroup<'_, M>,
        ) {
            let x = core::hint::black_box($point_a);
            let y = core::hint::black_box($point_b);
            group.bench_function("add", |b| b.iter(|| x + y));
        }

        fn bench_sub<M: ::criterion::measurement::Measurement>(
            group: &mut ::criterion::BenchmarkGroup<'_, M>,
        ) {
            let x = core::hint::black_box($point_a);
            let y = core::hint::black_box($point_b);
            group.bench_function("sub", |b| b.iter(|| x - y));
        }

        fn bench_neg<M: ::criterion::measurement::Measurement>(
            group: &mut ::criterion::BenchmarkGroup<'_, M>,
        ) {
            let x = core::hint::black_box($point_a);
            group.bench_function("neg", |b| b.iter(|| -x));
        }

        fn bench_scalar_mul<M: ::criterion::measurement::Measurement>(
            group: &mut ::criterion::BenchmarkGroup<'_, M>,
        ) {
            let p = core::hint::black_box($point_a);
            let s = core::hint::black_box($scalar);
            group.bench_function("scalar mul", |b| b.iter(|| p * s));
        }

        pub fn $name(c: &mut ::criterion::Criterion) {
            let mut group = c.benchmark_group($desc);
            bench_add(&mut group);
            bench_sub(&mut group);
            bench_neg(&mut group);
            bench_scalar_mul(&mut group);
            group.finish();
        }
    };
}
