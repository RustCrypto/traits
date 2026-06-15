//! Development-related functionality.
//!
//! Helpers and types for writing tests against concrete implementations of
//! the traits in this crate.

pub mod mock_curve;

/// Write a series of `criterion`-based benchmarks for arithmetic on a projective curve point.
#[macro_export]
macro_rules! bench_projective {
    ($name:ident, $point_type:ty, $point_a:expr, $point_b:expr, $scalar:expr) => {
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

        fn bench_point_mul<M: ::criterion::measurement::Measurement>(
            group: &mut ::criterion::BenchmarkGroup<'_, M>,
        ) {
            let p = core::hint::black_box($point_a);
            let s = core::hint::black_box($scalar);
            group.bench_function("point-scalar mul", |b| b.iter(|| p * s));
        }

        fn bench_point_mul_by_generator<M: ::criterion::measurement::Measurement>(
            group: &mut ::criterion::BenchmarkGroup<'_, M>,
        ) {
            use $crate::{group::Group, ops::MulByGeneratorVartime};

            let s = core::hint::black_box($scalar);
            group.bench_function("generator-scalar mul", |b| {
                b.iter(|| ProjectivePoint::mul_by_generator(&s))
            });
            group.bench_function("generator-scalar mul (variable-time)", |b| {
                b.iter(|| ProjectivePoint::mul_by_generator_vartime(&s))
            });
        }

        pub fn $name(c: &mut ::criterion::Criterion) {
            let mut group = c.benchmark_group(stringify!($point_type));
            bench_add(&mut group);
            bench_sub(&mut group);
            bench_neg(&mut group);
            bench_point_mul(&mut group);
            bench_point_mul_by_generator(&mut group);
            group.finish();
        }
    };
}
