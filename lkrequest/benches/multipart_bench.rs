//! Cost of the `multipart/form-data` boundary and form construction.
//!
//! Added because the F-01 fix changed how the boundary's random part is drawn —
//! **rejection sampling** over a 62-character alphabet, consuming a variable
//! amount of RNG output, where the old code hex-encoded a fixed 16 bytes — and
//! nothing else benchmarks this path.
//!
//! `Multipart::encode` is `pub(crate)`, so the escaping half of that change is
//! not reachable from a bench target and is measured separately.

use criterion::{criterion_group, criterion_main, BenchmarkId, Criterion};
use std::hint::black_box;

use lkrequest::multipart::Multipart;

fn bench_multipart(c: &mut Criterion) {
    // `Multipart::new()` is exactly one `generate_boundary()` call plus an
    // empty Vec, so this isolates the algorithm that changed.
    c.bench_function("multipart_boundary", |b| {
        b.iter(|| black_box(Multipart::new()));
    });

    let mut group = c.benchmark_group("multipart_build");
    for parts in [1usize, 8, 64] {
        group.bench_with_input(BenchmarkId::from_parameter(parts), &parts, |b, &parts| {
            b.iter(|| {
                let mut form = Multipart::new();
                for i in 0..parts {
                    form = form.text(&format!("field_{i}"), "value");
                }
                black_box(form.file("upload", "photo.jpg", "image/jpeg", vec![0u8; 1024]))
            });
        });
    }
    group.finish();
}

criterion_group!(benches, bench_multipart);
criterion_main!(benches);
