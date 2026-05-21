use criterion::{Criterion, criterion_group, criterion_main};
use resolvo_rpm::{LoadOptions, RpmProvider, resolve};
use std::path::Path;

const REPO_BASE: &str = concat!(env!("CARGO_MANIFEST_DIR"), "/test");

fn repo_path(name: &str) -> std::path::PathBuf {
    Path::new(REPO_BASE).join(name)
}

fn load_cs10_provider() -> RpmProvider {
    let mut provider = RpmProvider::new(Some("x86_64"));
    provider.load_repo(&repo_path("cs10-baseos"), "cs10-baseos");
    provider.load_repo(&repo_path("cs10-appstream"), "cs10-appstream");
    provider
}

fn load_cs10_provider_with_filelists() -> RpmProvider {
    let opts = LoadOptions::new().load_filelists(true);
    let mut provider = RpmProvider::new(Some("x86_64"));
    provider.load_repo_with_options(&repo_path("cs10-baseos"), "cs10-baseos", &opts);
    provider.load_repo_with_options(&repo_path("cs10-appstream"), "cs10-appstream", &opts);
    provider
}

fn bench_load_repo(c: &mut Criterion) {
    let mut group = c.benchmark_group("load_repo");
    group.sample_size(10);
    group.bench_function("cs10", |b| {
        b.iter(|| load_cs10_provider());
    });
    group.bench_function("cs10_with_filelists", |b| {
        b.iter(|| load_cs10_provider_with_filelists());
    });
    group.finish();
}

fn bench_solve_only(c: &mut Criterion) {
    let mut group = c.benchmark_group("solve_only");

    let provider = load_cs10_provider();
    let mut solver = resolvo::Solver::new(provider);

    for (label, pkgs) in [("bash", &["bash"][..]), ("dnf", &["dnf"][..])] {
        group.bench_function(label, |b| {
            b.iter(|| resolve(&mut solver, pkgs, &Default::default()).unwrap());
        });
    }

    group.finish();
}

fn bench_end_to_end(c: &mut Criterion) {
    let mut group = c.benchmark_group("end_to_end");
    group.sample_size(10);

    for (label, pkgs) in [("bash", &["bash"][..]), ("dnf", &["dnf"][..])] {
        group.bench_function(label, |b| {
            b.iter(|| {
                let provider = load_cs10_provider();
                let mut solver = resolvo::Solver::new(provider);
                resolve(&mut solver, pkgs, &Default::default()).unwrap()
            });
        });
    }

    group.finish();
}

criterion_group!(benches, bench_load_repo, bench_solve_only, bench_end_to_end);
criterion_main!(benches);
