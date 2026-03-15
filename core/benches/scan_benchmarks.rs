use criterion::{criterion_group, criterion_main, BenchmarkId, Criterion};
use std::fs;
use std::path::Path;
use stealth_scanner::detector_trait::AnalysisContext;
use stealth_scanner::detectors::build_registry;
use stealth_scanner::scan::{new_solidity_parser, scan_file_with};

fn collect_sol_files(dir: &str) -> Vec<(String, String)> {
    let mut files = Vec::new();
    let dir = Path::new(dir);
    if let Ok(entries) = fs::read_dir(dir) {
        for entry in entries.filter_map(Result::ok) {
            let path = entry.path();
            if path.extension().map_or(false, |e| e == "sol") {
                if let Ok(source) = fs::read_to_string(&path) {
                    let name = path.file_name().unwrap().to_string_lossy().to_string();
                    files.push((name, source));
                }
            }
        }
    }
    files.sort_by(|a, b| a.0.cmp(&b.0));
    files
}

fn bench_scan_single_file(c: &mut Criterion) {
    let registry = build_registry();
    let files = collect_sol_files("contracts");

    let mut group = c.benchmark_group("scan_single_file");
    for (name, source) in &files {
        let mut parser = new_solidity_parser().expect("parser");
        let path_str = format!("contracts/{}", name);
        group.bench_with_input(BenchmarkId::from_parameter(name), &path_str, |b, p| {
            b.iter(|| scan_file_with(p, &registry, &mut parser));
        });
        let _ = source;
    }
    group.finish();
}

fn bench_scan_directory(c: &mut Criterion) {
    let registry = build_registry();
    let files = collect_sol_files("contracts");

    c.bench_function("scan_directory", |b| {
        b.iter(|| {
            let mut parser = new_solidity_parser().expect("parser");
            for (name, _) in &files {
                let path_str = format!("contracts/{}", name);
                scan_file_with(&path_str, &registry, &mut parser);
            }
        });
    });
}

fn bench_parse_only(c: &mut Criterion) {
    let files = collect_sol_files("contracts");

    let mut group = c.benchmark_group("parse_only");
    for (name, source) in &files {
        group.bench_with_input(BenchmarkId::from_parameter(name), source, |b, src| {
            b.iter(|| {
                let mut parser = new_solidity_parser().expect("parser");
                parser.parse(src, None).expect("parse");
            });
        });
    }
    group.finish();
}

fn bench_detector_isolation(c: &mut Criterion) {
    let source =
        fs::read_to_string("contracts/comprehensive-vulnerabilities.sol").expect("reference file");
    let mut parser = new_solidity_parser().expect("parser");
    let tree = parser.parse(&source, None).expect("parse");

    let registry = build_registry();

    let mut group = c.benchmark_group("detector_isolation");
    for detector in registry.detectors() {
        let ctx = AnalysisContext::new(&tree, &source);
        group.bench_with_input(
            BenchmarkId::from_parameter(detector.id()),
            &ctx,
            |b, ctx| {
                b.iter(|| {
                    let mut findings = Vec::new();
                    detector.run(ctx, &mut findings);
                    findings
                });
            },
        );
    }
    group.finish();
}

fn bench_cfg_construction(c: &mut Criterion) {
    let source =
        fs::read_to_string("contracts/comprehensive-vulnerabilities.sol").expect("reference file");
    let mut parser = new_solidity_parser().expect("parser");
    let tree = parser.parse(&source, None).expect("parse");

    let ctx = AnalysisContext::new(&tree, &source);

    let mut group = c.benchmark_group("cfg_construction");
    for (i, func) in ctx.functions.iter().enumerate() {
        let func_name = func
            .child_by_field_name("name")
            .map(|n| n.utf8_text(source.as_bytes()).unwrap_or("?"))
            .unwrap_or("anonymous");

        let label = format!("{}_{}", i, func_name);
        group.bench_with_input(BenchmarkId::from_parameter(&label), func, |b, f| {
            b.iter(|| {
                stealth_scanner::cfg::ControlFlowGraph::build_for_function(&tree, &source, f)
            });
        });
    }
    group.finish();
}

criterion_group!(
    benches,
    bench_scan_single_file,
    bench_scan_directory,
    bench_parse_only,
    bench_detector_isolation,
    bench_cfg_construction,
);
criterion_main!(benches);
