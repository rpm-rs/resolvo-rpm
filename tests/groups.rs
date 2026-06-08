use std::collections::BTreeSet;

use resolvo_rpm::{
    CompsGroup, CompsPackageReq, DependencySpec, GroupInstallOptions, LoadOptions, PackageSpec,
    ResolveOptions, RpmProvider, resolve,
};

mod common;

/// Helper: build a CompsGroup with the given id and package list.
fn make_group(id: &str, packages: Vec<CompsPackageReq>) -> CompsGroup {
    CompsGroup {
        id: id.to_owned(),
        name: id.to_owned(),
        packages,
        ..CompsGroup::default()
    }
}

/// Helper: build a CompsPackageReq with the given name and type.
fn make_pkg_req(name: &str, reqtype: &str) -> CompsPackageReq {
    CompsPackageReq {
        name: name.to_owned(),
        reqtype: reqtype.to_owned(),
        requires: None,
        basearchonly: false,
    }
}

/// Helper: add a minimal package to the provider.
fn add_simple_package(provider: &mut RpmProvider, repo_id: usize, name: &str) {
    provider.add_package(
        repo_id,
        &PackageSpec {
            name,
            epoch: "0",
            version: "1.0",
            release: "1",
            arch: "x86_64",
            requires: &[],
            provides: &[],
            conflicts: &[],
            obsoletes: &[],
            recommends: &[],
            suggests: &[],
            supplements: &[],
            enhances: &[],
            files: &[],
        },
    );
}

#[test]
fn add_group_resolves_mandatory_and_default() {
    let mut provider = RpmProvider::new(None);
    let repo = provider.add_repo("test");

    add_simple_package(&mut provider, repo, "mandatory-pkg");
    add_simple_package(&mut provider, repo, "default-pkg");
    add_simple_package(&mut provider, repo, "optional-pkg");

    let group = make_group(
        "test-group",
        vec![
            make_pkg_req("mandatory-pkg", "mandatory"),
            make_pkg_req("default-pkg", "default"),
            make_pkg_req("optional-pkg", "optional"),
        ],
    );
    provider.add_group(repo, &group, &GroupInstallOptions::default());

    let mut solver = resolvo::Solver::new(provider);
    let result = resolve(&mut solver, &["@test-group"], &ResolveOptions::new()).unwrap();
    let names: BTreeSet<&str> = result
        .iter()
        .map(|s| solver.provider().package_name(*s))
        .collect();

    assert!(names.contains("@test-group"));
    assert!(names.contains("mandatory-pkg"));
    assert!(names.contains("default-pkg"));
    assert!(
        !names.contains("optional-pkg"),
        "optional packages should not be included by default"
    );
}

#[test]
fn add_group_includes_optional_when_requested() {
    let mut provider = RpmProvider::new(None);
    let repo = provider.add_repo("test");

    add_simple_package(&mut provider, repo, "mandatory-pkg");
    add_simple_package(&mut provider, repo, "optional-pkg");

    let group = make_group(
        "test-group",
        vec![
            make_pkg_req("mandatory-pkg", "mandatory"),
            make_pkg_req("optional-pkg", "optional"),
        ],
    );

    let options = GroupInstallOptions::new().include_optional(true);
    provider.add_group(repo, &group, &options);

    let mut solver = resolvo::Solver::new(provider);
    let result = resolve(&mut solver, &["@test-group"], &ResolveOptions::new()).unwrap();
    let names: BTreeSet<&str> = result
        .iter()
        .map(|s| solver.provider().package_name(*s))
        .collect();

    assert!(names.contains("mandatory-pkg"));
    assert!(
        names.contains("optional-pkg"),
        "optional packages should be included when requested"
    );
}

#[test]
fn add_group_skips_conditional_packages() {
    let mut provider = RpmProvider::new(None);
    let repo = provider.add_repo("test");

    add_simple_package(&mut provider, repo, "unconditional-pkg");
    add_simple_package(&mut provider, repo, "conditional-pkg");

    let group = make_group(
        "test-group",
        vec![
            make_pkg_req("unconditional-pkg", "mandatory"),
            CompsPackageReq {
                name: "conditional-pkg".to_owned(),
                reqtype: "conditional".to_owned(),
                requires: Some("some-lang".to_owned()),
                basearchonly: false,
            },
        ],
    );
    provider.add_group(repo, &group, &GroupInstallOptions::default());

    let mut solver = resolvo::Solver::new(provider);
    let result = resolve(&mut solver, &["@test-group"], &ResolveOptions::new()).unwrap();
    let names: BTreeSet<&str> = result
        .iter()
        .map(|s| solver.provider().package_name(*s))
        .collect();

    assert!(names.contains("unconditional-pkg"));
    assert!(
        !names.contains("conditional-pkg"),
        "conditional packages should be skipped"
    );
}

#[test]
fn add_group_resolves_transitive_deps() {
    let mut provider = RpmProvider::new(None);
    let repo = provider.add_repo("test");

    // "app" requires "lib"
    provider.add_package(
        repo,
        &PackageSpec {
            name: "app",
            epoch: "0",
            version: "1.0",
            release: "1",
            arch: "x86_64",
            requires: &[DependencySpec {
                name: "lib",
                flags: None,
                epoch: None,
                version: None,
                release: None,
                preinstall: false,
            }],
            provides: &[],
            conflicts: &[],
            obsoletes: &[],
            recommends: &[],
            suggests: &[],
            supplements: &[],
            enhances: &[],
            files: &[],
        },
    );
    add_simple_package(&mut provider, repo, "lib");

    let group = make_group("test-group", vec![make_pkg_req("app", "mandatory")]);
    provider.add_group(repo, &group, &GroupInstallOptions::default());

    let mut solver = resolvo::Solver::new(provider);
    let result = resolve(&mut solver, &["@test-group"], &ResolveOptions::new()).unwrap();
    let names: BTreeSet<&str> = result
        .iter()
        .map(|s| solver.provider().package_name(*s))
        .collect();

    assert!(names.contains("app"));
    assert!(
        names.contains("lib"),
        "transitive dependencies of group members should be resolved"
    );
}

#[test]
fn add_group_mandatory_only() {
    let mut provider = RpmProvider::new(None);
    let repo = provider.add_repo("test");

    add_simple_package(&mut provider, repo, "mandatory-pkg");
    add_simple_package(&mut provider, repo, "default-pkg");

    let group = make_group(
        "test-group",
        vec![
            make_pkg_req("mandatory-pkg", "mandatory"),
            make_pkg_req("default-pkg", "default"),
        ],
    );

    let options = GroupInstallOptions::new().include_default(false);
    provider.add_group(repo, &group, &options);

    let mut solver = resolvo::Solver::new(provider);
    let result = resolve(&mut solver, &["@test-group"], &ResolveOptions::new()).unwrap();
    let names: BTreeSet<&str> = result
        .iter()
        .map(|s| solver.provider().package_name(*s))
        .collect();

    assert!(names.contains("mandatory-pkg"));
    assert!(
        !names.contains("default-pkg"),
        "default packages should be excluded when include_default is false"
    );
}

#[test]
fn load_groups_from_repo() {
    let load_options = LoadOptions::new().load_groups(true);

    let mut provider = RpmProvider::new(Some("x86_64"));
    provider.load_repo_with_options(
        &common::repo_path("cs10-baseos"),
        "cs10-baseos",
        &load_options,
    );
    provider.load_repo_with_options(
        &common::repo_path("cs10-appstream"),
        "cs10-appstream",
        &load_options,
    );

    let mut solver = resolvo::Solver::new(provider);

    // The "core" group exists in cs10-baseos and should be resolvable.
    let result = resolve(&mut solver, &["@core"], &ResolveOptions::new()).unwrap();
    let names: BTreeSet<&str> = result
        .iter()
        .map(|s| solver.provider().package_name(*s))
        .collect();

    assert!(
        names.contains("@core"),
        "the @core virtual package should be in the result"
    );
    assert!(
        names.len() > 10,
        "the core group should pull in many packages, got {}",
        names.len()
    );
}

#[test]
fn group_mixed_with_packages() {
    let mut provider = RpmProvider::new(None);
    let repo = provider.add_repo("test");

    add_simple_package(&mut provider, repo, "group-member");
    add_simple_package(&mut provider, repo, "standalone-pkg");

    let group = make_group("my-group", vec![make_pkg_req("group-member", "mandatory")]);
    provider.add_group(repo, &group, &GroupInstallOptions::default());

    let mut solver = resolvo::Solver::new(provider);

    // Resolve both a group and a standalone package together.
    let result = resolve(
        &mut solver,
        &["@my-group", "standalone-pkg"],
        &ResolveOptions::new(),
    )
    .unwrap();
    let names: BTreeSet<&str> = result
        .iter()
        .map(|s| solver.provider().package_name(*s))
        .collect();

    assert!(names.contains("@my-group"));
    assert!(names.contains("group-member"));
    assert!(names.contains("standalone-pkg"));
}
