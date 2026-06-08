use resolvo_rpm::{
    ClosureOptions, LoadOptions, ResolveOptions, RpmProvider, UpdateRecord, resolve,
};
use rpm_version::Evr;
use std::{collections::BTreeSet, path::PathBuf, process};

use clap::{Parser, Subcommand};

/// Resolve RPM package dependencies using a SAT solver.
///
/// Takes one or more local repodata directories and a list of packages
/// to resolve dependencies for, then prints the full dependency closure.
#[derive(Debug, Parser)]
struct Args {
    #[clap(subcommand)]
    command: Command,
}

#[derive(Debug, Subcommand)]
enum Command {
    /// Resolve the full dependency closure for the given packages.
    Resolve {
        /// Paths to local repodata directories (must contain repodata/repomd.xml).
        /// Can be specified multiple times. Repos listed first have higher priority.
        #[clap(long, required = true)]
        repo: Vec<PathBuf>,

        /// Package names, @group-ids, or patch:ADVISORY-IDs to resolve.
        /// Group names must be prefixed with @ (e.g. @core, @development).
        /// Advisory IDs must be prefixed with patch: (e.g. patch:RHSA-2024:1234).
        #[clap(required = true)]
        packages: Vec<String>,

        /// Target architecture. Only packages matching this arch (and noarch)
        /// will be considered. If omitted, all architectures are included.
        #[clap(long)]
        arch: Option<String>,

        /// Disable Recommends. By default, recommended packages are installed
        /// if available (matching dnf behavior). This flag skips them entirely.
        #[clap(long)]
        disable_recommends: bool,

        /// Enable Suggests. By default, suggested packages are not installed
        /// (matching dnf behavior). This flag includes them as soft requirements.
        #[clap(long)]
        enable_suggests: bool,
    },
    /// Query the advisory (updateinfo) index.
    ///
    /// Lists advisories matching the given filters, or shows detail for a
    /// single advisory when --id is given. Filters are combined with AND.
    Query {
        /// Paths to local repodata directories (must contain repodata/repomd.xml).
        /// Can be specified multiple times.
        #[clap(long, required = true)]
        repo: Vec<PathBuf>,

        /// Target architecture for filtering packages.
        #[clap(long)]
        arch: Option<String>,

        /// Show full detail for a single advisory by ID.
        #[clap(long)]
        id: Option<String>,

        /// Filter advisories by affected package name.
        #[clap(long)]
        package: Option<String>,

        /// Filter advisories by CVE reference.
        #[clap(long)]
        cve: Option<String>,

        /// Filter advisories by type (security, bugfix, enhancement).
        #[clap(long = "type")]
        advisory_type: Option<String>,

        /// Filter advisories by severity (Critical, Important, Moderate, Low).
        #[clap(long)]
        severity: Option<String>,
    },
    /// Check that all dependencies within the repos are satisfiable.
    Depclose {
        /// Paths to local repodata directories (must contain repodata/repomd.xml).
        /// Can be specified multiple times.
        #[clap(long, required = true)]
        repo: Vec<PathBuf>,

        /// Only check packages from these repos for unsatisfied deps.
        /// Other repos are still used to satisfy dependencies.
        /// Must be a subset of --repo paths.
        #[clap(long)]
        check: Vec<PathBuf>,

        /// Only check the newest version of each package.
        #[clap(long)]
        newest: bool,

        /// Target architecture. Only packages matching this arch (and noarch)
        /// will be considered. If omitted, all architectures are included.
        #[clap(long)]
        arch: Option<String>,
    },
}

fn main() {
    tracing_subscriber::fmt::init();

    let args = Args::parse();

    match args.command {
        Command::Resolve {
            repo,
            packages,
            arch,
            disable_recommends,
            enable_suggests,
        } => cmd_resolve(
            &repo,
            &packages,
            arch.as_deref(),
            disable_recommends,
            enable_suggests,
        ),
        Command::Query {
            repo,
            arch,
            id,
            package,
            cve,
            advisory_type,
            severity,
        } => cmd_query(
            &repo,
            arch.as_deref(),
            id.as_deref(),
            package.as_deref(),
            cve.as_deref(),
            advisory_type.as_deref(),
            severity.as_deref(),
        ),
        Command::Depclose {
            repo,
            check,
            newest,
            arch,
        } => cmd_depclose(&repo, &check, newest, arch.as_deref()),
    }
}

/// Resolve the full dependency closure for a set of named packages via the
/// SAT solver, then print the result as an aligned table to stdout.
///
/// Exits with status 1 if resolution fails (e.g. missing or conflicting deps).
fn cmd_resolve(
    repos: &[PathBuf],
    packages: &[String],
    arch: Option<&str>,
    disable_recommends: bool,
    enable_suggests: bool,
) {
    let has_groups = packages.iter().any(|p| p.starts_with('@'));
    let has_advisories = packages.iter().any(|p| p.starts_with("patch:"));

    let load_options = LoadOptions::new()
        .load_groups(has_groups)
        .load_advisories(has_advisories);

    let mut provider = RpmProvider::new(arch);
    for repo_path in repos {
        let repo_label = &repo_path.display().to_string();
        provider.load_repo_with_options(repo_path, repo_label, &load_options);
    }

    let mut solver = resolvo::Solver::new(provider);
    let pkg_names: Vec<&str> = packages.iter().map(|s| s.as_str()).collect();
    let options = ResolveOptions::new()
        .enable_recommends(!disable_recommends)
        .enable_suggests(enable_suggests);

    let solvables = match resolve(&mut solver, &pkg_names, &options) {
        Ok(s) => s,
        Err(err) => report_error(&solver, err),
    };

    print_resolution(&solver, &solvables);
}

/// Query the advisory index, listing or showing detail for advisories.
fn cmd_query(
    repos: &[PathBuf],
    arch: Option<&str>,
    id: Option<&str>,
    package: Option<&str>,
    cve: Option<&str>,
    advisory_type: Option<&str>,
    severity: Option<&str>,
) {
    let load_options = LoadOptions::new().load_advisories(true);

    let mut provider = RpmProvider::new(arch);
    for repo_path in repos {
        let repo_label = &repo_path.display().to_string();
        provider.load_repo_with_options(repo_path, repo_label, &load_options);
    }

    if let Some(advisory_id) = id {
        match provider.advisory_by_id(advisory_id) {
            Some(advisory) => print_advisory_detail(advisory),
            None => {
                eprintln!("Advisory not found: {}", advisory_id);
                process::exit(1);
            }
        }
        return;
    }

    let mut results: Vec<&UpdateRecord> = provider.advisories().iter().collect();

    if let Some(pkg) = package {
        let pkg_set: std::collections::HashSet<&str> = provider
            .advisories_for_package(pkg)
            .iter()
            .map(|a| a.id.as_str())
            .collect();
        results.retain(|a| pkg_set.contains(a.id.as_str()));
    }

    if let Some(cve_id) = cve {
        let cve_set: std::collections::HashSet<&str> = provider
            .advisories_by_cve(cve_id)
            .iter()
            .map(|a| a.id.as_str())
            .collect();
        results.retain(|a| cve_set.contains(a.id.as_str()));
    }

    if let Some(atype) = advisory_type {
        results.retain(|a| a.update_type == atype);
    }

    if let Some(sev) = severity {
        results.retain(|a| a.severity.as_deref() == Some(sev));
    }

    if results.is_empty() {
        eprintln!("No advisories found.");
        return;
    }

    let id_width = results.iter().map(|a| a.id.len()).max().unwrap_or(0);
    let type_width = results
        .iter()
        .map(|a| a.update_type.len())
        .max()
        .unwrap_or(0);
    let sev_width = results
        .iter()
        .map(|a| a.severity.as_deref().unwrap_or("").len())
        .max()
        .unwrap_or(0);

    for advisory in &results {
        let sev = advisory.severity.as_deref().unwrap_or("");
        println!(
            "{:<iw$}  {:<tw$}  {:<sw$}  {}",
            advisory.id,
            advisory.update_type,
            sev,
            advisory.title,
            iw = id_width,
            tw = type_width,
            sw = sev_width,
        );
    }

    eprintln!("\n{} advisories", results.len());
}

/// Print full detail for a single advisory.
fn print_advisory_detail(advisory: &UpdateRecord) {
    let sev = advisory.severity.as_deref().unwrap_or("None");
    println!("{}  {}  {}", advisory.id, advisory.update_type, sev);
    println!("{}", advisory.title);

    if let Some(date) = &advisory.issued_date {
        println!("Issued:  {}", date);
    }
    if let Some(date) = &advisory.updated_date {
        println!("Updated: {}", date);
    }

    let cve_refs: Vec<_> = advisory
        .references
        .iter()
        .filter(|r| r.reftype == "cve")
        .collect();
    if !cve_refs.is_empty() {
        println!("\nReferences:");
        let id_width = cve_refs
            .iter()
            .map(|r| r.id.as_deref().unwrap_or("").len())
            .max()
            .unwrap_or(0);
        for r in &cve_refs {
            let ref_id = r.id.as_deref().unwrap_or("");
            println!("  {:<w$}  {}", ref_id, r.href, w = id_width);
        }
    }

    let packages: Vec<_> = advisory.pkglist.iter().flat_map(|c| &c.packages).collect();
    if !packages.is_empty() {
        println!("\nPackages:");
        let name_width = packages.iter().map(|p| p.name.len()).max().unwrap_or(0);
        let evrs: Vec<String> = packages
            .iter()
            .map(|p| Evr::new(&p.epoch, &p.version, &p.release).to_string())
            .collect();
        let evr_width = evrs.iter().map(|e| e.len()).max().unwrap_or(0);
        for (p, evr) in packages.iter().zip(&evrs) {
            println!(
                "  {:<nw$}  {:<ew$}  {}",
                p.name,
                evr,
                p.arch,
                nw = name_width,
                ew = evr_width,
            );
        }
    }
}

/// Check dependency closure: verify that every Requires of every package
/// in the repo set can be satisfied by at least one package in the same set.
///
/// This is a shallow check (no SAT solving) — it reports individual
/// broken dependencies, not transitive unsatisfiability. Analogous to
/// `dnf repoclosure`.
///
/// When `check_repos` is non-empty, only packages from those repos are
/// checked for broken deps - other repos still contribute providers.
///
/// When `newest` is true, only the highest-EVR version of each package
/// (per name+arch) is checked.
///
/// Prints unsatisfied deps to stdout as an aligned table, sorted by
/// package name. Exits with status 1 if any are found.
fn cmd_depclose(repos: &[PathBuf], check_repos: &[PathBuf], newest: bool, arch: Option<&str>) {
    let mut provider = RpmProvider::new(arch);
    for repo_path in repos {
        let repo_label = &repo_path.display().to_string();
        provider.load_repo(repo_path, repo_label);
    }

    // Map --check paths to repo_ids by matching against the --repo list.
    let check_repo_ids: Vec<usize> = check_repos
        .iter()
        .map(|check_path| {
            repos
                .iter()
                .position(|r| r == check_path)
                .unwrap_or_else(|| {
                    eprintln!(
                        "Error: --check path {:?} is not in the --repo list",
                        check_path
                    );
                    process::exit(2);
                })
        })
        .collect();

    let options = ClosureOptions::new()
        .check_repos(check_repo_ids)
        .newest_only(newest);
    let unsatisfied = provider.check_closure(&options);

    if unsatisfied.is_empty() {
        eprintln!("All dependencies satisfied.");
        return;
    }

    // Dedup via BTreeSet: the same (package, version, requirement) triple can
    // appear multiple times when a versioned requirement is interned identically
    // across packages, or when multiple versions of a package share the same
    // broken dep. The BTreeSet also gives us sorted output for free.
    let mut problems: BTreeSet<(String, String, String)> = BTreeSet::new();
    for &(sid, vs_id) in &unsatisfied {
        let pkg_name = provider.package_name(sid);
        let pkg_version = provider.package_version(sid).to_string();
        let req_name = provider
            .pool
            .resolve_package_name(provider.pool.resolve_version_set_package_name(vs_id));
        let vs = provider.pool.resolve_version_set(vs_id);
        let ver_str = vs.version.map(|id| provider.pool.resolve_string(id));
        let req_display = match (vs.flags, ver_str) {
            (Some(flags), Some(ver)) => format!("{} {} {}", req_name, flags.as_operator(), ver),
            _ => req_name.to_string(),
        };
        problems.insert((pkg_name.to_string(), pkg_version, req_display));
    }

    let pkg_width = problems
        .iter()
        .map(|(name, _, _)| name.len())
        .max()
        .unwrap_or(0);
    let ver_width = problems
        .iter()
        .map(|(_, ver, _)| ver.len())
        .max()
        .unwrap_or(0);

    for (pkg, ver, req) in &problems {
        println!(
            "{:<pw$}  {:<vw$}  requires: {}",
            pkg,
            ver,
            req,
            pw = pkg_width,
            vw = ver_width,
        );
    }

    eprintln!("\n{} unsatisfied dependencies", problems.len());
    process::exit(1);
}

/// Print the resolved packages in alphabetical order, aligned in columns,
/// with repo labels and a total count on stderr.
fn print_resolution(solver: &resolvo::Solver<RpmProvider>, solvables: &[resolvo::SolvableId]) {
    let provider = solver.provider();
    let resolved: BTreeSet<(String, String, &str)> = solvables
        .iter()
        .map(|s| {
            let name = provider.package_name(*s).to_string();
            let version = provider.package_version(*s).to_string();
            let repo = provider.repo_label(*s);
            (name, version, repo)
        })
        .collect();

    let name_width = resolved
        .iter()
        .map(|(name, _, _)| name.len())
        .max()
        .unwrap_or(0);
    let ver_width = resolved
        .iter()
        .map(|(_, ver, _)| ver.len())
        .max()
        .unwrap_or(0);
    for (name, version, repo) in &resolved {
        println!(
            "{:<nw$}  {:<vw$}  [{}]",
            name,
            version,
            repo,
            nw = name_width,
            vw = ver_width
        );
    }

    eprintln!("\n{} packages resolved", resolved.len());
}

/// Print the solver error to stderr and exit with status 1.
fn report_error(solver: &resolvo::Solver<RpmProvider>, err: resolvo::UnsolvableOrCancelled) -> ! {
    match err {
        resolvo::UnsolvableOrCancelled::Unsolvable(conflict) => {
            eprintln!("Error: {}", conflict.display_user_friendly(solver));
        }
        resolvo::UnsolvableOrCancelled::Cancelled(_) => {
            eprintln!("Cancelled");
        }
    }
    process::exit(1);
}
