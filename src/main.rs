use resolvo_rpm::{ClosureOptions, LoadOptions, ResolveOptions, RpmProvider, resolve};
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

        /// Package names or @group-ids to resolve dependencies for.
        /// Group names must be prefixed with @ (e.g. @core, @development).
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

    let load_options = LoadOptions::new().load_groups(has_groups);

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
