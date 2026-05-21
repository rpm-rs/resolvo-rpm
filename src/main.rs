use resolvo_rpm::{ResolveOptions, RpmProvider, resolve};
use std::{collections::BTreeSet, path::PathBuf, process};

use clap::Parser;

/// Resolve RPM package dependencies using a SAT solver.
///
/// Takes one or more local repodata directories and a list of packages
/// to resolve dependencies for, then prints the full dependency closure.
#[derive(Debug, Parser)]
struct Args {
    /// Paths to local repodata directories (must contain repodata/repomd.xml).
    /// Can be specified multiple times. Repos listed first have higher priority.
    #[clap(long, required = true)]
    repo: Vec<PathBuf>,

    /// Package names to resolve dependencies for.
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
}

fn main() {
    tracing_subscriber::fmt::init();

    let args = Args::parse();

    let mut provider = RpmProvider::new(args.arch.as_deref());
    for repo_path in &args.repo {
        let repo_label = &repo_path.display().to_string();
        provider.load_repo(repo_path, repo_label);
    }

    let mut solver = resolvo::Solver::new(provider);
    let pkg_names: Vec<&str> = args.packages.iter().map(|s| s.as_str()).collect();
    let options = ResolveOptions::new().enable_recommends(!args.disable_recommends);

    let solvables = match resolve(&mut solver, &pkg_names, &options) {
        Ok(s) => s,
        Err(err) => report_error(&solver, err),
    };

    print_resolution(&solver, &solvables);
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
