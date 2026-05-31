use std::path::Path;

use resolvo::utils::Pool;
use rpmrepo_metadata::FileType;
use rpmrepo_metadata::visitor::{FilelistsVisitor, PrimaryVisitor, RequirementData};

use crate::{
    HashMap, LoadOptions, PackageSpec, ProvidesMap, ProvidesVersion, RpmPackageVersion, RpmProvider,
    RpmRequirement, invert_flags,
};

use resolvo::{NameId, SolvableId, VersionSetId};

/// Accumulator for a single package's metadata during primary.xml parsing.
///
/// Fields are populated incrementally by `PrimaryVisitor` callbacks, then
/// consumed in `end_package` to build the final `RpmPackageVersion` and update
/// the provides map. Reused across packages via `reset()` to avoid allocation.
struct PackageInProgress {
    name: String,
    epoch: String,
    version: String,
    release: String,
    arch: String,
    requires: Vec<VersionSetId>,
    conflicts: Vec<VersionSetId>,
    recommends: Vec<VersionSetId>,
    /// Provides entries: (interned capability NameId, optional epoch, version, release).
    /// Stored with owned strings because the provides version may differ from the
    /// package EVR and must survive until `end_package` registers them.
    provides: Vec<(NameId, Option<String>, Option<String>, Option<String>)>,
    /// File paths declared in primary.xml's `<file>` elements (a subset of the
    /// full filelists). These are indexed as provides so that common file
    /// dependencies (e.g. `/usr/bin/python3`) resolve without loading filelists.xml.
    file_name_ids: Vec<NameId>,
}

impl PackageInProgress {
    /// Create a new empty accumulator.
    fn new() -> Self {
        Self {
            name: String::new(),
            epoch: String::new(),
            version: String::new(),
            release: String::new(),
            arch: String::new(),
            requires: Vec::new(),
            conflicts: Vec::new(),
            recommends: Vec::new(),
            provides: Vec::new(),
            file_name_ids: Vec::new(),
        }
    }

    /// Clear all fields so the accumulator can be reused for the next package.
    fn reset(&mut self) {
        self.name.clear();
        self.epoch.clear();
        self.version.clear();
        self.release.clear();
        self.arch.clear();
        self.requires.clear();
        self.conflicts.clear();
        self.recommends.clear();
        self.provides.clear();
        self.file_name_ids.clear();
    }
}

/// Intern a requirement into the resolvo pool, returning a `VersionSetId`.
///
/// Converts the parsed `RequirementData` (with borrowed string fields) into an
/// `RpmRequirement` (with pool-interned `StringId` fields) and registers it
/// under the requirement's package name.
fn intern_requirement(pool: &Pool<RpmRequirement>, data: &RequirementData<'_>) -> VersionSetId {
    let name_id = pool.intern_package_name(data.name);
    let req = RpmRequirement {
        flags: data.flags,
        epoch: data.epoch.map(|s| pool.intern_string(s)),
        version: data.version.map(|s| pool.intern_string(s)),
        release: data.release.map(|s| pool.intern_string(s)),
        preinstall: data.preinstall,
    };
    pool.intern_version_set(name_id, req)
}

/// Intern a requirement with its version constraint inverted.
///
/// Used for Conflicts: RPM says "conflicts with foo >= 2.0", meaning "this
/// package cannot coexist with foo 2.0 or newer." resolvo models this as a
/// `constrains` entry, which means "the selected version of foo must satisfy
/// this version set." So we invert the flags: `>= 2.0` becomes `< 2.0`,
/// telling the solver "if foo is selected, it must be older than 2.0."
fn intern_inverted_requirement(
    pool: &Pool<RpmRequirement>,
    data: &RequirementData<'_>,
) -> VersionSetId {
    let name_id = pool.intern_package_name(data.name);
    let req = RpmRequirement {
        flags: data.flags.map(invert_flags),
        epoch: data.epoch.map(|s| pool.intern_string(s)),
        version: data.version.map(|s| pool.intern_string(s)),
        release: data.release.map(|s| pool.intern_string(s)),
        preinstall: data.preinstall,
    };
    pool.intern_version_set(name_id, req)
}

/// Visitor that streams primary.xml and populates the resolvo pool.
///
/// As the XML parser encounters each `<package>` element, the visitor
/// accumulates its metadata into `pkg`, then in `end_package` commits
/// a solvable to the pool and updates the provides map. Packages that
/// don't match the target architecture are skipped entirely via the
/// `skip` flag, avoiding unnecessary pool allocations.
struct PrimaryLoaderVisitor<'a> {
    pool: &'a Pool<RpmRequirement>,
    provides_map: &'a mut ProvidesMap,
    provides_versions: &'a mut HashMap<(SolvableId, NameId), ProvidesVersion>,
    repo_id: usize,
    target_arch: Option<&'a str>,
    pkg: PackageInProgress,
    /// When true, all visitor callbacks for the current package are no-ops.
    /// Set when the package's arch doesn't match the target.
    skip: bool,
}

impl<'a> PrimaryLoaderVisitor<'a> {
    /// Create a visitor that will populate the given pool and provides map.
    fn new(
        pool: &'a Pool<RpmRequirement>,
        provides_map: &'a mut ProvidesMap,
        provides_versions: &'a mut HashMap<(SolvableId, NameId), ProvidesVersion>,
        repo_id: usize,
        target_arch: Option<&'a str>,
    ) -> Self {
        Self {
            pool,
            provides_map,
            provides_versions,
            repo_id,
            target_arch,
            pkg: PackageInProgress::new(),
            skip: false,
        }
    }
}

impl PrimaryVisitor for PrimaryLoaderVisitor<'_> {
    /// Start processing a new `<package>` element from primary.xml.
    ///
    /// Resets the accumulator and checks the architecture filter. If the
    /// package's arch doesn't match the target (and isn't `noarch`), sets
    /// `skip = true` so all subsequent callbacks for this package are no-ops.
    fn begin_package(&mut self, name: &str, arch: &str, _checksum_type: &str, _pkgid: &str) {
        self.pkg.reset();

        if let Some(target) = self.target_arch {
            if arch != target && arch != "noarch" {
                self.skip = true;
                return;
            }
        }
        self.skip = false;

        self.pkg.name.push_str(name);
        self.pkg.arch.push_str(arch);
    }

    /// Record the package's epoch-version-release from the `<version>` element.
    fn set_evr(&mut self, epoch: &str, version: &str, release: &str) {
        if self.skip {
            return;
        }
        self.pkg.epoch.push_str(epoch);
        self.pkg.version.push_str(version);
        self.pkg.release.push_str(release);
    }

    /// Record a `<rpm:provides>` entry.
    ///
    /// Provides are stored with their optional version fields as owned strings
    /// (not yet interned) because they'll be registered in the provides map
    /// in `end_package`, after the solvable ID is known.
    fn add_provide(&mut self, req: RequirementData<'_>) {
        if self.skip {
            return;
        }
        let cap_id = self.pool.intern_package_name(req.name);
        self.pkg.provides.push((
            cap_id,
            req.epoch.map(|s| s.to_owned()),
            req.version.map(|s| s.to_owned()),
            req.release.map(|s| s.to_owned()),
        ));
    }

    /// Record a `<rpm:requires>` entry as a hard dependency.
    ///
    /// Rich/boolean dependencies (containing " if ") are skipped because the
    /// solver doesn't yet support conditional expressions like
    /// `Requires: (foo if bar)`.
    fn add_require(&mut self, req: RequirementData<'_>) {
        if self.skip {
            return;
        }
        // Skip rich/boolean dependencies — not yet supported by the solver.
        if req.name.contains(" if ") {
            return;
        }
        let vs_id = intern_requirement(self.pool, &req);
        self.pkg.requires.push(vs_id);
    }

    /// Record a `<rpm:conflicts>` entry.
    ///
    /// The version constraint is inverted before interning (see
    /// `intern_inverted_requirement`) because resolvo's `constrains` mechanism
    /// expresses "the other package must match this set", which is the logical
    /// inverse of "conflicts with versions matching this set."
    ///
    /// Rich/boolean dependencies (starting with `(`) are skipped.
    fn add_conflict(&mut self, req: RequirementData<'_>) {
        if self.skip {
            return;
        }
        // Skip rich/boolean dependencies — not yet supported by the solver.
        if req.name.starts_with('(') {
            return;
        }
        let vs_id = intern_inverted_requirement(self.pool, &req);
        self.pkg.conflicts.push(vs_id);
    }

    /// Record a `<rpm:recommends>` entry as a weak dependency.
    ///
    /// Recommends are not hard requirements — they're collected separately and
    /// passed to the solver as soft requirements in a second pass (see
    /// `collect_recommended_solvables`).
    ///
    /// Rich/boolean dependencies (starting with `(`) are skipped.
    fn add_recommend(&mut self, req: RequirementData<'_>) {
        if self.skip {
            return;
        }
        // Skip rich/boolean dependencies — not yet supported by the solver.
        if req.name.starts_with('(') {
            return;
        }
        let vs_id = intern_requirement(self.pool, &req);
        self.pkg.recommends.push(vs_id);
    }

    /// Record a `<file>` element from primary.xml.
    ///
    /// Primary.xml includes a subset of file paths (typically executables in
    /// /usr/bin, /usr/sbin, etc.) to satisfy common file dependencies without
    /// needing to parse the much larger filelists.xml. These are indexed as
    /// provides in `end_package`.
    fn add_file(&mut self, _filetype: FileType, path: &str) {
        if self.skip {
            return;
        }
        let file_id = self.pool.intern_package_name(path);
        self.pkg.file_name_ids.push(file_id);
    }

    /// Finalize the current package: create a solvable and update the provides map.
    ///
    /// This is where the accumulated metadata becomes part of the solver's state:
    /// 1. Creates an `RpmPackageVersion` record and interns it as a solvable.
    /// 2. Registers the package name itself as a provides (every package
    ///    implicitly provides its own name).
    /// 3. Registers each explicit `Provides:` entry in the provides map. If a
    ///    provides entry has version info, records it in `provides_versions` so
    ///    version comparisons use the provides version, not the package EVR.
    /// 4. Registers file paths from primary.xml as provides.
    fn end_package(&mut self) {
        if self.skip {
            return;
        }

        let name_id = self.pool.intern_package_name(&self.pkg.name);

        let pack = RpmPackageVersion {
            name: std::mem::take(&mut self.pkg.name),
            epoch: std::mem::take(&mut self.pkg.epoch),
            version: std::mem::take(&mut self.pkg.version),
            release: std::mem::take(&mut self.pkg.release),
            arch: std::mem::take(&mut self.pkg.arch),
            repo_id: self.repo_id,
            requires: std::mem::take(&mut self.pkg.requires),
            conflicts: std::mem::take(&mut self.pkg.conflicts),
            recommends: std::mem::take(&mut self.pkg.recommends),
        };

        let solvable = self.pool.intern_solvable(name_id, pack);

        // Every package implicitly provides its own name.
        self.provides_map.entry(name_id).push(solvable);

        // Register explicit Provides: entries.
        for (cap_id, prov_epoch, prov_version, prov_release) in self.pkg.provides.drain(..) {
            self.provides_map.entry(cap_id).push(solvable);

            // Only store a separate provides version when one was specified.
            // Without this, version checks fall back to the package's own EVR.
            if prov_version.is_some() || prov_epoch.is_some() || prov_release.is_some() {
                self.provides_versions.insert(
                    (solvable, cap_id),
                    ProvidesVersion {
                        epoch: prov_epoch.unwrap_or_default(),
                        version: prov_version.unwrap_or_default(),
                        release: prov_release.unwrap_or_default(),
                    },
                );
            }
        }

        // Register file paths from primary.xml as provides.
        for file_id in self.pkg.file_name_ids.drain(..) {
            self.provides_map.entry(file_id).push(solvable);
        }
    }
}

/// Visitor that streams filelists.xml and registers file paths as provides.
///
/// Unlike `PrimaryLoaderVisitor`, this doesn't create solvables - they already
/// exist from primary.xml parsing. Instead, it looks up existing solvables by
/// package name and adds their file paths to the provides map so that file
/// dependencies (e.g. `Requires: /usr/lib64/libcurl.so.4`) can be resolved.
struct FilelistsLoaderVisitor<'a> {
    pool: &'a Pool<RpmRequirement>,
    provides_map: &'a mut ProvidesMap,
    /// Solvables for the current package. A package name may map to multiple
    /// solvables (e.g. same name from different repos), so all of them get
    /// the file provides.
    current_solvables: Vec<SolvableId>,
}

impl FilelistsVisitor for FilelistsLoaderVisitor<'_> {
    /// Look up the solvables for this package name so `add_file` knows which
    /// solvables to associate each file path with. If the package wasn't loaded
    /// (e.g. filtered by arch), `current_solvables` stays empty and files are
    /// skipped.
    fn begin_package(&mut self, _pkgid: &str, name: &str, _arch: &str) {
        self.current_solvables.clear();
        let pkg_name_id = self.pool.intern_package_name(name);
        if let Some(solvables) = self.provides_map.get(pkg_name_id) {
            self.current_solvables.extend_from_slice(solvables);
        }
    }

    /// Register a file path as a provides for all solvables of the current package.
    fn add_file(&mut self, _filetype: FileType, path: &str) {
        if self.current_solvables.is_empty() {
            return;
        }
        let file_id = self.pool.intern_package_name(path);
        self.provides_map
            .entry(file_id)
            .extend_from_slice(&self.current_solvables);
    }
}

impl RpmProvider {
    /// Load RPM repository metadata from a local directory with default options.
    ///
    /// Equivalent to calling [`load_repo_with_options`](Self::load_repo_with_options)
    /// with [`LoadOptions::default()`].
    pub fn load_repo(&mut self, path: &Path, label: &str) {
        self.load_repo_with_options(path, label, &LoadOptions::default());
    }

    /// Load RPM repository metadata from a local directory.
    ///
    /// `path` must point to a directory containing `repodata/repomd.xml`.
    /// `label` is a human-readable name shown in solver output.
    /// Repos loaded first have higher priority during resolution.
    ///
    /// Packages are filtered by the `target_arch` set in [`RpmProvider::new()`].
    /// When [`LoadOptions::load_filelists`] is true, filelists.xml is parsed
    /// immediately; otherwise it is deferred until a file dependency is
    /// encountered during resolution.
    pub fn load_repo_with_options(&mut self, path: &Path, label: &str, options: &LoadOptions) {
        let repo_id = self.repo_labels.len();
        self.repo_labels.push(label.to_string());

        let repo_reader = rpmrepo_metadata::RepositoryReader::new_from_directory(path).unwrap();
        let repomd = repo_reader.repomd();

        let primary_href = &repomd.get_record("primary").unwrap().location_href;
        let primary_path = path.join(primary_href);
        let mut xml_reader = rpmrepo_metadata::utils::xml_reader_from_file(&primary_path).unwrap();

        let mut provides_map = self.provides_to_package.borrow_mut();
        let mut visitor = PrimaryLoaderVisitor::new(
            &self.pool,
            &mut provides_map,
            &mut self.provides_versions,
            repo_id,
            self.target_arch.as_deref(),
        );

        rpmrepo_metadata::visitor::parse_primary(&mut xml_reader, &mut visitor).unwrap();

        if let Some(filelists_record) = repomd.get_record("filelists") {
            let filelists_path = path.join(&filelists_record.location_href);
            if options.load_filelists {
                let mut xml_reader =
                    rpmrepo_metadata::utils::xml_reader_from_file(&filelists_path).unwrap();
                let mut visitor = FilelistsLoaderVisitor {
                    pool: &self.pool,
                    provides_map: &mut provides_map,
                    current_solvables: Vec::new(),
                };
                rpmrepo_metadata::visitor::parse_filelists(&mut xml_reader, &mut visitor).unwrap();
            } else {
                self.filelists_paths.push(filelists_path);
            }
        }
    }

    /// Register a named repository, returning its `repo_id` for use with
    /// [`add_package`](Self::add_package).
    pub fn add_repo(&mut self, label: &str) -> usize {
        let repo_id = self.repo_labels.len();
        self.repo_labels.push(label.to_string());
        repo_id
    }

    /// Add a single package to the solver pool.
    ///
    /// Unlike [`load_repo()`](Self::load_repo), this does not apply
    /// `target_arch` filtering — the caller controls which packages are added.
    pub fn add_package(&mut self, repo_id: usize, spec: &PackageSpec<'_>) -> SolvableId {
        let requires: Vec<_> = spec
            .requires
            .iter()
            .map(|r| intern_requirement(&self.pool, r))
            .collect();
        let conflicts: Vec<_> = spec
            .conflicts
            .iter()
            .map(|r| intern_inverted_requirement(&self.pool, r))
            .collect();
        let recommends: Vec<_> = spec
            .recommends
            .iter()
            .map(|r| intern_requirement(&self.pool, r))
            .collect();

        let name_id = self.pool.intern_package_name(spec.name);

        let pack = RpmPackageVersion {
            name: spec.name.to_owned(),
            epoch: spec.epoch.to_owned(),
            version: spec.version.to_owned(),
            release: spec.release.to_owned(),
            arch: spec.arch.to_owned(),
            repo_id,
            requires,
            conflicts,
            recommends,
        };

        let solvable = self.pool.intern_solvable(name_id, pack);

        let mut provides_map = self.provides_to_package.borrow_mut();

        // Every package implicitly provides its own name.
        provides_map.entry(name_id).push(solvable);

        // Register explicit Provides entries.
        for prov in spec.provides {
            let cap_id = self.pool.intern_package_name(prov.name);
            provides_map.entry(cap_id).push(solvable);

            if prov.version.is_some() || prov.epoch.is_some() || prov.release.is_some() {
                self.provides_versions.insert(
                    (solvable, cap_id),
                    ProvidesVersion {
                        epoch: prov.epoch.unwrap_or_default().to_owned(),
                        version: prov.version.unwrap_or_default().to_owned(),
                        release: prov.release.unwrap_or_default().to_owned(),
                    },
                );
            }
        }

        // Register file paths as provides.
        for &file_path in spec.files {
            let file_id = self.pool.intern_package_name(file_path);
            provides_map.entry(file_id).push(solvable);
        }

        solvable
    }

    /// Parse filelists.xml for all loaded repos and index every file path
    /// into the provides map. Called lazily on the first `get_candidates` miss
    /// for a `/`-prefixed capability name.
    pub(crate) fn load_filelists(&self) {
        let mut loaded = self.filelists_loaded.borrow_mut();
        if *loaded {
            return;
        }
        *loaded = true;

        let mut provides_map = self.provides_to_package.borrow_mut();
        for filelists_path in &self.filelists_paths {
            let mut xml_reader =
                rpmrepo_metadata::utils::xml_reader_from_file(filelists_path).unwrap();

            let mut visitor = FilelistsLoaderVisitor {
                pool: &self.pool,
                provides_map: &mut provides_map,
                current_solvables: Vec::new(),
            };

            rpmrepo_metadata::visitor::parse_filelists(&mut xml_reader, &mut visitor).unwrap();
        }
    }
}

#[cfg(test)]
mod tests {
    use crate::{ResolveOptions, RpmProvider, resolve};
    use resolvo::Interner;
    use std::collections::BTreeSet;
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

    #[test]
    fn resolve_bash() {
        let provider = load_cs10_provider();
        let mut solver = resolvo::Solver::new(provider);
        let result = resolve(&mut solver, &["bash"], &ResolveOptions::new()).unwrap();
        let set: BTreeSet<String> = result
            .iter()
            .map(|s| solver.provider().display_solvable(*s).to_string())
            .collect();

        assert!(
            set.iter().any(|s| s.starts_with("bash ")),
            "bash must be in the result"
        );
        assert!(
            set.iter().any(|s| s.starts_with("glibc ")),
            "glibc must be in the result"
        );
    }

    #[test]
    fn resolve_dnf() {
        let provider = load_cs10_provider();
        let mut solver = resolvo::Solver::new(provider);
        let result = resolve(&mut solver, &["dnf"], &ResolveOptions::new()).unwrap();
        let set: BTreeSet<String> = result
            .iter()
            .map(|s| solver.provider().display_solvable(*s).to_string())
            .collect();

        assert!(
            set.iter().any(|s| s.starts_with("dnf ")),
            "dnf must be in the result"
        );
        assert!(
            set.iter().any(|s| s.starts_with("python3-dnf ")),
            "python3-dnf must be in the result"
        );
    }

    #[test]
    fn resolve_manual_packages() {
        use crate::{DependencySpec, PackageSpec};
        use rpmrepo_metadata::RequirementType;

        let mut provider = RpmProvider::new(None);
        let repo = provider.add_repo("test");

        // Package "app" requires "lib"
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
                    flags: Some(RequirementType::GE),
                    epoch: None,
                    version: Some("1.0"),
                    release: None,
                    preinstall: false,
                }],
                provides: &[],
                conflicts: &[],
                recommends: &[],
                files: &[],
            },
        );

        // Package "lib" provides itself
        provider.add_package(
            repo,
            &PackageSpec {
                name: "lib",
                epoch: "0",
                version: "2.0",
                release: "1",
                arch: "x86_64",
                requires: &[],
                provides: &[],
                conflicts: &[],
                recommends: &[],
                files: &[],
            },
        );

        let mut solver = resolvo::Solver::new(provider);
        let result = resolve(&mut solver, &["app"], &ResolveOptions::new()).unwrap();
        let names: BTreeSet<&str> = result
            .iter()
            .map(|s| solver.provider().package_name(*s))
            .collect();

        assert_eq!(names, BTreeSet::from(["app", "lib"]));
    }

    #[test]
    fn resolve_manual_provides() {
        use crate::{DependencySpec, PackageSpec};
        use rpmrepo_metadata::RequirementType;

        let mut provider = RpmProvider::new(None);
        let repo = provider.add_repo("test");

        // Package "app" requires capability "libfoo"
        provider.add_package(
            repo,
            &PackageSpec {
                name: "app",
                epoch: "0",
                version: "1.0",
                release: "1",
                arch: "x86_64",
                requires: &[DependencySpec {
                    name: "libfoo",
                    flags: None,
                    epoch: None,
                    version: None,
                    release: None,
                    preinstall: false,
                }],
                provides: &[],
                conflicts: &[],
                recommends: &[],
                files: &[],
            },
        );

        // Package "foo-impl" provides "libfoo" at version 3.0
        provider.add_package(
            repo,
            &PackageSpec {
                name: "foo-impl",
                epoch: "0",
                version: "1.0",
                release: "1",
                arch: "x86_64",
                requires: &[],
                provides: &[DependencySpec {
                    name: "libfoo",
                    flags: Some(RequirementType::EQ),
                    epoch: None,
                    version: Some("3.0"),
                    release: None,
                    preinstall: false,
                }],
                conflicts: &[],
                recommends: &[],
                files: &[],
            },
        );

        let mut solver = resolvo::Solver::new(provider);
        let result = resolve(&mut solver, &["app"], &ResolveOptions::new()).unwrap();
        let names: BTreeSet<&str> = result
            .iter()
            .map(|s| solver.provider().package_name(*s))
            .collect();

        assert_eq!(names, BTreeSet::from(["app", "foo-impl"]));
    }
}
