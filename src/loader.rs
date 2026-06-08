use std::path::Path;

use resolvo::utils::Pool;
use rpmrepo_metadata::FileType;
use rpmrepo_metadata::visitor::{
    CompsVisitor, FilelistsVisitor, PrimaryVisitor, RequirementData, UpdateinfoVisitor,
};

use crate::{
    GroupInstallOptions, HashMap, LoadOptions, PackageSpec, ProvidesMap, ProvidesVersion,
    RequirementType, RpmPackageVersion, RpmProvider, RpmRequirement, invert_flags,
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
    obsoletes: Vec<VersionSetId>,
    recommends: Vec<VersionSetId>,
    suggests: Vec<VersionSetId>,
    supplements: Vec<VersionSetId>,
    enhances: Vec<VersionSetId>,
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
            obsoletes: Vec::new(),
            recommends: Vec::new(),
            suggests: Vec::new(),
            supplements: Vec::new(),
            enhances: Vec::new(),
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
        self.obsoletes.clear();
        self.recommends.clear();
        self.suggests.clear();
        self.supplements.clear();
        self.enhances.clear();
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
    let req = if data.flags.is_none() {
        // Unversioned conflict/obsoletes: "cannot coexist with ANY version."
        // Use LT 0:0 — no real package can have version < 0, so filter_candidates
        // with inverse=true will forbid all candidates.
        RpmRequirement {
            flags: Some(RequirementType::LT),
            epoch: Some(pool.intern_string("0")),
            version: Some(pool.intern_string("0")),
            release: None,
            preinstall: false,
        }
    } else {
        RpmRequirement {
            flags: data.flags.map(invert_flags),
            epoch: data.epoch.map(|s| pool.intern_string(s)),
            version: data.version.map(|s| pool.intern_string(s)),
            release: data.release.map(|s| pool.intern_string(s)),
            preinstall: data.preinstall,
        }
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

    /// Record a `<rpm:obsoletes>` entry.
    ///
    /// Modeled as `constrains` with inverted version sets, same as Conflicts.
    /// At the resolver level, if this package is in the solution, the obsoleted
    /// versions are excluded. The install-level replacement semantics are not
    /// handled here.
    ///
    /// Rich/boolean dependencies (starting with `(`) are skipped.
    fn add_obsolete(&mut self, req: RequirementData<'_>) {
        if self.skip {
            return;
        }
        if req.name.starts_with('(') {
            return;
        }
        let vs_id = intern_inverted_requirement(self.pool, &req);
        self.pkg.obsoletes.push(vs_id);
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
        if req.name.starts_with('(') {
            return;
        }
        let vs_id = intern_requirement(self.pool, &req);
        self.pkg.recommends.push(vs_id);
    }

    /// Record a `<rpm:suggests>` entry as a weak dependency.
    ///
    /// Suggests are weaker than Recommends and off by default (matching dnf).
    ///
    /// Rich/boolean dependencies (starting with `(`) are skipped.
    fn add_suggest(&mut self, req: RequirementData<'_>) {
        if self.skip {
            return;
        }
        if req.name.starts_with('(') {
            return;
        }
        let vs_id = intern_requirement(self.pool, &req);
        self.pkg.suggests.push(vs_id);
    }

    /// Record a `<rpm:supplements>` entry.
    ///
    /// Data is parsed and stored but the reverse index and collection logic
    /// are deferred until boolean dependency support is implemented.
    ///
    /// Rich/boolean dependencies (starting with `(`) are skipped.
    fn add_supplement(&mut self, req: RequirementData<'_>) {
        if self.skip {
            return;
        }
        if req.name.starts_with('(') {
            return;
        }
        let vs_id = intern_requirement(self.pool, &req);
        self.pkg.supplements.push(vs_id);
    }

    /// Record a `<rpm:enhances>` entry.
    ///
    /// Data is parsed and stored but the reverse index and collection logic
    /// are deferred until boolean dependency support is implemented.
    ///
    /// Rich/boolean dependencies (starting with `(`) are skipped.
    fn add_enhance(&mut self, req: RequirementData<'_>) {
        if self.skip {
            return;
        }
        if req.name.starts_with('(') {
            return;
        }
        let vs_id = intern_requirement(self.pool, &req);
        self.pkg.enhances.push(vs_id);
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
            obsoletes: std::mem::take(&mut self.pkg.obsoletes),
            recommends: std::mem::take(&mut self.pkg.recommends),
            suggests: std::mem::take(&mut self.pkg.suggests),
            supplements: std::mem::take(&mut self.pkg.supplements),
            enhances: std::mem::take(&mut self.pkg.enhances),
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

/// Visitor that streams comps.xml and collects group definitions.
///
/// Accumulates each `<group>` element into a `CompsGroup`, then pushes
/// the completed group onto the output vec in `end_group`. Categories,
/// environments, and langpacks are ignored — only groups are collected.
struct GroupLoaderVisitor<'a> {
    current_group: Option<rpmrepo_metadata::CompsGroup>,
    groups: &'a mut Vec<rpmrepo_metadata::CompsGroup>,
}

impl CompsVisitor for GroupLoaderVisitor<'_> {
    fn begin_group(&mut self) {
        self.current_group = Some(rpmrepo_metadata::CompsGroup::default());
    }

    fn set_group_id(&mut self, id: &str) {
        if let Some(g) = &mut self.current_group {
            g.id = id.to_owned();
        }
    }

    fn set_group_name(&mut self, name: &str, lang: Option<&str>) {
        if let Some(g) = &mut self.current_group {
            match lang {
                None => g.name = name.to_owned(),
                Some(l) => g.name_by_lang.push((l.to_owned(), name.to_owned())),
            }
        }
    }

    fn set_group_description(&mut self, desc: &str, lang: Option<&str>) {
        if let Some(g) = &mut self.current_group {
            match lang {
                None => g.description = desc.to_owned(),
                Some(l) => g.desc_by_lang.push((l.to_owned(), desc.to_owned())),
            }
        }
    }

    fn set_group_default(&mut self, default: bool) {
        if let Some(g) = &mut self.current_group {
            g.default = default;
        }
    }

    fn set_group_uservisible(&mut self, visible: bool) {
        if let Some(g) = &mut self.current_group {
            g.uservisible = visible;
        }
    }

    fn set_group_biarchonly(&mut self, biarchonly: bool) {
        if let Some(g) = &mut self.current_group {
            g.biarchonly = biarchonly;
        }
    }

    fn set_group_langonly(&mut self, langonly: &str) {
        if let Some(g) = &mut self.current_group {
            g.langonly = Some(langonly.to_owned());
        }
    }

    fn set_group_display_order(&mut self, order: u32) {
        if let Some(g) = &mut self.current_group {
            g.display_order = Some(order);
        }
    }

    fn add_group_package(
        &mut self,
        name: &str,
        reqtype: &str,
        requires: Option<&str>,
        basearchonly: bool,
    ) {
        if let Some(g) = &mut self.current_group {
            g.packages.push(rpmrepo_metadata::CompsPackageReq {
                name: name.to_owned(),
                reqtype: reqtype.to_owned(),
                requires: requires.map(|s| s.to_owned()),
                basearchonly,
            });
        }
    }

    fn end_group(&mut self) {
        if let Some(g) = self.current_group.take() {
            self.groups.push(g);
        }
    }
}

/// Accumulator for a single advisory's package entries during updateinfo.xml parsing.
///
/// As the XML parser encounters each `<update>` element, the visitor records
/// the advisory ID and accumulates `(name, epoch, version, release, arch)`
/// tuples for each package in the advisory's pkglist. On `end_update`, the
/// completed advisory is pushed onto the output vec.
struct AdvisoryInProgress {
    id: String,
    packages: Vec<(String, String, String, String, String)>,
}

/// Visitor that streams updateinfo.xml and collects advisory definitions.
///
/// Only the advisory ID and its per-package NEVRA tuples are retained —
/// these are sufficient to generate the `patch:` virtual solvables with
/// conflicts. Metadata fields (title, severity, references, etc.) are
/// not needed for the solvable model and are ignored.
struct UpdateinfoLoaderVisitor<'a> {
    current: Option<AdvisoryInProgress>,
    advisories: &'a mut Vec<rpmrepo_metadata::UpdateRecord>,
    /// Temporary NEVRA for the current `<package>` element.
    current_pkg: Option<(String, String, String, String, String)>,
}

impl UpdateinfoVisitor for UpdateinfoLoaderVisitor<'_> {
    fn begin_update(&mut self, _from: &str, update_type: &str, _status: &str, _version: &str) {
        self.current = Some(AdvisoryInProgress {
            id: String::new(),
            packages: Vec::new(),
        });
        // Stash update_type so we can set it on the UpdateRecord in end_update.
        // We reuse the id field temporarily — it's overwritten by set_id.
        if let Some(c) = &mut self.current {
            c.id = update_type.to_owned();
        }
    }

    fn set_id(&mut self, id: &str) {
        if let Some(c) = &mut self.current {
            c.id = id.to_owned();
        }
    }

    fn begin_collection_package(
        &mut self,
        name: &str,
        epoch: &str,
        version: &str,
        release: &str,
        arch: &str,
        _src: Option<&str>,
    ) {
        self.current_pkg = Some((
            name.to_owned(),
            epoch.to_owned(),
            version.to_owned(),
            release.to_owned(),
            arch.to_owned(),
        ));
    }

    fn end_collection_package(&mut self) {
        if let (Some(c), Some(pkg)) = (&mut self.current, self.current_pkg.take()) {
            c.packages.push(pkg);
        }
    }

    fn end_update(&mut self) {
        if let Some(c) = self.current.take() {
            let mut record = rpmrepo_metadata::UpdateRecord::default();
            record.id = c.id;
            record.pkglist = vec![rpmrepo_metadata::UpdateCollection {
                packages: c
                    .packages
                    .into_iter()
                    .map(|(name, epoch, version, release, arch)| {
                        rpmrepo_metadata::UpdateCollectionPackage {
                            name,
                            epoch,
                            version,
                            release,
                            arch,
                            ..Default::default()
                        }
                    })
                    .collect(),
                ..Default::default()
            }];
            self.advisories.push(record);
        }
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

        // Must drop the provides_map borrow before add_group takes &mut self.
        drop(provides_map);

        if options.load_groups {
            if let Some(group_record) = repomd.get_record("group") {
                let group_path = path.join(&group_record.location_href);
                let mut xml_reader =
                    rpmrepo_metadata::utils::xml_reader_from_file(&group_path).unwrap();

                let mut groups: Vec<rpmrepo_metadata::CompsGroup> = Vec::new();
                let mut visitor = GroupLoaderVisitor {
                    current_group: None,
                    groups: &mut groups,
                };
                rpmrepo_metadata::visitor::parse_comps(&mut xml_reader, &mut visitor).unwrap();

                for group in &groups {
                    self.add_group(repo_id, group, &options.group_options);
                }
            }
        }

        if options.load_advisories {
            if let Some(updateinfo_record) = repomd.get_record("updateinfo") {
                let updateinfo_path = path.join(&updateinfo_record.location_href);
                let mut xml_reader =
                    rpmrepo_metadata::utils::xml_reader_from_file(&updateinfo_path).unwrap();

                let mut advisories: Vec<rpmrepo_metadata::UpdateRecord> = Vec::new();
                let mut visitor = UpdateinfoLoaderVisitor {
                    current: None,
                    advisories: &mut advisories,
                    current_pkg: None,
                };
                rpmrepo_metadata::visitor::parse_updateinfo(&mut xml_reader, &mut visitor).unwrap();

                for advisory in &advisories {
                    self.add_advisory(repo_id, advisory);
                }
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
        let obsoletes: Vec<_> = spec
            .obsoletes
            .iter()
            .map(|r| intern_inverted_requirement(&self.pool, r))
            .collect();
        let recommends: Vec<_> = spec
            .recommends
            .iter()
            .map(|r| intern_requirement(&self.pool, r))
            .collect();
        let suggests: Vec<_> = spec
            .suggests
            .iter()
            .map(|r| intern_requirement(&self.pool, r))
            .collect();
        let supplements: Vec<_> = spec
            .supplements
            .iter()
            .map(|r| intern_requirement(&self.pool, r))
            .collect();
        let enhances: Vec<_> = spec
            .enhances
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
            obsoletes,
            recommends,
            suggests,
            supplements,
            enhances,
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

    /// Add a package group as a virtual solvable in the solver pool.
    ///
    /// Creates a solvable named `@{group_id}` (e.g. `@core`) whose Requires
    /// are the packages in the group matching the selected package types.
    /// By default, mandatory and default packages are included; optional
    /// packages are excluded (matching dnf's `groupinstall` behavior).
    /// Use [`GroupInstallOptions`] to customize which types are included.
    ///
    /// The virtual solvable uses version `1.0-1` and arch `noarch`. It can
    /// be resolved like any other package by passing `@group-id` to
    /// [`resolve()`](crate::resolve).
    ///
    /// Conditional packages (those with a `requires` field in comps.xml) are
    /// skipped.
    pub fn add_group(
        &mut self,
        repo_id: usize,
        group: &rpmrepo_metadata::CompsGroup,
        options: &GroupInstallOptions,
    ) -> SolvableId {
        let virtual_name = format!("@{}", group.id);
        let name_id = self.pool.intern_package_name(&virtual_name);

        let requires: Vec<VersionSetId> = group
            .packages
            .iter()
            .filter(|p| {
                p.requires.is_none()
                    && match p.reqtype.as_str() {
                        "mandatory" => options.include_mandatory,
                        "default" => options.include_default,
                        "optional" => options.include_optional,
                        _ => false,
                    }
            })
            .map(|p| {
                let pkg_name_id = self.pool.intern_package_name(&p.name);
                let req = RpmRequirement {
                    flags: None,
                    epoch: None,
                    version: None,
                    release: None,
                    preinstall: false,
                };
                self.pool.intern_version_set(pkg_name_id, req)
            })
            .collect();

        let pack = RpmPackageVersion {
            name: virtual_name,
            epoch: "0".to_owned(),
            version: "1.0".to_owned(),
            release: "1".to_owned(),
            arch: "noarch".to_owned(),
            repo_id,
            requires,
            conflicts: Vec::new(),
            obsoletes: Vec::new(),
            recommends: Vec::new(),
            suggests: Vec::new(),
            supplements: Vec::new(),
            enhances: Vec::new(),
        };

        let solvable = self.pool.intern_solvable(name_id, pack);

        let mut provides_map = self.provides_to_package.borrow_mut();
        provides_map.entry(name_id).push(solvable);

        solvable
    }

    /// Add an advisory as a virtual solvable in the solver pool.
    ///
    /// Creates a solvable named `patch:{advisory_id}` (e.g. `patch:RHSA-2024:1234`)
    /// following libsolv's convention. For each package in the advisory's pkglist,
    /// a constrains entry `name >= epoch:version-release` is generated. This means
    /// resolving the patch solvable forces the solver to upgrade all affected
    /// packages past the fixed version. Source-arch entries are skipped.
    ///
    /// Unlike libsolv, which generates arch-qualified constraints (e.g.
    /// `name.x86_64 >= evr`), we use bare package names because our provides
    /// map indexes by unqualified name and arch filtering happens at load time.
    /// This is safe because RPM builds produce identical EVRs across all arches
    /// from the same SRPM.
    ///
    /// The virtual solvable uses arch `noarch` and the advisory's `version`
    /// field (defaulting to `"0"`) as its EVR.
    pub fn add_advisory(
        &mut self,
        repo_id: usize,
        advisory: &rpmrepo_metadata::UpdateRecord,
    ) -> SolvableId {
        let virtual_name = format!("patch:{}", advisory.id);
        let name_id = self.pool.intern_package_name(&virtual_name);

        let mut conflicts: Vec<VersionSetId> = Vec::new();

        for collection in &advisory.pkglist {
            for pkg in &collection.packages {
                if pkg.name.is_empty() || pkg.arch == "src" {
                    continue;
                }

                let epoch_str = if pkg.epoch.is_empty() {
                    "0"
                } else {
                    &pkg.epoch
                };

                // Constrains: name >= epoch:version-release
                //
                // resolvo's constrains means "the selected version must
                // satisfy this version set". GE ensures only versions at
                // or above the advisory's fix are eligible.
                let pkg_name_id = self.pool.intern_package_name(&pkg.name);
                let req = RpmRequirement {
                    flags: Some(RequirementType::GE),
                    epoch: Some(self.pool.intern_string(epoch_str)),
                    version: Some(self.pool.intern_string(&pkg.version)),
                    release: if pkg.release.is_empty() {
                        None
                    } else {
                        Some(self.pool.intern_string(&pkg.release))
                    },
                    preinstall: false,
                };
                conflicts.push(self.pool.intern_version_set(pkg_name_id, req));
            }
        }

        let advisory_version = if advisory.version.is_empty() {
            "0"
        } else {
            &advisory.version
        };

        let pack = RpmPackageVersion {
            name: virtual_name,
            epoch: "0".to_owned(),
            version: advisory_version.to_owned(),
            release: "1".to_owned(),
            arch: "noarch".to_owned(),
            repo_id,
            requires: Vec::new(),
            conflicts,
            obsoletes: Vec::new(),
            recommends: Vec::new(),
            suggests: Vec::new(),
            supplements: Vec::new(),
            enhances: Vec::new(),
        };

        let solvable = self.pool.intern_solvable(name_id, pack);

        let mut provides_map = self.provides_to_package.borrow_mut();
        provides_map.entry(name_id).push(solvable);

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
