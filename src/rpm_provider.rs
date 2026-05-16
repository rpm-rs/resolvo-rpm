use resolvo::{
    Candidates, Condition, ConditionId, ConditionalRequirement, Dependencies, DependencyProvider,
    HintDependenciesAvailable, Interner, KnownDependencies, NameId,
    Requirement as ResolvoRequirement, SolvableId, SolverCache, StringId, VersionSetId,
    VersionSetUnionId,
    utils::{Pool, VersionSet},
};
use rpm::Evr;
use rpmrepo_metadata::{RepositoryReader, Requirement};
use std::{cmp::Ordering, collections::HashMap, fmt::Display, hash::Hash, path::Path};

#[derive(Default, Debug, Clone)]
pub struct RPMPackageVersion {
    pub name: String,
    pub epoch: String,
    pub version: String,
    pub release: String,
    pub requires: Vec<Requirement>,
    pub suggests: Vec<Requirement>,
    // provides: Vec<Requirement>,
}

impl RPMPackageVersion {
    fn evr(&self) -> Evr<'_> {
        Evr::new(self.epoch.as_str(), self.version.as_str(), self.release.as_str())
    }
}

#[derive(Debug, Clone)]
pub struct RPMRequirement(pub Requirement);

impl PartialEq for RPMRequirement {
    fn eq(&self, other: &Self) -> bool {
        self.0.name == other.0.name
            && self.0.version == other.0.version
            && self.0.flags == other.0.flags
    }
}

impl Eq for RPMRequirement {}

impl Hash for RPMRequirement {
    fn hash<H: std::hash::Hasher>(&self, state: &mut H) {
        self.0.name.hash(state);
        self.0.version.hash(state);
        self.0.flags.hash(state);
    }
}

impl Display for RPMRequirement {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        let req = &self.0;
        write!(
            f,
            "{}-{}",
            req.flags.as_ref().unwrap_or(&"UNDEF".to_string()),
            req.version.as_ref().unwrap_or(&"UNDEF".to_string())
        )
    }
}

impl PartialEq for RPMPackageVersion {
    fn eq(&self, other: &Self) -> bool {
        self.name == other.name && self.evr() == other.evr()
    }
}

impl std::cmp::Eq for RPMPackageVersion {}

impl PartialOrd for RPMPackageVersion {
    fn partial_cmp(&self, other: &Self) -> Option<std::cmp::Ordering> {
        Some(self.cmp(other))
    }
}

impl Ord for RPMPackageVersion {
    fn cmp(&self, other: &Self) -> std::cmp::Ordering {
        self.evr().cmp(&other.evr())
    }
}

impl Display for RPMPackageVersion {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "{}", self.evr())
    }
}

fn check_version_constraint(
    flags: Option<&str>,
    req_epoch: Option<&str>,
    req_version: Option<&str>,
    req_release: Option<&str>,
    candidate: &RPMPackageVersion,
) -> bool {
    let flags = match flags {
        Some(f) => f,
        None => return true,
    };
    let req_version = match req_version {
        Some(v) => v,
        None => return true,
    };

    let req_evr = Evr::new(
        req_epoch.unwrap_or(""),
        req_version,
        req_release.unwrap_or(""),
    );
    let pkg_evr = candidate.evr();

    let ord = pkg_evr.cmp(&req_evr);
    match flags {
        "EQ" => ord == Ordering::Equal,
        "LT" => ord == Ordering::Less,
        "GT" => ord == Ordering::Greater,
        "LE" => ord == Ordering::Less || ord == Ordering::Equal,
        "GE" => ord == Ordering::Greater || ord == Ordering::Equal,
        _ => true,
    }
}

impl VersionSet for RPMRequirement {
    type V = RPMPackageVersion;
}

#[derive(Default)]
pub struct RPMProvider {
    pub pool: Pool<RPMRequirement>,
    pub provides_to_package: HashMap<String, Vec<SolvableId>>,
    // todo: this should disable individual rules / requirements
    pub disable_suggest: bool,
}

impl RPMProvider {
    pub fn from_repodata(path: &Path, disable_suggest: bool) -> Self {
        let reader = RepositoryReader::new_from_directory(path).unwrap();

        let pool = Pool::default();
        let mut provides_to_package = HashMap::new();

        for pkg in reader.iter_packages().unwrap() {
            let pkg = pkg.unwrap();

            let pack = RPMPackageVersion {
                name: pkg.name().to_string(),
                epoch: pkg.epoch().to_string(),
                version: pkg.version().to_string(),
                release: pkg.release().to_string(),
                requires: pkg.requires().to_vec(),
                suggests: pkg.suggests().to_vec(),
                // provides: Vec<Requirement>,
            };

            let name_id = pool.intern_package_name(pkg.name());
            let solvable = pool.intern_solvable(name_id, pack.clone());

            for p in pkg.provides() {
                println!("{} provides {}", pkg.name(), p.name);

                let provides = provides_to_package
                    .entry(p.name.clone())
                    .or_insert_with(Vec::new);

                provides.push(solvable);
            }
        }

        Self {
            pool,
            provides_to_package,
            disable_suggest,
        }
    }

    fn version_set_contains(&self, version_set: VersionSetId, solvable: SolvableId) -> bool {
        let vs = self.pool.resolve_version_set(version_set);
        let record = &self.pool.resolve_solvable(solvable).record;
        check_version_constraint(
            vs.0.flags.as_deref(),
            vs.0.epoch.as_deref(),
            vs.0.version.as_deref(),
            vs.0.release.as_deref(),
            record,
        )
    }
}

impl Interner for RPMProvider {
    fn display_solvable(&self, solvable: SolvableId) -> impl Display + '_ {
        let s = self.pool.resolve_solvable(solvable);
        let name = self.pool.resolve_package_name(s.name);
        format!("{} {}", name, s.record)
    }

    fn display_name(&self, name: NameId) -> impl Display + '_ {
        self.pool.resolve_package_name(name).clone()
    }

    fn display_version_set(&self, version_set: VersionSetId) -> impl Display + '_ {
        let vs = self.pool.resolve_version_set(version_set);
        format!("{}", vs)
    }

    fn display_string(&self, string_id: StringId) -> impl Display + '_ {
        self.pool.resolve_string(string_id).to_string()
    }

    fn version_set_name(&self, version_set: VersionSetId) -> NameId {
        self.pool.resolve_version_set_package_name(version_set)
    }

    fn solvable_name(&self, solvable: SolvableId) -> NameId {
        self.pool.resolve_solvable(solvable).name
    }

    fn version_sets_in_union(
        &self,
        version_set_union: VersionSetUnionId,
    ) -> impl Iterator<Item = VersionSetId> {
        self.pool.resolve_version_set_union(version_set_union)
    }

    fn resolve_condition(&self, condition: ConditionId) -> Condition {
        self.pool.resolve_condition(condition).clone()
    }
}

impl DependencyProvider for RPMProvider {
    async fn filter_candidates(
        &self,
        candidates: &[SolvableId],
        version_set: VersionSetId,
        inverse: bool,
    ) -> Vec<SolvableId> {
        candidates
            .iter()
            .copied()
            .filter(|&s| self.version_set_contains(version_set, s) != inverse)
            .collect()
    }

    async fn sort_candidates(&self, _solver: &SolverCache<Self>, solvables: &mut [SolvableId]) {
        solvables.sort_by(|a, b| {
            let a = &self.pool.resolve_solvable(*a).record;
            let b = &self.pool.resolve_solvable(*b).record;
            a.cmp(b)
        });
    }

    async fn get_candidates(&self, name: NameId) -> Option<Candidates> {
        let package_name = self.pool.resolve_package_name(name);
        let _package = self.provides_to_package.get(package_name)?;
        let candidates = match self.provides_to_package.get(package_name) {
            Some(candidates) => candidates.clone(),
            None => Vec::default(),
        };
        let mut result = Candidates {
            candidates,
            ..Candidates::default()
        };

        result.hint_dependencies_available = HintDependenciesAvailable::All;

        // let favor = self.favored.get(package_name);
        // let locked = self.locked.get(package_name);
        // let excluded = self.excluded.get(package_name);
        // for pack in package {
        //     let solvable = self.pool.resolve_solvable(*pack);
        //     candidates.candidates.push(solvable);
        //     // if Some(pack) == favor {
        //     //     candidates.favored = Some(solvable);
        //     // }
        //     // if Some(pack) == locked {
        //     //     candidates.locked = Some(solvable);
        //     // }
        //     // if let Some(excluded) = excluded.and_then(|d| d.get(pack)) {
        //     //     candidates
        //     //         .excluded
        //     //         .push((solvable, self.pool.intern_string(excluded)));
        //     // }
        // }

        Some(result)
    }

    async fn get_dependencies(&self, solvable: SolvableId) -> Dependencies {
        let candidate = self.pool.resolve_solvable(solvable);
        let pack = &candidate.record;

        let requirements = &pack.requires;

        let mut result = KnownDependencies::default();

        for req in requirements {
            if req.name.starts_with('/') || req.name.contains(" if ") {
                continue;
            };
            let dep_name = self.pool.intern_package_name(&req.name);
            let dep_spec = self
                .pool
                .intern_version_set(dep_name, RPMRequirement(req.clone()));
            result.requirements.push(ConditionalRequirement {
                condition: None,
                requirement: ResolvoRequirement::Single(dep_spec),
            });
        }
        if !self.disable_suggest {
            for req in &pack.suggests {
                if req.name.starts_with('/') || req.name.contains(" if ") {
                    continue;
                };
                let dep_name = self.pool.intern_package_name(&req.name);
                let dep_spec = self
                    .pool
                    .intern_version_set(dep_name, RPMRequirement(req.clone()));
                result.requirements.push(ConditionalRequirement {
                    condition: None,
                    requirement: ResolvoRequirement::Single(dep_spec),
                });
            }
        }

        Dependencies::Known(result)
    }
}
