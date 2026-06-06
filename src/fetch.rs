use std::fs::{self, File};
use std::io;
use std::path::Path;

use reqwest::blocking::Client;
use rpmrepo_metadata::RepositoryReader;
use url::Url;

/// Download RPM repository metadata from a remote URL into a local directory.
///
/// Fetches `repomd.xml` followed by the primary, filelists, and other metadata files.
/// Skips the download entirely if `repomd.xml` already exists in `target_folder`.
pub fn fetch_repodata(base_url: Url, target_folder: &Path) {
    let client = Client::new();

    if target_folder.join("repodata/repomd.xml").exists() {
        println!("repomd.xml already exists");
        return;
    }

    // Fetch repomd.xml first - it's the manifest that lists all other metadata files.
    let url = base_url.join("repodata/repomd.xml").unwrap();
    let mut resp = client.get(url).send().unwrap();

    let path = target_folder.to_path_buf();
    fs::create_dir_all(path.join("repodata")).unwrap();
    let mut file = File::create(path.join("repodata/repomd.xml")).unwrap();
    io::copy(&mut resp, &mut file).unwrap();

    // Parse repomd.xml to discover the paths of each metadata file, then
    // download them to the same relative paths under target_folder.
    let reader = RepositoryReader::new_from_directory(target_folder).unwrap();
    let repomd = reader.repomd();

    let data = repomd.get_filelist_data().unwrap();
    let url = base_url
        .join(&data.location_href.to_string_lossy())
        .unwrap();
    let mut resp = client.get(url).send().unwrap();
    let mut file = File::create(target_folder.join(&data.location_href)).unwrap();
    io::copy(&mut resp, &mut file).unwrap();

    let data = repomd.get_other_data().unwrap();
    let url = base_url
        .join(&data.location_href.to_string_lossy())
        .unwrap();
    let mut resp = client.get(url).send().unwrap();
    let mut file = File::create(target_folder.join(&data.location_href)).unwrap();
    io::copy(&mut resp, &mut file).unwrap();

    let data = repomd.get_primary_data().unwrap();
    let url = base_url
        .join(&data.location_href.to_string_lossy())
        .unwrap();
    let mut resp = client.get(url).send().unwrap();
    let mut file = File::create(target_folder.join(&data.location_href)).unwrap();
    io::copy(&mut resp, &mut file).unwrap();
}
