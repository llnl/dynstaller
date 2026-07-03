use std::{
    collections::BTreeMap,
    fs::{File, OpenOptions},
    io::Write,
    path::{Component, Path, PathBuf},
};

use crate::{
    build,
    monitor::{ItemMetadata, Monitor},
    options::{MonitorOptions, PackerOptions},
};

use anyhow::Result;
use serde::Serialize;
use time::OffsetDateTime;
use zip::ZipWriter;

pub struct Packer {
    monitor_options: MonitorOptions,
    packer_options: PackerOptions,
    monitor: Box<dyn Monitor>,
}

impl Packer {
    pub fn new(
        monitor_options: MonitorOptions,
        packer_options: PackerOptions,
        monitor: Box<dyn Monitor>,
    ) -> Self {
        Packer {
            monitor_options,
            packer_options,
            monitor,
        }
    }

    fn files_normalized(&self) -> Result<BTreeMap<PathBuf, ItemMetadata>> {
        self.monitor.get_changed_files().map(|f| {
            f.into_iter()
                .map(|(p, m)| (Self::normalize_path(p), m))
                .collect()
        })
    }

    fn metadata(&self) -> Result<PackerMetadata> {
        Ok(PackerMetadata {
            version: PackerVersion::new(),
            timestamp: OffsetDateTime::now_utc(),
            monitor: self.monitor_options.clone(),
            packer: self.packer_options.clone(),
            files: self.files_normalized()?,
            registry_keys: self
                .monitor
                .get_changed_registry_keys()
                .unwrap_or_else(|| Ok(BTreeMap::default()))?,
        })
    }

    pub fn write_out(&self) -> Result<()> {
        log::info!(
            "Writing out changes to {}",
            self.packer_options.output.display()
        );

        let mut open_options = OpenOptions::new();
        open_options.write(true).truncate(true);
        if self.packer_options.overwrite {
            open_options.create(true);
        } else {
            open_options.create_new(true);
        }
        let file = open_options.open(&self.packer_options.output)?;
        let mut zip = ZipWriter::new(file);

        // Write metadata as JSON
        let metadata = self.metadata()?;
        let metadata_json = serde_json::to_string_pretty(&metadata)?;
        zip.start_file("metadata.json", zip::write::SimpleFileOptions::default())?;
        zip.write_all(metadata_json.as_bytes())?;

        // Write all changed files
        let changed_files = self.files_normalized()?;
        let base_path = Self::normalize_path(self.monitor_options.path.clone());
        log::debug!(
            "Base path: {} -> {}",
            self.monitor_options.path.display(),
            base_path.display()
        );

        let file_total = changed_files.len();
        let mut file_count = 0;
        for file_path in changed_files.keys() {
            if Self::is_reserved_path(file_path) {
                log::warn!("Skipping reserved path: {}", file_path.display());
                continue;
            }

            // Skip if the file doesn't exist anymore
            if !file_path.exists() {
                log::warn!("File no longer exists, skipping: {}", file_path.display());
                continue;
            }

            // Copy the file content
            let file = File::open(file_path);
            let mut file = match file {
                Ok(file) => file,
                Err(e) => {
                    log::error!("Failed to open file {}: {}", file_path.display(), e);
                    continue;
                }
            };

            let file_len = file.metadata()?.len();
            if file_len > self.packer_options.size_limit {
                log::warn!(
                    "File {} exceeds size limit ({} bytes), skipping",
                    file_path.display(),
                    file_len
                );
                continue;
            }

            // Create safe ZIP entry path using the helper function
            let zip_path = Self::create_zip_entry_path(file_path, &base_path);

            log::debug!(
                "Writing file ({} bytes): {} -> {}",
                file_len,
                file_path.display(),
                zip_path
            );

            if let Err(e) = zip.start_file(&zip_path, zip::write::SimpleFileOptions::default()) {
                log::error!("Failed to start ZIP entry for {zip_path}: {e}");
                continue;
            }

            if let Err(e) = std::io::copy(&mut file, &mut zip) {
                log::error!("Failed to write file {} to ZIP: {}", file_path.display(), e);
                continue;
            }

            file_count += 1;
        }

        zip.finish()?;
        log::info!(
            "Successfully wrote {file_count}/{file_total} files to {}",
            self.packer_options.output.display()
        );

        Ok(())
    }

    fn is_reserved_path<P: AsRef<Path>>(path: P) -> bool {
        let path = path.as_ref();

        let mut components = path.components();
        if let (Some(Component::Prefix(_)), Some(Component::RootDir), Some(Component::Normal(name))) =
            (components.next(), components.next(), components.next())
            && name.to_string_lossy().starts_with('$')
        {
            // Check for reserved names like $Extend, $Mft, etc.
            // https://flatcap.github.io/linux-ntfs/ntfs/files/index.html
            return true;
        }
        false
    }

    /// Normalize a Windows path by resolving it to its canonical form
    /// This handles UNC paths, relative paths, and other complex Windows path formats
    fn normalize_path<P: AsRef<Path>>(path: P) -> PathBuf {
        let mut path = path.as_ref().to_owned();

        let mut components = path.components();
        if let (Some(Component::Prefix(prefix)), None) = (components.next(), components.next()) {
            // If the path starts with a prefix (like "C:"), we need to handle it specially
            let mut drive_root = PathBuf::new();
            drive_root.push(Component::Prefix(prefix));
            drive_root.push(Component::RootDir);
            path = drive_root;
        }

        if let Ok(canonical) = path.canonicalize() {
            canonical
        } else {
            // If canonicalization fails, at least normalize components
            let mut normalized = PathBuf::new();

            for component in path.components() {
                match component {
                    Component::ParentDir => {
                        normalized.pop();
                    }
                    Component::CurDir => {
                        // Skip current directory components
                    }
                    _ => {
                        normalized.push(component);
                    }
                }
            }

            normalized
        }
    }

    /// Create a safe ZIP entry path from a file path relative to a base path
    fn create_zip_entry_path(normalized_file: &Path, normalized_base: &Path) -> String {
        // Try to get relative path from normalized paths
        let relative_path = match normalized_file.strip_prefix(normalized_base) {
            Ok(rel_path) => rel_path,
            Err(_) => {
                // If we can't make it relative, use just the filename
                // This is a fallback for cases where paths are on different drives/volumes
                normalized_file
                    .file_name()
                    .map_or_else(|| Path::new("unknown_file"), Path::new)
            }
        };

        // Convert to ZIP-safe path (forward slashes, no problematic characters)
        let zip_path = relative_path
            .to_string_lossy()
            .replace('\\', "/")
            .replace([':', '|', '<', '>', '"', '*', '?'], "_");

        format!("files/{zip_path}")
    }
}

#[derive(Serialize, Debug)]
struct PackerMetadata {
    version: PackerVersion,
    #[serde(with = "time::serde::rfc3339")]
    timestamp: OffsetDateTime,
    monitor: MonitorOptions,
    packer: PackerOptions,
    files: BTreeMap<PathBuf, ItemMetadata>,
    registry_keys: BTreeMap<PathBuf, ItemMetadata>,
}

#[derive(Serialize, Debug)]
struct PackerVersion {
    version: String,
    branch: String,
    commit: String,
    build_time: String,
    rust_version: String,
    rust_channel: String,
}

impl PackerVersion {
    fn new() -> Self {
        PackerVersion {
            version: build::PKG_VERSION.to_owned(),
            branch: build::BRANCH.to_owned(),
            commit: build::SHORT_COMMIT.to_owned(),
            build_time: build::BUILD_TIME.to_owned(),
            rust_version: build::RUST_VERSION.to_owned(),
            rust_channel: build::RUST_CHANNEL.to_owned(),
        }
    }
}
