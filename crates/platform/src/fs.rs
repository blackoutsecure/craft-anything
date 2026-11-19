//! File safety: bounded regular-file reads and atomic writes (temp file, fsync, rename),
//! optionally private (0600 on Unix).

use craft_anything_evidence::{ErrorCode, ToolError};
use std::ffi::OsStr;
use std::io::{Read as _, Write as _};
use std::path::{Component, Path, PathBuf};
use std::sync::atomic::{AtomicU64, Ordering};

static COUNTER: AtomicU64 = AtomicU64::new(0);

pub use cap_std::fs::Metadata as ReadOnlyMetadata;

/// Open a regular file and return metadata from the opened handle. Symlinks to regular files
/// are allowed. On Unix, a path replaced by a FIFO cannot block the open before its type is checked.
pub fn open_regular_file(path: &Path) -> Result<(std::fs::File, std::fs::Metadata), ToolError> {
    let invalid = || ToolError::invalid(format!("{} is not a regular file", path.display()));
    let before = std::fs::metadata(path).map_err(|e| ToolError::io(path.display(), e))?;
    if !before.is_file() {
        return Err(invalid());
    }
    let mut options = std::fs::OpenOptions::new();
    options.read(true);
    #[cfg(unix)]
    {
        use std::os::unix::fs::OpenOptionsExt as _;
        options.custom_flags(nix::libc::O_NONBLOCK);
    }
    let file = options.open(path).map_err(|e| ToolError::io(path.display(), e))?;
    let metadata = file.metadata().map_err(|e| ToolError::io(path.display(), e))?;
    if !metadata.is_file() {
        return Err(invalid());
    }
    Ok((file, metadata))
}

/// Read a whole regular file, enforcing `max` on the bytes read as well as the size metadata.
/// The one-byte overflow probe does not add to `max`, so even `u64::MAX` cannot overflow.
pub fn read_file_capped(path: &Path, max: u64) -> Result<Vec<u8>, ToolError> {
    let (file, metadata) = open_regular_file(path)?;
    read_file_handle_capped(file, metadata, path, max)
}

fn read_file_handle_capped(mut file: std::fs::File, metadata: std::fs::Metadata, path: &Path, max: u64) -> Result<Vec<u8>, ToolError> {
    if metadata.len() > max {
        return Err(ToolError::new(ErrorCode::OverLimit, format!("{} is {} bytes; the limit is {max}", path.display(), metadata.len()))
            .with_remediation("Raise the size limit parameter if you really want to read it."));
    }
    let mut bytes = Vec::new();
    (&mut file).take(max).read_to_end(&mut bytes).map_err(|e| ToolError::io(path.display(), e))?;
    let mut extra = [0u8; 1];
    match file.read_exact(&mut extra) {
        Ok(()) => Err(ToolError::new(ErrorCode::OverLimit, format!("{} contains more than {max} bytes; the read limit was reached", path.display()))
            .with_remediation("Raise the size limit parameter if you really want to read it.")),
        Err(error) if error.kind() == std::io::ErrorKind::UnexpectedEof => Ok(bytes),
        Err(error) => Err(ToolError::io(path.display(), error)),
    }
}

/// Read-only directory capability. Every component is opened without following links, and
/// file reads use the validated handle rather than reopening a checked pathname.
#[derive(Debug)]
pub struct ReadOnlyDirectory(cap_std::fs::Dir);

impl ReadOnlyDirectory {
    /// Open an absolute, physical directory path, including its ancestors without links.
    pub fn open(path: &Path) -> Result<Self, ToolError> {
        use cap_std::ambient_authority;

        if !path.is_absolute() {
            return Err(ToolError::invalid("A read-only directory root must be an absolute path."));
        }
        let mut anchor = PathBuf::new();
        let mut relative = PathBuf::new();
        for component in path.components() {
            match component {
                Component::Prefix(_) | Component::RootDir => anchor.push(component.as_os_str()),
                Component::Normal(name) => relative.push(name),
                Component::CurDir => {}
                Component::ParentDir => return Err(ToolError::invalid("A directory root cannot contain parent traversal.")),
            }
        }
        let directory = cap_std::fs::Dir::open_ambient_dir(&anchor, ambient_authority()).map_err(|error| ToolError::io(path.display(), error))?;
        Self(directory).open_dir(&relative)
    }

    /// Open a descendant directory without following any symbolic-link component.
    pub fn open_dir(&self, relative: &Path) -> Result<Self, ToolError> {
        use cap_fs_ext::DirExt as _;

        let mut directory = self.0.try_clone().map_err(|error| ToolError::io(relative.display(), error))?;
        for name in relative_parts(relative)? {
            directory = directory.open_dir_nofollow(name).map_err(|error| ToolError::io(relative.display(), error))?;
        }
        Ok(Self(directory))
    }

    /// List this opened directory, retaining its handle while names are consumed.
    pub fn entries(&self) -> std::io::Result<impl Iterator<Item = std::io::Result<std::ffi::OsString>> + use<>> {
        Ok(self.0.entries()?.map(|entry| entry.map(|entry| entry.file_name())))
    }

    /// Read descendant metadata without following the last link or any parent link.
    pub fn symlink_metadata(&self, relative: &Path) -> Result<ReadOnlyMetadata, ToolError> {
        let (directory, name) = self.parent_directory(relative)?;
        directory.0.symlink_metadata(name).map_err(|error| ToolError::io(relative.display(), error))
    }

    /// Open a regular descendant file without following links or reading its contents.
    pub fn open_regular_file(&self, relative: &Path) -> Result<(std::fs::File, std::fs::Metadata), ToolError> {
        self.open_regular_file_after(relative, || {})
    }

    fn open_regular_file_after(&self, relative: &Path, before_open: impl FnOnce()) -> Result<(std::fs::File, std::fs::Metadata), ToolError> {
        use cap_fs_ext::{FollowSymlinks, OpenOptionsFollowExt as _};

        let (directory, name) = self.parent_directory(relative)?;
        before_open();
        let mut options = cap_std::fs::OpenOptions::new();
        options.read(true).follow(FollowSymlinks::No);
        #[cfg(unix)]
        {
            use cap_std::fs::OpenOptionsExt as _;
            options.custom_flags(nix::libc::O_NONBLOCK);
        }
        let file = directory.0.open_with(name, &options).map_err(|error| ToolError::io(relative.display(), error))?.into_std();
        let metadata = file.metadata().map_err(|error| ToolError::io(relative.display(), error))?;
        if !metadata.is_file() {
            return Err(ToolError::invalid(format!("{} is not a regular file", relative.display())));
        }
        Ok((file, metadata))
    }

    fn parent_directory<'a>(&self, relative: &'a Path) -> Result<(Self, &'a OsStr), ToolError> {
        let parts = relative_parts(relative)?;
        let (name, parents) = parts.split_last().ok_or_else(|| ToolError::invalid("A directory member needs a relative filename."))?;
        let parent: PathBuf = parents.iter().collect();
        Ok((self.open_dir(&parent)?, *name))
    }

    /// Read a regular descendant through its opened handle with the shared hard byte cap.
    pub fn read_file_capped(&self, relative: &Path, max: u64) -> Result<Vec<u8>, ToolError> {
        let (file, metadata) = self.open_regular_file(relative)?;
        read_file_handle_capped(file, metadata, relative, max)
    }
}

fn relative_parts(path: &Path) -> Result<Vec<&OsStr>, ToolError> {
    let mut parts = Vec::new();
    for component in path.components() {
        match component {
            Component::Normal(name) => parts.push(name),
            Component::CurDir => {}
            _ => return Err(ToolError::invalid(format!("{} is not a contained relative path", path.display()))),
        }
    }
    Ok(parts)
}

/// Write `bytes` to `path` atomically, keeping the existing file's permissions when it exists.
pub fn write_atomic(path: &Path, bytes: &[u8]) -> Result<(), ToolError> {
    write_impl(path, bytes, false)
}

/// Write `bytes` to `path` atomically with owner-only permissions (0600 on Unix). Used for
/// configuration files that may hold paths or tokens, and for the key fallback file.
pub fn write_atomic_private(path: &Path, bytes: &[u8]) -> Result<(), ToolError> {
    write_impl(path, bytes, true)
}

/// Restrict an existing, caller-selected private-data directory to its owner (0700 on Unix).
/// This changes the supplied directory, including an existing custom config directory, not its
/// ancestors. The caller must select a dedicated directory, not an unrelated shared folder.
/// Returns an error if permissions cannot be set; does not create the directory.
pub fn set_private_dir(dir: &Path) -> Result<(), ToolError> {
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt as _;
        std::fs::set_permissions(dir, std::fs::Permissions::from_mode(0o700)).map_err(|e| ToolError::io(dir.display(), e))?;
    }
    #[cfg(not(unix))]
    let _ = dir;
    Ok(())
}

fn write_impl(path: &Path, bytes: &[u8], private: bool) -> Result<(), ToolError> {
    let dir = match path.parent() {
        Some(d) if !d.as_os_str().is_empty() => d.to_path_buf(),
        Some(_) => std::path::PathBuf::from("."),
        None => return Err(ToolError::invalid(format!("{} has no parent folder", path.display()))),
    };
    std::fs::create_dir_all(&dir).map_err(|e| ToolError::io(dir.display(), e))?;
    let existing_perms = std::fs::metadata(path).ok().map(|m| m.permissions());
    let (tmp, mut f) = create_temp(&dir, path, private, &COUNTER)?;
    let result = (|| {
        if private {
            set_private(&tmp)?;
        } else if let Some(p) = existing_perms {
            std::fs::set_permissions(&tmp, p).map_err(|e| ToolError::io(tmp.display(), e))?;
        }
        f.write_all(bytes).map_err(|e| ToolError::io(tmp.display(), e))?;
        f.sync_all().map_err(|e| ToolError::io(tmp.display(), e))?;
        drop(f);
        rename_retrying(&tmp, path).map_err(|e| ToolError::io(path.display(), e))
    })();
    if result.is_err() {
        let _ = std::fs::remove_file(&tmp);
    }
    result
}

/// Reserve a short, new temporary file before entering the cleanup scope. A collision belongs to
/// another write, so it must never be truncated or removed by this call.
fn create_temp(dir: &Path, destination: &Path, private: bool, counter: &AtomicU64) -> Result<(std::path::PathBuf, std::fs::File), ToolError> {
    let mut options = std::fs::OpenOptions::new();
    options.write(true).create_new(true);
    #[cfg(unix)]
    {
        use std::os::unix::fs::OpenOptionsExt as _;
        if private {
            options.mode(0o600);
        }
    }
    #[cfg(not(unix))]
    let _ = private;
    let destination_name = destination.file_name().and_then(|name| name.to_str());
    for _ in 0..64 {
        let n = counter.fetch_add(1, Ordering::Relaxed);
        let name = format!(".craft-anything.tmp-{}-{n}", std::process::id());
        // Conservatively exclude case-insensitive and Windows trailing-dot/space aliases.
        if destination_name.is_some_and(|destination| destination.trim_end_matches(['.', ' ']).eq_ignore_ascii_case(&name)) {
            continue;
        }
        let tmp = dir.join(name);
        match options.open(&tmp) {
            Ok(file) => return Ok((tmp, file)),
            Err(error) if error.kind() == std::io::ErrorKind::AlreadyExists => continue,
            Err(error) => return Err(ToolError::io(tmp.display(), error)),
        }
    }
    let error = std::io::Error::new(std::io::ErrorKind::AlreadyExists, "could not reserve an unused temporary file");
    Err(ToolError::io(dir.display(), error))
}

/// On Windows a file another program has open for a moment (an antivirus scan, the search
/// indexer) can't be replaced: try again briefly before giving up.
fn rename_retrying(from: &Path, to: &Path) -> std::io::Result<()> {
    let mut tries = 0;
    loop {
        match std::fs::rename(from, to) {
            Err(e) if e.kind() == std::io::ErrorKind::PermissionDenied && tries < 20 => {
                tries += 1;
                std::thread::sleep(std::time::Duration::from_millis(100));
            }
            r => return r,
        }
    }
}

#[cfg(unix)]
fn set_private(path: &Path) -> Result<(), ToolError> {
    use std::os::unix::fs::PermissionsExt as _;
    std::fs::set_permissions(path, std::fs::Permissions::from_mode(0o600)).map_err(|e| ToolError::io(path.display(), e))
}

#[cfg(not(unix))]
fn set_private(_path: &Path) -> Result<(), ToolError> {
    // Windows: files under the user's profile are already private to the user by default ACLs.
    Ok(())
}

/// Copy `from` to `to` only if `to` does not exist yet (the first backup is never overwritten).
/// Returns true when a copy was made, false when a backup already existed.
pub fn backup_once(from: &Path, to: &Path) -> Result<bool, ToolError> {
    if to.exists() {
        return Ok(false);
    }
    let bytes = std::fs::read(from).map_err(|e| ToolError::io(from.display(), e))?;
    let mut f = match std::fs::OpenOptions::new().write(true).create_new(true).open(to) {
        Ok(f) => f,
        Err(e) if e.kind() == std::io::ErrorKind::AlreadyExists => return Ok(false),
        Err(e) => return Err(ToolError::io(to.display(), e)),
    };
    set_private(to)?;
    f.write_all(&bytes).map_err(|e| ToolError::io(to.display(), e))?;
    f.sync_all().map_err(|e| ToolError::io(to.display(), e))?;
    Ok(true)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[cfg(unix)]
    #[test]
    fn rooted_reads_refuse_a_same_size_symlink_swap_before_opening() {
        use std::os::unix::fs::symlink;

        let root = tempfile::tempdir().unwrap();
        let outside = tempfile::tempdir().unwrap();
        let member = root.path().join("Info.plist");
        let external = outside.path().join("Info.plist");
        std::fs::write(&member, b"inside").unwrap();
        std::fs::write(&external, b"beyond").unwrap();
        let directory = ReadOnlyDirectory::open(&std::fs::canonicalize(root.path()).unwrap()).unwrap();
        let result = directory.open_regular_file_after(Path::new("Info.plist"), || {
            std::fs::remove_file(&member).unwrap();
            symlink(&external, &member).unwrap();
        });
        assert!(result.is_err(), "a replacement must not open the external plist");
    }

    #[cfg(unix)]
    #[test]
    fn rooted_reads_keep_the_parent_handle_when_its_path_is_replaced() {
        use std::os::unix::fs::symlink;

        let root = tempfile::tempdir().unwrap();
        let outside = tempfile::tempdir().unwrap();
        let parent = root.path().join("parent");
        std::fs::create_dir(&parent).unwrap();
        std::fs::write(parent.join("Info.plist"), b"inside").unwrap();
        std::fs::write(outside.path().join("Info.plist"), b"beyond").unwrap();
        let directory = ReadOnlyDirectory::open(&std::fs::canonicalize(root.path()).unwrap()).unwrap();
        let (file, metadata) = directory
            .open_regular_file_after(Path::new("parent/Info.plist"), || {
                std::fs::rename(&parent, root.path().join("saved-parent")).unwrap();
                symlink(outside.path(), &parent).unwrap();
            })
            .unwrap();
        assert_eq!(read_file_handle_capped(file, metadata, Path::new("parent/Info.plist"), 6).unwrap(), b"inside");
    }

    #[cfg(unix)]
    #[test]
    fn bounded_handle_reads_do_not_reopen_a_replaced_path() {
        use std::os::unix::fs::symlink;

        let root = tempfile::tempdir().unwrap();
        let outside = tempfile::tempdir().unwrap();
        let member = root.path().join("Info.plist");
        let external = outside.path().join("Info.plist");
        std::fs::write(&member, b"inside").unwrap();
        std::fs::write(&external, b"beyond").unwrap();
        let directory = ReadOnlyDirectory::open(&std::fs::canonicalize(root.path()).unwrap()).unwrap();
        let (file, metadata) = directory.open_regular_file(Path::new("Info.plist")).unwrap();
        std::fs::remove_file(&member).unwrap();
        symlink(&external, &member).unwrap();
        assert_eq!(read_file_handle_capped(file, metadata, Path::new("Info.plist"), 6).unwrap(), b"inside");
    }

    #[test]
    fn rooted_reads_refuse_path_escape_and_enforce_the_existing_byte_cap() {
        let root = tempfile::tempdir().unwrap();
        std::fs::write(root.path().join("Info.plist"), b"inside").unwrap();
        let directory = ReadOnlyDirectory::open(&std::fs::canonicalize(root.path()).unwrap()).unwrap();
        assert!(directory.read_file_capped(Path::new("../outside"), 10).is_err());
        assert!(directory.read_file_capped(root.path(), 10).is_err());
        assert_eq!(directory.read_file_capped(Path::new("Info.plist"), 5).unwrap_err().code, ErrorCode::OverLimit);
        assert_eq!(directory.read_file_capped(Path::new("Info.plist"), 6).unwrap(), b"inside");
    }

    #[cfg(unix)]
    #[test]
    fn rooted_directories_refuse_symlink_targets_with_trailing_slashes() {
        use std::os::unix::fs::symlink;

        let root = tempfile::tempdir().unwrap();
        let outside = tempfile::tempdir().unwrap();
        symlink(format!("{}/", outside.path().display()), root.path().join("escape")).unwrap();
        let directory = ReadOnlyDirectory::open(&std::fs::canonicalize(root.path()).unwrap()).unwrap();
        assert!(directory.open_dir(Path::new("escape")).is_err());
        assert!(directory.open_dir(Path::new("escape/")).is_err());
    }

    #[test]
    fn atomic_write_replaces_and_private_is_0600() {
        let dir = tempfile::tempdir().unwrap();
        let p = dir.path().join("sub").join("a.txt");
        write_atomic(&p, b"one").unwrap();
        write_atomic(&p, b"two").unwrap();
        assert_eq!(std::fs::read(&p).unwrap(), b"two");
        let q = dir.path().join("secret");
        write_atomic_private(&q, b"k").unwrap();
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt as _;
            assert_eq!(std::fs::metadata(&q).unwrap().permissions().mode() & 0o777, 0o600);
        }
        // no temp files left behind
        assert_eq!(std::fs::read_dir(dir.path().join("sub")).unwrap().count(), 1);
    }

    #[cfg(unix)]
    #[test]
    fn temporary_file_creation_permissions_respect_private_flag() {
        use std::os::unix::fs::PermissionsExt as _;

        let dir = tempfile::tempdir().unwrap();
        let counter = AtomicU64::new(0);
        let destination = dir.path().join("settings.json");
        let (_, private) = create_temp(dir.path(), &destination, true, &counter).unwrap();
        // Observe the new file directly, before write_impl can call set_private.
        assert_eq!(private.metadata().unwrap().permissions().mode() & 0o077, 0);

        let regular = std::fs::File::create(dir.path().join("regular")).unwrap();
        let (_, non_private) = create_temp(dir.path(), &destination, false, &counter).unwrap();
        assert_eq!(non_private.metadata().unwrap().permissions().mode() & 0o777, regular.metadata().unwrap().permissions().mode() & 0o777);
    }

    #[test]
    fn temporary_candidates_exclude_destination_aliases() {
        let name = format!(".craft-anything.tmp-{}-0", std::process::id());
        for (component, next_counter) in [
            (name.clone(), 2),
            (name.to_ascii_uppercase(), 2),
            (format!("{name}. "), 2),
            (format!("{}. ", name.to_ascii_uppercase()), 2),
            ("settings.json".into(), 1),
        ] {
            let dir = tempfile::tempdir().unwrap();
            let counter = AtomicU64::new(0);
            let destination = dir.path().join(".").join(component);
            let (temporary, file) = create_temp(dir.path(), &destination, false, &counter).unwrap();
            assert!(!destination.exists());
            assert_eq!(counter.load(Ordering::Relaxed), next_counter);
            assert_eq!(temporary, dir.path().join(format!(".craft-anything.tmp-{}-{}", std::process::id(), next_counter - 1)));
            assert_eq!(file.metadata().unwrap().len(), 0);
        }
    }

    #[test]
    fn backup_is_never_overwritten() {
        let dir = tempfile::tempdir().unwrap();
        let a = dir.path().join("a");
        let b = dir.path().join("a.bak");
        std::fs::write(&a, "first").unwrap();
        assert!(backup_once(&a, &b).unwrap());
        std::fs::write(&a, "second").unwrap();
        assert!(!backup_once(&a, &b).unwrap());
        assert_eq!(std::fs::read_to_string(&b).unwrap(), "first");
    }
}
