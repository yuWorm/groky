use std::path::{Path, PathBuf};
use std::sync::LazyLock;
use std::time::{Duration, Instant, SystemTime};

use async_trait::async_trait;
use futures_util::StreamExt;
use sha2::{Digest, Sha256};
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::time::timeout;
use uuid::Uuid;
use xai_grok_ssh::{
    ConnectionLease, SshCommandEvent,
    sftp::protocol::{FileAttributes, OpenFlags},
};
use xai_grok_workspace_types::ssh_wire::{SshWorkerBuildInfo, local_worker_build_info};

use crate::compat::{parse_sha256, release_download_url, repo};

const COMMAND_TIMEOUT: Duration = Duration::from_secs(240);
const COMMAND_START_TIMEOUT: Duration = Duration::from_secs(20);
const COMMAND_OUTPUT_LIMIT: usize = 64 * 1024;
const INFO_OUTPUT_LIMIT: usize = 16 * 1024;
const DOWNLOAD_TIMEOUT: Duration = Duration::from_secs(180);
const UPLOAD_TIMEOUT: Duration = Duration::from_secs(15 * 60);
const MAX_ARTIFACT_BYTES: u64 = 2 * 1024 * 1024 * 1024;
const MAX_CHECKSUM_BYTES: usize = 16 * 1024;
const COPY_CHUNK_BYTES: usize = 64 * 1024;

/// UI boundary for an exceptional local download and authenticated SFTP upload.
#[async_trait]
pub(super) trait WorkerInstallInteraction: Send + Sync {
    fn progress(&self, message: &str);

    async fn approve_local_upload(
        &self,
        version: &str,
        platform: &str,
        remote_error: &str,
    ) -> Result<bool, String>;
}

/// Resolve, validate, and if necessary install the exact worker required by this
/// client. This is deliberately only used for the built-in worker command;
/// user-configured commands remain entirely user-managed.
pub(super) async fn prepare_worker(
    lease: &ConnectionLease,
    local_home: &Path,
    interaction: &dyn WorkerInstallInteraction,
) -> Result<Vec<String>, String> {
    let remote = LeaseRemote { lease };
    interaction.progress("Detecting remote worker platform");
    let platform = probe_remote_platform(&remote).await?;
    ensure_supported_platform(&platform)?;
    let expected = expected_worker_info_for_remote(local_worker_build_info(), &platform);
    let current_executable = if expected.product_version.is_none() {
        Some(
            std::env::current_exe()
                .map_err(|error| format!("could not locate local groky executable: {error}"))?,
        )
    } else {
        None
    };
    let urls = expected
        .product_version
        .as_deref()
        .map(|version| release_urls(version, &platform))
        .transpose()?;

    prepare_worker_with_sources(
        &remote,
        local_home,
        interaction,
        expected,
        platform,
        urls,
        current_executable.as_deref(),
    )
    .await
}

/// Module-private installer seam. Production supplies authenticated SSH
/// transport and trusted GitHub-release URLs; tests supply real local shell
/// commands and a local HTTP release fixture without changing production
/// endpoints or relying on a published release.
async fn prepare_worker_with_sources(
    remote: &dyn RemoteTransport,
    local_home: &Path,
    interaction: &dyn WorkerInstallInteraction,
    expected: SshWorkerBuildInfo,
    platform: RemotePlatform,
    release_urls: Option<ReleaseUrls>,
    current_executable: Option<&Path>,
) -> Result<Vec<String>, String> {
    ensure_supported_platform(&platform)?;
    let desired = DesiredWorker::from_local(expected, &platform, current_executable).await?;
    let target = InstallTarget::new(&platform, &desired)?;

    interaction.progress("Checking managed SSH worker");
    if managed_worker_matches(remote, &target, &desired.expected).await? {
        interaction.progress("Using matching managed SSH worker");
        return Ok(target.argv());
    }

    let stage = target.stage();
    let result = async {
        create_remote_stage(remote, &target, &stage).await?;
        match &desired.kind {
            DesiredKind::Release => {
                let urls = release_urls
                    .as_ref()
                    .ok_or_else(|| "release worker installation is missing release URLs".to_owned())?;
                interaction.progress("Downloading exact worker release on remote host");
                if let Err(remote_error) = download_and_validate_remote(
                    remote,
                    &stage,
                    urls,
                    &desired.expected,
                )
                .await
                {
                    cleanup_remote_stage(remote, &target, &stage).await;
                    interaction.progress("Remote download failed; local download and SSH upload require approval");
                    let approved = interaction
                        .approve_local_upload(
                            &desired.display_version,
                            &platform.label(),
                            &remote_error,
                        )
                        .await
                        .map_err(|error| {
                            format!(
                                "could not obtain approval for local worker upload after remote download failed: {error}"
                            )
                        })?;
                    if !approved {
                        return Err(format!(
                            "local worker upload cancelled after remote download failed: {remote_error}"
                        ));
                    }

                    interaction.progress("Downloading exact worker release locally");
                    let local_artifact =
                        download_verified_locally(local_home, urls, &desired.display_version).await?;
                    let upload_result = async {
                        create_remote_stage(remote, &target, &stage).await?;
                        interaction.progress("Uploading worker over authenticated SFTP");
                        timeout(UPLOAD_TIMEOUT, remote.upload(&local_artifact.path, &stage.binary))
                            .await
                            .map_err(|_| "authenticated SFTP worker upload timed out".to_owned())??;
                        write_remote_checksum(remote, &stage.checksum, &local_artifact.checksum).await?;
                        validate_remote_stage(remote, &stage, &desired.expected).await
                    }
                    .await;
                    let _ = tokio::fs::remove_file(&local_artifact.path).await;
                    upload_result?;
                }
            }
            DesiredKind::Dev => {
                let current_executable = current_executable.ok_or_else(|| {
                    "development worker installation was missing the local executable".to_owned()
                })?;
                interaction.progress("Local development build requires explicit SSH upload approval");
                let approved = interaction
                    .approve_local_upload(
                        &desired.display_version,
                        &platform.label(),
                        "development builds are not published as releases",
                    )
                    .await
                    .map_err(|error| {
                        format!("could not obtain approval for local development worker upload: {error}")
                    })?;
                if !approved {
                    return Err("local development worker upload cancelled".into());
                }
                interaction.progress("Uploading local development worker over authenticated SFTP");
                timeout(UPLOAD_TIMEOUT, remote.upload(current_executable, &stage.binary))
                    .await
                    .map_err(|_| "authenticated SFTP development worker upload timed out".to_owned())??;
                let checksum = desired
                    .local_checksum
                    .as_deref()
                    .ok_or_else(|| "development worker was missing its local checksum".to_owned())?;
                write_remote_checksum(remote, &stage.checksum, checksum).await?;
                validate_remote_stage(remote, &stage, &desired.expected).await?;
            }
        }

        interaction.progress("Publishing validated SSH worker");
        match publish_remote_stage(remote, &target, &stage).await? {
            PublishOutcome::Published => {
                cleanup_remote_stage(remote, &target, &stage).await;
                Ok(target.argv())
            }
            PublishOutcome::Existing => {
                cleanup_remote_stage(remote, &target, &stage).await;
                if managed_worker_matches(remote, &target, &desired.expected).await? {
                    Ok(target.argv())
                } else {
                    Err(format!(
                        "managed worker path {} already exists but does not match this client; refusing to replace an existing worker",
                        target.binary
                    ))
                }
            }
        }
    }
    .await;
    if result.is_err() {
        cleanup_remote_stage(remote, &target, &stage).await;
    }
    result
}

#[derive(Clone, Debug)]
struct RemotePlatform {
    home: String,
    os: String,
    arch: String,
}

impl RemotePlatform {
    fn label(&self) -> String {
        format!("{}-{}", self.os, self.arch)
    }

    fn groky_home(&self) -> String {
        let home = self.home.trim_end_matches('/');
        if home.is_empty() {
            "/.groky".into()
        } else {
            format!("{home}/.groky")
        }
    }

    fn worker_root(&self) -> String {
        format!("{}/workers", self.groky_home())
    }
}

fn expected_worker_info_for_remote(
    mut local: SshWorkerBuildInfo,
    platform: &RemotePlatform,
) -> SshWorkerBuildInfo {
    local.os.clone_from(&platform.os);
    local.arch.clone_from(&platform.arch);
    local
}

#[derive(Clone, Debug)]
struct ReleaseUrls {
    artifact: String,
    checksum: String,
    /// Only the module-private local fixture may disable this. Production URLs
    /// are fixed GitHub HTTPS release assets.
    require_https: bool,
}

#[derive(Debug)]
struct DownloadedArtifact {
    path: PathBuf,
    checksum: String,
}

#[derive(Debug)]
struct DesiredWorker {
    expected: SshWorkerBuildInfo,
    kind: DesiredKind,
    directory_key: String,
    display_version: String,
    local_checksum: Option<String>,
}

#[derive(Clone, Debug)]
struct CachedExecutableDigest {
    path: std::path::PathBuf,
    length: u64,
    modified: Option<SystemTime>,
    digest: String,
}

static LOCAL_EXECUTABLE_DIGEST: LazyLock<tokio::sync::Mutex<Option<CachedExecutableDigest>>> =
    LazyLock::new(|| tokio::sync::Mutex::new(None));

#[derive(Debug)]
enum DesiredKind {
    Release,
    Dev,
}

impl DesiredWorker {
    async fn from_local(
        expected: SshWorkerBuildInfo,
        platform: &RemotePlatform,
        current_executable: Option<&Path>,
    ) -> Result<Self, String> {
        match expected.product_version.as_deref() {
            Some(raw_version) => {
                let version = normalized_release_version(raw_version)?;
                Ok(Self {
                    expected,
                    kind: DesiredKind::Release,
                    directory_key: version.clone(),
                    display_version: version,
                    local_checksum: None,
                })
            }
            None => {
                let (local_os, local_arch) = local_platform()?;
                if platform.os != local_os || platform.arch != local_arch {
                    return Err(format!(
                        "local dev build cannot run on remote {}; local platform is {local_os}-{local_arch}. \
                         Build groky for the remote platform or use a tagged release.",
                        platform.label()
                    ));
                }
                let current_executable = current_executable.ok_or_else(|| {
                    "development worker installation was missing the local executable".to_owned()
                })?;
                let local_checksum = cached_current_executable_sha256(current_executable).await?;
                let directory_key = format!("dev-{local_checksum}");
                Ok(Self {
                    expected,
                    kind: DesiredKind::Dev,
                    display_version: directory_key.clone(),
                    directory_key,
                    local_checksum: Some(local_checksum),
                })
            }
        }
    }
}

#[derive(Debug)]
struct InstallTarget {
    groky_home: String,
    root: String,
    version_dir: String,
    platform_dir: String,
    binary: String,
    platform: String,
    lock: String,
}

impl InstallTarget {
    fn new(platform: &RemotePlatform, desired: &DesiredWorker) -> Result<Self, String> {
        safe_component("worker release", &desired.directory_key)?;
        let groky_home = platform.groky_home();
        let root = platform.worker_root();
        let version_dir = format!("{root}/{}", desired.directory_key);
        let platform_label = platform.label();
        safe_component("worker platform", &platform_label)?;
        let platform_dir = format!("{version_dir}/{platform_label}");
        Ok(Self {
            groky_home,
            root: root.clone(),
            version_dir,
            binary: format!("{platform_dir}/groky"),
            platform_dir,
            lock: format!(
                "{root}/.install-{}-{platform_label}.lock",
                desired.directory_key
            ),
            platform: platform_label,
        })
    }

    fn stage(&self) -> InstallStage {
        let nonce = Uuid::now_v7();
        let directory = format!("{}/.stage-{}-{nonce}", self.root, self.platform);
        let platform_dir = format!("{directory}/{}", self.platform);
        InstallStage {
            directory,
            platform_dir: platform_dir.clone(),
            binary: format!("{platform_dir}/groky"),
            checksum: format!("{platform_dir}/groky.sha256"),
        }
    }

    fn argv(&self) -> Vec<String> {
        vec![self.binary.clone(), "worker".into(), "--stdio".into()]
    }
}

#[derive(Debug)]
struct InstallStage {
    directory: String,
    platform_dir: String,
    binary: String,
    checksum: String,
}

#[derive(Debug)]
struct CommandOutput {
    stdout: Vec<u8>,
}

#[async_trait]
trait RemoteTransport: Send + Sync {
    async fn run(&self, command: &str) -> Result<CommandOutput, String>;
    async fn upload(&self, local: &Path, remote: &str) -> Result<(), String>;
}

async fn run_posix(remote: &dyn RemoteTransport, script: &str) -> Result<CommandOutput, String> {
    remote.run(&posix_command(script)?).await
}

struct LeaseRemote<'a> {
    lease: &'a ConnectionLease,
}

#[async_trait]
impl RemoteTransport for LeaseRemote<'_> {
    async fn run(&self, command: &str) -> Result<CommandOutput, String> {
        run_lease_command(self.lease, command).await
    }

    async fn upload(&self, local: &Path, remote: &str) -> Result<(), String> {
        let sftp = self
            .lease
            .open_sftp()
            .await
            .map_err(|error| format!("could not open authenticated SFTP channel: {error}"))?;
        upload_over_sftp(&sftp, local, remote).await
    }
}

async fn probe_remote_platform(remote: &dyn RemoteTransport) -> Result<RemotePlatform, String> {
    let output = run_posix(
        remote,
        "set -eu; LC_ALL=C; export LC_ALL; printf '%s\\n' \"$HOME\"; \
         (uname -s 2>/dev/null || printf '%s\\n' unsupported); \
         (uname -m 2>/dev/null || printf '%s\\n' unsupported)",
    )
    .await?;
    let text = String::from_utf8(output.stdout)
        .map_err(|_| "remote platform probe returned non-UTF-8 output".to_owned())?;
    let lines = text.lines().collect::<Vec<_>>();
    let [home, raw_os, raw_arch] = lines.as_slice() else {
        return Err("remote platform probe returned an unexpected response".into());
    };
    let os = match raw_os.to_ascii_lowercase().as_str() {
        "linux" => "linux",
        "darwin" => "macos",
        other => {
            return Err(format!(
                "remote operating system {other:?} is unsupported; managed workers require Linux or macOS"
            ));
        }
    };
    if home.is_empty()
        || !home.starts_with('/')
        || home
            .bytes()
            .any(|byte| byte == 0 || byte.is_ascii_control())
    {
        return Err("remote platform probe returned an unsafe HOME directory".into());
    }
    let arch = match raw_arch.to_ascii_lowercase().as_str() {
        "x86_64" | "amd64" => "x86_64",
        "aarch64" | "arm64" => "aarch64",
        other => {
            return Err(format!(
                "remote architecture {other:?} is unsupported; managed workers require x86_64 or aarch64"
            ));
        }
    };
    Ok(RemotePlatform {
        home: (*home).to_owned(),
        os: os.into(),
        arch: arch.into(),
    })
}

async fn managed_worker_matches(
    remote: &dyn RemoteTransport,
    target: &InstallTarget,
    expected: &SshWorkerBuildInfo,
) -> Result<bool, String> {
    let paths_are_safe = format!(
        "set -eu; \
         test ! -L {groky}; test -d {groky}; test -O {groky}; \
         test ! -L {root}; test -d {root}; test -O {root}; \
         test ! -L {version}; test -d {version}; test -O {version}; \
         test ! -L {platform}; test -d {platform}; test -O {platform}; \
         test ! -L {binary}; test -f {binary}; test -x {binary}; test -O {binary}",
        groky = shell_quote(&target.groky_home)?,
        root = shell_quote(&target.root)?,
        version = shell_quote(&target.version_dir)?,
        platform = shell_quote(&target.platform_dir)?,
        binary = shell_quote(&target.binary)?,
    );
    if run_posix(remote, &paths_are_safe).await.is_err() {
        return Ok(false);
    }
    let worker_info = format!("exec {} worker --info", shell_quote(&target.binary)?);
    let output = match run_posix(remote, &worker_info).await {
        Ok(output) => output,
        Err(_) => return Ok(false),
    };
    if output.stdout.len() > INFO_OUTPUT_LIMIT {
        return Ok(false);
    }
    let Ok(actual) = serde_json::from_slice::<SshWorkerBuildInfo>(&output.stdout) else {
        return Ok(false);
    };
    Ok(actual == *expected)
}

async fn create_remote_stage(
    remote: &dyn RemoteTransport,
    target: &InstallTarget,
    stage: &InstallStage,
) -> Result<(), String> {
    let script = format!(
        "set -eu; \
         ensure_owned_dir() {{ \
             path=$1; \
             if [ -L \"$path\" ]; then printf 'refusing symlinked managed worker directory: %s\\n' \"$path\" >&2; exit 70; fi; \
             if [ -e \"$path\" ]; then \
                 if ! [ -d \"$path\" ]; then printf 'managed worker path is not a directory: %s\\n' \"$path\" >&2; exit 70; fi; \
                 if ! [ -O \"$path\" ]; then printf 'managed worker directory is not owned by the SSH user: %s\\n' \"$path\" >&2; exit 70; fi; \
             else \
                 mkdir -m 700 \"$path\"; \
             fi; \
         }}; \
         ensure_owned_dir {groky}; ensure_owned_dir {root}; ensure_owned_dir {version}; \
         chmod 700 {groky}; chmod 700 {root}; chmod 700 {version}; \
         if [ -e {stage} ] || [ -L {stage} ]; then printf 'worker staging directory already exists: %s\\n' {stage} >&2; exit 73; fi; \
         mkdir -m 700 {stage}; \
         mkdir -m 700 {platform}",
        groky = shell_quote(&target.groky_home)?,
        root = shell_quote(&target.root)?,
        version = shell_quote(&target.version_dir)?,
        stage = shell_quote(&stage.directory)?,
        platform = shell_quote(&stage.platform_dir)?,
    );
    run_posix(remote, &script).await.map(|_| ())
}

async fn download_and_validate_remote(
    remote: &dyn RemoteTransport,
    stage: &InstallStage,
    urls: &ReleaseUrls,
    expected: &SshWorkerBuildInfo,
) -> Result<(), String> {
    download_remote_file(
        remote,
        &urls.artifact,
        &stage.binary,
        urls.require_https,
        MAX_ARTIFACT_BYTES,
    )
    .await?;
    download_remote_file(
        remote,
        &urls.checksum,
        &stage.checksum,
        urls.require_https,
        MAX_CHECKSUM_BYTES as u64,
    )
    .await?;
    validate_remote_stage(remote, stage, expected).await
}

async fn download_remote_file(
    remote: &dyn RemoteTransport,
    url: &str,
    destination: &str,
    require_https: bool,
    max_bytes: u64,
) -> Result<(), String> {
    if require_https && !url.starts_with("https://") {
        return Err("refusing non-HTTPS worker release URL".into());
    }
    let curl_options = if require_https {
        "--proto '=https' --proto-redir '=https' --tlsv1.2"
    } else {
        ""
    };
    let wget_options = if require_https { "--https-only" } else { "" };
    let file_limit_blocks = max_bytes.div_ceil(512);
    let script = format!(
        "set -eu; ulimit -f {file_limit_blocks} 2>/dev/null || true; \
         if command -v curl >/dev/null 2>&1; then \
             curl --fail --location --silent --show-error {curl_options} --connect-timeout 15 --max-time 180 --max-filesize {max_bytes} \
                 --output {destination} -- {url}; \
         elif command -v wget >/dev/null 2>&1; then \
             wget {wget_options} --quiet --timeout=15 --tries=1 --quota={max_bytes} --output-document={destination} -- {url}; \
         else \
             printf '%s\\n' 'neither curl nor wget is available on the remote host' >&2; exit 127; \
         fi",
        destination = shell_quote(destination)?,
        url = shell_quote(url)?,
    );
    run_posix(remote, &script).await.map(|_| ())
}

async fn validate_remote_stage(
    remote: &dyn RemoteTransport,
    stage: &InstallStage,
    expected: &SshWorkerBuildInfo,
) -> Result<(), String> {
    let checksum_script = format!(
        "set -eu; \
         expected=$(awk 'NF {{ print $1; exit }}' {checksum} | tr '[:upper:]' '[:lower:]'); \
         case \"$expected\" in ''|*[!0123456789abcdef]*) printf 'worker checksum is invalid: %s\\n' \"$expected\" >&2; exit 65;; esac; \
         if [ \"${{#expected}}\" -ne 64 ]; then printf 'worker checksum has invalid length: %s\\n' \"$expected\" >&2; exit 65; fi; \
         if command -v sha256sum >/dev/null 2>&1; then \
             actual=$(sha256sum {binary} | awk '{{print $1}}'); \
         elif command -v shasum >/dev/null 2>&1; then \
             actual=$(shasum -a 256 {binary} | awk '{{print $1}}'); \
         else \
             printf '%s\\n' 'no SHA-256 utility is available on the remote host' >&2; exit 66; \
         fi; \
         if [ \"$actual\" != \"$expected\" ]; then \
             printf 'worker checksum mismatch: got %s expected %s\\n' \"$actual\" \"$expected\" >&2; exit 65; \
         fi; \
         chmod 700 {binary}",
        checksum = shell_quote(&stage.checksum)?,
        binary = shell_quote(&stage.binary)?,
    );
    run_posix(remote, &checksum_script).await?;
    let worker_info = format!("exec {} worker --info", shell_quote(&stage.binary)?);
    let output = run_posix(remote, &worker_info).await?;
    if output.stdout.len() > INFO_OUTPUT_LIMIT {
        return Err("staged worker --info response exceeds the installer limit".into());
    }
    let actual = serde_json::from_slice::<SshWorkerBuildInfo>(&output.stdout)
        .map_err(|error| format!("staged worker did not return valid --info JSON: {error}"))?;
    if actual != *expected {
        return Err(format!(
            "staged worker identity does not match this client (got version {:?}, protocol {}, {}-{})",
            actual.product_version, actual.protocol_version, actual.os, actual.arch
        ));
    }
    Ok(())
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum PublishOutcome {
    Published,
    Existing,
}

async fn publish_remote_stage(
    remote: &dyn RemoteTransport,
    target: &InstallTarget,
    stage: &InstallStage,
) -> Result<PublishOutcome, String> {
    let script = format!(
        "set -eu; \
         test ! -L {groky}; test -d {groky}; test -O {groky}; \
         test ! -L {root}; test -d {root}; test -O {root}; \
         test ! -L {version}; test -d {version}; test -O {version}; \
         attempts=0; \
         while ! mkdir -m 700 {lock} 2>/dev/null; do \
             if [ -L {lock} ]; then printf 'managed worker install lock is a symlink: %s\\n' {lock} >&2; exit 74; fi; \
             attempts=$((attempts + 1)); \
             if [ \"$attempts\" -ge 30 ]; then printf 'timed out waiting for managed worker install lock: %s\\n' {lock} >&2; exit 75; fi; \
             sleep 1; \
         done; \
         release_lock() {{ rmdir {lock} || true; }}; \
         trap release_lock EXIT HUP INT TERM; \
         test ! -L {root}; test -d {root}; test -O {root}; \
         test ! -L {stage}; test -d {stage}; test -O {stage}; \
         test ! -L {platform}; test -d {platform}; test -O {platform}; \
         test ! -L {binary}; test -f {binary}; test -O {binary}; \
         if [ -e {target} ] || [ -L {target} ]; then printf '%s\\n' existing; exit 0; fi; \
         mv {platform} {target}; \
         printf '%s\\n' published",
        lock = shell_quote(&target.lock)?,
        groky = shell_quote(&target.groky_home)?,
        root = shell_quote(&target.root)?,
        version = shell_quote(&target.version_dir)?,
        stage = shell_quote(&stage.directory)?,
        platform = shell_quote(&stage.platform_dir)?,
        binary = shell_quote(&stage.binary)?,
        target = shell_quote(&target.platform_dir)?,
    );
    let output = run_posix(remote, &script).await?;
    match String::from_utf8_lossy(&output.stdout).trim() {
        "published" => Ok(PublishOutcome::Published),
        "existing" => Ok(PublishOutcome::Existing),
        other => Err(format!(
            "remote worker publish returned an unexpected result: {other:?}"
        )),
    }
}

async fn write_remote_checksum(
    remote: &dyn RemoteTransport,
    destination: &str,
    checksum: &str,
) -> Result<(), String> {
    if parse_sha256(checksum).as_deref() != Some(checksum) {
        return Err("local worker checksum was not valid SHA-256".into());
    }
    let script = format!(
        "set -eu; umask 077; printf '%s\\n' {checksum} > {destination}; chmod 600 {destination}",
        checksum = shell_quote(checksum)?,
        destination = shell_quote(destination)?,
    );
    run_posix(remote, &script).await.map(|_| ())
}

async fn cleanup_remote_stage(
    remote: &dyn RemoteTransport,
    target: &InstallTarget,
    stage: &InstallStage,
) {
    let (Ok(groky), Ok(root), Ok(stage)) = (
        shell_quote(&target.groky_home),
        shell_quote(&target.root),
        shell_quote(&stage.directory),
    ) else {
        return;
    };
    let script = format!(
        "set -eu; \
         if [ -L {groky} ] || ! [ -d {groky} ] || ! [ -O {groky} ]; then exit 0; fi; \
         if [ -L {root} ] || ! [ -d {root} ] || ! [ -O {root} ]; then exit 0; fi; \
         if [ -L {stage} ]; then rm -f {stage}; \
         elif [ -e {stage} ]; then \
             if ! [ -d {stage} ] || ! [ -O {stage} ]; then exit 0; fi; \
             rm -rf {stage}; \
         fi"
    );
    let _ = run_posix(remote, &script).await;
}

fn release_urls(version: &str, platform: &RemotePlatform) -> Result<ReleaseUrls, String> {
    let version = normalized_release_version(version)?;
    let asset = format!("groky-{version}-{}-{}", platform.os, platform.arch);
    let tag = format!("v{version}");
    let repository = repo();
    Ok(ReleaseUrls {
        artifact: release_download_url(&repository, &tag, &asset),
        checksum: release_download_url(&repository, &tag, &format!("{asset}.sha256")),
        require_https: true,
    })
}

async fn download_verified_locally(
    local_home: &Path,
    urls: &ReleaseUrls,
    version: &str,
) -> Result<DownloadedArtifact, String> {
    if urls.require_https
        && (!urls.artifact.starts_with("https://") || !urls.checksum.starts_with("https://"))
    {
        return Err("refusing non-HTTPS worker release URL".into());
    }
    let redirects = if urls.require_https {
        reqwest::redirect::Policy::custom(|attempt| {
            if attempt.previous().len() > 10 {
                attempt.error("worker release download exceeded the redirect limit")
            } else if attempt.url().scheme() == "https" {
                attempt.follow()
            } else {
                attempt.error("worker release download redirected to a non-HTTPS URL")
            }
        })
    } else {
        reqwest::redirect::Policy::limited(10)
    };
    let client = reqwest::Client::builder()
        .redirect(redirects)
        .connect_timeout(Duration::from_secs(15))
        .timeout(DOWNLOAD_TIMEOUT)
        .user_agent(format!("groky/{version}"))
        .build()
        .map_err(|error| format!("could not create local release HTTP client: {error}"))?;
    let checksum_response = client
        .get(&urls.checksum)
        .send()
        .await
        .map_err(|error| format!("could not download worker checksum locally: {error}"))?;
    if urls.require_https && checksum_response.url().scheme() != "https" {
        return Err("worker checksum download redirected to a non-HTTPS URL".into());
    }
    if !checksum_response.status().is_success() {
        return Err(format!(
            "could not download worker checksum locally: HTTP {}",
            checksum_response.status()
        ));
    }
    let checksum =
        parse_sha256(&read_response_limited(checksum_response, MAX_CHECKSUM_BYTES).await?)
            .ok_or_else(|| "worker release checksum was missing or invalid".to_owned())?;

    let cache = local_home.join("downloads");
    tokio::fs::create_dir_all(&cache)
        .await
        .map_err(|error| format!("could not create local worker download cache: {error}"))?;
    let temporary = cache.join(format!(".worker-{version}-{}.tmp", Uuid::now_v7()));
    let result = async {
        let response = client
            .get(&urls.artifact)
            .send()
            .await
            .map_err(|error| format!("could not download worker release locally: {error}"))?;
        if urls.require_https && response.url().scheme() != "https" {
            return Err("worker release download redirected to a non-HTTPS URL".into());
        }
        if !response.status().is_success() {
            return Err(format!(
                "could not download worker release locally: HTTP {}",
                response.status()
            ));
        }
        if response
            .content_length()
            .is_some_and(|length| length > MAX_ARTIFACT_BYTES)
        {
            return Err("worker release exceeds the installer size limit".into());
        }
        let mut options = tokio::fs::OpenOptions::new();
        options.write(true).create_new(true);
        #[cfg(unix)]
        options.mode(0o600);
        let mut file = options
            .open(&temporary)
            .await
            .map_err(|error| format!("could not create local worker staging file: {error}"))?;
        let mut actual = Sha256::new();
        let mut total = 0_u64;
        let mut stream = response.bytes_stream();
        while let Some(chunk) = stream.next().await {
            let chunk =
                chunk.map_err(|error| format!("worker release download failed: {error}"))?;
            total = total
                .checked_add(
                    u64::try_from(chunk.len())
                        .map_err(|_| "worker download chunk was too large")?,
                )
                .ok_or_else(|| "worker release exceeds the installer size limit".to_owned())?;
            if total > MAX_ARTIFACT_BYTES {
                return Err("worker release exceeds the installer size limit".into());
            }
            actual.update(&chunk);
            file.write_all(&chunk)
                .await
                .map_err(|error| format!("could not write local worker staging file: {error}"))?;
        }
        file.flush()
            .await
            .map_err(|error| format!("could not flush local worker staging file: {error}"))?;
        file.sync_all()
            .await
            .map_err(|error| format!("could not synchronize local worker staging file: {error}"))?;
        let actual = format!("{:x}", actual.finalize());
        if actual != checksum {
            return Err(format!(
                "worker release checksum mismatch (got {actual}, expected {checksum})"
            ));
        }
        Ok(())
    }
    .await;
    if let Err(error) = result {
        let _ = tokio::fs::remove_file(&temporary).await;
        return Err(error);
    }
    if let Err(error) = set_local_owner_only(&temporary).await {
        let _ = tokio::fs::remove_file(&temporary).await;
        return Err(error);
    }
    Ok(DownloadedArtifact {
        path: temporary,
        checksum,
    })
}

async fn read_response_limited(
    response: reqwest::Response,
    limit: usize,
) -> Result<String, String> {
    if response
        .content_length()
        .is_some_and(|length| length > limit as u64)
    {
        return Err("worker release checksum exceeds the installer limit".into());
    }
    let mut bytes = Vec::new();
    let mut stream = response.bytes_stream();
    while let Some(chunk) = stream.next().await {
        let chunk = chunk.map_err(|error| format!("could not read worker checksum: {error}"))?;
        if bytes.len().saturating_add(chunk.len()) > limit {
            return Err("worker release checksum exceeds the installer limit".into());
        }
        bytes.extend_from_slice(&chunk);
    }
    String::from_utf8(bytes).map_err(|_| "worker release checksum was not UTF-8".into())
}

async fn sha256_file(path: &Path) -> Result<String, String> {
    let mut file = tokio::fs::File::open(path)
        .await
        .map_err(|error| format!("could not read local groky executable: {error}"))?;
    let mut buffer = [0_u8; COPY_CHUNK_BYTES];
    let mut digest = Sha256::new();
    let mut total = 0_u64;
    loop {
        let count = file
            .read(&mut buffer)
            .await
            .map_err(|error| format!("could not read local groky executable: {error}"))?;
        if count == 0 {
            break;
        }
        total = total
            .checked_add(u64::try_from(count).map_err(|_| "local executable chunk was too large")?)
            .ok_or_else(|| {
                "local development executable exceeds the installer size limit".to_owned()
            })?;
        if total > MAX_ARTIFACT_BYTES {
            return Err("local development executable exceeds the installer size limit".into());
        }
        digest.update(&buffer[..count]);
    }
    Ok(format!("{:x}", digest.finalize()))
}

async fn cached_current_executable_sha256(path: &Path) -> Result<String, String> {
    // Hold the asynchronous cache lock across the stream so simultaneous SSH
    // project opens do not all re-hash a large running development binary.
    let mut cache = LOCAL_EXECUTABLE_DIGEST.lock().await;
    let metadata = tokio::fs::metadata(path)
        .await
        .map_err(|error| format!("could not inspect local groky executable: {error}"))?;
    let length = metadata.len();
    if length > MAX_ARTIFACT_BYTES {
        return Err("local development executable exceeds the installer size limit".into());
    }
    let modified = metadata.modified().ok();
    if let Some(cached) = cache.as_ref()
        && cached.path.as_path() == path
        && cached.length == length
        && cached.modified == modified
    {
        return Ok(cached.digest.clone());
    }
    let digest = sha256_file(path).await?;
    *cache = Some(CachedExecutableDigest {
        path: path.to_path_buf(),
        length,
        modified,
        digest: digest.clone(),
    });
    Ok(digest)
}

async fn upload_over_sftp(
    sftp: &xai_grok_ssh::SftpConnection,
    local: &Path,
    remote: &str,
) -> Result<(), String> {
    let mut attributes = FileAttributes::empty();
    attributes.permissions = Some(0o700);
    let mut remote_file = sftp
        .open_with_flags_and_attributes(
            remote.to_owned(),
            OpenFlags::CREATE | OpenFlags::EXCLUDE | OpenFlags::WRITE,
            attributes,
        )
        .await
        .map_err(|error| format!("could not create remote worker staging file: {error}"))?;
    let upload = async {
        let mut local_file = tokio::fs::File::open(local)
            .await
            .map_err(|error| format!("could not open local worker staging file: {error}"))?;
        let mut buffer = [0_u8; COPY_CHUNK_BYTES];
        let mut total = 0_u64;
        loop {
            let count = local_file
                .read(&mut buffer)
                .await
                .map_err(|error| format!("could not read local worker staging file: {error}"))?;
            if count == 0 {
                break;
            }
            total = total
                .checked_add(u64::try_from(count).map_err(|_| "local worker chunk was too large")?)
                .ok_or_else(|| "local worker upload exceeds the installer size limit".to_owned())?;
            if total > MAX_ARTIFACT_BYTES {
                return Err("local worker upload exceeds the installer size limit".into());
            }
            remote_file
                .write_all(&buffer[..count])
                .await
                .map_err(|error| format!("could not upload worker over SFTP: {error}"))?;
        }
        remote_file
            .flush()
            .await
            .map_err(|error| format!("could not flush remote worker staging file: {error}"))?;
        remote_file.sync_all().await.map_err(|error| {
            format!("could not synchronize remote worker staging file: {error}")
        })?;
        remote_file
            .shutdown()
            .await
            .map_err(|error| format!("could not close remote worker staging file: {error}"))?;
        Ok::<(), String>(())
    }
    .await;
    if upload.is_err() {
        let _ = sftp.remove_file(remote.to_owned()).await;
    }
    upload
}

async fn set_local_owner_only(path: &Path) -> Result<(), String> {
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        let path = path.to_path_buf();
        tokio::task::spawn_blocking(move || {
            std::fs::set_permissions(&path, std::fs::Permissions::from_mode(0o600))
        })
        .await
        .map_err(|error| format!("could not set local worker staging permissions: {error}"))?
        .map_err(|error| format!("could not set local worker staging permissions: {error}"))?;
    }
    #[cfg(not(unix))]
    {
        let _ = path;
    }
    Ok(())
}

async fn run_lease_command(
    lease: &ConnectionLease,
    command: &str,
) -> Result<CommandOutput, String> {
    let mut handle = timeout(COMMAND_START_TIMEOUT, lease.exec_command(command))
        .await
        .map_err(|_| "remote worker installer command timed out while starting".to_owned())?
        .map_err(|error| format!("could not start remote worker installer command: {error}"))?;
    let deadline = Instant::now() + COMMAND_TIMEOUT;
    let mut stdout = Vec::new();
    let mut stderr = Vec::new();
    let mut exit_status = None;
    let mut exit_signal = None;
    loop {
        let remaining = deadline
            .checked_duration_since(Instant::now())
            .filter(|remaining| !remaining.is_zero())
            .ok_or_else(|| "remote worker installer command timed out".to_owned())?;
        let event = match timeout(remaining, handle.next_event()).await {
            Ok(Ok(Some(event))) => event,
            Ok(Ok(None)) => break,
            Ok(Err(error)) => {
                return Err(format!("remote worker installer command failed: {error}"));
            }
            Err(_) => {
                stop_lease_command(&handle).await;
                return Err("remote worker installer command timed out".into());
            }
        };
        match event {
            SshCommandEvent::Stdout(chunk) => {
                append_command_output(&mut stdout, &chunk, "stdout", &handle).await?
            }
            SshCommandEvent::Stderr(chunk) => {
                append_command_output(&mut stderr, &chunk, "stderr", &handle).await?
            }
            SshCommandEvent::ExitStatus(status) => exit_status = Some(status),
            SshCommandEvent::ExitSignal(signal) => exit_signal = Some(signal),
        }
    }
    match (exit_status, exit_signal) {
        (Some(0), None) => Ok(CommandOutput { stdout }),
        (Some(status), None) => Err(command_failure(status, &stderr)),
        (_, Some(signal)) => Err(format!(
            "remote worker installer command terminated by {signal}: {}",
            output_excerpt(&stderr)
        )),
        (None, None) => Err("remote worker installer command ended without an exit status".into()),
    }
}

async fn append_command_output(
    output: &mut Vec<u8>,
    chunk: &[u8],
    stream: &str,
    handle: &xai_grok_ssh::SshCommand,
) -> Result<(), String> {
    if output.len().saturating_add(chunk.len()) > COMMAND_OUTPUT_LIMIT {
        stop_lease_command(handle).await;
        return Err(format!(
            "remote worker installer {stream} exceeded the {} byte limit; output was truncated at the limit",
            COMMAND_OUTPUT_LIMIT
        ));
    }
    output.extend_from_slice(chunk);
    Ok(())
}

async fn stop_lease_command(handle: &xai_grok_ssh::SshCommand) {
    let _ = handle.signal("TERM").await;
    let _ = handle.close().await;
}

fn command_failure(status: u32, stderr: &[u8]) -> String {
    let detail = output_excerpt(stderr);
    if detail.is_empty() {
        format!("remote worker installer command exited with status {status}")
    } else {
        format!("remote worker installer command exited with status {status}: {detail}")
    }
}

fn output_excerpt(bytes: &[u8]) -> String {
    String::from_utf8_lossy(bytes).trim().to_owned()
}

fn normalized_release_version(version: &str) -> Result<String, String> {
    let normalized = version.trim().trim_start_matches('v');
    if normalized.is_empty() {
        return Err("local product release version is empty".into());
    }
    semver::Version::parse(normalized).map_err(|error| {
        format!("local product release version {version:?} is not valid SemVer: {error}")
    })?;
    safe_component("worker release", normalized)?;
    Ok(normalized.to_owned())
}

fn ensure_supported_platform(platform: &RemotePlatform) -> Result<(), String> {
    if matches!(platform.os.as_str(), "linux" | "macos")
        && matches!(platform.arch.as_str(), "x86_64" | "aarch64")
    {
        return Ok(());
    }
    Err(format!(
        "managed SSH workers do not support remote platform {}",
        platform.label()
    ))
}

fn local_platform() -> Result<(&'static str, &'static str), String> {
    let os = match std::env::consts::OS {
        "macos" => "macos",
        "linux" => "linux",
        other => {
            return Err(format!(
                "local platform {other:?} cannot provide a managed SSH worker"
            ));
        }
    };
    let arch = match std::env::consts::ARCH {
        "x86_64" => "x86_64",
        "aarch64" => "aarch64",
        other => {
            return Err(format!(
                "local architecture {other:?} cannot provide a managed SSH worker"
            ));
        }
    };
    Ok((os, arch))
}

fn safe_component(label: &str, component: &str) -> Result<(), String> {
    if component.is_empty()
        || !component
            .bytes()
            .all(|byte| byte.is_ascii_alphanumeric() || matches!(byte, b'.' | b'_' | b'-' | b'+'))
    {
        return Err(format!("{label} contains unsafe path characters"));
    }
    Ok(())
}

fn shell_quote(value: &str) -> Result<String, String> {
    if value.contains('\0') {
        return Err("remote worker installer argument contains NUL".into());
    }
    Ok(format!("'{}'", value.replace('\'', "'\\''")))
}

fn posix_command(script: &str) -> Result<String, String> {
    Ok(format!("/bin/sh -c {}", shell_quote(script)?))
}
#[cfg(all(test, unix))]
mod tests {
    use std::path::{Path, PathBuf};
    use std::sync::Arc;
    use std::sync::atomic::{AtomicBool, AtomicUsize, Ordering};

    use async_trait::async_trait;
    use axum::{Router, routing::get};
    use sha2::{Digest, Sha256};
    use tempfile::TempDir;
    use tokio::process::Command;

    use super::*;

    #[tokio::test]
    async fn direct_install_uses_the_exact_remote_platform_asset() {
        let fixture = InstallerFixture::new(false, true).await;

        assert_eq!(fixture.install().await.unwrap(), fixture.expected_argv());
        assert_eq!(fixture.interaction.approvals(), 0);
        assert_eq!(fixture.downloads(), 2);
        fixture.assert_installed().await;
    }

    #[tokio::test]
    async fn probe_normalizes_the_actual_unix_platform() {
        let temporary = tempfile::tempdir().unwrap();
        let remote = LocalRemote {
            home: temporary.path().to_path_buf(),
            path: std::env::var("PATH").unwrap_or_default(),
        };

        let platform = probe_remote_platform(&remote).await.unwrap();
        assert_eq!(
            platform.os,
            match std::env::consts::OS {
                "macos" => "macos",
                "linux" => "linux",
                other => panic!("unsupported test host {other}"),
            }
        );
        assert_eq!(
            platform.arch,
            match std::env::consts::ARCH {
                "x86_64" => "x86_64",
                "aarch64" => "aarch64",
                other => panic!("unsupported test host architecture {other}"),
            }
        );
    }

    #[test]
    fn release_urls_use_the_remote_platform_and_an_exact_tag() {
        let urls = release_urls(
            "1.2.3",
            &RemotePlatform {
                home: "/remote".into(),
                os: "macos".into(),
                arch: "aarch64".into(),
            },
        )
        .unwrap();

        assert!(urls.artifact.ends_with("/v1.2.3/groky-1.2.3-macos-aarch64"));
        assert!(urls.checksum.ends_with(".sha256"));
        assert!(!urls.artifact.contains("/latest/"));
    }

    #[tokio::test]
    async fn matching_installed_worker_reuses_without_a_network_request() {
        let fixture = InstallerFixture::new(false, true).await;
        fixture.install().await.unwrap();
        let requests_before = fixture.downloads();

        assert_eq!(
            fixture.install_without_current_executable().await.unwrap(),
            fixture.expected_argv()
        );
        assert_eq!(fixture.downloads(), requests_before);
        assert_eq!(fixture.interaction.approvals(), 0);
    }

    #[tokio::test]
    async fn failed_remote_download_can_fall_back_to_local_stream_and_sftp_upload() {
        let fixture = InstallerFixture::new(true, true).await;

        assert_eq!(fixture.install().await.unwrap(), fixture.expected_argv());
        assert_eq!(fixture.interaction.approvals(), 1);
        fixture.assert_installed().await;
    }

    #[cfg(any(target_os = "linux", target_os = "macos"))]
    #[tokio::test]
    async fn dev_build_uses_only_the_explicit_same_platform_upload() {
        let fixture = InstallerFixture::new(false, true).await;
        let (os, arch) = local_platform().unwrap();
        let expected = SshWorkerBuildInfo {
            product_version: None,
            protocol_version: 17,
            os: os.into(),
            arch: arch.into(),
        };
        tokio::fs::write(&fixture.current_executable, worker_script(&expected))
            .await
            .unwrap();
        make_executable(&fixture.current_executable);
        let platform = RemotePlatform {
            home: fixture.remote.home.to_string_lossy().into_owned(),
            os: os.into(),
            arch: arch.into(),
        };

        let argv = prepare_worker_with_sources(
            &fixture.remote,
            &fixture.local_home,
            fixture.interaction.as_ref(),
            expected.clone(),
            platform,
            None,
            Some(&fixture.current_executable),
        )
        .await
        .unwrap();

        let [binary, command, stdio] = argv.as_slice() else {
            panic!("installer returned unexpected worker argv: {argv:?}");
        };
        assert!(binary.contains("/workers/dev-"));
        assert_eq!(command, "worker");
        assert_eq!(stdio, "--stdio");
        assert_eq!(fixture.interaction.approvals(), 1);
        assert_eq!(fixture.downloads(), 0);
        let output = Command::new(binary.as_str())
            .arg("worker")
            .arg("--info")
            .output()
            .await
            .unwrap();
        assert!(output.status.success());
        assert_eq!(
            serde_json::from_slice::<SshWorkerBuildInfo>(&output.stdout).unwrap(),
            expected
        );
    }

    #[tokio::test]
    async fn denied_local_upload_leaves_existing_worker_untouched() {
        let fixture = InstallerFixture::new(true, true).await;
        fixture.interaction.set_approved(false);
        let previous = fixture.seed_old_worker().await;

        let error = fixture.install().await.unwrap_err();
        assert!(error.contains("cancelled"));
        assert_eq!(fixture.interaction.approvals(), 1);
        assert_eq!(tokio::fs::read(previous).await.unwrap(), b"old worker");
    }

    #[tokio::test]
    async fn checksum_mismatch_never_replaces_an_existing_worker() {
        let fixture = InstallerFixture::new(false, false).await;
        let previous = fixture.seed_old_worker().await;

        let error = fixture.install().await.unwrap_err();
        assert!(error.contains("checksum mismatch"));
        assert_eq!(fixture.interaction.approvals(), 1);
        assert_eq!(tokio::fs::read(previous).await.unwrap(), b"old worker");
    }

    #[tokio::test]
    async fn existing_mismatched_version_is_never_moved_or_replaced() {
        let fixture = InstallerFixture::new(false, true).await;
        let previous = fixture.seed_old_worker().await;

        let error = fixture.install().await.unwrap_err();
        assert!(error.contains("refusing to replace"));
        assert_eq!(fixture.interaction.approvals(), 0);
        assert_eq!(tokio::fs::read(previous).await.unwrap(), b"old worker");
    }

    #[cfg(unix)]
    #[tokio::test]
    async fn symlinked_worker_root_is_rejected_without_touching_its_target() {
        let fixture = InstallerFixture::new(false, true).await;
        let outside = fixture._temporary.path().join("outside");
        std::fs::create_dir(&outside).unwrap();
        std::os::unix::fs::symlink(&outside, fixture.remote.home.join(".groky")).unwrap();

        let error = fixture.install().await.unwrap_err();
        assert!(error.contains("symlinked managed worker directory"));
        assert!(!outside.join("workers").exists());
    }

    #[tokio::test]
    async fn release_update_and_shared_home_platforms_preserve_existing_workers() {
        let mut fixture = InstallerFixture::new(false, true).await;
        fixture.install().await.unwrap();
        let previous = fixture.installed_binary();
        let previous_bytes = tokio::fs::read(&previous).await.unwrap();

        fixture.set_release("1.2.4", "linux", "x86_64").await;
        assert_eq!(fixture.install().await.unwrap(), fixture.expected_argv());
        fixture.assert_installed().await;
        let updated = fixture.installed_binary();
        let updated_bytes = tokio::fs::read(&updated).await.unwrap();

        fixture.set_release("1.2.4", "macos", "aarch64").await;
        assert_eq!(fixture.install().await.unwrap(), fixture.expected_argv());
        fixture.assert_installed().await;
        assert_eq!(tokio::fs::read(previous).await.unwrap(), previous_bytes);
        assert_eq!(tokio::fs::read(updated).await.unwrap(), updated_bytes);
        assert_eq!(fixture.interaction.approvals(), 0);
    }

    #[tokio::test]
    async fn concurrent_publish_reuses_one_complete_worker_without_nested_stages() {
        let fixture = InstallerFixture::new(false, true).await;
        tokio::fs::create_dir_all(fixture.remote.home.join(".groky/workers/1.2.3"))
            .await
            .unwrap();
        let (first, second) = tokio::join!(fixture.install(), fixture.install());
        assert_eq!(first.unwrap(), fixture.expected_argv());
        assert_eq!(second.unwrap(), fixture.expected_argv());
        fixture.assert_installed().await;
        let mut entries = tokio::fs::read_dir(fixture.remote.home.join(".groky/workers"))
            .await
            .unwrap();
        while let Some(entry) = entries.next_entry().await.unwrap() {
            assert!(
                !entry.file_name().to_string_lossy().starts_with('.'),
                "stage or lock leaked"
            );
        }
    }

    #[tokio::test]
    async fn shell_metacharacters_in_home_are_literal_and_publish_lock_is_released() {
        let mut fixture = InstallerFixture::new(false, true).await;
        let home = fixture
            ._temporary
            .path()
            .join("remote $(printf injected) ' \" home");
        tokio::fs::rename(&fixture.remote.home, &home)
            .await
            .unwrap();
        fixture.remote.home = home;
        fixture.install().await.unwrap();
        fixture.assert_installed().await;
        assert!(
            !fixture
                .remote
                .home
                .join(".groky/workers/.install-1.2.3-linux-x86_64.lock")
                .exists()
        );
    }

    struct InstallerFixture {
        _temporary: TempDir,
        remote: LocalRemote,
        local_home: PathBuf,
        expected: SshWorkerBuildInfo,
        platform: RemotePlatform,
        urls: ReleaseUrls,
        current_executable: PathBuf,
        interaction: Arc<TestInteraction>,
        downloads: Arc<AtomicUsize>,
        server: tokio::task::JoinHandle<()>,
    }

    impl InstallerFixture {
        async fn new(remote_download_fails: bool, valid_checksum: bool) -> Self {
            let temporary = tempfile::tempdir().unwrap();
            let remote_home = temporary.path().join("remote-home");
            let local_home = temporary.path().join("local-home");
            tokio::fs::create_dir_all(&remote_home).await.unwrap();
            tokio::fs::create_dir_all(&local_home).await.unwrap();

            let expected = SshWorkerBuildInfo {
                product_version: Some("1.2.3".into()),
                protocol_version: 17,
                os: "linux".into(),
                arch: "x86_64".into(),
            };
            let asset = worker_script(&expected);
            let checksum = if valid_checksum {
                format!("{:x}  groky-1.2.3-linux-x86_64\n", Sha256::digest(&asset))
            } else {
                format!("{}  groky-1.2.3-linux-x86_64\n", "0".repeat(64))
            };
            let (urls, downloads, server) = release_fixture(asset.clone(), checksum).await;
            let current_executable = local_home.join("groky-current");
            tokio::fs::write(&current_executable, asset).await.unwrap();
            make_executable(&current_executable);

            let remote = LocalRemote {
                home: remote_home,
                path: local_shell_path(temporary.path(), remote_download_fails),
            };
            Self {
                _temporary: temporary,
                remote,
                local_home,
                expected,
                platform: RemotePlatform {
                    home: String::new(),
                    os: "linux".into(),
                    arch: "x86_64".into(),
                },
                urls,
                current_executable,
                interaction: Arc::new(TestInteraction::default()),
                downloads,
                server,
            }
        }

        async fn set_release(&mut self, version: &str, os: &str, arch: &str) {
            self.expected.product_version = Some(version.into());
            self.expected.os = os.into();
            self.expected.arch = arch.into();
            self.platform.os = os.into();
            self.platform.arch = arch.into();
            let asset = worker_script(&self.expected);
            let checksum = format!("{:x}", Sha256::digest(&asset));
            self.server.abort();
            (self.urls, self.downloads, self.server) = release_fixture(asset, checksum).await;
        }

        async fn install(&self) -> Result<Vec<String>, String> {
            let mut platform = self.platform.clone();
            platform.home = self.remote.home.to_string_lossy().into_owned();
            prepare_worker_with_sources(
                &self.remote,
                &self.local_home,
                self.interaction.as_ref(),
                self.expected.clone(),
                platform,
                Some(self.urls.clone()),
                Some(&self.current_executable),
            )
            .await
        }

        async fn install_without_current_executable(&self) -> Result<Vec<String>, String> {
            let mut platform = self.platform.clone();
            platform.home = self.remote.home.to_string_lossy().into_owned();
            prepare_worker_with_sources(
                &self.remote,
                &self.local_home,
                self.interaction.as_ref(),
                self.expected.clone(),
                platform,
                Some(self.urls.clone()),
                None,
            )
            .await
        }

        fn expected_argv(&self) -> Vec<String> {
            vec![
                self.installed_binary().to_string_lossy().into_owned(),
                "worker".into(),
                "--stdio".into(),
            ]
        }

        fn installed_binary(&self) -> PathBuf {
            self.remote.home.join(format!(
                ".groky/workers/{}/{}-{}/groky",
                self.expected.product_version.as_deref().unwrap(),
                self.expected.os,
                self.expected.arch,
            ))
        }

        fn downloads(&self) -> usize {
            self.downloads.load(Ordering::SeqCst)
        }

        async fn seed_old_worker(&self) -> PathBuf {
            let path = self.installed_binary();
            tokio::fs::create_dir_all(path.parent().unwrap())
                .await
                .unwrap();
            tokio::fs::write(&path, b"old worker").await.unwrap();
            path
        }

        async fn assert_installed(&self) {
            let output = Command::new(self.installed_binary())
                .arg("worker")
                .arg("--info")
                .output()
                .await
                .unwrap();
            assert!(output.status.success());
            assert_eq!(
                serde_json::from_slice::<SshWorkerBuildInfo>(&output.stdout).unwrap(),
                self.expected
            );
        }
    }

    impl Drop for InstallerFixture {
        fn drop(&mut self) {
            self.server.abort();
        }
    }

    struct LocalRemote {
        home: PathBuf,
        path: String,
    }

    #[async_trait]
    impl RemoteTransport for LocalRemote {
        async fn run(&self, command: &str) -> Result<CommandOutput, String> {
            let output = Command::new("/bin/sh")
                .arg("-c")
                .arg(command)
                .env("HOME", &self.home)
                .env("GROK_HOME", self.home.join(".groky"))
                .env("PATH", &self.path)
                .output()
                .await
                .map_err(|error| format!("could not run local remote fixture command: {error}"))?;
            if !output.status.success() {
                return Err(command_failure(
                    output.status.code().unwrap_or(1) as u32,
                    &output.stderr,
                ));
            }
            Ok(CommandOutput {
                stdout: output.stdout,
            })
        }

        async fn upload(&self, local: &Path, remote: &str) -> Result<(), String> {
            tokio::fs::copy(local, remote)
                .await
                .map_err(|error| format!("local SFTP fixture copy failed: {error}"))?;
            Ok(())
        }
    }

    struct TestInteraction {
        approved: AtomicBool,
        approvals: AtomicUsize,
    }

    impl Default for TestInteraction {
        fn default() -> Self {
            Self {
                approved: AtomicBool::new(true),
                approvals: AtomicUsize::new(0),
            }
        }
    }

    impl TestInteraction {
        fn set_approved(&self, approved: bool) {
            self.approved.store(approved, Ordering::SeqCst);
        }

        fn approvals(&self) -> usize {
            self.approvals.load(Ordering::SeqCst)
        }
    }

    #[async_trait]
    impl WorkerInstallInteraction for TestInteraction {
        fn progress(&self, _: &str) {}

        async fn approve_local_upload(&self, _: &str, _: &str, _: &str) -> Result<bool, String> {
            self.approvals.fetch_add(1, Ordering::SeqCst);
            Ok(self.approved.load(Ordering::SeqCst))
        }
    }

    async fn release_fixture(
        asset: Vec<u8>,
        checksum: String,
    ) -> (ReleaseUrls, Arc<AtomicUsize>, tokio::task::JoinHandle<()>) {
        let downloads = Arc::new(AtomicUsize::new(0));
        let asset_downloads = Arc::clone(&downloads);
        let checksum_downloads = Arc::clone(&downloads);
        let asset_route = asset.clone();
        let checksum_route = checksum.clone();
        let router = Router::new()
            .route(
                "/asset",
                get(move || {
                    let body = asset_route.clone();
                    let downloads = Arc::clone(&asset_downloads);
                    async move {
                        downloads.fetch_add(1, Ordering::SeqCst);
                        body
                    }
                }),
            )
            .route(
                "/asset.sha256",
                get(move || {
                    let body = checksum_route.clone();
                    let downloads = Arc::clone(&checksum_downloads);
                    async move {
                        downloads.fetch_add(1, Ordering::SeqCst);
                        body
                    }
                }),
            );
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let base = format!("http://{}", listener.local_addr().unwrap());
        let server = tokio::spawn(async move {
            axum::serve(listener, router).await.unwrap();
        });
        (
            ReleaseUrls {
                artifact: format!("{base}/asset"),
                checksum: format!("{base}/asset.sha256"),
                require_https: false,
            },
            downloads,
            server,
        )
    }

    fn worker_script(info: &SshWorkerBuildInfo) -> Vec<u8> {
        let json = serde_json::to_string(info).unwrap();
        format!(
            "#!/bin/sh\nif test \"$#\" = 2 && test \"$1\" = worker && test \"$2\" = --info; then printf '%s\\n' '{json}'; else exit 64; fi\n"
        )
        .into_bytes()
    }

    fn local_shell_path(root: &Path, disable_downloaders: bool) -> String {
        let inherited = std::env::var("PATH").unwrap_or_default();
        if !disable_downloaders {
            return inherited;
        }
        let commands = root.join("no-downloaders");
        std::fs::create_dir_all(&commands).unwrap();
        for name in ["curl", "wget"] {
            let path = commands.join(name);
            std::fs::write(&path, "#!/bin/sh\nexit 7\n").unwrap();
            make_executable(&path);
        }
        format!("{}:{inherited}", commands.display())
    }

    fn make_executable(path: &Path) {
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            let mut permissions = std::fs::metadata(path).unwrap().permissions();
            permissions.set_mode(0o700);
            std::fs::set_permissions(path, permissions).unwrap();
        }
        #[cfg(not(unix))]
        {
            let _ = path;
            panic!("worker installer shell fixture requires Unix");
        }
    }
}
