//! Workerless SSH file and content-search operations.
//!
//! SFTP is used for file operations; the only remote command this module emits
//! is a fully quoted, fixed-shape `rg` invocation for the read-only search tool.
//! It intentionally does not provide a generic execution path.

use std::borrow::Cow;
use std::path::PathBuf;
use std::time::{Duration, Instant};

use serde::Serialize;
use serde::de::DeserializeOwned;
use serde_json::Value;
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use uuid::Uuid;
use xai_grok_ssh::{
    ConnectionLease, SftpConnection, SshCommandEvent,
    sftp::{
        client::error::Error as SftpError,
        protocol::{FileAttributes, OpenFlags, StatusCode},
    },
};
use xai_grok_tools::{
    implementations::{
        grok_build::{
            grep::{
                GrepSearchInput, OutputMode, count_matches, format_content_output,
                format_count_output, format_files_with_matches_output, parse_file_matches,
            },
            read_file::{MAX_LINES_READ, READ_FILE_MAX_BYTES, ReadFileInput, exceeds_read_cap},
        },
        opencode::{edit::EditInput, write::WriteInput},
        read_file::bytes_to_metadata,
    },
    types::output::{
        FileContent, GrepSearchOutput, NoMatchesFoundError, ReadFileOutput,
        SearchReplaceEditContextInformation, SearchReplaceEditDetail, SearchReplaceEditsApplied,
        SearchReplaceOutput,
    },
};
use xai_grok_workspace_types::ssh::{ResolvedSshInvocation, SshBinding, SshOperation};

use super::SshDispatchResult;

const SEARCH_OUTPUT_BYTES: usize = 40 * 1024;
const SEARCH_RAW_BYTES: usize = 128 * 1024;
const SEARCH_STDERR_BYTES: usize = 16 * 1024;
const SEARCH_MAX_CHARS_PER_LINE: usize = 1_000;
const SEARCH_TIMEOUT: Duration = Duration::from_secs(20);
const SEARCH_CONTENT_DEFAULT: usize = 200;
const SEARCH_CONTENT_MAX: usize = 2_000;
const SEARCH_FILE_DEFAULT: usize = 500;
const SEARCH_FILE_MAX: usize = 10_000;
const EDIT_CONTEXT_LINES: usize = 3;
/// Source is read in fixed chunks and scanned to EOF so total line counts and
/// negative offsets stay accurate. Only the requested window is retained.
const READ_SOURCE_CHUNK_BYTES: usize = 32 * 1024;

type AuthorizationCheck<'a> = dyn Fn() -> bool + Send + Sync + 'a;

/// Canonicalize a requested root and ensure it is a directory before a grant is
/// persisted. `realpath` makes the persisted root stable across symlink aliases.
pub(super) async fn canonical_root(lease: &ConnectionLease, root: &str) -> Result<String, String> {
    reject_nul("SSH root", root)?;
    let sftp = lease.open_sftp().await.map_err(transport_error)?;
    canonical_root_with_sftp(&sftp, root).await
}

/// Revalidate the invocation CWD against the binding's canonical root.
pub(super) async fn validate_cwd(
    lease: &ConnectionLease,
    binding: &SshBinding,
    cwd: &str,
) -> Result<String, String> {
    reject_nul("SSH working directory", cwd)?;
    let sftp = lease.open_sftp().await.map_err(transport_error)?;
    let root = canonical_root_with_sftp(&sftp, &binding.root).await?;
    if root != binding.root {
        return Err("remote canonical root changed since this SSH grant was approved".into());
    }
    canonical_cwd_with_sftp(&sftp, &root, cwd).await
}

/// Execute a workerless explicit SSH file/search tool.
///
/// The caller owns approval and binding epoch checks. `still_authorized` is a
/// synchronous revocation token supplied by the service and is checked after
/// path preparation immediately before a read/search, and before every remote
/// filesystem mutation. It cannot make an SFTP v3 rename a cross-client CAS.
pub(super) async fn execute(
    lease: &ConnectionLease,
    binding: &SshBinding,
    invocation: &ResolvedSshInvocation,
    tool_name: &str,
    args: Value,
    still_authorized: &AuthorizationCheck<'_>,
) -> Result<SshDispatchResult, String> {
    let expected_operation = match tool_name {
        "GrokBuild:read_file" | "GrokBuild:grep" => SshOperation::Read,
        "OpenCode:write" | "OpenCode:edit" => SshOperation::Write,
        _ => {
            return Err(format!(
                "workerless SSH backend does not implement remote tool {tool_name:?}"
            ));
        }
    };
    if invocation.operation != expected_operation
        || !binding.capabilities.permits(expected_operation)
    {
        return Err("SSH invocation is not authorized for this native operation".into());
    }

    let sftp = lease.open_sftp().await.map_err(transport_error)?;
    let root = canonical_root_with_sftp(&sftp, &binding.root).await?;
    if root != binding.root {
        return Err("remote canonical root changed since this SSH grant was approved".into());
    }
    let cwd = canonical_cwd_with_sftp(&sftp, &root, &invocation.cwd).await?;

    match tool_name {
        "GrokBuild:read_file" => {
            let input: ReadFileInput =
                decode_input(args, "read_file", &["target_file", "offset", "limit"])?;
            native_read(&sftp, &root, &cwd, input, still_authorized).await
        }
        "OpenCode:write" => {
            let input: WriteInput = decode_input(args, "write", &["file_path", "content"])?;
            native_write(&sftp, &root, &cwd, input, still_authorized).await
        }
        "OpenCode:edit" => {
            let input: EditInput = decode_input(
                args,
                "edit",
                &["filePath", "oldString", "newString", "replaceAll"],
            )?;
            native_edit(&sftp, &root, &cwd, input, still_authorized).await
        }
        "GrokBuild:grep" => {
            let input: GrepSearchInput = decode_input(
                args,
                "grep",
                &[
                    "pattern",
                    "path",
                    "glob",
                    "output_mode",
                    "-B",
                    "-A",
                    "-C",
                    "-i",
                    "type",
                    "head_limit",
                    "multiline",
                ],
            )?;
            native_search(lease, &sftp, &root, &cwd, input, still_authorized).await
        }
        _ => unreachable!("tool name matched above"),
    }
}

async fn native_read(
    sftp: &SftpConnection,
    root: &str,
    cwd: &str,
    input: ReadFileInput,
    still_authorized: &AuthorizationCheck<'_>,
) -> Result<SshDispatchResult, String> {
    if input.pages.is_some() || input.format.is_some() {
        return Err(
            "workerless SSH read supports UTF-8 text only; PDF page and format options are unavailable"
                .into(),
        );
    }
    let requested = resolve_user_path(cwd, &input.path)?;
    let path = resolve_existing_path(sftp, root, &requested).await?;
    ensure_authorized(still_authorized)?;

    let limit = input.limit.unwrap_or(MAX_LINES_READ).min(MAX_LINES_READ);
    // Positive ranges can be collected while counting and validating the source.
    // Negative ranges need the final line count before choosing their window.
    let mut collector = (input.offset.unwrap_or(1) >= 0).then(|| {
        ReadWindowCollector::new(ReadSelection::new(
            input.offset,
            limit,
            &RemoteTextScan::default(),
        ))
    });
    let scan = scan_remote_text(sftp, &path, &mut collector).await?;
    let output = if scan.is_empty {
        ReadFileOutput::FileContent(FileContent {
            content: String::new(),
            content_concise: None,
            absolute_path: PathBuf::from(&path),
            offset: stored_read_offset(input.offset),
            limit: input.limit,
            raw_output: String::new(),
            total_lines: 0,
            extracted_images: Vec::new(),
        })
    } else {
        ensure_authorized(still_authorized)?;
        let window = match collector {
            Some(collector) => collector.finish(&scan),
            None => {
                let selection = ReadSelection::new(input.offset, limit, &scan);
                stream_selected_read_window(sftp, &path, selection, &scan).await?
            }
        };
        match (!window.too_large)
            .then(|| format_read_window(window))
            .flatten()
        {
            None => ReadFileOutput::FileTooLarge(format!(
                "The requested line range in {path} exceeds the workerless SSH read output limit; request fewer lines."
            )),
            Some(formatted) if exceeds_read_cap(&formatted.content) => {
                ReadFileOutput::FileTooLarge(format!(
                    "The requested line range in {path} exceeds the workerless SSH read output limit; request fewer lines."
                ))
            }
            Some(formatted) => ReadFileOutput::FileContent(FileContent {
                content_concise: Some(formatted.content.clone()),
                content: formatted.content,
                absolute_path: PathBuf::from(&path),
                offset: stored_read_offset(input.offset),
                limit: input.limit,
                raw_output: formatted.raw_output,
                total_lines: scan.total_lines,
                extracted_images: formatted.extracted_images,
            }),
        }
    };
    let prompt = match &output {
        ReadFileOutput::FileContent(content) => content.content.clone(),
        ReadFileOutput::FileTooLarge(message) => message.clone(),
        _ => format!("Unable to read remote file {path}"),
    };
    dispatch_result(output, prompt)
}

async fn native_write(
    sftp: &SftpConnection,
    root: &str,
    cwd: &str,
    input: WriteInput,
    still_authorized: &AuthorizationCheck<'_>,
) -> Result<SshDispatchResult, String> {
    let requested = resolve_user_path(cwd, &input.file_path)?;
    let target = prepare_write_target(sftp, root, &requested, still_authorized).await?;
    write_atomically(
        sftp,
        root,
        &target.path,
        input.content.as_bytes(),
        target.permissions,
        target.existed,
        None,
        still_authorized,
    )
    .await?;

    let old_string = target.old_text.unwrap_or_default();
    let created = !target.existed;
    let detail = whole_file_edit_detail(&old_string, &input.content);
    let output = SearchReplaceOutput::EditsApplied(SearchReplaceEditsApplied {
        old_string,
        new_string: input.content,
        tool_output_for_prompt: if created {
            format!("The remote file {} has been created.", target.path)
        } else {
            format!("Wrote remote file {} successfully.", target.path)
        },
        tool_output_for_prompt_concise: Some(if created {
            format!("The remote file {} has been created.", target.path)
        } else {
            format!("Wrote remote file {} successfully.", target.path)
        }),
        absolute_path: PathBuf::from(&target.path),
        edits: SearchReplaceEditContextInformation {
            details: vec![detail],
        },
        patch: None,
        unicode_normalized: false,
    });
    let prompt = match &output {
        SearchReplaceOutput::EditsApplied(applied) => applied.tool_output_for_prompt.clone(),
        _ => unreachable!(),
    };
    dispatch_result(output, prompt)
}

async fn native_edit(
    sftp: &SftpConnection,
    root: &str,
    cwd: &str,
    input: EditInput,
    still_authorized: &AuthorizationCheck<'_>,
) -> Result<SshDispatchResult, String> {
    if let Err(message) = validate_edit_strings(&input.old_string, &input.new_string) {
        return dispatch_result(
            SearchReplaceOutput::InvalidInput(message.into()),
            message.into(),
        );
    }

    let requested = resolve_user_path(cwd, &input.file_path)?;
    if input.old_string.is_empty() {
        return native_edit_create(sftp, root, &requested, input, still_authorized).await;
    }

    let path = resolve_existing_path(sftp, root, &requested).await?;
    let original_bytes = read_limited(sftp, &path, READ_FILE_MAX_BYTES).await?;
    let original = std::str::from_utf8(&original_bytes).map_err(|_| {
        format!(
            "workerless SSH edit supports UTF-8 text only; {path} is binary or uses another encoding"
        )
    })?;
    let positions = match select_edit_positions(original, &input.old_string, input.replace_all) {
        Ok(positions) => positions,
        Err(EditMatchError::NoMatch) => {
            let output = SearchReplaceOutput::NoMatchesFound(NoMatchesFoundError {
                message: "The string to replace was not found in the file. Make sure it matches exactly, including whitespace and indentation.".into(),
                file_path: PathBuf::from(&path),
                file_snapshot_at_edit: Some(original.to_owned()),
            });
            return dispatch_result(
                output,
                "No exact matching text was found in the remote file.".into(),
            );
        }
        Err(EditMatchError::Multiple) => {
            let output = SearchReplaceOutput::MultipleMatchesFound(
                "The string to replace was found multiple times in the file. Use replaceAll to replace every occurrence, or include more context to select one occurrence.".into(),
            );
            return dispatch_result(output, "The requested remote edit is ambiguous.".into());
        }
    };
    let (updated, new_positions) =
        replace_positions(original, &positions, &input.old_string, &input.new_string)?;

    // SFTP v3 does not expose a conditional rename. `write_atomically` re-reads
    // immediately before its single rename to detect a competing change while
    // this edit was prepared; a different client can still race after that
    // check.
    let permissions = existing_permissions(sftp, &path).await?;
    write_atomically(
        sftp,
        root,
        &path,
        updated.as_bytes(),
        permissions,
        true,
        Some(original.as_bytes()),
        still_authorized,
    )
    .await?;

    let details = new_positions
        .iter()
        .zip(positions.iter())
        .map(|(&new_position, &old_position)| {
            edit_detail(
                original,
                &updated,
                old_position,
                new_position,
                &input.old_string,
                &input.new_string,
            )
        })
        .collect();
    let prompt = if new_positions.len() == 1 {
        format!("The remote file {} has been updated.", path)
    } else {
        format!(
            "All {} occurrences were replaced in remote file {}.",
            new_positions.len(),
            path
        )
    };
    let output = SearchReplaceOutput::EditsApplied(SearchReplaceEditsApplied {
        old_string: input.old_string,
        new_string: input.new_string,
        tool_output_for_prompt: prompt.clone(),
        tool_output_for_prompt_concise: Some(prompt.clone()),
        absolute_path: PathBuf::from(&path),
        edits: SearchReplaceEditContextInformation { details },
        patch: None,
        unicode_normalized: false,
    });
    dispatch_result(output, prompt)
}

async fn native_edit_create(
    sftp: &SftpConnection,
    root: &str,
    requested: &str,
    input: EditInput,
    still_authorized: &AuthorizationCheck<'_>,
) -> Result<SshDispatchResult, String> {
    let target = prepare_write_target(sftp, root, requested, still_authorized).await?;
    if !empty_old_may_create(target.existed, target.is_empty) {
        let output = SearchReplaceOutput::FileAlreadyExists(
            "oldString is empty, which is only allowed when creating a new file or when the file is empty.".into(),
        );
        return dispatch_result(output, "The remote file already contains text.".into());
    }

    let expected_original = target.existed.then_some(&[] as &[u8]);
    write_atomically(
        sftp,
        root,
        &target.path,
        input.new_string.as_bytes(),
        target.permissions,
        target.existed,
        expected_original,
        still_authorized,
    )
    .await?;
    let prompt = format!("The remote file {} has been created.", target.path);
    let output = SearchReplaceOutput::EditsApplied(SearchReplaceEditsApplied {
        old_string: String::new(),
        new_string: input.new_string.clone(),
        tool_output_for_prompt: prompt.clone(),
        tool_output_for_prompt_concise: Some(prompt.clone()),
        absolute_path: PathBuf::from(&target.path),
        edits: SearchReplaceEditContextInformation {
            details: vec![whole_file_edit_detail("", &input.new_string)],
        },
        patch: None,
        unicode_normalized: false,
    });
    dispatch_result(output, prompt)
}

async fn native_search(
    lease: &ConnectionLease,
    sftp: &SftpConnection,
    root: &str,
    cwd: &str,
    input: GrepSearchInput,
    still_authorized: &AuthorizationCheck<'_>,
) -> Result<SshDispatchResult, String> {
    reject_nul("grep pattern", &input.pattern)?;
    if let Some(path) = &input.path {
        reject_nul("grep path", path)?;
    }
    if let Some(glob) = &input.glob {
        reject_nul("grep glob", glob)?;
    }
    if let Some(file_type) = &input.r#type {
        reject_nul("grep type", file_type)?;
    }

    let requested = match input.path.as_deref() {
        Some(path) => resolve_user_path(cwd, path)?,
        None => cwd.to_owned(),
    };
    let path = resolve_existing_path(sftp, root, &requested).await?;
    let output_mode = input.output_mode.clone().unwrap_or_default();
    let head_limit = search_head_limit(&input, &output_mode);
    let command = build_rg_command(&input, &output_mode, &path);
    ensure_authorized(still_authorized)?;

    let mut command_handle = lease
        .exec_command(&command)
        .await
        .map_err(transport_error)?;
    let mut stdout = Vec::new();
    let mut stderr = Vec::new();
    let mut stderr_truncated = false;
    let mut exit_status = None;
    let mut exit_signal = None;
    let mut truncated = false;
    let mut timed_out = false;
    let mut stop_requested = false;

    let deadline = Instant::now() + SEARCH_TIMEOUT;
    loop {
        let Some(remaining) = search_remaining_time(deadline, Instant::now()) else {
            timed_out = true;
            request_search_stop(&command_handle).await?;
            break;
        };
        let event = match tokio::time::timeout(remaining, command_handle.next_event()).await {
            Ok(result) => result.map_err(transport_error)?,
            Err(_) => {
                timed_out = true;
                request_search_stop(&command_handle).await?;
                break;
            }
        };
        let Some(event) = event else {
            break;
        };
        match event {
            SshCommandEvent::Stdout(chunk) => {
                if !stop_requested {
                    let overflow = append_capped(&mut stdout, &chunk, SEARCH_RAW_BYTES);
                    let line_limit_reached =
                        stdout.iter().filter(|&&byte| byte == b'\n').count() > head_limit;
                    if overflow || line_limit_reached {
                        truncated = true;
                        stop_requested = true;
                        request_search_stop(&command_handle).await?;
                    }
                }
            }
            SshCommandEvent::Stderr(chunk) => {
                stderr_truncated |= append_capped(&mut stderr, &chunk, SEARCH_STDERR_BYTES);
            }
            SshCommandEvent::ExitStatus(status) => exit_status = Some(status),
            SshCommandEvent::ExitSignal(signal) => exit_signal = Some(signal),
        }
    }

    let exit_code =
        resolve_search_exit_code(exit_status, exit_signal.as_deref(), timed_out, truncated)?;
    let output = format_search_output(
        &path,
        &stdout,
        &stderr,
        stderr_truncated,
        exit_code,
        &output_mode,
        head_limit,
        truncated || timed_out,
        timed_out,
        exit_signal.as_deref(),
    );
    let prompt = String::from_utf8_lossy(&output.stdout).into_owned();
    dispatch_result(output, prompt)
}

async fn canonical_root_with_sftp(sftp: &SftpConnection, root: &str) -> Result<String, String> {
    let canonical = sftp
        .canonicalize(root.to_owned())
        .await
        .map_err(|error| format!("could not canonicalize SSH root {root:?}: {error}"))?;
    reject_nul("canonical SSH root", &canonical)?;
    if !is_normal_absolute_path(&canonical) {
        return Err("SSH server returned a non-canonical root path".into());
    }
    let metadata = sftp
        .metadata(canonical.clone())
        .await
        .map_err(|error| format!("could not inspect SSH root {canonical:?}: {error}"))?;
    if !metadata.is_dir() {
        return Err(format!("SSH root {canonical:?} is not a directory"));
    }
    Ok(canonical)
}

async fn canonical_cwd_with_sftp(
    sftp: &SftpConnection,
    root: &str,
    cwd: &str,
) -> Result<String, String> {
    let canonical = sftp.canonicalize(cwd.to_owned()).await.map_err(|error| {
        format!("could not canonicalize SSH working directory {cwd:?}: {error}")
    })?;
    reject_nul("canonical SSH working directory", &canonical)?;
    if !is_path_within(&canonical, root) {
        return Err("SSH working directory escapes the granted root".into());
    }
    let metadata = sftp.metadata(canonical.clone()).await.map_err(|error| {
        format!("could not inspect SSH working directory {canonical:?}: {error}")
    })?;
    if !metadata.is_dir() {
        return Err(format!(
            "SSH working directory {canonical:?} is not a directory"
        ));
    }
    Ok(canonical)
}

async fn resolve_existing_path(
    sftp: &SftpConnection,
    root: &str,
    requested: &str,
) -> Result<String, String> {
    if !is_path_within(requested, root) {
        return Err("remote path escapes the granted root".into());
    }
    reject_symlink_components(sftp, root, requested).await?;
    let canonical = sftp
        .canonicalize(requested.to_owned())
        .await
        .map_err(|error| {
            if is_not_found(&error) {
                format!("remote file not found: {requested}")
            } else {
                format!("could not canonicalize remote path {requested:?}: {error}")
            }
        })?;
    reject_nul("canonical remote path", &canonical)?;
    if !is_path_within(&canonical, root) {
        return Err("remote path resolves outside the granted root".into());
    }
    Ok(canonical)
}

async fn prepare_write_target(
    sftp: &SftpConnection,
    root: &str,
    requested: &str,
    still_authorized: &AuthorizationCheck<'_>,
) -> Result<WriteTarget, String> {
    if !is_path_within(requested, root) || requested == root {
        return Err("remote write path must be a file below the granted root".into());
    }
    ensure_safe_parent_dirs(sftp, root, requested, still_authorized).await?;

    match sftp.symlink_metadata(requested.to_owned()).await {
        Ok(metadata) => {
            if metadata.is_symlink() {
                return Err("refusing to write through a remote symlink".into());
            }
            if metadata.is_dir() {
                return Err("remote write path is a directory".into());
            }
            let canonical = sftp
                .canonicalize(requested.to_owned())
                .await
                .map_err(|error| format!("could not canonicalize remote write path: {error}"))?;
            reject_nul("canonical remote write path", &canonical)?;
            if !is_path_within(&canonical, root) {
                return Err("remote write path resolves outside the granted root".into());
            }
            let bytes = read_limited(sftp, &canonical, READ_FILE_MAX_BYTES).await?;
            let old_text = String::from_utf8_lossy(&bytes).into_owned();
            Ok(WriteTarget {
                path: canonical,
                existed: true,
                is_empty: bytes.is_empty(),
                old_text: Some(old_text),
                permissions: metadata.permissions,
            })
        }
        Err(error) if is_not_found(&error) => Ok(WriteTarget {
            path: requested.to_owned(),
            existed: false,
            is_empty: true,
            old_text: None,
            permissions: None,
        }),
        Err(error) => Err(format!(
            "could not inspect remote write path {requested:?}: {error}"
        )),
    }
}

async fn existing_permissions(sftp: &SftpConnection, path: &str) -> Result<Option<u32>, String> {
    let metadata = sftp
        .symlink_metadata(path.to_owned())
        .await
        .map_err(|error| format!("could not inspect remote file before edit: {error}"))?;
    if metadata.is_symlink() {
        return Err("refusing to edit through a remote symlink".into());
    }
    Ok(metadata.permissions)
}

async fn verify_edit_unchanged(
    sftp: &SftpConnection,
    root: &str,
    path: &str,
    expected: &[u8],
) -> Result<(), String> {
    let current = resolve_existing_path(sftp, root, path).await?;
    if current != path {
        return Err("remote file changed path while preparing edit".into());
    }
    let actual = read_limited(sftp, path, READ_FILE_MAX_BYTES).await?;
    if actual != expected {
        return Err(
            "remote file changed while preparing edit; refusing to overwrite newer content".into(),
        );
    }
    Ok(())
}

async fn ensure_safe_parent_dirs(
    sftp: &SftpConnection,
    root: &str,
    target: &str,
    still_authorized: &AuthorizationCheck<'_>,
) -> Result<(), String> {
    let relative = target
        .strip_prefix(root.trim_end_matches('/'))
        .and_then(|suffix| suffix.strip_prefix('/'))
        .ok_or_else(|| "remote write path escapes the granted root".to_owned())?;
    let components: Vec<&str> = relative.split('/').collect();
    if components.len() < 2 {
        return Ok(());
    }
    let mut current = root.trim_end_matches('/').to_owned();
    for component in components.iter().take(components.len() - 1) {
        current = join_component(&current, component)?;
        match sftp.symlink_metadata(current.clone()).await {
            Ok(metadata) => {
                if metadata.is_symlink() {
                    return Err(format!(
                        "refusing to write through remote symlink {current}"
                    ));
                }
                if !metadata.is_dir() {
                    return Err(format!("remote parent {current} is not a directory"));
                }
            }
            Err(error) if is_not_found(&error) => {
                ensure_authorized(still_authorized)?;
                sftp.create_dir(current.clone()).await.map_err(|error| {
                    format!("could not create remote parent directory {current:?}: {error}")
                })?;
                let metadata = sftp
                    .symlink_metadata(current.clone())
                    .await
                    .map_err(|error| {
                        format!(
                            "could not verify created remote parent directory {current:?}: {error}"
                        )
                    })?;
                if metadata.is_symlink() || !metadata.is_dir() {
                    return Err(format!(
                        "created remote parent {current} is not a safe directory"
                    ));
                }
            }
            Err(error) => {
                return Err(format!(
                    "could not inspect remote parent {current:?}: {error}"
                ));
            }
        }
        let canonical = sftp.canonicalize(current.clone()).await.map_err(|error| {
            format!("could not canonicalize remote parent {current:?}: {error}")
        })?;
        if !is_path_within(&canonical, root) {
            return Err("remote parent resolves outside the granted root".into());
        }
    }
    Ok(())
}

async fn reject_symlink_components(
    sftp: &SftpConnection,
    root: &str,
    target: &str,
) -> Result<(), String> {
    let relative = target
        .strip_prefix(root.trim_end_matches('/'))
        .filter(|suffix| suffix.is_empty() || suffix.starts_with('/'))
        .map(|suffix| suffix.trim_start_matches('/'))
        .ok_or_else(|| "remote path escapes the granted root".to_owned())?;
    let mut current = root.trim_end_matches('/').to_owned();
    for component in relative
        .split('/')
        .filter(|component| !component.is_empty())
    {
        current = join_component(&current, component)?;
        let metadata = sftp
            .symlink_metadata(current.clone())
            .await
            .map_err(|error| {
                if is_not_found(&error) {
                    format!("remote file not found: {target}")
                } else {
                    format!("could not inspect remote path {current:?}: {error}")
                }
            })?;
        if metadata.is_symlink() {
            return Err(format!("refusing to access remote symlink {current}"));
        }
    }
    Ok(())
}

async fn write_atomically(
    sftp: &SftpConnection,
    root: &str,
    target: &str,
    data: &[u8],
    permissions: Option<u32>,
    target_existed: bool,
    expected_original: Option<&[u8]>,
    still_authorized: &AuthorizationCheck<'_>,
) -> Result<(), String> {
    if !is_path_within(target, root) {
        return Err("remote write path escapes the granted root".into());
    }
    if target_existed {
        ensure_authorized(still_authorized)?;
        let supported = sftp
            .supports_atomic_replace()
            .await
            .map_err(|error| format!("could not negotiate posix-rename@openssh.com: {error}"))?;
        if !supported {
            return Err(
                "remote SFTP server does not support posix-rename@openssh.com; refusing to modify an existing file without atomic replacement"
                    .into(),
            );
        }
    }
    let (parent, filename) = split_parent(target)?;
    let temporary = format!("{parent}/.{filename}.grok-{}.tmp", Uuid::now_v7());
    if !is_path_within(&temporary, root) {
        return Err("remote temporary path escapes the granted root".into());
    }
    // Revalidate every parent immediately before creating the temporary file:
    // a dangling or newly introduced symlink must not turn a new-file write
    // into an escape from the granted root.
    ensure_safe_parent_dirs(sftp, root, target, still_authorized).await?;
    let mut attributes = FileAttributes::empty();
    attributes.permissions = permissions;

    ensure_authorized(still_authorized)?;
    let mut file = sftp
        .open_with_flags_and_attributes(
            temporary.clone(),
            OpenFlags::CREATE | OpenFlags::EXCLUDE | OpenFlags::WRITE,
            attributes,
        )
        .await
        .map_err(|error| format!("could not create remote temporary file: {error}"))?;
    let write_result = async {
        ensure_authorized(still_authorized)?;
        file.write_all(data)
            .await
            .map_err(|error| format!("could not write remote temporary file: {error}"))?;
        file.flush()
            .await
            .map_err(|error| format!("could not flush remote temporary file: {error}"))?;
        file.sync_all()
            .await
            .map_err(|error| format!("could not synchronize remote temporary file: {error}"))?;
        file.shutdown()
            .await
            .map_err(|error| format!("could not close remote temporary file: {error}"))?;
        Ok::<(), String>(())
    }
    .await;
    if let Err(error) = write_result {
        if still_authorized() {
            let _ = sftp.remove_file(temporary).await;
        }
        return Err(error);
    }

    if let Some(expected) = expected_original
        && let Err(error) = verify_edit_unchanged(sftp, root, target, expected).await
    {
        if still_authorized() {
            let _ = sftp.remove_file(temporary).await;
        }
        return Err(error);
    }
    ensure_authorized(still_authorized)?;
    // Existing targets require the negotiated OpenSSH extension because SFTP
    // v3 rename is no-overwrite. A target known absent keeps baseline v3
    // no-overwrite semantics and fails if another client creates it meanwhile.
    let replacement = if target_existed {
        sftp.atomic_replace(temporary.clone(), target.to_owned())
            .await
    } else {
        sftp.rename(temporary.clone(), target.to_owned()).await
    };
    if let Err(error) = replacement {
        if still_authorized() {
            let _ = sftp.remove_file(temporary).await;
        }
        return Err(format!(
            "remote server rejected {} into {target:?}; no non-atomic fallback was used: {error}",
            if target_existed {
                "posix-rename@openssh.com atomic replacement"
            } else {
                "SFTP v3 no-overwrite rename"
            }
        ));
    }
    Ok(())
}

async fn read_limited(sftp: &SftpConnection, path: &str, limit: usize) -> Result<Vec<u8>, String> {
    let metadata = sftp
        .metadata(path.to_owned())
        .await
        .map_err(|error| format!("could not inspect remote file {path:?}: {error}"))?;
    if metadata.is_dir() {
        return Err(format!("remote path {path:?} is a directory, not a file"));
    }
    if metadata.len() > limit as u64 {
        return Err(format!(
            "remote file {path:?} exceeds the {} byte read limit",
            limit
        ));
    }
    let mut file = sftp
        .open(path.to_owned())
        .await
        .map_err(|error| format!("could not open remote file {path:?}: {error}"))?;
    let mut bytes = Vec::with_capacity(usize::try_from(metadata.len()).unwrap_or(limit).min(limit));
    let mut limited = (&mut file).take((limit + 1) as u64);
    limited
        .read_to_end(&mut bytes)
        .await
        .map_err(|error| format!("could not read remote file {path:?}: {error}"))?;
    if bytes.len() > limit {
        return Err(format!(
            "remote file {path:?} exceeds the {} byte read limit",
            limit
        ));
    }
    Ok(bytes)
}

async fn scan_remote_text(
    sftp: &SftpConnection,
    path: &str,
    collector: &mut Option<ReadWindowCollector>,
) -> Result<RemoteTextScan, String> {
    let metadata = sftp
        .metadata(path.to_owned())
        .await
        .map_err(|error| format!("could not inspect remote file {path:?}: {error}"))?;
    if metadata.is_dir() {
        return Err(format!("remote path {path:?} is a directory, not a file"));
    }

    let mut file = sftp
        .open(path.to_owned())
        .await
        .map_err(|error| format!("could not open remote file {path:?}: {error}"))?;
    let mut buffer = [0; READ_SOURCE_CHUNK_BYTES];
    let mut utf8 = StreamingUtf8Validator::default();
    let mut scan = RemoteTextScan {
        is_empty: true,
        ..Default::default()
    };
    let mut checked_metadata = false;
    loop {
        let len = file
            .read(&mut buffer)
            .await
            .map_err(|error| format!("could not read remote file {path:?}: {error}"))?;
        if len == 0 {
            break;
        }
        let chunk = &buffer[..len];
        if !checked_metadata {
            checked_metadata = true;
            if let Ok(metadata) = bytes_to_metadata(chunk)
                && (metadata.is_pdf() || metadata.is_image())
            {
                return Err(format!(
                    "workerless SSH read does not decode {} files; use a UTF-8 text file",
                    metadata.mime_type
                ));
            }
        }
        utf8.push(chunk)
            .map_err(|()| invalid_remote_text_error(path))?;
        if let Some(collector) = collector {
            collector.push(chunk);
        }
        scan.is_empty = false;
        scan.line_breaks = scan
            .line_breaks
            .saturating_add(chunk.iter().filter(|&&byte| byte == b'\n').count());
        scan.ends_with_newline = chunk.last() == Some(&b'\n');
    }
    utf8.finish()
        .map_err(|()| invalid_remote_text_error(path))?;
    file.close()
        .await
        .map_err(|error| format!("could not close remote file {path:?}: {error}"))?;
    scan.total_lines = (!scan.is_empty)
        .then_some(scan.line_breaks.saturating_add(1))
        .unwrap_or(0);
    Ok(scan)
}

async fn stream_selected_read_window(
    sftp: &SftpConnection,
    path: &str,
    selection: ReadSelection,
    scan: &RemoteTextScan,
) -> Result<ReadWindow, String> {
    let mut file = sftp
        .open(path.to_owned())
        .await
        .map_err(|error| format!("could not open remote file {path:?}: {error}"))?;
    let mut buffer = [0; READ_SOURCE_CHUNK_BYTES];
    let mut utf8 = StreamingUtf8Validator::default();
    let mut collector = ReadWindowCollector::new(selection);
    while !collector.too_large
        && collector.current_line.saturating_sub(selection.first_line) < selection.limit
    {
        let len = file
            .read(&mut buffer)
            .await
            .map_err(|error| format!("could not read remote file {path:?}: {error}"))?;
        if len == 0 {
            utf8.finish()
                .map_err(|()| invalid_remote_text_error(path))?;
            break;
        }
        let chunk = &buffer[..len];
        utf8.push(chunk)
            .map_err(|()| invalid_remote_text_error(path))?;
        collector.push(chunk);
    }
    file.close()
        .await
        .map_err(|error| format!("could not close remote file {path:?}: {error}"))?;
    Ok(collector.finish(scan))
}

fn invalid_remote_text_error(path: &str) -> String {
    format!(
        "workerless SSH read supports UTF-8 text only; {path} is binary or uses another encoding"
    )
}

#[derive(Default)]
struct RemoteTextScan {
    is_empty: bool,
    line_breaks: usize,
    ends_with_newline: bool,
    total_lines: usize,
}

#[derive(Clone, Copy)]
struct ReadSelection {
    first_line: usize,
    limit: usize,
}

impl ReadSelection {
    fn new(offset: Option<i64>, limit: usize, scan: &RemoteTextScan) -> Self {
        Self {
            first_line: resolve_streamed_read_start_line(offset, scan),
            limit,
        }
    }

    fn contains(self, line: usize) -> bool {
        line >= self.first_line && line.saturating_sub(self.first_line) < self.limit
    }
}

fn resolve_streamed_read_start_line(offset: Option<i64>, scan: &RemoteTextScan) -> usize {
    let offset = offset.unwrap_or(1);
    if offset == 0 {
        return 1;
    }
    if offset > 0 {
        return usize::try_from(offset).unwrap_or(usize::MAX);
    }
    let mut total_fields = scan.total_lines;
    if !scan.ends_with_newline {
        total_fields = total_fields.saturating_add(1);
    }
    let total_fields = i64::try_from(total_fields).unwrap_or(i64::MAX);
    usize::try_from(total_fields.saturating_add(offset).saturating_add(1).max(1))
        .unwrap_or(usize::MAX)
}

struct ReadWindowCollector {
    selection: ReadSelection,
    current_line: usize,
    raw: Vec<u8>,
    too_large: bool,
}

impl ReadWindowCollector {
    fn new(selection: ReadSelection) -> Self {
        Self {
            selection,
            current_line: 1,
            raw: Vec::new(),
            too_large: false,
        }
    }

    fn push(&mut self, bytes: &[u8]) {
        let mut start = 0;
        for (index, &byte) in bytes.iter().enumerate() {
            if byte == b'\n' {
                self.push_current_line(&bytes[start..=index]);
                self.current_line = self.current_line.saturating_add(1);
                start = index + 1;
            }
        }
        self.push_current_line(&bytes[start..]);
    }

    fn push_current_line(&mut self, bytes: &[u8]) {
        if self.too_large || !self.selection.contains(self.current_line) {
            return;
        }
        if self.raw.len().saturating_add(bytes.len()) > READ_FILE_MAX_BYTES {
            self.too_large = true;
            return;
        }
        self.raw.extend_from_slice(bytes);
    }

    fn finish(self, scan: &RemoteTextScan) -> ReadWindow {
        ReadWindow {
            raw: self.raw,
            first_line: self.selection.first_line,
            trailing_empty_selected: scan.ends_with_newline
                && self.selection.contains(scan.total_lines),
            too_large: self.too_large,
        }
    }
}

struct ReadWindow {
    raw: Vec<u8>,
    first_line: usize,
    trailing_empty_selected: bool,
    too_large: bool,
}

struct FormattedReadWindow {
    content: String,
    raw_output: String,
    extracted_images: Vec<xai_grok_tools::util::base64_images::ExtractedImage>,
}

fn format_read_window(window: ReadWindow) -> Option<FormattedReadWindow> {
    let mut raw_output = String::from_utf8(window.raw).ok()?;
    if raw_output.ends_with("\r\n") {
        raw_output.truncate(raw_output.len().saturating_sub(2));
        raw_output.push('\n');
    }
    let mut content = String::new();
    let mut extracted_images = Vec::new();
    let mut visible_lines = 0usize;
    for raw_line in raw_output.split_inclusive('\n') {
        let line_number = window.first_line.saturating_add(visible_lines);
        let line = raw_line.strip_suffix('\n').unwrap_or(raw_line);
        let line = line.strip_suffix('\r').unwrap_or(line);
        let line: Cow<'_, str> =
            match xai_grok_tools::util::base64_images::try_extract_base64_images(line) {
                Some(result) => {
                    extracted_images.extend(result.images);
                    Cow::Owned(result.text)
                }
                None => Cow::Borrowed(line),
            };
        append_formatted_read_line(&mut content, line_number, &line, visible_lines == 0)?;
        visible_lines = visible_lines.saturating_add(1);
    }
    if window.trailing_empty_selected {
        let line_number = window.first_line.saturating_add(visible_lines);
        append_formatted_read_line(&mut content, line_number, "", visible_lines == 0)?;
    }
    Some(FormattedReadWindow {
        content,
        raw_output,
        extracted_images,
    })
}

fn append_formatted_read_line(
    content: &mut String,
    line_number: usize,
    line: &str,
    is_first_visible: bool,
) -> Option<()> {
    let separator_len = usize::from(!is_first_visible);
    let prefix_len = if is_first_visible || line_number.is_multiple_of(10) {
        line_number.to_string().len().saturating_add('→'.len_utf8())
    } else {
        0
    };
    if content
        .len()
        .saturating_add(separator_len)
        .saturating_add(prefix_len)
        .saturating_add(line.len())
        > READ_FILE_MAX_BYTES
    {
        return None;
    }
    if !is_first_visible {
        content.push('\n');
    }
    if prefix_len > 0 {
        use std::fmt::Write as _;
        write!(content, "{line_number}→").ok()?;
    }
    content.push_str(line);
    Some(())
}

#[derive(Default)]
struct StreamingUtf8Validator {
    incomplete: [u8; 3],
    incomplete_len: usize,
}

impl StreamingUtf8Validator {
    fn push(&mut self, mut bytes: &[u8]) -> Result<(), ()> {
        if self.incomplete_len > 0 {
            let width = utf8_sequence_width(self.incomplete[0]).ok_or(())?;
            let needed = width.saturating_sub(self.incomplete_len);
            if bytes.len() < needed {
                self.incomplete[self.incomplete_len..self.incomplete_len + bytes.len()]
                    .copy_from_slice(bytes);
                self.incomplete_len += bytes.len();
                return Ok(());
            }
            let mut complete = [0; 4];
            complete[..self.incomplete_len]
                .copy_from_slice(&self.incomplete[..self.incomplete_len]);
            complete[self.incomplete_len..width].copy_from_slice(&bytes[..needed]);
            std::str::from_utf8(&complete[..width]).map_err(|_| ())?;
            self.incomplete_len = 0;
            bytes = &bytes[needed..];
        }
        match std::str::from_utf8(bytes) {
            Ok(_) => Ok(()),
            Err(error) if error.error_len().is_some() => Err(()),
            Err(error) => {
                let tail = &bytes[error.valid_up_to()..];
                if tail.is_empty() || tail.len() > self.incomplete.len() {
                    return Err(());
                }
                self.incomplete[..tail.len()].copy_from_slice(tail);
                self.incomplete_len = tail.len();
                Ok(())
            }
        }
    }

    fn finish(self) -> Result<(), ()> {
        if self.incomplete_len == 0 {
            Ok(())
        } else {
            Err(())
        }
    }
}

fn utf8_sequence_width(first: u8) -> Option<usize> {
    match first {
        0x00..=0x7f => Some(1),
        0xc2..=0xdf => Some(2),
        0xe0..=0xef => Some(3),
        0xf0..=0xf4 => Some(4),
        _ => None,
    }
}

fn build_rg_command(input: &GrepSearchInput, output_mode: &OutputMode, path: &str) -> String {
    let mut arguments = vec![
        "env".to_owned(),
        "-i".to_owned(),
        "PATH=/opt/homebrew/bin:/usr/local/bin:/usr/bin:/bin".to_owned(),
        "LC_ALL=C".to_owned(),
        "LANG=C".to_owned(),
        "RIPGREP_CONFIG_PATH=/dev/null".to_owned(),
        "PAGER=cat".to_owned(),
        "GIT_PAGER=cat".to_owned(),
        "rg".to_owned(),
        "--no-config".to_owned(),
        "--no-follow".to_owned(),
        "--color=never".to_owned(),
        "--heading".to_owned(),
        "--with-filename".to_owned(),
        "--line-number".to_owned(),
        "--max-columns".to_owned(),
        SEARCH_MAX_CHARS_PER_LINE.to_string(),
        "--max-columns-preview".to_owned(),
        "--max-filesize".to_owned(),
        "5M".to_owned(),
    ];
    if input.case_insensitive {
        arguments.push("--ignore-case".to_owned());
    }
    if let Some(glob) = &input.glob {
        arguments.extend(["--glob".to_owned(), glob.clone()]);
    }
    if let Some(file_type) = input.r#type.as_ref().filter(|value| !value.is_empty()) {
        arguments.extend(["--type".to_owned(), file_type.clone()]);
    }
    if input.multiline {
        arguments.extend(["-U".to_owned(), "--multiline-dotall".to_owned()]);
    }
    if let Some(context) = input.context.filter(|&value| value > 0) {
        arguments.extend(["-C".to_owned(), context.to_string()]);
    }
    if let Some(before) = input.before_context.filter(|&value| value > 0) {
        arguments.extend(["-B".to_owned(), before.to_string()]);
    }
    if let Some(after) = input.after_context.filter(|&value| value > 0) {
        arguments.extend(["-A".to_owned(), after.to_string()]);
    }
    match output_mode {
        OutputMode::Content => {}
        OutputMode::FilesWithMatches => arguments.push("-l".to_owned()),
        OutputMode::Count => arguments.push("-c".to_owned()),
    }
    arguments.extend([
        "-e".to_owned(),
        input.pattern.clone(),
        "--".to_owned(),
        path.to_owned(),
    ]);
    arguments
        .into_iter()
        .map(|argument| shell_quote(&argument))
        .collect::<Vec<_>>()
        .join(" ")
}

async fn request_search_stop(command: &xai_grok_ssh::SshCommand) -> Result<(), String> {
    command.signal("TERM").await.map_err(transport_error)?;
    command.close().await.map_err(transport_error)
}

fn search_remaining_time(deadline: Instant, now: Instant) -> Option<Duration> {
    deadline
        .checked_duration_since(now)
        .filter(|remaining| !remaining.is_zero())
}

fn resolve_search_exit_code(
    exit_status: Option<u32>,
    exit_signal: Option<&str>,
    timed_out: bool,
    truncated: bool,
) -> Result<i32, String> {
    match (exit_status, exit_signal, timed_out) {
        (_, _, true) => Ok(-1),
        (Some(status), None, _) => Ok(i32::try_from(status).unwrap_or(-1)),
        (_, Some(_), _) if truncated => Ok(0),
        (_, Some(_), _) => Ok(-1),
        (None, None, _) if truncated => Ok(0),
        (None, None, _) => Err("remote rg command ended without an exit status".into()),
    }
}

#[allow(clippy::too_many_arguments)]
fn format_search_output(
    path: &str,
    stdout: &[u8],
    stderr: &[u8],
    stderr_truncated: bool,
    exit_code: i32,
    output_mode: &OutputMode,
    head_limit: usize,
    truncated: bool,
    timed_out: bool,
    signal: Option<&str>,
) -> GrepSearchOutput {
    let mut stderr = stderr.to_vec();
    if stderr_truncated {
        const MARKER: &[u8] = b"\n[remote rg stderr truncated]";
        stderr.truncate(SEARCH_STDERR_BYTES.saturating_sub(MARKER.len()));
        stderr.extend_from_slice(MARKER);
    }
    let raw = String::from_utf8_lossy(stdout);
    let mut lines: Vec<String> = raw.lines().map(ToOwned::to_owned).collect();
    let output_truncated = truncated || lines.len() > head_limit;
    lines.truncate(head_limit);

    if timed_out {
        let body = if lines.is_empty() {
            "Ripgrep search timed out before returning results. Try a narrower path or pattern."
                .to_owned()
        } else {
            format_search_body(lines, output_mode, true)
        };
        return GrepSearchOutput {
            stdout: workspace_result(path, &body).into_bytes(),
            stderr,
            exit_code: -1,
            match_count: 0,
            file_matches: Vec::new(),
        };
    }
    if exit_code == 1 && lines.is_empty() {
        return GrepSearchOutput {
            stdout: workspace_result(path, "No matches found").into_bytes(),
            stderr: Vec::new(),
            exit_code,
            match_count: 0,
            file_matches: Vec::new(),
        };
    }
    if exit_code != 0 {
        let message = if exit_code == 127 {
            "Remote ripgrep dependency `rg` is unavailable on the sanitized PATH.".to_owned()
        } else {
            let reason = signal
                .map(|value| format!(" (terminated by {value})"))
                .unwrap_or_default();
            format!("Error calling remote rg: exit {exit_code}{reason}")
        };
        return GrepSearchOutput {
            stdout: message.into_bytes(),
            stderr,
            exit_code,
            match_count: 0,
            file_matches: Vec::new(),
        };
    }

    let match_count = match output_mode {
        OutputMode::Content => count_matches(&lines),
        OutputMode::FilesWithMatches => lines.len(),
        OutputMode::Count => lines
            .iter()
            .filter_map(|line| {
                line.rsplit_once(':')
                    .and_then(|(_, count)| count.parse::<usize>().ok())
            })
            .sum(),
    };
    let file_matches = if matches!(output_mode, OutputMode::Content) {
        parse_file_matches(&lines, SEARCH_MAX_CHARS_PER_LINE)
    } else {
        Vec::new()
    };
    let body = format_search_body(lines, output_mode, output_truncated);
    GrepSearchOutput {
        stdout: workspace_result(path, &body).into_bytes(),
        stderr,
        exit_code,
        match_count,
        file_matches,
    }
}

fn workspace_result(path: &str, body: &str) -> String {
    let path = path
        .replace('&', "&amp;")
        .replace('"', "&quot;")
        .replace('<', "&lt;")
        .replace('>', "&gt;");
    format!("<workspace_result workspace_path=\"{path}\">\n{body}\n</workspace_result>")
}

fn format_search_body(lines: Vec<String>, output_mode: &OutputMode, truncated: bool) -> String {
    match output_mode {
        OutputMode::Content => format_content_output(
            lines,
            truncated,
            SEARCH_MAX_CHARS_PER_LINE,
            SEARCH_OUTPUT_BYTES,
        ),
        OutputMode::FilesWithMatches => format_files_with_matches_output(
            lines,
            truncated,
            SEARCH_MAX_CHARS_PER_LINE,
            SEARCH_OUTPUT_BYTES,
        ),
        OutputMode::Count => format_count_output(
            lines,
            truncated,
            SEARCH_MAX_CHARS_PER_LINE,
            SEARCH_OUTPUT_BYTES,
        ),
    }
}

fn search_head_limit(input: &GrepSearchInput, output_mode: &OutputMode) -> usize {
    let (default, maximum) = match output_mode {
        OutputMode::Content => (SEARCH_CONTENT_DEFAULT, SEARCH_CONTENT_MAX),
        OutputMode::FilesWithMatches | OutputMode::Count => (SEARCH_FILE_DEFAULT, SEARCH_FILE_MAX),
    };
    input.head_limit.unwrap_or(default).min(maximum)
}

fn append_capped(buffer: &mut Vec<u8>, chunk: &[u8], cap: usize) -> bool {
    let remaining = cap.saturating_sub(buffer.len());
    let take = remaining.min(chunk.len());
    buffer.extend_from_slice(&chunk[..take]);
    take != chunk.len()
}

fn decode_input<T: DeserializeOwned>(
    args: Value,
    tool: &str,
    allowed: &[&str],
) -> Result<T, String> {
    let object = args
        .as_object()
        .ok_or_else(|| format!("{tool} arguments must be a JSON object"))?;
    for key in object.keys() {
        if !allowed.contains(&key.as_str()) {
            return Err(format!(
                "{tool} does not support argument {key:?} in workerless SSH mode"
            ));
        }
    }
    serde_json::from_value(args).map_err(|error| format!("invalid {tool} arguments: {error}"))
}

fn dispatch_result<T: Serialize>(
    output: T,
    prompt_text: String,
) -> Result<SshDispatchResult, String> {
    Ok(SshDispatchResult {
        output: serde_json::to_value(output)
            .map_err(|error| format!("could not serialize native SSH result: {error}"))?,
        prompt_text,
    })
}

fn resolve_user_path(cwd: &str, value: &str) -> Result<String, String> {
    reject_nul("remote path", value)?;
    if value.is_empty() {
        return Err("remote path must not be empty".into());
    }
    let mut result = if value.starts_with('/') {
        "/".to_owned()
    } else {
        cwd.to_owned()
    };
    for component in value
        .split('/')
        .filter(|part| !part.is_empty() && *part != ".")
    {
        result = join_component(&result, component)?;
    }
    Ok(result)
}

fn join_component(parent: &str, component: &str) -> Result<String, String> {
    if component.is_empty() || component == "." || component == ".." {
        return Err("remote path must not contain empty, '.' or '..' components".into());
    }
    Ok(if parent == "/" {
        format!("/{component}")
    } else {
        format!("{parent}/{component}")
    })
}

fn split_parent(path: &str) -> Result<(&str, &str), String> {
    let (parent, name) = path
        .rsplit_once('/')
        .ok_or_else(|| "remote path is not absolute".to_owned())?;
    if name.is_empty() || name == "." || name == ".." {
        return Err("remote path has no file name".into());
    }
    Ok((if parent.is_empty() { "/" } else { parent }, name))
}

fn is_normal_absolute_path(path: &str) -> bool {
    path == "/"
        || (path.starts_with('/')
            && path
                .split('/')
                .skip(1)
                .all(|component| !component.is_empty() && component != "." && component != ".."))
}

fn is_path_within(path: &str, root: &str) -> bool {
    is_normal_absolute_path(path)
        && is_normal_absolute_path(root)
        && (root == "/"
            || path == root
            || path
                .strip_prefix(root)
                .is_some_and(|suffix| suffix.starts_with('/')))
}

fn shell_quote(argument: &str) -> String {
    format!("'{}'", argument.replace('\'', "'\"'\"'"))
}

fn reject_nul(name: &str, value: &str) -> Result<(), String> {
    if value.contains('\0') {
        Err(format!("{name} must not contain NUL"))
    } else {
        Ok(())
    }
}

fn ensure_authorized(check: &AuthorizationCheck<'_>) -> Result<(), String> {
    if check() {
        Ok(())
    } else {
        Err("SSH binding was revoked before the native operation could run".into())
    }
}

fn transport_error(error: impl std::fmt::Display) -> String {
    format!("SSH transport: {error}")
}

fn is_not_found(error: &SftpError) -> bool {
    matches!(error, SftpError::Status(status) if status.status_code == StatusCode::NoSuchFile)
}

fn stored_read_offset(offset: Option<i64>) -> Option<usize> {
    offset
        .filter(|&value| value >= 0)
        .map(|value| value as usize)
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum EditMatchError {
    NoMatch,
    Multiple,
}

fn validate_edit_strings(old: &str, new: &str) -> Result<(), &'static str> {
    if old == new {
        Err("Old string and new string are the same")
    } else {
        Ok(())
    }
}

fn empty_old_may_create(exists: bool, is_empty: bool) -> bool {
    !exists || is_empty
}

fn select_edit_positions(
    original: &str,
    old: &str,
    replace_all: bool,
) -> Result<Vec<usize>, EditMatchError> {
    let positions: Vec<usize> = original
        .match_indices(old)
        .map(|(position, _)| position)
        .collect();
    if positions.is_empty() {
        Err(EditMatchError::NoMatch)
    } else if positions.len() > 1 && !replace_all {
        Err(EditMatchError::Multiple)
    } else if replace_all {
        Ok(positions)
    } else {
        Ok(vec![positions[0]])
    }
}

fn replace_positions(
    original: &str,
    positions: &[usize],
    old: &str,
    new: &str,
) -> Result<(String, Vec<usize>), String> {
    let mut updated =
        String::with_capacity(original.len() + positions.len().saturating_mul(new.len()));
    let mut new_positions = Vec::with_capacity(positions.len());
    let mut cursor = 0;
    for &position in positions {
        let before = original
            .get(cursor..position)
            .ok_or_else(|| "invalid remote edit match positions".to_owned())?;
        updated.push_str(before);
        new_positions.push(updated.len());
        updated.push_str(new);
        cursor = position + old.len();
    }
    updated.push_str(
        original
            .get(cursor..)
            .ok_or_else(|| "invalid remote edit match positions".to_owned())?,
    );
    Ok((updated, new_positions))
}

fn whole_file_edit_detail(old: &str, new: &str) -> SearchReplaceEditDetail {
    SearchReplaceEditDetail {
        old_string: old.to_owned(),
        old_line: 1,
        new_string: new.to_owned(),
        new_line: 1,
        context_before: String::new(),
        context_after: String::new(),
        line_prefix: String::new(),
    }
}

fn edit_detail(
    original: &str,
    updated: &str,
    old_position: usize,
    new_position: usize,
    old: &str,
    new: &str,
) -> SearchReplaceEditDetail {
    let old_line = line_number_at(original, old_position);
    let new_line = line_number_at(updated, new_position);
    let (context_before, context_after) = edit_context(updated, new_position, new);
    let line_start = updated[..new_position]
        .rfind('\n')
        .map(|index| index + 1)
        .unwrap_or(0);
    SearchReplaceEditDetail {
        old_string: old.to_owned(),
        old_line,
        new_string: new.to_owned(),
        new_line,
        context_before,
        context_after,
        line_prefix: updated[line_start..new_position].to_owned(),
    }
}

fn line_number_at(text: &str, position: usize) -> usize {
    text[..position]
        .bytes()
        .filter(|&byte| byte == b'\n')
        .count()
        + 1
}

fn edit_context(text: &str, position: usize, replacement: &str) -> (String, String) {
    let start_line = line_number_at(text, position).saturating_sub(1);
    let end_line = start_line + replacement.split_inclusive('\n').count().max(1) - 1;
    let lines: Vec<&str> = text.split_inclusive('\n').collect();
    let before_start = start_line.saturating_sub(EDIT_CONTEXT_LINES);
    let after_end = (end_line + EDIT_CONTEXT_LINES + 1).min(lines.len());
    (
        lines[before_start..start_line].concat(),
        lines[(end_line + 1).min(lines.len())..after_end].concat(),
    )
}

struct WriteTarget {
    path: String,
    existed: bool,
    is_empty: bool,
    old_text: Option<String>,
    permissions: Option<u32>,
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn path_resolution_rejects_lexical_root_escapes() {
        assert_eq!(
            resolve_user_path("/repo/src", "lib.rs"),
            Ok("/repo/src/lib.rs".into())
        );
        assert!(resolve_user_path("/repo/src", "../secret").is_err());
        assert_eq!(
            resolve_user_path("/repo/src", "nested//./file"),
            Ok("/repo/src/nested/file".into())
        );
        assert_eq!(resolve_user_path("/repo/src", "."), Ok("/repo/src".into()));
        assert_eq!(resolve_user_path("/", "./"), Ok("/".into()));
        assert_eq!(resolve_user_path("/", "//repo/./"), Ok("/repo".into()));
        assert!(resolve_user_path("/repo", "/repo/../secret").is_err());
        assert!(!is_path_within("/repo-other/file", "/repo"));
        assert!(is_path_within("/repo/file", "/repo"));
        assert!(is_path_within("/anything", "/"));
    }

    #[test]
    fn edit_requires_unique_match_unless_replace_all() {
        let text = "same\nsame\n";
        assert_eq!(
            select_edit_positions(text, "same", false),
            Err(EditMatchError::Multiple)
        );
        assert_eq!(
            select_edit_positions(text, "missing", false),
            Err(EditMatchError::NoMatch)
        );
        let positions = select_edit_positions(text, "same", true).unwrap();
        let (updated, new_positions) = replace_positions(text, &positions, "same", "new").unwrap();
        assert_eq!(updated, "new\nnew\n");
        assert_eq!(new_positions, vec![0, 4]);
    }

    #[test]
    fn edit_detail_tracks_old_and_new_locations() {
        let (updated, positions) =
            replace_positions("one\ntwo\n", &[4], "two", "three\nfour").unwrap();
        let detail = edit_detail(
            "one\ntwo\n",
            &updated,
            4,
            positions[0],
            "two",
            "three\nfour",
        );
        assert_eq!(detail.old_line, 2);
        assert_eq!(detail.new_line, 2);
        assert_eq!(detail.line_prefix, "");
    }

    #[test]
    fn edit_rejects_noop_and_allows_empty_old_only_for_new_or_empty_files() {
        assert_eq!(
            validate_edit_strings("unchanged", "unchanged"),
            Err("Old string and new string are the same")
        );
        assert!(validate_edit_strings("", "new").is_ok());
        assert!(empty_old_may_create(false, false));
        assert!(empty_old_may_create(true, true));
        assert!(!empty_old_may_create(true, false));
    }

    #[test]
    fn input_validation_rejects_ignored_fields() {
        let args = serde_json::json!({"target_file": "a", "unsupported": true});
        let error = decode_input::<ReadFileInput>(args, "read_file", &["target_file"]).unwrap_err();
        assert!(error.contains("unsupported"));
    }

    #[test]
    fn streamed_read_selects_requested_and_negative_ranges() {
        let source = b"one\ntwo\nthree\n";
        let scan = RemoteTextScan {
            is_empty: false,
            line_breaks: 3,
            ends_with_newline: true,
            total_lines: 4,
        };
        let selection = ReadSelection::new(Some(2), 2, &scan);
        let mut collector = ReadWindowCollector::new(selection);
        for chunk in source.chunks(2) {
            collector.push(chunk);
        }
        assert!(!collector.too_large);
        let formatted = format_read_window(ReadWindow {
            raw: collector.raw,
            first_line: selection.first_line,
            trailing_empty_selected: false,
            too_large: false,
        })
        .unwrap();
        assert_eq!(formatted.content, "2→two\nthree");
        assert_eq!(formatted.raw_output, "two\nthree\n");

        let unterminated = RemoteTextScan {
            is_empty: false,
            line_breaks: 2,
            ends_with_newline: false,
            total_lines: 3,
        };
        assert_eq!(resolve_streamed_read_start_line(Some(-2), &unterminated), 3);
        assert_eq!(resolve_streamed_read_start_line(Some(-1), &unterminated), 4);
    }

    #[test]
    fn streamed_read_skips_large_unrequested_source() {
        let mut source = vec![b'x'; READ_FILE_MAX_BYTES + 1];
        source.extend_from_slice(b"\nneedle\n");
        let scan = RemoteTextScan {
            is_empty: false,
            line_breaks: 2,
            ends_with_newline: true,
            total_lines: 3,
        };
        let selection = ReadSelection::new(Some(2), 1, &scan);
        let mut collector = ReadWindowCollector::new(selection);
        for chunk in source.chunks(127) {
            collector.push(chunk);
        }
        assert!(!collector.too_large);
        assert_eq!(collector.raw, b"needle\n");
        let formatted = format_read_window(ReadWindow {
            raw: collector.raw,
            first_line: selection.first_line,
            trailing_empty_selected: false,
            too_large: false,
        })
        .unwrap();
        assert_eq!(formatted.content, "2→needle");
    }

    #[test]
    fn streamed_read_bounds_an_oversized_requested_line() {
        let source = vec![b'x'; READ_FILE_MAX_BYTES + 1];
        let scan = RemoteTextScan {
            is_empty: false,
            line_breaks: 0,
            ends_with_newline: false,
            total_lines: 1,
        };
        let selection = ReadSelection::new(Some(1), 1, &scan);
        let mut collector = ReadWindowCollector::new(selection);
        for chunk in source.chunks(127) {
            collector.push(chunk);
        }
        assert!(collector.too_large);
        assert!(collector.raw.len() <= READ_FILE_MAX_BYTES);
    }
    #[test]
    fn search_deadline_is_global_and_truncated_close_is_useful() {
        let now = Instant::now();
        let deadline = now + SEARCH_TIMEOUT;
        assert_eq!(search_remaining_time(deadline, now), Some(SEARCH_TIMEOUT));
        assert_eq!(search_remaining_time(deadline, deadline), None);
        assert_eq!(resolve_search_exit_code(None, None, false, true), Ok(0));
        assert!(resolve_search_exit_code(None, None, false, false).is_err());
    }
}
