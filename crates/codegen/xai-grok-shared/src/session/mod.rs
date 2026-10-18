use std::path::PathBuf;

pub mod info;
pub mod location;

pub use info::Info;
pub use location::{info_for_location, is_ssh_storage_cwd, storage_cwd, storage_cwd_from_dirname};

// Re-export shared feedback wire types used by downstream crates (e.g. xai-grok-pager-render).
pub use prod_mc_cli_chat_proxy_types::feedback_types::FeedbackTerminalInfo;

pub fn session_dir(info: &Info) -> PathBuf {
    xai_grok_config::sessions_cwd_dir(&info.cwd).join(info.id.to_string())
}
