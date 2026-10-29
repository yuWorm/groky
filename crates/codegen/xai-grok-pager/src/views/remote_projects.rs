//! Remote SSH project picker state, merge logic, rendering, and input.

use std::collections::HashMap;

use chrono::{DateTime, Utc};
use crossterm::event::{Event, KeyCode, KeyEvent, KeyModifiers};
use ratatui::buffer::Buffer;
use ratatui::layout::Rect;
use ratatui::style::Style;

use crate::theme::Theme;
use crate::views::modal_window::{
    self, ModalSizing, ModalWindowConfig, ModalWindowState, Shortcut,
};
use crate::views::picker::{
    self, PickerConfig, PickerEntry, PickerOutcome, PickerRow, PickerState,
};

const TABS: [&str; 3] = ["All", "Remembered", "Recent"];

/// Configured target metadata used only to label a remembered or historical project.
#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) struct RemoteProjectTarget {
    pub target_id: String,
    pub label: String,
    pub host: String,
}

/// A project rule returned by the local SSH service.
#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) struct RememberedRemoteProject {
    pub target_id: String,
    pub root: String,
}

/// One persisted SSH project session from `x.ai/session/list`.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct RemoteProjectSession {
    pub target_id: String,
    pub root: String,
    pub session_id: String,
    /// Storage cwd from the session row (an `ssh-v1-…` key for SSH projects), not a remote path.
    pub cwd: String,
    pub last_active_at: DateTime<Utc>,
}

/// The configuration and remembered-project half of a remote project load.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct RemoteProjectCatalog {
    pub(crate) targets: Vec<RemoteProjectTarget>,
    pub(crate) remembered: Vec<RememberedRemoteProject>,
}

/// A selectable remote project, merged by `(target_id, root)`.
#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) struct RemoteProjectRow {
    pub target_id: String,
    pub label: String,
    pub host: String,
    pub root: String,
    pub remembered: bool,
    pub session_count: usize,
    pub last_active_at: Option<DateTime<Utc>>,
    pub latest_session: Option<RemoteProjectSession>,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum RemoteProjectsTab {
    All,
    Remembered,
    Recent,
}

impl RemoteProjectsTab {
    fn index(self) -> usize {
        match self {
            Self::All => 0,
            Self::Remembered => 1,
            Self::Recent => 2,
        }
    }

    fn from_index(index: usize) -> Self {
        match index % TABS.len() {
            1 => Self::Remembered,
            2 => Self::Recent,
            _ => Self::All,
        }
    }

    fn cycle(self, backwards: bool) -> Self {
        let index = self.index();
        let next = if backwards {
            (index + TABS.len() - 1) % TABS.len()
        } else {
            (index + 1) % TABS.len()
        };
        Self::from_index(next)
    }
}

/// Remote picker state retained by its owning SSH manager.
#[derive(Debug)]
pub(crate) struct RemoteProjectsState {
    generation: u64,
    pub picker: PickerState,
    pub tab: RemoteProjectsTab,
    pub rows: Vec<RemoteProjectRow>,
    loading: bool,
    error: Option<String>,
    hint: Option<String>,
}

impl RemoteProjectsState {
    pub(crate) fn loading(generation: u64) -> Self {
        Self {
            generation,
            picker: PickerState::input_active(),
            tab: RemoteProjectsTab::All,
            rows: Vec::new(),
            loading: true,
            error: None,
            hint: None,
        }
    }

    pub(crate) fn generation(&self) -> u64 {
        self.generation
    }

    pub(crate) fn apply(
        &mut self,
        generation: u64,
        result: Result<(RemoteProjectCatalog, Vec<RemoteProjectSession>), String>,
    ) {
        if generation != self.generation {
            return;
        }
        self.loading = false;
        self.hint = None;
        match result {
            Ok((catalog, sessions)) => {
                self.rows =
                    merge_remote_project_rows(catalog.targets, catalog.remembered, sessions);
                self.error = None;
                self.picker.selected = 0;
            }
            Err(error) => {
                self.rows.clear();
                self.error = Some(error);
            }
        }
    }

    pub(crate) fn set_tab_from_index(&mut self, index: usize, window: &mut ModalWindowState) {
        self.set_tab(RemoteProjectsTab::from_index(index), window);
    }

    pub(crate) fn filtered_row_indices(&self) -> Vec<usize> {
        let query = self.picker.query().trim().to_lowercase();
        self.rows
            .iter()
            .enumerate()
            .filter(|(_, row)| {
                matches!(self.tab, RemoteProjectsTab::All)
                    || matches!(self.tab, RemoteProjectsTab::Remembered) && row.remembered
                    || matches!(self.tab, RemoteProjectsTab::Recent) && row.session_count > 0
            })
            .filter(|(_, row)| {
                query.is_empty()
                    || [
                        row.label.as_str(),
                        row.host.as_str(),
                        row.target_id.as_str(),
                        row.root.as_str(),
                    ]
                    .into_iter()
                    .any(|field| field.to_lowercase().contains(&query))
            })
            .map(|(index, _)| index)
            .collect()
    }

    fn set_tab(&mut self, tab: RemoteProjectsTab, window: &mut ModalWindowState) {
        self.tab = tab;
        window.active_tab = tab.index();
        self.picker.selected = 0;
        self.picker.scroll_offset = None;
        self.hint = None;
    }

    fn selected_row(&self) -> Option<&RemoteProjectRow> {
        let rows = self.filtered_row_indices();
        rows.get(self.picker.selected)
            .and_then(|index| self.rows.get(*index))
    }
}

/// Selection outcome translated by the SSH modal host into pager actions.
pub(crate) enum RemoteProjectsOutcome {
    Close,
    Changed,
    Unchanged,
    StartNew { target_id: String, root: String },
    Resume { session_id: String, cwd: String },
}

fn ensure_remote_project_row<'a>(
    rows: &'a mut HashMap<(String, String), RemoteProjectRow>,
    targets: &HashMap<String, RemoteProjectTarget>,
    target_id: String,
    root: String,
) -> &'a mut RemoteProjectRow {
    rows.entry((target_id.clone(), root.clone()))
        .or_insert_with(|| {
            let target = targets.get(&target_id);
            let label = target
                .map(|target| target.label.trim())
                .filter(|label| !label.is_empty())
                .map(ToOwned::to_owned)
                .or_else(|| {
                    target
                        .map(|target| target.host.trim())
                        .filter(|host| !host.is_empty())
                        .map(ToOwned::to_owned)
                })
                .unwrap_or_else(|| target_id.clone());
            RemoteProjectRow {
                target_id,
                label,
                host: target.map(|target| target.host.clone()).unwrap_or_default(),
                root,
                remembered: false,
                session_count: 0,
                last_active_at: None,
                latest_session: None,
            }
        })
}

/// Merge rule-store entries and persisted SSH sessions into project picker rows.
pub(crate) fn merge_remote_project_rows(
    targets: Vec<RemoteProjectTarget>,
    remembered: Vec<RememberedRemoteProject>,
    sessions: Vec<RemoteProjectSession>,
) -> Vec<RemoteProjectRow> {
    let targets = targets
        .into_iter()
        .map(|target| (target.target_id.clone(), target))
        .collect::<HashMap<_, _>>();
    let mut rows = HashMap::<(String, String), RemoteProjectRow>::new();

    for project in remembered {
        if project.target_id.trim().is_empty() || project.root.trim().is_empty() {
            continue;
        }
        ensure_remote_project_row(&mut rows, &targets, project.target_id, project.root)
            .remembered = true;
    }
    for session in sessions {
        if session.target_id.trim().is_empty() || session.root.trim().is_empty() {
            continue;
        }
        let row = ensure_remote_project_row(
            &mut rows,
            &targets,
            session.target_id.clone(),
            session.root.clone(),
        );
        row.session_count += 1;
        if row
            .last_active_at
            .is_none_or(|last_active_at| session.last_active_at > last_active_at)
        {
            row.last_active_at = Some(session.last_active_at);
            row.latest_session = Some(session);
        }
    }

    let mut rows = rows.into_values().collect::<Vec<_>>();
    rows.sort_by(
        |left, right| match (left.last_active_at, right.last_active_at) {
            (Some(left_time), Some(right_time)) => right_time
                .cmp(&left_time)
                .then_with(|| left.label.cmp(&right.label))
                .then_with(|| left.root.cmp(&right.root)),
            (Some(_), None) => std::cmp::Ordering::Less,
            (None, Some(_)) => std::cmp::Ordering::Greater,
            (None, None) => left
                .label
                .to_lowercase()
                .cmp(&right.label.to_lowercase())
                .then_with(|| left.root.cmp(&right.root)),
        },
    );
    rows
}

/// Render the picker within the SSH manager's modal chrome.
pub(crate) fn render_remote_projects(
    buf: &mut Buffer,
    area: Rect,
    window: &mut ModalWindowState,
    state: &mut RemoteProjectsState,
    compact: bool,
    theme: &Theme,
) {
    window.active_tab = state.tab.index();
    let shortcuts = [
        Shortcut {
            label: "Enter new session",
            clickable: false,
            id: 0,
        },
        Shortcut {
            label: "Ctrl+R resume latest",
            clickable: false,
            id: 0,
        },
        Shortcut {
            label: "Tab switch list",
            clickable: false,
            id: 0,
        },
        Shortcut {
            label: "Esc close",
            clickable: false,
            id: 0,
        },
    ];
    let config = ModalWindowConfig {
        title: "Remote projects",
        tabs: Some(&TABS),
        shortcuts: &shortcuts,
        sizing: ModalSizing::medium().with_compact(compact),
        fold_info: None,
    };
    let Some(modal) = modal_window::render_modal_window(buf, area, window, &config, theme) else {
        state.picker.hit_areas = None;
        return;
    };
    let content = modal.content;
    if content.height == 0 {
        return;
    }
    picker::render_picker_search_bar(
        buf,
        content.x,
        content.y,
        content.width,
        theme,
        &state.picker,
        true,
        false,
        Some(theme.bg_base),
    );
    let divider_y = content.y.saturating_add(1);
    if divider_y < content.bottom() {
        picker::render_divider(
            buf,
            modal.inner_x,
            divider_y,
            modal.inner_width,
            theme,
            Some(theme.bg_base),
        );
    }
    let rows_area = Rect::new(
        content.x,
        divider_y.saturating_add(1),
        content.width,
        content.bottom().saturating_sub(divider_y.saturating_add(1)),
    );
    state.picker.hit_areas = None;
    if state.loading {
        buf.set_string(
            rows_area.x,
            rows_area.y,
            "Loading remote projects…",
            Style::default().fg(theme.text_secondary),
        );
        return;
    }
    if let Some(error) = state.error.as_deref() {
        for (offset, line) in modal_window::word_wrap(error, rows_area.width as usize)
            .into_iter()
            .take(rows_area.height as usize)
            .enumerate()
        {
            buf.set_stringn(
                rows_area.x,
                rows_area.y.saturating_add(offset as u16),
                line,
                rows_area.width as usize,
                Style::default().fg(theme.accent_error),
            );
        }
        return;
    }

    let filtered = state.filtered_row_indices();
    if filtered.is_empty() {
        let text = if state.rows.is_empty() {
            "No remote projects yet. Use /ssh → Open remote project, or groky ssh open."
        } else {
            "No remote projects match this list or search."
        };
        buf.set_stringn(
            rows_area.x,
            rows_area.y,
            text,
            rows_area.width as usize,
            Style::default().fg(theme.text_secondary),
        );
        return;
    }

    let roots = filtered
        .iter()
        .map(|index| state.rows[*index].root.as_str())
        .collect::<Vec<_>>();
    let secondary = filtered
        .iter()
        .map(|index| secondary_text(&state.rows[*index]))
        .collect::<Vec<_>>();
    let summaries = roots
        .iter()
        .zip(&secondary)
        .map(|(root, secondary)| [*root, secondary.as_str()])
        .collect::<Vec<_>>();
    let entries = filtered
        .iter()
        .enumerate()
        .map(|(visible_index, row_index)| {
            let row = &state.rows[*row_index];
            PickerEntry::Row(PickerRow {
                label: &row.label,
                right_label: "",
                selected: state.picker.selected == visible_index,
                expanded: false,
                fields: &[],
                description_lines: &[],
                summary_lines: &summaries[visible_index],
                dimmed: false,
                indent: 0,
                badge: if row.remembered { "remembered" } else { "" },
                badge_color: Some(theme.fuzzy_accent),
                collapsible: false,
                underline_last_desc: false,
            })
        })
        .collect::<Vec<_>>();
    let hits = picker::render_picker_content_with_scrollbar_x(
        buf,
        rows_area,
        theme,
        &mut state.picker,
        &entries,
        &[],
        &[],
        Some(theme.bg_base),
        false,
        0,
        modal.inner_x + modal.inner_width.saturating_sub(1),
    );
    state.picker.hit_areas = Some(crate::views::picker::PickerHitAreas {
        close_button: Rect::default(),
        search_bar: Rect::new(content.x, content.y, content.width, 1),
        item_rects: hits.item_rects,
        entry_indices: hits.entry_indices,
        tab_rects: Vec::new(),
        filter_rect: None,
    });
    if let Some(hint) = state.hint.as_deref() {
        let y = rows_area.bottom().saturating_sub(1);
        buf.set_stringn(
            rows_area.x,
            y,
            hint,
            rows_area.width as usize,
            Style::default().fg(theme.text_secondary),
        );
    }
}

/// Handle an event within the picker. SSH modal chrome is handled here so its tabs
/// remain independent from the manager's ordinary pages.
pub(crate) fn handle_remote_projects_event(
    state: &mut RemoteProjectsState,
    window: &mut ModalWindowState,
    event: &Event,
) -> RemoteProjectsOutcome {
    let Event::Key(key) = event else {
        let entry_count = state.filtered_row_indices().len();
        let outcome =
            picker::handle_picker_input(event, &mut state.picker, entry_count, &picker_config());
        return handle_picker_outcome(state, outcome);
    };
    if key.code == KeyCode::Esc && key.modifiers.is_empty() {
        return RemoteProjectsOutcome::Close;
    }
    let backwards_tab = key.code == KeyCode::BackTab
        || key.code == KeyCode::Tab && key.modifiers == KeyModifiers::SHIFT;
    if (key.code == KeyCode::Tab && key.modifiers.is_empty()) || backwards_tab {
        state.set_tab(state.tab.cycle(backwards_tab), window);
        return RemoteProjectsOutcome::Changed;
    }
    if key.code == KeyCode::Char('r') && key.modifiers == KeyModifiers::CONTROL {
        return match state
            .selected_row()
            .and_then(|row| row.latest_session.as_ref())
        {
            Some(session) => RemoteProjectsOutcome::Resume {
                session_id: session.session_id.clone(),
                cwd: session.cwd.clone(),
            },
            None => {
                state.hint = Some("No saved session to resume for this project.".into());
                RemoteProjectsOutcome::Changed
            }
        };
    }
    let entry_count = state.filtered_row_indices().len();
    let outcome =
        picker::handle_picker_input(event, &mut state.picker, entry_count, &picker_config());
    handle_picker_outcome(state, outcome)
}

fn handle_picker_outcome(
    state: &mut RemoteProjectsState,
    outcome: PickerOutcome,
) -> RemoteProjectsOutcome {
    match outcome {
        PickerOutcome::Selected(index) => state
            .filtered_row_indices()
            .get(index)
            .and_then(|row_index| state.rows.get(*row_index))
            .map(|row| RemoteProjectsOutcome::StartNew {
                target_id: row.target_id.clone(),
                root: row.root.clone(),
            })
            .unwrap_or(RemoteProjectsOutcome::Unchanged),
        PickerOutcome::Closed => RemoteProjectsOutcome::Close,
        PickerOutcome::Changed
        | PickerOutcome::QueryChanged
        | PickerOutcome::Expand(_)
        | PickerOutcome::Collapse(_)
        | PickerOutcome::Copy(_)
        | PickerOutcome::SubmitQuery
        | PickerOutcome::TabChanged(_)
        | PickerOutcome::FilterCycled
        | PickerOutcome::Action(_)
        | PickerOutcome::NonSelectableClick(_) => RemoteProjectsOutcome::Changed,
        PickerOutcome::Unchanged => RemoteProjectsOutcome::Unchanged,
    }
}

fn picker_config() -> PickerConfig<'static> {
    PickerConfig {
        title: None,
        show_search_hint: true,
        expandable: false,
        esc_clears_query: false,
        shortcuts: None,
        pending_hint: None,
        shortcuts_area: None,
        non_selectable: &[],
        non_selectable_clickable: &[],
        tabs: None,
        active_tab: 0,
        filter_label: None,
        filter_key_hint: None,
        filter_active: false,
        header_note: None,
        action_keys: &[],
        disable_search: false,
        compact_bottom_bar: true,
        search_only_on_slash: false,
        vim_normal_first: false,
    }
}

fn secondary_text(row: &RemoteProjectRow) -> String {
    let mut details = Vec::new();
    if row.remembered {
        details.push("remembered".to_owned());
    }
    if row.session_count > 0 {
        let suffix = if row.session_count == 1 {
            "session"
        } else {
            "sessions"
        };
        details.push(format!("{} {suffix}", row.session_count));
    }
    if let Some(last_active_at) = row.last_active_at {
        details.push(format!("active {}", relative_time(last_active_at)));
    }
    details.join(" · ")
}

fn relative_time(timestamp: DateTime<Utc>) -> String {
    let duration = Utc::now().signed_duration_since(timestamp);
    if duration.num_minutes() < 1 {
        "just now".into()
    } else if duration.num_minutes() < 60 {
        format!("{}m ago", duration.num_minutes())
    } else if duration.num_hours() < 24 {
        format!("{}h ago", duration.num_hours())
    } else {
        format!("{}d ago", duration.num_days())
    }
}

#[cfg(test)]
mod tests {
    use chrono::TimeZone;
    use crossterm::event::{Event, KeyCode, KeyEvent, KeyModifiers};

    use super::*;

    fn target(id: &str, label: &str) -> RemoteProjectTarget {
        RemoteProjectTarget {
            target_id: id.into(),
            label: label.into(),
            host: format!("{id}.example.test"),
        }
    }

    fn session(id: &str, root: &str, session_id: &str, minute: i64) -> RemoteProjectSession {
        RemoteProjectSession {
            target_id: id.into(),
            root: root.into(),
            session_id: session_id.into(),
            cwd: root.into(),
            last_active_at: Utc
                .with_ymd_and_hms(2026, 1, 1, 0, minute as u32, 0)
                .unwrap(),
        }
    }

    #[test]
    fn merge_deduplicates_projects_marks_remembered_and_sorts_recent_first() {
        let rows = merge_remote_project_rows(
            vec![
                target("east", "East"),
                target("west", "West"),
                target("north", "Alpha"),
            ],
            vec![
                RememberedRemoteProject {
                    target_id: "east".into(),
                    root: "/srv/a".into(),
                },
                RememberedRemoteProject {
                    target_id: "west".into(),
                    root: "/srv/z".into(),
                },
                RememberedRemoteProject {
                    target_id: "north".into(),
                    root: "/srv/zz".into(),
                },
            ],
            vec![
                session("east", "/srv/a", "old", 1),
                session("east", "/srv/a", "latest", 5),
                session("east", "/srv/b", "other", 3),
            ],
        );

        assert_eq!(
            rows.iter().map(|row| row.root.as_str()).collect::<Vec<_>>(),
            vec!["/srv/a", "/srv/b", "/srv/zz", "/srv/z"]
        );
        assert!(rows[0].remembered);
        assert_eq!(rows[0].session_count, 2);
        assert_eq!(
            rows[0].latest_session.as_ref().unwrap().session_id,
            "latest"
        );
        assert_eq!(rows[1].session_count, 1);
        assert!(rows[3].remembered);
        assert_eq!(rows[3].session_count, 0);
    }

    #[test]
    fn tabs_filter_remembered_and_recent_rows() {
        let mut state = RemoteProjectsState::loading(1);
        state.apply(
            1,
            Ok((
                RemoteProjectCatalog::default(),
                vec![session("east", "/srv/a", "recent", 1)],
            )),
        );
        state.rows.push(RemoteProjectRow {
            target_id: "remembered".into(),
            label: "Remembered".into(),
            host: String::new(),
            root: "/srv/r".into(),
            remembered: true,
            session_count: 0,
            last_active_at: None,
            latest_session: None,
        });
        state.tab = RemoteProjectsTab::All;
        assert_eq!(state.filtered_row_indices().len(), 2);
        state.tab = RemoteProjectsTab::Remembered;
        assert_eq!(state.filtered_row_indices(), vec![1]);
        state.tab = RemoteProjectsTab::Recent;
        assert_eq!(state.filtered_row_indices(), vec![0]);
    }

    #[test]
    fn typing_filters_across_project_fields() {
        let mut state = RemoteProjectsState::loading(1);
        state.apply(
            1,
            Ok((
                RemoteProjectCatalog::default(),
                vec![session("east", "/srv/a", "resume", 1)],
            )),
        );
        let mut window = ModalWindowState::new();
        assert!(matches!(
            handle_remote_projects_event(
                &mut state,
                &mut window,
                &Event::Key(KeyEvent::new(KeyCode::Char('s'), KeyModifiers::NONE)),
            ),
            RemoteProjectsOutcome::Changed
        ));
        assert_eq!(state.picker.query(), "s");
        assert_eq!(state.filtered_row_indices(), vec![0]);
    }

    #[test]
    fn enter_starts_a_new_session_and_ctrl_r_resumes_latest() {
        let mut state = RemoteProjectsState::loading(1);
        state.apply(
            1,
            Ok((
                RemoteProjectCatalog::default(),
                vec![session("east", "/srv/a", "resume", 1)],
            )),
        );
        let mut window = ModalWindowState::new();
        assert!(matches!(
            handle_remote_projects_event(
                &mut state,
                &mut window,
                &Event::Key(KeyEvent::new(KeyCode::Enter, KeyModifiers::NONE)),
            ),
            RemoteProjectsOutcome::StartNew { target_id, root } if target_id == "east" && root == "/srv/a"
        ));
        assert!(matches!(
            handle_remote_projects_event(
                &mut state,
                &mut window,
                &Event::Key(KeyEvent::new(KeyCode::Char('r'), KeyModifiers::CONTROL)),
            ),
            RemoteProjectsOutcome::Resume { session_id, cwd } if session_id == "resume" && cwd == "/srv/a"
        ));
    }

    #[test]
    fn ctrl_r_on_remembered_only_row_does_nothing_and_tab_cycles() {
        let mut state = RemoteProjectsState::loading(1);
        state.apply(
            1,
            Ok((
                RemoteProjectCatalog {
                    targets: vec![],
                    remembered: vec![RememberedRemoteProject {
                        target_id: "east".into(),
                        root: "/srv/a".into(),
                    }],
                },
                vec![],
            )),
        );
        let mut window = ModalWindowState::new();
        assert!(matches!(
            handle_remote_projects_event(
                &mut state,
                &mut window,
                &Event::Key(KeyEvent::new(KeyCode::Char('r'), KeyModifiers::CONTROL)),
            ),
            RemoteProjectsOutcome::Changed
        ));
        assert!(matches!(
            handle_remote_projects_event(
                &mut state,
                &mut window,
                &Event::Key(KeyEvent::new(KeyCode::Tab, KeyModifiers::NONE)),
            ),
            RemoteProjectsOutcome::Changed
        ));
        assert_eq!(state.tab, RemoteProjectsTab::Remembered);
        assert!(matches!(
            handle_remote_projects_event(
                &mut state,
                &mut window,
                &Event::Key(KeyEvent::new(KeyCode::BackTab, KeyModifiers::NONE)),
            ),
            RemoteProjectsOutcome::Changed
        ));
        assert_eq!(state.tab, RemoteProjectsTab::All);
    }
}
