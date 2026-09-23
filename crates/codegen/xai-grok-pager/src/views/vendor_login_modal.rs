//! Third-party provider login overlay.
//!
//! Chrome, close button, footer shortcuts, and click-outside come from
//! [`super::modal_window`]. Provider picking is a hoverable row list; the
//! API-key field uses [`LineEditor`] with a Settings-style caret.

use crossterm::event::{
    KeyCode, KeyEvent, KeyEventKind, KeyModifiers, MouseButton, MouseEventKind,
};
use ratatui::buffer::Buffer;
use ratatui::layout::Rect;
use ratatui::style::{Modifier, Style};
use ratatui::text::{Line, Span};
use ratatui::widgets::{Paragraph, Widget};
use unicode_width::UnicodeWidthStr;

use crate::input::line_editor::{LineEditOutcome, LineEditor};
use crate::render::line_utils::truncate_str;
use crate::theme::Theme;
use crate::views::modal_window::{
    ModalSizing, ModalWindowConfig, ModalWindowOutcome, ModalWindowState, Shortcut,
    handle_modal_key, handle_modal_mouse, render_modal_window,
};

const SHORTCUT_SUBMIT: usize = 1;
const SHORTCUT_CANCEL: usize = 2;
const SHORTCUT_SELECT_ALL: usize = 3;
const SHORTCUT_SELECT_NONE: usize = 4;
const SHORTCUT_SEARCH: usize = 5;
const SHORTCUT_ADD: usize = 6;
const SHORTCUT_SKIP_SYNC: usize = 7;
const SHORTCUT_TOGGLE_REASONING: usize = 8;
const SHORTCUT_REFRESH: usize = 9;
const ADD_CUSTOM_ID: &str = "__add_custom__";
const PROTOCOLS: &[&str] = &["chat_completions", "responses", "messages"];

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum CustomField {
    Name,
    BaseUrl,
    Protocol,
    Key,
}

#[derive(Debug)]
struct CustomDraft {
    /// Existing custom-provider id when editing; `None` when adding.
    id: Option<String>,
    name: LineEditor,
    base_url: LineEditor,
    key: LineEditor,
    protocol: usize,
    field: CustomField,
    models: Vec<CustomModelPick>,
    selected: usize,
    scroll: usize,
    search: LineEditor,
    search_focused: bool,
}

#[derive(Debug, Clone)]
struct CustomModelPick {
    api_model: String,
    name: String,
    context_window: u64,
    advertised_context_window: Option<u64>,
    supports_reasoning_effort: bool,
    enabled: bool,
    auto_compact_threshold_percent: Option<u8>,
}

impl CustomModelPick {
    fn from_custom_model(m: xai_grok_shell::compat::custom::CustomModel) -> Self {
        Self {
            api_model: m.api_model,
            name: m.name,
            context_window: m.context_window,
            advertised_context_window: m.advertised_context_window,
            supports_reasoning_effort: m.supports_reasoning_effort,
            enabled: m.enabled,
            auto_compact_threshold_percent: m.auto_compact_threshold_percent,
        }
    }

    /// Provider/models.dev cap when known. `None` means the user may type any size.
    fn provider_cap(&self) -> Option<u64> {
        if let Some(adv) = self.advertised_context_window.filter(|c| *c > 0) {
            return Some(adv);
        }
        let suggested = xai_grok_shell::compat::reasoning::suggest_model(&self.api_model);
        suggested.matched.then_some(suggested.context_window.max(1))
    }

    fn advertised_window(&self) -> u64 {
        self.provider_cap()
            .unwrap_or(self.context_window)
            .max(self.context_window)
            .max(1)
    }

    fn to_custom_model(&self) -> xai_grok_shell::compat::custom::CustomModel {
        xai_grok_shell::compat::custom::CustomModel {
            api_model: self.api_model.clone(),
            name: self.name.clone(),
            context_window: self.context_window,
            advertised_context_window: self.advertised_context_window,
            supports_reasoning_effort: self.supports_reasoning_effort,
            enabled: self.enabled,
            auto_compact_threshold_percent: self.auto_compact_threshold_percent,
        }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum AddModelField {
    ApiModel,
    Name,
    Context,
    Threshold,
    Reasoning,
}

#[derive(Debug)]
struct AddModelDraft {
    api_model: LineEditor,
    name: LineEditor,
    context_text: LineEditor,
    field: AddModelField,
    supports_reasoning_effort: bool,
    context_window: u64,
    advertised_context_window: u64,
    auto_compact_threshold_percent: Option<u8>,
    matched: bool,
    reasoning_touched: bool,
    context_touched: bool,
    error: Option<String>,
}

impl AddModelDraft {
    fn new() -> Self {
        let mut context_text = LineEditor::default();
        context_text.set_text(&xai_grok_shell::context_window::format_window(128_000));
        Self {
            api_model: LineEditor::default(),
            name: LineEditor::default(),
            context_text,
            field: AddModelField::ApiModel,
            supports_reasoning_effort: false,
            context_window: 128_000,
            advertised_context_window: 128_000,
            auto_compact_threshold_percent: None,
            matched: false,
            reasoning_touched: false,
            context_touched: false,
            error: None,
        }
    }

    fn set_context_window(&mut self, tokens: u64) {
        self.context_window = tokens.max(1);
        self.context_text
            .set_text(&xai_grok_shell::context_window::format_window(
                self.context_window,
            ));
    }

    fn parsed_context_window(&self) -> Result<u64, String> {
        let raw = self.context_text.text().trim();
        if raw.is_empty() {
            return Ok(self.context_window.max(1));
        }
        let hint_max = self.advertised_context_window.max(1);
        let Some(parsed) = xai_grok_shell::context_window::parse_window_arg(raw, hint_max) else {
            return Err(format!("Use 256k, 1M, or 1.05M (got '{raw}')"));
        };
        if self.matched {
            Ok(parsed.min(hint_max).max(1))
        } else {
            Ok(parsed.max(1))
        }
    }

    fn active_editor_mut(&mut self) -> Option<&mut LineEditor> {
        match self.field {
            AddModelField::ApiModel => Some(&mut self.api_model),
            AddModelField::Name => Some(&mut self.name),
            AddModelField::Context => Some(&mut self.context_text),
            AddModelField::Threshold | AddModelField::Reasoning => None,
        }
    }

    fn cycle_field(&mut self, forward: bool) {
        if self.field == AddModelField::Context
            && let Ok(tokens) = self.parsed_context_window()
        {
            self.set_context_window(tokens);
            self.context_touched = true;
        }
        const ORDER: [AddModelField; 5] = [
            AddModelField::ApiModel,
            AddModelField::Name,
            AddModelField::Context,
            AddModelField::Threshold,
            AddModelField::Reasoning,
        ];
        let i = ORDER.iter().position(|f| *f == self.field).unwrap_or(0);
        self.field = if forward {
            ORDER[(i + 1) % ORDER.len()]
        } else {
            ORDER[(i + ORDER.len() - 1) % ORDER.len()]
        };
    }

    fn refresh_suggestion(&mut self) {
        let suggested =
            xai_grok_shell::compat::reasoning::suggest_model(self.api_model.text().trim());
        self.advertised_context_window = suggested.context_window;
        if !self.context_touched {
            self.set_context_window(suggested.context_window);
        }
        self.matched = suggested.matched;
        if !self.reasoning_touched {
            self.supports_reasoning_effort = suggested.supports_reasoning_effort;
        }
    }
}

impl CustomDraft {
    fn new() -> Self {
        let mut base_url = LineEditor::default();
        base_url.set_text("https://");
        Self {
            id: None,
            name: LineEditor::default(),
            base_url,
            key: LineEditor::default(),
            protocol: 0,
            field: CustomField::Name,
            models: Vec::new(),
            selected: 0,
            scroll: 0,
            search: LineEditor::default(),
            search_focused: false,
        }
    }

    fn from_provider(provider: xai_grok_shell::compat::custom::CustomProvider, key: &str) -> Self {
        let mut name = LineEditor::default();
        name.set_text(&provider.name);
        let mut base_url = LineEditor::default();
        base_url.set_text(&provider.base_url);
        let mut key_ed = LineEditor::default();
        if !key.is_empty() {
            key_ed.set_text(key);
        }
        let protocol = PROTOCOLS
            .iter()
            .position(|p| *p == provider.api_backend.as_str())
            .unwrap_or(0);
        let models = provider
            .models
            .iter()
            .cloned()
            .map(CustomModelPick::from_custom_model)
            .collect();
        Self {
            id: Some(provider.id),
            name,
            base_url,
            key: key_ed,
            protocol,
            field: CustomField::Name,
            models,
            selected: 0,
            scroll: 0,
            search: LineEditor::default(),
            search_focused: false,
        }
    }

    fn active_editor_mut(&mut self) -> Option<&mut LineEditor> {
        match self.field {
            CustomField::Name => Some(&mut self.name),
            CustomField::BaseUrl => Some(&mut self.base_url),
            CustomField::Key => Some(&mut self.key),
            CustomField::Protocol => None,
        }
    }

    fn cycle_field(&mut self, forward: bool) {
        self.field = match (self.field, forward) {
            (CustomField::Name, true) | (CustomField::Key, false) => CustomField::BaseUrl,
            (CustomField::BaseUrl, true) | (CustomField::Name, false) => CustomField::Protocol,
            (CustomField::Protocol, true) | (CustomField::BaseUrl, false) => CustomField::Key,
            (CustomField::Key, true) | (CustomField::Protocol, false) => CustomField::Name,
        };
    }

    fn filtered_indices(&self) -> Vec<usize> {
        let q = self.search.text().trim().to_ascii_lowercase();
        self.models
            .iter()
            .enumerate()
            .filter(|(_, m)| {
                if q.is_empty() {
                    return true;
                }
                m.api_model.to_ascii_lowercase().contains(&q)
                    || m.name.to_ascii_lowercase().contains(&q)
            })
            .map(|(i, _)| i)
            .collect()
    }

    fn clamp_selection_to_filter(&mut self) {
        let filtered = self.filtered_indices();
        if filtered.is_empty() {
            return;
        }
        if !filtered.contains(&self.selected) {
            self.selected = filtered[0];
            self.scroll = 0;
        }
    }

    fn set_filtered_enabled(&mut self, enabled: bool) {
        let filtered = self.filtered_indices();
        for i in filtered {
            if let Some(row) = self.models.get_mut(i) {
                row.enabled = enabled;
            }
        }
    }

    fn move_selection(&mut self, delta: isize) -> bool {
        let filtered = self.filtered_indices();
        if filtered.is_empty() {
            return false;
        }
        let pos = filtered
            .iter()
            .position(|&i| i == self.selected)
            .unwrap_or(0);
        let next = pos as isize + delta;
        if next < 0 || next >= filtered.len() as isize {
            return false;
        }
        self.selected = filtered[next as usize];
        true
    }
}

#[derive(Debug)]
enum VendorLoginStep {
    Pick {
        selected: usize,
        scroll: usize,
    },
    Method {
        provider_id: String,
        provider_name: String,
        selected: usize,
        from_picker: bool,
    },
    Key {
        provider_id: String,
        provider_name: String,
        requires_auth: bool,
        from_picker: bool,
    },
    OAuthWait {
        provider_id: String,
        provider_name: String,
        authorize_url: String,
        instructions: String,
        from_picker: bool,
    },
    CustomForm,
    CustomModels,
}

#[derive(Debug)]
pub(crate) struct VendorLoginState {
    pub window: ModalWindowState,
    step: VendorLoginStep,
    pub(crate) editor: LineEditor,
    pub error: Option<String>,
    pub probing: bool,
    content_area: Option<Rect>,
    /// Screen Y → provider index, rebuilt each pick-step frame.
    row_map: Vec<(u16, usize)>,
    custom: Option<CustomDraft>,
    add_model: Option<AddModelDraft>,
    context_edit: Option<LineEditor>,
}

impl VendorLoginState {
    pub(crate) fn picker() -> Self {
        Self {
            window: ModalWindowState::new(),
            step: VendorLoginStep::Pick {
                selected: 0,
                scroll: 0,
            },
            editor: LineEditor::default(),
            error: None,
            probing: false,
            content_area: None,
            row_map: Vec::new(),
            custom: None,
            add_model: None,
            context_edit: None,
        }
    }

    pub(crate) fn for_provider(provider_id: String, provider_name: String) -> Self {
        let mut state = Self::picker();
        state.enter_provider(provider_id, provider_name, false);
        state
    }

    pub(crate) fn oauth_provider_id(&self) -> Option<&str> {
        match &self.step {
            VendorLoginStep::OAuthWait { provider_id, .. } => Some(provider_id.as_str()),
            _ => None,
        }
    }

    pub(crate) fn enter_oauth_wait(&mut self, authorize_url: String, instructions: String) {
        let (provider_id, provider_name, from_picker) = match &self.step {
            VendorLoginStep::Method {
                provider_id,
                provider_name,
                from_picker,
                ..
            }
            | VendorLoginStep::OAuthWait {
                provider_id,
                provider_name,
                from_picker,
                ..
            }
            | VendorLoginStep::Key {
                provider_id,
                provider_name,
                from_picker,
                ..
            } => (provider_id.clone(), provider_name.clone(), *from_picker),
            VendorLoginStep::Pick { .. }
            | VendorLoginStep::CustomForm
            | VendorLoginStep::CustomModels => return,
        };
        self.step = VendorLoginStep::OAuthWait {
            provider_id,
            provider_name,
            authorize_url,
            instructions,
            from_picker,
        };
        self.editor.reset();
        self.error = None;
        self.probing = false;
    }

    pub(crate) fn apply_custom_models(
        &mut self,
        models: Vec<(String, String, u64)>,
        error: Option<String>,
    ) {
        self.probing = false;
        self.add_model = None;
        if self.custom.is_none() {
            self.custom = Some(CustomDraft::new());
        }
        if let Some(err) = error {
            self.error = Some(err);
            self.step = VendorLoginStep::CustomModels;
            return;
        }
        self.error = None;
        self.step = VendorLoginStep::CustomModels;
        let Some(draft) = self.custom.as_mut() else {
            return;
        };
        let stored: Vec<xai_grok_shell::compat::custom::CustomModel> = draft
            .models
            .iter()
            .map(CustomModelPick::to_custom_model)
            .collect();
        let live = models
            .into_iter()
            .map(
                |(api_model, name, context_window)| xai_grok_shell::compat::custom::RemoteModel {
                    api_model,
                    name,
                    context_window,
                },
            )
            .collect();
        draft.models = xai_grok_shell::compat::custom::merge_live_models(&stored, live)
            .into_iter()
            .map(CustomModelPick::from_custom_model)
            .collect();
        draft.selected = 0;
        draft.scroll = 0;
        draft.search_focused = false;
        draft.clamp_selection_to_filter();
    }

    pub(crate) fn custom_form() -> Self {
        let mut state = Self::picker();
        state.enter_custom_form();
        state
    }

    pub(crate) fn edit_custom(provider_id: String) -> Self {
        let mut state = Self::picker();
        state.enter_custom_edit(&provider_id);
        state
    }

    fn enter_custom_form(&mut self) {
        self.custom = Some(CustomDraft::new());
        self.add_model = None;
        self.step = VendorLoginStep::CustomForm;
        self.error = None;
        self.probing = false;
        self.row_map.clear();
    }

    fn enter_custom_edit(&mut self, provider_id: &str) {
        let Some(provider) = xai_grok_shell::compat::custom::get_provider(provider_id) else {
            self.enter_custom_form();
            return;
        };
        let key = xai_grok_shell::compat::custom::stored_secret(provider_id).unwrap_or_default();
        let has_models = !provider.models.is_empty();
        self.custom = Some(CustomDraft::from_provider(provider, &key));
        self.add_model = None;
        self.step = if has_models {
            VendorLoginStep::CustomModels
        } else {
            VendorLoginStep::CustomForm
        };
        self.error = None;
        self.probing = false;
        self.row_map.clear();
    }

    fn enter_provider(&mut self, provider_id: String, provider_name: String, from_picker: bool) {
        if xai_grok_shell::compat::oauth::has_flow(&provider_id) {
            self.step = VendorLoginStep::Method {
                provider_id,
                provider_name,
                selected: 0,
                from_picker,
            };
            self.editor.reset();
            self.error = None;
            self.probing = false;
            self.row_map.clear();
            return;
        }
        self.enter_key_form(provider_id, provider_name, from_picker);
    }

    fn enter_key_form(&mut self, provider_id: String, provider_name: String, from_picker: bool) {
        let requires_auth = xai_grok_shell::compat::provider_by_id(&provider_id)
            .map(|p| p.requires_auth)
            .unwrap_or(true);
        self.step = VendorLoginStep::Key {
            provider_id,
            provider_name,
            requires_auth,
            from_picker,
        };
        self.editor.reset();
        self.error = None;
        self.probing = false;
        self.row_map.clear();
    }

    fn back_to_picker(&mut self) {
        self.step = VendorLoginStep::Pick {
            selected: 0,
            scroll: 0,
        };
        self.editor.reset();
        self.error = None;
        self.probing = false;
    }

    pub(crate) fn back_from_oauth(&mut self) {
        let (provider_id, provider_name, from_picker) = match &self.step {
            VendorLoginStep::OAuthWait {
                provider_id,
                provider_name,
                from_picker,
                ..
            } => (provider_id.clone(), provider_name.clone(), *from_picker),
            _ => return,
        };
        self.enter_provider(provider_id, provider_name, from_picker);
    }
}

#[derive(Debug)]
pub(crate) enum VendorLoginOutcome {
    Unchanged,
    Changed,
    Submit {
        provider_id: String,
        key: String,
    },
    StartOAuth {
        provider_id: String,
    },
    SubmitOAuthCode {
        provider_id: String,
        code: String,
    },
    SyncCustom {
        name: String,
        base_url: String,
        api_backend: String,
        auth_scheme: String,
        key: String,
    },
    SaveCustom {
        provider_id: Option<String>,
        name: String,
        base_url: String,
        api_backend: String,
        auth_scheme: String,
        key: String,
        models: Vec<xai_grok_shell::compat::custom::CustomModel>,
    },
    /// Re-fetch live `/models` for signed-in vendors (builtin cache + custom).
    RefreshCatalog,
    Close,
}

struct ProviderRow {
    id: String,
    name: String,
    status: String,
}

fn provider_rows() -> Vec<ProviderRow> {
    let mut rows: Vec<ProviderRow> = xai_grok_shell::compat::arg_items()
        .into_iter()
        .map(|(id, name, desc)| {
            let status = desc.rsplit(" · ").next().unwrap_or("").to_owned();
            ProviderRow { id, name, status }
        })
        .collect();
    rows.push(ProviderRow {
        id: ADD_CUSTOM_ID.into(),
        name: "+ Add custom provider".into(),
        status: "name · URL · protocol · key".into(),
    });
    rows
}

fn modal_config<'a>(
    title: &'a str,
    shortcuts: &'a [Shortcut<'a>],
    compact: bool,
) -> ModalWindowConfig<'a> {
    ModalWindowConfig {
        title,
        tabs: None,
        shortcuts,
        sizing: ModalSizing::medium().with_compact(compact),
        fold_info: None,
    }
}

fn pick_shortcuts() -> [Shortcut<'static>; 3] {
    [
        Shortcut {
            label: "Enter select",
            clickable: true,
            id: SHORTCUT_SUBMIT,
        },
        Shortcut {
            label: "r refresh",
            clickable: true,
            id: SHORTCUT_REFRESH,
        },
        Shortcut {
            label: "Esc cancel",
            clickable: true,
            id: SHORTCUT_CANCEL,
        },
    ]
}

fn key_shortcuts(from_picker: bool, probing: bool, requires_auth: bool) -> [Shortcut<'static>; 2] {
    let submit = if probing {
        "…"
    } else if requires_auth {
        "Enter verify"
    } else {
        "Enter connect"
    };
    let cancel = if from_picker && !probing {
        "Esc back"
    } else {
        "Esc cancel"
    };
    [
        Shortcut {
            label: submit,
            clickable: !probing,
            id: SHORTCUT_SUBMIT,
        },
        Shortcut {
            label: cancel,
            clickable: true,
            id: SHORTCUT_CANCEL,
        },
    ]
}

fn step_shortcuts(state: &VendorLoginState) -> Vec<Shortcut<'static>> {
    match &state.step {
        VendorLoginStep::Key {
            from_picker,
            requires_auth,
            ..
        } => {
            let [submit, cancel] = key_shortcuts(*from_picker, state.probing, *requires_auth);
            vec![submit, cancel]
        }
        VendorLoginStep::CustomForm => vec![
            Shortcut {
                label: if state.probing { "…" } else { "Enter sync" },
                clickable: !state.probing,
                id: SHORTCUT_SUBMIT,
            },
            Shortcut {
                label: "^Enter skip",
                clickable: !state.probing,
                id: SHORTCUT_SKIP_SYNC,
            },
            Shortcut {
                label: "Esc back",
                clickable: true,
                id: SHORTCUT_CANCEL,
            },
        ],
        VendorLoginStep::CustomModels if state.add_model.is_some() => vec![
            Shortcut {
                label: "Enter add",
                clickable: true,
                id: SHORTCUT_SUBMIT,
            },
            Shortcut {
                label: "Space reasoning",
                clickable: true,
                id: SHORTCUT_TOGGLE_REASONING,
            },
            Shortcut {
                label: "Esc back",
                clickable: true,
                id: SHORTCUT_CANCEL,
            },
        ],
        VendorLoginStep::CustomModels => vec![
            Shortcut {
                label: if state.probing { "…" } else { "Enter save" },
                clickable: !state.probing,
                id: SHORTCUT_SUBMIT,
            },
            Shortcut {
                label: if state.probing { "…" } else { "^R refresh" },
                clickable: !state.probing,
                id: SHORTCUT_REFRESH,
            },
            Shortcut {
                label: "i add",
                clickable: !state.probing,
                id: SHORTCUT_ADD,
            },
            Shortcut {
                label: "^A all",
                clickable: !state.probing,
                id: SHORTCUT_SELECT_ALL,
            },
            Shortcut {
                label: "^N none",
                clickable: !state.probing,
                id: SHORTCUT_SELECT_NONE,
            },
            Shortcut {
                label: "/ find",
                clickable: !state.probing,
                id: SHORTCUT_SEARCH,
            },
            Shortcut {
                label: "Esc back",
                clickable: true,
                id: SHORTCUT_CANCEL,
            },
        ],
        VendorLoginStep::Pick { .. } => {
            let [submit, refresh, cancel] = pick_shortcuts();
            vec![submit, refresh, cancel]
        }
        _ => {
            let [submit, _, cancel] = pick_shortcuts();
            vec![submit, cancel]
        }
    }
}

pub(crate) fn handle_vendor_login_key(
    state: &mut VendorLoginState,
    key: &KeyEvent,
) -> VendorLoginOutcome {
    if key.kind == KeyEventKind::Release {
        return VendorLoginOutcome::Unchanged;
    }

    if state.probing {
        return if matches!(key.code, KeyCode::Esc) {
            VendorLoginOutcome::Close
        } else {
            VendorLoginOutcome::Unchanged
        };
    }

    if matches!(key.code, KeyCode::Esc) {
        if state.add_model.is_some() {
            state.add_model = None;
            state.error = None;
            return VendorLoginOutcome::Changed;
        }
        if state.context_edit.is_some() {
            state.context_edit = None;
            state.error = None;
            return VendorLoginOutcome::Changed;
        }
        match &state.step {
            VendorLoginStep::Key {
                from_picker: true, ..
            }
            | VendorLoginStep::Method {
                from_picker: true, ..
            } => {
                state.back_to_picker();
                return VendorLoginOutcome::Changed;
            }
            VendorLoginStep::OAuthWait { .. } => {
                state.back_from_oauth();
                return VendorLoginOutcome::Changed;
            }
            VendorLoginStep::CustomModels => {
                if let Some(draft) = state.custom.as_mut()
                    && draft.search_focused
                {
                    if !draft.search.text().is_empty() {
                        draft.search.reset();
                        draft.clamp_selection_to_filter();
                    } else {
                        draft.search_focused = false;
                    }
                    return VendorLoginOutcome::Changed;
                }
                state.step = VendorLoginStep::CustomForm;
                state.error = None;
                return VendorLoginOutcome::Changed;
            }
            VendorLoginStep::CustomForm => {
                state.custom = None;
                state.back_to_picker();
                return VendorLoginOutcome::Changed;
            }
            VendorLoginStep::Method {
                from_picker: false, ..
            } => {
                return VendorLoginOutcome::Close;
            }
            _ => {}
        }
    }

    let title = title_for(state);
    let shortcuts = step_shortcuts(state);
    let config = modal_config(&title, &shortcuts, false);
    match handle_modal_key(&mut state.window, key, &config) {
        ModalWindowOutcome::CloseRequested => return VendorLoginOutcome::Close,
        ModalWindowOutcome::Handled => return VendorLoginOutcome::Changed,
        _ => {}
    }

    match &state.step {
        VendorLoginStep::Pick { .. } => handle_pick_key(state, key),
        VendorLoginStep::Method { .. } => handle_method_key(state, key),
        VendorLoginStep::OAuthWait { .. } => handle_oauth_wait_key(state, key),
        VendorLoginStep::Key { .. } => handle_key_form_key(state, key),
        VendorLoginStep::CustomForm => handle_custom_form_key(state, key),
        VendorLoginStep::CustomModels => handle_custom_models_key(state, key),
    }
}

fn method_rows(provider_id: &str) -> Vec<(String, String)> {
    let mut rows = Vec::new();
    if let Some(label) = xai_grok_shell::compat::oauth::login_label(provider_id) {
        rows.push(("oauth".into(), label.to_owned()));
    }
    rows.push(("api_key".into(), "API key".into()));
    rows
}

fn handle_method_key(state: &mut VendorLoginState, key: &KeyEvent) -> VendorLoginOutcome {
    if matches!(key.code, KeyCode::Enter) {
        return confirm_method(state);
    }
    let VendorLoginStep::Method {
        provider_id,
        selected,
        ..
    } = &mut state.step
    else {
        return VendorLoginOutcome::Unchanged;
    };
    let last = method_rows(provider_id).len().saturating_sub(1);
    match key.code {
        KeyCode::Up | KeyCode::Char('k') => {
            if *selected > 0 {
                *selected -= 1;
                VendorLoginOutcome::Changed
            } else {
                VendorLoginOutcome::Unchanged
            }
        }
        KeyCode::Down | KeyCode::Char('j') => {
            if *selected < last {
                *selected += 1;
                VendorLoginOutcome::Changed
            } else {
                VendorLoginOutcome::Unchanged
            }
        }
        _ => VendorLoginOutcome::Unchanged,
    }
}

fn handle_oauth_wait_key(state: &mut VendorLoginState, key: &KeyEvent) -> VendorLoginOutcome {
    if matches!(key.code, KeyCode::Enter) {
        return submit_oauth_code(state);
    }
    match state.editor.handle_key(key) {
        LineEditOutcome::Unhandled | LineEditOutcome::HandledNoChange => {
            VendorLoginOutcome::Unchanged
        }
        _ => VendorLoginOutcome::Changed,
    }
}

fn handle_pick_key(state: &mut VendorLoginState, key: &KeyEvent) -> VendorLoginOutcome {
    if matches!(key.code, KeyCode::Enter) {
        return confirm_pick(state);
    }
    if matches!(key.code, KeyCode::Char('r') | KeyCode::Char('R')) {
        return VendorLoginOutcome::RefreshCatalog;
    }
    let VendorLoginStep::Pick { selected, scroll } = &mut state.step else {
        return VendorLoginOutcome::Unchanged;
    };
    match key.code {
        KeyCode::Up | KeyCode::Char('k') => {
            if *selected > 0 {
                *selected -= 1;
                if *selected < *scroll {
                    *scroll = *selected;
                }
                VendorLoginOutcome::Changed
            } else {
                VendorLoginOutcome::Unchanged
            }
        }
        KeyCode::Down | KeyCode::Char('j') => {
            let last = provider_rows().len().saturating_sub(1);
            if *selected < last {
                *selected += 1;
                VendorLoginOutcome::Changed
            } else {
                VendorLoginOutcome::Unchanged
            }
        }
        _ => VendorLoginOutcome::Unchanged,
    }
}

fn handle_key_form_key(state: &mut VendorLoginState, key: &KeyEvent) -> VendorLoginOutcome {
    if matches!(key.code, KeyCode::Enter) {
        return submit_key(state);
    }
    match state.editor.handle_key(key) {
        LineEditOutcome::Unhandled | LineEditOutcome::HandledNoChange => {
            VendorLoginOutcome::Unchanged
        }
        _ => {
            state.error = None;
            VendorLoginOutcome::Changed
        }
    }
}

pub(crate) fn handle_vendor_login_paste(
    state: &mut VendorLoginState,
    text: &str,
) -> VendorLoginOutcome {
    if state.probing
        || matches!(
            state.step,
            VendorLoginStep::Pick { .. } | VendorLoginStep::Method { .. }
        )
    {
        return VendorLoginOutcome::Unchanged;
    }
    if matches!(state.step, VendorLoginStep::CustomModels) {
        if let Some(editor) = state.context_edit.as_mut() {
            match editor.insert_paste(text) {
                LineEditOutcome::Unhandled | LineEditOutcome::HandledNoChange => {
                    return VendorLoginOutcome::Unchanged;
                }
                _ => {
                    state.error = None;
                    return VendorLoginOutcome::Changed;
                }
            }
        }
        if let Some(add) = state.add_model.as_mut() {
            if add.field == AddModelField::Context && !add.context_touched {
                add.context_text.reset();
            }
            let Some(editor) = add.active_editor_mut() else {
                return VendorLoginOutcome::Unchanged;
            };
            match editor.insert_paste(text) {
                LineEditOutcome::Unhandled | LineEditOutcome::HandledNoChange => {
                    return VendorLoginOutcome::Unchanged;
                }
                _ => {
                    if add.field == AddModelField::ApiModel {
                        add.refresh_suggestion();
                    }
                    if add.field == AddModelField::Context {
                        add.context_touched = true;
                    }
                    add.error = None;
                    return VendorLoginOutcome::Changed;
                }
            }
        }
        let pasted = state.custom.as_mut().and_then(|draft| {
            if !draft.search_focused {
                return None;
            }
            Some(draft.search.insert_paste(text))
        });
        if pasted.is_some() {
            if let Some(draft) = state.custom.as_mut() {
                draft.clamp_selection_to_filter();
            }
            return VendorLoginOutcome::Changed;
        }
        return VendorLoginOutcome::Unchanged;
    }
    if matches!(state.step, VendorLoginStep::CustomForm) {
        let pasted = state
            .custom
            .as_mut()
            .and_then(|d| d.active_editor_mut())
            .map(|editor| editor.insert_paste(text));
        if pasted.is_some() {
            state.error = None;
            return VendorLoginOutcome::Changed;
        }
        return VendorLoginOutcome::Unchanged;
    }
    match state.editor.insert_paste(text) {
        LineEditOutcome::Unhandled | LineEditOutcome::HandledNoChange => {
            VendorLoginOutcome::Unchanged
        }
        _ => {
            state.error = None;
            VendorLoginOutcome::Changed
        }
    }
}

pub(crate) fn handle_vendor_login_mouse(
    state: &mut VendorLoginState,
    kind: MouseEventKind,
    column: u16,
    row: u16,
) -> VendorLoginOutcome {
    let chrome = handle_modal_mouse(&mut state.window, kind, column, row);
    match chrome {
        ModalWindowOutcome::CloseRequested => return VendorLoginOutcome::Close,
        ModalWindowOutcome::ShortcutActivated(SHORTCUT_CANCEL) => {
            if state.add_model.is_some() {
                state.add_model = None;
                state.error = None;
                return VendorLoginOutcome::Changed;
            }
            if state.context_edit.is_some() {
                state.context_edit = None;
                state.error = None;
                return VendorLoginOutcome::Changed;
            }
            if !state.probing {
                match &state.step {
                    VendorLoginStep::Key {
                        from_picker: true, ..
                    }
                    | VendorLoginStep::Method {
                        from_picker: true, ..
                    } => {
                        state.back_to_picker();
                        return VendorLoginOutcome::Changed;
                    }
                    VendorLoginStep::OAuthWait { .. } => {
                        state.back_from_oauth();
                        return VendorLoginOutcome::Changed;
                    }
                    VendorLoginStep::CustomModels => {
                        if let Some(draft) = state.custom.as_mut()
                            && draft.search_focused
                        {
                            if !draft.search.text().is_empty() {
                                draft.search.reset();
                                draft.clamp_selection_to_filter();
                            } else {
                                draft.search_focused = false;
                            }
                            return VendorLoginOutcome::Changed;
                        }
                        state.step = VendorLoginStep::CustomForm;
                        return VendorLoginOutcome::Changed;
                    }
                    VendorLoginStep::CustomForm => {
                        state.custom = None;
                        state.back_to_picker();
                        return VendorLoginOutcome::Changed;
                    }
                    _ => {}
                }
            }
            return VendorLoginOutcome::Close;
        }
        ModalWindowOutcome::ShortcutActivated(SHORTCUT_SUBMIT) => {
            if state.probing {
                return VendorLoginOutcome::Unchanged;
            }
            return match &state.step {
                VendorLoginStep::Pick { .. } => confirm_pick(state),
                VendorLoginStep::Method { .. } => confirm_method(state),
                VendorLoginStep::Key { .. } => submit_key(state),
                VendorLoginStep::OAuthWait { .. } => submit_oauth_code(state),
                VendorLoginStep::CustomForm => submit_custom_sync(state),
                VendorLoginStep::CustomModels if state.add_model.is_some() => {
                    commit_add_model(state)
                }
                VendorLoginStep::CustomModels => submit_custom_save(state),
            };
        }
        ModalWindowOutcome::ShortcutActivated(SHORTCUT_REFRESH) => {
            if state.probing {
                return VendorLoginOutcome::Unchanged;
            }
            return match &state.step {
                VendorLoginStep::Pick { .. } => VendorLoginOutcome::RefreshCatalog,
                VendorLoginStep::CustomModels if state.add_model.is_none() => {
                    submit_custom_sync(state)
                }
                _ => VendorLoginOutcome::Unchanged,
            };
        }
        ModalWindowOutcome::ShortcutActivated(SHORTCUT_ADD) => {
            if state.probing {
                return VendorLoginOutcome::Unchanged;
            }
            return open_add_model(state);
        }
        ModalWindowOutcome::ShortcutActivated(SHORTCUT_SKIP_SYNC) => {
            if state.probing {
                return VendorLoginOutcome::Unchanged;
            }
            return skip_to_custom_models(state);
        }
        ModalWindowOutcome::ShortcutActivated(SHORTCUT_TOGGLE_REASONING) => {
            if let Some(add) = state.add_model.as_mut() {
                add.supports_reasoning_effort = !add.supports_reasoning_effort;
                add.reasoning_touched = true;
                add.field = AddModelField::Reasoning;
                return VendorLoginOutcome::Changed;
            }
            return toggle_selected_reasoning(state);
        }
        ModalWindowOutcome::ShortcutActivated(SHORTCUT_SELECT_ALL) => {
            if state.probing {
                return VendorLoginOutcome::Unchanged;
            }
            if let Some(draft) = state.custom.as_mut() {
                draft.set_filtered_enabled(true);
                return VendorLoginOutcome::Changed;
            }
            return VendorLoginOutcome::Unchanged;
        }
        ModalWindowOutcome::ShortcutActivated(SHORTCUT_SELECT_NONE) => {
            if state.probing {
                return VendorLoginOutcome::Unchanged;
            }
            if let Some(draft) = state.custom.as_mut() {
                draft.set_filtered_enabled(false);
                return VendorLoginOutcome::Changed;
            }
            return VendorLoginOutcome::Unchanged;
        }
        ModalWindowOutcome::ShortcutActivated(SHORTCUT_SEARCH) => {
            if state.probing {
                return VendorLoginOutcome::Unchanged;
            }
            if let Some(draft) = state.custom.as_mut() {
                draft.search_focused = true;
                return VendorLoginOutcome::Changed;
            }
            return VendorLoginOutcome::Unchanged;
        }
        ModalWindowOutcome::Handled => return VendorLoginOutcome::Changed,
        _ => {}
    }

    if state.probing {
        return VendorLoginOutcome::Unchanged;
    }

    let Some(area) = state.content_area else {
        return VendorLoginOutcome::Unchanged;
    };
    let in_content = column >= area.x
        && column < area.x + area.width
        && row >= area.y
        && row < area.y + area.height;

    if state.add_model.is_some() {
        return VendorLoginOutcome::Unchanged;
    }

    if matches!(kind, MouseEventKind::Down(MouseButton::Left)) && in_content {
        if matches!(state.step, VendorLoginStep::CustomModels) && row == area.y {
            if let Some(draft) = state.custom.as_mut() {
                draft.search_focused = true;
                return VendorLoginOutcome::Changed;
            }
        }
        if let Some(&(_, idx)) = state.row_map.iter().find(|(y, _)| *y == row) {
            if matches!(state.step, VendorLoginStep::Pick { .. }) {
                if let VendorLoginStep::Pick { selected, .. } = &mut state.step {
                    *selected = idx;
                }
                return confirm_pick(state);
            }
            if matches!(state.step, VendorLoginStep::Method { .. }) {
                if let VendorLoginStep::Method { selected, .. } = &mut state.step {
                    *selected = idx;
                }
                return confirm_method(state);
            }
            if matches!(state.step, VendorLoginStep::CustomModels) {
                if let Some(draft) = state.custom.as_mut() {
                    draft.search_focused = false;
                    draft.selected = idx;
                    if let Some(row) = draft.models.get_mut(idx) {
                        row.enabled = !row.enabled;
                    }
                    return VendorLoginOutcome::Changed;
                }
            }
        }
        if matches!(state.step, VendorLoginStep::CustomForm)
            && let Some(draft) = state.custom.as_mut()
        {
            let idx = row.saturating_sub(area.y) / 2;
            draft.field = match idx {
                0 => CustomField::Name,
                1 => CustomField::BaseUrl,
                2 => CustomField::Protocol,
                3 => CustomField::Key,
                _ => return VendorLoginOutcome::Unchanged,
            };
            if draft.field == CustomField::Protocol {
                draft.protocol = (draft.protocol + 1) % PROTOCOLS.len();
            }
            return VendorLoginOutcome::Changed;
        }
        return VendorLoginOutcome::Unchanged;
    }

    if let VendorLoginStep::Method { selected, .. } = &mut state.step {
        if matches!(kind, MouseEventKind::Moved) && in_content {
            if let Some(&(_, idx)) = state.row_map.iter().find(|(y, _)| *y == row) {
                if *selected != idx {
                    *selected = idx;
                    return VendorLoginOutcome::Changed;
                }
            }
        }
        return VendorLoginOutcome::Unchanged;
    }

    if matches!(state.step, VendorLoginStep::CustomModels) {
        if matches!(kind, MouseEventKind::Moved) && in_content {
            if let Some(&(_, idx)) = state.row_map.iter().find(|(y, _)| *y == row)
                && let Some(draft) = state.custom.as_mut()
                && draft.selected != idx
            {
                draft.selected = idx;
                return VendorLoginOutcome::Changed;
            }
        }
        return VendorLoginOutcome::Unchanged;
    }

    let VendorLoginStep::Pick { selected, scroll } = &mut state.step else {
        return VendorLoginOutcome::Unchanged;
    };
    match kind {
        MouseEventKind::Moved if in_content => {
            if let Some(&(_, idx)) = state.row_map.iter().find(|(y, _)| *y == row) {
                if *selected != idx {
                    *selected = idx;
                    return VendorLoginOutcome::Changed;
                }
            }
            VendorLoginOutcome::Unchanged
        }
        MouseEventKind::ScrollUp if in_content => {
            if *selected > 0 {
                *selected -= 1;
                if *selected < *scroll {
                    *scroll = *selected;
                }
                VendorLoginOutcome::Changed
            } else {
                VendorLoginOutcome::Unchanged
            }
        }
        MouseEventKind::ScrollDown if in_content => {
            let last = provider_rows().len().saturating_sub(1);
            if *selected < last {
                *selected += 1;
                VendorLoginOutcome::Changed
            } else {
                VendorLoginOutcome::Unchanged
            }
        }
        _ => VendorLoginOutcome::Unchanged,
    }
}

fn confirm_pick(state: &mut VendorLoginState) -> VendorLoginOutcome {
    let selected = match &state.step {
        VendorLoginStep::Pick { selected, .. } => *selected,
        _ => return VendorLoginOutcome::Unchanged,
    };
    let rows = provider_rows();
    let Some(row) = rows.get(selected) else {
        return VendorLoginOutcome::Unchanged;
    };
    let id = row.id.clone();
    let name = row.name.clone();
    if id == ADD_CUSTOM_ID {
        state.enter_custom_form();
        return VendorLoginOutcome::Changed;
    }
    if xai_grok_shell::compat::custom::get_provider(&id).is_some() {
        state.enter_custom_edit(&id);
        return VendorLoginOutcome::Changed;
    }
    state.enter_provider(id, name, true);
    VendorLoginOutcome::Changed
}

fn handle_custom_form_key(state: &mut VendorLoginState, key: &KeyEvent) -> VendorLoginOutcome {
    if matches!(key.code, KeyCode::Enter) {
        if key.modifiers.contains(KeyModifiers::CONTROL) {
            return skip_to_custom_models(state);
        }
        return submit_custom_sync(state);
    }
    let outcome = {
        let Some(draft) = state.custom.as_mut() else {
            return VendorLoginOutcome::Unchanged;
        };
        match key.code {
            KeyCode::Tab | KeyCode::Down => {
                draft.cycle_field(true);
                VendorLoginOutcome::Changed
            }
            KeyCode::BackTab | KeyCode::Up => {
                draft.cycle_field(false);
                VendorLoginOutcome::Changed
            }
            KeyCode::Left if draft.field == CustomField::Protocol => {
                if draft.protocol > 0 {
                    draft.protocol -= 1;
                } else {
                    draft.protocol = PROTOCOLS.len() - 1;
                }
                VendorLoginOutcome::Changed
            }
            KeyCode::Right if draft.field == CustomField::Protocol => {
                draft.protocol = (draft.protocol + 1) % PROTOCOLS.len();
                VendorLoginOutcome::Changed
            }
            _ => {
                if let Some(editor) = draft.active_editor_mut() {
                    match editor.handle_key(key) {
                        LineEditOutcome::Unhandled | LineEditOutcome::HandledNoChange => {
                            VendorLoginOutcome::Unchanged
                        }
                        _ => VendorLoginOutcome::Changed,
                    }
                } else {
                    VendorLoginOutcome::Unchanged
                }
            }
        }
    };
    if matches!(outcome, VendorLoginOutcome::Changed) {
        state.error = None;
    }
    outcome
}

fn handle_custom_models_key(state: &mut VendorLoginState, key: &KeyEvent) -> VendorLoginOutcome {
    if state.add_model.is_some() {
        return handle_add_model_key(state, key);
    }
    if state.context_edit.is_some() {
        return handle_context_edit_key(state, key);
    }
    if key.modifiers.contains(KeyModifiers::CONTROL) {
        match key.code {
            KeyCode::Char('a') | KeyCode::Char('A') => {
                if let Some(draft) = state.custom.as_mut() {
                    draft.set_filtered_enabled(true);
                    return VendorLoginOutcome::Changed;
                }
            }
            KeyCode::Char('n') | KeyCode::Char('N') => {
                if let Some(draft) = state.custom.as_mut() {
                    draft.set_filtered_enabled(false);
                    return VendorLoginOutcome::Changed;
                }
            }
            KeyCode::Char('r') | KeyCode::Char('R') => {
                if state.add_model.is_none() {
                    return submit_custom_sync(state);
                }
            }
            _ => {}
        }
    }

    let search_focused = state.custom.as_ref().is_some_and(|d| d.search_focused);

    if search_focused {
        match key.code {
            KeyCode::Enter | KeyCode::Down | KeyCode::Tab => {
                if let Some(draft) = state.custom.as_mut() {
                    draft.search_focused = false;
                    draft.clamp_selection_to_filter();
                }
                return VendorLoginOutcome::Changed;
            }
            _ => {
                let outcome = {
                    let Some(draft) = state.custom.as_mut() else {
                        return VendorLoginOutcome::Unchanged;
                    };
                    match draft.search.handle_key(key) {
                        LineEditOutcome::Unhandled | LineEditOutcome::HandledNoChange => {
                            VendorLoginOutcome::Unchanged
                        }
                        _ => {
                            draft.clamp_selection_to_filter();
                            VendorLoginOutcome::Changed
                        }
                    }
                };
                return outcome;
            }
        }
    }

    if matches!(key.code, KeyCode::Enter) {
        return submit_custom_save(state);
    }
    if matches!(key.code, KeyCode::Char('i') | KeyCode::Char('+')) {
        return open_add_model(state);
    }
    if matches!(key.code, KeyCode::Char('r')) {
        return toggle_selected_reasoning(state);
    }
    if matches!(key.code, KeyCode::Char('[') | KeyCode::Char(']')) {
        return cycle_selected_context(state, matches!(key.code, KeyCode::Char(']')));
    }
    if matches!(key.code, KeyCode::Char('c')) {
        return start_context_edit(state);
    }
    if matches!(key.code, KeyCode::Char('t')) {
        return cycle_selected_threshold(state, true);
    }
    let Some(draft) = state.custom.as_mut() else {
        return VendorLoginOutcome::Unchanged;
    };
    match key.code {
        KeyCode::Char('/') | KeyCode::Tab => {
            draft.search_focused = true;
            VendorLoginOutcome::Changed
        }
        KeyCode::Up | KeyCode::Char('k') => {
            if draft.move_selection(-1) {
                VendorLoginOutcome::Changed
            } else {
                VendorLoginOutcome::Unchanged
            }
        }
        KeyCode::Down | KeyCode::Char('j') => {
            if draft.move_selection(1) {
                VendorLoginOutcome::Changed
            } else {
                VendorLoginOutcome::Unchanged
            }
        }
        KeyCode::Char(' ') => {
            if let Some(row) = draft.models.get_mut(draft.selected) {
                row.enabled = !row.enabled;
                VendorLoginOutcome::Changed
            } else {
                VendorLoginOutcome::Unchanged
            }
        }
        KeyCode::Char('a') => {
            draft.set_filtered_enabled(true);
            VendorLoginOutcome::Changed
        }
        KeyCode::Char('n') => {
            draft.set_filtered_enabled(false);
            VendorLoginOutcome::Changed
        }
        _ => VendorLoginOutcome::Unchanged,
    }
}

fn submit_custom_sync(state: &mut VendorLoginState) -> VendorLoginOutcome {
    let Some(draft) = state.custom.as_ref() else {
        return VendorLoginOutcome::Unchanged;
    };
    let name = draft.name.text().trim().to_owned();
    let base_url = draft.base_url.text().trim().to_owned();
    let mut key = draft.key.text().trim().to_owned();
    if key.is_empty()
        && let Some(id) = draft.id.as_deref()
        && let Some(stored) = xai_grok_shell::compat::custom::stored_secret(id)
    {
        key = stored;
    }
    if name.is_empty() || base_url.len() < 8 {
        state.error = Some("Name and base URL are required".into());
        return VendorLoginOutcome::Changed;
    }
    let api_backend = PROTOCOLS[draft.protocol].to_owned();
    let auth_scheme = if api_backend == "messages" {
        "x-api-key".to_owned()
    } else {
        "bearer".to_owned()
    };
    state.probing = true;
    state.error = None;
    VendorLoginOutcome::SyncCustom {
        name,
        base_url,
        api_backend,
        auth_scheme,
        key,
    }
}

fn skip_to_custom_models(state: &mut VendorLoginState) -> VendorLoginOutcome {
    let Some(draft) = state.custom.as_ref() else {
        return VendorLoginOutcome::Unchanged;
    };
    let name = draft.name.text().trim().to_owned();
    let base_url = draft.base_url.text().trim().to_owned();
    if name.is_empty() || base_url.len() < 8 {
        state.error = Some("Name and base URL are required".into());
        return VendorLoginOutcome::Changed;
    }
    state.probing = false;
    state.error = None;
    state.add_model = None;
    state.step = VendorLoginStep::CustomModels;
    VendorLoginOutcome::Changed
}

fn open_add_model(state: &mut VendorLoginState) -> VendorLoginOutcome {
    if !matches!(state.step, VendorLoginStep::CustomModels) {
        return VendorLoginOutcome::Unchanged;
    }
    if state.custom.is_none() {
        return VendorLoginOutcome::Unchanged;
    }
    state.add_model = Some(AddModelDraft::new());
    state.error = None;
    VendorLoginOutcome::Changed
}

fn start_context_edit(state: &mut VendorLoginState) -> VendorLoginOutcome {
    let Some(draft) = state.custom.as_ref() else {
        return VendorLoginOutcome::Unchanged;
    };
    let Some(row) = draft.models.get(draft.selected) else {
        return VendorLoginOutcome::Unchanged;
    };
    let _ = row;
    state.context_edit = Some(LineEditor::default());
    state.error = None;
    VendorLoginOutcome::Changed
}

fn handle_context_edit_key(state: &mut VendorLoginState, key: &KeyEvent) -> VendorLoginOutcome {
    if matches!(key.code, KeyCode::Enter) {
        return commit_context_edit(state);
    }
    let Some(editor) = state.context_edit.as_mut() else {
        return VendorLoginOutcome::Unchanged;
    };
    match editor.handle_key(key) {
        LineEditOutcome::Unhandled | LineEditOutcome::HandledNoChange => {
            VendorLoginOutcome::Unchanged
        }
        _ => {
            state.error = None;
            VendorLoginOutcome::Changed
        }
    }
}

fn commit_context_edit(state: &mut VendorLoginState) -> VendorLoginOutcome {
    let raw = state
        .context_edit
        .as_ref()
        .map(|e| e.text().trim().to_owned())
        .unwrap_or_default();
    let Some(draft) = state.custom.as_mut() else {
        return VendorLoginOutcome::Unchanged;
    };
    let Some(row) = draft.models.get_mut(draft.selected) else {
        return VendorLoginOutcome::Unchanged;
    };
    let advertised = row.advertised_window();
    let Some(parsed) = xai_grok_shell::context_window::parse_window_arg(&raw, advertised) else {
        state.error = Some(format!("Use 256k, 1M, or 1.05M (got '{raw}')"));
        return VendorLoginOutcome::Changed;
    };
    row.context_window = match row.provider_cap() {
        Some(cap) => parsed.min(cap).max(1),
        None => parsed.max(1),
    };
    state.context_edit = None;
    state.error = None;
    VendorLoginOutcome::Changed
}

fn cycle_selected_context(state: &mut VendorLoginState, forward: bool) -> VendorLoginOutcome {
    let Some(draft) = state.custom.as_mut() else {
        return VendorLoginOutcome::Unchanged;
    };
    let Some(row) = draft.models.get_mut(draft.selected) else {
        return VendorLoginOutcome::Unchanged;
    };
    let max = row.advertised_window();
    row.context_window =
        xai_grok_shell::context_window::cycle_gear(row.context_window, max, forward);
    VendorLoginOutcome::Changed
}

fn cycle_selected_threshold(state: &mut VendorLoginState, forward: bool) -> VendorLoginOutcome {
    let Some(draft) = state.custom.as_mut() else {
        return VendorLoginOutcome::Unchanged;
    };
    let Some(row) = draft.models.get_mut(draft.selected) else {
        return VendorLoginOutcome::Unchanged;
    };
    row.auto_compact_threshold_percent = xai_grok_shell::context_window::cycle_threshold(
        row.auto_compact_threshold_percent,
        forward,
    );
    VendorLoginOutcome::Changed
}

fn toggle_selected_reasoning(state: &mut VendorLoginState) -> VendorLoginOutcome {
    let Some(draft) = state.custom.as_mut() else {
        return VendorLoginOutcome::Unchanged;
    };
    let Some(row) = draft.models.get_mut(draft.selected) else {
        return VendorLoginOutcome::Unchanged;
    };
    row.supports_reasoning_effort = !row.supports_reasoning_effort;
    VendorLoginOutcome::Changed
}

fn handle_add_model_key(state: &mut VendorLoginState, key: &KeyEvent) -> VendorLoginOutcome {
    if matches!(key.code, KeyCode::Enter) {
        return commit_add_model(state);
    }
    let Some(add) = state.add_model.as_mut() else {
        return VendorLoginOutcome::Unchanged;
    };
    match key.code {
        KeyCode::Tab | KeyCode::Down => {
            add.cycle_field(true);
            VendorLoginOutcome::Changed
        }
        KeyCode::BackTab | KeyCode::Up => {
            add.cycle_field(false);
            VendorLoginOutcome::Changed
        }
        KeyCode::Char(' ') if add.field == AddModelField::Reasoning => {
            add.supports_reasoning_effort = !add.supports_reasoning_effort;
            add.reasoning_touched = true;
            VendorLoginOutcome::Changed
        }
        KeyCode::Left | KeyCode::Right if add.field == AddModelField::Reasoning => {
            add.supports_reasoning_effort = !add.supports_reasoning_effort;
            add.reasoning_touched = true;
            VendorLoginOutcome::Changed
        }
        KeyCode::Left | KeyCode::Right if add.field == AddModelField::Threshold => {
            let forward = matches!(key.code, KeyCode::Right);
            add.auto_compact_threshold_percent = xai_grok_shell::context_window::cycle_threshold(
                add.auto_compact_threshold_percent,
                forward,
            );
            VendorLoginOutcome::Changed
        }
        KeyCode::Char('[') | KeyCode::Char(']') if add.field == AddModelField::Context => {
            if let Ok(tokens) = add.parsed_context_window() {
                add.context_window = tokens;
            }
            let max = if add.matched {
                add.advertised_context_window.max(1)
            } else {
                add.context_window.max(1)
            };
            add.set_context_window(xai_grok_shell::context_window::cycle_gear(
                add.context_window,
                max,
                matches!(key.code, KeyCode::Char(']')),
            ));
            add.context_touched = true;
            VendorLoginOutcome::Changed
        }
        _ => {
            let on_id = add.field == AddModelField::ApiModel;
            let on_ctx = add.field == AddModelField::Context;
            if on_ctx && !add.context_touched {
                add.context_text.reset();
            }
            let changed = match add.active_editor_mut() {
                Some(editor) => !matches!(
                    editor.handle_key(key),
                    LineEditOutcome::Unhandled | LineEditOutcome::HandledNoChange
                ),
                None => return VendorLoginOutcome::Unchanged,
            };
            if !changed {
                return VendorLoginOutcome::Unchanged;
            }
            if on_id {
                add.refresh_suggestion();
            }
            if on_ctx {
                add.context_touched = true;
            }
            add.error = None;
            VendorLoginOutcome::Changed
        }
    }
}

fn commit_add_model(state: &mut VendorLoginState) -> VendorLoginOutcome {
    let parsed = {
        let Some(add) = state.add_model.as_ref() else {
            return VendorLoginOutcome::Unchanged;
        };
        add.parsed_context_window()
    };
    let context_window = match parsed {
        Ok(tokens) => tokens,
        Err(err) => {
            if let Some(add) = state.add_model.as_mut() {
                add.error = Some(err);
            }
            return VendorLoginOutcome::Changed;
        }
    };
    let (api_model, name, advertised, matched, supports_reasoning_effort, threshold) = {
        let Some(add) = state.add_model.as_ref() else {
            return VendorLoginOutcome::Unchanged;
        };
        (
            add.api_model.text().trim().to_owned(),
            add.name.text().trim().to_owned(),
            add.advertised_context_window,
            add.matched,
            add.supports_reasoning_effort,
            add.auto_compact_threshold_percent,
        )
    };
    if api_model.is_empty() {
        if let Some(add) = state.add_model.as_mut() {
            add.error = Some("Model id is required".into());
        }
        return VendorLoginOutcome::Changed;
    }
    let duplicate = state.custom.as_ref().is_some_and(|draft| {
        draft
            .models
            .iter()
            .any(|m| m.api_model.eq_ignore_ascii_case(&api_model))
    });
    if duplicate {
        if let Some(add) = state.add_model.as_mut() {
            add.error = Some(format!("Already in the list: {api_model}"));
        }
        return VendorLoginOutcome::Changed;
    }
    let pick = CustomModelPick {
        api_model,
        name,
        context_window,
        advertised_context_window: if matched {
            Some(advertised.max(1))
        } else {
            None
        },
        supports_reasoning_effort,
        enabled: true,
        auto_compact_threshold_percent: threshold,
    };
    let Some(draft) = state.custom.as_mut() else {
        return VendorLoginOutcome::Unchanged;
    };
    draft.models.push(pick);
    draft.selected = draft.models.len() - 1;
    draft.search_focused = false;
    draft.clamp_selection_to_filter();
    state.add_model = None;
    state.error = None;
    VendorLoginOutcome::Changed
}

fn submit_custom_save(state: &mut VendorLoginState) -> VendorLoginOutcome {
    let Some(draft) = state.custom.as_ref() else {
        return VendorLoginOutcome::Unchanged;
    };
    if !draft.models.iter().any(|m| m.enabled) {
        state.error = Some("Enable at least one model".into());
        return VendorLoginOutcome::Changed;
    }
    let name = draft.name.text().trim().to_owned();
    let base_url = draft.base_url.text().trim().to_owned();
    let key = draft.key.text().trim().to_owned();
    let api_backend = PROTOCOLS[draft.protocol].to_owned();
    let auth_scheme = if api_backend == "messages" {
        "x-api-key".to_owned()
    } else {
        "bearer".to_owned()
    };
    let models = draft.models.iter().map(|m| m.to_custom_model()).collect();
    state.probing = true;
    VendorLoginOutcome::SaveCustom {
        provider_id: draft.id.clone(),
        name,
        base_url,
        api_backend,
        auth_scheme,
        key,
        models,
    }
}

fn confirm_method(state: &mut VendorLoginState) -> VendorLoginOutcome {
    let (provider_id, provider_name, selected, from_picker) = match &state.step {
        VendorLoginStep::Method {
            provider_id,
            provider_name,
            selected,
            from_picker,
        } => (
            provider_id.clone(),
            provider_name.clone(),
            *selected,
            *from_picker,
        ),
        _ => return VendorLoginOutcome::Unchanged,
    };
    let rows = method_rows(&provider_id);
    let Some((id, _)) = rows.get(selected) else {
        return VendorLoginOutcome::Unchanged;
    };
    if id == "oauth" {
        state.probing = true;
        state.error = None;
        return VendorLoginOutcome::StartOAuth { provider_id };
    }
    state.enter_key_form(provider_id, provider_name, from_picker);
    VendorLoginOutcome::Changed
}

fn submit_oauth_code(state: &mut VendorLoginState) -> VendorLoginOutcome {
    let VendorLoginStep::OAuthWait { provider_id, .. } = &state.step else {
        return VendorLoginOutcome::Unchanged;
    };
    let code = state.editor.text().trim().to_owned();
    if code.is_empty() {
        state.error = Some("Paste the redirect URL or authorization code".into());
        return VendorLoginOutcome::Changed;
    }
    VendorLoginOutcome::SubmitOAuthCode {
        provider_id: provider_id.clone(),
        code,
    }
}

fn submit_key(state: &mut VendorLoginState) -> VendorLoginOutcome {
    let (provider_id, requires_auth) = match &state.step {
        VendorLoginStep::Key {
            provider_id,
            requires_auth,
            ..
        } => (provider_id.clone(), *requires_auth),
        _ => return VendorLoginOutcome::Unchanged,
    };
    let key = state.editor.text().trim().to_owned();
    if key.is_empty()
        && requires_auth
        && xai_grok_shell::compat::provider_by_id(&provider_id).is_some()
    {
        state.error = Some("Paste an API key first".into());
        return VendorLoginOutcome::Changed;
    }
    state.probing = true;
    state.error = None;
    VendorLoginOutcome::Submit { provider_id, key }
}

fn title_for(state: &VendorLoginState) -> String {
    if state.add_model.is_some() {
        return "Add model".into();
    }
    match &state.step {
        VendorLoginStep::Pick { .. } => "Sign in · Providers".into(),
        VendorLoginStep::CustomForm => {
            if state.custom.as_ref().is_some_and(|d| d.id.is_some()) {
                "Edit custom provider".into()
            } else {
                "Add custom provider".into()
            }
        }
        VendorLoginStep::CustomModels => {
            let name = state
                .custom
                .as_ref()
                .map(|d| d.name.text().trim().to_owned())
                .filter(|s| !s.is_empty());
            match name {
                Some(name) => format!("Select models · {name}"),
                None => "Select models".into(),
            }
        }
        VendorLoginStep::Method { provider_name, .. }
        | VendorLoginStep::Key { provider_name, .. }
        | VendorLoginStep::OAuthWait { provider_name, .. } => {
            format!("Sign in · {provider_name}")
        }
    }
}

pub(crate) fn render_vendor_login_modal(
    buf: &mut Buffer,
    area: Rect,
    state: &mut VendorLoginState,
    compact: bool,
) {
    let theme = Theme::current();
    let title = title_for(state);
    let shortcuts = step_shortcuts(state);
    let config = modal_config(&title, &shortcuts, compact);
    let Some(areas) = render_modal_window(buf, area, &mut state.window, &config, &theme) else {
        state.content_area = None;
        state.row_map.clear();
        return;
    };
    state.content_area = Some(areas.content);
    match &state.step {
        VendorLoginStep::Pick { .. } => render_pick_list(buf, areas.content, state, &theme),
        VendorLoginStep::Method { .. } => render_method_list(buf, areas.content, state, &theme),
        VendorLoginStep::Key { .. } => render_key_form(buf, areas.content, state, &theme),
        VendorLoginStep::OAuthWait { .. } => render_oauth_wait(buf, areas.content, state, &theme),
        VendorLoginStep::CustomForm => render_custom_form(buf, areas.content, state, &theme),
        VendorLoginStep::CustomModels if state.add_model.is_some() => {
            render_add_model(buf, areas.content, state, &theme)
        }
        VendorLoginStep::CustomModels => render_custom_models(buf, areas.content, state, &theme),
    }
}

fn render_method_list(buf: &mut Buffer, area: Rect, state: &mut VendorLoginState, theme: &Theme) {
    let VendorLoginStep::Method {
        provider_id,
        selected,
        ..
    } = &state.step
    else {
        return;
    };
    let rows = method_rows(provider_id);
    let selected = *selected;
    state.row_map.clear();
    for (i, (_, label)) in rows.iter().enumerate() {
        if i as u16 >= area.height {
            break;
        }
        let y = area.y + i as u16;
        state.row_map.push((y, i));
        let focused = i == selected;
        if focused {
            let hover = Style::default().bg(theme.bg_highlight);
            for x in area.x..area.x + area.width {
                if let Some(cell) = buf.cell_mut((x, y)) {
                    cell.set_style(hover);
                }
            }
        }
        let style = if focused {
            Style::default()
                .fg(theme.text_primary)
                .bg(theme.bg_highlight)
                .add_modifier(Modifier::BOLD)
        } else {
            Style::default().fg(theme.text_primary)
        };
        Paragraph::new(Line::from(Span::styled(label.clone(), style))).render(
            Rect {
                x: area.x,
                y,
                width: area.width,
                height: 1,
            },
            buf,
        );
    }
}

fn render_oauth_wait(buf: &mut Buffer, area: Rect, state: &VendorLoginState, theme: &Theme) {
    let VendorLoginStep::OAuthWait {
        authorize_url,
        instructions,
        ..
    } = &state.step
    else {
        return;
    };
    if area.height == 0 {
        return;
    }
    let mut y = area.y;
    Paragraph::new(Line::from(Span::styled(
        truncate_str(instructions, area.width as usize),
        Style::default().fg(theme.text_secondary),
    )))
    .render(
        Rect {
            x: area.x,
            y,
            width: area.width,
            height: 1,
        },
        buf,
    );
    y = y.saturating_add(2);
    if y < area.y + area.height {
        Paragraph::new(Line::from(Span::styled(
            truncate_str(authorize_url, area.width as usize),
            Style::default()
                .fg(theme.accent_user)
                .add_modifier(Modifier::UNDERLINED),
        )))
        .render(
            Rect {
                x: area.x,
                y,
                width: area.width,
                height: 1,
            },
            buf,
        );
        y = y.saturating_add(2);
    }
    if y >= area.y + area.height {
        return;
    }
    let input_bg = theme.bg_visual;
    let input_rect = Rect {
        x: area.x,
        y,
        width: area.width,
        height: 1,
    };
    buf.set_style(input_rect, Style::default().bg(input_bg));
    let room = area.width as usize;
    if state.editor.text().is_empty() {
        let ph = truncate_str("<paste redirect URL or code>", room.saturating_sub(1));
        let ph_w = ph.width() as u16;
        buf.set_span(
            area.x,
            y,
            &Span::styled(ph, Style::default().fg(theme.gray_dim).bg(input_bg)),
            ph_w,
        );
        buf.set_span(
            area.x,
            y,
            &Span::styled(
                crate::glyphs::selection_bar(),
                Style::default().fg(theme.accent_user).bg(input_bg),
            ),
            1,
        );
    } else {
        let viewport = state.editor.viewport(room);
        let visible = &state.editor.text()[viewport.visible_byte_range];
        let w = (visible.width() as u16).min(area.width);
        buf.set_span(
            area.x,
            y,
            &Span::styled(
                visible,
                Style::default().fg(theme.text_primary).bg(input_bg),
            ),
            w,
        );
        let cursor_x =
            area.x + (viewport.cursor_display_column as u16).min(area.width.saturating_sub(1));
        buf.set_span(
            cursor_x,
            y,
            &Span::styled(
                crate::glyphs::selection_bar(),
                Style::default().fg(theme.accent_user).bg(input_bg),
            ),
            1,
        );
    }
    if let Some(err) = &state.error {
        let err_y = y.saturating_add(2);
        if err_y < area.y + area.height {
            let text = truncate_str(err, area.width as usize);
            let tw = text.width() as u16;
            buf.set_span(
                area.x,
                err_y,
                &Span::styled(text, Style::default().fg(theme.accent_error)),
                tw,
            );
        }
    }
}

fn render_cycle_row(
    buf: &mut Buffer,
    area: Rect,
    y: u16,
    label: &str,
    value: &str,
    focused: bool,
    theme: &Theme,
) {
    if y >= area.y + area.height {
        return;
    }
    let bg = if focused {
        theme.bg_visual
    } else {
        theme.bg_base
    };
    let row = Rect {
        x: area.x,
        y,
        width: area.width,
        height: 1,
    };
    buf.set_style(row, Style::default().bg(bg));
    let line = format!("{label}: {value}   ←→");
    buf.set_span(
        area.x,
        y,
        &Span::styled(
            truncate_str(&line, area.width as usize),
            Style::default().fg(theme.text_primary).bg(bg),
        ),
        area.width,
    );
}

fn render_labeled_input(
    buf: &mut Buffer,
    area: Rect,
    y: u16,
    label: &str,
    editor: &LineEditor,
    focused: bool,
    mask: bool,
    theme: &Theme,
) {
    let bg = if focused {
        theme.bg_visual
    } else {
        theme.bg_base
    };
    let row = Rect {
        x: area.x,
        y,
        width: area.width,
        height: 1,
    };
    buf.set_style(row, Style::default().bg(bg));
    let label_s = format!("{label}: ");
    let label_w = label_s.width() as u16;
    buf.set_span(
        area.x,
        y,
        &Span::styled(label_s, Style::default().fg(theme.gray_bright).bg(bg)),
        label_w.min(area.width),
    );
    if area.width <= label_w {
        return;
    }
    let input_x = area.x + label_w;
    let room = area.width.saturating_sub(label_w) as usize;
    let text = editor.text();
    let display = if mask && !text.is_empty() {
        "•".repeat(text.chars().count())
    } else {
        text.to_owned()
    };
    if display.is_empty() && focused {
        buf.set_span(
            input_x,
            y,
            &Span::styled(
                crate::glyphs::selection_bar(),
                Style::default().fg(theme.accent_user).bg(bg),
            ),
            1,
        );
        return;
    }
    let shown = truncate_str(&display, room.saturating_sub(1));
    let sw = shown.width() as u16;
    buf.set_span(
        input_x,
        y,
        &Span::styled(shown, Style::default().fg(theme.text_primary).bg(bg)),
        sw,
    );
    if focused {
        let cursor_x = input_x + sw.min(area.width.saturating_sub(label_w + 1));
        buf.set_span(
            cursor_x,
            y,
            &Span::styled(
                crate::glyphs::selection_bar(),
                Style::default().fg(theme.accent_user).bg(bg),
            ),
            1,
        );
    }
}

fn render_custom_form(buf: &mut Buffer, area: Rect, state: &VendorLoginState, theme: &Theme) {
    let Some(draft) = state.custom.as_ref() else {
        return;
    };
    if area.height == 0 {
        return;
    }
    let fields = [
        (CustomField::Name, "Name", false),
        (CustomField::BaseUrl, "Base URL", false),
        (CustomField::Protocol, "Protocol", false),
        (CustomField::Key, "API key", true),
    ];
    for (i, (field, label, mask)) in fields.iter().enumerate() {
        let y = area.y + i as u16 * 2;
        if y >= area.y + area.height {
            break;
        }
        let focused = draft.field == *field;
        if *field == CustomField::Protocol {
            let bg = if focused {
                theme.bg_visual
            } else {
                theme.bg_base
            };
            let row = Rect {
                x: area.x,
                y,
                width: area.width,
                height: 1,
            };
            buf.set_style(row, Style::default().bg(bg));
            let value = PROTOCOLS[draft.protocol];
            let line = format!("Protocol: {value}   ←/→");
            buf.set_span(
                area.x,
                y,
                &Span::styled(
                    truncate_str(&line, area.width as usize),
                    Style::default().fg(theme.text_primary).bg(bg),
                ),
                area.width,
            );
        } else {
            let editor = match field {
                CustomField::Name => &draft.name,
                CustomField::BaseUrl => &draft.base_url,
                CustomField::Key => &draft.key,
                CustomField::Protocol => continue,
            };
            render_labeled_input(buf, area, y, label, editor, focused, *mask, theme);
        }
    }
    let hint_y = area.y + 8;
    if hint_y < area.y + area.height {
        let hint = if state.probing {
            "Fetching /models…"
        } else if let Some(err) = &state.error {
            err.as_str()
        } else {
            "Tab fields · Enter sync · ^Enter skip list"
        };
        let style = if state.error.is_some() {
            Style::default().fg(theme.accent_error)
        } else if state.probing {
            Style::default().fg(theme.accent_model)
        } else {
            Style::default().fg(theme.gray_bright)
        };
        let text = truncate_str(hint, area.width as usize);
        let tw = text.width() as u16;
        buf.set_span(area.x, hint_y, &Span::styled(text, style), tw);
    }
}

fn render_add_model(buf: &mut Buffer, area: Rect, state: &mut VendorLoginState, theme: &Theme) {
    let Some(add) = state.add_model.as_ref() else {
        return;
    };
    if area.height == 0 {
        return;
    }
    render_labeled_input(
        buf,
        area,
        area.y,
        "Model id",
        &add.api_model,
        add.field == AddModelField::ApiModel,
        false,
        theme,
    );
    if area.y + 2 < area.y + area.height {
        render_labeled_input(
            buf,
            area,
            area.y + 2,
            "Name",
            &add.name,
            add.field == AddModelField::Name,
            false,
            theme,
        );
    }
    render_labeled_input(
        buf,
        area,
        area.y + 4,
        "Context",
        &add.context_text,
        add.field == AddModelField::Context,
        false,
        theme,
    );
    render_cycle_row(
        buf,
        area,
        area.y + 6,
        "Compact",
        &xai_grok_shell::context_window::format_threshold(add.auto_compact_threshold_percent),
        add.field == AddModelField::Threshold,
        theme,
    );
    let reasoning_y = area.y + 8;
    if reasoning_y < area.y + area.height {
        let focused = add.field == AddModelField::Reasoning;
        let bg = if focused {
            theme.bg_visual
        } else {
            theme.bg_base
        };
        let row = Rect {
            x: area.x,
            y: reasoning_y,
            width: area.width,
            height: 1,
        };
        buf.set_style(row, Style::default().bg(bg));
        let mark = if add.supports_reasoning_effort {
            "[x]"
        } else {
            "[ ]"
        };
        let line = format!("Reasoning: {mark}   Space");
        buf.set_span(
            area.x,
            reasoning_y,
            &Span::styled(
                truncate_str(&line, area.width as usize),
                Style::default().fg(theme.text_primary).bg(bg),
            ),
            area.width,
        );
    }
    let hint_y = area.y + 10;
    if hint_y < area.y + area.height {
        let hint = if let Some(err) = add.error.as_deref() {
            err.to_owned()
        } else if add.field == AddModelField::Context {
            "Type 256k, 1M, or 1.05M".to_owned()
        } else if add.api_model.text().trim().is_empty() {
            "Wire id sent to the provider".to_owned()
        } else if add.matched {
            format!(
                "models.dev · {} ctx  (256k / 1M){}",
                xai_grok_shell::context_window::format_window(add.context_window),
                if add.supports_reasoning_effort {
                    " · reasoning"
                } else {
                    ""
                }
            )
        } else {
            format!(
                "unknown to models.dev · {} ctx  (256k / 1M){}",
                xai_grok_shell::context_window::format_window(add.context_window),
                if add.supports_reasoning_effort {
                    " · reasoning on"
                } else {
                    " · reasoning off"
                }
            )
        };
        let style = if add.error.is_some() {
            Style::default().fg(theme.accent_error)
        } else {
            Style::default().fg(theme.gray_bright)
        };
        let text = truncate_str(&hint, area.width as usize);
        let tw = text.width() as u16;
        buf.set_span(area.x, hint_y, &Span::styled(text, style), tw);
    }
}

fn render_custom_models(buf: &mut Buffer, area: Rect, state: &mut VendorLoginState, theme: &Theme) {
    if area.height == 0 {
        return;
    }
    let probing = state.probing;
    let error = state.error.clone();
    let search_y = area.y;
    let list_top = area.y.saturating_add(1);
    let list_bottom = area.y + area.height.saturating_sub(1);
    let list_height = list_bottom.saturating_sub(list_top);
    let Some(draft) = state.custom.as_mut() else {
        return;
    };
    draft.clamp_selection_to_filter();
    let filtered = draft.filtered_indices();
    let search_focused = draft.search_focused;
    let query = draft.search.text().to_owned();
    let enabled_n = draft.models.iter().filter(|m| m.enabled).count();
    let total_n = draft.models.len();

    let search_bg = if search_focused {
        theme.bg_visual
    } else {
        theme.bg_base
    };
    let search_rect = Rect {
        x: area.x,
        y: search_y,
        width: area.width,
        height: 1,
    };
    buf.set_style(search_rect, Style::default().bg(search_bg));
    let prefix = "/ ";
    let prefix_w = prefix.width() as u16;
    buf.set_span(
        area.x,
        search_y,
        &Span::styled(prefix, Style::default().fg(theme.gray_bright).bg(search_bg)),
        prefix_w.min(area.width),
    );
    if area.width > prefix_w {
        let room = area.width.saturating_sub(prefix_w) as usize;
        if query.is_empty() {
            let ph = truncate_str("find models", room);
            let ph_w = ph.width() as u16;
            buf.set_span(
                area.x + prefix_w,
                search_y,
                &Span::styled(ph, Style::default().fg(theme.gray_dim).bg(search_bg)),
                ph_w,
            );
            if search_focused {
                buf.set_span(
                    area.x + prefix_w,
                    search_y,
                    &Span::styled(
                        crate::glyphs::selection_bar(),
                        Style::default().fg(theme.accent_user).bg(search_bg),
                    ),
                    1,
                );
            }
        } else {
            let shown = truncate_str(&query, room.saturating_sub(1));
            let sw = shown.width() as u16;
            buf.set_span(
                area.x + prefix_w,
                search_y,
                &Span::styled(shown, Style::default().fg(theme.text_primary).bg(search_bg)),
                sw,
            );
            if search_focused {
                buf.set_span(
                    area.x + prefix_w + sw.min(area.width.saturating_sub(prefix_w + 1)),
                    search_y,
                    &Span::styled(
                        crate::glyphs::selection_bar(),
                        Style::default().fg(theme.accent_user).bg(search_bg),
                    ),
                    1,
                );
            }
        }
    }

    let visible = list_height.max(1) as usize;
    let pos = filtered
        .iter()
        .position(|&i| i == draft.selected)
        .unwrap_or(0);
    if pos < draft.scroll {
        draft.scroll = pos;
    } else if pos >= draft.scroll + visible {
        draft.scroll = pos.saturating_add(1).saturating_sub(visible);
    }
    let selected = draft.selected;
    let scroll = draft.scroll;
    let models = draft.models.clone();
    state.row_map.clear();
    for (row_idx, &i) in filtered.iter().skip(scroll).take(visible).enumerate() {
        let y = list_top + row_idx as u16;
        if y >= list_bottom {
            break;
        }
        state.row_map.push((y, i));
        let Some(row) = models.get(i) else {
            continue;
        };
        let focused = i == selected && !search_focused;
        if focused {
            let hover = Style::default().bg(theme.bg_highlight);
            for x in area.x..area.x + area.width {
                if let Some(cell) = buf.cell_mut((x, y)) {
                    cell.set_style(hover);
                }
            }
        }
        let mark = if row.enabled { "[x]" } else { "[ ]" };
        let think = if row.supports_reasoning_effort {
            "  think"
        } else {
            ""
        };
        let ctx = xai_grok_shell::context_window::format_window(row.context_window);
        let thresh =
            xai_grok_shell::context_window::format_threshold(row.auto_compact_threshold_percent);
        let label = if row.name.is_empty() {
            format!("{mark} {}  {ctx}  {thresh}{think}", row.api_model)
        } else {
            format!(
                "{mark} {}  {}  {ctx}  {thresh}{think}",
                row.api_model, row.name
            )
        };
        let style = if focused {
            Style::default()
                .fg(theme.text_primary)
                .bg(theme.bg_highlight)
        } else {
            Style::default().fg(theme.text_primary)
        };
        Paragraph::new(Line::from(Span::styled(
            truncate_str(&label, area.width as usize),
            style,
        )))
        .render(
            Rect {
                x: area.x,
                y,
                width: area.width,
                height: 1,
            },
            buf,
        );
    }

    let status_y = area.y + area.height.saturating_sub(1);
    if status_y > search_y {
        if let Some(editor) = state.context_edit.as_ref() {
            render_labeled_input(buf, area, status_y, "Context", editor, true, false, theme);
        } else {
            let hint = if probing {
                "Saving provider…".to_owned()
            } else if let Some(err) = error.as_deref() {
                err.to_owned()
            } else if !query.trim().is_empty() {
                format!("{enabled_n}/{total_n} enabled · {} shown", filtered.len())
            } else if total_n == 0 {
                "No models — press i to add".to_owned()
            } else {
                format!(
                    "{enabled_n}/{total_n} enabled · Space toggle · c type ctx · [] cycle · t compact · r reasoning · i add"
                )
            };
            let style = if error.is_some() {
                Style::default().fg(theme.accent_error)
            } else if probing {
                Style::default().fg(theme.accent_model)
            } else {
                Style::default().fg(theme.gray_bright)
            };
            let text = truncate_str(&hint, area.width as usize);
            let tw = text.width() as u16;
            buf.set_span(area.x, status_y, &Span::styled(text, style), tw);
        }
    }
}

fn render_pick_list(buf: &mut Buffer, area: Rect, state: &mut VendorLoginState, theme: &Theme) {
    let rows = provider_rows();
    let VendorLoginStep::Pick { selected, scroll } = &mut state.step else {
        return;
    };
    if rows.is_empty() {
        state.row_map.clear();
        Paragraph::new(Line::from(Span::styled(
            "No providers in catalog",
            Style::default().fg(theme.gray_bright),
        )))
        .render(area, buf);
        return;
    }
    if *selected >= rows.len() {
        *selected = rows.len() - 1;
    }
    let visible = area.height.max(1) as usize;
    if *selected < *scroll {
        *scroll = *selected;
    } else if *selected >= *scroll + visible {
        *scroll = (*selected).saturating_add(1).saturating_sub(visible);
    }

    state.row_map.clear();
    for (row_idx, (i, row)) in rows
        .iter()
        .enumerate()
        .skip(*scroll)
        .take(visible)
        .enumerate()
    {
        let y = area.y + row_idx as u16;
        state.row_map.push((y, i));
        let focused = i == *selected;
        if focused {
            let hover = Style::default().bg(theme.bg_highlight);
            for x in area.x..area.x + area.width {
                if let Some(cell) = buf.cell_mut((x, y)) {
                    cell.set_style(hover);
                }
            }
        }
        let name_style = if focused {
            Style::default()
                .fg(theme.text_primary)
                .bg(theme.bg_highlight)
                .add_modifier(Modifier::BOLD)
        } else {
            Style::default().fg(theme.text_primary)
        };
        let status_style = if focused {
            Style::default()
                .fg(theme.gray_bright)
                .bg(theme.bg_highlight)
        } else {
            Style::default().fg(theme.gray_bright)
        };
        let status_w = row.status.width() as u16;
        let gap = 2u16;
        let name_budget = area
            .width
            .saturating_sub(status_w.saturating_add(gap))
            .max(1) as usize;
        let name = truncate_str(&row.name, name_budget);
        let mut spans = vec![Span::styled(name, name_style)];
        if area.width > status_w + 1 {
            let used = spans[0].content.width() as u16;
            let pad = area.width.saturating_sub(used).saturating_sub(status_w);
            if pad > 0 {
                spans.push(Span::styled(
                    " ".repeat(pad as usize),
                    if focused {
                        Style::default().bg(theme.bg_highlight)
                    } else {
                        Style::default()
                    },
                ));
            }
            spans.push(Span::styled(row.status.clone(), status_style));
        }
        Paragraph::new(Line::from(spans)).render(
            Rect {
                x: area.x,
                y,
                width: area.width,
                height: 1,
            },
            buf,
        );
    }
}

fn render_key_form(buf: &mut Buffer, area: Rect, state: &VendorLoginState, theme: &Theme) {
    let VendorLoginStep::Key {
        provider_name,
        requires_auth,
        ..
    } = &state.step
    else {
        return;
    };
    if area.height == 0 || area.width == 0 {
        return;
    }

    let prompt = if *requires_auth {
        format!("Paste your {provider_name} API key")
    } else {
        format!("Connect to local {provider_name} (no API key)")
    };
    Paragraph::new(Line::from(Span::styled(
        truncate_str(&prompt, area.width as usize),
        Style::default().fg(theme.text_secondary),
    )))
    .render(
        Rect {
            x: area.x,
            y: area.y,
            width: area.width,
            height: 1,
        },
        buf,
    );

    if area.height < 3 {
        return;
    }
    let input_y = area.y + 2;
    let input_bg = theme.bg_visual;
    let has_error = state.error.is_some();
    let input_fg = if has_error {
        theme.accent_error
    } else {
        theme.text_primary
    };
    let input_style = Style::default().fg(input_fg).bg(input_bg);
    let cursor_style = Style::default().fg(theme.accent_user).bg(input_bg);
    let input_rect = Rect {
        x: area.x,
        y: input_y,
        width: area.width,
        height: 1,
    };
    buf.set_style(input_rect, Style::default().bg(input_bg));

    let room = area.width as usize;
    if room == 0 {
        return;
    }
    let cursor_reserve = 1usize;
    let visible_w = room.saturating_sub(cursor_reserve);

    if state.editor.text().is_empty() {
        let placeholder = if *requires_auth {
            "<paste or type>"
        } else {
            "<Enter to connect>"
        };
        if visible_w > 0 && !state.probing {
            let ph = truncate_str(placeholder, visible_w);
            let ph_w = ph.width() as u16;
            buf.set_span(
                area.x,
                input_y,
                &Span::styled(ph, Style::default().fg(theme.gray_dim).bg(input_bg)),
                ph_w,
            );
        }
        buf.set_span(
            area.x,
            input_y,
            &Span::styled(crate::glyphs::selection_bar(), cursor_style),
            1,
        );
    } else {
        let viewport = state.editor.viewport(room);
        let visible = &state.editor.text()[viewport.visible_byte_range];
        let display: String = "•".repeat(visible.chars().count());
        let display_w = (display.width() as u16).min(area.width);
        buf.set_span(
            area.x,
            input_y,
            &Span::styled(&display, input_style),
            display_w,
        );
        let cursor_x =
            area.x + (viewport.cursor_display_column as u16).min(area.width.saturating_sub(1));
        buf.set_span(
            cursor_x,
            input_y,
            &Span::styled(crate::glyphs::selection_bar(), cursor_style),
            1,
        );
    }

    if area.height < 5 {
        return;
    }
    let status_y = input_y + 2;
    let status = if state.probing {
        if *requires_auth {
            "Checking key…"
        } else {
            "Connecting…"
        }
    } else if let Some(err) = &state.error {
        err.as_str()
    } else {
        ""
    };
    if !status.is_empty() {
        let style = if state.error.is_some() {
            Style::default().fg(theme.accent_error)
        } else {
            Style::default().fg(theme.accent_model)
        };
        let text = truncate_str(status, area.width as usize);
        let text_w = text.width() as u16;
        buf.set_span(area.x, status_y, &Span::styled(text, style), text_w);
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crossterm::event::{KeyCode, KeyEvent, KeyModifiers};

    fn key(code: KeyCode) -> KeyEvent {
        KeyEvent::new(code, KeyModifiers::NONE)
    }

    #[test]
    fn picker_enter_opens_key_form() {
        let mut state = VendorLoginState::picker();
        assert!(matches!(state.step, VendorLoginStep::Pick { .. }));
        let out = handle_vendor_login_key(&mut state, &key(KeyCode::Enter));
        assert!(matches!(out, VendorLoginOutcome::Changed));
        assert!(matches!(
            state.step,
            VendorLoginStep::Key {
                from_picker: true,
                ..
            }
        ));
    }

    #[test]
    fn esc_from_key_form_returns_to_picker() {
        let mut state = VendorLoginState::picker();
        let _ = handle_vendor_login_key(&mut state, &key(KeyCode::Enter));
        let out = handle_vendor_login_key(&mut state, &key(KeyCode::Esc));
        assert!(matches!(out, VendorLoginOutcome::Changed));
        assert!(matches!(state.step, VendorLoginStep::Pick { .. }));
    }

    #[test]
    fn direct_provider_esc_closes() {
        let mut state = VendorLoginState::for_provider("openai".into(), "OpenAI".into());
        let out = handle_vendor_login_key(&mut state, &key(KeyCode::Esc));
        assert!(matches!(out, VendorLoginOutcome::Close));
    }

    #[test]
    fn empty_key_refuses_submit() {
        let mut state = VendorLoginState::for_provider("openai".into(), "OpenAI".into());
        let out = handle_vendor_login_key(&mut state, &key(KeyCode::Enter));
        assert!(matches!(out, VendorLoginOutcome::Changed));
        assert_eq!(state.error.as_deref(), Some("Paste an API key first"));
        assert!(!state.probing);
    }

    #[test]
    fn openrouter_opens_on_method_choice() {
        let mut state = VendorLoginState::for_provider("openrouter".into(), "OpenRouter".into());
        assert!(matches!(state.step, VendorLoginStep::Method { .. }));
        let out = handle_vendor_login_key(&mut state, &key(KeyCode::Enter));
        match out {
            VendorLoginOutcome::StartOAuth { provider_id } => {
                assert_eq!(provider_id, "openrouter");
            }
            other => panic!("expected StartOAuth, got {other:?}"),
        }
    }

    #[test]
    fn line_editor_arrow_keys_move_cursor() {
        let mut state = VendorLoginState::for_provider("openai".into(), "OpenAI".into());
        assert!(matches!(
            handle_vendor_login_paste(&mut state, "sk-test"),
            VendorLoginOutcome::Changed
        ));
        let end = state.editor.cursor_byte();
        assert!(end > 0);
        let out = handle_vendor_login_key(&mut state, &key(KeyCode::Left));
        assert!(matches!(out, VendorLoginOutcome::Changed));
        assert!(state.editor.cursor_byte() < end);
    }

    #[test]
    fn add_custom_row_opens_form() {
        let mut state = VendorLoginState::picker();
        let idx = provider_rows()
            .iter()
            .position(|r| r.id == ADD_CUSTOM_ID)
            .expect("add custom row");
        if let VendorLoginStep::Pick { selected, .. } = &mut state.step {
            *selected = idx;
        }
        let out = handle_vendor_login_key(&mut state, &key(KeyCode::Enter));
        assert!(matches!(out, VendorLoginOutcome::Changed));
        assert!(matches!(state.step, VendorLoginStep::CustomForm));
    }

    #[test]
    fn custom_form_requires_name_and_url() {
        let mut state = VendorLoginState::custom_form();
        let out = handle_vendor_login_key(&mut state, &key(KeyCode::Enter));
        assert!(matches!(out, VendorLoginOutcome::Changed));
        assert_eq!(
            state.error.as_deref(),
            Some("Name and base URL are required")
        );
        assert!(!state.probing);
    }

    #[test]
    fn custom_form_tab_and_protocol_cycle() {
        let mut state = VendorLoginState::custom_form();
        assert_eq!(state.custom.as_ref().unwrap().field, CustomField::Name);
        let _ = handle_vendor_login_key(&mut state, &key(KeyCode::Tab));
        assert_eq!(state.custom.as_ref().unwrap().field, CustomField::BaseUrl);
        let _ = handle_vendor_login_key(&mut state, &key(KeyCode::Tab));
        assert_eq!(state.custom.as_ref().unwrap().field, CustomField::Protocol);
        let start = state.custom.as_ref().unwrap().protocol;
        let _ = handle_vendor_login_key(&mut state, &key(KeyCode::Right));
        assert_eq!(
            state.custom.as_ref().unwrap().protocol,
            (start + 1) % PROTOCOLS.len()
        );
        assert_eq!(PROTOCOLS[1], "responses");
    }

    #[test]
    fn custom_form_sync_and_toggle_models() {
        let mut state = VendorLoginState::custom_form();
        let _ = handle_vendor_login_paste(&mut state, "Acme");
        let _ = handle_vendor_login_key(&mut state, &key(KeyCode::Tab));
        let _ = handle_vendor_login_paste(&mut state, "acme.example/v1");
        let _ = handle_vendor_login_key(&mut state, &key(KeyCode::Tab));
        let _ = handle_vendor_login_key(&mut state, &key(KeyCode::Tab));
        let _ = handle_vendor_login_paste(&mut state, "sk-test");
        match handle_vendor_login_key(&mut state, &key(KeyCode::Enter)) {
            VendorLoginOutcome::SyncCustom {
                name,
                base_url,
                api_backend,
                key,
                ..
            } => {
                assert_eq!(name, "Acme");
                assert_eq!(base_url, "https://acme.example/v1");
                assert_eq!(api_backend, "chat_completions");
                assert_eq!(key, "sk-test");
            }
            other => panic!("expected SyncCustom, got {other:?}"),
        }
        assert!(state.probing);
        state.apply_custom_models(
            vec![
                ("acme-large".into(), "Large".into(), 64_000),
                ("acme-small".into(), "Small".into(), 32_000),
            ],
            None,
        );
        assert!(matches!(state.step, VendorLoginStep::CustomModels));
        let _ = handle_vendor_login_key(&mut state, &key(KeyCode::Char(' ')));
        assert!(!state.custom.as_ref().unwrap().models[0].enabled);
        let _ = handle_vendor_login_key(&mut state, &key(KeyCode::Down));
        match handle_vendor_login_key(&mut state, &key(KeyCode::Enter)) {
            VendorLoginOutcome::SaveCustom {
                provider_id,
                models,
                ..
            } => {
                assert!(provider_id.is_none());
                assert!(!models[0].enabled);
                assert!(models[1].enabled);
            }
            other => panic!("expected SaveCustom, got {other:?}"),
        }
    }

    fn ctrl(code: KeyCode) -> KeyEvent {
        KeyEvent::new(code, KeyModifiers::CONTROL)
    }

    #[test]
    fn custom_models_search_and_select_visible() {
        let mut state = VendorLoginState::custom_form();
        state.apply_custom_models(
            vec![
                ("gpt-4o".into(), "GPT-4o".into(), 128_000),
                ("claude-sonnet".into(), "Sonnet".into(), 200_000),
                ("gpt-4.1".into(), "GPT-4.1".into(), 128_000),
            ],
            None,
        );
        let _ = handle_vendor_login_key(&mut state, &key(KeyCode::Char('n')));
        assert!(
            state
                .custom
                .as_ref()
                .unwrap()
                .models
                .iter()
                .all(|m| !m.enabled)
        );
        let _ = handle_vendor_login_key(&mut state, &key(KeyCode::Char('/')));
        assert!(state.custom.as_ref().unwrap().search_focused);
        let _ = handle_vendor_login_paste(&mut state, "gpt");
        assert_eq!(state.custom.as_ref().unwrap().filtered_indices().len(), 2);
        let _ = handle_vendor_login_key(&mut state, &ctrl(KeyCode::Char('a')));
        let draft = state.custom.as_ref().unwrap();
        assert!(
            draft
                .models
                .iter()
                .filter(|m| m.api_model.starts_with("gpt"))
                .all(|m| m.enabled)
        );
        assert!(
            !draft
                .models
                .iter()
                .find(|m| m.api_model == "claude-sonnet")
                .unwrap()
                .enabled
        );
    }

    #[test]
    fn custom_resync_preserves_enabled_and_id() {
        let mut state = VendorLoginState::custom_form();
        if let Some(draft) = state.custom.as_mut() {
            draft.id = Some("acme".into());
            draft.name.set_text("Acme");
        }
        state.apply_custom_models(
            vec![
                ("keep".into(), "Keep".into(), 32_000),
                ("drop".into(), "Drop".into(), 32_000),
            ],
            None,
        );
        let _ = handle_vendor_login_key(&mut state, &key(KeyCode::Down));
        let _ = handle_vendor_login_key(&mut state, &key(KeyCode::Char(' ')));
        state.apply_custom_models(
            vec![
                ("keep".into(), "Keep".into(), 32_000),
                ("drop".into(), "Drop".into(), 32_000),
                ("new".into(), "New".into(), 32_000),
            ],
            None,
        );
        let draft = state.custom.as_ref().unwrap();
        assert!(
            draft
                .models
                .iter()
                .find(|m| m.api_model == "keep")
                .unwrap()
                .enabled
        );
        assert!(
            !draft
                .models
                .iter()
                .find(|m| m.api_model == "drop")
                .unwrap()
                .enabled
        );
        assert!(
            draft
                .models
                .iter()
                .find(|m| m.api_model == "new")
                .unwrap()
                .enabled
        );
        match handle_vendor_login_key(&mut state, &key(KeyCode::Enter)) {
            VendorLoginOutcome::SaveCustom { provider_id, .. } => {
                assert_eq!(provider_id.as_deref(), Some("acme"));
            }
            other => panic!("expected SaveCustom, got {other:?}"),
        }
    }

    fn fill_custom_form(state: &mut VendorLoginState) {
        let _ = handle_vendor_login_paste(state, "Acme");
        let _ = handle_vendor_login_key(state, &key(KeyCode::Tab));
        let _ = handle_vendor_login_paste(state, "acme.example/v1");
        let _ = handle_vendor_login_key(state, &key(KeyCode::Tab));
        let _ = handle_vendor_login_key(state, &key(KeyCode::Tab));
        let _ = handle_vendor_login_paste(state, "sk-test");
    }

    #[test]
    fn custom_sync_error_keeps_models_step() {
        let mut state = VendorLoginState::custom_form();
        fill_custom_form(&mut state);
        state.apply_custom_models(
            vec![],
            Some("404 from https://acme.example/v1/models".into()),
        );
        assert!(matches!(state.step, VendorLoginStep::CustomModels));
        assert!(state.custom.as_ref().unwrap().models.is_empty());
        assert!(state.error.as_ref().is_some_and(|e| e.contains("404")));
    }

    #[test]
    fn custom_sync_error_preserves_existing_models() {
        let mut state = VendorLoginState::custom_form();
        state.apply_custom_models(vec![("keep".into(), "Keep".into(), 32_000)], None);
        state.apply_custom_models(vec![], Some("couldn't list models".into()));
        assert!(matches!(state.step, VendorLoginStep::CustomModels));
        assert_eq!(state.custom.as_ref().unwrap().models.len(), 1);
        assert_eq!(state.custom.as_ref().unwrap().models[0].api_model, "keep");
    }

    #[test]
    fn custom_form_ctrl_enter_skips_sync() {
        let mut state = VendorLoginState::custom_form();
        fill_custom_form(&mut state);
        let out = handle_vendor_login_key(&mut state, &ctrl(KeyCode::Enter));
        assert!(matches!(out, VendorLoginOutcome::Changed));
        assert!(matches!(state.step, VendorLoginStep::CustomModels));
        assert!(!state.probing);
        assert!(state.custom.as_ref().unwrap().models.is_empty());
    }

    #[test]
    fn custom_models_add_and_dedupe() {
        let mut state = VendorLoginState::custom_form();
        fill_custom_form(&mut state);
        let _ = handle_vendor_login_key(&mut state, &ctrl(KeyCode::Enter));
        let out = handle_vendor_login_key(&mut state, &key(KeyCode::Char('i')));
        assert!(matches!(out, VendorLoginOutcome::Changed));
        assert!(state.add_model.is_some());
        let _ = handle_vendor_login_paste(&mut state, "proxy-mystery-v1");
        match handle_vendor_login_key(&mut state, &key(KeyCode::Enter)) {
            VendorLoginOutcome::Changed => {}
            other => panic!("expected Changed after add, got {other:?}"),
        }
        assert!(state.add_model.is_none());
        let draft = state.custom.as_ref().unwrap();
        assert_eq!(draft.models.len(), 1);
        assert_eq!(draft.models[0].api_model, "proxy-mystery-v1");
        assert!(draft.models[0].enabled);
        assert!(!draft.models[0].supports_reasoning_effort);

        let _ = handle_vendor_login_key(&mut state, &key(KeyCode::Char('i')));
        let _ = handle_vendor_login_paste(&mut state, "proxy-mystery-v1");
        let _ = handle_vendor_login_key(&mut state, &key(KeyCode::Enter));
        assert!(
            state
                .add_model
                .as_ref()
                .unwrap()
                .error
                .as_ref()
                .is_some_and(|e| e.contains("Already"))
        );
        assert_eq!(state.custom.as_ref().unwrap().models.len(), 1);
    }

    #[test]
    fn custom_models_add_matches_models_dev() {
        let mut state = VendorLoginState::custom_form();
        fill_custom_form(&mut state);
        let _ = handle_vendor_login_key(&mut state, &ctrl(KeyCode::Enter));
        let _ = handle_vendor_login_key(&mut state, &key(KeyCode::Char('i')));
        let _ = handle_vendor_login_paste(&mut state, "gpt-5.6-sol");
        let add = state.add_model.as_ref().unwrap();
        assert!(add.matched);
        assert!(add.supports_reasoning_effort);
        assert_eq!(add.context_window, 1_050_000);
        let _ = handle_vendor_login_key(&mut state, &key(KeyCode::Enter));
        let row = &state.custom.as_ref().unwrap().models[0];
        assert!(row.supports_reasoning_effort);
        assert_eq!(row.context_window, 1_050_000);
    }

    #[test]
    fn custom_models_add_accepts_k_m_units() {
        let mut state = VendorLoginState::custom_form();
        fill_custom_form(&mut state);
        let _ = handle_vendor_login_key(&mut state, &ctrl(KeyCode::Enter));
        let _ = handle_vendor_login_key(&mut state, &key(KeyCode::Char('i')));
        let _ = handle_vendor_login_paste(&mut state, "proxy-wide-v1");
        let _ = handle_vendor_login_key(&mut state, &key(KeyCode::Tab));
        let _ = handle_vendor_login_key(&mut state, &key(KeyCode::Tab));
        assert_eq!(
            state.add_model.as_ref().unwrap().field,
            AddModelField::Context
        );
        let _ = handle_vendor_login_paste(&mut state, "1.05M");
        let _ = handle_vendor_login_key(&mut state, &key(KeyCode::Enter));
        assert!(state.add_model.is_none());
        let row = &state.custom.as_ref().unwrap().models[0];
        assert_eq!(row.api_model, "proxy-wide-v1");
        assert_eq!(row.context_window, 1_050_000);
        assert!(row.advertised_context_window.is_none());
    }

    #[test]
    fn custom_models_add_matched_clamps_typed_window() {
        let mut state = VendorLoginState::custom_form();
        fill_custom_form(&mut state);
        let _ = handle_vendor_login_key(&mut state, &ctrl(KeyCode::Enter));
        let _ = handle_vendor_login_key(&mut state, &key(KeyCode::Char('i')));
        let _ = handle_vendor_login_paste(&mut state, "gpt-5.6-sol");
        let _ = handle_vendor_login_key(&mut state, &key(KeyCode::Tab));
        let _ = handle_vendor_login_key(&mut state, &key(KeyCode::Tab));
        let _ = handle_vendor_login_paste(&mut state, "256k");
        let _ = handle_vendor_login_key(&mut state, &key(KeyCode::Enter));
        let row = &state.custom.as_ref().unwrap().models[0];
        assert_eq!(row.context_window, 256_000);
        assert_eq!(row.advertised_context_window, Some(1_050_000));
    }

    #[test]
    fn custom_models_list_c_types_k_units() {
        let mut state = VendorLoginState::custom_form();
        fill_custom_form(&mut state);
        state.apply_custom_models(vec![("wide".into(), "Wide".into(), 1_050_000)], None);
        assert_eq!(
            state.custom.as_ref().unwrap().models[0].context_window,
            1_050_000
        );
        let _ = handle_vendor_login_key(&mut state, &key(KeyCode::Char('c')));
        assert!(state.context_edit.is_some());
        let _ = handle_vendor_login_paste(&mut state, "256k");
        let _ = handle_vendor_login_key(&mut state, &key(KeyCode::Enter));
        assert!(state.context_edit.is_none());
        assert_eq!(
            state.custom.as_ref().unwrap().models[0].context_window,
            256_000
        );
    }

    #[test]
    fn custom_models_ctrl_r_resyncs_and_keeps_manual() {
        let mut state = VendorLoginState::custom_form();
        fill_custom_form(&mut state);
        state.apply_custom_models(
            vec![
                ("keep".into(), "Keep".into(), 32_000),
                ("manual".into(), "Manual".into(), 32_000),
            ],
            None,
        );
        let _ = handle_vendor_login_key(&mut state, &key(KeyCode::Down));
        match handle_vendor_login_key(&mut state, &ctrl(KeyCode::Char('r'))) {
            VendorLoginOutcome::SyncCustom { name, key, .. } => {
                assert_eq!(name, "Acme");
                assert_eq!(key, "sk-test");
            }
            other => panic!("expected SyncCustom, got {other:?}"),
        }
        assert!(state.probing);
        state.probing = false;
        state.apply_custom_models(
            vec![
                ("keep".into(), "Keep v2".into(), 64_000),
                ("new".into(), "New".into(), 128_000),
            ],
            None,
        );
        let draft = state.custom.as_ref().unwrap();
        let ids: Vec<&str> = draft.models.iter().map(|m| m.api_model.as_str()).collect();
        assert_eq!(ids, ["keep", "new", "manual"]);
        assert_eq!(draft.models[0].name, "Keep v2");
        assert_eq!(draft.models[0].context_window, 64_000);
        assert!(draft.models[1].enabled);
        assert!(
            draft
                .models
                .iter()
                .find(|m| m.api_model == "manual")
                .unwrap()
                .enabled
        );
    }

    #[test]
    fn picker_r_refreshes_catalog() {
        let mut state = VendorLoginState::picker();
        match handle_vendor_login_key(&mut state, &key(KeyCode::Char('r'))) {
            VendorLoginOutcome::RefreshCatalog => {}
            other => panic!("expected RefreshCatalog, got {other:?}"),
        }
    }

    #[test]
    fn custom_models_r_toggles_reasoning_and_save_keeps_it() {
        let mut state = VendorLoginState::custom_form();
        fill_custom_form(&mut state);
        state.apply_custom_models(vec![("proxy-mystery-v1".into(), "".into(), 128_000)], None);
        assert!(!state.custom.as_ref().unwrap().models[0].supports_reasoning_effort);
        let _ = handle_vendor_login_key(&mut state, &key(KeyCode::Char('r')));
        assert!(state.custom.as_ref().unwrap().models[0].supports_reasoning_effort);
        match handle_vendor_login_key(&mut state, &key(KeyCode::Enter)) {
            VendorLoginOutcome::SaveCustom { models, .. } => {
                assert!(models[0].supports_reasoning_effort);
                assert_eq!(models[0].api_model, "proxy-mystery-v1");
            }
            other => panic!("expected SaveCustom, got {other:?}"),
        }
    }
}
