pub(in crate::app::dispatch) mod dashboard;
pub(in crate::app::dispatch) mod setters;
pub(in crate::app::dispatch) mod ui;

use crate::app::app_view::AppView;
use crate::app::dispatch::settings::ui::save_success_toast;
use crate::settings::SettingValue;

pub(in crate::app::dispatch) fn handle_setting_persisted(
    app: &mut AppView,
    key: &str,
    value: SettingValue,
) {
    if let ("dashboard_preview", SettingValue::Bool(enabled)) = (key, value) {
        // An older save must not close a preview the user has re-enabled.
        if app.current_ui.dashboard_preview_enabled() != enabled {
            return;
        }
        if let Some(dashboard) = app.dashboard.as_mut() {
            dashboard.set_preview_enabled(enabled, &mut app.agents);
        }
        app.show_toast(&save_success_toast("Dashboard preview", enabled));
    }
}
