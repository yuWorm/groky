//! Session context-window gears: buckets cut from a model's max window.
//!
//! Catalog `context_window` is the user max (clamped to the provider advertised
//! size). `/window` picks a gear ≤ that max for the live session.

pub const GEAR_128K: u64 = 128_000;
pub const GEAR_256K: u64 = 256_000;
pub const GEAR_512K: u64 = 512_000;
pub const GEAR_1024K: u64 = 1_024_000;

const GEAR_STEPS: &[u64] = &[GEAR_128K, GEAR_256K, GEAR_512K, GEAR_1024K];

/// Compact-threshold percents offered in the vendor model list. `None` means inherit.
pub const THRESHOLD_STEPS: &[u8] = &[70, 75, 80, 85, 90, 95];

/// Gears available under `max`, always including `max` itself.
///
/// 128k is omitted when `max >= 512k` so large-window models are not cluttered
/// with a tiny first rung.
pub fn gears_for_max(max: u64) -> Vec<u64> {
    if max == 0 {
        return Vec::new();
    }
    let skip_128k = max >= GEAR_512K;
    let mut gears: Vec<u64> = GEAR_STEPS
        .iter()
        .copied()
        .filter(|&g| g < max && !(skip_128k && g == GEAR_128K))
        .collect();
    gears.push(max);
    gears
}

/// Compact-trigger budget for `window` at `threshold_percent`.
pub fn compact_budget(window: u64, threshold_percent: u8) -> u64 {
    window.saturating_mul(u64::from(threshold_percent.min(100))) / 100
}

pub fn format_window(tokens: u64) -> String {
    if tokens == 0 {
        return "0".to_string();
    }
    if tokens % 1_000_000 == 0 {
        format!("{}M", tokens / 1_000_000)
    } else if tokens % 1_000 == 0 {
        format!("{}k", tokens / 1_000)
    } else {
        tokens.to_string()
    }
}

/// Parse `256k`, `512K`, `1M`, `1.05M`, `256000`, or `max`.
pub fn parse_window_arg(raw: &str, max: u64) -> Option<u64> {
    let s = raw.trim();
    if s.is_empty() {
        return None;
    }
    if s.eq_ignore_ascii_case("max") {
        return (max > 0).then_some(max);
    }
    let mut lower: String = s
        .chars()
        .filter(|c| !c.is_whitespace() && *c != '_' && *c != ',')
        .collect::<String>()
        .to_ascii_lowercase();
    if let Some(stripped) = lower.strip_suffix("tokens") {
        lower = stripped.to_string();
    }
    let (num, multiplier) = if let Some(rest) = lower.strip_suffix('m') {
        (rest, 1_000_000.0_f64)
    } else if let Some(rest) = lower.strip_suffix('k') {
        (rest, 1_000.0)
    } else {
        (lower.as_str(), 1.0)
    };
    if num.is_empty() {
        return None;
    }
    let n: f64 = num.parse().ok()?;
    if !n.is_finite() || n <= 0.0 {
        return None;
    }
    let tokens = (n * multiplier).round();
    if tokens < 1.0 || tokens > u64::MAX as f64 {
        return None;
    }
    Some(tokens as u64)
}

/// Snap `wanted` onto a gear of `max`. Exact matches win; otherwise the
/// smallest gear that can hold `wanted`, else `max`.
pub fn snap_to_gear(wanted: u64, max: u64) -> Option<u64> {
    let gears = gears_for_max(max);
    if gears.is_empty() {
        return None;
    }
    if let Some(&exact) = gears.iter().find(|&&g| g == wanted) {
        return Some(exact);
    }
    gears
        .iter()
        .copied()
        .find(|&g| g >= wanted)
        .or_else(|| gears.last().copied())
}

pub fn cycle_gear(current: u64, max: u64, forward: bool) -> u64 {
    let gears = gears_for_max(max);
    if gears.is_empty() {
        return max.max(1);
    }
    if let Some(i) = gears.iter().position(|&g| g == current) {
        let next = if forward {
            (i + 1) % gears.len()
        } else {
            (i + gears.len() - 1) % gears.len()
        };
        return gears.get(next).copied().unwrap_or(max);
    }
    if forward {
        gears
            .iter()
            .copied()
            .find(|&g| g > current)
            .or_else(|| gears.first().copied())
            .unwrap_or(max)
    } else {
        gears
            .iter()
            .copied()
            .rev()
            .find(|&g| g < current)
            .or_else(|| gears.last().copied())
            .unwrap_or(max)
    }
}

pub fn cycle_threshold(current: Option<u8>, forward: bool) -> Option<u8> {
    let mut steps: Vec<Option<u8>> = vec![None];
    steps.extend(THRESHOLD_STEPS.iter().copied().map(Some));
    let i = steps.iter().position(|s| *s == current).unwrap_or(0);
    let next = if forward {
        (i + 1) % steps.len()
    } else {
        (i + steps.len() - 1) % steps.len()
    };
    steps.get(next).copied().flatten()
}

pub fn format_threshold(threshold: Option<u8>) -> String {
    match threshold {
        Some(p) => format!("{p}%"),
        None => "inherit".to_string(),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn gears_include_max_and_skip_128k_on_large_windows() {
        assert_eq!(gears_for_max(0), Vec::<u64>::new());
        assert_eq!(gears_for_max(GEAR_128K), vec![GEAR_128K]);
        assert_eq!(gears_for_max(200_000), vec![GEAR_128K, 200_000]);
        assert_eq!(gears_for_max(400_000), vec![GEAR_128K, GEAR_256K, 400_000]);
        assert_eq!(gears_for_max(GEAR_512K), vec![GEAR_256K, GEAR_512K]);
        assert_eq!(
            gears_for_max(1_050_000),
            vec![GEAR_256K, GEAR_512K, GEAR_1024K, 1_050_000]
        );
    }

    #[test]
    fn parse_and_format_roundtrip_common_gears() {
        assert_eq!(parse_window_arg("256k", 1_000_000), Some(GEAR_256K));
        assert_eq!(parse_window_arg("512K", 1_000_000), Some(GEAR_512K));
        assert_eq!(parse_window_arg("1m", 2_000_000), Some(1_000_000));
        assert_eq!(parse_window_arg("1M", 2_000_000), Some(1_000_000));
        assert_eq!(parse_window_arg("1.05M", 2_000_000), Some(1_050_000));
        assert_eq!(parse_window_arg("1.5m", 2_000_000), Some(1_500_000));
        assert_eq!(parse_window_arg("256 k", 1_000_000), Some(GEAR_256K));
        assert_eq!(parse_window_arg("256000", 1_000_000), Some(256_000));
        assert_eq!(parse_window_arg("1,050,000", 2_000_000), Some(1_050_000));
        assert_eq!(parse_window_arg("256k tokens", 1_000_000), Some(GEAR_256K));
        assert_eq!(parse_window_arg("max", 1_050_000), Some(1_050_000));
        assert_eq!(parse_window_arg("", 1_000_000), None);
        assert_eq!(parse_window_arg("bogus", 1_000_000), None);
        assert_eq!(format_window(GEAR_256K), "256k");
        assert_eq!(format_window(1_000_000), "1M");
        assert_eq!(format_window(1_050_000), "1050k");
    }

    #[test]
    fn snap_and_cycle_gears() {
        let max = 1_050_000;
        assert_eq!(snap_to_gear(GEAR_256K, max), Some(GEAR_256K));
        assert_eq!(snap_to_gear(200_000, max), Some(GEAR_256K));
        assert_eq!(snap_to_gear(300_000, max), Some(GEAR_512K));
        assert_eq!(cycle_gear(GEAR_256K, max, true), GEAR_512K);
        assert_eq!(cycle_gear(max, max, true), GEAR_256K);
        assert_eq!(cycle_gear(GEAR_256K, max, false), max);
    }

    #[test]
    fn threshold_cycle_includes_inherit() {
        assert_eq!(cycle_threshold(None, true), Some(70));
        assert_eq!(cycle_threshold(Some(95), true), None);
        assert_eq!(cycle_threshold(Some(70), false), None);
        assert_eq!(format_threshold(None), "inherit");
        assert_eq!(format_threshold(Some(85)), "85%");
    }

    #[test]
    fn compact_budget_is_percent_of_window() {
        assert_eq!(compact_budget(256_000, 80), 204_800);
        assert_eq!(compact_budget(100, 0), 0);
    }
}
