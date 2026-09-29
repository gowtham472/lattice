//! The executive report: a PDF for people who decide, rendered from a LATTICE report.
//!
//! It answers four questions in order: how exposed are we, where is the risk, what will fixing
//! it cost against the national timeline, and what do we fix first. It closes with the method
//! and the exact inputs, including a digest of the report it was rendered from.
//!
//! Rendering is deterministic: the same report JSON always gives the same bytes, so a PDF can be
//! signed (`PDF_SIGNATURE_CONTEXT`) and re-rendered later to check it.

pub mod pdf;
pub mod view;

use pdf::{Color, Font, Info, PAGE_HEIGHT, PAGE_WIDTH, Page, fit, text_width, wrap};
use std::collections::BTreeMap;
use thiserror::Error;
use view::{REPORT_FORMAT, Report};

/// Context string for detached ML-DSA-65 signatures over executive-report PDFs.
pub const PDF_SIGNATURE_CONTEXT: &str = "lattice-report-pdf-v1";

#[derive(Debug, Error)]
pub enum ReportError {
    #[error("not a LATTICE report: {0}")]
    Parse(String),
    #[error("unsupported report format {0:?}; expected {REPORT_FORMAT}")]
    Format(String),
}

const MARGIN: f32 = 48.0;
const WIDTH: f32 = PAGE_WIDTH - 2.0 * MARGIN;
const TOP: f32 = PAGE_HEIGHT - 82.0;
const BOTTOM: f32 = 70.0;

// The palette of the LATTICE site and cockpit: ink on warm paper, one orange accent.
const INK: Color = Color(0.071, 0.071, 0.071);
const MUTED: Color = Color(0.333, 0.329, 0.31);
const FAINT: Color = Color(0.549, 0.545, 0.522);
const LINE: Color = Color(0.894, 0.89, 0.871);
const DASH: Color = Color(0.796, 0.788, 0.761);
const PAPER: Color = Color(0.957, 0.957, 0.945);
const ACCENT: Color = Color(1.0, 0.357, 0.102);
const ACCENT_WASH: Color = Color(1.0, 0.941, 0.91);

const TIERS: [&str; 5] = ["critical", "high", "medium", "low", "info"];

fn tier_color(tier: &str) -> Color {
    match tier {
        "critical" => Color(0.847, 0.208, 0.165),
        "high" => Color(0.91, 0.439, 0.047),
        "medium" => Color(0.769, 0.569, 0.008),
        "low" => Color(0.18, 0.42, 1.0),
        _ => FAINT,
    }
}

fn title_case(text: &str) -> String {
    let mut chars = text.chars();
    chars.next().map_or_else(String::new, |first| {
        first.to_uppercase().collect::<String>() + chars.as_str()
    })
}

/// `1.0` → `1`, `0.75` → `0.8`: one decimal, none when whole.
fn decimal(value: f64) -> String {
    let rounded = (value * 10.0).round() / 10.0;
    if rounded.fract() == 0.0 {
        format!("{rounded:.0}")
    } else {
        format!("{rounded:.1}")
    }
}

fn plural(count: usize, one: &str, many: &str) -> String {
    format!("{count} {}", if count == 1 { one } else { many })
}

/// `2026-09-23T00:00:00Z` → `D:20260923000000Z`.
fn pdf_date(rfc3339: &str) -> Option<String> {
    let digits: String = rfc3339.chars().filter(char::is_ascii_digit).collect();
    (digits.len() >= 14).then(|| format!("D:{}Z", &digits[..14]))
}

/// The LATTICE mark: a lattice of nodes, the one that matters in orange. `size` is its width;
/// (`x`, `y`) is its bottom-left corner.
fn mark(page: &mut Page, x: f32, y: f32, size: f32) {
    let unit = size / 24.0;
    let at = |u: f32, v: f32| (x + u * unit, y + (24.0 - v) * unit);
    for (a, b) in [
        ((4.0, 4.0), (20.0, 4.0)),
        ((4.0, 12.0), (20.0, 12.0)),
        ((4.0, 20.0), (20.0, 20.0)),
        ((4.0, 4.0), (4.0, 20.0)),
        ((12.0, 4.0), (12.0, 20.0)),
        ((20.0, 4.0), (20.0, 20.0)),
        ((4.0, 4.0), (20.0, 20.0)),
    ] {
        page.line(at(a.0, a.1), at(b.0, b.1), 1.5 * unit, DASH);
    }
    for (u, v) in [
        (4.0, 4.0),
        (12.0, 4.0),
        (20.0, 4.0),
        (4.0, 12.0),
        (20.0, 12.0),
        (4.0, 20.0),
        (12.0, 20.0),
        (20.0, 20.0),
    ] {
        let (cx, cy) = at(u, v);
        page.circle(cx, cy, 2.2 * unit, INK);
    }
    let (cx, cy) = at(12.0, 12.0);
    page.circle(cx, cy, 3.0 * unit, ACCENT);
}

#[derive(Clone, Copy, PartialEq)]
enum Align {
    Left,
    Right,
}

struct Column {
    title: &'static str,
    width: f32,
    align: Align,
}

#[derive(Clone)]
struct Cell {
    text: String,
    font: Font,
    color: Color,
    /// Drawn as a coloured dot and a word in that colour, the way the cockpit shows tiers.
    dot: Option<Color>,
}

impl Cell {
    fn plain(text: impl Into<String>) -> Self {
        Self {
            text: text.into(),
            font: Font::Regular,
            color: INK,
            dot: None,
        }
    }

    fn mono(text: impl Into<String>) -> Self {
        Self {
            font: Font::Mono,
            ..Self::plain(text)
        }
    }

    fn muted(text: impl Into<String>) -> Self {
        Self {
            color: MUTED,
            ..Self::plain(text)
        }
    }

    fn tier(tier: &str) -> Self {
        let color = tier_color(tier);
        Self {
            font: Font::Bold,
            color,
            dot: Some(color),
            ..Self::plain(title_case(tier))
        }
    }
}

/// Lays content out top to bottom, starting new pages as needed.
struct Composer {
    pages: Vec<Page>,
    y: f32,
}

impl Composer {
    fn new() -> Self {
        Self {
            pages: vec![Page::default()],
            y: TOP,
        }
    }

    fn page(&mut self) -> &mut Page {
        self.pages.last_mut().expect("there is always a page")
    }

    fn new_page(&mut self) {
        self.pages.push(Page::default());
        self.y = TOP;
    }

    /// Starts a new page unless `height` still fits on this one.
    fn room(&mut self, height: f32) -> bool {
        if self.y - height < BOTTOM {
            self.new_page();
            return false;
        }
        true
    }

    fn gap(&mut self, height: f32) {
        self.y -= height;
    }

    /// A section heading over a dashed blueprint rule, moved to the next page with its section
    /// unless `keep` points of the section's opening content fit below it.
    fn heading(&mut self, text: &str, keep: f32) {
        self.room(48.0 + keep);
        self.gap(24.0);
        let y = self.y;
        self.page().text(MARGIN, y, 15.0, Font::Bold, INK, text);
        self.gap(9.0);
        let y = self.y;
        self.page()
            .dashed((MARGIN, y), (MARGIN + WIDTH, y), 0.7, DASH, 3.0, 3.0);
        self.gap(15.0);
    }

    fn paragraph(&mut self, text: &str, size: f32, font: Font, color: Color) {
        let leading = size * 1.45;
        for line in wrap(text, font, size, WIDTH) {
            self.room(leading);
            let y = self.y - size;
            self.page().text(MARGIN, y, size, font, color, &line);
            self.gap(leading);
        }
    }

    fn bullet(&mut self, text: &str) {
        let size = 10.0;
        let leading = 14.5;
        let lines = wrap(text, Font::Regular, size, WIDTH - 16.0);
        self.room(leading * lines.len().min(3) as f32);
        for (i, line) in lines.iter().enumerate() {
            self.room(leading);
            let y = self.y - size;
            if i == 0 {
                self.page().circle(MARGIN + 3.5, y + 3.3, 2.6, ACCENT);
            }
            self.page()
                .text(MARGIN + 16.0, y, size, Font::Regular, INK, line);
            self.gap(leading);
        }
        self.gap(4.0);
    }

    /// A tinted card with an orange edge: the statement a section turns on.
    fn callout(&mut self, title: &str, body: &str) {
        let size = 9.0;
        let leading = 13.0;
        let lines = wrap(body, Font::Regular, size, WIDTH - 32.0);
        let height = 44.0 + (lines.len() as f32 - 1.0) * leading;
        self.room(height + 10.0);
        let top = self.y;
        self.page()
            .round_rect(MARGIN, top - height, WIDTH, height, 10.0, ACCENT_WASH);
        self.page()
            .round_rect(MARGIN, top - height, 3.5, height, 1.75, ACCENT);
        let title = fit(title, Font::Bold, 10.5, WIDTH - 32.0);
        self.page()
            .text(MARGIN + 16.0, top - 18.0, 10.5, Font::Bold, INK, &title);
        for (i, line) in lines.iter().enumerate() {
            self.page().text(
                MARGIN + 16.0,
                top - 33.0 - i as f32 * leading,
                size,
                Font::Regular,
                MUTED,
                line,
            );
        }
        self.gap(height + 12.0);
    }

    fn table(&mut self, columns: &[Column], rows: &[Vec<Cell>]) {
        const SIZE: f32 = 8.5;
        const LEADING: f32 = 11.0;
        const PAD: f32 = 5.0;
        let header = |composer: &mut Self| {
            composer.room(20.0 + LEADING + 2.0 * PAD);
            let y = composer.y - 10.0;
            let mut x = MARGIN;
            for column in columns {
                match column.align {
                    Align::Left => {
                        composer
                            .page()
                            .text(x + PAD, y, 8.0, Font::Bold, FAINT, column.title);
                    }
                    Align::Right => composer.page().text_right(
                        x + column.width - PAD,
                        y,
                        8.0,
                        Font::Bold,
                        FAINT,
                        column.title,
                    ),
                }
                x += column.width;
            }
            composer.gap(16.0);
            let y = composer.y;
            composer
                .page()
                .line((MARGIN, y), (MARGIN + WIDTH, y), 0.7, LINE);
        };
        header(self);
        for (index, row) in rows.iter().enumerate() {
            let wrapped: Vec<Vec<String>> = columns
                .iter()
                .zip(row)
                .map(|(column, cell)| {
                    if cell.dot.is_some() {
                        vec![cell.text.clone()]
                    } else {
                        wrap(&cell.text, cell.font, SIZE, column.width - 2.0 * PAD)
                    }
                })
                .collect();
            let lines = wrapped.iter().map(Vec::len).max().unwrap_or(1);
            let height = lines as f32 * LEADING + 2.0 * PAD;
            if !self.room(height) {
                header(self);
            }
            let top = self.y;
            let mut x = MARGIN;
            for ((column, cell), lines) in columns.iter().zip(row).zip(&wrapped) {
                for (i, line) in lines.iter().enumerate() {
                    let y = top - PAD - SIZE - i as f32 * LEADING + 1.0;
                    if let Some(color) = cell.dot {
                        self.page().circle(x + PAD + 3.0, y + 3.0, 3.0, color);
                        self.page()
                            .text(x + PAD + 10.0, y, SIZE, Font::Bold, color, line);
                        continue;
                    }
                    match column.align {
                        Align::Left => {
                            self.page()
                                .text(x + PAD, y, SIZE, cell.font, cell.color, line);
                        }
                        Align::Right => self.page().text_right(
                            x + column.width - PAD,
                            y,
                            SIZE,
                            cell.font,
                            cell.color,
                            line,
                        ),
                    }
                }
                x += column.width;
            }
            self.gap(height);
            if index + 1 < rows.len() {
                let y = self.y;
                self.page()
                    .dashed((MARGIN, y), (MARGIN + WIDTH, y), 0.5, LINE, 2.0, 2.0);
            }
        }
        self.gap(6.0);
    }

    /// Four headline figures on paper cards.
    fn figures(&mut self, figures: &[(String, String, Color)]) {
        let height = 78.0;
        self.room(height + 12.0);
        let gutter = 10.0;
        let width = (WIDTH - gutter * (figures.len() as f32 - 1.0)) / figures.len() as f32;
        let top = self.y;
        for (i, (value, label, color)) in figures.iter().enumerate() {
            let x = MARGIN + i as f32 * (width + gutter);
            self.page()
                .round_rect(x, top - height, width, height, 12.0, PAPER);
            self.page()
                .text(x + 14.0, top - 36.0, 27.0, Font::Bold, *color, value);
            for (j, line) in wrap(label, Font::Regular, 8.5, width - 26.0)
                .iter()
                .take(2)
                .enumerate()
            {
                self.page().text(
                    x + 14.0,
                    top - 52.0 - j as f32 * 10.5,
                    8.5,
                    Font::Regular,
                    MUTED,
                    line,
                );
            }
        }
        self.gap(height + 12.0);
    }

    /// One segmented bar split by tier, with a legend of dots.
    fn tier_bar(&mut self, counts: &BTreeMap<&str, usize>) {
        let total: usize = counts.values().sum();
        if total == 0 {
            return;
        }
        self.room(50.0);
        let top = self.y;
        let present: Vec<(&str, usize)> = TIERS
            .iter()
            .map(|tier| (*tier, counts.get(tier).copied().unwrap_or(0)))
            .filter(|(_, count)| *count > 0)
            .collect();
        let gap = 3.0;
        let usable = WIDTH - gap * (present.len() as f32 - 1.0);
        let mut x = MARGIN;
        for (tier, count) in &present {
            let width = usable * *count as f32 / total as f32;
            self.page()
                .round_rect(x, top - 14.0, width, 14.0, 4.0, tier_color(tier));
            x += width + gap;
        }
        let mut x = MARGIN;
        let y = top - 32.0;
        for tier in TIERS {
            let count = counts.get(tier).copied().unwrap_or(0);
            self.page().circle(x + 4.0, y + 3.2, 3.5, tier_color(tier));
            let label = format!("{} {count}", title_case(tier));
            self.page()
                .text(x + 12.0, y, 9.0, Font::Regular, INK, &label);
            x += 12.0 + text_width(&label, Font::Regular, 9.0) + 20.0;
        }
        self.gap(46.0);
    }

    /// Horizontal bars, one per labelled value, scaled to the largest.
    fn bars(&mut self, rows: &[(String, f64, String, Color)]) {
        let label_width = 170.0;
        let note_width = 110.0;
        let row = 22.0;
        let height = row * rows.len() as f32 + 6.0;
        self.room(height);
        let top = self.y;
        let max = rows.iter().map(|r| r.1).fold(0.0_f64, f64::max).max(1e-9);
        let track = WIDTH - label_width - note_width;
        for (i, (label, value, note, color)) in rows.iter().enumerate() {
            let y = top - 6.0 - i as f32 * row;
            self.page().text(
                MARGIN,
                y - 10.0,
                9.0,
                Font::Regular,
                INK,
                &fit(label, Font::Regular, 9.0, label_width - 10.0),
            );
            let x = MARGIN + label_width;
            self.page().round_rect(x, y - 13.0, track, 12.0, 6.0, PAPER);
            let width = (track * (*value / max) as f32).max(12.0);
            self.page()
                .round_rect(x, y - 13.0, width, 12.0, 6.0, *color);
            self.page().text(
                x + track + 10.0,
                y - 10.0,
                9.0,
                Font::Regular,
                MUTED,
                &fit(note, Font::Regular, 9.0, note_width - 10.0),
            );
        }
        self.gap(height + 6.0);
    }

    /// Running header and footer on every page, now that the page count is known.
    fn finish(mut self, subject: &str, generated: &str) -> Vec<Page> {
        let count = self.pages.len();
        for (i, page) in self.pages.iter_mut().enumerate() {
            let head = PAGE_HEIGHT - 42.0;
            mark(page, MARGIN, head - 3.0, 14.0);
            page.text(MARGIN + 20.0, head, 9.5, Font::Bold, INK, "LATTICE");
            page.text(
                MARGIN + 20.0 + text_width("LATTICE", Font::Bold, 9.5) + 6.0,
                head,
                9.0,
                Font::Regular,
                FAINT,
                "Quantum-readiness report",
            );
            page.text_right(
                MARGIN + WIDTH,
                head,
                9.0,
                Font::Regular,
                MUTED,
                &fit(subject, Font::Regular, 9.0, WIDTH / 2.0),
            );
            page.dashed(
                (MARGIN, head - 12.0),
                (MARGIN + WIDTH, head - 12.0),
                0.7,
                DASH,
                3.0,
                3.0,
            );
            page.dashed((MARGIN, 50.0), (MARGIN + WIDTH, 50.0), 0.7, DASH, 3.0, 3.0);
            page.text(
                MARGIN,
                36.0,
                8.0,
                Font::Regular,
                FAINT,
                &format!("Generated {generated} · deterministic rendering of the LATTICE report"),
            );
            page.text_right(
                MARGIN + WIDTH,
                36.0,
                8.0,
                Font::Bold,
                MUTED,
                &format!("Page {} of {count}", i + 1),
            );
        }
        self.pages
    }
}

/// Renders the executive report for a `lattice-report/1` JSON document.
pub fn executive_pdf(report_json: &[u8]) -> Result<Vec<u8>, ReportError> {
    let report: Report =
        serde_json::from_slice(report_json).map_err(|e| ReportError::Parse(e.to_string()))?;
    if report.format != REPORT_FORMAT {
        return Err(ReportError::Format(report.format));
    }
    let digest = blake3::hash(report_json).to_hex().to_string();
    let pages = compose(&report, &digest);
    let info = Info {
        title: format!("Quantum-readiness report: {}", report.subject),
        subject: "Cryptographic inventory, quantum risk and migration plan".into(),
        producer: format!("LATTICE {}", report.provenance.tool_version),
        created: pdf_date(&report.generated),
    };
    Ok(pdf::write(&info, &pages))
}

fn compose(report: &Report, digest: &str) -> Vec<Page> {
    let date = report.generated.get(..10).unwrap_or(&report.generated);
    let provenance = &report.provenance;
    let summary = &report.summary;
    let mut c = Composer::new();

    // title, on a paper card
    let meta = format!(
        "Assessed {date} · assessment year {} · Q-day window {}–{} · {} files scanned",
        provenance.assessment_year,
        provenance.q_day_earliest,
        provenance.q_day_latest,
        report.stats.files_scanned
    );
    let height = 104.0;
    let top = c.y;
    c.page()
        .round_rect(MARGIN, top - height, WIDTH, height, 14.0, PAPER);
    mark(c.page(), MARGIN + WIDTH - 62.0, top - height + 30.0, 40.0);
    c.page().text(
        MARGIN + 20.0,
        top - 36.0,
        21.0,
        Font::Bold,
        INK,
        "Quantum-readiness executive report",
    );
    c.page().text(
        MARGIN + 20.0,
        top - 60.0,
        15.0,
        Font::Bold,
        ACCENT,
        &fit(&report.subject, Font::Bold, 15.0, WIDTH - 110.0),
    );
    c.page().text(
        MARGIN + 20.0,
        top - 82.0,
        8.5,
        Font::Regular,
        MUTED,
        &fit(&meta, Font::Regular, 8.5, WIDTH - 110.0),
    );
    c.gap(height + 14.0);

    let mut tiers: BTreeMap<&str, usize> = BTreeMap::new();
    for asset in &report.assets {
        *tiers.entry(asset.assessment.tier.as_str()).or_default() += 1;
    }
    let urgent =
        tiers.get("critical").copied().unwrap_or(0) + tiers.get("high").copied().unwrap_or(0);
    c.figures(&[
        (
            summary.assets.to_string(),
            "cryptographic assets found".into(),
            INK,
        ),
        (
            summary.quantum_vulnerable.to_string(),
            "breakable by a quantum computer".into(),
            ACCENT,
        ),
        (
            summary.mosca_urgent.to_string(),
            "already too late by Mosca's inequality".into(),
            tier_color("critical"),
        ),
        (
            summary.broken_now.to_string(),
            "broken today, without a quantum computer".into(),
            tier_color("critical"),
        ),
    ]);

    c.heading("Key findings", 80.0);
    c.bullet(&format!(
        "{} of the {} cryptographic assets found use algorithms a quantum computer breaks. {} \
         fail Mosca's inequality for a Q-day as early as {}: the data they protect must stay \
         secret for longer than the time left once migration is accounted for, so traffic \
         recorded today is already at risk.",
        summary.quantum_vulnerable,
        summary.assets,
        plural(summary.mosca_urgent, "asset", "assets"),
        provenance.q_day_earliest
    ));
    if summary.broken_now > 0 {
        c.bullet(&format!(
            "{} broken by classical attacks today, independent of quantum computing, and should \
             be fixed first.",
            if summary.broken_now == 1 {
                "1 asset is".to_owned()
            } else {
                format!("{} assets are", summary.broken_now)
            }
        ));
    }
    c.bullet(&format!(
        "{} rated critical or high priority; priority combines how exposed each asset is, how \
         long the data it protects must stay secret, how live it is, and how hard it is to change.",
        plural(urgent, "asset is", "assets are")
    ));
    if let Some(plan) = &report.plan {
        let team = plan
            .engineers_needed
            .map(|engineers| {
                format!(
                    " Meeting every deadline from {} takes {} engineer{} full-time.",
                    plan.assessment_year,
                    decimal(engineers),
                    if (engineers - 1.0).abs() < f64::EPSILON {
                        ""
                    } else {
                        "s"
                    }
                )
            })
            .unwrap_or_default();
        c.bullet(&format!(
            "Migration is estimated at {} person-weeks across {} changes, scheduled against the \
             {}.{team}{}",
            decimal(plan.total_person_weeks),
            report.roadmap.len(),
            plan.timeline,
            if plan.overdue {
                " At least one deadline has already passed with work outstanding."
            } else {
                ""
            }
        ));
    }

    c.heading("Risk by tier", 50.0);
    c.tier_bar(&tiers);

    c.heading("Where the risk is", 90.0);
    let mut components: BTreeMap<&str, (usize, usize, usize, u8)> = BTreeMap::new();
    for asset in &report.assets {
        let entry = components
            .entry(asset.asset.component.as_str())
            .or_default();
        entry.0 += 1;
        match asset.assessment.tier.as_str() {
            "critical" => entry.1 += 1,
            "high" => entry.2 += 1,
            _ => {}
        }
        entry.3 = entry.3.max(asset.assessment.priority);
    }
    let mut ranked: Vec<_> = components.into_iter().collect();
    ranked.sort_by(|a, b| b.1.3.cmp(&a.1.3).then(b.1.1.cmp(&a.1.1)).then(a.0.cmp(b.0)));
    let shown = ranked.len().min(12);
    let rows: Vec<Vec<Cell>> = ranked
        .iter()
        .take(shown)
        .map(|(component, (assets, critical, high, top))| {
            vec![
                Cell::plain(*component),
                Cell::plain(assets.to_string()),
                Cell::plain(critical.to_string()),
                Cell::plain(high.to_string()),
                Cell::mono(top.to_string()),
            ]
        })
        .collect();
    c.table(
        &[
            Column {
                title: "Component",
                width: 259.0,
                align: Align::Left,
            },
            Column {
                title: "Assets",
                width: 60.0,
                align: Align::Right,
            },
            Column {
                title: "Critical",
                width: 60.0,
                align: Align::Right,
            },
            Column {
                title: "High",
                width: 60.0,
                align: Align::Right,
            },
            Column {
                title: "Top priority",
                width: 60.0,
                align: Align::Right,
            },
        ],
        &rows,
    );
    if ranked.len() > shown {
        c.paragraph(
            &format!(
                "… and {} more components in the full report.",
                ranked.len() - shown
            ),
            8.5,
            Font::Regular,
            MUTED,
        );
    }

    if let Some(plan) = &report.plan {
        c.heading("Plan against the national timeline", 250.0);
        let team = plan
            .engineers_needed
            .map(|engineers| {
                format!(
                    " Meeting every deadline from {} takes {} engineer{} full-time.",
                    plan.assessment_year,
                    decimal(engineers),
                    if (engineers - 1.0).abs() < f64::EPSILON {
                        ""
                    } else {
                        "s"
                    }
                )
            })
            .unwrap_or_default();
        c.callout(
            &plan.timeline,
            &format!(
                "{} person-weeks of migration work across {} changes.{team}",
                decimal(plan.total_person_weeks),
                report.roadmap.len()
            ),
        );
        let bars: Vec<(String, f64, String, Color)> = plan
            .waves
            .iter()
            .map(|wave| {
                let due = wave
                    .due_year
                    .map_or_else(|| "no deadline".to_owned(), |year| format!("due {year}"));
                let color = match wave.due_year {
                    Some(_) if wave.overdue => tier_color("critical"),
                    Some(_) => ACCENT,
                    None => DASH,
                };
                (
                    wave.name.clone(),
                    wave.person_weeks,
                    format!("{} pw · {due}", decimal(wave.person_weeks)),
                    color,
                )
            })
            .collect();
        c.bars(&bars);
        c.paragraph(
            &format!(
                "Source: {}. Engineers are full-time equivalents needed from the start of {} to \
                 finish each wave, and every wave before it, by the end of its due year.",
                plan.reference, plan.assessment_year
            ),
            8.5,
            Font::Regular,
            MUTED,
        );
        c.gap(4.0);
        let rows: Vec<Vec<Cell>> = plan
            .waves
            .iter()
            .map(|wave| {
                let due = match wave.due_year {
                    Some(year) if wave.overdue => Cell {
                        color: tier_color("critical"),
                        font: Font::Bold,
                        ..Cell::plain(format!("{year} · overdue"))
                    },
                    Some(year) => Cell::plain(year.to_string()),
                    None => Cell::muted("no deadline"),
                };
                vec![
                    Cell::plain(wave.name.clone()),
                    Cell::plain(wave.items.to_string()),
                    Cell::mono(decimal(wave.person_weeks)),
                    due,
                    Cell::mono(if wave.due_year.is_some() {
                        decimal(wave.cumulative_person_weeks)
                    } else {
                        String::new()
                    }),
                    Cell::mono(wave.engineers_needed.map(decimal).unwrap_or_default()),
                ]
            })
            .collect();
        c.table(
            &[
                Column {
                    title: "Wave",
                    width: 179.0,
                    align: Align::Left,
                },
                Column {
                    title: "Items",
                    width: 44.0,
                    align: Align::Right,
                },
                Column {
                    title: "Person-weeks",
                    width: 74.0,
                    align: Align::Right,
                },
                Column {
                    title: "Due",
                    width: 70.0,
                    align: Align::Left,
                },
                Column {
                    title: "Work by then",
                    width: 70.0,
                    align: Align::Right,
                },
                Column {
                    title: "Engineers",
                    width: 62.0,
                    align: Align::Right,
                },
            ],
            &rows,
        );
    }

    c.heading("Fix first", 110.0);
    let due: BTreeMap<&str, Option<u16>> = report
        .roadmap
        .iter()
        .map(|item| (item.asset_id.as_str(), item.due_year))
        .collect();
    let mut first: Vec<_> = report
        .assets
        .iter()
        .filter(|a| a.recommendation.action != "retain")
        .collect();
    first.sort_by(|a, b| {
        b.assessment
            .priority
            .cmp(&a.assessment.priority)
            .then(a.asset.id.cmp(&b.asset.id))
    });
    let rows: Vec<Vec<Cell>> = first
        .iter()
        .take(15)
        .map(|asset| {
            vec![
                Cell::tier(&asset.assessment.tier),
                Cell::mono(asset.assessment.priority.to_string()),
                Cell {
                    font: Font::Bold,
                    ..Cell::plain(asset.name.clone())
                },
                Cell::muted(asset.asset.component.clone()),
                Cell::plain(format!(
                    "{} → {}",
                    title_case(&asset.recommendation.action),
                    asset.recommendation.target
                )),
                Cell::mono(
                    asset
                        .effort
                        .as_ref()
                        .map(|e| decimal(e.person_weeks))
                        .unwrap_or_default(),
                ),
                Cell::plain(
                    due.get(asset.asset.id.as_str())
                        .copied()
                        .flatten()
                        .map(|year| year.to_string())
                        .unwrap_or_default(),
                ),
            ]
        })
        .collect();
    c.table(
        &[
            Column {
                title: "Tier",
                width: 58.0,
                align: Align::Left,
            },
            Column {
                title: "Prio",
                width: 30.0,
                align: Align::Right,
            },
            Column {
                title: "Asset",
                width: 92.0,
                align: Align::Left,
            },
            Column {
                title: "Component",
                width: 88.0,
                align: Align::Left,
            },
            Column {
                title: "Action",
                width: 159.0,
                align: Align::Left,
            },
            Column {
                title: "Weeks",
                width: 38.0,
                align: Align::Right,
            },
            Column {
                title: "Due",
                width: 34.0,
                align: Align::Left,
            },
        ],
        &rows,
    );
    if first.len() > 15 {
        c.paragraph(
            &format!(
                "… and {} more changes in the full report and the CBOM.",
                first.len() - 15
            ),
            8.5,
            Font::Regular,
            MUTED,
        );
    }

    c.heading("Method and inputs", 120.0);
    c.paragraph(
        "LATTICE reads source code, binaries, certificates, keys, configuration, container \
         images and packet captures without executing or modifying them, and builds a graph \
         from entry points through code to the cryptography and the data it protects. Each asset \
         is scored for quantum breakability, harvest-now-decrypt-later or trust-now-forge-later \
         exposure, crypto-agility and Mosca's inequality; every score in the full report carries \
         its reasons. Effort estimates multiply a base per action by the surface changed, a \
         crypto-agility penalty, the spread across files and the criticality of the data; all \
         weights are in the versioned policy.",
        9.0,
        Font::Regular,
        INK,
    );
    c.gap(6.0);
    let knowledge = match (&provenance.knowledge_sequence, &provenance.knowledge_signer) {
        (Some(sequence), Some(signer)) => format!(
            "{} (bundle #{sequence}, signed by {signer})",
            provenance.knowledge_version
        ),
        (Some(sequence), None) => format!(
            "{} (#{sequence}, compiled in)",
            provenance.knowledge_version
        ),
        _ => provenance.knowledge_version.clone(),
    };
    let failures = report.failures.len();
    let rows = vec![
        vec![
            Cell::muted("Tool"),
            Cell::plain(format!("LATTICE {}", provenance.tool_version)),
        ],
        vec![Cell::muted("Knowledge"), Cell::plain(knowledge)],
        vec![
            Cell::muted("Rules and policy"),
            Cell::plain(format!(
                "rules {}, policy {}",
                provenance.rules_version, provenance.policy_version
            )),
        ],
        vec![
            Cell::muted("Q-day window"),
            Cell::plain(format!(
                "{}–{}, assessed from {}",
                provenance.q_day_earliest, provenance.q_day_latest, provenance.assessment_year
            )),
        ],
        vec![
            Cell::muted("Coverage"),
            Cell::plain(format!(
                "{} files, {} bytes; {}",
                report.stats.files_scanned,
                report.stats.bytes_scanned,
                if failures == 0 {
                    "no files failed to parse".to_owned()
                } else {
                    format!(
                        "{} could not be read (listed in the full report)",
                        plural(failures, "file", "files")
                    )
                }
            )),
        ],
        vec![
            Cell::muted("Rendered from"),
            Cell::mono(format!("report BLAKE3 {digest}")),
        ],
    ];
    c.table(
        &[
            Column {
                title: "Input",
                width: 110.0,
                align: Align::Left,
            },
            Column {
                title: "Value",
                width: WIDTH - 110.0,
                align: Align::Left,
            },
        ],
        &rows,
    );
    c.paragraph(
        "Verify this document with its detached ML-DSA-65 signature: \
         lattice verify <report.pdf> --public-key <trusted key>. Rendering is deterministic, \
         so the same report always gives the same PDF.",
        8.5,
        Font::Regular,
        MUTED,
    );

    c.finish(&report.subject, date)
}

#[cfg(test)]
mod tests;
