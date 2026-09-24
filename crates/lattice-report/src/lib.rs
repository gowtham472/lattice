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
const TOP: f32 = PAGE_HEIGHT - 70.0;
const BOTTOM: f32 = 64.0;

const INK: Color = Color(0.1, 0.12, 0.16);
const MUTED: Color = Color(0.38, 0.41, 0.47);
const RULE: Color = Color(0.82, 0.84, 0.87);
const PANEL: Color = Color(0.95, 0.96, 0.97);
const WHITE: Color = Color(1.0, 1.0, 1.0);
const ACCENT: Color = Color(0.09, 0.4, 0.69);

const TIERS: [&str; 5] = ["critical", "high", "medium", "low", "info"];

fn tier_color(tier: &str) -> Color {
    match tier {
        "critical" => Color(0.74, 0.1, 0.14),
        "high" => Color(0.86, 0.38, 0.05),
        "medium" => Color(0.78, 0.58, 0.0),
        "low" => Color(0.2, 0.55, 0.32),
        _ => Color(0.5, 0.54, 0.6),
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
    /// Drawn as a coloured chip with white text instead of plain text.
    chip: Option<Color>,
}

impl Cell {
    fn plain(text: impl Into<String>) -> Self {
        Self {
            text: text.into(),
            font: Font::Regular,
            color: INK,
            chip: None,
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

    fn chip(text: impl Into<String>, color: Color) -> Self {
        Self {
            font: Font::Bold,
            chip: Some(color),
            ..Self::plain(text)
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

    /// A section heading, moved to the next page with its section unless `keep` points of the
    /// section's opening content fit below it.
    fn heading(&mut self, text: &str, keep: f32) {
        self.room(41.0 + keep);
        self.gap(20.0);
        let y = self.y;
        self.page().text(MARGIN, y, 13.0, Font::Bold, INK, text);
        self.gap(7.0);
        let y = self.y;
        self.page()
            .line((MARGIN, y), (MARGIN + WIDTH, y), 0.6, RULE);
        self.gap(14.0);
    }

    fn paragraph(&mut self, text: &str, size: f32, font: Font, color: Color) {
        let leading = size * 1.4;
        for line in wrap(text, font, size, WIDTH) {
            self.room(leading);
            let y = self.y - size;
            self.page().text(MARGIN, y, size, font, color, &line);
            self.gap(leading);
        }
    }

    fn bullet(&mut self, text: &str) {
        let size = 10.0;
        let leading = 14.0;
        let lines = wrap(text, Font::Regular, size, WIDTH - 14.0);
        self.room(leading * lines.len().min(3) as f32);
        for (i, line) in lines.iter().enumerate() {
            self.room(leading);
            let y = self.y - size;
            if i == 0 {
                self.page()
                    .text(MARGIN + 2.0, y, size, Font::Bold, ACCENT, "•");
            }
            self.page()
                .text(MARGIN + 14.0, y, size, Font::Regular, INK, line);
            self.gap(leading);
        }
        self.gap(3.0);
    }

    fn table(&mut self, columns: &[Column], rows: &[Vec<Cell>]) {
        const SIZE: f32 = 8.5;
        const LEADING: f32 = 11.0;
        const PAD: f32 = 4.0;
        let header = |composer: &mut Self| {
            composer.room(18.0 + LEADING + 2.0 * PAD);
            let y = composer.y - 10.0;
            let mut x = MARGIN;
            for column in columns {
                let title = column.title.to_uppercase();
                match column.align {
                    Align::Left => composer
                        .page()
                        .text(x + PAD, y, 7.5, Font::Bold, MUTED, &title),
                    Align::Right => composer.page().text_right(
                        x + column.width - PAD,
                        y,
                        7.5,
                        Font::Bold,
                        MUTED,
                        &title,
                    ),
                }
                x += column.width;
            }
            composer.gap(15.0);
            let y = composer.y;
            composer
                .page()
                .line((MARGIN, y), (MARGIN + WIDTH, y), 0.6, RULE);
        };
        header(self);
        for (index, row) in rows.iter().enumerate() {
            let wrapped: Vec<Vec<String>> = columns
                .iter()
                .zip(row)
                .map(|(column, cell)| {
                    if cell.chip.is_some() {
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
            if index % 2 == 1 {
                self.page().rect(MARGIN, top - height, WIDTH, height, PANEL);
            }
            let mut x = MARGIN;
            for ((column, cell), lines) in columns.iter().zip(row).zip(&wrapped) {
                for (i, line) in lines.iter().enumerate() {
                    let y = top - PAD - SIZE - i as f32 * LEADING + 1.0;
                    if let Some(color) = cell.chip {
                        let width = text_width(line, Font::Bold, 7.0) + 8.0;
                        self.page().rect(x + PAD, y - 2.5, width, 10.5, color);
                        self.page()
                            .text(x + PAD + 4.0, y, 7.0, Font::Bold, WHITE, line);
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
        }
        self.gap(4.0);
    }

    /// Four headline figures in boxes.
    fn figures(&mut self, figures: &[(String, String, Color)]) {
        let height = 66.0;
        self.room(height + 10.0);
        let gutter = 10.0;
        let width = (WIDTH - gutter * (figures.len() as f32 - 1.0)) / figures.len() as f32;
        let top = self.y;
        for (i, (value, label, color)) in figures.iter().enumerate() {
            let x = MARGIN + i as f32 * (width + gutter);
            self.page().rect(x, top - height, width, height, PANEL);
            self.page().rect(x, top - height, 3.0, height, *color);
            self.page()
                .text(x + 12.0, top - 30.0, 22.0, Font::Bold, INK, value);
            for (j, line) in wrap(label, Font::Regular, 8.5, width - 20.0)
                .iter()
                .take(2)
                .enumerate()
            {
                self.page().text(
                    x + 12.0,
                    top - 45.0 - j as f32 * 10.0,
                    8.5,
                    Font::Regular,
                    MUTED,
                    line,
                );
            }
        }
        self.gap(height + 10.0);
    }

    /// One bar split by tier, with a legend.
    fn tier_bar(&mut self, counts: &BTreeMap<&str, usize>) {
        let total: usize = counts.values().sum();
        if total == 0 {
            return;
        }
        self.room(48.0);
        let top = self.y;
        let mut x = MARGIN;
        for tier in TIERS {
            let count = counts.get(tier).copied().unwrap_or(0);
            let width = WIDTH * count as f32 / total as f32;
            if width > 0.0 {
                self.page()
                    .rect(x, top - 14.0, width, 14.0, tier_color(tier));
                x += width;
            }
        }
        let mut x = MARGIN;
        let y = top - 30.0;
        for tier in TIERS {
            let count = counts.get(tier).copied().unwrap_or(0);
            self.page().rect(x, y - 1.0, 8.0, 8.0, tier_color(tier));
            let label = format!("{} {count}", title_case(tier));
            self.page()
                .text(x + 12.0, y, 9.0, Font::Regular, INK, &label);
            x += 12.0 + text_width(&label, Font::Regular, 9.0) + 18.0;
        }
        self.gap(44.0);
    }

    /// Running header and footer on every page, now that the page count is known.
    fn finish(mut self, subject: &str, generated: &str) -> Vec<Page> {
        let count = self.pages.len();
        for (i, page) in self.pages.iter_mut().enumerate() {
            let head = PAGE_HEIGHT - 36.0;
            page.text(
                MARGIN,
                head,
                8.0,
                Font::Bold,
                ACCENT,
                "LATTICE · Quantum-readiness report",
            );
            page.text_right(
                MARGIN + WIDTH,
                head,
                8.0,
                Font::Regular,
                MUTED,
                &fit(subject, Font::Regular, 8.0, WIDTH / 2.0),
            );
            page.line(
                (MARGIN, head - 8.0),
                (MARGIN + WIDTH, head - 8.0),
                0.6,
                RULE,
            );
            page.line((MARGIN, 48.0), (MARGIN + WIDTH, 48.0), 0.6, RULE);
            page.text(
                MARGIN,
                36.0,
                8.0,
                Font::Regular,
                MUTED,
                &format!("Generated {generated} · deterministic rendering of the LATTICE report"),
            );
            page.text_right(
                MARGIN + WIDTH,
                36.0,
                8.0,
                Font::Regular,
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

    // title
    c.paragraph("Quantum-readiness executive report", 22.0, Font::Bold, INK);
    c.gap(2.0);
    c.paragraph(&report.subject, 14.0, Font::Bold, ACCENT);
    c.paragraph(
        &format!(
            "Assessed {date} · assessment year {} · Q-day window {}–{} · {} files scanned",
            provenance.assessment_year,
            provenance.q_day_earliest,
            provenance.q_day_latest,
            report.stats.files_scanned
        ),
        9.0,
        Font::Regular,
        MUTED,
    );
    c.gap(14.0);

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
            ACCENT,
        ),
        (
            summary.quantum_vulnerable.to_string(),
            "breakable by a quantum computer".into(),
            tier_color("high"),
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
        c.heading("Plan against the national timeline", 190.0);
        c.paragraph(&plan.timeline, 10.0, Font::Bold, INK);
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
                Cell::chip(
                    asset.assessment.tier.to_uppercase(),
                    tier_color(&asset.assessment.tier),
                ),
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
