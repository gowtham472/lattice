//! Compares two CBOMs for the CI gate. Works on CBOMs rather than reports so a baseline can be
//! any archived, signed CBOM: the `lattice:tier` and `lattice:priority` properties carry what
//! the gate needs, and asset `bom-ref`s are stable identities across runs.

use lattice_cbom::{Bom, Component};
use lattice_risk::Tier;
use serde::Serialize;
use std::collections::BTreeMap;

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize)]
#[serde(rename_all = "kebab-case")]
pub enum ChangeKind {
    /// Not in the baseline.
    Added,
    /// In both, at a higher tier than before.
    Worsened,
    /// In both, at a lower tier than before.
    Improved,
    /// In the baseline, gone now.
    Removed,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct Change {
    pub kind: ChangeKind,
    pub bom_ref: String,
    pub name: String,
    pub component: String,
    pub tier: Option<Tier>,
    pub previous_tier: Option<Tier>,
    /// Whether this change fails the gate.
    pub regression: bool,
    pub reason: String,
}

#[derive(Debug, Clone, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct Comparison {
    pub threshold: Tier,
    pub changes: Vec<Change>,
}

impl Comparison {
    pub fn regressions(&self) -> impl Iterator<Item = &Change> {
        self.changes.iter().filter(|change| change.regression)
    }

    pub fn passed(&self) -> bool {
        self.regressions().next().is_none()
    }
}

struct Entry<'a> {
    name: &'a str,
    component: &'a str,
    tier: Option<Tier>,
}

fn entries(bom: &Bom) -> BTreeMap<&str, Entry<'_>> {
    bom.components
        .iter()
        .filter(|c| c.component_type == "cryptographic-asset")
        .filter_map(|c| {
            Some((
                c.bom_ref.as_deref()?,
                Entry {
                    name: &c.name,
                    component: property(c, "component").unwrap_or("."),
                    tier: property(c, "tier").and_then(Tier::parse),
                },
            ))
        })
        .collect()
}

fn property<'a>(component: &'a Component, name: &str) -> Option<&'a str> {
    let wanted = format!("{}{name}", lattice_cbom::PROPERTY_NAMESPACE);
    component
        .properties
        .iter()
        .find(|p| p.name == wanted)
        .map(|p| p.value.as_str())
}

/// Every difference between `baseline` and `current`. A change is a regression when it adds an
/// asset at or above `threshold`, or raises an existing asset into or within that band.
pub fn compare(baseline: &Bom, current: &Bom, threshold: Tier) -> Comparison {
    let before = entries(baseline);
    let after = entries(current);
    let label = |tier: Option<Tier>| tier.map_or("unscored", Tier::as_str);
    let mut changes = Vec::new();

    for (bom_ref, now) in &after {
        let at_threshold = now.tier.is_some_and(|tier| tier >= threshold);
        match before.get(bom_ref) {
            None => changes.push(Change {
                kind: ChangeKind::Added,
                bom_ref: (*bom_ref).to_owned(),
                name: now.name.to_owned(),
                component: now.component.to_owned(),
                tier: now.tier,
                previous_tier: None,
                regression: at_threshold,
                reason: format!("new {} asset", label(now.tier)),
            }),
            Some(then) if now.tier > then.tier => changes.push(Change {
                kind: ChangeKind::Worsened,
                bom_ref: (*bom_ref).to_owned(),
                name: now.name.to_owned(),
                component: now.component.to_owned(),
                tier: now.tier,
                previous_tier: then.tier,
                regression: at_threshold,
                reason: format!("tier rose from {} to {}", label(then.tier), label(now.tier)),
            }),
            Some(then) if now.tier < then.tier => changes.push(Change {
                kind: ChangeKind::Improved,
                bom_ref: (*bom_ref).to_owned(),
                name: now.name.to_owned(),
                component: now.component.to_owned(),
                tier: now.tier,
                previous_tier: then.tier,
                regression: false,
                reason: format!("tier fell from {} to {}", label(then.tier), label(now.tier)),
            }),
            Some(_) => {}
        }
    }
    for (bom_ref, then) in &before {
        if !after.contains_key(bom_ref) {
            changes.push(Change {
                kind: ChangeKind::Removed,
                bom_ref: (*bom_ref).to_owned(),
                name: then.name.to_owned(),
                component: then.component.to_owned(),
                tier: None,
                previous_tier: then.tier,
                regression: false,
                reason: format!("{} asset no longer present", label(then.tier)),
            });
        }
    }
    changes.sort_by(|a, b| {
        b.regression
            .cmp(&a.regression)
            .then(b.tier.cmp(&a.tier))
            .then_with(|| a.bom_ref.cmp(&b.bom_ref))
    });
    Comparison { threshold, changes }
}
