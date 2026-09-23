//! The crypto data-flow graph: which code reaches which cryptography, from which entry points,
//! protecting which data.
//!
//! Built from collector facts, not guesses. Functions and their calls come from the syntax tree;
//! entry points from framework annotations, route registrations, `main` and TLS listeners. A
//! breadth-first search from entry points (most exposed first) records, for every reachable
//! function, the path that reaches it, so every "reachable" verdict can be printed as a chain an
//! analyst can check in the code.
//!
//! Unreached is not "dead": frameworks we do not model can still call code, so an unreached asset
//! receives the policy's default exposure and says so.

use lattice_classify::DataClassification;
use lattice_core::policy::{Criticality, Policy};
use lattice_core::{
    CallFact, CryptoAsset, EntryBinding, EntryKind, EntryPoint, Finding, FunctionFact, LibraryFact,
    Surface,
};
use petgraph::Direction::Outgoing;
use petgraph::stable_graph::{NodeIndex, StableDiGraph};
use petgraph::visit::{EdgeRef, IntoEdgeReferences};
use serde::Serialize;
use std::collections::{BTreeMap, BTreeSet, HashMap, VecDeque};

/// A call name matching more than this many functions in scope is treated as unresolvable rather
/// than fanned out, so one common name (`get`, `run`) cannot connect the whole program.
const MAX_CALL_TARGETS: usize = 8;

#[derive(Debug, Clone, PartialEq, Serialize)]
#[serde(
    tag = "type",
    rename_all = "camelCase",
    rename_all_fields = "camelCase"
)]
pub enum Node {
    Component {
        id: String,
    },
    Entry {
        id: String,
        kind: EntryKind,
        detail: String,
    },
    Function {
        id: String,
        name: String,
        path: String,
        line: u64,
    },
    Crypto {
        id: String,
        name: String,
        asset_type: String,
    },
    Data {
        id: String,
        class: String,
        secrecy_lifetime_years: f64,
        criticality: Criticality,
    },
    Library {
        id: String,
        name: String,
        version: Option<String>,
        pqc_capable: bool,
    },
}

impl Node {
    pub fn id(&self) -> &str {
        match self {
            Self::Component { id }
            | Self::Entry { id, .. }
            | Self::Function { id, .. }
            | Self::Crypto { id, .. }
            | Self::Data { id, .. }
            | Self::Library { id, .. } => id,
        }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Serialize)]
#[serde(rename_all = "kebab-case")]
pub enum Edge {
    Contains,
    Exposes,
    Calls,
    Uses,
    Protects,
    DependsOn,
    Links,
}

/// Everything the risk engine needs about one asset's place in the system, with reasons.
#[derive(Debug, Clone, PartialEq, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct AssetContext {
    pub reachable: bool,
    /// Entry point that reaches the asset (the most exposed one, when several do).
    pub entry: Option<EntryPoint>,
    /// Function names from the entry point to the function using the asset.
    pub path: Vec<String>,
    pub exposure: f64,
    pub exposure_reason: String,
    pub data: DataClassification,
    /// Whether the classification was inherited from the component rather than observed.
    pub data_inherited: bool,
    pub pqc_ready_library: Option<String>,
}

#[derive(Debug, Clone, Serialize)]
pub struct SerializableGraph {
    pub nodes: Vec<Node>,
    pub edges: Vec<SerializableEdge>,
}

#[derive(Debug, Clone, Serialize)]
pub struct SerializableEdge {
    pub source: String,
    pub target: String,
    pub kind: Edge,
}

#[derive(Debug, Clone, Default, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct GraphStats {
    pub functions: usize,
    pub entry_points: usize,
    pub calls_resolved: usize,
    pub calls_unresolved: usize,
    pub reachable_functions: usize,
    pub reachable_assets: usize,
}

pub struct GraphInput<'a> {
    pub assets: &'a [CryptoAsset],
    pub functions: &'a [FunctionFact],
    pub calls: &'a [CallFact],
    pub bindings: &'a [EntryBinding],
    pub libraries: &'a [LibraryFact],
    /// Classification per asset id, from the classifier.
    pub classifications: &'a BTreeMap<String, DataClassification>,
    pub policy: &'a Policy,
}

#[derive(Debug, Default)]
pub struct CryptoGraph {
    graph: StableDiGraph<Node, Edge>,
    index: HashMap<String, NodeIndex>,
    contexts: BTreeMap<String, AssetContext>,
    stats: GraphStats,
}

/// How an entry point reached a function: the entry and the previous function on the path.
#[derive(Debug, Clone)]
struct Reach {
    entry: usize,
    parent: Option<usize>,
}

impl CryptoGraph {
    pub fn build(input: &GraphInput<'_>) -> Self {
        let mut graph = Self::default();
        let functions = input.functions;
        graph.stats.functions = functions.len();

        // ---- entry points: annotations/main/listeners, plus resolved route bindings ----------
        let mut entries: Vec<(usize, EntryPoint)> = functions
            .iter()
            .enumerate()
            .filter_map(|(i, f)| f.entry.clone().map(|entry| (i, entry)))
            .collect();
        let by_file_name =
            index_functions(functions, |f| (f.location.path.clone(), f.name.clone()));
        let by_component_name =
            index_functions(functions, |f| (f.component.clone(), f.name.clone()));
        for binding in input.bindings {
            let targets = by_file_name
                .get(&(binding.file.clone(), binding.handler.clone()))
                .or_else(|| {
                    by_component_name.get(&(binding.component.clone(), binding.handler.clone()))
                });
            if let Some(targets) = targets.filter(|t| t.len() <= MAX_CALL_TARGETS) {
                for &target in targets {
                    entries.push((target, binding.entry.clone()));
                }
            }
        }
        // most exposed first, so the first path found to a function is its most exposed one
        entries.sort_by(|a, b| {
            exposure_weight(input.policy, b.1.kind)
                .total_cmp(&exposure_weight(input.policy, a.1.kind))
                .then_with(|| a.0.cmp(&b.0))
        });
        // keep each function's most exposed entry (the first after sorting)
        let mut seen_entries = BTreeSet::new();
        entries.retain(|(function, _)| seen_entries.insert(*function));
        graph.stats.entry_points = entries.len();

        // ---- call edges ----------------------------------------------------------------------
        let by_id: HashMap<&str, usize> = functions
            .iter()
            .enumerate()
            .map(|(i, f)| (f.id.as_str(), i))
            .collect();
        let mut callees: Vec<Vec<usize>> = vec![Vec::new(); functions.len()];
        for call in input.calls {
            let Some(&caller) = by_id.get(call.caller.as_str()) else {
                continue;
            };
            let caller_fact = &functions[caller];
            let targets = by_file_name
                .get(&(caller_fact.location.path.clone(), call.callee.clone()))
                .or_else(|| {
                    by_component_name.get(&(caller_fact.component.clone(), call.callee.clone()))
                })
                .filter(|t| t.len() <= MAX_CALL_TARGETS);
            match targets {
                Some(targets) => {
                    graph.stats.calls_resolved += 1;
                    callees[caller].extend(targets.iter().copied().filter(|&t| t != caller));
                }
                None => graph.stats.calls_unresolved += 1,
            }
        }
        for list in &mut callees {
            list.sort_unstable();
            list.dedup();
        }

        // ---- reachability (BFS, parent pointers) ---------------------------------------------
        let mut reach: Vec<Option<Reach>> = vec![None; functions.len()];
        let mut queue = VecDeque::new();
        for (entry_index, (function, _)) in entries.iter().enumerate() {
            if reach[*function].is_none() {
                reach[*function] = Some(Reach {
                    entry: entry_index,
                    parent: None,
                });
                queue.push_back(*function);
            }
        }
        while let Some(current) = queue.pop_front() {
            let entry = reach[current].as_ref().map_or(0, |r| r.entry);
            for &next in &callees[current] {
                if reach[next].is_none() {
                    reach[next] = Some(Reach {
                        entry,
                        parent: Some(current),
                    });
                    queue.push_back(next);
                }
            }
        }
        graph.stats.reachable_functions = reach.iter().filter(|r| r.is_some()).count();

        // ---- nodes and structural edges ------------------------------------------------------
        for function in functions {
            let component = graph.node(Node::Component {
                id: component_id(&function.component),
            });
            let node = graph.node(Node::Function {
                id: function.id.clone(),
                name: function.name.clone(),
                path: function.location.path.clone(),
                line: function.location.line.unwrap_or(0),
            });
            graph.edge(component, node, Edge::Contains);
        }
        for (function, entry) in &entries {
            let fact = &functions[*function];
            let entry_node = graph.node(Node::Entry {
                id: format!("entry/{}", fact.id),
                kind: entry.kind,
                detail: entry.detail.clone(),
            });
            let target = graph.index[&fact.id];
            graph.edge(entry_node, target, Edge::Exposes);
        }
        for (caller, targets) in callees.iter().enumerate() {
            let source = graph.index[&functions[caller].id];
            for &target in targets {
                let target = graph.index[&functions[target].id];
                graph.edge(source, target, Edge::Calls);
            }
        }
        for library in input.libraries {
            let component = graph.node(Node::Component {
                id: component_id(&library.component),
            });
            let node = graph.node(Node::Library {
                id: format!(
                    "library/{}/{}/{}",
                    library.component,
                    library.name,
                    library.version.as_deref().unwrap_or("unknown")
                ),
                name: library.name.clone(),
                version: library.version.clone(),
                pqc_capable: library.pqc_capable,
            });
            graph.edge(component, node, Edge::Links);
        }

        // listeners by file, for configuration assets
        let listeners: HashMap<&str, &FunctionFact> = functions
            .iter()
            .filter(|f| {
                f.entry
                    .as_ref()
                    .is_some_and(|e| e.kind == EntryKind::Listener)
            })
            .map(|f| (f.location.path.as_str(), f))
            .collect();
        // certificates and keys a listener presents, by (component, file name)
        let served: HashMap<(&str, &str), &FunctionFact> = listeners
            .values()
            .flat_map(|f| {
                f.serves
                    .iter()
                    .map(move |name| ((f.component.as_str(), name.as_str()), *f))
            })
            .collect();
        // listeners by the host names they answer to, for handshakes seen in traffic
        let by_host: HashMap<(&str, &str), &FunctionFact> = listeners
            .values()
            .flat_map(|f| {
                f.hosts
                    .iter()
                    .map(move |host| ((f.component.as_str(), host.as_str()), *f))
            })
            .collect();

        // most sensitive observed classification per component, for inheritance
        let mut component_data: BTreeMap<&str, &DataClassification> = BTreeMap::new();
        for asset in input.assets {
            if let Some(data) = input
                .classifications
                .get(&asset.id)
                .filter(|d| d.class != "unclassified")
            {
                let slot = component_data
                    .entry(asset.component.as_str())
                    .or_insert(data);
                if (data.criticality, ordered(data.secrecy_lifetime_years))
                    > (slot.criticality, ordered(slot.secrecy_lifetime_years))
                {
                    *slot = data;
                }
            }
        }

        // ---- per-asset context -----------------------------------------------------------------
        for asset in input.assets {
            let crypto = graph.node(Node::Crypto {
                id: asset.id.clone(),
                name: asset.finding.display_name(),
                asset_type: asset.finding.asset_type().into(),
            });
            let component = graph.node(Node::Component {
                id: component_id(&asset.component),
            });
            graph.edge(component, crypto, Edge::Contains);

            let mut best: Option<(f64, usize, &EntryPoint)> = None;
            for function in asset.usages().filter_map(|usage| usage.function.as_deref()) {
                let Some(&index) = by_id.get(function) else {
                    continue;
                };
                let node = graph.index[function];
                graph.edge(node, crypto, Edge::Uses);
                if let Some(r) = &reach[index] {
                    let entry = &entries[r.entry].1;
                    let weight = exposure_weight(input.policy, entry.kind);
                    if best.is_none_or(|(w, _, _)| weight > w) {
                        best = Some((weight, index, entry));
                    }
                }
            }
            for dependency in &asset.depends_on {
                if let Some(&target) = graph.index.get(dependency) {
                    graph.edge(crypto, target, Edge::DependsOn);
                }
            }

            let listener = asset
                .occurrences
                .iter()
                .filter(|o| matches!(o.surface, Surface::Config | Surface::Cloud))
                .find_map(|o| {
                    listeners
                        .get(o.location.path.as_str())
                        .map(|l| (*l, Via::Configured))
                })
                .or_else(|| {
                    // a certificate or key file the listener's configuration points at
                    asset.occurrences.iter().find_map(|o| {
                        let name = o.location.path.rsplit('/').next().unwrap_or_default();
                        served
                            .get(&(asset.component.as_str(), name))
                            .map(|l| (*l, Via::Serves(name)))
                    })
                })
                .or_else(|| {
                    // negotiated in captured traffic to a host name the listener answers to
                    asset
                        .occurrences
                        .iter()
                        .filter(|o| o.surface == Surface::Runtime)
                        .find_map(|o| {
                            let host = o.evidence.matched_token.as_str();
                            host_listener(&by_host, &asset.component, host)
                                .map(|l| (l, Via::Traffic(host, &o.location.path)))
                        })
                });
            let observed_on_wire = asset
                .occurrences
                .iter()
                .find(|o| o.surface == Surface::Runtime);

            let (reachable, entry, path, exposure, exposure_reason) = if let Some((
                weight,
                function,
                entry,
            )) = best
            {
                let path = path_to(function, &reach, functions);
                let reason = format!(
                    "reachable from {} via {}",
                    describe_entry(entry),
                    path.join(" → ")
                );
                (true, Some(entry.clone()), path, weight, reason)
            } else if let Some((listener, via)) = listener {
                // a TLS listener is itself the entry point: what it configures, presents or
                // negotiates is exposed to every client that connects
                if let Some(&node) = graph.index.get(listener.id.as_str()) {
                    graph.edge(node, crypto, Edge::Uses);
                }
                let entry = listener.entry.clone();
                let detail = entry.as_ref().map_or("", |e| e.detail.as_str());
                let at = listener.location.short();
                let reason = match via {
                    Via::Configured => format!("configured on a TLS listener ({detail}) at {at}"),
                    Via::Serves(file) => {
                        format!(
                            "presented by the TLS listener ({detail}) configured at {at}, which references `{file}`"
                        )
                    }
                    Via::Traffic(host, capture) => {
                        format!(
                            "negotiated in live traffic to `{host}` ({capture}), served by the TLS listener ({detail}) at {at}"
                        )
                    }
                };
                (
                    true,
                    entry,
                    Vec::new(),
                    input.policy.exposure.listener,
                    reason,
                )
            } else if let Some(occurrence) = observed_on_wire {
                (
                    true,
                    None,
                    Vec::new(),
                    input.policy.exposure.listener,
                    format!(
                        "negotiated in live traffic with `{}` ({})",
                        occurrence.evidence.matched_token,
                        occurrence.location.short()
                    ),
                )
            } else {
                (
                    false,
                    None,
                    Vec::new(),
                    input.policy.exposure.unreached,
                    "no detected entry point reaches it; policy default exposure applies (not assumed dead)".into(),
                )
            };
            if reachable {
                graph.stats.reachable_assets += 1;
            }

            let observed = input.classifications.get(&asset.id).cloned();
            let inherit =
                !matches!(asset.finding, Finding::Algorithm(_)) || asset.usages().next().is_none();
            let (data, data_inherited) =
                match (observed, component_data.get(asset.component.as_str())) {
                    (Some(data), _) if data.class != "unclassified" => (data, false),
                    (_, Some(component)) if inherit => {
                        let mut data = (*component).clone();
                        data.explanation = format!(
                            "inherited from component `{}`, whose most sensitive data is {}",
                            asset.component, data.explanation
                        );
                        data.confidence = (data.confidence * 0.8 * 100.0).round() / 100.0;
                        (data, true)
                    }
                    (Some(data), _) => (data, false),
                    (None, _) => (
                        lattice_classify::Classifier::new(input.policy).unclassified(&asset.id),
                        false,
                    ),
                };
            let data_node = graph.node(Node::Data {
                id: data.data_asset_id.clone(),
                class: data.class.clone(),
                secrecy_lifetime_years: data.secrecy_lifetime_years,
                criticality: data.criticality,
            });
            graph.edge(crypto, data_node, Edge::Protects);

            let pqc_ready_library = input
                .libraries
                .iter()
                .find(|library| library.component == asset.component && library.pqc_capable)
                .map(|library| {
                    format!(
                        "{} {}: {}",
                        library.name,
                        library.version.as_deref().unwrap_or(""),
                        library.basis
                    )
                });

            graph.contexts.insert(
                asset.id.clone(),
                AssetContext {
                    reachable,
                    entry,
                    path,
                    exposure,
                    exposure_reason,
                    data,
                    data_inherited,
                    pqc_ready_library,
                },
            );
        }
        graph
    }

    pub fn context(&self, asset_id: &str) -> Option<&AssetContext> {
        self.contexts.get(asset_id)
    }

    pub fn stats(&self) -> &GraphStats {
        &self.stats
    }

    /// Deterministic node/edge lists for the cockpit and the JSON report.
    pub fn to_serializable(&self) -> SerializableGraph {
        let mut nodes: Vec<Node> = self.graph.node_weights().cloned().collect();
        nodes.sort_by(|a, b| a.id().cmp(b.id()));
        let mut edges: Vec<SerializableEdge> = self
            .graph
            .edge_references()
            .map(|edge| SerializableEdge {
                source: self.graph[edge.source()].id().to_owned(),
                target: self.graph[edge.target()].id().to_owned(),
                kind: *edge.weight(),
            })
            .collect();
        edges.sort_by(|a, b| (&a.source, &a.target, a.kind).cmp(&(&b.source, &b.target, b.kind)));
        SerializableGraph { nodes, edges }
    }

    fn node(&mut self, node: Node) -> NodeIndex {
        if let Some(&index) = self.index.get(node.id()) {
            return index;
        }
        let id = node.id().to_owned();
        let index = self.graph.add_node(node);
        self.index.insert(id, index);
        index
    }

    fn edge(&mut self, source: NodeIndex, target: NodeIndex, kind: Edge) {
        if !self
            .graph
            .edges_directed(source, Outgoing)
            .any(|e| e.target() == target && *e.weight() == kind)
        {
            self.graph.add_edge(source, target, kind);
        }
    }
}

fn index_functions<K: std::hash::Hash + Eq>(
    functions: &[FunctionFact],
    key: impl Fn(&FunctionFact) -> K,
) -> HashMap<K, Vec<usize>> {
    let mut map: HashMap<K, Vec<usize>> = HashMap::new();
    for (index, function) in functions.iter().enumerate() {
        map.entry(key(function)).or_default().push(index);
    }
    map
}

fn exposure_weight(policy: &Policy, kind: EntryKind) -> f64 {
    match kind {
        EntryKind::HttpRoute => policy.exposure.http_route,
        EntryKind::Listener => policy.exposure.listener,
        EntryKind::LibraryExport => policy.exposure.library_export,
        EntryKind::Main => policy.exposure.main,
    }
}

fn describe_entry(entry: &EntryPoint) -> String {
    let kind = match entry.kind {
        EntryKind::HttpRoute => "HTTP route",
        EntryKind::Listener => "TLS listener",
        EntryKind::LibraryExport => "library export",
        EntryKind::Main => "process entry",
    };
    format!("{kind} `{}`", entry.detail)
}

fn path_to(function: usize, reach: &[Option<Reach>], functions: &[FunctionFact]) -> Vec<String> {
    let mut path = Vec::new();
    let mut current = Some(function);
    let mut guard = 0;
    while let Some(index) = current {
        path.push(functions[index].name.clone());
        current = reach[index].as_ref().and_then(|r| r.parent);
        guard += 1;
        if guard > 64 {
            path.push("…".into());
            break;
        }
    }
    path.reverse();
    path
}

fn component_id(component: &str) -> String {
    format!("component/{component}")
}

fn ordered(value: f64) -> i64 {
    (value * 1000.0) as i64
}

/// Components that contain at least one asset, for summaries.
pub fn components(assets: &[CryptoAsset]) -> BTreeSet<String> {
    assets.iter().map(|asset| asset.component.clone()).collect()
}

/// How a TLS listener exposes an asset.
enum Via<'a> {
    /// Its own configuration selects the asset.
    Configured,
    /// It presents this certificate or key file.
    Serves(&'a str),
    /// A handshake to this host name, in this capture, negotiated it.
    Traffic(&'a str, &'a str),
}

/// The listener answering to `host` in `component`: an exact name first, then a wildcard
/// covering exactly one more label (`*.example.in` matches `pay.example.in`).
fn host_listener<'f>(
    by_host: &HashMap<(&str, &str), &'f FunctionFact>,
    component: &str,
    host: &str,
) -> Option<&'f FunctionFact> {
    by_host.get(&(component, host)).copied().or_else(|| {
        let (_, parent) = host.split_once('.')?;
        by_host
            .get(&(component, format!("*.{parent}").as_str()))
            .copied()
    })
}

#[cfg(test)]
mod tests {
    use super::*;
    use lattice_classify::{Classifier, EvidenceSource};
    use lattice_core::{
        AlgorithmRef, AlgorithmSource, ApiStyle, Evidence, EvidenceKind, Location, Observation,
        ProtocolFinding, ProtocolKind, Usage, normalize,
    };

    fn function(id: &str, name: &str, path: &str, entry: Option<EntryKind>) -> FunctionFact {
        FunctionFact {
            id: id.into(),
            component: ".".into(),
            name: name.into(),
            location: Location::at_line(path, 1, 1),
            entry: entry.map(|kind| EntryPoint {
                kind,
                detail: format!("{name}-entry"),
            }),
            parameters: vec![],
            serves: Vec::new(),
            hosts: Vec::new(),
        }
    }

    fn call(caller: &str, callee: &str) -> CallFact {
        CallFact {
            caller: caller.into(),
            callee: callee.into(),
            location: Location::at_line("app.py", 1, 1),
        }
    }

    fn crypto_use(function: &str, id: &str, path: &str) -> Observation {
        Observation {
            surface: Surface::Source,
            component: ".".into(),
            location: Location::at_line(path, 5, 1),
            finding: Finding::algorithm(AlgorithmRef::new(id)),
            evidence: Evidence {
                collector: "source".into(),
                rule_id: "r".into(),
                rule_version: "1".into(),
                kind: EvidenceKind::ApiCall,
                matched_token: "t".into(),
            },
            usage: Some(Usage {
                language: "python".into(),
                api: "api".into(),
                function: Some(function.into()),
                identifiers: vec!["card_number".into()],
                algorithm_source: AlgorithmSource::Literal,
                api_style: ApiStyle::Provider,
            }),
        }
    }

    fn classify(
        assets: &[CryptoAsset],
        functions: &[FunctionFact],
    ) -> BTreeMap<String, DataClassification> {
        let classifier = Classifier::new(Policy::active());
        let by_id: HashMap<&str, &FunctionFact> =
            functions.iter().map(|f| (f.id.as_str(), f)).collect();
        assets
            .iter()
            .map(|a| (a.id.clone(), classifier.classify(a, &by_id)))
            .collect()
    }

    #[test]
    fn reachability_follows_calls_from_route_entries_and_explains_the_path() {
        let functions = vec![
            function("f/pay", "pay", "app.py", Some(EntryKind::HttpRoute)),
            function("f/seal", "seal_card", "app.py", None),
            function("f/orphan", "orphan", "app.py", None),
        ];
        let calls = vec![call("f/pay", "seal_card")];
        let assets = normalize(vec![
            crypto_use("f/seal", "rsa", "app.py"),
            crypto_use("f/orphan", "md5", "app.py"),
        ]);
        let classifications = classify(&assets, &functions);
        let graph = CryptoGraph::build(&GraphInput {
            assets: &assets,
            functions: &functions,
            calls: &calls,
            bindings: &[],
            libraries: &[],
            classifications: &classifications,
            policy: Policy::active(),
        });
        let rsa = assets
            .iter()
            .find(|a| a.algorithm().unwrap().id == "rsa")
            .unwrap();
        let context = graph.context(&rsa.id).unwrap();
        assert!(context.reachable);
        assert_eq!(context.path, vec!["pay".to_owned(), "seal_card".to_owned()]);
        assert_eq!(context.exposure, 1.0);
        assert!(context.exposure_reason.contains("HTTP route"));
        assert_eq!(context.data.class, "financial");

        let md5 = assets
            .iter()
            .find(|a| a.algorithm().unwrap().id == "md5")
            .unwrap();
        let orphan = graph.context(&md5.id).unwrap();
        assert!(!orphan.reachable);
        assert_eq!(orphan.exposure, Policy::active().exposure.unreached);
        assert!(orphan.exposure_reason.contains("not assumed dead"));
        assert_eq!(graph.stats().reachable_assets, 1);
    }

    #[test]
    fn route_bindings_make_handlers_entry_points() {
        let functions = vec![
            function("f/main", "main", "main.go", Some(EntryKind::Main)),
            function("f/pay", "pay", "main.go", None),
        ];
        let bindings = vec![EntryBinding {
            component: ".".into(),
            file: "main.go".into(),
            handler: "pay".into(),
            entry: EntryPoint {
                kind: EntryKind::HttpRoute,
                detail: "http.HandleFunc(\"/pay\")".into(),
            },
            location: Location::at_line("main.go", 3, 1),
        }];
        let assets = normalize(vec![crypto_use("f/pay", "rsa", "main.go")]);
        let classifications = classify(&assets, &functions);
        let graph = CryptoGraph::build(&GraphInput {
            assets: &assets,
            functions: &functions,
            calls: &[],
            bindings: &bindings,
            libraries: &[],
            classifications: &classifications,
            policy: Policy::active(),
        });
        let context = graph.context(&assets[0].id).unwrap();
        assert!(context.reachable);
        assert_eq!(
            context.entry.as_ref().unwrap().kind,
            EntryKind::HttpRoute,
            "the route beats main"
        );
    }

    #[test]
    fn protocol_assets_inherit_component_data_and_listener_exposure() {
        let functions = vec![
            function("f/pay", "pay", "app.py", Some(EntryKind::HttpRoute)),
            FunctionFact {
                id: "./nginx.conf::<tls-listener>".into(),
                component: ".".into(),
                name: "<tls-listener>".into(),
                location: Location::at_line("nginx.conf", 2, 1),
                entry: Some(EntryPoint {
                    kind: EntryKind::Listener,
                    detail: "listen 443 ssl".into(),
                }),
                parameters: vec![],
                serves: vec!["server.crt".into()],
                hosts: Vec::new(),
            },
        ];
        let certificate = Observation {
            surface: Surface::Certificate,
            component: ".".into(),
            location: Location::file("tls/server.crt"),
            finding: Finding::Certificate(lattice_core::CertificateFinding {
                subject: "CN=pay".into(),
                issuer: "CN=ca".into(),
                not_before: "2026-01-01T00:00:00Z".into(),
                not_after: "2027-01-01T00:00:00Z".into(),
                serial: "01".into(),
                public_key: lattice_core::AlgorithmRef::new("rsa"),
                signature: lattice_core::AlgorithmRef::new("rsa"),
                self_signed: false,
                is_ca: false,
                fingerprint_sha256: "ab".repeat(32),
            }),
            evidence: Evidence {
                collector: "pki".into(),
                rule_id: "pki.x509".into(),
                rule_version: "1".into(),
                kind: EvidenceKind::Certificate,
                matched_token: "CERTIFICATE".into(),
            },
            usage: None,
        };
        let tls = Observation {
            surface: Surface::Config,
            component: ".".into(),
            location: Location::at_line("nginx.conf", 3, 1),
            finding: Finding::Protocol(ProtocolFinding {
                protocol: ProtocolKind::Tls,
                version: Some("1.0".into()),
                cipher_suites: vec![],
                groups: vec![],
            }),
            evidence: Evidence {
                collector: "config".into(),
                rule_id: "r".into(),
                rule_version: "1".into(),
                kind: EvidenceKind::Configuration,
                matched_token: "ssl_protocols".into(),
            },
            usage: None,
        };
        let assets = normalize(vec![crypto_use("f/pay", "rsa", "app.py"), tls, certificate]);
        let classifications = classify(&assets, &functions);
        let graph = CryptoGraph::build(&GraphInput {
            assets: &assets,
            functions: &functions,
            calls: &[],
            bindings: &[],
            libraries: &[],
            classifications: &classifications,
            policy: Policy::active(),
        });
        let protocol = assets
            .iter()
            .find(|a| matches!(a.finding, Finding::Protocol(_)))
            .unwrap();
        let context = graph.context(&protocol.id).unwrap();
        assert!(context.data_inherited);
        assert_eq!(context.data.class, "financial");
        assert!(context.exposure_reason.contains("TLS listener"));
        assert_eq!(context.exposure, 1.0);
        assert!(context.reachable, "the listener is the entry point");

        let certificate = assets
            .iter()
            .find(|a| matches!(a.finding, Finding::Certificate(_)))
            .unwrap();
        let context = graph.context(&certificate.id).unwrap();
        assert!(context.reachable);
        assert!(
            context.exposure_reason.contains("`server.crt`"),
            "{}",
            context.exposure_reason
        );
        let edges = graph.to_serializable().edges;
        for asset in [protocol, certificate] {
            assert!(edges.iter().any(|e| e.kind == Edge::Uses
                && e.source == "./nginx.conf::<tls-listener>"
                && e.target == asset.id));
        }
    }

    #[test]
    fn ambiguous_common_names_do_not_connect_everything() {
        let mut functions = vec![function("f/pay", "pay", "a.py", Some(EntryKind::HttpRoute))];
        for i in 0..20 {
            functions.push(function(
                &format!("f/run{i}"),
                "run",
                &format!("m{i}.py"),
                None,
            ));
        }
        let calls = vec![call("f/pay", "run")];
        let assets = normalize(vec![crypto_use("f/run3", "md5", "m3.py")]);
        let classifications = classify(&assets, &functions);
        let graph = CryptoGraph::build(&GraphInput {
            assets: &assets,
            functions: &functions,
            calls: &calls,
            bindings: &[],
            libraries: &[],
            classifications: &classifications,
            policy: Policy::active(),
        });
        assert!(!graph.context(&assets[0].id).unwrap().reachable);
        assert_eq!(graph.stats().calls_unresolved, 1);
    }

    #[test]
    fn serialization_is_deterministic() {
        let functions = vec![function(
            "f/pay",
            "pay",
            "app.py",
            Some(EntryKind::HttpRoute),
        )];
        let assets = normalize(vec![crypto_use("f/pay", "rsa", "app.py")]);
        let classifications = classify(&assets, &functions);
        let input = GraphInput {
            assets: &assets,
            functions: &functions,
            calls: &[],
            bindings: &[],
            libraries: &[],
            classifications: &classifications,
            policy: Policy::active(),
        };
        let a = serde_json::to_string(&CryptoGraph::build(&input).to_serializable()).unwrap();
        let b = serde_json::to_string(&CryptoGraph::build(&input).to_serializable()).unwrap();
        assert_eq!(a, b);
        let _ = EvidenceSource::Argument;
    }
}
