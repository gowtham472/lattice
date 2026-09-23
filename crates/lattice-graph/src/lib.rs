//! In-memory crypto data-flow graph and explainable reachability queries.

use lattice_classify::DataClassificationResult;
use lattice_core::CryptoAsset;
use petgraph::stable_graph::{NodeIndex, StableDiGraph};
use petgraph::visit::{EdgeRef, IntoEdgeReferences};
use petgraph::Direction::{Incoming, Outgoing};
use serde::Serialize;
use std::collections::{BTreeMap, BTreeSet};

#[derive(Debug, Clone, PartialEq, Serialize)]
#[serde(tag = "type", rename_all = "camelCase")]
pub enum GraphNode {
    CryptoAsset { id: String, algorithm: String },
    DataAsset {
        id: String,
        classification: String,
        secrecy_lifetime_years: f64,
        business_criticality: String,
        classifier_rule: String,
        confidence: f64,
    },
    CodeUnit { id: String, path: String },
    EntryPoint { id: String, exposure: f64 },
}

impl GraphNode {
    pub fn id(&self) -> &str {
        match self {
            Self::CryptoAsset { id, .. }
            | Self::DataAsset { id, .. }
            | Self::CodeUnit { id, .. }
            | Self::EntryPoint { id, .. } => id,
        }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize)]
pub enum EdgeKind {
    Uses,
    Protects,
    ReachableFrom,
}

#[derive(Debug, Clone, PartialEq, Serialize)]
pub struct GraphAssetContext {
    pub protected_data_ids: Vec<String>,
    pub classifications: Vec<String>,
    pub business_criticality: String,
    pub secrecy_lifetime_years: f64,
    pub reachable_from: Vec<String>,
    pub external_exposure: f64,
}

#[derive(Debug, Clone, Serialize)]
pub struct SerializableNode {
    pub id: String,
    pub node: GraphNode,
}

#[derive(Debug, Clone, Serialize)]
pub struct SerializableEdge {
    pub source: String,
    pub target: String,
    pub kind: EdgeKind,
}

#[derive(Debug, Clone, Serialize)]
pub struct SerializableGraph {
    pub nodes: Vec<SerializableNode>,
    pub edges: Vec<SerializableEdge>,
}

#[derive(Debug, Default)]
pub struct CryptoGraph {
    graph: StableDiGraph<GraphNode, EdgeKind>,
    by_id: BTreeMap<String, NodeIndex>,
}

impl CryptoGraph {
    pub fn build(
        assets: &[CryptoAsset],
        classifications: &BTreeMap<String, DataClassificationResult>,
        exposure: f64,
    ) -> Self {
        let mut result = Self::default();
        for asset in assets {
            let crypto_index = result.upsert_node(GraphNode::CryptoAsset {
                id: asset.id.clone(),
                algorithm: asset.algorithm.family.clone(),
            });

            if let Some(classification) = classifications.get(&asset.id) {
                let data_index = result.upsert_node(GraphNode::DataAsset {
                    id: classification.data_asset_id.clone(),
                    classification: classification.classification.as_str().into(),
                    secrecy_lifetime_years: classification.secrecy_lifetime_years,
                    business_criticality: classification.business_criticality.as_str().into(),
                    classifier_rule: classification.rule_id.clone(),
                    confidence: classification.confidence,
                });
                result.add_edge_once(crypto_index, data_index, EdgeKind::Protects);
            }

            for location in &asset.locations {
                let code_id = format!("code/{}", location.path);
                let code_index = result.upsert_node(GraphNode::CodeUnit {
                    id: code_id.clone(),
                    path: location.path.clone(),
                });
                result.add_edge_once(code_index, crypto_index, EdgeKind::Uses);

                if exposure > 0.0 && looks_like_entry_point(&location.path) {
                    let entry_id = format!("entry/{}", location.path);
                    let entry_index = result.upsert_node(GraphNode::EntryPoint {
                        id: entry_id,
                        exposure,
                    });
                    result.add_edge_once(entry_index, code_index, EdgeKind::ReachableFrom);
                }
            }
        }
        result
    }

    pub fn asset_context(&self, asset_id: &str) -> Option<GraphAssetContext> {
        let &crypto_index = self.by_id.get(asset_id)?;
        let mut protected_data_ids = BTreeSet::new();
        let mut classifications = BTreeSet::new();
        let mut business_criticality = "low";
        let mut secrecy_lifetime_years: f64 = 0.0;

        for edge in self.graph.edges_directed(crypto_index, Outgoing) {
            if edge.weight() != &EdgeKind::Protects {
                continue;
            }
            if let GraphNode::DataAsset {
                id,
                classification,
                secrecy_lifetime_years: lifetime,
                business_criticality: criticality,
                ..
            } = &self.graph[edge.target()]
            {
                protected_data_ids.insert(id.clone());
                classifications.insert(classification.clone());
                secrecy_lifetime_years = secrecy_lifetime_years.max(*lifetime);
                if criticality_rank(criticality) > criticality_rank(business_criticality) {
                    business_criticality = criticality;
                }
            }
        }

        let mut reachable_from = BTreeSet::new();
        let mut external_exposure: f64 = 0.0;
        for uses_edge in self.graph.edges_directed(crypto_index, Incoming) {
            if uses_edge.weight() != &EdgeKind::Uses {
                continue;
            }
            let code_index = uses_edge.source();
            for reachability_edge in self.graph.edges_directed(code_index, Incoming) {
                if reachability_edge.weight() != &EdgeKind::ReachableFrom {
                    continue;
                }
                if let GraphNode::EntryPoint { id, exposure } = &self.graph[reachability_edge.source()] {
                    reachable_from.insert(id.clone());
                    external_exposure = external_exposure.max(*exposure);
                }
            }
        }

        Some(GraphAssetContext {
            protected_data_ids: protected_data_ids.into_iter().collect(),
            classifications: classifications.into_iter().collect(),
            business_criticality: business_criticality.into(),
            secrecy_lifetime_years,
            reachable_from: reachable_from.into_iter().collect(),
            external_exposure,
        })
    }

    pub fn is_reachable(&self, asset_id: &str) -> bool {
        self.asset_context(asset_id)
            .is_some_and(|context| !context.reachable_from.is_empty())
    }

    pub fn to_serializable(&self) -> SerializableGraph {
        let mut nodes = self
            .graph
            .node_indices()
            .map(|index| SerializableNode {
                id: self.graph[index].id().to_owned(),
                node: self.graph[index].clone(),
            })
            .collect::<Vec<_>>();
        nodes.sort_by(|a, b| a.id.cmp(&b.id));

        let mut edges = self
            .graph
            .edge_references()
            .map(|edge| SerializableEdge {
                source: self.graph[edge.source()].id().to_owned(),
                target: self.graph[edge.target()].id().to_owned(),
                kind: *edge.weight(),
            })
            .collect::<Vec<_>>();
        edges.sort_by(|a, b| {
            (&a.source, &a.target, edge_rank(a.kind)).cmp(&(&b.source, &b.target, edge_rank(b.kind)))
        });
        SerializableGraph { nodes, edges }
    }

    fn upsert_node(&mut self, node: GraphNode) -> NodeIndex {
        if let Some(index) = self.by_id.get(node.id()) {
            return *index;
        }
        let id = node.id().to_owned();
        let index = self.graph.add_node(node);
        self.by_id.insert(id, index);
        index
    }

    fn add_edge_once(&mut self, source: NodeIndex, target: NodeIndex, kind: EdgeKind) {
        let exists = self
            .graph
            .edges_connecting(source, target)
            .any(|edge| edge.weight() == &kind);
        if !exists {
            self.graph.add_edge(source, target, kind);
        }
    }
}

fn looks_like_entry_point(path: &str) -> bool {
    let normalized = path.to_ascii_lowercase();
    ["api", "route", "controller", "server", "endpoint", "handler", "main"]
        .iter()
        .any(|term| normalized.contains(term))
}

fn criticality_rank(value: &str) -> u8 {
    match value {
        "critical" => 4,
        "high" => 3,
        "medium" => 2,
        _ => 1,
    }
}

fn edge_rank(kind: EdgeKind) -> u8 {
    match kind {
        EdgeKind::Uses => 1,
        EdgeKind::Protects => 2,
        EdgeKind::ReachableFrom => 3,
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use lattice_classify::{BusinessCriticality, DataClassification};
    use lattice_core::{Algorithm, EvidenceGrade, Liveness, Location, Surface};

    fn asset() -> CryptoAsset {
        CryptoAsset {
            id: "crypto/rsa/example".into(),
            algorithm: Algorithm {
                family: "RSA".into(),
                primitive: "public-key".into(),
                key_size_bits: Some(2048),
                mode: None,
                curve: None,
            },
            parameters: BTreeMap::new(),
            locations: vec![Location {
                path: "payments/api.py".into(),
                line: Some(3),
                column: Some(1),
                byte_offset: Some(20),
            }],
            surfaces: BTreeSet::from([Surface::Source]),
            evidence: vec![],
            liveness: Liveness::Capable,
            evidence_grade: EvidenceGrade::C,
        }
    }

    #[test]
    fn graph_context_is_derived_by_traversing_protects_and_reachability_edges() {
        let asset = asset();
        let classification = DataClassificationResult {
            data_asset_id: "data/financial/example".into(),
            classification: DataClassification::Financial,
            secrecy_lifetime_years: 10.0,
            business_criticality: BusinessCriticality::Critical,
            rule_id: "data.financial@1".into(),
            confidence: 0.8,
            explanation: "test".into(),
        };
        let graph = CryptoGraph::build(
            std::slice::from_ref(&asset),
            &BTreeMap::from([(asset.id.clone(), classification)]),
            1.0,
        );

        let context = graph.asset_context(&asset.id).unwrap();
        assert_eq!(context.secrecy_lifetime_years, 10.0);
        assert_eq!(context.business_criticality, "critical");
        assert_eq!(context.external_exposure, 1.0);
        assert!(graph.is_reachable(&asset.id));
        assert_eq!(graph.to_serializable().edges.len(), 3);
    }
}
