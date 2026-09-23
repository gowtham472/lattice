//! Source collector: finds cryptographic API use on the syntax tree of nine languages.
//!
//! For each file it parses the source with tree-sitter (under a deadline), then walks the tree
//! once. Calls are matched against the rule database (`rules.rs`); matched calls have their
//! algorithm and parameters read out of literal arguments, same-file constants, nested calls
//! (`ec.SECP384R1()`), keyword arguments and object-literal properties. Results of crypto calls
//! bound to a variable can be refined by later calls on that variable
//! (`kpg.initialize(1024)` → RSA-1024).
//!
//! Alongside the observations it records the code facts the graph needs: every function, every
//! call between functions, and every entry point (framework routes, `main`).

pub mod lang;
pub mod rules;

use crate::sandbox::Deadline;
use crate::{Artifact, Collector, CollectorError, Findings};
use lang::{Language, first_named_child, last_named_child};
use lattice_core::names;
use lattice_core::{
    AlgorithmFinding, AlgorithmRef, AlgorithmSource, CallFact, EntryBinding, EntryKind, EntryPoint,
    Evidence, EvidenceKind, Finding, FunctionFact, Location, Observation, Params, Primitive,
    ProtocolFinding, ProtocolKind, Registry, Surface, Usage,
};
use rules::{CompiledRule, Grammar, ParamName, RuleKind, RuleSet, ValueSource};
use std::collections::{BTreeSet, HashMap};
use tree_sitter::{Node, ParseOptions, ParseState, Parser, Tree};

const COLLECTOR: &str = "source";
/// Bounds on what one file may produce, so a hostile file cannot exhaust memory.
const MAX_OBSERVATIONS_PER_FILE: usize = 20_000;
const MAX_CALL_FACTS_PER_FILE: usize = 200_000;
const MAX_TOKEN: usize = 96;
const MAX_IDENTIFIERS: usize = 12;

/// Decorator, annotation and attribute names (lowercased) that bind a handler to an HTTP route.
const ROUTE_MARKERS: &[&str] = &[
    "route",
    "get",
    "post",
    "put",
    "delete",
    "patch",
    "head",
    "options",
    "api_route",
    "websocket",
    "getmapping",
    "postmapping",
    "putmapping",
    "deletemapping",
    "patchmapping",
    "requestmapping",
    "path",
    "httpget",
    "httppost",
    "httpput",
    "httpdelete",
    "httppatch",
    "webmethod",
    "messagemapping",
];
/// Call names (lowercased) that register a handler for a path passed as the first argument.
const ROUTE_REGISTRATIONS: &[&str] = &[
    "handlefunc",
    "handle",
    "handlerfunc",
    "get",
    "post",
    "put",
    "delete",
    "patch",
    "all",
    "route",
    "mapget",
    "mappost",
    "mapput",
    "mapdelete",
    "mappatch",
    "any",
    "options",
    "head",
];

pub struct SourceCollector {
    rules: RuleSet,
}

impl std::fmt::Debug for SourceCollector {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("SourceCollector")
            .field("rules", &self.rules.len())
            .finish()
    }
}

impl SourceCollector {
    pub fn new() -> Result<Self, CollectorError> {
        Ok(Self {
            rules: RuleSet::active()?,
        })
    }

    pub fn with_rules(rules: RuleSet) -> Self {
        Self { rules }
    }

    pub fn rule_version(&self) -> &str {
        &self.rules.version
    }
}

impl Collector for SourceCollector {
    fn name(&self) -> &'static str {
        COLLECTOR
    }

    fn accepts(&self, path: &str, head: &[u8]) -> bool {
        Language::from_path(path).is_some() && !head.contains(&0)
    }

    fn collect(
        &self,
        artifact: &Artifact<'_>,
        deadline: &Deadline,
        findings: &mut Findings,
    ) -> Result<(), String> {
        let language = Language::from_path(artifact.path).ok_or("not a supported source file")?;
        let source = String::from_utf8_lossy(artifact.bytes);
        let tree = parse(language, &source, deadline)?;
        let mut scan = FileScan::new(language, &source, artifact, &self.rules, deadline);
        scan.run(&tree)?;
        findings.append(scan.findings);
        Ok(())
    }
}

/// Parses under the deadline: tree-sitter polls the progress callback and stops when it
/// returns `true`.
fn parse(language: Language, source: &str, deadline: &Deadline) -> Result<Tree, String> {
    let mut parser = Parser::new();
    parser
        .set_language(&language.grammar())
        .map_err(|error| format!("{} grammar failed to load: {error}", language.name()))?;
    let bytes = source.as_bytes();
    let mut read = |offset: usize, _| &bytes[offset.min(bytes.len())..];
    let mut cancel = |_: &ParseState| deadline.expired();
    parser
        .parse_with_options(
            &mut read,
            None,
            Some(ParseOptions::new().progress_callback(&mut cancel)),
        )
        .ok_or_else(|| "parse exceeded its time budget; abandoned".to_owned())
}

#[derive(Debug, Clone)]
enum Literal {
    Str(String),
    Int(i128),
}

impl Literal {
    fn text(&self) -> String {
        match self {
            Self::Str(value) => value.clone(),
            Self::Int(value) => value.to_string(),
        }
    }
}

/// A candidate reading of an argument, with where the value came from.
#[derive(Debug, Clone)]
struct Candidate {
    text: String,
    source: AlgorithmSource,
}

/// What a grammar makes of a candidate.
enum Resolved {
    Algorithm(AlgorithmRef),
    Params(Params),
    Protocol(ProtocolKind, String),
}

struct Frame {
    node_id: usize,
    id: String,
    bindings: HashMap<String, usize>,
}

struct FileScan<'a> {
    language: Language,
    source: &'a str,
    path: &'a str,
    component: &'a str,
    rules: &'a RuleSet,
    deadline: &'a Deadline,
    constants: HashMap<String, Literal>,
    frames: Vec<Frame>,
    scopes: Vec<(usize, String)>,
    file_bindings: HashMap<String, usize>,
    /// (function, variable) pairs already linked to a module-level binding.
    linked_uses: BTreeSet<(String, String)>,
    pending_entries: HashMap<usize, EntryPoint>,
    findings: Findings,
}

impl<'a> FileScan<'a> {
    fn new(
        language: Language,
        source: &'a str,
        artifact: &Artifact<'a>,
        rules: &'a RuleSet,
        deadline: &'a Deadline,
    ) -> Self {
        Self {
            language,
            source,
            path: artifact.path,
            component: artifact.component,
            rules,
            deadline,
            constants: HashMap::new(),
            frames: Vec::new(),
            scopes: Vec::new(),
            file_bindings: HashMap::new(),
            linked_uses: BTreeSet::new(),
            pending_entries: HashMap::new(),
            findings: Findings::default(),
        }
    }

    fn run(&mut self, tree: &Tree) -> Result<(), String> {
        let root = tree.root_node();
        self.collect_constants(root)?;
        let mut cursor = root.walk();
        let mut visited: usize = 0;
        'walk: loop {
            let node = cursor.node();
            self.enter(node);
            visited += 1;
            if visited.is_multiple_of(2048) {
                self.deadline.check()?;
            }
            if !Language::is_comment(node.kind()) && cursor.goto_first_child() {
                continue;
            }
            loop {
                self.exit(cursor.node());
                if cursor.goto_next_sibling() {
                    continue 'walk;
                }
                if !cursor.goto_parent() {
                    break 'walk;
                }
            }
        }
        Ok(())
    }

    // ---- traversal -----------------------------------------------------------------------

    fn enter(&mut self, node: Node<'_>) {
        let kind = node.kind();
        if self.language.is_scope(kind)
            && let Some(name) = node.child_by_field_name("name").map(|name| self.text(name))
        {
            self.scopes.push((node.id(), dotted(&name)));
        }
        if self.language.is_function(kind) {
            self.enter_function(node);
        }
        if self.language.is_call(kind) {
            self.handle_call(node);
        }
        if matches!(kind, "assignment_expression" | "assignment") {
            self.handle_assignment(node);
        }
        if self.language.is_import(kind) {
            self.handle_import(node);
        }
        if self.language == Language::Go && kind == "composite_literal" {
            self.handle_go_tls_config(node);
        }
    }

    fn exit(&mut self, node: Node<'_>) {
        if self
            .frames
            .last()
            .is_some_and(|frame| frame.node_id == node.id())
        {
            self.frames.pop();
        }
        if self.scopes.last().is_some_and(|(id, _)| *id == node.id()) {
            self.scopes.pop();
        }
    }

    // ---- functions and entry points --------------------------------------------------------

    fn enter_function(&mut self, node: Node<'_>) {
        let line = node.start_position().row + 1;
        let name = self.function_name(node);
        let qualified = match (&name, self.frames.last()) {
            (Some(name), _) => {
                let mut parts: Vec<String> =
                    self.scopes.iter().map(|(_, scope)| scope.clone()).collect();
                parts.push(dotted(name));
                parts.join(".")
            }
            (None, Some(parent)) => {
                let parent_name = parent.id.rsplit("::").next().unwrap_or("");
                format!("{parent_name}.<anonymous@{line}>")
            }
            (None, None) => format!("<anonymous@{line}>"),
        };
        let id = format!("{}::{}::{}", self.component, self.path, qualified);
        let entry = self.entry_for(node, name.as_deref());
        let parameters = self.parameters(node);
        self.findings.functions.push(FunctionFact {
            id: id.clone(),
            component: self.component.to_owned(),
            name: name.unwrap_or_else(|| format!("<anonymous@{line}>")),
            location: self.location(node),
            entry,
            parameters,
            serves: Vec::new(),
            hosts: Vec::new(),
        });
        self.frames.push(Frame {
            node_id: node.id(),
            id,
            bindings: HashMap::new(),
        });
    }

    fn function_name(&self, node: Node<'_>) -> Option<String> {
        if matches!(self.language, Language::C | Language::Cpp) {
            let mut declarator = node.child_by_field_name("declarator")?;
            for _ in 0..8 {
                match declarator.kind() {
                    "function_declarator" => {
                        return declarator
                            .child_by_field_name("declarator")
                            .map(|inner| self.text(inner));
                    }
                    _ => {
                        declarator = declarator
                            .child_by_field_name("declarator")
                            .or_else(|| last_named_child(declarator))?
                    }
                }
            }
            return None;
        }
        if let Some(name) = node.child_by_field_name("name") {
            return Some(self.text(name));
        }
        // anonymous functions take the name they are bound to
        let parent = node.parent()?;
        match parent.kind() {
            "variable_declarator" => parent.child_by_field_name("name").map(|n| self.text(n)),
            "pair" => parent
                .child_by_field_name("key")
                .map(|n| unquote(&self.text(n))),
            "assignment_expression" | "assignment" => parent
                .child_by_field_name("left")
                .map(|n| last_segment(&dotted(&self.text(n))).to_owned()),
            _ => None,
        }
    }

    fn parameters(&self, node: Node<'_>) -> Vec<String> {
        let parameters = node.child_by_field_name("parameters").or_else(|| {
            // C/C++ keep parameters on the function declarator
            let declarator = node.child_by_field_name("declarator")?;
            declarator.child_by_field_name("parameters")
        });
        let Some(parameters) = parameters else {
            return Vec::new();
        };
        let mut names = Vec::new();
        let mut cursor = parameters.walk();
        for child in parameters.named_children(&mut cursor) {
            let name = child
                .child_by_field_name("name")
                .or_else(|| child.child_by_field_name("pattern"))
                .or_else(|| child.child_by_field_name("declarator"))
                .or((child.kind() == "identifier").then_some(child))
                .or_else(|| find_descendant(child, &["identifier"], 3));
            if let Some(name) = name {
                let text = self.text(name);
                let text = text.trim_start_matches(['*', '&']).trim();
                if !text.is_empty() && text.len() <= 64 && is_identifier(text) {
                    names.push(text.to_owned());
                }
            }
            if names.len() >= 16 {
                break;
            }
        }
        names
    }

    fn entry_for(&mut self, node: Node<'_>, name: Option<&str>) -> Option<EntryPoint> {
        if let Some(entry) = self.pending_entries.remove(&node.id()) {
            return Some(entry);
        }
        for decoration in self.decorations(node) {
            let marker = self.decoration_name(decoration);
            if ROUTE_MARKERS.contains(&marker.to_ascii_lowercase().as_str()) {
                return Some(EntryPoint {
                    kind: EntryKind::HttpRoute,
                    detail: truncate(&self.text(decoration), 120),
                });
            }
        }
        let name = name?;
        let main = match self.language {
            Language::CSharp => name == "Main",
            Language::Python | Language::JavaScript | Language::TypeScript | Language::Tsx => false,
            _ => name == "main",
        };
        if main {
            return Some(EntryPoint {
                kind: EntryKind::Main,
                detail: format!("{name}()"),
            });
        }
        if self.language == Language::Java
            && matches!(name, "doGet" | "doPost" | "doPut" | "doDelete" | "service")
        {
            return Some(EntryPoint {
                kind: EntryKind::HttpRoute,
                detail: format!("servlet {name}()"),
            });
        }
        if matches!(
            self.language,
            Language::JavaScript | Language::TypeScript | Language::Tsx
        ) && matches!(name, "GET" | "POST" | "PUT" | "DELETE" | "PATCH")
            && node
                .parent()
                .is_some_and(|parent| parent.kind() == "export_statement")
        {
            return Some(EntryPoint {
                kind: EntryKind::HttpRoute,
                detail: format!("exported route handler {name}"),
            });
        }
        if self.language == Language::Python
            && name == "main"
            && self.source.contains("__name__ == \"__main__\"")
                | self.source.contains("__name__ == '__main__'")
        {
            return Some(EntryPoint {
                kind: EntryKind::Main,
                detail: "main() under __main__".into(),
            });
        }
        None
    }

    fn decorations<'t>(&self, node: Node<'t>) -> Vec<Node<'t>> {
        let mut found = Vec::new();
        let mut collect = |container: Node<'t>| {
            let mut cursor = container.walk();
            for child in container.named_children(&mut cursor) {
                match child.kind() {
                    "decorator" | "annotation" | "marker_annotation" | "attribute" => {
                        found.push(child)
                    }
                    "attribute_list" | "modifiers" => {
                        let mut inner = child.walk();
                        found.extend(
                            child
                                .named_children(&mut inner)
                                .filter(|n| Language::is_decoration(n.kind())),
                        );
                    }
                    _ => {}
                }
            }
        };
        match self.language {
            Language::Python => {
                if let Some(parent) = node
                    .parent()
                    .filter(|parent| parent.kind() == "decorated_definition")
                {
                    collect(parent);
                }
            }
            Language::Rust => {
                let mut sibling = node.prev_named_sibling();
                while let Some(current) = sibling.filter(|s| s.kind() == "attribute_item") {
                    collect(current);
                    sibling = current.prev_named_sibling();
                }
            }
            _ => collect(node),
        }
        found
    }

    fn decoration_name(&self, decoration: Node<'_>) -> String {
        let target = decoration
            .child_by_field_name("name")
            .or_else(|| {
                let first = first_named_child(decoration)?;
                Some(match first.kind() {
                    "call" | "call_expression" => {
                        first.child_by_field_name("function").unwrap_or(first)
                    }
                    _ => first,
                })
            })
            .unwrap_or(decoration);
        last_segment(&dotted(&self.text(target))).to_owned()
    }

    // ---- calls -------------------------------------------------------------------------------

    fn handle_call(&mut self, node: Node<'_>) {
        let Some(callee) = self.callee(node) else {
            return;
        };
        if callee.is_empty() {
            return;
        }
        if let Some(frame) = self.frames.last()
            && self.findings.calls.len() < MAX_CALL_FACTS_PER_FILE
        {
            self.findings.calls.push(CallFact {
                caller: frame.id.clone(),
                callee: last_segment(&callee).to_owned(),
                location: self.location(node),
            });
        }
        self.handle_route_registration(node, &callee);
        self.link_module_binding(node, &callee);
        let matches = self.rules.for_call(self.language, &callee);
        for (rule, captures) in matches {
            if self.findings.observations.len() >= MAX_OBSERVATIONS_PER_FILE {
                return;
            }
            self.apply_rule(node, &callee, rule, &captures);
        }
    }

    /// A function calling a method on a module-level crypto object (`_key.public_key()` where
    /// `_key = rsa.generate_private_key(...)` sits at module scope) uses that asset. The use is
    /// recorded as another occurrence attributed to the function, so reachability and data
    /// classification see the code that actually exercises the key, not just where it was made.
    fn link_module_binding(&mut self, node: Node<'_>, callee: &str) {
        let Some(function) = self.frames.last().map(|frame| frame.id.clone()) else {
            return;
        };
        let mut segments = callee.split('.');
        let first = segments.next().unwrap_or_default();
        let variable = if matches!(first, "self" | "this" | "cls") {
            segments.next().unwrap_or_default()
        } else {
            first
        };
        if variable.is_empty()
            || variable == callee
            || self
                .frames
                .iter()
                .any(|f| f.bindings.contains_key(variable))
        {
            return;
        }
        let Some(&index) = self.file_bindings.get(variable) else {
            return;
        };
        if self.findings.observations.len() >= MAX_OBSERVATIONS_PER_FILE
            || !self
                .linked_uses
                .insert((function.clone(), variable.to_owned()))
        {
            return;
        }
        let mut observation = self.findings.observations[index].clone();
        observation.location = self.location(node);
        observation.evidence.rule_id.push_str("+use");
        observation.evidence.matched_token = truncate(variable, MAX_TOKEN);
        if let Some(usage) = observation.usage.as_mut() {
            usage.api = truncate(callee, MAX_TOKEN);
            usage.function = Some(function);
            usage.identifiers = self.identifiers(node);
        }
        self.findings.observations.push(observation);
    }

    /// The call target as a dotted path, with argument lists and generics removed:
    /// `Router::new().route` → `Router.new.route`, `javax.crypto.Cipher.getInstance`.
    fn callee(&self, node: Node<'_>) -> Option<String> {
        let target = match node.kind() {
            "method_invocation" => {
                let name = self.text(node.child_by_field_name("name")?);
                return Some(match node.child_by_field_name("object") {
                    Some(object) => format!("{}.{name}", dotted(&self.text(object))),
                    None => name,
                });
            }
            "object_creation_expression" => node.child_by_field_name("type")?,
            "new_expression" => node.child_by_field_name("constructor")?,
            _ => node.child_by_field_name("function")?,
        };
        Some(dotted(&self.text(target)))
    }

    fn arguments<'t>(&self, call: Node<'t>) -> Vec<(Option<String>, Node<'t>)> {
        let Some(arguments) = call.child_by_field_name("arguments") else {
            return Vec::new();
        };
        let mut cursor = arguments.walk();
        arguments
            .named_children(&mut cursor)
            .filter(|child| !Language::is_comment(child.kind()))
            .filter_map(|child| match child.kind() {
                "keyword_argument" => Some((
                    child.child_by_field_name("name").map(|n| self.text(n)),
                    child.child_by_field_name("value")?,
                )),
                "argument" => {
                    let keyword = child.child_by_field_name("name").map(|n| self.text(n));
                    Some((keyword, last_named_child(child)?))
                }
                _ => Some((None, child)),
            })
            .collect()
    }

    fn handle_route_registration(&mut self, node: Node<'_>, callee: &str) {
        let name = last_segment(callee).to_ascii_lowercase();
        if !ROUTE_REGISTRATIONS.contains(&name.as_str()) {
            return;
        }
        let arguments = self.arguments(node);
        let Some((_, first)) = arguments.first() else {
            return;
        };
        let Some(route) = self
            .string_literal(*first)
            .filter(|path| path.starts_with('/'))
        else {
            return;
        };
        let detail = truncate(&format!("{callee}(\"{route}\")"), 120);
        let entry = EntryPoint {
            kind: EntryKind::HttpRoute,
            detail,
        };
        for (_, argument) in arguments.iter().skip(1) {
            self.bind_handler(*argument, &entry, 0);
        }
    }

    fn bind_handler(&mut self, argument: Node<'_>, entry: &EntryPoint, depth: usize) {
        let kind = argument.kind();
        if self.language.is_function(kind) {
            self.pending_entries.insert(argument.id(), entry.clone());
        } else if Language::is_path(kind) {
            let handler = last_segment(&dotted(&self.text(argument))).to_owned();
            if is_identifier(&handler) {
                self.findings.bindings.push(EntryBinding {
                    component: self.component.to_owned(),
                    file: self.path.to_owned(),
                    handler,
                    entry: entry.clone(),
                    location: self.location(argument),
                });
            }
        } else if depth == 0 && self.language.is_call(kind) {
            // axum `.route("/pay", post(pay))`: the handler is inside the method router call
            for (_, inner) in self.arguments(argument) {
                self.bind_handler(inner, entry, depth + 1);
            }
        }
    }

    fn apply_rule(
        &mut self,
        node: Node<'_>,
        callee: &str,
        rule: &CompiledRule,
        captures: &HashMap<String, String>,
    ) {
        match rule.def.kind {
            RuleKind::Algorithm => self.apply_algorithm_rule(node, callee, rule, captures),
            RuleKind::Refine => self.apply_refine_rule(node, callee, rule, captures),
            RuleKind::CipherList | RuleKind::GroupList | RuleKind::ProtocolVersion => {
                self.apply_protocol_rule(node, callee, rule, captures)
            }
            RuleKind::Assign => {}
        }
    }

    fn apply_algorithm_rule(
        &mut self,
        node: Node<'_>,
        callee: &str,
        rule: &CompiledRule,
        captures: &HashMap<String, String>,
    ) {
        let mut outcomes: Vec<(AlgorithmRef, AlgorithmSource)> = Vec::new();
        if let Some(id) = &rule.def.algorithm {
            outcomes.push((AlgorithmRef::new(id), AlgorithmSource::Implicit));
        } else if !rule.def.algorithms.is_empty() {
            outcomes.extend(
                rule.def
                    .algorithms
                    .iter()
                    .map(|id| (AlgorithmRef::new(id), AlgorithmSource::Implicit)),
            );
        } else if let Some(source) = &rule.def.from {
            for (resolved, origin) in self.resolve(node, captures, source, Grammar::Name, None) {
                if let Resolved::Algorithm(algorithm) = resolved {
                    outcomes.push((algorithm, origin));
                }
            }
        }
        if outcomes.is_empty() {
            return;
        }
        let extracted = self.extract_params(node, captures, rule, None);
        let heuristic = node.has_error();
        let mut last_index = None;
        let registry = Registry::active();
        let mut seen = BTreeSet::new();
        for (mut algorithm, origin) in outcomes {
            algorithm.params.fill_from(&rule.def.params);
            algorithm.params.fill_from(&extracted);
            if let Some(spec) = registry.get(&algorithm.id) {
                algorithm.params = relevant_params(spec.primitive, algorithm.params);
                if let Some(curve) = algorithm.params.curve.take() {
                    algorithm.params.curve = Some(registry.canonical_curve(&curve));
                }
            }
            if !seen.insert(algorithm.clone()) {
                continue;
            }
            let finding = Finding::Algorithm(AlgorithmFinding {
                algorithm,
                primitive: rule.def.primitive,
                function: rule.def.function,
            });
            last_index = Some(self.emit(node, callee, rule, finding, origin, heuristic));
        }
        if let (Some(index), Some(variable)) = (last_index, self.binding_variable(node)) {
            match self.frames.last_mut() {
                Some(frame) => frame.bindings.insert(variable, index),
                None => self.file_bindings.insert(variable, index),
            };
        }
    }

    fn apply_refine_rule(
        &mut self,
        node: Node<'_>,
        callee: &str,
        rule: &CompiledRule,
        captures: &HashMap<String, String>,
    ) {
        let receiver = match rule.def.receiver_arg {
            Some(index) => self
                .arguments(node)
                .get(index)
                .map(|(_, argument)| last_segment(&dotted(&self.text(*argument))).to_owned()),
            None => {
                let segments: Vec<&str> = callee.split('.').collect();
                (segments.len() >= 2).then(|| segments[segments.len() - 2].to_owned())
            }
        };
        let Some(receiver) = receiver else { return };
        let Some(index) = self.lookup_binding(&receiver) else {
            return;
        };
        let params = self.extract_params(node, captures, rule, None);
        self.refine_observation(index, &params);
    }

    fn refine_observation(&mut self, index: usize, params: &Params) {
        let registry = Registry::active();
        if let Some(Observation {
            finding: Finding::Algorithm(finding),
            ..
        }) = self.findings.observations.get_mut(index)
        {
            let mut merged = finding.algorithm.params.clone();
            merged.fill_from(params);
            if let Some(spec) = registry.get(&finding.algorithm.id) {
                merged = relevant_params(spec.primitive, merged);
                if let Some(curve) = merged.curve.take() {
                    merged.curve = Some(registry.canonical_curve(&curve));
                }
            }
            finding.algorithm.params = merged;
        }
    }

    fn apply_protocol_rule(
        &mut self,
        node: Node<'_>,
        callee: &str,
        rule: &CompiledRule,
        captures: &HashMap<String, String>,
    ) {
        let Some(source) = &rule.def.from else { return };
        let protocol = rule.def.protocol.unwrap_or(ProtocolKind::Tls);
        let heuristic = node.has_error();
        match rule.def.kind {
            RuleKind::ProtocolVersion => {
                for (resolved, origin) in
                    self.resolve(node, captures, source, Grammar::Version, None)
                {
                    if let Resolved::Protocol(kind, version) = resolved {
                        let finding = Finding::Protocol(ProtocolFinding {
                            protocol: kind,
                            version: Some(version),
                            cipher_suites: Vec::new(),
                            groups: Vec::new(),
                        });
                        self.emit(node, callee, rule, finding, origin, heuristic);
                    }
                }
            }
            RuleKind::CipherList | RuleKind::GroupList => {
                let texts: Vec<Candidate> = self.raw_values(node, captures, source);
                let mut suites = Vec::new();
                let mut groups = Vec::new();
                let mut algorithms: Vec<AlgorithmRef> = Vec::new();
                let mut origin = AlgorithmSource::Literal;
                for candidate in texts {
                    origin = candidate.source;
                    for token in candidate
                        .text
                        .split([':', ',', ' ', ';'])
                        .map(str::trim)
                        .filter(|t| !t.is_empty())
                    {
                        if rule.def.kind == RuleKind::CipherList {
                            if let Some(suite) = names::parse_cipher_suite(token) {
                                algorithms.extend(suite.algorithms().cloned());
                                suites.push(suite.name);
                            }
                        } else if let Some(group) = names::resolve_group(token) {
                            algorithms.push(group);
                            groups.push(token.to_owned());
                        }
                    }
                }
                if suites.is_empty() && groups.is_empty() {
                    return;
                }
                suites.sort();
                suites.dedup();
                groups.sort();
                groups.dedup();
                let finding = Finding::Protocol(ProtocolFinding {
                    protocol,
                    version: None,
                    cipher_suites: suites,
                    groups,
                });
                self.emit(node, callee, rule, finding, origin, heuristic);
                let registry = Registry::active();
                algorithms.sort();
                algorithms.dedup();
                for mut algorithm in algorithms {
                    if let Some(curve) = algorithm.params.curve.take() {
                        algorithm.params.curve = Some(registry.canonical_curve(&curve));
                    }
                    self.emit(
                        node,
                        callee,
                        rule,
                        Finding::algorithm(algorithm),
                        origin,
                        heuristic,
                    );
                }
            }
            _ => {}
        }
    }

    fn handle_assignment(&mut self, node: Node<'_>) {
        let (Some(left), Some(right)) = (
            node.child_by_field_name("left"),
            node.child_by_field_name("right"),
        ) else {
            return;
        };
        let target = dotted(&self.text(left));
        let segments: Vec<&str> = target.split('.').collect();
        if segments.len() < 2 {
            return;
        }
        let property = segments[segments.len() - 1];
        let receiver = segments[segments.len() - 2];
        let rules = self.rules.for_assignment(self.language, property);
        if rules.is_empty() {
            return;
        }
        let Some(index) = self.lookup_binding(receiver) else {
            return;
        };
        for rule in rules {
            let params = self.extract_params(node, &HashMap::new(), rule, Some(right));
            self.refine_observation(index, &params);
        }
    }

    fn handle_import(&mut self, node: Node<'_>) {
        if self.rules.imports.is_empty()
            || self.findings.observations.len() >= MAX_OBSERVATIONS_PER_FILE
        {
            return;
        }
        let text = truncate(&self.text(node), 256);
        let stripped: String = text
            .replace(['"', '\'', '<', '>', ';', '{', '}', '(', ')'], " ")
            .split_whitespace()
            .filter(|word| {
                !matches!(
                    *word,
                    "from"
                        | "import"
                        | "use"
                        | "using"
                        | "#include"
                        | "include"
                        | "static"
                        | "as"
                        | "pub"
                )
            })
            .collect::<Vec<_>>()
            .join("/");
        let variants = [
            stripped.clone(),
            stripped.replace(['.', ':'], "/").replace("//", "/"),
        ];
        let language = self.language;
        let matches: Vec<_> = self
            .rules
            .imports
            .iter()
            .filter(|rule| {
                rule.languages
                    .iter()
                    .any(|l| language.matches_rule_language(l))
            })
            .filter(|rule| {
                rule.module
                    .iter()
                    .any(|module| variants.iter().any(|v| v.contains(module.as_str())))
            })
            .cloned()
            .collect();
        for rule in matches {
            let algorithm = AlgorithmRef::with_params(rule.algorithm.clone(), rule.params.clone());
            self.findings.observations.push(Observation {
                surface: Surface::Source,
                component: self.component.to_owned(),
                location: self.location(node),
                finding: Finding::algorithm(algorithm),
                evidence: Evidence {
                    collector: COLLECTOR.into(),
                    rule_id: rule.id.clone(),
                    rule_version: self.rules.version.clone(),
                    kind: EvidenceKind::Import,
                    matched_token: truncate(&stripped, MAX_TOKEN),
                },
                usage: None,
            });
        }
    }

    /// Go `tls.Config{MinVersion: ..., CipherSuites: ..., CurvePreferences: ...}`: TLS policy
    /// written as a struct literal rather than a call.
    fn handle_go_tls_config(&mut self, node: Node<'_>) {
        let Some(type_node) = node.child_by_field_name("type") else {
            return;
        };
        if dotted(&self.text(type_node)) != "tls.Config" {
            return;
        }
        let Some(body) = node.child_by_field_name("body") else {
            return;
        };
        let mut version = None;
        let mut suites = Vec::new();
        let mut groups = Vec::new();
        let mut algorithms = Vec::new();
        let mut cursor = body.walk();
        for element in body
            .named_children(&mut cursor)
            .filter(|n| n.kind() == "keyed_element")
        {
            let (Some(key), Some(value)) = (
                element.child_by_field_name("key"),
                element.child_by_field_name("value"),
            ) else {
                continue;
            };
            let names: Vec<String> =
                descendants_of(value, &["selector_expression", "identifier"], 64)
                    .into_iter()
                    .filter(|n| {
                        n.kind() == "selector_expression"
                            || n.parent()
                                .is_some_and(|p| p.kind() != "selector_expression")
                    })
                    .map(|n| last_segment(&dotted(&self.text(n))).to_owned())
                    .collect();
            match self.text(key).as_str() {
                "MinVersion" => {
                    version = names
                        .first()
                        .and_then(|name| names::parse_protocol_version(name))
                }
                "CipherSuites" => {
                    for name in &names {
                        if let Some(suite) = names::parse_cipher_suite(name) {
                            algorithms.extend(suite.algorithms().cloned());
                            suites.push(suite.name);
                        }
                    }
                }
                "CurvePreferences" => {
                    for name in &names {
                        let group_name = name.strip_prefix("Curve").unwrap_or(name);
                        if let Some(group) = names::resolve_group(group_name) {
                            algorithms.push(group);
                            groups.push(group_name.to_owned());
                        }
                    }
                }
                _ => {}
            }
        }
        if version.is_none() && suites.is_empty() && groups.is_empty() {
            return;
        }
        let evidence = Evidence {
            collector: COLLECTOR.into(),
            rule_id: "go.tls.config".into(),
            rule_version: self.rules.version.clone(),
            kind: if node.has_error() {
                EvidenceKind::Heuristic
            } else {
                EvidenceKind::ApiCall
            },
            matched_token: "tls.Config".into(),
        };
        let usage = Usage {
            language: self.language.name().into(),
            api: "tls.Config".into(),
            function: self.frames.last().map(|frame| frame.id.clone()),
            identifiers: Vec::new(),
            algorithm_source: AlgorithmSource::Literal,
            api_style: lattice_core::ApiStyle::Protocol,
        };
        let (protocol, version) = match version {
            Some((protocol, version)) => (protocol, Some(version)),
            None => (ProtocolKind::Tls, None),
        };
        let mut findings = vec![Finding::Protocol(ProtocolFinding {
            protocol,
            version,
            cipher_suites: suites,
            groups,
        })];
        let registry = Registry::active();
        findings.extend(algorithms.into_iter().map(|mut algorithm| {
            if let Some(curve) = algorithm.params.curve.take() {
                algorithm.params.curve = Some(registry.canonical_curve(&curve));
            }
            Finding::algorithm(algorithm)
        }));
        for finding in findings {
            self.findings.observations.push(Observation {
                surface: Surface::Source,
                component: self.component.to_owned(),
                location: self.location(node),
                finding,
                evidence: evidence.clone(),
                usage: Some(usage.clone()),
            });
        }
    }

    // ---- values ------------------------------------------------------------------------------

    /// Applies a rule's parameter extractors. The first extractor to succeed for a parameter
    /// wins; later ones for the same parameter are fallbacks.
    fn extract_params(
        &self,
        node: Node<'_>,
        captures: &HashMap<String, String>,
        rule: &CompiledRule,
        assigned: Option<Node<'_>>,
    ) -> Params {
        let mut params = Params::default();
        for definition in &rule.def.param {
            let grammar = definition.source.grammar.unwrap_or(match definition.name {
                ParamName::KeyBits => Grammar::Int,
                ParamName::Curve => Grammar::Curve,
                ParamName::Mode => Grammar::Mode,
                ParamName::Padding => Grammar::Padding,
                ParamName::Digest => Grammar::Digest,
                ParamName::ParameterSet => Grammar::Name,
            });
            let already = match definition.name {
                ParamName::KeyBits => params.key_bits.is_some(),
                ParamName::ParameterSet => params.parameter_set.is_some(),
                ParamName::Curve => params.curve.is_some(),
                ParamName::Mode => params.mode.is_some(),
                ParamName::Padding => params.padding.is_some(),
                ParamName::Digest => params.digest.is_some(),
            };
            if already {
                continue;
            }
            if definition.name == ParamName::ParameterSet && definition.source.grammar.is_none() {
                if let Some(candidate) = self
                    .raw_values(node, captures, &definition.source)
                    .into_iter()
                    .next()
                {
                    params.parameter_set = Some(candidate.text);
                }
                continue;
            }
            for (resolved, _) in self.resolve(node, captures, &definition.source, grammar, assigned)
            {
                let value = match resolved {
                    Resolved::Params(value) => value,
                    Resolved::Algorithm(algorithm) => {
                        let mut value = algorithm.params.clone();
                        if definition.name == ParamName::Digest {
                            value.digest = Some(algorithm.id.clone());
                        }
                        value
                    }
                    Resolved::Protocol(..) => continue,
                };
                let taken = match definition.name {
                    ParamName::KeyBits => value.key_bits.map(|bits| params.key_bits = Some(bits)),
                    ParamName::ParameterSet => value
                        .parameter_set
                        .map(|set| params.parameter_set = Some(set)),
                    ParamName::Curve => value.curve.map(|curve| params.curve = Some(curve)),
                    ParamName::Mode => value.mode.map(|mode| params.mode = Some(mode)),
                    ParamName::Padding => {
                        value.padding.map(|padding| params.padding = Some(padding))
                    }
                    ParamName::Digest => value.digest.map(|digest| params.digest = Some(digest)),
                };
                if taken.is_some() {
                    break;
                }
            }
        }
        params
    }

    /// Resolves a value source under a grammar. Array arguments yield one result per element;
    /// anything else yields the first candidate that the grammar accepts.
    fn resolve(
        &self,
        node: Node<'_>,
        captures: &HashMap<String, String>,
        source: &ValueSource,
        default: Grammar,
        assigned: Option<Node<'_>>,
    ) -> Vec<(Resolved, AlgorithmSource)> {
        let grammar = source.grammar.unwrap_or(default);
        let groups: Vec<Vec<Candidate>> = if let Some(capture) = &source.capture {
            captures
                .get(capture)
                .map(|text| {
                    vec![vec![Candidate {
                        text: text.clone(),
                        source: AlgorithmSource::Implicit,
                    }]]
                })
                .unwrap_or_default()
        } else if source.value {
            assigned
                .map(|value| vec![self.candidates(value, 0)])
                .unwrap_or_default()
        } else {
            match self.source_node(node, source) {
                Some(value)
                    if matches!(
                        value.kind(),
                        "array"
                            | "list"
                            | "array_creation_expression"
                            | "array_initializer"
                            | "initializer_list"
                            | "tuple"
                    ) =>
                {
                    let mut cursor = value.walk();
                    let elements: Vec<Node<'_>> = value
                        .named_children(&mut cursor)
                        .filter(|child| !Language::is_comment(child.kind()))
                        .flat_map(|child| {
                            // Java `new String[]{"a"}`: descend into the initializer
                            if matches!(
                                child.kind(),
                                "array_initializer" | "initializer_expression"
                            ) {
                                let mut inner = child.walk();
                                child.named_children(&mut inner).collect::<Vec<_>>()
                            } else {
                                vec![child]
                            }
                        })
                        .collect();
                    elements
                        .into_iter()
                        .map(|element| self.candidates(element, 0))
                        .collect()
                }
                Some(value) => vec![self.candidates(value, 0)],
                None => Vec::new(),
            }
        };
        let mut results = Vec::new();
        for candidates in groups {
            for candidate in candidates {
                let variants =
                    strip_variants(&candidate.text, &source.strip_prefix, &source.strip_suffix);
                if let Some(resolved) = variants
                    .iter()
                    .find_map(|variant| apply_grammar(grammar, variant))
                {
                    results.push((resolved, candidate.source));
                    break;
                }
            }
        }
        results
    }

    /// Raw candidate strings for list-valued sources (cipher strings, group lists).
    fn raw_values(
        &self,
        node: Node<'_>,
        captures: &HashMap<String, String>,
        source: &ValueSource,
    ) -> Vec<Candidate> {
        if let Some(capture) = &source.capture {
            return captures
                .get(capture)
                .map(|text| {
                    vec![Candidate {
                        text: text.clone(),
                        source: AlgorithmSource::Implicit,
                    }]
                })
                .unwrap_or_default();
        }
        let Some(value) = self.source_node(node, source) else {
            return Vec::new();
        };
        let nodes: Vec<Node<'_>> = if matches!(
            value.kind(),
            "array" | "list" | "array_creation_expression" | "array_initializer"
        ) {
            descendants_of(
                value,
                &[
                    "string",
                    "string_literal",
                    "interpreted_string_literal",
                    "identifier",
                ],
                256,
            )
        } else {
            vec![value]
        };
        nodes
            .into_iter()
            .filter_map(|n| {
                if let Some(text) = self.string_literal(n) {
                    return Some(Candidate {
                        text,
                        source: AlgorithmSource::Literal,
                    });
                }
                if n.kind() == "identifier"
                    && let Some(Literal::Str(text)) = self.constants.get(&self.text(n))
                {
                    return Some(Candidate {
                        text: text.clone(),
                        source: AlgorithmSource::Constant,
                    });
                }
                None
            })
            .collect()
    }

    fn source_node<'t>(&self, call: Node<'t>, source: &ValueSource) -> Option<Node<'t>> {
        let arguments = self.arguments(call);
        if let Some(keyword) = &source.keyword {
            return arguments
                .iter()
                .find(|(name, _)| name.as_deref() == Some(keyword))
                .map(|(_, node)| *node);
        }
        if let Some(property) = &source.property {
            let searched: Vec<Node<'t>> = match source.arg {
                Some(index) => arguments
                    .get(index)
                    .map(|(_, node)| *node)
                    .into_iter()
                    .collect(),
                None => arguments.iter().map(|(_, node)| *node).collect(),
            };
            return searched
                .into_iter()
                .find_map(|argument| self.object_property(argument, property));
        }
        let index = source.arg?;
        arguments
            .iter()
            .filter(|(name, _)| name.is_none())
            .nth(index)
            .map(|(_, node)| *node)
    }

    fn object_property<'t>(&self, object: Node<'t>, property: &str) -> Option<Node<'t>> {
        if !matches!(object.kind(), "object" | "dictionary") {
            return None;
        }
        let mut cursor = object.walk();
        object
            .named_children(&mut cursor)
            .filter(|child| child.kind() == "pair")
            .find(|pair| {
                pair.child_by_field_name("key")
                    .is_some_and(|key| unquote(&self.text(key)) == property)
            })
            .and_then(|pair| pair.child_by_field_name("value"))
    }

    /// Every reading of a value, most direct first.
    fn candidates(&self, node: Node<'_>, depth: usize) -> Vec<Candidate> {
        if depth > 3 {
            return Vec::new();
        }
        let kind = node.kind();
        if let Some(text) = self.string_literal(node) {
            return vec![Candidate {
                text,
                source: AlgorithmSource::Literal,
            }];
        }
        if Language::is_integer(kind) {
            return parse_int(&self.text(node))
                .map(|value| {
                    vec![Candidate {
                        text: value.to_string(),
                        source: AlgorithmSource::Literal,
                    }]
                })
                .unwrap_or_default();
        }
        if kind == "preproc_arg" {
            return vec![Candidate {
                text: self.text(node).trim().to_owned(),
                source: AlgorithmSource::Constant,
            }];
        }
        if kind == "identifier" {
            let name = self.text(node);
            if let Some(literal) = self.constants.get(&name) {
                return vec![Candidate {
                    text: literal.text(),
                    source: AlgorithmSource::Constant,
                }];
            }
            // Macro-style constants from headers (`EVP_PKEY_RSA`, `NID_secp384r1`) name the
            // algorithm themselves; ordinary variables do not and stay unresolved (dynamic).
            if looks_like_constant(&name) {
                return vec![Candidate {
                    text: name,
                    source: AlgorithmSource::Implicit,
                }];
            }
            return Vec::new();
        }
        if Language::is_path(kind) {
            return path_candidates(&dotted(&self.text(node)));
        }
        if self.language.is_call(kind) {
            let mut result = self
                .callee(node)
                .map(|callee| path_candidates(&callee))
                .unwrap_or_default();
            if let Some((_, first)) = self.arguments(node).into_iter().find(|(_, argument)| {
                self.string_literal(*argument).is_some() || Language::is_integer(argument.kind())
            }) {
                result.extend(self.candidates(first, depth + 1));
            }
            return result;
        }
        if matches!(
            kind,
            "unary_expression"
                | "reference_expression"
                | "await_expression"
                | "parenthesized_expression"
                | "cast_expression"
                | "type_cast_expression"
                | "as_expression"
                | "non_null_expression"
                | "pointer_expression"
                | "literal_element"
                | "expression_list"
                | "argument"
                | "try_expression"
                | "field_initializer"
        ) {
            return last_named_child(node)
                .map(|inner| self.candidates(inner, depth + 1))
                .unwrap_or_default();
        }
        Vec::new()
    }

    /// Unquoted content of a string literal, or `None` if the node is not a plain string (an
    /// interpolated template is dynamic, not literal).
    fn string_literal(&self, node: Node<'_>) -> Option<String> {
        if !Language::is_string(node.kind()) {
            return None;
        }
        let mut cursor = node.walk();
        let children: Vec<Node<'_>> = node.named_children(&mut cursor).collect();
        if children.iter().any(|child| {
            matches!(
                child.kind(),
                "interpolation" | "template_substitution" | "string_interpolation"
            )
        }) {
            return None;
        }
        let content: String = children
            .iter()
            .filter(|child| {
                matches!(
                    child.kind(),
                    "string_content"
                        | "string_fragment"
                        | "interpreted_string_literal_content"
                        | "string_literal_content"
                        | "escape_sequence"
                        | "raw_string_literal_content"
                )
            })
            .map(|child| self.text(*child))
            .collect();
        if !content.is_empty() {
            return Some(content);
        }
        if node.kind() == "concatenated_string" {
            return Some(
                children
                    .iter()
                    .filter_map(|child| self.string_literal(*child))
                    .collect(),
            );
        }
        Some(unquote(&self.text(node)))
    }

    fn collect_constants(&mut self, root: Node<'_>) -> Result<(), String> {
        let mut cursor = root.walk();
        let mut visited = 0usize;
        'walk: loop {
            let node = cursor.node();
            visited += 1;
            if visited.is_multiple_of(4096) {
                self.deadline.check()?;
            }
            if let Some((name, value)) = self.language.binding_parts(node)
                && matches!(
                    name.kind(),
                    "identifier" | "field_identifier" | "property_identifier"
                )
            {
                let literal = if let Some(text) = self.string_literal(value) {
                    Some(Literal::Str(text))
                } else if Language::is_integer(value.kind()) || value.kind() == "preproc_arg" {
                    let text = self.text(value);
                    parse_int(text.trim()).map(Literal::Int).or_else(|| {
                        let unquoted = unquote(text.trim());
                        (!unquoted.is_empty() && value.kind() == "preproc_arg")
                            .then_some(Literal::Str(unquoted))
                    })
                } else {
                    None
                };
                if let Some(literal) = literal {
                    self.constants.insert(self.text(name), literal);
                }
            }
            if cursor.goto_first_child() {
                continue;
            }
            loop {
                if cursor.goto_next_sibling() {
                    continue 'walk;
                }
                if !cursor.goto_parent() {
                    break 'walk;
                }
            }
        }
        Ok(())
    }

    /// The variable a call's result is bound to: `kpg` in `kpg = KeyPairGenerator.getInstance(..)`.
    fn binding_variable(&self, call: Node<'_>) -> Option<String> {
        let mut child = call;
        for _ in 0..4 {
            let parent = child.parent()?;
            if let Some((name, value)) = self.language.binding_parts(parent) {
                if value.id() == child.id() || is_ancestor(value, call) {
                    let text = last_segment(&dotted(&self.text(name))).to_owned();
                    return is_identifier(&text).then_some(text);
                }
                return None;
            }
            if !matches!(
                parent.kind(),
                "await_expression"
                    | "unary_expression"
                    | "parenthesized_expression"
                    | "expression_list"
                    | "cast_expression"
                    | "try_expression"
                    | "reference_expression"
                    | "as_expression"
                    | "non_null_expression"
                    | "equals_value_clause"
            ) {
                return None;
            }
            child = parent;
        }
        None
    }

    fn lookup_binding(&self, variable: &str) -> Option<usize> {
        self.frames
            .iter()
            .rev()
            .find_map(|frame| frame.bindings.get(variable).copied())
            .or_else(|| self.file_bindings.get(variable).copied())
    }

    // ---- output -----------------------------------------------------------------------------

    fn emit(
        &mut self,
        node: Node<'_>,
        callee: &str,
        rule: &CompiledRule,
        finding: Finding,
        origin: AlgorithmSource,
        heuristic: bool,
    ) -> usize {
        let usage = Usage {
            language: self.language.name().into(),
            api: truncate(callee, MAX_TOKEN),
            function: self.frames.last().map(|frame| frame.id.clone()),
            identifiers: self.identifiers(node),
            algorithm_source: origin,
            api_style: rule.def.style,
        };
        self.findings.observations.push(Observation {
            surface: Surface::Source,
            component: self.component.to_owned(),
            location: self.location(node),
            finding,
            evidence: Evidence {
                collector: COLLECTOR.into(),
                rule_id: rule.def.id.clone(),
                rule_version: format!("{}/{}", self.rules.version, rule.def.version),
                kind: if heuristic {
                    EvidenceKind::Heuristic
                } else {
                    EvidenceKind::ApiCall
                },
                matched_token: truncate(callee, MAX_TOKEN),
            },
            usage: Some(usage),
        });
        self.findings.observations.len() - 1
    }

    /// Identifier names in a call's arguments and the variable it is bound to. Names only: the
    /// classifier reads them to decide what data the call touches; values are never kept.
    fn identifiers(&self, call: Node<'_>) -> Vec<String> {
        let mut names = BTreeSet::new();
        if let Some(variable) = self.binding_variable(call) {
            names.insert(variable);
        }
        if let Some(arguments) = call.child_by_field_name("arguments") {
            for node in descendants_of(
                arguments,
                &["identifier", "property_identifier", "field_identifier"],
                64,
            ) {
                if is_api_vocabulary(node, arguments) {
                    continue;
                }
                let text = self.text(node);
                if is_identifier(&text) && text.len() <= 48 {
                    names.insert(text);
                }
                if names.len() >= MAX_IDENTIFIERS {
                    break;
                }
            }
        }
        names.into_iter().collect()
    }

    fn location(&self, node: Node<'_>) -> Location {
        let start = node.start_position();
        Location {
            path: self.path.to_owned(),
            line: Some(start.row as u64 + 1),
            column: Some(start.column as u64 + 1),
            byte_offset: Some(node.start_byte() as u64),
        }
    }

    fn text(&self, node: Node<'_>) -> String {
        self.source.get(node.byte_range()).unwrap_or("").to_owned()
    }
}

// ---- helpers --------------------------------------------------------------------------------

/// Whether an identifier inside a call's arguments names API vocabulary rather than data: a
/// keyword or option name (`public_exponent=`, `{ modulusLength: … }`) or the callee of a nested
/// call (`padding.OAEP(...)`, `hashes.SHA256()`). Those describe the crypto call itself and would
/// otherwise mislead data classification (`public_exponent` is not public data).
fn is_api_vocabulary(node: Node<'_>, arguments: Node<'_>) -> bool {
    let mut child = node;
    while let Some(parent) = child.parent() {
        if parent.id() == arguments.id() {
            return false;
        }
        let is_field = |field: &str| {
            parent
                .child_by_field_name(field)
                .is_some_and(|n| n.id() == child.id())
        };
        let vocabulary = match parent.kind() {
            // Python `name=value`; JS/TS object keys; Rust struct literal fields
            "keyword_argument" | "pair" | "field_initializer" => {
                is_field("name") || is_field("key") || is_field("field")
            }
            // callee of a nested call in every supported grammar
            "call" | "call_expression" | "invocation_expression" => is_field("function"),
            // Java `obj.method(...)`: the method name, not the receiver
            "method_invocation" => is_field("name"),
            _ => false,
        };
        if vocabulary {
            return true;
        }
        child = parent;
    }
    false
}

/// Keeps only the parameters meaningful for a primitive, so an extractor that reads a generic
/// "size" argument never attaches a key size to a hash.
fn relevant_params(primitive: Primitive, params: Params) -> Params {
    match primitive {
        Primitive::BlockCipher | Primitive::StreamCipher | Primitive::Ae => Params {
            key_bits: params.key_bits,
            mode: params.mode,
            padding: params.padding,
            ..Params::default()
        },
        Primitive::Hash | Primitive::Xof => Params::default(),
        Primitive::Mac | Primitive::Kdf | Primitive::Drbg => Params {
            digest: params.digest,
            key_bits: params.key_bits,
            ..Params::default()
        },
        Primitive::Kem | Primitive::Combiner => Params {
            parameter_set: params.parameter_set,
            ..Params::default()
        },
        Primitive::Signature | Primitive::Pke | Primitive::KeyAgree => Params {
            key_bits: params.key_bits,
            curve: params.curve,
            digest: params.digest,
            padding: params.padding,
            parameter_set: params.parameter_set,
            ..Params::default()
        },
        Primitive::Other | Primitive::Unknown => params,
    }
}

fn apply_grammar(grammar: Grammar, text: &str) -> Option<Resolved> {
    let text = text.trim();
    if text.is_empty() {
        return None;
    }
    match grammar {
        Grammar::Name => names::resolve(text).map(Resolved::Algorithm),
        Grammar::JcaCipher => names::resolve_jca_cipher(text).map(Resolved::Algorithm),
        Grammar::Group => names::resolve_group(text).map(Resolved::Algorithm),
        Grammar::Curve => names::resolve_curve(text).map(|curve| {
            Resolved::Params(Params {
                curve: Some(curve),
                ..Params::default()
            })
        }),
        Grammar::Mode => canonical_mode(text).map(|mode| {
            Resolved::Params(Params {
                mode: Some(mode),
                ..Params::default()
            })
        }),
        Grammar::Digest => {
            let algorithm = names::resolve(text)?;
            let spec = Registry::active().get(&algorithm.id)?;
            matches!(spec.primitive, Primitive::Hash | Primitive::Xof).then(|| {
                Resolved::Params(Params {
                    digest: Some(algorithm.id),
                    ..Params::default()
                })
            })
        }
        Grammar::Int => parse_int(text)
            .and_then(|value| u32::try_from(value).ok())
            .filter(|bits| (8..=65536).contains(bits))
            .map(|bits| {
                Resolved::Params(Params {
                    key_bits: Some(bits),
                    ..Params::default()
                })
            }),
        Grammar::Padding => {
            let normalized = lattice_core::knowledge::normalize_token(text);
            let padding = if normalized.contains("oaep") {
                "oaep"
            } else if normalized.contains("pss") {
                "pss"
            } else if normalized.contains("pkcs1") {
                "pkcs1v15"
            } else {
                return None;
            };
            Some(Resolved::Params(Params {
                padding: Some(padding.into()),
                ..Params::default()
            }))
        }
        Grammar::Version => names::parse_protocol_version(text)
            .map(|(kind, version)| Resolved::Protocol(kind, version)),
    }
}

fn canonical_mode(text: &str) -> Option<String> {
    let normalized = lattice_core::knowledge::normalize_token(text);
    let mode = match normalized.as_str() {
        "ecb" | "cbc" | "ctr" | "gcm" | "ccm" | "ofb" | "cfb" | "xts" | "ocb" | "siv" | "eax"
        | "kw" | "kwp" => normalized.as_str(),
        "cfb8" | "cfb1" | "cfb128" | "cfb64" => "cfb",
        "ofb128" | "ofb64" => "ofb",
        "ctr128" => "ctr",
        "gcmsiv" => "gcm-siv",
        "ocb3" => "ocb",
        "cts" => "cts",
        "ige" => "ige",
        _ => return None,
    };
    Some(mode.to_owned())
}

/// Candidate readings of a dotted path, most specific first: `hashes.SHA256` →
/// [`hashes.SHA256`, `SHA256`, `hashes`]; `sha256.New` → [.., `New`, `sha256`].
fn path_candidates(path: &str) -> Vec<Candidate> {
    let mut candidates = vec![Candidate {
        text: path.to_owned(),
        source: AlgorithmSource::Implicit,
    }];
    let segments: Vec<&str> = path.split('.').filter(|s| !s.is_empty()).collect();
    if segments.len() > 1 {
        candidates.extend(segments.iter().rev().map(|segment| Candidate {
            text: (*segment).to_owned(),
            source: AlgorithmSource::Implicit,
        }));
    }
    candidates
}

fn strip_variants(text: &str, prefixes: &[String], suffixes: &[String]) -> Vec<String> {
    let mut variants = vec![text.to_owned()];
    for prefix in prefixes {
        if let Some(rest) = text.strip_prefix(prefix.as_str()) {
            variants.insert(0, rest.to_owned());
        }
    }
    for suffix in suffixes {
        let current: Vec<String> = variants.clone();
        for variant in current {
            if let Some(rest) = variant.strip_suffix(suffix.as_str()) {
                variants.insert(0, rest.to_owned());
            }
        }
    }
    variants
}

/// Collapses a callee or path expression into `a.b.c`: separators `::`, `->`, `?.` become `.`,
/// argument lists and generic parameters are removed, whitespace dropped.
fn dotted(text: &str) -> String {
    let mut output = String::with_capacity(text.len().min(256));
    let mut depth_paren = 0usize;
    let mut depth_angle = 0usize;
    let mut chars = text.chars().peekable();
    while let Some(c) = chars.next() {
        if output.len() > 256 {
            break;
        }
        match c {
            '(' | '[' => depth_paren += 1,
            ')' | ']' => depth_paren = depth_paren.saturating_sub(1),
            '<' if depth_paren == 0 => depth_angle += 1,
            '>' if depth_angle > 0 => depth_angle -= 1,
            _ if depth_paren > 0 || depth_angle > 0 => {}
            ':' if chars.peek() == Some(&':') => {
                chars.next();
                output.push('.');
            }
            '-' if chars.peek() == Some(&'>') => {
                chars.next();
                output.push('.');
            }
            '?' if chars.peek() == Some(&'.') => {}
            c if c.is_whitespace() => {}
            '&' | '*' | '!' => {}
            c => output.push(c),
        }
    }
    while output.contains("..") {
        output = output.replace("..", ".");
    }
    output.trim_matches('.').to_owned()
}

fn last_segment(path: &str) -> &str {
    path.rsplit('.').next().unwrap_or(path)
}

fn unquote(text: &str) -> String {
    let trimmed = text.trim();
    let without_prefix = trimmed
        .trim_start_matches(|c: char| c.is_ascii_alphabetic() && trimmed.contains(['"', '\'']));
    without_prefix
        .trim_matches(|c| matches!(c, '"' | '\'' | '`'))
        .to_owned()
}

fn is_identifier(text: &str) -> bool {
    !text.is_empty()
        && text
            .chars()
            .next()
            .is_some_and(|c| c.is_alphabetic() || c == '_' || c == '$')
        && text
            .chars()
            .all(|c| c.is_alphanumeric() || c == '_' || c == '$')
}

/// `EVP_PKEY_RSA`, `NID_X9_62_prime256v1`, `BCRYPT_AES_ALGORITHM`, `MBEDTLS_ECP_DP_SECP256R1`:
/// macro names that carry the algorithm themselves. Requires an underscore and an uppercase
/// prefix so ordinary variables (`aes`, `key`) never qualify.
fn looks_like_constant(name: &str) -> bool {
    name.contains('_')
        && name
            .chars()
            .take_while(|c| *c != '_')
            .all(|c| c.is_ascii_uppercase() || c.is_ascii_digit())
        && name.chars().next().is_some_and(|c| c.is_ascii_uppercase())
}

fn parse_int(text: &str) -> Option<i128> {
    let cleaned: String = text
        .trim()
        .trim_end_matches(['u', 'U', 'l', 'L', 'z', 'Z'])
        .trim_end_matches("usize")
        .trim_end_matches("u32")
        .trim_end_matches("u64")
        .trim_end_matches("i32")
        .chars()
        .filter(|c| *c != '_' && *c != '\'')
        .collect();
    if let Some(hex) = cleaned
        .strip_prefix("0x")
        .or_else(|| cleaned.strip_prefix("0X"))
    {
        return i128::from_str_radix(hex, 16).ok();
    }
    cleaned.parse().ok()
}

fn truncate(text: &str, limit: usize) -> String {
    let single_line: String = text.split_whitespace().collect::<Vec<_>>().join(" ");
    if single_line.chars().count() <= limit {
        single_line
    } else {
        let cut: String = single_line.chars().take(limit.saturating_sub(1)).collect();
        format!("{cut}…")
    }
}

fn find_descendant<'t>(node: Node<'t>, kinds: &[&str], max_depth: usize) -> Option<Node<'t>> {
    descendants_of(node, kinds, 64)
        .into_iter()
        .find(|n| depth_below(node, *n) <= max_depth)
}

fn depth_below(ancestor: Node<'_>, node: Node<'_>) -> usize {
    let mut depth = 0;
    let mut current = node;
    while current.id() != ancestor.id() {
        match current.parent() {
            Some(parent) => {
                current = parent;
                depth += 1;
            }
            None => return usize::MAX,
        }
    }
    depth
}

fn is_ancestor(ancestor: Node<'_>, node: Node<'_>) -> bool {
    depth_below(ancestor, node) != usize::MAX
}

/// Bounded breadth-first collection of descendants of the given kinds (strings excluded).
fn descendants_of<'t>(node: Node<'t>, kinds: &[&str], limit: usize) -> Vec<Node<'t>> {
    let mut found = Vec::new();
    let mut queue = std::collections::VecDeque::from([node]);
    let mut visited = 0;
    while let Some(current) = queue.pop_front() {
        visited += 1;
        if visited > limit * 16 || found.len() >= limit {
            break;
        }
        if current.id() != node.id() && kinds.contains(&current.kind()) {
            found.push(current);
        }
        if Language::is_string(current.kind()) && current.id() != node.id() {
            continue;
        }
        let mut cursor = current.walk();
        queue.extend(current.named_children(&mut cursor));
    }
    found
}

#[cfg(test)]
mod tests;
