//! Per-language knowledge of tree-sitter grammars, verified against real parse trees
//! (`tests/ast_probe.rs`). Everything language-specific in the source collector lives here, so
//! the walker in `mod.rs` works in one vocabulary: calls, arguments, literals, functions.

use tree_sitter::{Language as Grammar, Node};

#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum Language {
    C,
    Cpp,
    Python,
    Java,
    Go,
    JavaScript,
    TypeScript,
    Tsx,
    Rust,
    CSharp,
}

impl Language {
    pub fn from_path(path: &str) -> Option<Self> {
        let extension = path.rsplit_once('.')?.1.to_ascii_lowercase();
        Some(match extension.as_str() {
            "c" | "h" => Self::C,
            "cc" | "cpp" | "cxx" | "c++" | "hpp" | "hh" | "hxx" | "ipp" => Self::Cpp,
            "py" | "pyi" | "pyw" => Self::Python,
            "java" => Self::Java,
            "go" => Self::Go,
            "js" | "mjs" | "cjs" | "jsx" => Self::JavaScript,
            "ts" | "mts" | "cts" => Self::TypeScript,
            "tsx" => Self::Tsx,
            "rs" => Self::Rust,
            "cs" => Self::CSharp,
            _ => return None,
        })
    }

    /// Name used in rules and reports.
    pub fn name(self) -> &'static str {
        match self {
            Self::C => "c",
            Self::Cpp => "cpp",
            Self::Python => "python",
            Self::Java => "java",
            Self::Go => "go",
            Self::JavaScript => "javascript",
            Self::TypeScript | Self::Tsx => "typescript",
            Self::Rust => "rust",
            Self::CSharp => "csharp",
        }
    }

    /// Rule language families: C rules apply to C++, JavaScript rules to TypeScript.
    pub fn matches_rule_language(self, rule_language: &str) -> bool {
        rule_language == self.name()
            || (rule_language == "c" && self == Self::Cpp)
            || (rule_language == "javascript" && matches!(self, Self::TypeScript | Self::Tsx))
    }

    pub fn grammar(self) -> Grammar {
        match self {
            Self::C => tree_sitter_c::LANGUAGE.into(),
            Self::Cpp => tree_sitter_cpp::LANGUAGE.into(),
            Self::Python => tree_sitter_python::LANGUAGE.into(),
            Self::Java => tree_sitter_java::LANGUAGE.into(),
            Self::Go => tree_sitter_go::LANGUAGE.into(),
            Self::JavaScript => tree_sitter_javascript::LANGUAGE.into(),
            Self::TypeScript => tree_sitter_typescript::LANGUAGE_TYPESCRIPT.into(),
            Self::Tsx => tree_sitter_typescript::LANGUAGE_TSX.into(),
            Self::Rust => tree_sitter_rust::LANGUAGE.into(),
            Self::CSharp => tree_sitter_c_sharp::LANGUAGE.into(),
        }
    }

    pub fn is_call(self, kind: &str) -> bool {
        match self {
            Self::Python => kind == "call",
            Self::Java => matches!(kind, "method_invocation" | "object_creation_expression"),
            Self::JavaScript | Self::TypeScript | Self::Tsx => {
                matches!(kind, "call_expression" | "new_expression")
            }
            Self::CSharp => matches!(kind, "invocation_expression" | "object_creation_expression"),
            Self::C | Self::Cpp | Self::Go | Self::Rust => kind == "call_expression",
        }
    }

    /// Nodes that define a named or anonymous function body.
    pub fn is_function(self, kind: &str) -> bool {
        match self {
            Self::C | Self::Cpp => kind == "function_definition",
            Self::Python => kind == "function_definition",
            Self::Java => matches!(kind, "method_declaration" | "constructor_declaration"),
            Self::Go => matches!(
                kind,
                "function_declaration" | "method_declaration" | "func_literal"
            ),
            Self::JavaScript | Self::TypeScript | Self::Tsx => matches!(
                kind,
                "function_declaration"
                    | "method_definition"
                    | "arrow_function"
                    | "function_expression"
                    | "generator_function_declaration"
                    | "function"
            ),
            Self::Rust => matches!(kind, "function_item" | "closure_expression"),
            Self::CSharp => matches!(
                kind,
                "method_declaration"
                    | "constructor_declaration"
                    | "local_function_statement"
                    | "lambda_expression"
            ),
        }
    }

    /// Nodes that introduce a naming scope for functions (classes, impls, namespaces).
    pub fn is_scope(self, kind: &str) -> bool {
        matches!(
            kind,
            "class_definition"
                | "class_declaration"
                | "class_specifier"
                | "struct_specifier"
                | "interface_declaration"
                | "enum_declaration"
                | "record_declaration"
                | "impl_item"
                | "trait_item"
                | "namespace_definition"
                | "namespace_declaration"
                | "class"
                | "abstract_class_declaration"
                | "struct_declaration"
        )
    }

    pub fn is_comment(kind: &str) -> bool {
        matches!(kind, "comment" | "line_comment" | "block_comment")
    }

    pub fn is_string(kind: &str) -> bool {
        matches!(
            kind,
            "string"
                | "string_literal"
                | "interpreted_string_literal"
                | "raw_string_literal"
                | "template_string"
                | "concatenated_string"
                | "verbatim_string_literal"
                | "raw_string"
                | "char_literal"
        )
    }

    pub fn is_integer(kind: &str) -> bool {
        matches!(
            kind,
            "integer"
                | "number"
                | "number_literal"
                | "int_literal"
                | "decimal_integer_literal"
                | "integer_literal"
                | "hex_integer_literal"
        )
    }

    /// Nodes whose text is a dotted path (`a.b.c`, `a::b`, `a->b`).
    pub fn is_path(kind: &str) -> bool {
        matches!(
            kind,
            "identifier"
                | "attribute"
                | "member_expression"
                | "selector_expression"
                | "scoped_identifier"
                | "qualified_identifier"
                | "member_access_expression"
                | "field_expression"
                | "field_access"
                | "type_identifier"
                | "property_identifier"
                | "field_identifier"
                | "scoped_type_identifier"
                | "qualified_name"
                | "namespace_identifier"
                | "generic_name"
                | "qualified_type"
        )
    }

    /// Declaration or assignment nodes that bind a name to a value: the source of file constants
    /// and of variable bindings (`kpg = KeyPairGenerator.getInstance(...)`).
    pub fn binding_parts<'t>(self, node: Node<'t>) -> Option<(Node<'t>, Node<'t>)> {
        let field = |name: &str| node.child_by_field_name(name);
        match node.kind() {
            // Java, JS/TS, C#
            "variable_declarator" => {
                let name = field("name")?;
                let value = field("value")
                    .or_else(|| last_named_child(node).filter(|v| v.id() != name.id()))?;
                Some((name, value))
            }
            // C/C++
            "init_declarator" => Some((field("declarator")?, field("value")?)),
            "preproc_def" => Some((field("name")?, field("value")?)),
            // Python, C#
            "assignment" | "assignment_expression" => Some((field("left")?, field("right")?)),
            // Go
            "const_spec" | "var_spec" => {
                Some((field("name")?, first_named_child(field("value")?)?))
            }
            "short_var_declaration" | "assignment_statement" => Some((
                first_named_child(field("left")?)?,
                first_named_child(field("right")?)?,
            )),
            // Rust
            "let_declaration" => Some((field("pattern")?, field("value")?)),
            "const_item" | "static_item" => Some((field("name")?, field("value")?)),
            _ => None,
        }
    }

    pub fn is_import(self, kind: &str) -> bool {
        matches!(
            kind,
            "import_statement"
                | "import_from_statement"
                | "import_declaration"
                | "import_spec"
                | "preproc_include"
                | "use_declaration"
                | "using_directive"
        )
    }

    /// Nodes that attach entry-point metadata to the function that follows or contains them.
    pub fn is_decoration(kind: &str) -> bool {
        matches!(
            kind,
            "decorator" | "annotation" | "marker_annotation" | "attribute" | "attribute_item"
        )
    }
}

pub fn first_named_child(node: Node<'_>) -> Option<Node<'_>> {
    let mut cursor = node.walk();
    node.named_children(&mut cursor)
        .find(|child| !Language::is_comment(child.kind()))
}

pub fn last_named_child(node: Node<'_>) -> Option<Node<'_>> {
    let mut cursor = node.walk();
    node.named_children(&mut cursor)
        .filter(|child| !Language::is_comment(child.kind()))
        .last()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn extensions_map_to_languages() {
        assert_eq!(Language::from_path("src/Pay.java"), Some(Language::Java));
        assert_eq!(Language::from_path("a/b/c.PY"), Some(Language::Python));
        assert_eq!(Language::from_path("x.tsx"), Some(Language::Tsx));
        assert_eq!(Language::from_path("README.md"), None);
        assert_eq!(Language::from_path("Makefile"), None);
    }

    #[test]
    fn rule_families() {
        assert!(Language::Cpp.matches_rule_language("c"));
        assert!(Language::TypeScript.matches_rule_language("javascript"));
        assert!(!Language::C.matches_rule_language("cpp"));
    }

    #[test]
    fn every_grammar_loads() {
        for language in [
            Language::C,
            Language::Cpp,
            Language::Python,
            Language::Java,
            Language::Go,
            Language::JavaScript,
            Language::TypeScript,
            Language::Tsx,
            Language::Rust,
            Language::CSharp,
        ] {
            let mut parser = tree_sitter::Parser::new();
            parser
                .set_language(&language.grammar())
                .expect("grammar ABI is compatible");
        }
    }
}
