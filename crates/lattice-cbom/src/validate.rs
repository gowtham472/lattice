//! Validation against the official CycloneDX 1.6 JSON schemas, vendored in `schema/` from the
//! `1.6.1` tag of github.com/CycloneDX/specification. The schemas are compiled in and every
//! reference resolves locally: validation never touches the network.

use jsonschema::{Registry, Validator};
use serde_json::Value;
use std::sync::OnceLock;

const BOM_SCHEMA: &str = include_str!("../schema/bom-1.6.schema.json");
const SPDX_SCHEMA: &str = include_str!("../schema/spdx.schema.json");
const JSF_SCHEMA: &str = include_str!("../schema/jsf-0.82.schema.json");

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct SchemaViolation {
    /// JSON pointer to the offending value.
    pub path: String,
    pub message: String,
}

impl std::fmt::Display for SchemaViolation {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        let path = if self.path.is_empty() {
            "/"
        } else {
            &self.path
        };
        write!(f, "{path}: {}", self.message)
    }
}

fn validator() -> &'static Validator {
    static REGISTRY: OnceLock<Registry<'static>> = OnceLock::new();
    static VALIDATOR: OnceLock<Validator> = OnceLock::new();
    VALIDATOR.get_or_init(|| {
        let parse = |text: &str| {
            serde_json::from_str::<Value>(text).expect("vendored schema is valid JSON")
        };
        let registry = REGISTRY.get_or_init(|| {
            Registry::new()
                .add(
                    "http://cyclonedx.org/schema/spdx.schema.json",
                    parse(SPDX_SCHEMA),
                )
                .and_then(|builder| {
                    builder.add(
                        "http://cyclonedx.org/schema/jsf-0.82.schema.json",
                        parse(JSF_SCHEMA),
                    )
                })
                .and_then(|builder| builder.prepare())
                .expect("vendored schemas register")
        });
        jsonschema::options()
            .with_draft(jsonschema::Draft::Draft7)
            .with_registry(registry)
            .should_validate_formats(true)
            .build(&parse(BOM_SCHEMA))
            .expect("the CycloneDX 1.6 schema compiles")
    })
}

/// Validates a CBOM document, returning every violation (not just the first).
pub fn validate(document: &Value) -> Result<(), Vec<SchemaViolation>> {
    let violations: Vec<SchemaViolation> = validator()
        .iter_errors(document)
        .map(|error| SchemaViolation {
            path: error.instance_path().to_string(),
            message: error.to_string(),
        })
        .collect();
    if violations.is_empty() {
        Ok(())
    } else {
        Err(violations)
    }
}

/// Checks the references schema validation cannot: every `ref`/`dependsOn` and every crypto
/// `...Ref` must name a `bom-ref` defined in the document, and `bom-ref`s must be unique.
pub fn check_references(document: &Value) -> Result<(), Vec<SchemaViolation>> {
    let mut defined = std::collections::BTreeSet::new();
    let mut violations = Vec::new();
    let mut define =
        |value: Option<&Value>, path: String, violations: &mut Vec<SchemaViolation>| {
            if let Some(reference) = value.and_then(Value::as_str)
                && !defined.insert(reference.to_owned())
            {
                violations.push(SchemaViolation {
                    path,
                    message: format!("duplicate bom-ref {reference:?}"),
                });
            }
        };
    define(
        document.pointer("/metadata/component/bom-ref"),
        "/metadata/component/bom-ref".into(),
        &mut violations,
    );
    let components = document
        .get("components")
        .and_then(Value::as_array)
        .cloned()
        .unwrap_or_default();
    for (index, component) in components.iter().enumerate() {
        define(
            component.get("bom-ref"),
            format!("/components/{index}/bom-ref"),
            &mut violations,
        );
    }

    let mut require = |value: Option<&Value>, path: String| {
        if let Some(reference) = value.and_then(Value::as_str)
            && !defined.contains(reference)
        {
            violations.push(SchemaViolation {
                path,
                message: format!("reference to undefined bom-ref {reference:?}"),
            });
        }
    };
    for (index, component) in components.iter().enumerate() {
        let base = format!("/components/{index}/cryptoProperties");
        for pointer in [
            "/certificateProperties/signatureAlgorithmRef",
            "/certificateProperties/subjectPublicKeyRef",
            "/relatedCryptoMaterialProperties/algorithmRef",
        ] {
            require(
                component.pointer(&format!("/cryptoProperties{pointer}")),
                format!("{base}{pointer}"),
            );
        }
    }
    for (index, dependency) in document
        .get("dependencies")
        .and_then(Value::as_array)
        .into_iter()
        .flatten()
        .enumerate()
    {
        require(dependency.get("ref"), format!("/dependencies/{index}/ref"));
        for (inner, target) in dependency
            .get("dependsOn")
            .and_then(Value::as_array)
            .into_iter()
            .flatten()
            .enumerate()
        {
            require(
                Some(target),
                format!("/dependencies/{index}/dependsOn/{inner}"),
            );
        }
    }
    if violations.is_empty() {
        Ok(())
    } else {
        Err(violations)
    }
}
