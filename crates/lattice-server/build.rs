//! Embeds the built cockpit (`cockpit/dist`, or the directory named by LATTICE_COCKPIT_DIST)
//! in the binary, so one file serves both the API and the UI. Without a built cockpit the
//! table is empty and the server falls back to a directory on disk. Files are listed in path
//! order, so the output is reproducible.

use std::path::{Path, PathBuf};

fn main() {
    println!("cargo:rerun-if-env-changed=LATTICE_COCKPIT_DIST");
    let manifest = PathBuf::from(std::env::var("CARGO_MANIFEST_DIR").expect("set by cargo"));
    let dist = std::env::var_os("LATTICE_COCKPIT_DIST")
        .map(PathBuf::from)
        .unwrap_or_else(|| manifest.join("../../cockpit/dist"));
    println!("cargo:rerun-if-changed={}", dist.display());

    let mut files = Vec::new();
    if dist.join("index.html").is_file() {
        collect(&dist, &dist, &mut files);
    }
    files.sort();
    let mut table = String::from("/// The built cockpit: (path, bytes), in path order.\n");
    table.push_str("pub static FILES: &[(&str, &[u8])] = &[\n");
    for (relative, absolute) in &files {
        println!("cargo:rerun-if-changed={}", absolute.display());
        table.push_str(&format!(
            "    ({relative:?}, include_bytes!({:?})),\n",
            absolute.display().to_string()
        ));
    }
    table.push_str("];\n");
    let out = PathBuf::from(std::env::var("OUT_DIR").expect("set by cargo")).join("cockpit.rs");
    std::fs::write(out, table).expect("writing the cockpit table");
}

fn collect(root: &Path, dir: &Path, files: &mut Vec<(String, PathBuf)>) {
    let Ok(entries) = std::fs::read_dir(dir) else {
        return;
    };
    for entry in entries.flatten() {
        let path = entry.path();
        if path.is_dir() {
            collect(root, &path, files);
        } else if let Ok(relative) = path.strip_prefix(root) {
            let relative = relative
                .components()
                .map(|c| c.as_os_str().to_string_lossy().into_owned())
                .collect::<Vec<_>>()
                .join("/");
            let absolute = path.canonicalize().unwrap_or(path);
            files.push((relative, absolute));
        }
    }
}
