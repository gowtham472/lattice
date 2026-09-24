//! Go executables: find functions by name, stripped or not.
//!
//! Go links its own cryptography (`crypto/...`) into every binary, so OpenSSL probes never see
//! it. Production Go binaries are usually stripped (`-ldflags="-s -w"`), which removes the ELF
//! symbol table but not the runtime's own function table, `.gopclntab`, which Go needs for stack
//! traces. This module reads that table (Go 1.18 and later) and falls back to the ELF symbol
//! table when it is absent.

/// A Go function and its virtual address.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Function {
    pub name: String,
    pub address: u64,
}

/// Whether an ELF file is a Go program.
pub fn is_go(elf: &goblin::elf::Elf<'_>) -> bool {
    elf.section_headers.iter().any(|section| {
        matches!(
            elf.shdr_strtab.get_at(section.sh_name),
            Some(".gopclntab" | ".go.buildinfo")
        )
    })
}

fn read_uint(bytes: &[u8], offset: usize, size: usize) -> Option<u64> {
    let slice = bytes.get(offset..offset.checked_add(size)?)?;
    Some(match size {
        4 => u64::from(u32::from_le_bytes(slice.try_into().ok()?)),
        8 => u64::from_le_bytes(slice.try_into().ok()?),
        _ => return None,
    })
}

fn c_string(bytes: &[u8], offset: usize) -> Option<&str> {
    let tail = bytes.get(offset..)?;
    let end = tail.iter().position(|b| *b == 0)?;
    std::str::from_utf8(&tail[..end]).ok()
}

/// Functions from `.gopclntab` (Go 1.18+ layout: magic 0xfffffff0 or 0xfffffff1, little-endian),
/// keeping only those `wanted` accepts. `text` is the address of the `.text` section: the
/// table's own `textStart` is filled in by the runtime and is zero in the file.
pub fn pclntab_functions(
    table: &[u8],
    text: u64,
    wanted: impl Fn(&str) -> bool,
) -> Result<Vec<Function>, String> {
    let magic = read_uint(table, 0, 4).ok_or("pclntab too short")?;
    if magic != 0xffff_fff0 && magic != 0xffff_fff1 {
        return Err(format!(
            "unsupported Go pclntab version {magic:#x} (Go 1.18+ needed)"
        ));
    }
    let pointer = usize::from(*table.get(7).ok_or("pclntab too short")?);
    if pointer != 4 && pointer != 8 {
        return Err("unsupported pointer size in pclntab".into());
    }
    let word = |index: usize| {
        read_uint(table, 8 + index * pointer, pointer).ok_or("pclntab header truncated")
    };
    // every offset comes from the file: convert and add with checks, never wrap
    let offset = |value: u64| usize::try_from(value).map_err(|_| "pclntab offset out of range");
    let functions = offset(word(0)?)?;
    let text_start = match word(2)? {
        0 => text,
        start => start,
    };
    let names = offset(word(3)?)?;
    let functab = offset(word(7)?)?;
    if functions > 10_000_000 || functions.saturating_mul(8) > table.len() {
        return Err("implausible function count in pclntab".into());
    }
    let mut found = Vec::new();
    for index in 0..functions {
        // functab: (entry offset, func offset) pairs of u32
        let entry = functab
            .checked_add(index * 8)
            .ok_or("pclntab function table out of range")?;
        let (Some(entry_offset), Some(func_offset)) = (
            read_uint(table, entry, 4),
            entry.checked_add(4).and_then(|at| read_uint(table, at, 4)),
        ) else {
            return Err("pclntab function table truncated".into());
        };
        // _func: entryOff u32, nameOff i32, ...
        let Some(name_offset) = functab
            .checked_add(func_offset as usize)
            .and_then(|func| func.checked_add(4))
            .and_then(|at| read_uint(table, at, 4))
        else {
            continue;
        };
        let Some(name) = names
            .checked_add(name_offset as usize)
            .and_then(|at| c_string(table, at))
        else {
            continue;
        };
        if wanted(name)
            && let Some(address) = text_start.checked_add(entry_offset)
        {
            found.push(Function {
                name: name.to_owned(),
                address,
            });
        }
    }
    Ok(found)
}

/// Functions of a Go ELF binary, from `.gopclntab` or, failing that, the symbol table.
pub fn functions(
    bytes: &[u8],
    elf: &goblin::elf::Elf<'_>,
    wanted: impl Fn(&str) -> bool,
) -> Result<Vec<Function>, String> {
    if let Some(section) = elf
        .section_headers
        .iter()
        .find(|s| elf.shdr_strtab.get_at(s.sh_name) == Some(".gopclntab"))
    {
        let start = section.sh_offset as usize;
        let end = start
            .checked_add(section.sh_size as usize)
            .ok_or("bad .gopclntab bounds")?;
        let table = bytes.get(start..end).ok_or(".gopclntab outside the file")?;
        let text = elf
            .section_headers
            .iter()
            .find(|s| elf.shdr_strtab.get_at(s.sh_name) == Some(".text"))
            .map(|s| s.sh_addr)
            .ok_or("no .text section")?;
        return pclntab_functions(table, text, wanted);
    }
    Ok(elf
        .syms
        .iter()
        .filter(|s| s.st_type() == goblin::elf::sym::STT_FUNC && s.st_value != 0)
        .filter_map(|s| {
            let name = elf.strtab.get_at(s.st_name)?;
            wanted(name).then(|| Function {
                name: name.to_owned(),
                address: s.st_value,
            })
        })
        .collect())
}

/// TLS `CurveID` values Go negotiates, by name (RFC 8446, RFC 7919, draft-ietf-tls-ecdhe-mlkem).
pub fn curve_name(id: u64) -> Option<&'static str> {
    Some(match id {
        23 => "secp256r1",
        24 => "secp384r1",
        25 => "secp521r1",
        29 => "x25519",
        30 => "x448",
        256 => "ffdhe2048",
        257 => "ffdhe3072",
        258 => "ffdhe4096",
        512 => "MLKEM512",
        513 => "MLKEM768",
        514 => "MLKEM1024",
        4587 => "SecP256r1MLKEM768",
        4588 => "X25519MLKEM768",
        4589 => "SecP384r1MLKEM1024",
        _ => return None,
    })
}
