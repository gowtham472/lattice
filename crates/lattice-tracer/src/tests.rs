use super::*;

fn system_openssl() -> Vec<PathBuf> {
    default_libraries()
        .into_iter()
        .filter(|l| l.to_string_lossy().contains(".so.3"))
        .collect()
}

#[test]
fn plans_probes_at_real_function_offsets() {
    let libraries = system_openssl();
    if libraries.is_empty() {
        eprintln!("no OpenSSL 3 on this machine; skipping");
        return;
    }
    let probes = plan(&libraries).unwrap();
    let functions: Vec<&str> = probes.iter().map(|p| p.function.as_str()).collect();
    for expected in [
        "EVP_CIPHER_fetch",
        "EVP_MD_fetch",
        "EVP_PKEY_CTX_new_from_name",
        "EVP_aes_256_gcm",
        "EVP_des_ede3_cbc",
        "EVP_sha1",
        "RSA_generate_key_ex",
    ] {
        assert!(functions.contains(&expected), "{expected} not planned");
    }
    if libraries
        .iter()
        .any(|l| l.to_string_lossy().contains("libssl"))
    {
        assert!(functions.contains(&"SSL_CTX_ctrl"));
        assert!(functions.contains(&"SSL_CTX_set_ciphersuites"));
    }
    assert!(
        !functions
            .iter()
            .any(|f| *f == "EVP_CIPHER_CTX_new" || *f == "EVP_default_properties_is_fips_enabled"),
        "only calls that select cryptography are probed"
    );
    // every offset lands inside its library, on the function's first bytes
    for probe in &probes {
        let size = std::fs::metadata(&probe.library).unwrap().len();
        assert!(probe.offset > 0 && probe.offset < size, "{probe:?}");
    }
    let getters = probes
        .iter()
        .filter(|p| p.kind() == Some(CallKind::Getter))
        .count();
    let setup: Vec<_> = probes
        .iter()
        .filter(|p| p.kind().is_none())
        .map(|p| (p.function.as_str(), p.role))
        .collect();
    assert!(setup.contains(&("OPENSSL_init_crypto", Role::SetupEnter)));
    assert!(setup.contains(&("OPENSSL_init_crypto", Role::SetupExit)));
    assert!(
        getters > 50,
        "legacy getters discovered from the symbol table: {getters}"
    );
}

fn probe(
    function: &str,
    kind: CallKind,
    argument: Option<usize>,
    only_when: Option<(usize, i64)>,
) -> Probe {
    Probe {
        library: PathBuf::from("/usr/lib/x86_64-linux-gnu/libcrypto.so.3"),
        offset: 0x1a2b3c,
        function: function.into(),
        role: Role::Call(kind),
        fetch: match (kind, argument) {
            (_, None) => Fetch::Nothing,
            (CallKind::RsaBits, Some(index)) => Fetch::Int32(index),
            (_, Some(index)) => Fetch::String(index),
        },
        abi: Abi::C,
        only_when,
        executable: false,
    }
}

#[cfg(target_arch = "x86_64")]
#[test]
fn uprobe_definitions_fetch_the_right_argument() {
    let fetch = probe("EVP_CIPHER_fetch", CallKind::Algorithm, Some(1), None);
    assert_eq!(
        definition("lattice_1", "p0", &fetch).unwrap(),
        "p:lattice_1/p0 /usr/lib/x86_64-linux-gnu/libcrypto.so.3:0x1a2b3c value=+0(%si):string"
    );
    let bits = probe("RSA_generate_key_ex", CallKind::RsaBits, Some(1), None);
    assert!(
        definition("g", "p1", &bits)
            .unwrap()
            .ends_with("value=%si:s32")
    );
    let getter = probe("EVP_sha1", CallKind::Getter, None, None);
    assert!(
        definition("g", "p2", &getter)
            .unwrap()
            .ends_with(":0x1a2b3c")
    );
    let exit = Probe {
        role: Role::SetupExit,
        ..probe("SSL_CTX_new_ex", CallKind::Getter, None, None)
    };
    assert!(definition("g", "p4", &exit).unwrap().starts_with("r:g/p4 "));
    let groups = probe("SSL_CTX_ctrl", CallKind::Groups, Some(3), Some((1, 92)));
    assert!(
        definition("g", "p3", &groups)
            .unwrap()
            .ends_with("cmd=%si:s64 value=+0(%cx):string")
    );
}

#[test]
fn trace_pipe_lines_parse() {
    let line = parse::parse(
        "           nginx-4211    [002] ..... 81234.567890: p7: (0x7f3a2c1b2e40) value=\"AES-256-GCM\"",
    )
    .unwrap();
    assert_eq!(line.command, "nginx");
    assert_eq!(line.pid, 4211);
    assert_eq!(line.event, "p7");
    assert_eq!(line.fields["value"], "AES-256-GCM");

    let dashed = parse::parse(
        " my-worker-2-99 [000] d..1. 5.000001: p12: (0x55d0c0ffee00) cmd=92 value=\"X25519MLKEM768:X25519\"",
    )
    .unwrap();
    assert_eq!(dashed.command, "my-worker-2");
    assert_eq!(dashed.pid, 99);
    assert_eq!(dashed.fields["cmd"], "92");
    assert_eq!(dashed.fields["value"], "X25519MLKEM768:X25519");

    let getter = parse::parse("curl-7 [001] ..... 1.5: p3: (0x7f00)").unwrap();
    assert!(getter.fields.is_empty());
    assert!(parse::parse("# tracer: nop").is_none());
    assert!(parse::parse("").is_none());
}

#[test]
fn calls_aggregate_per_executable_and_argument() {
    let probes = vec![
        probe("EVP_CIPHER_fetch", CallKind::Algorithm, Some(1), None),
        probe("EVP_sha1", CallKind::Getter, None, None),
    ];
    let mut aggregator = Aggregator::new(probes, 3);
    let lines = [
        "nginx-10 [000] ..... 1.0: p0: (0x1) value=\"AES-256-GCM\"",
        "nginx-10 [000] ..... 1.1: p0: (0x1) value=\"AES-256-GCM\"",
        "nginx-11 [001] ..... 1.2: p0: (0x1) value=\"AES-256-GCM\"",
        "curl-20 [001] ..... 1.3: p1: (0x2)",
        "curl-20 [001] ..... 1.4: p0: (0x1) value=\"ChaCha20-Poly1305\"",
        "curl-20 [001] ..... 1.5: p0: (0x1) value=\"AES-128-GCM\"",
        "nginx-10 [000] ..... 1.6: p9: (0x1) value=\"unknown probe\"",
    ];
    for line in lines {
        let parsed = parse::parse(line).unwrap();
        aggregator.add(&parsed, |pid| match pid {
            10 | 11 => Some("/usr/sbin/nginx".into()),
            _ => None,
        });
    }
    assert_eq!(
        aggregator.dropped, 1,
        "the limit of three distinct calls holds"
    );
    let trace = aggregator.finish("2026-09-24T00:00:00Z".into(), 60);
    assert_eq!(trace.format, FORMAT);
    let events: Vec<(&str, &str, Option<&str>, u64)> = trace
        .events
        .iter()
        .map(|e| {
            (
                e.executable.as_str(),
                e.function.as_str(),
                e.value.as_deref(),
                e.count,
            )
        })
        .collect();
    assert_eq!(
        events,
        [
            (
                "/usr/sbin/nginx",
                "EVP_CIPHER_fetch",
                Some("AES-256-GCM"),
                3
            ),
            ("curl", "EVP_CIPHER_fetch", Some("ChaCha20-Poly1305"), 1),
            ("curl", "EVP_sha1", None, 1),
        ]
    );
}

#[test]
fn calls_during_openssl_setup_are_not_use() {
    let setup = |role| Probe {
        role,
        ..probe("OPENSSL_init_crypto", CallKind::Getter, None, None)
    };
    let probes = vec![
        probe("EVP_des_ede3_cbc", CallKind::Getter, None, None),
        setup(Role::SetupEnter),
        setup(Role::SetupExit),
    ];
    let mut aggregator = Aggregator::new(probes, 100);
    for line in [
        // thread 10 initialises: every getter is enumerated
        "app-10 [000] ..... 1.0: p1: (0x1)",
        "app-10 [000] ..... 1.1: p0: (0x2)",
        "app-10 [000] ..... 1.2: p1: (0x1)",
        "app-10 [000] ..... 1.3: p0: (0x2)",
        "app-10 [000] ..... 1.4: p2: (0x3 <- 0x1)",
        "app-10 [000] ..... 1.5: p0: (0x2)",
        // another thread's call during thread 10's setup is still use
        "app-11 [001] ..... 1.25: p0: (0x2)",
        "app-10 [000] ..... 1.6: p2: (0x3 <- 0x1)",
        // after setup: real use
        "app-10 [000] ..... 1.7: p0: (0x2)",
    ] {
        aggregator.add(&parse::parse(line).unwrap(), |_| {
            Some("/usr/bin/app".into())
        });
    }
    assert_eq!(aggregator.ignored_setup, 3);
    let trace = aggregator.finish("2026-09-24T00:00:00Z".into(), 1);
    assert_eq!(trace.ignored_setup_calls, 3);
    assert_eq!(trace.events.len(), 1);
    assert_eq!(
        trace.events[0].count, 2,
        "thread 11's call and thread 10's call after setup"
    );
}

/// Unstripped and stripped builds of `testdata/gocrypto`, named by LATTICE_TEST_GO_BINARIES
/// (colon-separated); CI builds them, local runs skip without them.
fn go_binaries() -> Option<Vec<PathBuf>> {
    let list = std::env::var("LATTICE_TEST_GO_BINARIES").ok()?;
    Some(list.split(':').map(PathBuf::from).collect())
}

#[test]
fn go_functions_are_found_in_stripped_binaries() {
    let Some(binaries) = go_binaries() else {
        eprintln!("LATTICE_TEST_GO_BINARIES not set; skipping");
        return;
    };
    let mut plans = Vec::new();
    for binary in &binaries {
        let probes = plan(std::slice::from_ref(binary)).unwrap();
        assert!(
            probes.iter().all(|p| p.abi == Abi::Go && p.executable),
            "{binary:?}"
        );
        let by_name: BTreeMap<String, (u64, Fetch)> = probes
            .iter()
            .map(|p| (p.function.clone(), (p.offset, p.fetch)))
            .collect();
        for (function, fetch) in [
            ("crypto/aes.NewCipher", Fetch::KeyBits("AES", 1)),
            ("crypto/rsa.GenerateKey", Fetch::Int64(2)),
            (
                "crypto/tls.(*hybridKeyExchange).serverSharedSecret",
                Fetch::CurveId,
            ),
            ("crypto/mlkem.GenerateKey768", Fetch::Fixed("ML-KEM-768")),
            ("crypto/md5.Sum", Fetch::Fixed("MD5")),
        ] {
            assert_eq!(
                by_name.get(function).map(|p| p.1),
                Some(fetch),
                "{function} in {binary:?}"
            );
        }
        plans.push(by_name);
    }
    assert!(
        plans.windows(2).all(|w| w[0] == w[1]),
        "stripping removes the symbol table, not what the function table says"
    );
}

#[cfg(target_arch = "x86_64")]
#[test]
fn go_probes_use_go_registers_and_interpret_values() {
    let go_probe = |function: &str, fetch| Probe {
        library: PathBuf::from("/srv/app"),
        offset: 0x1000,
        function: function.into(),
        role: Role::Call(CallKind::Algorithm),
        fetch,
        abi: Abi::Go,
        only_when: None,
        executable: true,
    };
    let aes = go_probe("crypto/aes.NewCipher", Fetch::KeyBits("AES", 1));
    assert!(
        definition("g", "p0", &aes)
            .unwrap()
            .ends_with(" value=%bx:s64")
    );
    let rsa = go_probe("crypto/rsa.GenerateKey", Fetch::Int64(2));
    assert!(
        definition("g", "p1", &rsa)
            .unwrap()
            .ends_with(" value=%cx:s64")
    );
    let hybrid = go_probe(
        "crypto/tls.(*hybridKeyExchange).serverSharedSecret",
        Fetch::CurveId,
    );
    assert!(
        definition("g", "p2", &hybrid)
            .unwrap()
            .ends_with(" value=+0(%ax):u16")
    );
    let md5 = go_probe("crypto/md5.Sum", Fetch::Fixed("MD5"));
    assert!(definition("g", "p3", &md5).unwrap().ends_with(":0x1000"));

    assert_eq!(
        interpret(Fetch::KeyBits("AES", 1), Some("32")).as_deref(),
        Some("AES-256")
    );
    assert_eq!(interpret(Fetch::KeyBits("AES", 1), Some("0")), None);
    assert_eq!(
        interpret(Fetch::CurveId, Some("4588")).as_deref(),
        Some("X25519MLKEM768")
    );
    assert_eq!(
        interpret(Fetch::CurveId, Some("29")).as_deref(),
        Some("x25519")
    );
    assert_eq!(
        interpret(Fetch::CurveId, Some("65000")).as_deref(),
        Some("0xfde8")
    );
    assert_eq!(interpret(Fetch::Fixed("MD5"), None).as_deref(), Some("MD5"));

    // a Go program's calls are attributed to the program, even after it has exited
    let mut aggregator = Aggregator::new(vec![md5], 10);
    aggregator.add(
        &parse::parse("<...>-77 [000] ..... 1.0: p0: (0x1)").unwrap(),
        |_| None,
    );
    let trace = aggregator.finish("2026-09-24T00:00:00Z".into(), 1);
    assert_eq!(trace.events[0].executable, "/srv/app");
    assert_eq!(trace.events[0].value.as_deref(), Some("MD5"));
}

#[test]
fn garbage_is_not_a_go_function_table() {
    assert!(golang::pclntab_functions(b"not a pclntab", 0, |_| true).is_err());
    assert!(golang::pclntab_functions(&[0xf1, 0xff, 0xff, 0xff, 0, 0, 1, 8], 0, |_| true).is_err());
    let mut header = vec![0xf1, 0xff, 0xff, 0xff, 0, 0, 1, 8];
    header.extend_from_slice(&u64::MAX.to_le_bytes());
    header.extend(std::iter::repeat_n(0u8, 56));
    assert!(
        golang::pclntab_functions(&header, 0, |_| true).is_err(),
        "implausible counts are refused"
    );
}

#[test]
fn a_hostile_function_table_cannot_overflow_addresses() {
    // found by the gopclntab fuzz target: a textStart near u64::MAX
    let mut table = vec![0xf1, 0xff, 0xff, 0xff, 0x00, 0x00, 0x01, 0x08];
    table.extend_from_slice(&[0x00, 0x08, 0, 0, 0, 0, 0, 0]); // nfunc
    table.extend_from_slice(&[0; 8]); // nfiles
    table.extend_from_slice(&[0, 0, 0, 0xff, 0xff, 0xff, 0xff, 0xff]); // textStart
    table.extend_from_slice(&[0xff; 18]);
    table.extend_from_slice(&[0; 26]);
    table.extend_from_slice(&[0x80, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0]);
    // never panics; whatever it returns stays in range
    let _ = golang::pclntab_functions(&table, 0x40_1000, |_| true);
}

#[test]
fn bundled_libraries_are_recognised_through_their_prefixes() {
    assert_eq!(canonical("aws_lc_0_45_0_X25519_keypair"), "X25519_keypair");
    assert_eq!(canonical("aws_lc_fips_0_13_7_ECDSA_sign"), "ECDSA_sign");
    assert_eq!(
        canonical("ring_core_0_17_14__x25519_scalar_mult_adx"),
        "x25519_scalar_mult_adx"
    );
    // not a versioned prefix: left alone
    assert_eq!(canonical("aws_lc_rs_helper"), "aws_lc_rs_helper");
    assert_eq!(canonical("aws_lc_0_45_0_"), "aws_lc_0_45_0_");
    assert_eq!(canonical("EVP_CIPHER_fetch"), "EVP_CIPHER_fetch");

    assert!(getter("EVP_aead_aes_256_gcm_tls13"));
    assert!(getter("EVP_aead_chacha20_poly1305"));
    assert!(!getter("EVP_aead_aes_128_gcm_init"));

    assert_eq!(
        interpret(Fetch::Nid(0), Some("989")).as_deref(),
        Some("ML-KEM-768")
    );
    assert_eq!(
        interpret(Fetch::Nid(0), Some("948")).as_deref(),
        Some("X25519")
    );
    // NID_X9_62_id_ecPublicKey: ECDH or ECDSA, so nothing
    assert_eq!(interpret(Fetch::Nid(0), Some("408")), None);
    assert_eq!(
        interpret(Fetch::Bits("AES", 1), Some("128")).as_deref(),
        Some("AES-128")
    );
    assert_eq!(interpret(Fetch::Bits("AES", 1), Some("7")), None);

    // uninterpretable values are not recorded
    let nid = Probe {
        library: PathBuf::from("/usr/bin/envoy"),
        offset: 0x2000,
        function: "EVP_PKEY_CTX_new_id".into(),
        role: Role::Call(CallKind::Algorithm),
        fetch: Fetch::Nid(0),
        abi: Abi::C,
        only_when: None,
        executable: true,
    };
    assert!(
        definition("g", "p0", &nid)
            .unwrap()
            .ends_with(" value=%di:s32")
            || cfg!(not(target_arch = "x86_64"))
    );
    let mut aggregator = Aggregator::new(vec![nid], 10);
    for value in ["408", "989"] {
        aggregator.add(
            &parse::parse(&format!("envoy-9 [000] ..... 1.0: p0: (0x1) value={value}")).unwrap(),
            |_| None,
        );
    }
    let trace = aggregator.finish("2026-09-25T00:00:00Z".into(), 1);
    let values: Vec<Option<&str>> = trace.events.iter().map(|e| e.value.as_deref()).collect();
    assert_eq!(values, [Some("ML-KEM-768")]);
}

/// `testdata/rustlsring` built unstripped, named by LATTICE_TEST_RING_BINARY; CI builds it,
/// local runs skip without it.
#[test]
fn ring_is_found_in_a_rustls_program() {
    let Ok(binary) = std::env::var("LATTICE_TEST_RING_BINARY") else {
        eprintln!("LATTICE_TEST_RING_BINARY not set; skipping");
        return;
    };
    let probes = plan(&[PathBuf::from(binary)]).unwrap();
    let functions: Vec<&str> = probes.iter().map(|p| p.function.as_str()).collect();
    assert!(probes.iter().all(|p| p.executable && p.abi == Abi::C));
    assert!(
        functions.contains(&"x25519_scalar_mult_generic_masked"),
        "{functions:?}"
    );
    assert!(
        functions.iter().any(
            |f| f.starts_with("aes_") && f.ends_with("set_encrypt_key_base")
                || *f == "vpaes_set_encrypt_key"
        ),
        "{functions:?}"
    );
    assert!(
        functions
            .iter()
            .any(|f| f.starts_with("chacha20_poly1305_seal")),
        "{functions:?}"
    );
}
