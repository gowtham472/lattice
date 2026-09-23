//! Developer probe: prints syntax trees for representative crypto snippets.
//! Run with: cargo test -p lattice-collectors --test ast_probe -- --ignored --nocapture
use tree_sitter::{Language, Node, Parser};

fn dump(node: Node, source: &str, depth: usize, out: &mut String) {
    let field_note = String::new();
    let text = if node.child_count() == 0 {
        format!(" {:?}", &source[node.byte_range()])
    } else {
        String::new()
    };
    out.push_str(&format!(
        "{}{}{}{}\n",
        "  ".repeat(depth),
        node.kind(),
        field_note,
        text
    ));
    let mut cursor = node.walk();
    for (i, child) in node.children(&mut cursor).enumerate() {
        let name = node
            .field_name_for_child(i as u32)
            .map(|f| format!("{f}: "))
            .unwrap_or_default();
        let mut sub = String::new();
        dump(child, source, depth + 1, &mut sub);
        let sub = sub.replacen(
            &"  ".repeat(depth + 1),
            &format!("{}{}", "  ".repeat(depth + 1), name),
            1,
        );
        out.push_str(&sub);
    }
}

fn show(name: &str, language: Language, source: &str) {
    let mut parser = Parser::new();
    parser.set_language(&language).unwrap();
    let tree = parser.parse(source, None).unwrap();
    let mut out = String::new();
    dump(tree.root_node(), source, 0, &mut out);
    println!("===== {name} =====\n{out}");
}

#[test]
#[ignore]
fn probe() {
    show(
        "c",
        tree_sitter_c::LANGUAGE.into(),
        "#define BITS 2048\nstatic const int KB = 1024;\nint main(void) { RSA_generate_key_ex(rsa, BITS, e, NULL); EVP_EncryptInit_ex(ctx, EVP_aes_256_gcm(), NULL, k, iv); return 0; }\n",
    );
    show(
        "cpp",
        tree_sitter_cpp::LANGUAGE.into(),
        "void Svc::run() { auto c = EVP_CIPHER_fetch(nullptr, \"AES-128-CBC\", nullptr); crypto::Hash::sha1(x); }\n",
    );
    show(
        "python",
        tree_sitter_python::LANGUAGE.into(),
        "ALG = 'sha1'\n@app.route('/pay', methods=['POST'])\ndef pay(card_number):\n    k = rsa.generate_private_key(public_exponent=65537, key_size=2048)\n    c = Cipher(algorithms.AES(key), modes.GCM(iv))\n    return hashlib.new(ALG, card_number)\n",
    );
    show(
        "java",
        tree_sitter_java::LANGUAGE.into(),
        "class P { static final String ALG = \"AES\"; @PostMapping(\"/pay\") public void pay(String cardNumber) throws Exception { KeyPairGenerator kpg = KeyPairGenerator.getInstance(\"RSA\"); kpg.initialize(1024); Cipher c = Cipher.getInstance(ALG); SecretKeySpec s = new SecretKeySpec(k, \"AES\"); } }\n",
    );
    show(
        "go",
        tree_sitter_go::LANGUAGE.into(),
        "package main\nconst Bits = 2048\nfunc main() { http.HandleFunc(\"/pay\", pay) }\nfunc pay(w http.ResponseWriter, r *http.Request) { k, _ := rsa.GenerateKey(rand.Reader, Bits); b, _ := aes.NewCipher(key); g, _ := cipher.NewGCM(b); h := hmac.New(sha256.New, key); cfg := &tls.Config{MinVersion: tls.VersionTLS10} }\n",
    );
    show(
        "javascript",
        tree_sitter_javascript::LANGUAGE.into(),
        "const ALG = 'md5';\napp.post('/pay', (req, res) => { crypto.createHash(ALG); crypto.generateKeyPairSync('rsa', { modulusLength: 1024 }); jwt.sign(p, s, { algorithm: 'HS256' }); });\nfunction h(cardNumber) { return new Foo(1); }\n",
    );
    show(
        "typescript",
        tree_sitter_typescript::LANGUAGE_TYPESCRIPT.into(),
        "export async function seal(data: string): Promise<void> { await crypto.subtle.generateKey({ name: 'RSA-OAEP', modulusLength: 2048, hash: 'SHA-256' }, true, ['encrypt']); }\n",
    );
    show(
        "rust",
        tree_sitter_rust::LANGUAGE.into(),
        "const BITS: usize = 2048;\n#[get(\"/pay\")]\nasync fn pay() { let k = RsaPrivateKey::new(&mut rng, BITS); let c = Aes256Gcm::new(&key); let d = Sha1::digest(b\"x\"); let s = openssl::symm::Cipher::aes_128_cbc(); x.encrypt(n, p); }\nfn main() { let app = Router::new().route(\"/pay\", post(pay)); }\n",
    );
    show(
        "csharp",
        tree_sitter_c_sharp::LANGUAGE.into(),
        "class C { const int Bits = 1024; [HttpPost(\"pay\")] public void Pay(string cardNumber) { var r = RSA.Create(Bits); var a = Aes.Create(); a.Mode = CipherMode.ECB; var h = new HMACSHA1(k); var d = new Rfc2898DeriveBytes(p, s, 1000, HashAlgorithmName.SHA1); } }\n",
    );
}
