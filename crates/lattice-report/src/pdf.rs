//! A small, deterministic PDF 1.7 writer: text in the standard 14 fonts, filled rectangles and
//! lines, nothing else.
//!
//! The standard fonts need no embedding, so the output is compact and byte-for-byte a function of
//! what was drawn: no timestamps are read, and the document ID is a hash of the content. Text is
//! encoded in WinAnsi; characters outside it are replaced by ASCII equivalents. Widths come from
//! the fonts' published metrics, so text can be measured and wrapped exactly.

use std::fmt::Write as _;

pub const PAGE_WIDTH: f32 = 595.0;
pub const PAGE_HEIGHT: f32 = 842.0;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Font {
    Regular,
    Bold,
    Mono,
}

impl Font {
    fn resource(self) -> &'static str {
        match self {
            Self::Regular => "F1",
            Self::Bold => "F2",
            Self::Mono => "F3",
        }
    }

    fn base_font(self) -> &'static str {
        match self {
            Self::Regular => "Helvetica",
            Self::Bold => "Helvetica-Bold",
            Self::Mono => "Courier",
        }
    }

    /// Advance width of one WinAnsi byte, in thousandths of the font size.
    fn width(self, byte: u8) -> u16 {
        if self == Self::Mono {
            return 600;
        }
        let table = match self {
            Self::Bold => &HELVETICA_BOLD,
            _ => &HELVETICA,
        };
        match byte {
            32..=126 => table[usize::from(byte - 32)],
            0xB7 => 278,                              // middle dot
            0xD7 => 584,                              // multiplication sign
            0x96 => 556,                              // en dash
            0x97 | 0x85 => 1000,                      // em dash, ellipsis
            0x95 => 350,                              // bullet
            0x91 | 0x92 if self == Self::Bold => 278, // single quotes
            0x91 | 0x92 => 222,
            0x93 | 0x94 if self == Self::Bold => 500, // double quotes
            0x93 | 0x94 => 333,
            0xB0 => 400, // degree
            _ => 556,
        }
    }
}

/// Helvetica advance widths for ASCII 32..=126 (Adobe Core14 AFM).
const HELVETICA: [u16; 95] = [
    278, 278, 355, 556, 556, 889, 667, 191, 333, 333, 389, 584, 278, 333, 278, 278, 556, 556, 556,
    556, 556, 556, 556, 556, 556, 556, 278, 278, 584, 584, 584, 556, 1015, 667, 667, 722, 722, 667,
    611, 778, 722, 278, 500, 667, 556, 833, 722, 778, 667, 778, 722, 667, 611, 722, 667, 944, 667,
    667, 611, 278, 278, 278, 469, 556, 333, 556, 556, 500, 556, 556, 278, 556, 556, 222, 222, 500,
    222, 833, 556, 556, 556, 556, 333, 500, 278, 556, 500, 722, 500, 500, 500, 334, 260, 334, 584,
];

/// Helvetica-Bold advance widths for ASCII 32..=126 (Adobe Core14 AFM).
const HELVETICA_BOLD: [u16; 95] = [
    278, 333, 474, 556, 556, 889, 722, 238, 333, 333, 389, 584, 278, 333, 278, 278, 556, 556, 556,
    556, 556, 556, 556, 556, 556, 556, 333, 333, 584, 584, 584, 611, 975, 722, 722, 722, 722, 667,
    611, 778, 722, 278, 556, 722, 611, 833, 722, 778, 667, 778, 722, 667, 611, 722, 667, 944, 667,
    667, 611, 333, 278, 333, 584, 556, 333, 556, 611, 556, 611, 556, 333, 611, 611, 278, 278, 556,
    278, 889, 611, 611, 611, 611, 389, 556, 333, 611, 556, 778, 556, 556, 500, 389, 280, 389, 584,
];

/// Encodes text in WinAnsi, replacing what it cannot represent.
pub fn encode(text: &str) -> Vec<u8> {
    let mut out = Vec::with_capacity(text.len());
    for c in text.chars() {
        match c {
            ' '..='~' => out.push(c as u8),
            '\u{A0}'..='\u{FF}' => out.push(c as u32 as u8),
            '€' => out.push(0x80),
            '…' => out.push(0x85),
            '•' => out.push(0x95),
            '–' => out.push(0x96),
            '—' => out.push(0x97),
            '‘' => out.push(0x91),
            '’' => out.push(0x92),
            '“' => out.push(0x93),
            '”' => out.push(0x94),
            '™' => out.push(0x99),
            '→' => out.extend_from_slice(b"->"),
            '←' => out.extend_from_slice(b"<-"),
            '≥' => out.extend_from_slice(b">="),
            '≤' => out.extend_from_slice(b"<="),
            '≈' => out.push(b'~'),
            '₹' => out.extend_from_slice(b"Rs "),
            '\t' | '\n' | '\r' => out.push(b' '),
            _ => out.push(b'?'),
        }
    }
    out
}

/// Width of `text` in points.
pub fn text_width(text: &str, font: Font, size: f32) -> f32 {
    let units: u32 = encode(text).iter().map(|b| u32::from(font.width(*b))).sum();
    units as f32 * size / 1000.0
}

/// Breaks `text` into lines no wider than `width`, at spaces where possible and inside words
/// that are too long on their own.
pub fn wrap(text: &str, font: Font, size: f32, width: f32) -> Vec<String> {
    let mut lines = Vec::new();
    let mut line = String::new();
    for word in text.split_whitespace() {
        let candidate = if line.is_empty() {
            word.to_owned()
        } else {
            format!("{line} {word}")
        };
        if text_width(&candidate, font, size) <= width {
            line = candidate;
            continue;
        }
        if !line.is_empty() {
            lines.push(std::mem::take(&mut line));
        }
        // the word alone may still be too wide: split it by characters
        let mut piece = String::new();
        for c in word.chars() {
            piece.push(c);
            if text_width(&piece, font, size) > width && piece.chars().count() > 1 {
                piece.pop();
                lines.push(std::mem::take(&mut piece));
                piece.push(c);
            }
        }
        line = piece;
    }
    if !line.is_empty() || lines.is_empty() {
        lines.push(line);
    }
    lines
}

/// Shortens `text` with an ellipsis until it fits `width`.
pub fn fit(text: &str, font: Font, size: f32, width: f32) -> String {
    if text_width(text, font, size) <= width {
        return text.to_owned();
    }
    let mut chars: Vec<char> = text.chars().collect();
    while !chars.is_empty() {
        chars.pop();
        let candidate: String = chars.iter().collect::<String>() + "…";
        if text_width(&candidate, font, size) <= width {
            return candidate;
        }
    }
    String::new()
}

#[derive(Debug, Clone, Copy, PartialEq)]
pub struct Color(pub f32, pub f32, pub f32);

/// Numbers with at most two decimals and no trailing zeros, so content streams are stable.
fn num(value: f32) -> String {
    let mut text = format!("{value:.2}");
    while text.contains('.') && (text.ends_with('0') || text.ends_with('.')) {
        text.pop();
    }
    if text == "-0" { "0".into() } else { text }
}

fn literal(bytes: &[u8]) -> Vec<u8> {
    let mut out = Vec::with_capacity(bytes.len() + 2);
    out.push(b'(');
    for &b in bytes {
        if matches!(b, b'(' | b')' | b'\\') {
            out.push(b'\\');
        }
        out.push(b);
    }
    out.push(b')');
    out
}

/// One page's drawing operations, in PDF coordinates (origin bottom-left, points).
#[derive(Debug, Default, Clone)]
pub struct Page {
    content: Vec<u8>,
}

impl Page {
    pub fn text(&mut self, x: f32, y: f32, size: f32, font: Font, color: Color, text: &str) {
        let Color(r, g, b) = color;
        let head = format!(
            "BT /{} {} Tf {} {} {} rg {} {} Td ",
            font.resource(),
            num(size),
            num(r),
            num(g),
            num(b),
            num(x),
            num(y)
        );
        self.content.extend_from_slice(head.as_bytes());
        self.content.extend_from_slice(&literal(&encode(text)));
        self.content.extend_from_slice(b" Tj ET\n");
    }

    /// Text whose right edge sits at `right`.
    pub fn text_right(
        &mut self,
        right: f32,
        y: f32,
        size: f32,
        font: Font,
        color: Color,
        text: &str,
    ) {
        let x = right - text_width(text, font, size);
        self.text(x, y, size, font, color, text);
    }

    pub fn rect(&mut self, x: f32, y: f32, width: f32, height: f32, color: Color) {
        let Color(r, g, b) = color;
        let op = format!(
            "{} {} {} rg {} {} {} {} re f\n",
            num(r),
            num(g),
            num(b),
            num(x),
            num(y),
            num(width),
            num(height)
        );
        self.content.extend_from_slice(op.as_bytes());
    }

    pub fn line(&mut self, from: (f32, f32), to: (f32, f32), width: f32, color: Color) {
        let Color(r, g, b) = color;
        let op = format!(
            "{} {} {} RG {} w {} {} m {} {} l S\n",
            num(r),
            num(g),
            num(b),
            num(width),
            num(from.0),
            num(from.1),
            num(to.0),
            num(to.1)
        );
        self.content.extend_from_slice(op.as_bytes());
    }
}

/// Document metadata. `created` is a PDF date (`D:YYYYMMDDHHmmSSZ`) supplied by the caller.
#[derive(Debug, Default, Clone)]
pub struct Info {
    pub title: String,
    pub subject: String,
    pub producer: String,
    pub created: Option<String>,
}

/// Serialises pages into a complete PDF file.
pub fn write(info: &Info, pages: &[Page]) -> Vec<u8> {
    const FONTS: [Font; 3] = [Font::Regular, Font::Bold, Font::Mono];
    // 1 catalog, 2 page tree, 3..=5 fonts, 6 info, then a page and its content per page
    const FIRST_PAGE: usize = 7;
    let mut objects: Vec<Vec<u8>> = Vec::new();

    objects.push(b"<< /Type /Catalog /Pages 2 0 R >>".to_vec());
    let kids: Vec<String> = (0..pages.len())
        .map(|i| format!("{} 0 R", FIRST_PAGE + 2 * i))
        .collect();
    objects.push(
        format!(
            "<< /Type /Pages /Kids [{}] /Count {} >>",
            kids.join(" "),
            pages.len()
        )
        .into_bytes(),
    );
    for font in FONTS {
        objects.push(
            format!(
                "<< /Type /Font /Subtype /Type1 /BaseFont /{} /Encoding /WinAnsiEncoding >>",
                font.base_font()
            )
            .into_bytes(),
        );
    }
    let mut info_body = b"<< /Title ".to_vec();
    info_body.extend_from_slice(&literal(&encode(&info.title)));
    info_body.extend_from_slice(b" /Subject ");
    info_body.extend_from_slice(&literal(&encode(&info.subject)));
    info_body.extend_from_slice(b" /Producer ");
    info_body.extend_from_slice(&literal(&encode(&info.producer)));
    if let Some(created) = &info.created {
        info_body.extend_from_slice(b" /CreationDate ");
        info_body.extend_from_slice(&literal(&encode(created)));
    }
    info_body.extend_from_slice(b" >>");
    objects.push(info_body);

    let mut fonts = String::new();
    for (i, font) in FONTS.iter().enumerate() {
        let _ = write!(fonts, "/{} {} 0 R ", font.resource(), 3 + i);
    }
    for (i, page) in pages.iter().enumerate() {
        objects.push(
            format!(
                "<< /Type /Page /Parent 2 0 R /MediaBox [0 0 {} {}] \
                 /Resources << /Font << {fonts}>> >> /Contents {} 0 R >>",
                num(PAGE_WIDTH),
                num(PAGE_HEIGHT),
                FIRST_PAGE + 2 * i + 1
            )
            .into_bytes(),
        );
        let mut stream = format!("<< /Length {} >>\nstream\n", page.content.len()).into_bytes();
        stream.extend_from_slice(&page.content);
        stream.extend_from_slice(b"\nendstream");
        objects.push(stream);
    }

    let mut out: Vec<u8> = b"%PDF-1.7\n%\xE2\xE3\xCF\xD3\n".to_vec();
    let mut offsets = Vec::with_capacity(objects.len());
    for (i, body) in objects.iter().enumerate() {
        offsets.push(out.len());
        out.extend_from_slice(format!("{} 0 obj\n", i + 1).as_bytes());
        out.extend_from_slice(body);
        out.extend_from_slice(b"\nendobj\n");
    }
    // the document ID is derived from the content, never from the clock
    let id = blake3::hash(&out).to_hex();
    let id = &id.as_str()[..32];
    let xref = out.len();
    let mut table = format!("xref\n0 {}\n0000000000 65535 f \n", objects.len() + 1);
    for offset in offsets {
        let _ = writeln!(table, "{offset:010} 00000 n ");
    }
    let _ = write!(
        table,
        "trailer\n<< /Size {} /Root 1 0 R /Info 6 0 R /ID [<{id}> <{id}>] >>\nstartxref\n{xref}\n%%EOF\n",
        objects.len() + 1
    );
    out.extend_from_slice(table.as_bytes());
    out
}
