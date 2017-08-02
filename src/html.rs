use ctype::isspace;
use nodes::{TableAlignment, NodeValue, ListType, AstNode};
use parser::ComrakOptions;
use std::cell::Cell;
use std::io::{Write, Result};

/// Formats an AST as HTML, modified by the given options.
pub fn format_document<'a>(root: &'a AstNode<'a>, options: &ComrakOptions, output: &mut Write) {
    let mut writer = WriteWithLast {
        output: output,
        last_was_lf: Cell::new(true),
    };
    let mut f = HtmlFormatter::new(options, &mut writer);
    f.format(root, false);
}

pub struct WriteWithLast<'w> {
    output: &'w mut Write,
    pub last_was_lf: Cell<bool>,
}

impl<'w> Write for WriteWithLast<'w> {
    fn flush(&mut self) -> Result<()> {
        self.output.flush()
    }

    fn write(&mut self, buf: &[u8]) -> Result<usize> {
        let l = buf.len();
        if l > 0 {
            self.last_was_lf.set(buf[l - 1] == 10);
        }
        self.output.write(buf)
    }
}


struct HtmlFormatter<'o> {
    output: &'o mut WriteWithLast<'o>,
    options: &'o ComrakOptions,
}

const NEEDS_ESCAPED : [bool; 256] = [
    false, false, false, false, false, false, false, false,
    false, false, false, false, false, false, false, false,
    false, false, false, false, false, false, false, false,
    false, false, false, false, false, false, false, false,
    false, false, true,  false, false, false, true,  false,
    false, false, false, false, false, false, false, false,
    false, false, false, false, false, false, false, false,
    false, false, false, false, true, false, true, false,
    false, false, false, false, false, false, false, false,
    false, false, false, false, false, false, false, false,
    false, false, false, false, false, false, false, false,
    false, false, false, false, false, false, false, false,
    false, false, false, false, false, false, false, false,
    false, false, false, false, false, false, false, false,
    false, false, false, false, false, false, false, false,
    false, false, false, false, false, false, false, false,
    false, false, false, false, false, false, false, false,
    false, false, false, false, false, false, false, false,
    false, false, false, false, false, false, false, false,
    false, false, false, false, false, false, false, false,
    false, false, false, false, false, false, false, false,
    false, false, false, false, false, false, false, false,
    false, false, false, false, false, false, false, false,
    false, false, false, false, false, false, false, false,
    false, false, false, false, false, false, false, false,
    false, false, false, false, false, false, false, false,
    false, false, false, false, false, false, false, false,
    false, false, false, false, false, false, false, false,
    false, false, false, false, false, false, false, false,
    false, false, false, false, false, false, false, false,
    false, false, false, false, false, false, false, false,
    false, false, false, false, false, false, false, false,
];

fn tagfilter(literal: &str) -> bool {
    lazy_static! {
        static ref TAGFILTER_BLACKLIST: [&'static str; 9] =
            ["title", "textarea", "style", "xmp", "iframe",
             "noembed", "noframes", "script", "plaintext"];
    }

    if literal.len() < 3 || literal.as_bytes()[0] != b'<' {
        return false;
    }

    let mut i = 1;
    if literal.as_bytes()[i] == b'/' {
        i += 1;
    }

    for t in TAGFILTER_BLACKLIST.iter() {
        if literal[i..].to_string().to_lowercase().starts_with(t) {
            let j = i + t.len();
            return isspace(literal.as_bytes()[j]) || literal.as_bytes()[j] == b'>' ||
                (literal.as_bytes()[j] == b'/' && literal.len() >= j + 2 &&
                     literal.as_bytes()[j + 1] == b'>');
        }
    }

    false
}

fn tagfilter_block(input: &str, o: &mut Write) {
    let src = input.as_bytes();
    let size = src.len();
    let mut i = 0;

    while i < size {
        let org = i;
        while i < size && src[i] != b'<' {
            i += 1;
        }

        if i > org {
            o.write_all(&src[org..i]).unwrap();
        }

        if i >= size {
            break;
        }

        if tagfilter(&input[i..]) {
            o.write_all(b"&lt;").unwrap();
        } else {
            o.write_all(b"<").unwrap();
        }

        i += 1;
    }
}

impl<'o> HtmlFormatter<'o> {
    fn new(options: &'o ComrakOptions, output: &'o mut WriteWithLast<'o>) -> Self {
        HtmlFormatter {
            options: options,
            output: output,
        }
    }

    fn cr(&mut self) {
        if !self.output.last_was_lf.get() {
            self.output.write_all(b"\n").unwrap();
        }
    }

    fn escape(&mut self, buffer: &str) {
        let src = buffer.as_bytes();
        let size = src.len();
        let mut i = 0;

        while i < size {
            let org = i;
            while i < size && !NEEDS_ESCAPED[src[i] as usize] {
                i += 1;
            }

            if i > org {
                self.output.write_all(&src[org..i]).unwrap();
            }

            if i >= size {
                break;
            }

            match src[i] as char {
                '"' => { self.output.write_all(b"&quot;").unwrap(); },
                '&' => { self.output.write_all(b"&amp;").unwrap(); },
                '<' => { self.output.write_all(b"&lt;").unwrap(); },
                '>' => { self.output.write_all(b"&gt;").unwrap(); },
                _ => unreachable!(),
            }

            i += 1;
        }
    }

    fn escape_href(&mut self, buffer: &str) {
        lazy_static! {
            static ref HREF_SAFE: [bool; 256] = {
                let mut a = [false; 256];
                for &c in b"-_.+!*'(),%#@?=;:/,+&$abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789".iter() {
                    a[c as usize] = true;
                }
                a
            };
        }

        let src = buffer.as_bytes();
        let size = src.len();
        let mut i = 0;

        while i < size {
            let org = i;
            while i < size && HREF_SAFE[src[i] as usize] {
                i += 1;
            }

            if i > org {
                self.output.write_all(&src[org..i]).unwrap();
            }

            if i >= size {
                break;
            }

            match src[i] as char {
                '&' => { self.output.write_all(b"&amp;").unwrap(); },
                '\'' => { self.output.write_all(b"&#x27;").unwrap(); },
                _ => write!(self.output, "%{:02X}", src[i]).unwrap(),
            }

            i += 1;
        }
    }

    fn format_children<'a>(&mut self, node: &'a AstNode<'a>, plain: bool) {
        for n in node.children() {
            self.format(n, plain);
        }
    }

    fn format<'a>(&mut self, node: &'a AstNode<'a>, plain: bool) {
        if plain {
            match node.data.borrow().value {
                NodeValue::Text(ref literal) |
                NodeValue::Code(ref literal) |
                NodeValue::HtmlInline(ref literal) => self.escape(literal),
                NodeValue::LineBreak | NodeValue::SoftBreak => { self.output.write_all(b" ").unwrap(); },
                _ => (),
            }
            self.format_children(node, true);
        } else {
            let new_plain = self.format_node(node, true);
            self.format_children(node, new_plain);
            self.format_node(node, false);
        }
    }

    fn format_node<'a>(&mut self, node: &'a AstNode<'a>, entering: bool) -> bool {
        match node.data.borrow().value {
            NodeValue::Document => (),
            NodeValue::BlockQuote => {
                if entering {
                    self.cr();
                    self.output.write_all(b"<blockquote>\n").unwrap();
                } else {
                    self.cr();
                    self.output.write_all(b"</blockquote>\n").unwrap();
                }
            }
            NodeValue::List(ref nl) => {
                if entering {
                    self.cr();
                    if nl.list_type == ListType::Bullet {
                        self.output.write_all(b"<ul>\n").unwrap();
                    } else if nl.start == 1 {
                        self.output.write_all(b"<ol>\n").unwrap();
                    } else {
                        write!(self.output, "<ol start=\"{}\">\n", nl.start).unwrap();
                    }
                } else if nl.list_type == ListType::Bullet {
                    self.output.write_all(b"</ul>\n").unwrap();
                } else {
                    self.output.write_all(b"</ol>\n").unwrap();
                }
            }
            NodeValue::Item(..) => {
                if entering {
                    self.cr();
                    self.output.write_all(b"<li>").unwrap();
                } else {
                    self.output.write_all(b"</li>\n").unwrap();
                }
            }
            NodeValue::Heading(ref nch) => {
                if entering {
                    self.cr();
                    write!(self.output, "<h{}>", nch.level).unwrap();
                } else {
                    write!(self.output, "</h{}>\n", nch.level).unwrap();
                }
            }
            NodeValue::CodeBlock(ref ncb) => {
                if entering {
                    self.cr();

                    if ncb.info.is_empty() {
                        self.output.write_all(b"<pre><code>").unwrap();
                    } else {
                        let mut first_tag = 0;
                        while first_tag < ncb.info.len() &&
                            !isspace(ncb.info.as_bytes()[first_tag])
                        {
                            first_tag += 1;
                        }

                        if self.options.github_pre_lang {
                            self.output.write_all(b"<pre lang=\"").unwrap();
                            self.escape(&ncb.info[..first_tag]);
                            self.output.write_all(b"\"><code>").unwrap();
                        } else {
                            self.output.write_all(b"<pre><code class=\"language-").unwrap();
                            self.escape(&ncb.info[..first_tag]);
                            self.output.write_all(b"\">").unwrap();
                        }
                    }
                    self.escape(&ncb.literal);
                    self.output.write_all(b"</code></pre>\n").unwrap();
                }
            }
            NodeValue::HtmlBlock(ref nhb) => {
                if entering {
                    self.cr();
                    if self.options.ext_tagfilter {
                        tagfilter_block(&nhb.literal, &mut self.output);
                    } else {
                        self.output.write_all(nhb.literal.as_bytes()).unwrap();
                    }
                    self.cr();
                }
            }
            NodeValue::ThematicBreak => {
                if entering {
                    self.cr();
                    self.output.write_all(b"<hr />\n").unwrap();
                }
            }
            NodeValue::Paragraph => {
                let tight = match node.parent().and_then(|n| n.parent()).map(|n| {
                    n.data.borrow().value.clone()
                }) {
                    Some(NodeValue::List(nl)) => nl.tight,
                    _ => false,
                };

                if entering {
                    if !tight {
                        self.cr();
                        self.output.write_all(b"<p>").unwrap();
                    }
                } else if !tight {
                    self.output.write_all(b"</p>\n").unwrap();
                }
            }
            NodeValue::Text(ref literal) => {
                if entering {
                    self.escape(literal);
                }
            }
            NodeValue::LineBreak => {
                if entering {
                    self.output.write_all(b"<br />\n").unwrap();
                }
            }
            NodeValue::SoftBreak => {
                if entering {
                    if self.options.hardbreaks {
                        self.output.write_all(b"<br />\n").unwrap();
                    } else {
                        self.output.write_all(b"\n").unwrap();
                    }
                }
            }
            NodeValue::Code(ref literal) => {
                if entering {
                    self.output.write_all(b"<code>").unwrap();
                    self.escape(literal);
                    self.output.write_all(b"</code>").unwrap();
                }
            }
            NodeValue::HtmlInline(ref literal) => {
                if entering {
                    if self.options.ext_tagfilter && tagfilter(literal) {
                        self.output.write_all(b"&lt;").unwrap();
                        self.output.write_all(literal[1..].as_bytes()).unwrap();
                    } else {
                        self.output.write_all(literal.as_bytes()).unwrap();
                    }
                }
            }
            NodeValue::Strong => {
                if entering {
                    self.output.write_all(b"<strong>").unwrap();
                } else {
                    self.output.write_all(b"</strong>").unwrap();
                }
            }
            NodeValue::Emph => {
                if entering {
                    self.output.write_all(b"<em>").unwrap();
                } else {
                    self.output.write_all(b"</em>").unwrap();
                }
            }
            NodeValue::Strikethrough => {
                if entering {
                    self.output.write_all(b"<del>").unwrap();
                } else {
                    self.output.write_all(b"</del>").unwrap();
                }
            }
            NodeValue::Superscript => {
                if entering {
                    self.output.write_all(b"<sup>").unwrap();
                } else {
                    self.output.write_all(b"</sup>").unwrap();
                }
            }
            NodeValue::Link(ref nl) => {
                if entering {
                    self.output.write_all(b"<a href=\"").unwrap();
                    self.escape_href(&nl.url);
                    if !nl.title.is_empty() {
                        self.output.write_all(b"\" title=\"").unwrap();
                        self.escape(&nl.title);
                    }
                    self.output.write_all(b"\">").unwrap();
                } else {
                    self.output.write_all(b"</a>").unwrap();
                }
            }
            NodeValue::Image(ref nl) => {
                if entering {
                    self.output.write_all(b"<img src=\"").unwrap();
                    self.escape_href(&nl.url);
                    self.output.write_all(b"\" alt=\"").unwrap();
                    return true;
                } else {
                    if !nl.title.is_empty() {
                        self.output.write_all(b"\" title=\"").unwrap();
                        self.escape(&nl.title);
                    }
                    self.output.write_all(b"\" />").unwrap();
                }
            }
            NodeValue::Table(..) => {
                if entering {
                    self.cr();
                    self.output.write_all(b"<table>\n").unwrap();
                } else {
                    if !node.last_child().unwrap().same_node(
                        node.first_child().unwrap(),
                    )
                    {
                        self.output.write_all(b"</tbody>").unwrap();
                    }
                    self.output.write_all(b"</table>\n").unwrap();
                }
            }
            NodeValue::TableRow(header) => {
                if entering {
                    self.cr();
                    if header {
                        self.output.write_all(b"<thead>").unwrap();
                        self.cr();
                    }
                    self.output.write_all(b"<tr>").unwrap();
                } else {
                    self.cr();
                    self.output.write_all(b"</tr>").unwrap();
                    if header {
                        self.cr();
                        self.output.write_all(b"</thead>").unwrap();
                        self.cr();
                        self.output.write_all(b"<tbody>").unwrap();
                    }
                }
            }
            NodeValue::TableCell => {
                let row = &node.parent().unwrap().data.borrow().value;
                let in_header = match *row {
                    NodeValue::TableRow(header) => header,
                    _ => panic!(),
                };

                let table = &node.parent().unwrap().parent().unwrap().data.borrow().value;
                let alignments = match *table {
                    NodeValue::Table(ref alignments) => alignments,
                    _ => panic!(),
                };

                if entering {
                    self.cr();
                    if in_header {
                        self.output.write_all(b"<th").unwrap();
                    } else {
                        self.output.write_all(b"<td").unwrap();
                    }

                    let mut start = node.parent().unwrap().first_child().unwrap();
                    let mut i = 0;
                    while !start.same_node(node) {
                        i += 1;
                        start = start.next_sibling().unwrap();
                    }

                    match alignments[i] {
                        TableAlignment::Left => { self.output.write_all(b" align=\"left\"").unwrap(); },
                        TableAlignment::Right => { self.output.write_all(b" align=\"right\"").unwrap(); },
                        TableAlignment::Center => { self.output.write_all(b" align=\"center\"").unwrap(); },
                        TableAlignment::None => (),
                    }

                    self.output.write_all(b">").unwrap();
                } else if in_header {
                    self.output.write_all(b"</th>").unwrap();
                } else {
                    self.output.write_all(b"</td>").unwrap();
                }
            }
        }
        false
    }
}
