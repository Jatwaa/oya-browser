use std::collections::HashMap;

pub type NodeId = usize;

#[derive(Debug, Clone)]
pub enum NodeData {
    Document,
    Element {
        tag: String,
        attrs: HashMap<String, String>,
    },
    Text(String),
    Comment(String),
}

#[derive(Debug, Clone)]
pub struct DomNode {
    pub id: NodeId,
    pub parent: Option<NodeId>,
    pub children: Vec<NodeId>,
    pub data: NodeData,
}

/// Arena-allocated DOM tree: zero reference-counting cycles, minimal memory overhead.
#[derive(Debug, Clone)]
pub struct ArenaDom {
    pub nodes: Vec<DomNode>,
    pub root: NodeId,
}

impl Default for ArenaDom {
    fn default() -> Self {
        Self::new()
    }
}

impl ArenaDom {
    pub fn new() -> Self {
        let root_node = DomNode {
            id: 0,
            parent: None,
            children: Vec::new(),
            data: NodeData::Document,
        };
        Self {
            nodes: vec![root_node],
            root: 0,
        }
    }

    pub fn alloc(&mut self, data: NodeData) -> NodeId {
        let id = self.nodes.len();
        self.nodes.push(DomNode {
            id,
            parent: None,
            children: Vec::new(),
            data,
        });
        id
    }

    pub fn append_child(&mut self, parent: NodeId, child: NodeId) {
        if let Some(old_parent) = self.nodes[child].parent {
            self.nodes[old_parent].children.retain(|&c| c != child);
        }
        self.nodes[child].parent = Some(parent);
        self.nodes[parent].children.push(child);
    }

    pub fn remove_from_parent(&mut self, child: NodeId) {
        if let Some(old_parent) = self.nodes[child].parent.take() {
            self.nodes[old_parent].children.retain(|&c| c != child);
        }
    }

    pub fn insert_before(&mut self, parent: NodeId, sibling: NodeId, new_child: NodeId) {
        self.remove_from_parent(new_child);
        self.nodes[new_child].parent = Some(parent);
        if let Some(pos) = self.nodes[parent].children.iter().position(|&c| c == sibling) {
            self.nodes[parent].children.insert(pos, new_child);
        } else {
            self.nodes[parent].children.push(new_child);
        }
    }

    pub fn node_count(&self) -> usize {
        self.nodes.len()
    }

    pub fn get_element_by_id(&self, target_id: &str) -> Option<NodeId> {
        for node in &self.nodes {
            if let NodeData::Element { attrs, .. } = &node.data
                && attrs.get("id").is_some_and(|v| v == target_id)
            {
                return Some(node.id);
            }
        }
        None
    }

    pub fn query_selector(&self, selector: &str) -> Option<NodeId> {
        let sel = selector.trim();
        if sel.is_empty() {
            return None;
        }
        for node in &self.nodes {
            if let NodeData::Element { tag, attrs } = &node.data
                && matches_simple_selector(sel, tag, attrs)
            {
                return Some(node.id);
            }
        }
        None
    }

    pub fn query_selector_all(&self, selector: &str) -> Vec<NodeId> {
        let sel = selector.trim();
        let mut out = Vec::new();
        if sel.is_empty() {
            return out;
        }
        for node in &self.nodes {
            if let NodeData::Element { tag, attrs } = &node.data
                && matches_simple_selector(sel, tag, attrs)
            {
                out.push(node.id);
            }
        }
        out
    }

    pub fn collect_scripts_ordered(&self) -> Vec<(Option<String>, Option<String>)> {
        let mut scripts = Vec::new();
        for node in &self.nodes {
            if let NodeData::Element { tag, attrs } = &node.data
                && tag.eq_ignore_ascii_case("script")
            {
                if let Some(src) = attrs.get("src") {
                    if !src.trim().is_empty() {
                        scripts.push((Some(src.trim().to_string()), None));
                    }
                } else {
                    let code = self.text_content(node.id);
                    if !code.trim().is_empty() {
                        scripts.push((None, Some(code)));
                    }
                }
            }
        }
        scripts
    }

    pub fn collect_stylesheet_links(&self) -> Vec<String> {
        let mut links = Vec::new();
        for node in &self.nodes {
            if let NodeData::Element { tag, attrs } = &node.data
                && tag.eq_ignore_ascii_case("link")
                && attrs
                    .get("rel")
                    .is_some_and(|r| r.eq_ignore_ascii_case("stylesheet"))
                && let Some(href) = attrs.get("href")
                && !href.trim().is_empty()
            {
                links.push(href.trim().to_string());
            }
        }
        links
    }

    pub fn collect_image_urls(&self) -> Vec<String> {
        let mut imgs = Vec::new();
        for node in &self.nodes {
            if let NodeData::Element { tag, attrs } = &node.data
                && tag.eq_ignore_ascii_case("img")
                && let Some(src) = attrs.get("src")
                && !src.trim().is_empty()
            {
                imgs.push(src.trim().to_string());
            }
        }
        imgs
    }

    pub fn find_first_tag(&self, tag_name: &str) -> Option<NodeId> {
        for node in &self.nodes {
            if let NodeData::Element { tag, .. } = &node.data
                && tag.eq_ignore_ascii_case(tag_name)
            {
                return Some(node.id);
            }
        }
        None
    }

    pub fn title(&self) -> String {
        if let Some(title_id) = self.find_first_tag("title") {
            let t = self.text_content(title_id).trim().to_string();
            if !t.is_empty() {
                return t;
            }
        }
        String::new()
    }

    pub fn text_content(&self, node_id: NodeId) -> String {
        let mut out = String::new();
        self.collect_text(node_id, &mut out);
        out
    }

    fn collect_text(&self, node_id: NodeId, out: &mut String) {
        match &self.nodes[node_id].data {
            NodeData::Text(t) => out.push_str(t),
            NodeData::Document | NodeData::Element { .. } => {
                for &child in &self.nodes[node_id].children {
                    self.collect_text(child, out);
                }
            }
            NodeData::Comment(_) => {}
        }
    }

    pub fn set_text_content(&mut self, node_id: NodeId, text: String) {
        let children = std::mem::take(&mut self.nodes[node_id].children);
        for c in children {
            self.nodes[c].parent = None;
        }
        let text_id = self.alloc(NodeData::Text(text));
        self.append_child(node_id, text_id);
    }

    pub fn collect_inline_scripts(&self) -> Vec<String> {
        let mut scripts = Vec::new();
        for node in &self.nodes {
            if let NodeData::Element { tag, attrs } = &node.data
                && tag.eq_ignore_ascii_case("script")
                && !attrs.contains_key("src")
            {
                let code = self.text_content(node.id);
                if !code.trim().is_empty() {
                    scripts.push(code);
                }
            }
        }
        scripts
    }

    pub fn collect_style_blocks(&self) -> String {
        let mut css = String::new();
        for node in &self.nodes {
            if let NodeData::Element { tag, .. } = &node.data
                && tag.eq_ignore_ascii_case("style")
            {
                css.push_str(&self.text_content(node.id));
                css.push('\n');
            }
        }
        css
    }

    pub fn serialize_html(&self) -> String {
        let mut out = String::new();
        for &child in &self.nodes[self.root].children {
            self.serialize_node(child, &mut out);
        }
        out
    }

    fn serialize_node(&self, id: NodeId, out: &mut String) {
        match &self.nodes[id].data {
            NodeData::Document => {
                for &child in &self.nodes[id].children {
                    self.serialize_node(child, out);
                }
            }
            NodeData::Text(t) => out.push_str(t),
            NodeData::Comment(c) => {
                out.push_str("<!--");
                out.push_str(c);
                out.push_str("-->");
            }
            NodeData::Element { tag, attrs } => {
                out.push('<');
                out.push_str(tag);
                let mut keys: Vec<&String> = attrs.keys().collect();
                keys.sort();
                for k in keys {
                    if let Some(v) = attrs.get(k) {
                        out.push(' ');
                        out.push_str(k);
                        out.push_str("=\"");
                        out.push_str(v);
                        out.push('"');
                    }
                }
                out.push('>');
                for &child in &self.nodes[id].children {
                    self.serialize_node(child, out);
                }
                if !is_void_element(tag) {
                    out.push_str("</");
                    out.push_str(tag);
                    out.push('>');
                }
            }
        }
    }
}

fn matches_simple_selector(
    selector: &str,
    tag: &str,
    attrs: &HashMap<String, String>,
) -> bool {
    if let Some(id_sel) = selector.strip_prefix('#') {
        return attrs.get("id").is_some_and(|v| v == id_sel);
    }
    if let Some(class_sel) = selector.strip_prefix('.') {
        return attrs
            .get("class")
            .is_some_and(|v| v.split_whitespace().any(|c| c == class_sel));
    }
    selector.eq_ignore_ascii_case(tag)
}

fn is_void_element(tag: &str) -> bool {
    matches!(
        tag,
        "area" | "base" | "br" | "col" | "embed" | "hr" | "img" | "input" | "link" | "meta"
            | "source" | "track" | "wbr"
    )
}
