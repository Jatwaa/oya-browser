use crate::dom::{ArenaDom, NodeData, NodeId};
use html5ever::interface::tree_builder::{ElementFlags, NodeOrText, QuirksMode, TreeSink};
use html5ever::tendril::{StrTendril, TendrilSink};
use html5ever::{Attribute, ExpandedName, QualName, ns, parse_document};
use std::borrow::Cow;
use std::cell::{Cell, RefCell};
use std::collections::HashMap;

pub fn parse_html(html: &str) -> ArenaDom {
    let sink = ArenaTreeSink::new();
    let parser = parse_document(sink, Default::default());
    let sink = parser.one(html);
    sink.dom.into_inner()
}

struct ArenaTreeSink {
    dom: RefCell<ArenaDom>,
    quirks_mode: Cell<QuirksMode>,
}

impl ArenaTreeSink {
    fn new() -> Self {
        Self {
            dom: RefCell::new(ArenaDom::new()),
            quirks_mode: Cell::new(QuirksMode::NoQuirks),
        }
    }
}

impl TreeSink for ArenaTreeSink {
    type Handle = NodeId;
    type Output = Self;
    type ElemName<'a>
        = ExpandedName<'a>
    where
        Self: 'a;

    fn finish(self) -> Self::Output {
        self
    }

    fn parse_error(&self, _msg: Cow<'static, str>) {}

    fn get_document(&self) -> Self::Handle {
        0
    }

    fn elem_name<'a>(&'a self, target: &'a Self::Handle) -> Self::ElemName<'a> {
        static HTML_NS: std::sync::OnceLock<html5ever::Namespace> = std::sync::OnceLock::new();
        let ns = HTML_NS.get_or_init(|| ns!(html));
        let dom = self.dom.borrow();
        let tag = match &dom.nodes[*target].data {
            NodeData::Element { tag, .. } => tag.as_str(),
            _ => "",
        };
        ExpandedName {
            ns,
            local: static_local_name(tag),
        }
    }

    fn create_element(
        &self,
        name: QualName,
        attrs: Vec<Attribute>,
        _flags: ElementFlags,
    ) -> Self::Handle {
        let mut attr_map = HashMap::with_capacity(attrs.len());
        for a in attrs {
            attr_map.insert(a.name.local.to_string(), a.value.to_string());
        }
        self.dom.borrow_mut().alloc(NodeData::Element {
            tag: name.local.to_string(),
            attrs: attr_map,
        })
    }

    fn create_comment(&self, text: StrTendril) -> Self::Handle {
        self.dom.borrow_mut().alloc(NodeData::Comment(text.to_string()))
    }

    fn create_pi(&self, _target: StrTendril, _data: StrTendril) -> Self::Handle {
        self.dom.borrow_mut().alloc(NodeData::Comment(String::new()))
    }

    fn append(&self, parent: &Self::Handle, child: NodeOrText<Self::Handle>) {
        let mut dom = self.dom.borrow_mut();
        match child {
            NodeOrText::AppendNode(id) => dom.append_child(*parent, id),
            NodeOrText::AppendText(text) => {
                if let Some(&last_id) = dom.nodes[*parent].children.last()
                    && let NodeData::Text(existing) = &mut dom.nodes[last_id].data
                {
                    existing.push_str(&text);
                    return;
                }
                let id = dom.alloc(NodeData::Text(text.to_string()));
                dom.append_child(*parent, id);
            }
        }
    }

    fn append_based_on_parent_node(
        &self,
        element: &Self::Handle,
        prev_element: &Self::Handle,
        child: NodeOrText<Self::Handle>,
    ) {
        let has_parent = self.dom.borrow().nodes[*element].parent.is_some();
        if has_parent {
            self.append_before_sibling(element, child);
        } else {
            self.append(prev_element, child);
        }
    }

    fn append_doctype_to_document(
        &self,
        _name: StrTendril,
        _public_id: StrTendril,
        _system_id: StrTendril,
    ) {
    }

    fn get_template_contents(&self, target: &Self::Handle) -> Self::Handle {
        *target
    }

    fn same_node(&self, x: &Self::Handle, y: &Self::Handle) -> bool {
        x == y
    }

    fn set_quirks_mode(&self, mode: QuirksMode) {
        self.quirks_mode.set(mode);
    }

    fn append_before_sibling(&self, sibling: &Self::Handle, new_node: NodeOrText<Self::Handle>) {
        let mut dom = self.dom.borrow_mut();
        let Some(parent) = dom.nodes[*sibling].parent else {
            return;
        };
        let child_id = match new_node {
            NodeOrText::AppendNode(id) => id,
            NodeOrText::AppendText(text) => dom.alloc(NodeData::Text(text.to_string())),
        };
        dom.insert_before(parent, *sibling, child_id);
    }

    fn add_attrs_if_missing(&self, target: &Self::Handle, attrs: Vec<Attribute>) {
        let mut dom = self.dom.borrow_mut();
        if let NodeData::Element {
            attrs: existing, ..
        } = &mut dom.nodes[*target].data
        {
            for a in attrs {
                existing
                    .entry(a.name.local.to_string())
                    .or_insert_with(|| a.value.to_string());
            }
        }
    }

    fn remove_from_parent(&self, target: &Self::Handle) {
        self.dom.borrow_mut().remove_from_parent(*target);
    }

    fn reparent_children(&self, node: &Self::Handle, new_parent: &Self::Handle) {
        let mut dom = self.dom.borrow_mut();
        let children = std::mem::take(&mut dom.nodes[*node].children);
        for c in children {
            dom.append_child(*new_parent, c);
        }
    }
}

fn static_local_name(tag: &str) -> &'static html5ever::LocalName {
    use html5ever::local_name;
    static MAP: std::sync::OnceLock<(HashMap<&'static str, html5ever::LocalName>, html5ever::LocalName)> =
        std::sync::OnceLock::new();
    let (map, fallback) = MAP.get_or_init(|| {
        let mut m = HashMap::new();
        m.insert("html", local_name!("html"));
        m.insert("head", local_name!("head"));
        m.insert("body", local_name!("body"));
        m.insert("title", local_name!("title"));
        m.insert("style", local_name!("style"));
        m.insert("script", local_name!("script"));
        m.insert("div", local_name!("div"));
        m.insert("span", local_name!("span"));
        m.insert("p", local_name!("p"));
        m.insert("a", local_name!("a"));
        m.insert("h1", local_name!("h1"));
        m.insert("h2", local_name!("h2"));
        m.insert("h3", local_name!("h3"));
        m.insert("h4", local_name!("h4"));
        m.insert("h5", local_name!("h5"));
        m.insert("h6", local_name!("h6"));
        m.insert("ul", local_name!("ul"));
        m.insert("ol", local_name!("ol"));
        m.insert("li", local_name!("li"));
        m.insert("b", local_name!("b"));
        m.insert("strong", local_name!("strong"));
        m.insert("br", local_name!("br"));
        m.insert("hr", local_name!("hr"));
        m.insert("table", local_name!("table"));
        m.insert("tr", local_name!("tr"));
        m.insert("td", local_name!("td"));
        m.insert("th", local_name!("th"));
        m.insert("tbody", local_name!("tbody"));
        m.insert("thead", local_name!("thead"));
        m.insert("form", local_name!("form"));
        m.insert("input", local_name!("input"));
        m.insert("button", local_name!("button"));
        m.insert("template", local_name!("template"));
        (m, local_name!("div"))
    });
    map.get(tag).unwrap_or(fallback)
}
