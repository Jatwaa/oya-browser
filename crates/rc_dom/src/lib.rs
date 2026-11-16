#![forbid(unsafe_code)]

pub mod dom;
pub mod parser;
pub mod style;

pub use dom::{ArenaDom, DomNode, NodeData, NodeId};
pub use parser::parse_html;
pub use style::{ComputedStyle, Display, FlexDir, Stylesheet, compute_style};

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn parses_html5_and_mutates_dom() {
        let mut dom = parse_html("<html><head><title>Test</title></head><body><p id='msg'>Old</p></body></html>");
        assert_eq!(dom.title(), "Test");
        let id = dom.get_element_by_id("msg").unwrap();
        assert_eq!(dom.text_content(id), "Old");
        dom.set_text_content(id, "New".to_string());
        assert_eq!(dom.text_content(id), "New");
    }
}
