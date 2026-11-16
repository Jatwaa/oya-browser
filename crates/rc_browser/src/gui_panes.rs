//! Panes: show up to four tabs at once, docked side by side like Windows snap layouts. Each pane
//! resizes with the window and the draggable dividers, and any pane can be maximized to fill the
//! content area and restored again.
//!
//! The focused pane is always the active tab, so the address bar, sign-in and all other toolbar
//! actions apply to it. Child module of `gui`.

use super::*;

const GAP: f32 = 6.0;
const HEADER_H: f32 = 28.0;

#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub(super) enum PaneLayout {
    Single,
    Columns2,
    Rows2,
    LeftAndTwo,
    Grid4,
}

impl PaneLayout {
    pub(super) fn all() -> [PaneLayout; 5] {
        [
            PaneLayout::Single,
            PaneLayout::Columns2,
            PaneLayout::Rows2,
            PaneLayout::LeftAndTwo,
            PaneLayout::Grid4,
        ]
    }

    pub(super) fn slots(self) -> usize {
        match self {
            PaneLayout::Single => 1,
            PaneLayout::Columns2 | PaneLayout::Rows2 => 2,
            PaneLayout::LeftAndTwo => 3,
            PaneLayout::Grid4 => 4,
        }
    }

    fn label(self) -> &'static str {
        match self {
            PaneLayout::Single => "One page",
            PaneLayout::Columns2 => "Two side by side",
            PaneLayout::Rows2 => "Two stacked",
            PaneLayout::LeftAndTwo => "One large, two small",
            PaneLayout::Grid4 => "Four (2 × 2)",
        }
    }
}

pub(super) struct Panes {
    pub layout: PaneLayout,
    pub slots: [Option<u64>; 4],
    pub focused: usize,
    pub maximized: Option<usize>,
    /// Divider positions as fractions of the content area.
    pub split_x: f32,
    pub split_y: f32,
    /// Active tab last time the panes were reconciled (see `reconcile_panes`).
    pub last_active: Option<u64>,
    /// Web tabs currently placed in a pane, with their page area (filled every frame).
    pub web_bodies: HashMap<u64, egui::Rect>,
}

impl Default for Panes {
    fn default() -> Self {
        Self {
            layout: PaneLayout::Single,
            slots: [None; 4],
            focused: 0,
            maximized: None,
            split_x: 0.5,
            split_y: 0.5,
            last_active: None,
            web_bodies: HashMap::new(),
        }
    }
}

impl Panes {
    pub(super) fn is_multi(&self) -> bool {
        self.layout != PaneLayout::Single
    }

    pub(super) fn slot_of(&self, tab_id: u64) -> Option<usize> {
        (0..self.layout.slots()).find(|&i| self.slots[i] == Some(tab_id))
    }
}

/// Pane rectangles for `layout` inside `area`, with dividers at `sx`/`sy` (fractions).
pub(super) fn pane_rects(layout: PaneLayout, area: egui::Rect, sx: f32, sy: f32) -> Vec<egui::Rect> {
    pane_rects_with_gap(layout, area, sx, sy, GAP)
}

fn pane_rects_with_gap(layout: PaneLayout, area: egui::Rect, sx: f32, sy: f32, gap: f32) -> Vec<egui::Rect> {
    use egui::{Rect, pos2};
    let h = gap / 2.0;
    let x = area.left() + area.width() * sx;
    let y = area.top() + area.height() * sy;
    let left = Rect::from_min_max(area.min, pos2(x - h, area.bottom()));
    let right = Rect::from_min_max(pos2(x + h, area.top()), area.max);
    let top = Rect::from_min_max(area.min, pos2(area.right(), y - h));
    let bottom = Rect::from_min_max(pos2(area.left(), y + h), area.max);
    match layout {
        PaneLayout::Single => vec![area],
        PaneLayout::Columns2 => vec![left, right],
        PaneLayout::Rows2 => vec![top, bottom],
        PaneLayout::LeftAndTwo => vec![
            left,
            Rect::from_min_max(right.min, pos2(right.right(), y - h)),
            Rect::from_min_max(pos2(right.left(), y + h), right.max),
        ],
        PaneLayout::Grid4 => vec![
            Rect::from_min_max(area.min, pos2(x - h, y - h)),
            Rect::from_min_max(pos2(x + h, area.top()), pos2(area.right(), y - h)),
            Rect::from_min_max(pos2(area.left(), y + h), pos2(x - h, area.bottom())),
            Rect::from_min_max(pos2(x + h, y + h), area.max),
        ],
    }
}

/// Small diagram of a layout for the Panes menu.
fn paint_layout_icon(painter: &egui::Painter, layout: PaneLayout, rect: egui::Rect, color: egui::Color32) {
    let inner = rect.shrink(1.0);
    for r in pane_rects_with_gap(layout, inner, 0.5, 0.5, 2.0) {
        painter.rect_stroke(r.shrink(0.5), 2.0, egui::Stroke::new(1.3, color), egui::StrokeKind::Inside);
    }
}

impl RustChromeApp {
    /// Switches layout. Going from one page to several fills the new panes with the active tab
    /// and the next open tabs; extra panes start empty.
    pub(super) fn set_pane_layout(&mut self, layout: PaneLayout) {
        let active = self.controller.tab().id;
        let was_multi = self.panes.is_multi();
        self.panes.layout = layout;
        self.panes.maximized = None;
        if layout == PaneLayout::Single {
            self.panes.slots = [None; 4];
            self.panes.focused = 0;
            return;
        }
        if !was_multi {
            self.panes.slots = [None; 4];
            self.panes.slots[0] = Some(active);
            let others: Vec<u64> = self
                .controller
                .tabs
                .iter()
                .map(|t| t.id)
                .filter(|id| *id != active)
                .collect();
            for (i, id) in others.into_iter().take(layout.slots() - 1).enumerate() {
                self.panes.slots[i + 1] = Some(id);
            }
            self.panes.focused = 0;
        }
        for slot in self.panes.slots.iter_mut().skip(layout.slots()) {
            *slot = None;
        }
        self.panes.focused = self.panes.focused.min(layout.slots() - 1);
        self.panes.last_active = Some(active);
        for twv in self.webviews.values_mut() {
            twv.last_bounds = (0, 0, 0, 0, false);
        }
    }

    pub(super) fn focus_pane(&mut self, i: usize) {
        if i >= self.panes.layout.slots() {
            return;
        }
        self.panes.focused = i;
        if let Some(tab_id) = self.panes.slots[i]
            && let Some(idx) = self.controller.tabs.iter().position(|t| t.id == tab_id)
        {
            self.controller.active_tab = idx;
            self.panes.last_active = Some(tab_id);
            self.sync_address_bar_from_tab();
        }
    }

    pub(super) fn toggle_maximize_pane(&mut self) {
        if !self.panes.is_multi() {
            return;
        }
        self.panes.maximized = match self.panes.maximized {
            Some(_) => None,
            None => Some(self.panes.focused),
        };
        for twv in self.webviews.values_mut() {
            twv.last_bounds = (0, 0, 0, 0, false);
        }
    }

    /// Keeps panes and the active tab in step: a tab activated elsewhere (tab strip, keyboard,
    /// new tab) is shown in the focused pane, or its pane is focused if it already has one.
    pub(super) fn reconcile_panes(&mut self) {
        let open: HashSet<u64> = self.controller.tabs.iter().map(|t| t.id).collect();
        for slot in self.panes.slots.iter_mut() {
            if slot.is_some_and(|id| !open.contains(&id)) {
                *slot = None;
            }
        }
        if !self.panes.is_multi() {
            return;
        }
        let active = self.controller.tab().id;
        if self.panes.last_active == Some(active) {
            return;
        }
        self.panes.last_active = Some(active);
        match self.panes.slot_of(active) {
            Some(i) => self.panes.focused = i,
            None => self.panes.slots[self.panes.focused] = Some(active),
        }
    }

    /// Draws pane frames, headers, dividers and the content of panes that are not web pages.
    /// Records where each web tab's page should go in `self.panes.web_bodies`.
    pub(super) fn render_panes(&mut self, ui: &mut egui::Ui, area: egui::Rect, p: &Palette) {
        self.panes.web_bodies.clear();
        let layout = self.panes.layout;
        let rects = pane_rects(layout, area, self.panes.split_x, self.panes.split_y);
        let shown: Vec<(usize, egui::Rect)> = match self.panes.maximized {
            Some(m) if m < rects.len() => vec![(m, area)],
            _ => rects.iter().copied().enumerate().collect(),
        };
        ui.painter().rect_filled(area, 0.0, p.frame);

        // Draggable dividers (not while a pane is maximized).
        if self.panes.maximized.is_none() {
            let x = area.left() + area.width() * self.panes.split_x;
            let y = area.top() + area.height() * self.panes.split_y;
            let vertical = matches!(layout, PaneLayout::Columns2 | PaneLayout::LeftAndTwo | PaneLayout::Grid4);
            let horizontal = matches!(layout, PaneLayout::Rows2 | PaneLayout::Grid4);
            if vertical {
                let r = egui::Rect::from_center_size(egui::pos2(x, area.center().y), egui::vec2(GAP + 4.0, area.height()));
                let resp = ui.interact(r, egui::Id::unique("oya_pane_split_x"), egui::Sense::drag());
                if resp.hovered() || resp.dragged() {
                    ui.ctx().set_cursor_icon(egui::CursorIcon::ResizeHorizontal);
                }
                if let Some(pos) = resp.interact_pointer_pos().filter(|_| resp.dragged()) {
                    self.panes.split_x = ((pos.x - area.left()) / area.width()).clamp(0.15, 0.85);
                }
            }
            let y_span = if layout == PaneLayout::LeftAndTwo {
                egui::Rect::from_min_max(egui::pos2(x, y - 5.0), egui::pos2(area.right(), y + 5.0))
            } else {
                egui::Rect::from_center_size(egui::pos2(area.center().x, y), egui::vec2(area.width(), GAP + 4.0))
            };
            if horizontal || layout == PaneLayout::LeftAndTwo {
                let resp = ui.interact(y_span, egui::Id::unique("oya_pane_split_y"), egui::Sense::drag());
                if resp.hovered() || resp.dragged() {
                    ui.ctx().set_cursor_icon(egui::CursorIcon::ResizeVertical);
                }
                if let Some(pos) = resp.interact_pointer_pos().filter(|_| resp.dragged()) {
                    self.panes.split_y = ((pos.y - area.top()) / area.height()).clamp(0.15, 0.85);
                }
            }
        }

        enum PaneAction {
            Focus(usize),
            Maximize(usize),
            Close(usize),
            Show(usize, u64),
            NewTab(usize),
        }
        let mut actions: Vec<PaneAction> = Vec::new();

        for (i, rect) in shown {
            let focused = i == self.panes.focused;
            let header = egui::Rect::from_min_size(rect.min, egui::vec2(rect.width(), HEADER_H));
            let body = egui::Rect::from_min_max(egui::pos2(rect.left(), header.bottom()), rect.max);
            let painter = ui.painter().clone();
            painter.rect_filled(
                header,
                egui::CornerRadius { nw: 8, ne: 8, sw: 0, se: 0 },
                if focused { p.surface } else { p.control },
            );
            if focused {
                painter.rect_filled(
                    egui::Rect::from_min_size(header.min, egui::vec2(header.width(), 2.0)),
                    0.0,
                    p.accent,
                );
            }

            let tab = self.panes.slots[i].and_then(|id| self.controller.tabs.iter().find(|t| t.id == id));
            let title = tab.map(tab_title).unwrap_or_else(|| "Empty pane".to_string());
            let header_resp = ui.interact(header, egui::Id::unique(("oya_pane_header", i)), egui::Sense::click());
            if header_resp.double_clicked() {
                actions.push(PaneAction::Maximize(i));
            } else if header_resp.clicked() {
                actions.push(PaneAction::Focus(i));
            }

            // Buttons on the right of the header.
            let close_c = egui::pos2(header.right() - 16.0, header.center().y);
            let max_c = egui::pos2(close_c.x - 26.0, header.center().y);
            for (c, icon, label, act) in [
                (close_c, Icon::CloseSmall, "Close pane", 0),
                (
                    max_c,
                    if self.panes.maximized.is_some() { Icon::Minus } else { Icon::Fullscreen },
                    if self.panes.maximized.is_some() { "Restore panes" } else { "Maximize pane" },
                    1,
                ),
            ] {
                let r = egui::Rect::from_center_size(c, egui::vec2(22.0, 22.0));
                let resp = ui.interact(r, egui::Id::unique(("oya_pane_btn", i, act)), egui::Sense::click());
                if resp.hovered() {
                    painter.circle_filled(c, 11.0, p.hover);
                }
                paint_icon(&painter, icon, c, p.text_weak);
                let label = label.to_string();
                resp.widget_info(|| egui::WidgetInfo::labeled(egui::Role::Button, true, &label));
                if resp.clicked() {
                    actions.push(if act == 0 { PaneAction::Close(i) } else { PaneAction::Maximize(i) });
                }
            }
            let mut job = egui::text::LayoutJob::single_section(
                format!("{}  {title}", i + 1),
                egui::text::TextFormat::simple(
                    egui::FontId::proportional(13.0),
                    if focused { p.text } else { p.text_weak },
                ),
            );
            job.wrap = egui::text::TextWrapping::truncate_at_width((max_c.x - 16.0 - header.left() - 12.0).max(20.0));
            let galley = painter.layout_job(job);
            let pos = egui::pos2(header.left() + 12.0, header.center().y - galley.size().y / 2.0);
            painter.galley(pos, galley, p.text);

            // Body.
            match tab {
                Some(t) if t.current_url.starts_with("https://") || t.current_url.starts_with("http://") => {
                    self.panes.web_bodies.insert(t.id, body);
                    painter.rect_filled(body, 0.0, p.surface);
                }
                Some(t) => {
                    let (tid, is_settings) = (t.id, is_settings_url(&t.current_url));
                    let is_active = tid == self.controller.tab().id;
                    painter.rect_filled(body, 0.0, if is_settings { p.frame } else { p.surface });
                    let mut child = ui.new_child(
                        egui::UiBuilder::new()
                            .max_rect(body.shrink(2.0))
                            .layout(egui::Layout::top_down(egui::Align::Min)),
                    );
                    child.set_clip_rect(body);
                    if is_settings {
                        let before = self.controller.settings.clone();
                        self.render_settings_page(&mut child, p);
                        self.guard_settings_changes(before);
                    } else if is_active {
                        self.render_internal_page(&mut child, p);
                    } else {
                        child.add_space(20.0);
                        child.vertical_centered(|ui| {
                            if ui.button("Show this page").clicked() {
                                actions.push(PaneAction::Focus(i));
                            }
                        });
                    }
                    if !focused && ui.rect_contains_pointer(body) && ui.input(|inp| inp.pointer.any_pressed()) {
                        actions.push(PaneAction::Focus(i));
                    }
                }
                None => {
                    painter.rect_filled(body, 0.0, p.surface);
                    let candidates: Vec<(u64, String)> = self
                        .controller
                        .tabs
                        .iter()
                        .filter(|t| self.panes.slot_of(t.id).is_none())
                        .map(|t| (t.id, tab_title(t)))
                        .take(8)
                        .collect();
                    let mut child = ui.new_child(
                        egui::UiBuilder::new()
                            .max_rect(body.shrink(16.0))
                            .layout(egui::Layout::top_down(egui::Align::Center)),
                    );
                    child.set_clip_rect(body);
                    child.add_space(12.0);
                    child.label(egui::RichText::new("Empty pane").size(16.0).color(p.text));
                    child.add_space(6.0);
                    if child.add(egui::Button::new(egui::RichText::new("New tab here").color(p.on_accent)).fill(p.accent)).clicked() {
                        actions.push(PaneAction::NewTab(i));
                    }
                    if !candidates.is_empty() {
                        child.add_space(8.0);
                        child.label(egui::RichText::new("Or show an open tab:").color(p.text_weak));
                        for (id, title) in candidates {
                            let short: String = title.chars().take(40).collect();
                            if child.button(short).clicked() {
                                actions.push(PaneAction::Show(i, id));
                            }
                        }
                    }
                    if !focused && ui.rect_contains_pointer(body) && ui.input(|inp| inp.pointer.any_pressed()) {
                        actions.push(PaneAction::Focus(i));
                    }
                }
            }
        }

        for action in actions {
            match action {
                PaneAction::Focus(i) => self.focus_pane(i),
                PaneAction::Maximize(i) => {
                    self.focus_pane(i);
                    self.toggle_maximize_pane();
                }
                PaneAction::Close(i) => {
                    self.panes.slots[i] = None;
                    if self.panes.maximized == Some(i) {
                        self.panes.maximized = None;
                    }
                    self.panes.focused = i;
                    // Keep last_active as is so the emptied pane is not refilled at once.
                    self.panes.last_active = Some(self.controller.tab().id);
                }
                PaneAction::Show(i, id) => {
                    self.panes.slots[i] = Some(id);
                    self.focus_pane(i);
                }
                PaneAction::NewTab(i) => {
                    self.panes.focused = i;
                    self.open_new_tab();
                    self.reconcile_panes();
                }
            }
        }
    }

    /// Contents of the Panes menu. Returns `true` when the menu should close.
    pub(super) fn pane_menu_contents(&mut self, ui: &mut egui::Ui, p: &Palette) -> bool {
        let mut close = false;
        ui.horizontal(|ui| {
            ui.add_space(12.0);
            ui.label(egui::RichText::new("Panes").strong().color(p.text));
        });
        ui.add_space(4.0);
        for layout in PaneLayout::all() {
            let w = ui.available_width();
            let (rect, resp) = ui.allocate_exact_size(egui::vec2(w, 34.0), egui::Sense::click());
            let painter = ui.painter();
            let current = self.panes.layout == layout;
            if current {
                painter.rect_filled(rect, 6.0, p.tonal);
            } else if resp.hovered() {
                painter.rect_filled(rect, 6.0, p.hover);
            }
            let icon = egui::Rect::from_min_size(rect.min + egui::vec2(12.0, 8.0), egui::vec2(26.0, 18.0));
            let fg = if current { p.on_tonal } else { p.text };
            paint_layout_icon(painter, layout, icon, fg);
            painter.text(
                egui::pos2(icon.right() + 12.0, rect.center().y),
                egui::Align2::LEFT_CENTER,
                layout.label(),
                egui::TextStyle::Body.resolve(ui.style()),
                fg,
            );
            let label = layout.label().to_string();
            resp.widget_info(|| egui::WidgetInfo::selected(egui::Role::MenuItemRadio, true, current, &label));
            if resp.clicked() {
                self.set_pane_layout(layout);
                close = true;
            }
        }
        if self.panes.is_multi() {
            menu_divider(ui, p);
            let label = if self.panes.maximized.is_some() {
                "Restore all panes"
            } else {
                "Maximize focused pane"
            };
            if menu_item(ui, p, label, "Ctrl+Shift+M", None).clicked() {
                self.toggle_maximize_pane();
                close = true;
            }
            ui.horizontal_wrapped(|ui| {
                ui.add_space(12.0);
                ui.label(
                    egui::RichText::new("Alt+1…4 switches panes. Double-click a pane's title bar to maximize it.")
                        .color(p.text_weak)
                        .size(12.0),
                );
            });
        }
        close
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn layouts_tile_the_area_without_overlap() {
        let area = egui::Rect::from_min_size(egui::pos2(0.0, 100.0), egui::vec2(1200.0, 800.0));
        for layout in PaneLayout::all() {
            let rects = pane_rects(layout, area, 0.5, 0.5);
            assert_eq!(rects.len(), layout.slots());
            for (i, a) in rects.iter().enumerate() {
                assert!(area.contains_rect(*a), "{layout:?} pane {i} outside");
                assert!(a.width() > 100.0 && a.height() > 100.0);
                for b in rects.iter().skip(i + 1) {
                    assert!(!a.intersects(b.shrink(0.5)), "{layout:?} overlap");
                }
            }
        }
        let moved = pane_rects(PaneLayout::Columns2, area, 0.7, 0.5);
        assert!(moved[0].width() > moved[1].width());
    }
}
