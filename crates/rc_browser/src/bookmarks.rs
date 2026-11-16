use serde::{Deserialize, Serialize};
use serde_json::Value;
use std::collections::BTreeSet;
use std::fs;
use std::path::{Path, PathBuf};
use std::time::{SystemTime, UNIX_EPOCH};

const BOOKMARKS_FILE: &str = "bookmarks.json";

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum BookmarkSortMode {
    SmartRelevance,
    ByFolder,
    MostVisited,
    RecentlyAdded,
    AlphabeticalAZ,
}

impl BookmarkSortMode {
    pub fn all() -> &'static [BookmarkSortMode] {
        &[
            BookmarkSortMode::SmartRelevance,
            BookmarkSortMode::ByFolder,
            BookmarkSortMode::MostVisited,
            BookmarkSortMode::RecentlyAdded,
            BookmarkSortMode::AlphabeticalAZ,
        ]
    }

    pub fn label(&self) -> &'static str {
        match self {
            BookmarkSortMode::SmartRelevance => "Smart Sort (Frequency + Recency + Domain)",
            BookmarkSortMode::ByFolder => "By Folder & Subfolder Hierarchy",
            BookmarkSortMode::MostVisited => "Most Visited First",
            BookmarkSortMode::RecentlyAdded => "Recently Added First",
            BookmarkSortMode::AlphabeticalAZ => "Alphabetical (A - Z)",
        }
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct BookmarkItem {
    pub id: u64,
    pub title: String,
    pub url: String,
    /// Hierarchical folder/subfolder path separated by `/` (e.g. `"Bookmarks Bar"`, `"Work/Rust"`, `"Media/Video"`).
    pub folder_path: String,
    pub visit_count: u32,
    pub created_at_ms: u64,
    pub last_visited_ms: u64,
    pub category_tag: String,
    /// The user's own note about the bookmark (shown as a column and a hover tooltip).
    #[serde(default)]
    pub description: String,
}

impl BookmarkItem {
    /// Computes a smart relevance score combining visit count, recency decay, and category weight.
    pub fn smart_score(&self, now: u64) -> f64 {
        let freq_score = (self.visit_count as f64 + 1.0).ln() * 25.0;
        let age_hours = (now.saturating_sub(self.last_visited_ms.max(self.created_at_ms)) as f64)
            / (1000.0 * 3600.0);
        let recency_score = 100.0 / (1.0 + (age_hours / 24.0).max(0.0));
        freq_score + recency_score
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct BookmarkStore {
    pub items: Vec<BookmarkItem>,
    pub folders: Vec<String>,
    pub sort_mode: BookmarkSortMode,
    next_id: u64,
    /// Where the store is persisted; `None` keeps it in memory (unit tests).
    #[serde(skip)]
    path: Option<PathBuf>,
}

impl Default for BookmarkStore {
    fn default() -> Self {
        Self::load()
    }
}

impl BookmarkStore {
    pub fn load() -> Self {
        if let Some(raw) = crate::integrity::load_verified(Path::new(BOOKMARKS_FILE))
            && let Ok(mut parsed) = serde_json::from_str::<BookmarkStore>(&raw)
        {
            parsed.path = Some(PathBuf::from(BOOKMARKS_FILE));
            parsed.ensure_default_folders();
            return parsed;
        }
        let mut store = Self {
            items: Vec::new(),
            folders: vec![
                "Bookmarks Bar".to_string(),
                "Work".to_string(),
                "Work/Projects".to_string(),
                "Media & Video".to_string(),
                "News & Reading".to_string(),
            ],
            sort_mode: BookmarkSortMode::SmartRelevance,
            next_id: 1,
            path: Some(PathBuf::from(BOOKMARKS_FILE)),
        };
        store.ensure_default_folders();
        store
    }

    /// Replaces the bookmarks with a JSON version written elsewhere (after the user approved
    /// adopting an outside change) and saves it with a fresh seal. Returns `false` if unreadable.
    pub fn adopt_json(&mut self, raw: &str) -> bool {
        let Ok(mut parsed) = serde_json::from_str::<BookmarkStore>(raw) else {
            return false;
        };
        parsed.path = self.path.clone();
        parsed.ensure_default_folders();
        *self = parsed;
        self.save();
        true
    }

    /// Writes the bookmarks with a tamper seal (see `integrity`).
    pub fn save(&self) {
        let Some(path) = &self.path else {
            return;
        };
        if let Ok(json) = serde_json::to_string_pretty(self) {
            crate::integrity::save_sealed(path, &json);
        }
    }

    fn ensure_default_folders(&mut self) {
        let mut set: BTreeSet<String> = self
            .folders
            .iter()
            .map(|f| normalize_folder_path(f))
            .filter(|f| !f.is_empty())
            .collect();
        set.insert("Bookmarks Bar".to_string());
        for item in &self.items {
            let norm = normalize_folder_path(&item.folder_path);
            if !norm.is_empty() {
                // Also ensure parent folders exist in the hierarchy
                let mut accum = String::new();
                for part in norm.split('/') {
                    if !accum.is_empty() {
                        accum.push('/');
                    }
                    accum.push_str(part);
                    set.insert(accum.clone());
                }
            }
        }
        self.folders = set.into_iter().collect();
    }

    pub fn add_folder(&mut self, folder_path: &str) {
        let norm = normalize_folder_path(folder_path);
        if norm.is_empty() {
            return;
        }
        let mut accum = String::new();
        for part in norm.split('/') {
            if !accum.is_empty() {
                accum.push('/');
            }
            accum.push_str(part);
            if !self.folders.contains(&accum) {
                self.folders.push(accum.clone());
            }
        }
        self.folders.sort();
        self.save();
    }

    pub fn is_bookmarked(&self, url: &str) -> bool {
        let u = url.trim();
        self.items.iter().any(|b| b.url == u)
    }

    pub fn add_or_update(&mut self, title: &str, url: &str, folder_path: &str) -> u64 {
        let clean_url = url.trim().to_string();
        let clean_folder = {
            let f = normalize_folder_path(folder_path);
            if f.is_empty() {
                "Bookmarks Bar".to_string()
            } else {
                f
            }
        };
        self.add_folder(&clean_folder);

        let clean_title = if title.trim().is_empty() {
            clean_url.clone()
        } else {
            title.trim().to_string()
        };
        let tag = infer_category_tag(&clean_url, &clean_title);
        let now = now_ms();

        if let Some(existing) = self.items.iter_mut().find(|b| b.url == clean_url) {
            existing.title = clean_title;
            existing.folder_path = clean_folder;
            existing.category_tag = tag;
            let id = existing.id;
            self.save();
            return id;
        }

        let id = self.next_id;
        self.next_id = self.next_id.wrapping_add(1);
        self.items.push(BookmarkItem {
            id,
            title: clean_title,
            url: clean_url,
            folder_path: clean_folder,
            visit_count: 1,
            created_at_ms: now,
            last_visited_ms: now,
            category_tag: tag,
            description: String::new(),
        });
        self.save();
        id
    }

    /// Sets the description of a bookmark.
    pub fn set_description(&mut self, bookmark_id: u64, description: &str) {
        if let Some(b) = self.items.iter_mut().find(|b| b.id == bookmark_id) {
            b.description = description.trim().to_string();
            self.save();
        }
    }

    pub fn record_visit(&mut self, url: &str) {
        let u = url.trim();
        let now = now_ms();
        let mut updated = false;
        for item in &mut self.items {
            if item.url == u {
                item.visit_count = item.visit_count.saturating_add(1);
                item.last_visited_ms = now;
                updated = true;
            }
        }
        if updated {
            self.save();
        }
    }


    pub fn remove(&mut self, bookmark_id: u64) {
        self.items.retain(|b| b.id != bookmark_id);
        self.save();
    }

    /// Returns bookmarks filtered by `search_query` and optional `folder_filter` (including its subfolders),
    /// ordered according to `self.sort_mode`.
    pub fn query(&self, search_query: &str, folder_filter: Option<&str>) -> Vec<BookmarkItem> {
        let q = search_query.trim().to_lowercase();
        let folder_prefix = folder_filter
            .map(normalize_folder_path)
            .filter(|s| !s.is_empty());

        let mut results: Vec<BookmarkItem> = self
            .items
            .iter()
            .filter(|b| {
                if let Some(ref fp) = folder_prefix {
                    let sub_prefix = format!("{fp}/");
                    if b.folder_path != *fp && !b.folder_path.starts_with(&sub_prefix) {
                        return false;
                    }
                }
                if q.is_empty() {
                    return true;
                }
                b.title.to_lowercase().contains(&q)
                    || b.url.to_lowercase().contains(&q)
                    || b.folder_path.to_lowercase().contains(&q)
                    || b.category_tag.to_lowercase().contains(&q)
            })
            .cloned()
            .collect();

        let now = now_ms();
        match self.sort_mode {
            BookmarkSortMode::SmartRelevance => {
                results.sort_by(|a, b| {
                    b.smart_score(now)
                        .partial_cmp(&a.smart_score(now))
                        .unwrap_or(std::cmp::Ordering::Equal)
                });
            }
            BookmarkSortMode::ByFolder => {
                results.sort_by(|a, b| {
                    a.folder_path
                        .cmp(&b.folder_path)
                        .then_with(|| a.title.to_lowercase().cmp(&b.title.to_lowercase()))
                });
            }
            BookmarkSortMode::MostVisited => {
                results.sort_by(|a, b| {
                    b.visit_count
                        .cmp(&a.visit_count)
                        .then_with(|| b.last_visited_ms.cmp(&a.last_visited_ms))
                });
            }
            BookmarkSortMode::RecentlyAdded => {
                results.sort_by_key(|b| std::cmp::Reverse(b.created_at_ms));
            }
            BookmarkSortMode::AlphabeticalAZ => {
                results.sort_by_key(|a| a.title.to_lowercase());
            }
        }
        results
    }

    /// Imports bookmarks (preserving folders and subfolders) from installed Google Chrome profiles.
    pub fn import_from_chrome(&mut self) -> Result<usize, String> {
        let local_app_data = std::env::var("LOCALAPPDATA")
            .map_err(|_| "LOCALAPPDATA environment variable not found".to_string())?;
        let user_data = PathBuf::from(local_app_data)
            .join("Google")
            .join("Chrome")
            .join("User Data");
        self.import_chromium_user_data(&user_data, "Imported/Chrome")
    }

    /// Imports bookmarks (preserving folders and subfolders) from installed Microsoft Edge profiles.
    pub fn import_from_edge(&mut self) -> Result<usize, String> {
        let local_app_data = std::env::var("LOCALAPPDATA")
            .map_err(|_| "LOCALAPPDATA environment variable not found".to_string())?;
        let user_data = PathBuf::from(local_app_data)
            .join("Microsoft")
            .join("Edge")
            .join("User Data");
        self.import_chromium_user_data(&user_data, "Imported/Edge")
    }

    /// Imports bookmarks from installed Mozilla Firefox profiles (`bookmarks.html` or `places.sqlite`).
    pub fn import_from_firefox(&mut self) -> Result<usize, String> {
        let app_data = std::env::var("APPDATA")
            .map_err(|_| "APPDATA environment variable not found".to_string())?;
        let profiles_dir = PathBuf::from(app_data)
            .join("Mozilla")
            .join("Firefox")
            .join("Profiles");
        if !profiles_dir.exists() {
            return Err(format!(
                "Firefox Profiles folder not found at {}",
                profiles_dir.display()
            ));
        }

        let mut total_imported = 0usize;
        let entries = fs::read_dir(&profiles_dir).map_err(|e| e.to_string())?;
        for entry in entries.flatten() {
            let p = entry.path();
            if !p.is_dir() {
                continue;
            }
            let html_export = p.join("bookmarks.html");
            if html_export.exists()
                && let Ok(raw) = fs::read_to_string(&html_export)
            {
                total_imported += self.parse_netscape_bookmarks_html(&raw, "Imported/Firefox");
            }
            let places_db = p.join("places.sqlite");
            if places_db.exists()
                && let Ok(bytes) = fs::read(&places_db)
            {
                total_imported += self.extract_urls_from_firefox_places(&bytes, "Imported/Firefox");
            }
        }

        if total_imported == 0 {
            Err("No Firefox bookmarks found in local profiles (you can also import an exported bookmarks.html file)".to_string())
        } else {
            self.save();
            Ok(total_imported)
        }
    }

    /// Imports bookmarks from a user-specified Chromium JSON (`Bookmarks`) or Netscape HTML (`bookmarks.html`) file.
    pub fn import_from_file(&mut self, path: &Path, root_folder: &str) -> Result<usize, String> {
        let raw = fs::read_to_string(path).map_err(|e| format!("Failed to read {}: {e}", path.display()))?;
        let trimmed = raw.trim_start();
        let count = if trimmed.starts_with('{') {
            self.parse_chromium_bookmarks_json(&raw, root_folder)?
        } else {
            self.parse_netscape_bookmarks_html(&raw, root_folder)
        };
        self.save();
        Ok(count)
    }

    fn import_chromium_user_data(
        &mut self,
        user_data_dir: &Path,
        root_prefix: &str,
    ) -> Result<usize, String> {
        if !user_data_dir.exists() {
            return Err(format!(
                "Browser profile directory not found at {}",
                user_data_dir.display()
            ));
        }
        let mut profiles = vec!["Default".to_string()];
        for i in 1..=8 {
            profiles.push(format!("Profile {i}"));
        }

        let mut total = 0usize;
        let mut found_any_file = false;
        for prof in profiles {
            let bm_file = user_data_dir.join(&prof).join("Bookmarks");
            if bm_file.exists() {
                found_any_file = true;
                if let Ok(raw) = fs::read_to_string(&bm_file)
                    && let Ok(c) = self.parse_chromium_bookmarks_json(&raw, root_prefix)
                {
                    total += c;
                }
            }
        }

        if !found_any_file {
            return Err(format!(
                "No Bookmarks file found under {}",
                user_data_dir.display()
            ));
        }
        self.save();
        Ok(total)
    }

    pub fn parse_chromium_bookmarks_json(
        &mut self,
        raw_json: &str,
        root_prefix: &str,
    ) -> Result<usize, String> {
        let val: Value =
            serde_json::from_str(raw_json).map_err(|e| format!("Invalid Bookmarks JSON: {e}"))?;
        let roots = val
            .get("roots")
            .and_then(|r| r.as_object())
            .ok_or_else(|| "Missing 'roots' in Chromium Bookmarks JSON".to_string())?;

        let mut count = 0usize;
        for (root_key, root_node) in roots {
            let sub_name = match root_key.as_str() {
                "bookmark_bar" => "Bookmarks Bar",
                "other" => "Other Bookmarks",
                "synced" => "Mobile Bookmarks",
                other => other,
            };
            let folder = if root_prefix.is_empty() {
                sub_name.to_string()
            } else {
                format!("{root_prefix}/{sub_name}")
            };
            count += self.walk_chromium_node(root_node, &folder);
        }
        Ok(count)
    }

    fn walk_chromium_node(&mut self, node: &Value, current_folder: &str) -> usize {
        let mut count = 0usize;
        let node_type = node.get("type").and_then(|v| v.as_str()).unwrap_or("");
        if node_type == "url" {
            if let Some(url) = node.get("url").and_then(|v| v.as_str())
                && (url.starts_with("https://") || url.starts_with("http://"))
            {
                let name = node.get("name").and_then(|v| v.as_str()).unwrap_or(url);
                self.add_or_update(name, url, current_folder);
                count += 1;
            }
        } else if let Some(children) = node.get("children").and_then(|v| v.as_array()) {
            let folder_name = node.get("name").and_then(|v| v.as_str()).unwrap_or("");
            let next_folder = if !folder_name.is_empty()
                && node_type == "folder"
                && !current_folder.ends_with(folder_name)
            {
                format!("{current_folder}/{folder_name}")
            } else {
                current_folder.to_string()
            };
            for child in children {
                count += self.walk_chromium_node(child, &next_folder);
            }
        }
        count
    }

    /// Parses Netscape Bookmark HTML format (`<!DOCTYPE NETSCAPE-Bookmark-file-1>`),
    /// used by Firefox, Chrome, and Edge HTML bookmark exports, preserving `<H3>` folders & subfolders.
    pub fn parse_netscape_bookmarks_html(&mut self, html: &str, root_prefix: &str) -> usize {
        let mut folder_stack: Vec<String> = vec![root_prefix.to_string()];
        let mut count = 0usize;

        for line in html.lines() {
            let trimmed = line.trim();
            let upper = trimmed.to_uppercase();

            if upper.contains("</DL>") && folder_stack.len() > 1 {
                folder_stack.pop();
            }

            if let Some(h3_start) = upper.find("<H3")
                && let Some(gt) = trimmed[h3_start..].find('>')
            {
                let after_gt = &trimmed[h3_start + gt + 1..];
                if let Some(end_h3) = after_gt.to_uppercase().find("</H3>") {
                    let folder_title = after_gt[..end_h3].trim();
                    if !folder_title.is_empty() {
                        let parent = folder_stack.last().cloned().unwrap_or_default();
                        let next = if parent.is_empty() {
                            folder_title.to_string()
                        } else {
                            format!("{parent}/{folder_title}")
                        };
                        folder_stack.push(next);
                    }
                }
            }

            if let Some(href_pos) = upper.find("HREF=\"") {
                let rest = &trimmed[href_pos + 6..];
                if let Some(end_q) = rest.find('"') {
                    let url = &rest[..end_q];
                    if url.starts_with("https://") || url.starts_with("http://") {
                        let title = if let Some(gt) = rest[end_q..].find('>') {
                            let after_a = &rest[end_q + gt + 1..];
                            if let Some(end_a) = after_a.to_uppercase().find("</A>") {
                                after_a[..end_a].trim()
                            } else {
                                url
                            }
                        } else {
                            url
                        };
                        let folder = folder_stack
                            .last()
                            .cloned()
                            .unwrap_or_else(|| "Bookmarks Bar".to_string());
                        self.add_or_update(title, url, &folder);
                        count += 1;
                    }
                }
            }
        }
        count
    }

    fn extract_urls_from_firefox_places(&mut self, bytes: &[u8], folder: &str) -> usize {
        let text = String::from_utf8_lossy(bytes);
        let mut count = 0usize;
        let mut search_from = 0usize;
        while let Some(rel) = text[search_from..].find("https://") {
            let start = search_from + rel;
            let slice = &text[start..];
            let end = slice
                .find(|c: char| {
                    c.is_control() || c.is_whitespace() || matches!(c, '"' | '\'' | '<' | '>' | '\0')
                })
                .unwrap_or(slice.len().min(240));
            let candidate = &slice[..end];
            if candidate.len() > 10
                && candidate.contains('.')
                && !candidate.contains("mozilla.org")
                && !candidate.contains("firefox.com")
                && !candidate.contains("services.addons")
            {
                self.add_or_update(candidate, candidate, folder);
                count += 1;
                if count >= 200 {
                    break;
                }
            }
            search_from = start + end.max(8);
        }
        count
    }
}

fn normalize_folder_path(raw: &str) -> String {
    raw.trim()
        .replace('\\', "/")
        .split('/')
        .map(|s| s.trim())
        .filter(|s| !s.is_empty())
        .collect::<Vec<_>>()
        .join("/")
}

fn infer_category_tag(url: &str, title: &str) -> String {
    let lower = format!("{} {}", url.to_lowercase(), title.to_lowercase());
    if lower.contains("youtube.com") || lower.contains("twitch.tv") || lower.contains("video") {
        "Video & Media".to_string()
    } else if lower.contains("github.com")
        || lower.contains("docs.rs")
        || lower.contains("rust-lang")
        || lower.contains("stackoverflow")
    {
        "Development".to_string()
    } else if lower.contains("news") || lower.contains("bbc.") || lower.contains("reuters") {
        "News".to_string()
    } else if lower.contains("google.") || lower.contains("duckduckgo") || lower.contains("bing.") {
        "Search".to_string()
    } else {
        "General".to_string()
    }
}

fn now_ms() -> u64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|d| d.as_millis() as u64)
        .unwrap_or(0)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn folders_subfolders_smart_sort_and_imports_work() {
        let mut store = BookmarkStore {
            items: Vec::new(),
            folders: Vec::new(),
            sort_mode: BookmarkSortMode::SmartRelevance,
            next_id: 1,
            path: None,
        };

        let id1 = store.add_or_update("Rust Book", "https://doc.rust-lang.org/book/", "Work/Rust/Docs");
        let id2 = store.add_or_update("YouTube", "https://www.youtube.com", "Media/Video");
        assert!(store.folders.contains(&"Work".to_string()));
        assert!(store.folders.contains(&"Work/Rust".to_string()));
        assert!(store.folders.contains(&"Work/Rust/Docs".to_string()));

        // Visit YouTube multiple times so Smart Sort ranks it first
        for _ in 0..5 {
            store.record_visit("https://www.youtube.com");
        }
        let smart = store.query("", None);
        assert_eq!(smart[0].id, id2);
        assert_eq!(smart[1].id, id1);

        // Filter by parent folder "Work" includes subfolder "Work/Rust/Docs"
        let work_only = store.query("", Some("Work"));
        assert_eq!(work_only.len(), 1);
        assert_eq!(work_only[0].title, "Rust Book");

        // Test Chromium/Edge JSON import with nested folders
        let sample_chrome_json = r#"{
            "roots": {
                "bookmark_bar": {
                    "type": "folder",
                    "name": "Bookmarks bar",
                    "children": [
                        {
                            "type": "folder",
                            "name": "Dev",
                            "children": [
                                { "type": "url", "name": "Crates.io", "url": "https://crates.io" }
                            ]
                        }
                    ]
                }
            }
        }"#;
        let imported_chrome = store
            .parse_chromium_bookmarks_json(sample_chrome_json, "Imported/Chrome")
            .unwrap();
        assert_eq!(imported_chrome, 1);

        // Test Firefox/Netscape HTML import with nested <H3> folders
        let sample_ff_html = r#"<!DOCTYPE NETSCAPE-Bookmark-file-1>
        <DL><p>
            <DT><H3>Mozilla Folder</H3>
            <DL><p>
                <DT><A HREF="https://developer.mozilla.org">MDN Web Docs</A>
            </DL><p>
        </DL><p>"#;
        let imported_ff = store.parse_netscape_bookmarks_html(sample_ff_html, "Imported/Firefox");
        assert_eq!(imported_ff, 1);
        assert_eq!(store.query("MDN", None).len(), 1);
    }
}
