use indexmap::IndexMap;
use md5::{Digest, Md5};
use mdbook::book::{Book, BookItem};
use mdbook::errors::*;
use mdbook::preprocess::{Preprocessor, PreprocessorContext};
use mdbook::MDBook;
use regex::Regex;
use serde::{Deserialize, Serialize};
use serde_json::Value;
use std::fs;
use std::fs::DirEntry;
use std::io::prelude::*;
use std::io::{BufReader, BufWriter};
use std::ops::Range;
use std::path::Path;

const README_FILE: &str = "README.md";
const SUMMARY_FILE: &str = "SUMMARY.md";

const TITLE_WAY: &str = "title";

#[derive(Debug)]
pub struct MdFile {
    pub meta: Meta,
    pub file: String,
    pub path: String,
}

#[derive(Debug)]
pub struct MdGroup {
    pub name: String,
    pub path: String,
    pub has_readme: bool,
    pub md_list: Vec<MdFile>,
    pub group_list: Vec<MdGroup>,
    pub group_map: IndexMap<String, Vec<MdFile>>,
}

/// A preprocessor for reading YAML front matter from a markdown file.
/// - `author` - For setting the author meta tag.
/// - `title` - For overwritting the title tag.
/// - `description` - For setting the description meta tag.
/// - `keywords` - For setting the keywords meta tag.
/// - `dir` - For setting the dir meta tag.
#[derive(Debug, Default, Serialize, Deserialize)]
pub struct Meta {
    pub section: Option<String>,
    pub title: Option<String>,
    pub author: Option<String>,
    pub description: Option<String>,
    pub keywords: Option<Vec<String>>,
}

#[derive(Default)]
pub struct CMSPreprocessor;

impl CMSPreprocessor {
    pub(crate) const NAME: &'static str = "cms";

    /// Create a new `MetadataPreprocessor`.
    pub fn new() -> Self {
        CMSPreprocessor
    }
}

impl Preprocessor for CMSPreprocessor {
    fn name(&self) -> &str {
        Self::NAME
    }

    fn run(&self, ctx: &PreprocessorContext, mut _book: Book) -> Result<Book> {
        let mut title_way = "filename";

        // In testing we want to tell the preprocessor to blow up by setting a
        // particular config value
        if let Some(nop_cfg) = ctx.config.get_preprocessor(self.name()) {
            if nop_cfg.contains_key("blow-up") {
                anyhow::bail!("Boom!!1!");
            }
            if nop_cfg.contains_key(TITLE_WAY) {
                let v = nop_cfg.get(TITLE_WAY).unwrap();
                title_way = v.as_str().unwrap_or("filename");
            }
        }

        let source_dir = ctx
            .root
            .join(&ctx.config.book.src)
            .to_str()
            .unwrap()
            .to_string();

        gen_summary(&source_dir, title_way);

        match MDBook::load(&ctx.root) {
            Ok(mut mdbook) => {
                mdbook.book.for_each_mut(|section: &mut BookItem| {
                    if let BookItem::Chapter(ref mut ch) = *section {
                        if let Some(m) = Match::find_metadata(&ch.content) {
                            if let Ok(meta) = serde_yaml::from_str(&ch.content[m.range]) {
                                // 暂时不用
                                let _meta: Value = meta;
                                ch.content = String::from(&ch.content[m.end..]);
                            };
                        }
                    }
                });
                Ok(mdbook.book)
            }
            Err(e) => {
                panic!("{}", e);
            }
        }
    }

    fn supports_renderer(&self, renderer: &str) -> bool {
        renderer != "not-supported"
    }
}

pub(crate) struct Match {
    pub(crate) range: Range<usize>,
    pub(crate) end: usize,
}

impl Match {
    pub(crate) fn find_metadata(contents: &str) -> Option<Match> {
        // lazily compute following regex
        // r"\A-{3,}\n(?P<metadata>.*?)^{3,}\n"
        lazy_static::lazy_static! {
            static ref RE: Regex = Regex::new(
                r"(?xms)          # insignificant whitespace mode and multiline
                \A-{3,}\n         # match a horizontal rule at the start of the content
                (?P<metadata>.*?) # name the match between horizontal rules metadata
                ^-{3,}\n          # match a horizontal rule
                "
            )
            .unwrap();
        };
        if let Some(mat) = RE.captures(contents) {
            // safe to unwrap as we know there is a match
            let metadata = mat.name("metadata").unwrap();
            Some(Match {
                range: metadata.start()..metadata.end(),
                end: mat.get(0).unwrap().end(),
            })
        } else {
            None
        }
    }
}

fn md5(buf: &str) -> String {
    let mut hasher = Md5::new();
    hasher.update(buf.as_bytes());
    let f = hasher.finalize();
    let md5_vec = f.as_slice();
    hex::encode_upper(md5_vec)
}

pub fn gen_summary(source_dir: &str, title_way: &str) {
    let mut source_dir = source_dir.to_string();
    if !source_dir.ends_with('/') {
        source_dir.push('/')
    }
    let group = walk_dir(&source_dir, title_way);
    let lines = gen_summary_lines(&source_dir, &group, title_way);
    let buff: String = lines.join("\n");

    let new_md5_string = md5(&buff);

    let summary_file = std::fs::OpenOptions::new()
        .write(true)
        .read(true)
        .create(true)
        .open(source_dir.clone() + "/" + SUMMARY_FILE)
        .unwrap();

    let mut old_summary_file_content = String::new();
    let mut summary_file_reader = BufReader::new(summary_file);
    summary_file_reader
        .read_to_string(&mut old_summary_file_content)
        .unwrap();

    let old_md5_string = md5(&old_summary_file_content);

    if new_md5_string == old_md5_string {
        return;
    }

    let summary_file = std::fs::OpenOptions::new()
        .write(true)
        .read(true)
        .create(true)
        .truncate(true)
        .open(source_dir + "/" + SUMMARY_FILE)
        .unwrap();
    let mut summary_file_writer = BufWriter::new(summary_file);
    summary_file_writer.write_all(buff.as_bytes()).unwrap();
}

fn count(s: &str) -> usize {
    s.split('/').count()
}

fn gen_summary_lines(root_dir: &str, group: &MdGroup, title_way: &str) -> Vec<String> {
    let mut lines: Vec<String> = vec![];

    let path = group.path.replace(root_dir, "");
    let cnt = count(&path);

    let buff_spaces = " ".repeat(4 * (cnt - 1));
    let mut name = group.name.clone();

    let buff_link: String;
    if name == "src" {
        name = String::from("Welcome");
    }

    if path.is_empty() {
        lines.push(String::from("# SUMMARY"));
        buff_link = String::new();
    } else {
        buff_link = format!("{}* [{}]()", buff_spaces, name);
    }

    if buff_spaces.is_empty() {
        lines.push(String::from("\n"));
        if name != "Welcome" {
            lines.push(String::from("----"));
        }
    }

    lines.push(buff_link);

    for md in &group.md_list {
        let path = md.path.replace(root_dir, "");
        if path == SUMMARY_FILE {
            continue;
        }
        if path.ends_with(README_FILE) {
            continue;
        }

        let cnt = count(&path);
        let buff_spaces = " ".repeat(4 * (cnt - 1));

        let buff_link: String;

        let meta = &md.meta;
        let title = match meta.title.as_ref() {
            None => "",
            Some(title) => title,
        };

        if title_way != "filename" && !title.is_empty() {
            buff_link = format!("{}* [{}]({})", buff_spaces, title, path);
        } else {
            buff_link = format!("{}* [{}]({})", buff_spaces, md.file, path);
        }

        lines.push(buff_link);
    }

    for (parent, ml) in &group.group_map {
        lines.push(format!("* [{}]()", parent));
        for md in ml {
            let path = md.path.replace(root_dir, "");
            if path == SUMMARY_FILE {
                continue;
            }
            if path.ends_with(README_FILE) {
                continue;
            }
            let buff_spaces = " ".repeat(4);

            let buff_link: String;

            let meta = &md.meta;
            let title = match meta.title.as_ref() {
                None => "",
                Some(title) => title,
            };
            if title_way != "filename" && !title.is_empty() {
                buff_link = format!("{}* [{}]({})", buff_spaces, title, path);
            } else {
                buff_link = format!("{}* [{}]({})", buff_spaces, md.file, path);
            }

            lines.push(buff_link);
        }
    }

    for group in &group.group_list {
        let mut line = gen_summary_lines(root_dir, group, title_way);
        lines.append(&mut line);
    }

    lines
}

fn get_meta(entry: &DirEntry, title_way: &str) -> Meta {
    let md_file = std::fs::File::open(entry.path().to_str().unwrap()).unwrap();
    let mut md_file_content = String::new();
    let mut md_file_reader = BufReader::new(md_file);
    md_file_reader.read_to_string(&mut md_file_content).unwrap();

    match title_way {
        "first-line" => {
            let lines = md_file_content.split('\n');

            let mut title: String = "".to_string();
            let mut first_h1_line = "";
            for line in lines {
                if line.starts_with("# ") {
                    first_h1_line = line.trim_matches('#').trim();
                    break;
                }
            }

            if first_h1_line.is_empty() {
                title = first_h1_line.to_string();
            }

            Meta {
                section: None,
                title: Some(title),
                author: None,
                description: None,
                keywords: None,
            }
        }
        "meta" => {
            if let Some(m) = Match::find_metadata(&md_file_content) {
                let meta_info = &md_file_content[m.range];

                match serde_yaml::from_str(meta_info) {
                    Ok(meta) => meta,
                    Err(_e) => Meta::default(),
                }
            } else {
                Meta::default()
            }
        }
        _ => Meta::default(),
    }
}

fn walk_dir(dir: &str, title_way: &str) -> MdGroup {
    let read_dir = fs::read_dir(dir).unwrap();
    let name = Path::new(dir)
        .file_name()
        .unwrap()
        .to_owned()
        .to_str()
        .unwrap()
        .to_string();
    let mut group = MdGroup {
        name,
        path: dir.to_string(),
        has_readme: false,
        group_list: vec![],
        md_list: vec![],
        group_map: Default::default(),
    };

    for entry in read_dir {
        let entry = entry.unwrap();
        // println!("{:?}", entry);
        if entry.file_type().unwrap().is_dir() {
            let g = walk_dir(entry.path().to_str().unwrap(), title_way);
            if g.has_readme {
                group.group_list.push(g);
            }
            continue;
        }
        let file_name = entry.file_name();
        let file_name = file_name.to_str().unwrap().to_string();
        if file_name == README_FILE {
            group.has_readme = true;
        }
        let arr: Vec<&str> = file_name.split('.').collect();
        if arr.len() < 2 {
            continue;
        }
        let file_name = arr[0];
        let file_ext = arr[1];
        if file_ext.to_lowercase() != "md" {
            continue;
        }

        let meta = get_meta(&entry, title_way);

        match &meta.section {
            None => {
                let md = MdFile {
                    meta,
                    file: file_name.to_string(),
                    path: entry.path().to_str().unwrap().to_string(),
                };
                group.md_list.push(md);
            }
            Some(meta_dir) => {
                let meta_dir = meta_dir.clone();
                let md = MdFile {
                    meta,
                    file: file_name.to_string(),
                    path: entry.path().to_str().unwrap().to_string(),
                };
                (*group.group_map.entry(meta_dir.clone()).or_default()).push(md);
            }
        }
    }

    group
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_find_metadata_not_at_start() {
        let s = "\
        content\n\
        ---
        author: \"Adam\"
        title: \"Blog Post #1\"
        keywords:
          : \"rust\"
          : \"blog\"
        date: \"2021/02/15\"
        modified: \"2021/02/16\"\n\
        ---
        content
        ";
        if let Some(_) = Match::find_metadata(s) {
            panic!()
        }
    }

    #[test]
    fn test_find_metadata_at_start() {
        let s = "\
        ---
        author: \"Adam\"
        title: \"Blog Post #1\"
        keywords:
          - \"rust\"
          - \"blog\"
        date: \"2021/02/15\"
        description: \"My rust blog.\"
        modified: \"2021/02/16\"\n\
        ---\n\
        content
        ";
        if let None = Match::find_metadata(s) {
            panic!()
        }
    }

    #[test]
    fn test_find_metadata_partial_metadata() {
        let s = "\
        ---
        author: \"Adam\n\
        content
        ";
        if let Some(_) = Match::find_metadata(s) {
            panic!()
        }
    }

    #[test]
    fn test_find_metadata_not_metadata() {
        type Map = serde_json::Map<String, serde_json::Value>;
        let s = "\
        ---
        This is just standard content that happens to start with a line break
        and has a second line break in the text.\n\
        ---
        followed by more content
        ";
        if let Some(m) = Match::find_metadata(s) {
            if let Ok(_) = serde_yaml::from_str::<Map>(&s[m.range]) {
                panic!()
            }
        }
    }
}
