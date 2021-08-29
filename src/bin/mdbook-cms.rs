use clap::{App, Arg, ArgMatches, SubCommand};
use mdbook::errors::Error;
use mdbook::preprocess::{CmdPreprocessor, Preprocessor};
use mdbook_cms::CMSPreprocessor;
use semver::{Version, VersionReq};
use std::fs::File;
use std::io;
use std::io::Write;
use std::process;

const CMS_CONFIG: &[u8] = include_bytes!(concat!(env!("CARGO_MANIFEST_DIR"), "/vendor/config.yml"));
const CMS_INDEX: &[u8] = include_bytes!(concat!(env!("CARGO_MANIFEST_DIR"), "/vendor/index.html"));

const CMS_DIR: &str = "admin";
const CMS_FILES: &[(&str, &[u8])] = &[("config.yml", CMS_CONFIG), ("index.html", CMS_INDEX)];

pub fn make_app() -> App<'static, 'static> {
    App::new("mdbook-cms")
        .about("A mdbook preprocessor to add cms.")
        .subcommand(
            SubCommand::with_name("supports")
                .arg(Arg::with_name("renderer").required(true))
                .about("Check whether a renderer is supported by this preprocessor"),
        )
}

fn main() {
    let matches = make_app().get_matches();

    // Users will want to construct their own preprocessor here
    let preprocessor = CMSPreprocessor::new();

    if let Some(sub_args) = matches.subcommand_matches("supports") {
        handle_supports(&preprocessor, sub_args);
    } else if let Err(e) = handle_preprocessing(&preprocessor) {
        eprintln!("{}", e);
        process::exit(1);
    }
}

fn handle_preprocessing(pre: &dyn Preprocessor) -> Result<(), Error> {
    let (ctx, book) = CmdPreprocessor::parse_input(io::stdin())?;

    let admin_dir = ctx.config.book.src.join(CMS_DIR);
    std::fs::create_dir_all(&admin_dir).unwrap();

    for (name, content) in CMS_FILES {
        let filepath = admin_dir.join(name);
        if !filepath.exists() {
            let mut file = File::create(filepath).expect("can't open file for writing");
            file.write_all(content)
                .expect("can't write content to file");
        }
    }

    let book_version = Version::parse(&ctx.mdbook_version)?;
    let version_req = VersionReq::parse(mdbook::MDBOOK_VERSION)?;

    if !version_req.matches(&book_version) {
        eprintln!(
            "Warning: The {} plugin was built against version {} of mdbook, \
             but we're being called from version {}",
            pre.name(),
            mdbook::MDBOOK_VERSION,
            ctx.mdbook_version
        );
    }

    let processed_book = pre.run(&ctx, book)?;
    serde_json::to_writer(io::stdout(), &processed_book)?;

    Ok(())
}

fn handle_supports(pre: &dyn Preprocessor, sub_args: &ArgMatches) -> ! {
    let renderer = sub_args.value_of("renderer").expect("Required argument");
    let supported = pre.supports_renderer(renderer);

    // Signal whether the renderer is supported by exiting with 1 or 0.
    if supported {
        process::exit(0);
    } else {
        process::exit(1);
    }
}
