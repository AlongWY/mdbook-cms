# mdbook-cms

A preprocessor bring cms to mdbook.

#### install

```bash
cargo install mdbook-cms
```

#### Use cms mdbook preprocessor.

```bash
#cat /path/to/your/mdbook/book.toml

[book]
authors = []
language = "en"
multilingual = false
src = "src"

[build]
create-missing = false

#use cms preprocessor
[preprocessor.cms]
# meta/first-line/filename
title = "meta"

[output.html.fold]
enable = true
level = 0

```

When you run

```bash
mdbook serve
```

Or

```bash
mdbook build
```

this will also walk your mdbook src dir and generate the book summary in /path/to/your/mdbook/src/SUMMARY.md


