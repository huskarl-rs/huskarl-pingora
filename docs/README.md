# Documentation sources

Read the [rendered guides and API reference](https://docs.rs/huskarl-pingora/latest/huskarl_pingora/).
For unpublished changes, run `cargo doc --no-deps --all-features` and open
`target/doc/huskarl_pingora/index.html`.

These Markdown files are included in rustdoc by `src/_docs.rs`. Rustdoc resolves
`crate::` links and hides doctest setup lines beginning with `#`; GitHub's Markdown
renderer does neither. Repository landing pages therefore link to rendered guides.

| Reader need | Sources |
|---|---|
| Learn through a first successful run | `tutorial/` |
| Complete a specific integration task | `how_to/` |
| Understand design and tradeoffs | `explanation/` |
| Look up behavior and configuration | `reference/` and public API rustdoc |
| Change or validate this library | `contributing/` |
