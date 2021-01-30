use oauth_1a::*;
use pulldown_cmark::{Options, Parser};
use std::fs;
use tumblr_api::*;

fn main() {
    let mut renderer = PostRenderer::new();

    let markdown_input = r#"# Hello, world!
This is a test. Here's an ordered list:

1. One
2. Two
3. Three

## And an unordered one
* Element
* Element
* Element

Here's a **code block**:

```
fn main() {
    println!("Hello, world!");
}
```"#;

    let mut options = Options::empty();
    options.insert(Options::ENABLE_STRIKETHROUGH);
    let parser = Parser::new_ext(markdown_input, options);

    for event in parser {
        renderer.push(event);
    }

    let blocks = renderer.finish();

    let mut tumblr = if let Ok(tumblr) = fs::read_to_string("tumblr.toml")
        .map_err(anyhow::Error::from)
        .and_then(|x| toml::from_str(&x).map_err(From::from))
    {
        tumblr
    } else {
        let mut args = std::env::args().skip(1);
        let client_id = ClientId(args.next().unwrap());
        let client_secret = ClientSecret(args.next().unwrap());
        let tumblr = Tumblr::authorize_local(client_id, client_secret).unwrap();
        fs::write("tumblr.toml", toml::ser::to_string_pretty(&tumblr).unwrap()).unwrap();
        tumblr
    };
    println!("{:#?}", tumblr);
    println!("{:#?}", tumblr.user_info());
    println!("{:#?}", blocks);
    println!("{}", serde_json::to_string_pretty(&blocks).unwrap());

    println!(
        "{:#?}",
        tumblr.new_post(
            "leo60228.tumblr.com".into(),
            blocks,
            Some("".into()),
            Default::default()
        )
    );
}
