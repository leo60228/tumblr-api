use maplit::*;
use oauth_1a::*;
use std::fs;
use tumblr_api::*;

fn main() {
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

    println!(
        "{:#?}",
        tumblr.new_post(
            "leo60228.tumblr.com".into(),
            vec![
                PostContent::Text(TextBlock {
                    text: "Hello, world!".into(),
                    subtype: None,
                }),
                PostContent::Image(ImageBlock {
                    media: vec![MediaObject {
                        file: MediaFile::Identifier("vriska".to_string()),
                        mime_type: Some(mime::IMAGE_PNG),
                        width: Some(92),
                        height: Some(128),
                        original_dimensions_missing: false,
                        cropped: false,
                        has_original_dimensions: true,
                    }],
                    ..Default::default()
                })
            ],
            hashmap! {
                "vriska".to_string() => MediaUpload {
                    bytes: fs::read("/home/leo60228/vriska_emote.png").unwrap(),
                    mime_type: mime::IMAGE_PNG,
                    filename: "vriska_emote.png".into(),
                }
            }
        )
    );
}
