use anyhow::{anyhow, Result};
use http_types::{Method, Url};
use mime::MediaType;
use oauth_1a::*;
use reqwest::blocking::{
    multipart::{Form, Part},
    RequestBuilder,
};
use serde::{
    de::{DeserializeOwned, Deserializer},
    ser::Serializer,
    Deserialize, Serialize,
};
use std::collections::HashMap;
use std::convert::identity;
use std::convert::TryInto;
use std::fmt::{self, Debug};
use std::num::ParseIntError;
use std::ops::Not;
use std::str::FromStr;
use tiny_http::{Response as HttpResponse, Server};

#[derive(Debug, Serialize, Deserialize)]
pub struct Tumblr {
    key: SigningKey,
    data: OAuthData,
}

#[derive(Debug, Serialize, Deserialize)]
pub struct Meta {
    pub status: u16,
    pub msg: String,
}

#[derive(Debug, Serialize, Deserialize)]
pub struct ApiError {
    pub title: String,
    pub code: u16,
}

#[derive(Debug, Serialize, Deserialize)]
pub struct Response<T: DeserializeOwned> {
    pub meta: Meta,
    #[serde(
        deserialize_with = "serde_with::rust::default_on_error::deserialize",
        default = "Default::default"
    )]
    pub response: Option<T>,
    #[serde(default)]
    pub errors: Vec<ApiError>,
}

#[derive(Debug, Serialize, Deserialize)]
#[serde(rename_all = "kebab-case")]
pub enum TextBlockSubtype {
    Heading1,
    Heading2,
    Quirky,
    Quote,
    Indented,
    Chat,
    OrderedListItem,
    UnorderedListItem,
}

#[derive(Debug, Serialize, Deserialize)]
pub struct TextBlock {
    pub text: String,
    pub subtype: Option<TextBlockSubtype>,
}

macro_rules! fromstr_display {
    ($x:ty) => {
        impl<'de> Deserialize<'de> for $x {
            fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
            where
                D: Deserializer<'de>,
            {
                serde_with::rust::display_fromstr::deserialize(deserializer)
            }
        }

        impl Serialize for $x {
            fn serialize<S>(&self, serializer: S) -> Result<S::Ok, S::Error>
            where
                S: Serializer,
            {
                serde_with::rust::display_fromstr::serialize(self, serializer)
            }
        }
    };
}

#[derive(Debug, Clone, Copy, Default, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub struct ColorId(pub usize);

impl fmt::Display for ColorId {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "c{}", self.0)
    }
}

impl FromStr for ColorId {
    type Err = ParseIntError;

    fn from_str(src: &str) -> Result<Self, ParseIntError> {
        Ok(Self(src.trim_start_matches("c").parse()?))
    }
}

fromstr_display!(ColorId);

#[derive(Debug, Clone, Copy, Default, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub struct Color(pub [u8; 3]);

impl fmt::Display for Color {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{:x}{:x}{:x}", self.0[0], self.0[1], self.0[2])
    }
}

impl FromStr for Color {
    type Err = anyhow::Error;

    fn from_str(src: &str) -> Result<Self> {
        match src.len() {
            3 => {
                let mut chars = src.chars().filter_map(|x| x.to_digit(16));
                let r = (chars.next().ok_or_else(|| anyhow!("Not numeric!"))? << 4) as u8;
                let g = (chars.next().ok_or_else(|| anyhow!("Not numeric!"))? << 4) as u8;
                let b = (chars.next().ok_or_else(|| anyhow!("Not numeric!"))? << 4) as u8;
                Ok(Self([r, g, b]))
            }
            6 => {
                let mut chars = src.chars().filter_map(|x| x.to_digit(16));
                let mut r = (chars.next().ok_or_else(|| anyhow!("Not numeric!"))? << 4) as u8;
                r += chars.next().ok_or_else(|| anyhow!("Not numeric!"))? as u8;
                let mut g = (chars.next().ok_or_else(|| anyhow!("Not numeric!"))? << 4) as u8;
                g += chars.next().ok_or_else(|| anyhow!("Not numeric!"))? as u8;
                let mut b = (chars.next().ok_or_else(|| anyhow!("Not numeric!"))? << 4) as u8;
                b += chars.next().ok_or_else(|| anyhow!("Not numeric!"))? as u8;
                Ok(Self([r, g, b]))
            }
            x => Err(anyhow!("Invalid length {}", x)),
        }
    }
}

fromstr_display!(Color);

#[derive(Debug, Serialize, Deserialize)]
pub struct MediaUpload {
    pub bytes: Vec<u8>,
    pub mime_type: MediaType,
    pub filename: String,
}

#[derive(Debug, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum MediaFile {
    Url(Url),
    Identifier(String),
}

#[derive(Debug, Serialize, Deserialize)]
pub struct MediaObject {
    #[serde(flatten)]
    pub file: MediaFile,
    #[serde(rename = "type")]
    #[serde(skip_serializing_if = "Option::is_none")]
    pub mime_type: Option<MediaType>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub width: Option<usize>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub height: Option<usize>,
    #[serde(skip_serializing_if = "Not::not")]
    pub original_dimensions_missing: bool,
    #[serde(skip_serializing_if = "Not::not")]
    pub cropped: bool,
    #[serde(skip_serializing_if = "Not::not")]
    pub has_original_dimensions: bool,
}

#[derive(Debug, Serialize, Deserialize, Default)]
pub struct ImageBlock {
    pub media: Vec<MediaObject>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub colors: Option<HashMap<ColorId, Color>>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub feedback_token: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub poster: Option<MediaObject>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub alt_text: Option<String>,
}

#[derive(Debug, Serialize, Deserialize)]
pub struct LinkBlock {
    pub url: Url,
    pub title: Option<String>,
    pub description: Option<String>,
    pub author: Option<String>,
    pub site_name: Option<String>,
    pub display_url: Option<String>,
    pub poster: Option<MediaObject>,
}

#[derive(Debug, Serialize, Deserialize)]
#[serde(tag = "type")]
#[serde(rename_all = "lowercase")]
pub enum PostContent {
    Text(TextBlock),
    Image(ImageBlock),
    Link(LinkBlock),
}

impl<T: Debug + DeserializeOwned> From<Response<T>> for Result<T> {
    fn from(r: Response<T>) -> Self {
        if (200..300).contains(&r.meta.status) {
            if let Some(response) = r.response {
                return Ok(response);
            }
        }

        Err(anyhow!(
            "API error: {} {} ({:#?})",
            r.meta.status,
            r.meta.msg,
            r.errors
        ))
    }
}

#[derive(Debug, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum PostFormat {
    Html,
    Markdown,
    Raw,
}

#[derive(Debug, Serialize, Deserialize)]
pub enum TwitterStatus {
    Y,
    N,
    #[serde(rename = "auto")]
    Auto,
}

#[derive(Debug, Serialize, Deserialize)]
pub enum FacebookStatus {
    Y,
    N,
}

impl FacebookStatus {
    fn no() -> Self {
        Self::N
    }
}

#[derive(Debug, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum BlogType {
    Public,
    Private,
}

impl BlogType {
    fn public() -> Self {
        Self::Public
    }
}

#[derive(Debug, Serialize, Deserialize)]
pub struct Blog {
    pub name: String,
    pub url: Url,
    pub title: String,
    pub primary: bool,
    pub followers: usize,
    pub tweet: TwitterStatus,
    #[serde(default = "FacebookStatus::no")]
    pub facebook: FacebookStatus,
    #[serde(rename = "type")]
    #[serde(default = "BlogType::public")]
    pub typ: BlogType,
}

#[derive(Debug, Serialize, Deserialize)]
pub struct UserInfo {
    pub following: usize,
    pub default_post_format: PostFormat,
    pub name: String,
    pub likes: usize,
    pub blogs: Vec<Blog>,
}

impl Tumblr {
    pub fn authorize<C, F, E>(
        open: F,
        client_id: ClientId,
        client_secret: ClientSecret,
        callback: C,
    ) -> Result<Self>
    where
        C: AsRef<str>,
        F: FnOnce(&str) -> Result<Url, E>,
        E: Into<Box<dyn std::error::Error + Send + Sync + 'static>>,
    {
        let callback = callback.as_ref().to_string();

        let mut key = SigningKey::without_token(client_secret);
        let mut data = OAuthData {
            client_id,
            token: None,
            signature_method: SignatureMethod::HmacSha1,
            nonce: Nonce::generate(),
        };
        let initiate = Url::parse("https://www.tumblr.com/oauth/request_token").unwrap();
        let req = SignableRequest::new(Method::Post, initiate.clone(), Default::default());
        let authorization =
            data.authorization(req, AuthorizationType::RequestToken { callback }, &key);
        let resp = reqwest::blocking::Client::new()
            .post(initiate)
            .header("Authorization", authorization)
            .header("Content-Length", "0")
            .send()?
            .text()?;
        data.regen_nonce();
        let token = receive_token(&mut data, &mut key, &resp)?;
        let authorize_url = format!(
            "https://www.tumblr.com/oauth/authorize?oauth_token={}",
            token.0
        );
        let authorization_response = open(&authorize_url).map_err(|x| anyhow!(x.into()))?;
        let verifier = get_verifier(&authorization_response)?;
        let access = Url::parse("https://www.tumblr.com/oauth/access_token").unwrap();
        let req = SignableRequest::new(Method::Post, access.clone(), Default::default());
        let authorization =
            data.authorization(req, AuthorizationType::AccessToken { verifier }, &key);
        let resp = reqwest::blocking::Client::new()
            .post(access)
            .header("Authorization", authorization)
            .header("Content-Length", "0")
            .send()?
            .text()?;
        data.regen_nonce();
        receive_token(&mut data, &mut key, &resp)?;
        Ok(Self { key, data })
    }

    pub fn authorize_local(client_id: ClientId, client_secret: ClientSecret) -> Result<Self> {
        let server = Server::http("127.0.0.1:1234").map_err(|x| anyhow!(x))?;
        Self::authorize::<_, _, anyhow::Error>(
            |url| {
                open::that(url)?;
                for request in server.incoming_requests() {
                    let url = Url::parse("http://localhost:1234")
                        .unwrap()
                        .join(request.url())?;
                    if url.path() == "/" {
                        let response =
                            HttpResponse::from_string("Authorized. You can close this page now.");
                        request.respond(response)?;
                        return Ok(url);
                    } else {
                        let response =
                            HttpResponse::from_string("404 Not Found").with_status_code(404);
                        request.respond(response)?;
                    }
                }
                Err(anyhow!("Didn't get callback!"))
            },
            client_id,
            client_secret,
            "http://localhost:1234",
        )
    }

    fn req<T, U, B, F>(&mut self, url: U, method: Method, body: Option<B>, extra: F) -> Result<T>
    where
        T: DeserializeOwned + Debug,
        U: TryInto<Url>,
        U::Error: Into<Box<dyn std::error::Error + Send + Sync + 'static>>,
        B: Serialize,
        F: FnOnce(RequestBuilder) -> RequestBuilder,
    {
        let url = url.try_into().map_err(|x| anyhow!(x.into()))?;
        self.data.regen_nonce();
        let req = SignableRequest::new(method, url.clone(), Default::default());
        let authorization = self
            .data
            .authorization(req, AuthorizationType::Request, &self.key);
        if let Some(body) = body {
            extra(
                reqwest::blocking::Client::new()
                    .request(method.to_string().parse()?, url)
                    .header("Authorization", authorization)
                    .json(&body),
            )
            .send()?
            .json::<Response<T>>()?
            .into()
        } else {
            extra(
                reqwest::blocking::Client::new()
                    .request(method.to_string().parse()?, url)
                    .header("Authorization", authorization)
                    .header("Content-Length", "0"),
            )
            .send()?
            .json::<Response<T>>()?
            .into()
        }
    }

    fn get<T, U>(&mut self, url: U) -> Result<T>
    where
        T: DeserializeOwned + Debug,
        U: TryInto<Url>,
        U::Error: Into<Box<dyn std::error::Error + Send + Sync + 'static>>,
    {
        self.req(url, Method::Get, None::<()>, identity)
    }

    pub fn user_info(&mut self) -> Result<UserInfo> {
        #[derive(Debug, Deserialize)]
        struct User {
            pub user: UserInfo,
        }

        Ok(self
            .get::<User, _>("https://api.tumblr.com/v2/user/info")?
            .user)
    }

    pub fn new_post(
        &mut self,
        blog: String,
        content: Vec<PostContent>,
        media: HashMap<String, MediaUpload>,
    ) -> Result<u64> {
        #[derive(Debug, Serialize)]
        struct NewPost {
            pub content: Vec<PostContent>,
        }

        #[derive(Debug, Deserialize)]
        struct PostId {
            #[serde(with = "serde_with::rust::display_fromstr")]
            pub id: u64,
        }

        let new = NewPost { content };
        let mut form = Form::new().part(
            "json",
            Part::text(serde_json::to_string(&new)?).mime_str("application/json")?,
        );
        for (k, v) in media {
            form = form.part(
                k,
                Part::bytes(v.bytes)
                    .mime_str(v.mime_type.as_ref())?
                    .file_name(v.filename),
            );
        }

        Ok(self
            .req::<PostId, _, _, _>(
                &format!("https://api.tumblr.com/v2/blog/{}/posts", blog)[..],
                Method::Post,
                None::<()>,
                |req| req.multipart(form),
            )?
            .id)
    }
}
