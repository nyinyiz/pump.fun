use oauth2::{
    AuthUrl, AuthorizationCode, ClientId, ClientSecret, CsrfToken, PkceCodeChallenge,
    RedirectUrl, Scope, TokenUrl, TokenResponse,
};
use std::error::Error;
use oauth2::basic::BasicClient;
use reqwest::Client as ReqwestClient; // Import the reqwest Client
use reqwest::Error as ReqwestError; // Import reqwest error for handling

// Twitter API credentials
const CLIENT_ID: &str = "your_twitter_client_id";
const CLIENT_SECRET: &str = "your_twitter_client_secret";
const REDIRECT_URI: &str = "https://example.com/oauth/callback"; // update with your callback route

// Twitter API endpoints
const AUTH_URL: &str = "https://twitter.com/i/oauth2/authorize";
const TOKEN_URL: &str = "https://api.twitter.com/2/oauth2/token";


#[tokio::main]
async fn main() -> Result<(), Box<dyn Error>> {
    // Create the OAuth2 client
    let client = BasicClient::new(
        ClientId::new(CLIENT_ID.to_string()),
        Some(ClientSecret::new(CLIENT_SECRET.to_string())),
        AuthUrl::new(AUTH_URL.to_string())?,
        Some(TokenUrl::new(TOKEN_URL.to_string())?),
    )
        .set_redirect_uri(RedirectUrl::new(REDIRECT_URI.to_string())?);

    // Generate the authorization URL
    let (pkce_challenge, pkce_verifier) = PkceCodeChallenge::new_random_sha256();
    let (auth_url, csrf_token) = client
        .authorize_url(CsrfToken::new_random)
        .add_scope(Scope::new("tweet.write".to_string()))
        .set_pkce_challenge(pkce_challenge)
        .url();

    println!("Open this URL in your browser to authenticate:");
    println!("{}", auth_url);

    // Receive the authorization code from the callback
    println!("Enter the authorization code from the callback URL:");
    let auth_code = AuthorizationCode::new(
        rpassword::prompt_password("Authorization code: ")?.trim().to_string(),
    );

    // Create an asynchronous HTTP client
    let reqwest_client = ReqwestClient::new(); // Instantiate the reqwest async client

    // Create a closure to perform the request
    let request_async = move |req: oauth2::HttpRequest| {
        let client = reqwest_client.clone(); // Clone the reqwest client
        async move {
            // Extract URL and body from the `req`
            let url = req.url.to_string();
            let body = String::from_utf8_lossy(&req.body).into_owned();

            let response = client
                .post(&url) // Use the token URL directly
                .header("Content-Type", "application/x-www-form-urlencoded")
                .body(body) // Use the extracted body as a String
                .send()
                .await?;

            let text = response.text().await?;
            Ok(text) // Handle response as needed
        }
    };

    // Exchange the authorization code for an access token
    let token_response = client
        .exchange_code(auth_code)
        .set_pkce_verifier(pkce_verifier)
        .request_async(request_async) // Pass the closure here
        .await?;

    // Extract the access token from the response
    let access_token = token_response.access_token().clone();

    println!("Access token: {}", access_token.secret());

    Ok(())
}
