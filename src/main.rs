use actix_web::{web, App, HttpResponse, HttpServer, Responder};
use base64::{engine::general_purpose, Engine as _};
use josekit::{
    jwk::{self, Jwk},
    jws::{JwsHeader, ES256},
    jwt,
    JoseError,
};
use serde_json::{json, Value};
use std::collections::HashSet;
use std::sync::Mutex;
use uuid::Uuid;
use reqwest;
use anyhow::anyhow;

struct AppState {
    nonces: Mutex<HashSet<String>>,
}

fn decode_jwt_header(token: &str) -> Result<Value, JoseError> {
    let parts: Vec<&str> = token.split('.').collect();
    if parts.len() != 3 {
        return Err(JoseError::InvalidJwtFormat(anyhow!("JWT must have 3 parts")));
    }
    let header_bytes = general_purpose::URL_SAFE_NO_PAD
        .decode(parts[0])
        .map_err(|e| JoseError::InvalidJwtFormat(anyhow!("Base64 decode error: {}", e)))?;
    let header_value: Value = serde_json::from_slice(&header_bytes)
        .map_err(|e| JoseError::InvalidJwtFormat(anyhow!("JSON decode error: {}", e)))?;
    Ok(header_value)
}

async fn generate_nonce(data: web::Data<AppState>) -> impl Responder {
    let nonce = Uuid::new_v4().to_string();
    data.nonces.lock().unwrap().insert(nonce.clone());
    HttpResponse::Ok().json(json!({ "nonce": nonce }))
}

async fn verify_attestation(
    data: web::Data<AppState>,
    body: String,
) -> impl Responder {
    let token = body.trim();

    let header_value = match decode_jwt_header(token) {
        Ok(val) => val,
        Err(e) => {
            return HttpResponse::BadRequest().json(json!({ "error": e.to_string() }))
        }
    };

    let jwk_value = match header_value.get("jwk") {
        Some(v) => v.clone(),
        None => {
            return HttpResponse::BadRequest()
                .json(json!({ "error": "JWK missing in header" }))
        }
    };

    let jwk = match jwk_value.as_object() {
        Some(map) => match Jwk::from_map(map.clone()) {
            Ok(jwk) => jwk,
            Err(e) => {
                return HttpResponse::BadRequest()
                    .json(json!({ "error": format!("failed to parse JWK: {}", e) }))
            }
        },
        None => {
            return HttpResponse::BadRequest()
                .json(json!({ "error": "JWK is not a JSON object" }))
        }
    };

    let verifier = match ES256.verifier_from_jwk(&jwk) {
        Ok(v) => v,
        Err(e) => {
            return HttpResponse::BadRequest()
                .json(json!({ "error": e.to_string() }))
        }
    };

    let (payload, _header) = match jwt::decode_with_verifier(token, &verifier) {
        Ok(tuple) => tuple,
        Err(e) => {
            return HttpResponse::BadRequest()
                .json(json!({ "error": e.to_string() }))
        }
    };

    let nonce = match payload.claim("nonce").and_then(|v| v.as_str()) {
        Some(n) => n,
        None => {
            return HttpResponse::BadRequest()
                .json(json!({ "error": "nonce not found in claims" }))
        }
    };

    let mut nonces = data.nonces.lock().unwrap();
    if nonces.remove(nonce) {
        HttpResponse::Ok().json(json!({ "status": "success" }))
    } else {
        HttpResponse::BadRequest().json(json!({ "error": "invalid or reused nonce" }))
    }
}

async fn prove_ownership() -> Result<(), Box<dyn std::error::Error>> {
    let client = reqwest::Client::new();

    let nonce_resp = client
        .get("http://127.0.0.1:8080/nonce")
        .send()
        .await?
        .json::<serde_json::Value>()
        .await?;
    let nonce = nonce_resp["nonce"]
        .as_str()
        .ok_or_else(|| anyhow!("nonce field missing"))?;

    let private_key = jwk::Jwk::generate_ec_key(josekit::jwk::alg::ec::EcCurve::P256)?;
    let public_key = private_key.to_public_key()?;


    let mut header = JwsHeader::new();
    header.set_token_type("JWT");
    header.set_jwk(public_key);

    let mut payload = jwt::JwtPayload::new();
    payload.set_claim("nonce", Some(json!(nonce)))?;

    let signer = ES256.signer_from_jwk(&private_key)?;
    let signed_jwt = jwt::encode_with_signer(&payload, &header, &signer)?;

    let verify_resp = client
        .post("http://127.0.0.1:8080/verify")
        .body(signed_jwt)
        .send()
        .await?;
    println!("Verification response: {}", verify_resp.status());
    Ok(())
}

#[actix_web::main]
async fn main() -> std::io::Result<()> {
    let state = web::Data::new(AppState {
        nonces: Mutex::new(HashSet::new()),
    });

    let server = HttpServer::new(move || {
        App::new()
            .app_data(state.clone())
            .route("/nonce", web::get().to(generate_nonce))
            .route("/verify", web::post().to(verify_attestation))
    })
    .bind("127.0.0.1:8080")?
    .run();

    let holder = tokio::spawn(async {
        if let Err(e) = prove_ownership().await {
            eprintln!("Holder script failed: {}", e);
        }
    });

    let (server_res, holder_res) = tokio::join!(server, holder);
    server_res?;
    holder_res.map_err(|e| std::io::Error::new(std::io::ErrorKind::Other, e.to_string()))?;
    Ok(())
}
