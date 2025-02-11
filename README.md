# Key Ownership Prover

This project demonstrates a simple web service in Rust that proves ownership of a private key using JSON Web Tokens (JWT) and JSON Web Keys (JWK). The solution is composed of two actors:

1. **Verifier Web Service:**  
   Provides two endpoints:
   - **GET /nonce:** Generates a one-time nonce and returns it as JSON.
   - **POST /verify:** Accepts a signed JWT, verifies its signature using the embedded public key (provided in the `"jwk"` field of the JWT header), and checks that the payload contains a valid nonce. The nonce is then removed (to prevent replay attacks).

2. **Holder (Client) Script:**  
   Acts as the entity that proves key ownership by:
   - Fetching a nonce from the verifier.
   - Generating an EC (P-256) key pair in JWK format.
   - Embedding its public key in the JWT header (in the `"jwk"` field).
   - Creating a JWT payload that includes the nonce.
   - Signing the JWT with ES256 using the private key.
   - Posting the signed JWT to the verifier.

The private key remains secret and is used only for signing. The public key (in JWK format) is embedded in the JWT header so the verifier can verify the signature.

## Prerequisites

- [Rust](https://www.rust-lang.org/tools/install) (latest stable version)
- Cargo (comes with Rust)
- OpenSSL (if required by the `josekit` crate on your system)
- (Optional) [curl](https://curl.se/) or [Postman](https://www.postman.com/) for manual endpoint testing

## Installation

1. **Clone the Repository:**

   ```sh
   git clone https://github.com/yourusername/key-ownership-prover.git
   cd key-ownership-prover

2. **Ensure Dependencies Are Set:**

Your Cargo.toml should include the following dependencies:
[dependencies]
actix-web = "4.0"
josekit = "0.10.1"
serde_json = "1.0"
uuid = { version = "1.0", features = ["v4", "serde"] }
serde = { version = "1.0", features = ["derive"] }
reqwest = { version = "0.12", features = ["json"] }
tokio = { version = "1.0", features = ["full"] }
anyhow = "1.0"
base64 = "0.13"

3. **Build the Project:**

    ```sh
    cargo build --release

4. **Running the Demo:**

    To run the complete demo (both the verifier and the holder):


    ```sh 
    cargo run

When you run the command, the Actix‑web server will start on http://127.0.0.1:8080 and the holder task will run concurrently. The holder task will:

GET a nonce from the verifier (/nonce).
Generate an EC key pair (P‑256) in JWK format.
Embed the public key in the JWT header under the "jwk" field.
Create a JWT payload that includes the nonce.
Sign the JWT using ES256 with the private key.
POST the signed JWT to /verify.
You should see an output similar to:

Verification response: ```200 OK```

This indicates that the JWT was successfully verified and that the nonce was valid and consumed.

## Manual Testing

**Testing the /nonce Endpoint**

1. **Open a terminal and run:**


    ```sh
    curl http://127.0.0.1:8080/nonce

2. **You should see a response like:**
    ```sh
    {"nonce": "329e8be2-1057-4bc3-b440-2a85a149f583"}

**Testing the /verify Endpoint Manually**
To manually test the ```/verify``` endpoint, you need to create a valid JWT. You can use jwt.io to do this, but note the following:

1. **Prepare the JWT Header:**

    Set the header to include:
    ```sh
        "alg": "ES256"

        "typ": "JWT"

    A custom "jwk" field containing your public key in JWK format. For example:
        {
          "alg": "ES256",
          "typ": "JWT",
          "jwk": {
            "kty": "EC",
            "crv": "P-256",
            "x": "YourBase64UrlEncodedX",
            "y": "YourBase64UrlEncodedY"
          }
        }
    
    Replace "YourBase64UrlEncodedX" and "YourBase64UrlEncodedY" with the values from your public key.


2. **Prepare the JWT Payload:**

The payload should include the nonce you obtained from the /nonce endpoint. For example:

    {
      "nonce": "329e8be2-1057-4bc3-b440-2a85a149f583"
    }

3. **Sign the JWT:**

In jwt.io’s ```"VERIFY SIGNATURE"``` section, paste your ```ES256 private key``` in PEM format (the key corresponding to your public key). Ensure that the signing algorithm is set to ES256. Generate the token.

4. **Test the /verify Endpoint:**

Copy the generated JWT and post it to the ```/verify``` endpoint:

    curl -X POST http://127.0.0.1:8080/verify -d "<your_generated_jwt>"

Replace ```<your_generated_jwt>``` with the JWT from jwt.io. If the JWT is valid, you should receive:

    {"status": "success"}

## Project Structure

```src/main.rs:``` Contains the complete implementation of both the verifier service and the holder functionality.

```Cargo.toml:``` Lists all dependencies.