# Custom JWT Core in Go

This project implements a JSON Web Token (JWT) authentication system **from scratch** using only the Go standard library.  
It is built for **learning purposes** to understand how JWT works internally.

## Features
- HS256 (HMAC-SHA256) signing
- Base64URL encoding
- Token expiration (`exp`)
- Custom JWT verification
- HTTP authentication middleware
- No third-party libraries

## Project Structure
jwt/
├── main.go
├
│ 
└── go.mod


## How JWT Works (Internally)
1. Header and payload are JSON encoded
2. Both are Base64URL encoded
3. Signature is generated using HMAC-SHA256
4. Token format: `header.payload.signature`
5. Expiry is validated on every request

## Run the Project
```bash
go run main.go
