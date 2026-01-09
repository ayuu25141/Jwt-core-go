// package main

// import (
// 	"crypto/hmac"
// 	"crypto/sha256"
// 	"encoding/base64"
// 	"encoding/json"
// 	"fmt"
// "time"

// 	"net/http"
// 	"strings"
// )
// func Loginhandler(w http.ResponseWriter, r *http.Request) {
//     secretkey := []byte("ayush")
//     userID := int64(123)
//     exp := time.Now().Add(time.Hour * 24).Unix()

//     token, err := Createjwttoken(secretkey, userID, exp)
//     if err != nil {
//         http.Error(w, "Error creating token", http.StatusInternalServerError)
//         return
//     }

//     // Set JWT as an HTTP-only cookie
//     http.SetCookie(w, &http.Cookie{
//         Name:     "jwtToken",
//         Value:    token,
//         Expires:  time.Now().Add(24 * time.Hour),
//         HttpOnly: true,
//         Secure:   false, // Set to true in production (requires HTTPS)
//         SameSite: http.SameSiteLaxMode,
//         Path:     "/",   // Cookie is valid for all paths
//     })

//     fmt.Fprint(w, "Logged in! Cookie set. You can now access protected routes.")
// }

// func protectedHandler(w http.ResponseWriter, r *http.Request) {
//     // Extract JWT from Authorization header
//     authHeader := r.Header.Get("Authorization")
//     if authHeader == "" {
//         http.Error(w, "Missing token", http.StatusUnauthorized)
//         return
//     }

//     tokenString := strings.TrimPrefix(authHeader, "Bearer ")
//     if tokenString == authHeader {
//         http.Error(w, "Invalid token format", http.StatusUnauthorized)
//         return
//     }

//     // Validate JWT
//     secretKey := []byte("ayush")
//     payload, err := Decodejwt(tokenString, secretKey)
//     if err != nil {
//         http.Error(w, "Invalid token", http.StatusUnauthorized)
//         return
//     }

//     // Check expiration
//     if payload.Expiretime < time.Now().Unix() {
//         http.Error(w, "Token expired", http.StatusUnauthorized)
//         return
//     }

//     // Token is valid; proceed
//     fmt.Fprintf(w, "Welcome back, user %d! You are authenticated.", payload.Userid)
// }

// func main()  {
// http.HandleFunc("/",func(w http.ResponseWriter, r *http.Request) {
// 	fmt.Fprintf(w,"hello backend")
// })	
// http.HandleFunc("/login",Loginhandler)
// http.HandleFunc("/protected",protectedHandler)


// http.ListenAndServe(":8080",nil)



// }
// func base64Encoded(data []byte)  string {
// 	return strings.TrimRight(base64.URLEncoding.EncodeToString(data),"=")
// }
// func base64Decoded(encodestring string) ([]byte , error) {
//   return base64.URLEncoding.DecodeString(
//         encodestring + strings.Repeat("=", (4-len(encodestring)%4)%4),
//     )}

// type Headerofjwt struct{
// 	Alg string `json:"alg"`
// 	Typ string `json:"jwt"`
// }	
// type Payloadofjwt struct{
// Userid int64 `json:"user_id"`
// Expiretime int64 `json:"exp"`
// }
// func Createjwttoken(secretkey []byte,userid int64,exp int64) (string,error) {
// 	// marshaling the sttruct in json format	===> Header
// 	header := Headerofjwt{Alg: "HS256",Typ: "JWT"}
// 	// Base64 encoding only need ray binary byte so need of change in bytes 
// 	headerbyteformat,_ := json.Marshal(header)
// 	// now need to encode func to use that Format
// 	headerencodedformat := base64Encoded(headerbyteformat)

// // marhsaling the struct in json format ===> payload
// payload := Payloadofjwt{Userid: userid,Expiretime: exp}
// // base 64 encode need ray byte data not struct to byte format
// payloadbyteformat,_ := json.Marshal(payload)
// // now encode func run t that format
// payloadencodeformat := base64Encoded(payloadbyteformat)

// // signature
// signaturedata := []byte(headerencodedformat + "." + payloadencodeformat)
// Hashing := hmac.New(sha256.New,secretkey)
// Hashing.Write(signaturedata)
// sign := base64Encoded(Hashing.Sum(nil))


// // now combine that sign with jwt 
// return  fmt.Sprintf("%s.%s.%s",headerencodedformat,payloadencodeformat,sign),nil


// }

// func Decodejwt(tokenstring string , secretkey []byte) (Payloadofjwt,error) {
// 	// check token length of validation
// 	parts := strings.Split(tokenstring,".")
// 	if len(parts) != 3 {
// 		fmt.Println("TOken validation fails  invalid token format")
// 	}
// // now parts accordin to data of that format
//   headerEncoded, payloadEncoded, signatureEncoded := parts[0], parts[1], parts[2]

// // verify signatire
// data := []byte(headerEncoded+"."+payloadEncoded)
// Hashing := hmac.New(sha256.New,secretkey)
// Hashing.Write(data)
// expectedsignature := base64Encoded(Hashing.Sum(nil))

//   if !hmac.Equal([]byte(signatureEncoded), []byte(expectedsignature)) {
//         return Payloadofjwt{}, fmt.Errorf("invalid signature")
//     }
// // decode payload
// payloadbyte	,err := base64Decoded(payloadEncoded)
// if err != nil {
// 	return  Payloadofjwt{},err
// }
// var payload Payloadofjwt
// err = json.Unmarshal(payloadbyte, &payload)
//     if err != nil {
//         return Payloadofjwt{}, err
//     }

//     return payload, nil
// }

package main

import (
	"crypto/hmac"
	"crypto/sha256"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"log"
	"net/http"
	"strings"
	"time"
)

func base64Encoded(data []byte) string {
	return strings.TrimRight(base64.URLEncoding.EncodeToString(data), "=")
}

func base64Decoded(encodedString string) ([]byte, error) {
	return base64.URLEncoding.DecodeString(
		encodedString + strings.Repeat("=", (4-len(encodedString)%4)%4),
	)
}

type Headerofjwt struct {
	Alg string `json:"alg"`
	Typ string `json:"typ"` // Fixed typo: "jwt" → "typ"
}

type Payloadofjwt struct {
	Userid     int64 `json:"user_id"`
	Expiretime int64 `json:"exp"`
}

func Createjwttoken(secretkey []byte, userid int64, exp int64) (string, error) {
	header := Headerofjwt{Alg: "HS256", Typ: "JWT"}
	headerbyteformat, _ := json.Marshal(header)
	headerencodedformat := base64Encoded(headerbyteformat)

	payload := Payloadofjwt{Userid: userid, Expiretime: exp}
	payloadbyteformat, _ := json.Marshal(payload)
	payloadencodeformat := base64Encoded(payloadbyteformat)

	signaturedata := []byte(headerencodedformat + "." + payloadencodeformat)
	Hashing := hmac.New(sha256.New, secretkey)
	Hashing.Write(signaturedata)
	sign := base64Encoded(Hashing.Sum(nil))

	return fmt.Sprintf("%s.%s.%s", headerencodedformat, payloadencodeformat, sign), nil
}

func Decodejwt(tokenstring string, secretkey []byte) (Payloadofjwt, error) {
	parts := strings.Split(tokenstring, ".")
	if len(parts) != 3 {
		return Payloadofjwt{}, fmt.Errorf("invalid token format")
	}

	headerEncoded, payloadEncoded, signatureEncoded := parts[0], parts[1], parts[2]

	data := []byte(headerEncoded + "." + payloadEncoded)
	Hashing := hmac.New(sha256.New, secretkey)
	Hashing.Write(data)
	expectedsignature := base64Encoded(Hashing.Sum(nil))

	if !hmac.Equal([]byte(signatureEncoded), []byte(expectedsignature)) {
		return Payloadofjwt{}, fmt.Errorf("invalid signature")
	}

	payloadbyte, err := base64Decoded(payloadEncoded)
	if err != nil {
		return Payloadofjwt{}, err
	}

	var payload Payloadofjwt
	err = json.Unmarshal(payloadbyte, &payload)
	if err != nil {
		return Payloadofjwt{}, err
	}

	return payload, nil
}

func Loginhandler(w http.ResponseWriter, r *http.Request) {
	secretkey := []byte("ayush")
	userID := int64(123)
	exp := time.Now().Add(time.Hour * 24).Unix()

	token, err := Createjwttoken(secretkey, userID, exp)
	if err != nil {
		http.Error(w, "Error creating token", http.StatusInternalServerError)
		return
	}

	// Set JWT as an HTTP-only cookie
	http.SetCookie(w, &http.Cookie{
		Name:     "jwtToken",
		Value:    token,
		Expires:  time.Now().Add(24 * time.Hour),
		HttpOnly: true,
		Secure:   false, // Set to true in production
		SameSite: http.SameSiteLaxMode,
		Path:     "/",
	})

	fmt.Fprint(w, "Logged in! Cookie set. You can now access protected routes.")
}

func protectedHandler(w http.ResponseWriter, r *http.Request) {
	cookie, err := r.Cookie("jwtToken")
	if err != nil {
		http.Error(w, "Missing token. Please log in.", http.StatusUnauthorized)
		return
	}

	secretKey := []byte("ayush")
	payload, err := Decodejwt(cookie.Value, secretKey)
	if err != nil {
		http.Error(w, "Invalid token. Please log in again.", http.StatusUnauthorized)
		return
	}

	if payload.Expiretime < time.Now().Unix() {
		http.Error(w, "Token expired. Please log in again.", http.StatusUnauthorized)
		return
	}

	fmt.Fprintf(w, "Welcome back, user %d! You are authenticated.", payload.Userid)
}

func main() {
	http.HandleFunc("/", func(w http.ResponseWriter, r *http.Request) {
		fmt.Fprintf(w, "Hello backend")
	})
	http.HandleFunc("/login", Loginhandler)
	http.HandleFunc("/protected", protectedHandler)

	log.Println("Server running on http://localhost:8080")
	log.Fatal(http.ListenAndServe(":8080", nil))
}
