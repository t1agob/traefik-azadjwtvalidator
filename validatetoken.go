// Package traefikazadjwtvalidator is a Traefik middleware to validate Azure AD JWT Tokens.
package traefikazadjwtvalidator

import (
	"context"
	"crypto"
	"crypto/rsa"
	"crypto/sha256"
	"crypto/x509"
	"encoding/base64"
	"encoding/json"
	"encoding/pem"
	"errors"
	"fmt"
	"io"
	"log"
	"math/big"
	"net/http"
	"os"
	"strings"
	"time"

	"github.com/golang-jwt/jwt/v4"
)

var rsakeys map[string]*rsa.PublicKey

// Config the plugin configuration.
type Config struct {
	PublicKey     string
	KeysURL       string
	Issuer        string
	Audience      jwt.ClaimStrings
	Roles         []string
	MatchAllRoles bool
	LogLevel      string
}

// AzureJwtPlugin contains the configuration for the Traefik Plugin.
type AzureJwtPlugin struct {
	next   http.Handler
	config *Config
}

var (
	loggerINFO  = log.New(io.Discard, "INFO: azure-jwt-token-validator: ", log.Ldate|log.Ltime|log.Lshortfile)
	loggerDEBUG = log.New(io.Discard, "DEBUG: azure-jwt-token-validator: ", log.Ldate|log.Ltime|log.Lshortfile)
	loggerWARN  = log.New(io.Discard, "WARN: azure-jwt-token-validator: ", log.Ldate|log.Ltime|log.Lshortfile)
)

// CreateConfig creates the default plugin configuration.
func CreateConfig() *Config {
	return &Config{}
}

// New created a new Demo plugin.
func New(ctx context.Context, next http.Handler, config *Config, name string) (http.Handler, error) {
	loggerWARN.SetOutput(os.Stdout)

	switch config.LogLevel {
	case "INFO":
		loggerINFO.SetOutput(os.Stdout)
	case "DEBUG":
		loggerINFO.SetOutput(os.Stdout)
		loggerDEBUG.SetOutput(os.Stdout)
	}

	if len(config.Audience) == 0 {
		return nil, fmt.Errorf("configuration incorrect, missing audience")
	}

	if strings.TrimSpace(config.Issuer) == "" {
		return nil, fmt.Errorf("configuration incorrect, missing issuer")
	}

	if strings.TrimSpace(config.KeysURL) == "" && strings.TrimSpace(config.PublicKey) == "" {
		return nil, fmt.Errorf("configuration incorrect, missing either a JWKS url or a static public key")
	}

	plugin := &AzureJwtPlugin{
		next:   next,
		config: config,
	}

	go plugin.scheduleUpdateKeys(config)

	return plugin, nil
}

func (azureJwt *AzureJwtPlugin) ServeHTTP(rw http.ResponseWriter, req *http.Request) {
	tokenValid := false

	token, err := azureJwt.ExtractToken(req)

	if err == nil {
		valerr := azureJwt.ValidateToken(token)
		if valerr == nil {
			loggerDEBUG.Println("Accepted request")
			tokenValid = true
		} else {
			loggerDEBUG.Println(valerr)
		}
	} else {
		loggerDEBUG.Println(err)
	}

	if tokenValid {
		azureJwt.next.ServeHTTP(rw, req)
	} else {
		http.Error(rw, "Not allowed", http.StatusForbidden)
	}
}

func (azureJwt *AzureJwtPlugin) scheduleUpdateKeys(config *Config) {
	for {
		azureJwt.GetPublicKeys(config)
		time.Sleep(15 * time.Minute)
	}
}

// GetPublicKeys .
func (azureJwt *AzureJwtPlugin) GetPublicKeys(config *Config) {
	err := verifyAndSetPublicKey(config.PublicKey)
	if err != nil {
		loggerWARN.Println("failed to load public key. ", err)
	}

	if strings.TrimSpace(config.KeysURL) != "" {
		var body map[string]interface{}
		resp, err := http.Get(config.KeysURL)
		if err != nil {
			loggerWARN.Println("failed to load public key from:", config.KeysURL)
		} else {
			err = json.NewDecoder(resp.Body).Decode(&body)
			if err != nil {
				loggerWARN.Println("failed ot decode body:", resp.Body)
			}

			for _, bodykey := range body["keys"].([]interface{}) {
				key := bodykey.(map[string]interface{})

				kid := key["kid"].(string)
				e := key["e"].(string)
				rsakey := new(rsa.PublicKey)
				number, _ := base64.RawURLEncoding.DecodeString(key["n"].(string))
				rsakey.N = new(big.Int).SetBytes(number)

				b, err := base64.RawURLEncoding.DecodeString(e)
				if err != nil {
					log.Fatalf("Error parsing key E: %v", err)
				}

				rsakey.E = int(new(big.Int).SetBytes(b).Uint64())
				rsakeys[kid] = rsakey
			}
		}
	}
}

func verifyAndSetPublicKey(publicKey string) error {
	rsakeys = make(map[string]*rsa.PublicKey)

	if strings.TrimSpace(publicKey) != "" {
		pubPem, _ := pem.Decode([]byte(publicKey))
		if pubPem == nil {
			return fmt.Errorf("public key could not be decoded")
		}
		if pubPem.Type != "RSA PUBLIC KEY" {
			return fmt.Errorf("public key format invalid")
		}

		parsedKey, err := x509.ParsePKIXPublicKey(pubPem.Bytes)
		if err != nil {
			return fmt.Errorf("unable to parse RSA public key")
		}

		var (
			pubKey *rsa.PublicKey
			ok     bool
		)

		if pubKey, ok = parsedKey.(*rsa.PublicKey); !ok {
			return fmt.Errorf("unable to convert RSA public key")
		}

		rsakeys["config_rsa"] = pubKey
	}

	return nil
}

// ExtractToken .
func (azureJwt *AzureJwtPlugin) ExtractToken(request *http.Request) (*AzureJwt, error) {
	authHeader, ok := request.Header["Authorization"]
	if !ok {
		fmt.Println("No header token")
		return nil, errors.New("no token")
	}
	auth := authHeader[0]
	if !strings.HasPrefix(auth, "Bearer ") {
		fmt.Println("No bearer token")
		return nil, errors.New("no token")
	}
	parts := strings.Split(auth[7:], ".")
	if len(parts) != 3 {
		fmt.Println("invalid token format")
		return nil, errors.New("no token")
	}

	header, err := base64.RawURLEncoding.DecodeString(parts[0])
	if err != nil {
		fmt.Printf("Header: %+v", err)
		return nil, errors.New("invalid token")
	}
	payload, err := base64.RawURLEncoding.DecodeString(parts[1])
	if err != nil {
		fmt.Printf("Payload: %+v", err)
		return nil, errors.New("invalid token")
	}
	signature, err := base64.RawURLEncoding.DecodeString(parts[2])
	if err != nil {
		fmt.Printf("Signature: %+v", err)
		return nil, errors.New("invalid token")
	}
	jwtToken := AzureJwt{
		RawToken:   []byte(auth[7 : len(parts[0])+len(parts[1])+8]),
		Signature:  signature,
		RawPayload: payload,
	}
	err = json.Unmarshal(header, &jwtToken.Header)
	if err != nil {
		fmt.Printf("JSON HEADER: %+v", err)
		return nil, errors.New("invalid token")
	}
	err = json.Unmarshal(payload, &jwtToken.Payload)
	if err != nil {
		fmt.Printf("JSON PAYLOAD: %+v", err)
		return nil, errors.New("invalid token")
	}
	return &jwtToken, nil
}

// ValidateToken checks if Json Web Token passed as parameter is valid.
func (azureJwt *AzureJwtPlugin) ValidateToken(token *AzureJwt) error {
	hash := sha256.Sum256(token.RawToken)

	err := rsa.VerifyPKCS1v15(rsakeys[token.Header.Kid], crypto.SHA256, hash[:], token.Signature)
	if err != nil {
		return err
	}

	if err := azureJwt.VerifyToken(token); err != nil {
		return err
	}

	var claims Claims
	if err := json.Unmarshal(token.RawPayload, &claims); err != nil {
		return err
	}

	return nil
}

// VerifyToken verifies the Json Web Token passed as parameter.
func (azureJwt *AzureJwtPlugin) VerifyToken(jwtToken *AzureJwt) error {
	tokenExpiration, err := jwtToken.Payload.Exp.Int64()
	if err != nil {
		return err
	}

	if tokenExpiration < time.Now().Unix() {
		loggerDEBUG.Println("Token has expired", time.Unix(tokenExpiration, 0))
		return errors.New("token is expired")
	}

	err = azureJwt.validateClaims(&jwtToken.Payload)
	if err != nil {
		return err
	}

	return nil
}

func (azureJwt *AzureJwtPlugin) validateClaims(parsedClaims *Claims) error {
	validAudience := validateAudience(azureJwt.config.Audience, parsedClaims)
	if !validAudience {
		return errors.New("token audience is wrong")
	}

	if parsedClaims.Iss != azureJwt.config.Issuer {
		return errors.New("wrong issuer")
	}

	if parsedClaims.Roles != nil {
		if len(azureJwt.config.Roles) > 0 {
			var allRolesValid = true

			if !azureJwt.config.MatchAllRoles {
				allRolesValid = false
			}

			for _, role := range azureJwt.config.Roles {
				roleValid := parsedClaims.isValidForRole(role)
				if azureJwt.config.MatchAllRoles && !roleValid {
					allRolesValid = false
					break
				}
				if !azureJwt.config.MatchAllRoles && roleValid {
					allRolesValid = true
					break
				}
			}

			if !allRolesValid {
				loggerDEBUG.Println("missing correct role, found: " + strings.Join(parsedClaims.Roles, ",") + ", expected: " + strings.Join(azureJwt.config.Roles, ","))
				return errors.New("missing correct role")
			}
		}
	} else if len(azureJwt.config.Roles) > 0 {
		return errors.New("missing correct role")
	}

	return nil
}

func (claims *Claims) isValidForAudience(configAud string) bool {
	for _, parsedAud := range claims.Aud {
		if parsedAud == configAud {
			loggerDEBUG.Println("Match:", parsedAud, configAud)
			return true
		}

		loggerDEBUG.Println("No match:", parsedAud, configAud)
	}

	return false
}

func (claims *Claims) isValidForRole(configRole string) bool {
	for _, parsedRole := range claims.Roles {
		if parsedRole == configRole {
			loggerDEBUG.Println("Match:", parsedRole, configRole)
			return true
		}

		loggerDEBUG.Println("No match:", parsedRole, configRole)
	}

	return false
}

func validateAudience(configAud jwt.ClaimStrings, claims *Claims) bool {
	if claims.Aud != nil {
		if len(configAud) > 0 {
			validAudClaims := false

			for _, aud := range configAud {
				audValid := claims.isValidForAudience(aud)
				if audValid {
					loggerDEBUG.Println("JWT audience valid")
					validAudClaims = true

					break
				}
			}

			if !validAudClaims {
				return false
			}
		}
	}
	return true
}
