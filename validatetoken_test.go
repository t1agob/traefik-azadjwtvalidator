package traefikazadjwtvalidator

import (
	"crypto/rand"
	"crypto/rsa"
	"crypto/x509"
	"encoding/pem"
	"fmt"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	// yaegi:tags safe
	jwt "github.com/golang-jwt/jwt/v4"
)

type JwtClaim struct {
	Roles []string
	jwt.RegisteredClaims
}

func TestValidToken(t *testing.T) {
	azureJwtPlugin := AzureJwtPlugin{
		config: &Config{
			Issuer:   "random-issuer",
			Audience: jwt.ClaimStrings{"admin"},
			Roles:    []string{"test_role_1"},
		},
	}

	expiresAt := time.Now().Add(time.Hour)
	var (
		extractedToken *AzureJwt
		err            error
	)

	validToken, publicKey := generateTestToken(t, expiresAt, azureJwtPlugin.config.Roles, azureJwtPlugin.config.Audience, azureJwtPlugin.config.Issuer)
	extractedToken, err = createRequestAndValidateToken(t, azureJwtPlugin, publicKey, validToken)

	if err != nil {
		t.Fatal(err)
	}

	if !SliceCompare(azureJwtPlugin.config.Roles, extractedToken.Payload.Roles) {
		t.Error("Roles do not match.")
	}

	if azureJwtPlugin.config.Issuer != extractedToken.Payload.Iss {
		t.Error("Issuer does not match.")
	}
}

func TestExpiredToken(t *testing.T) {
	azureJwtPlugin := AzureJwtPlugin{
		config: &Config{
			Issuer:   "random-issuer",
			Audience: jwt.ClaimStrings{"admin"},
			Roles:    []string{"test_role_1"},
		},
	}

	expiresAt := time.Now().Add(-time.Hour)
	invalidToken, publicKey := generateTestToken(t, expiresAt, azureJwtPlugin.config.Roles, azureJwtPlugin.config.Audience, azureJwtPlugin.config.Issuer)

	extractedToken, err := createRequestAndValidateToken(t, azureJwtPlugin, publicKey, invalidToken)
	if err != nil {
		if !strings.Contains(err.Error(), "token is expired") {
			t.Error("Token is still valid.")
		}
	}

	if !SliceCompare(azureJwtPlugin.config.Roles, extractedToken.Payload.Roles) {
		t.Error("Roles do not match.")
	}

	if azureJwtPlugin.config.Issuer != extractedToken.Payload.Iss {
		t.Error("Issuer does not match.")
	}
}

func TestWrongAudienceToken(t *testing.T) {
	azureJwtPlugin := AzureJwtPlugin{
		config: &Config{
			Issuer:   "random-issuer",
			Audience: jwt.ClaimStrings{"right-audience"},
			Roles:    []string{"test_role_1"},
		},
	}

	expiresAt := time.Now().Add(time.Hour)
	invalidToken, publicKey := generateTestToken(t, expiresAt, azureJwtPlugin.config.Roles, jwt.ClaimStrings{"wrong-audience"}, azureJwtPlugin.config.Issuer)

	extractedToken, err := createRequestAndValidateToken(t, azureJwtPlugin, publicKey, invalidToken)
	if err != nil {
		if err.Error() == "token audience is wrong" {
			t.Log("Successfully validated error message")
		} else {
			t.Error("Expecting wrong audience but instead got a right one.")
		}
	}

	if !SliceCompare(azureJwtPlugin.config.Roles, extractedToken.Payload.Roles) {
		t.Error("Roles do not match.")
	}

	if azureJwtPlugin.config.Issuer != extractedToken.Payload.Iss {
		t.Error("Issuer does not match.")
	}
}

func TestWrongAudienceInMultipleToken(t *testing.T) {
	azureJwtPlugin := AzureJwtPlugin{
		config: &Config{
			Issuer:   "random-issuer",
			Audience: jwt.ClaimStrings{"right-audience", "another-right-audience"},
			Roles:    []string{"test_role_1"},
		},
	}

	expiresAt := time.Now().Add(time.Hour)
	invalidToken, publicKey := generateTestToken(t, expiresAt, azureJwtPlugin.config.Roles, jwt.ClaimStrings{"wrong-audience"}, azureJwtPlugin.config.Issuer)

	extractedToken, err := createRequestAndValidateToken(t, azureJwtPlugin, publicKey, invalidToken)
	if err != nil {
		if err.Error() == "token audience is wrong" {
			t.Log("Successfully validated error message")
		} else {
			t.Error("Expecting wrong audience but instead got a right one.")
		}
	}
	if !SliceCompare(azureJwtPlugin.config.Roles, extractedToken.Payload.Roles) {
		t.Error("Roles do not match.")
	}

	if azureJwtPlugin.config.Issuer != extractedToken.Payload.Iss {
		t.Error("Issuer does not match.")
	}
}

func TestValidAudienceInMultipleToken(t *testing.T) {
	azureJwtPlugin := AzureJwtPlugin{
		config: &Config{
			Issuer:   "random-issuer",
			Audience: jwt.ClaimStrings{"right-audience", "another-right-audience"},
			Roles:    []string{"test_role_1"},
		},
	}

	expiresAt := time.Now().Add(time.Hour)
	invalidToken, publicKey := generateTestToken(t, expiresAt, azureJwtPlugin.config.Roles, jwt.ClaimStrings{"right-audience"}, azureJwtPlugin.config.Issuer)

	extractedToken, err := createRequestAndValidateToken(t, azureJwtPlugin, publicKey, invalidToken)
	if err != nil {
		t.Error("Token is not valid.")
	}

	if !SliceCompare(azureJwtPlugin.config.Roles, extractedToken.Payload.Roles) {
		t.Error("Roles do not match.")
	}

	if azureJwtPlugin.config.Issuer != extractedToken.Payload.Iss {
		t.Error("Issuer does not match.")
	}
}

func TestMissingRolesInToken(t *testing.T) {
	azureJwtPlugin := AzureJwtPlugin{
		config: &Config{
			Issuer:   "random-issuer",
			Audience: jwt.ClaimStrings{"tenant"},
			Roles:    []string{"test_role_1", "test_role_2"},
		},
	}

	expiresAt := time.Now().Add(time.Hour)
	validToken, publicKey := generateTestToken(t, expiresAt, []string{"test_role_2"}, azureJwtPlugin.config.Audience, azureJwtPlugin.config.Issuer)

	extractedToken, err := createRequestAndValidateToken(t, azureJwtPlugin, publicKey, validToken)
	if err != nil {
		t.Error("Token is not valid")
	}

	if azureJwtPlugin.config.Issuer != extractedToken.Payload.Iss {
		t.Error("Issuer does not match.")
	}
}

func TestOneRoleInToken(t *testing.T) {
	azureJwtPlugin := AzureJwtPlugin{
		config: &Config{
			Issuer:        "random-issuer",
			Audience:      jwt.ClaimStrings{"tenant"},
			Roles:         []string{"test_role_1", "test_role_2"},
			MatchAllRoles: true,
		},
	}

	expiresAt := time.Now().Add(time.Hour)
	validToken, publicKey := generateTestToken(t, expiresAt, []string{"test_role_2"}, azureJwtPlugin.config.Audience, azureJwtPlugin.config.Issuer)

	extractedToken, err := createRequestAndValidateToken(t, azureJwtPlugin, publicKey, validToken)

	if err.Error() == "missing correct role" {
		t.Log("Successfully confirm missing correct role")
	} else {
		t.Error("Failed to validate role")
	}

	if azureJwtPlugin.config.Issuer != extractedToken.Payload.Iss {
		t.Error("Issuer does not match.")
	}
}

func TestNoRolesInToken(t *testing.T) {
	azureJwtPlugin := AzureJwtPlugin{
		config: &Config{
			Issuer:   "random-issuer",
			Audience: jwt.ClaimStrings{"tenant"},
		},
	}

	expiresAt := time.Now().Add(time.Hour)
	validToken, publicKey := generateTestToken(t, expiresAt, nil, azureJwtPlugin.config.Audience, azureJwtPlugin.config.Issuer)

	extractedToken, err := createRequestAndValidateToken(t, azureJwtPlugin, publicKey, validToken)
	if err != nil {
		t.Error("Token is not valid")
	}

	if azureJwtPlugin.config.Issuer != extractedToken.Payload.Iss {
		t.Error("Issuer does not match.")
	}
}

func createRequestAndValidateToken(t *testing.T, azureJwtPlugin AzureJwtPlugin, publicKey *rsa.PublicKey, token string) (*AzureJwt, error) {
	t.Helper()

	azureJwtPlugin.GetPublicKeys(&Config{
		PublicKey: string(PublicKeyToBytes(publicKey)),
	})

	request := httptest.NewRequest(http.MethodGet, "/testtoken", nil)
	request.Header.Set("Authorization", "Bearer "+token)
	extractedToken, err := azureJwtPlugin.ExtractToken(request)
	if err != nil {
		t.Fatal(err)
	}

	err = azureJwtPlugin.ValidateToken(extractedToken)

	return extractedToken, err
}

func generateTestToken(t *testing.T, expiresAt time.Time, roles []string, audience jwt.ClaimStrings, issuer string) (string, *rsa.PublicKey) {
	t.Helper()

	privateKey, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		fmt.Println("Error generating key", err)
		panic(err)
	}

	testClaims := &JwtClaim{
		Roles: roles,
		RegisteredClaims: jwt.RegisteredClaims{
			Audience:  audience,
			Issuer:    issuer,
			ExpiresAt: jwt.NewNumericDate(expiresAt),
		},
	}

	token := jwt.NewWithClaims(jwt.SigningMethodRS256, testClaims)
	token.Header["kid"] = "config_rsa"

	signedString, errSignedString := token.SignedString(privateKey)

	if errSignedString != nil {
		panic(errSignedString)
	}

	return signedString, &privateKey.PublicKey
}

func PublicKeyToBytes(pub *rsa.PublicKey) []byte {
	pubASN1, err := x509.MarshalPKIXPublicKey(pub)
	if err != nil {
		panic(err)
	}

	pubBytes := pem.EncodeToMemory(&pem.Block{
		Type:  "RSA PUBLIC KEY",
		Bytes: pubASN1,
	})

	return pubBytes
}

func SliceCompare(a, b []string) bool {
	if len(a) != len(b) {
		return false
	}

	for i, v := range a {
		if v != b[i] {
			return false
		}
	}
	return true
}
