// Copyright (c) Microsoft Corporation.
// Licensed under the MIT license.

package accesstokens

import (
	"encoding/base64"
	"encoding/json"
	"testing"
	"time"
)

func TestIDTokenUnmarshalNonce(t *testing.T) {
	tests := []struct {
		name        string
		nonce       string
		payload     string
		expectError bool
		expected    IDToken
	}{
		{
			name:  "Success: Nonce with valid JWT",
			nonce: "test-nonce-123",
			payload: `{
				"preferred_username": "user@example.com",
				"given_name": "John",
				"family_name": "Doe",
				"name": "John Doe",
				"nonce": "test-nonce-123",
				"oid": "12345678-1234-1234-1234-123456789012",
				"tid": "tenant-id-123",
				"sub": "subject-123",
				"upn": "user@example.com",
				"email": "user@example.com",
				"iss": "https://login.microsoftonline.com/tenant-id-123/v2.0",
				"aud": "client-id-123",
				"exp": 1735689600,
				"iat": 1735686000,
				"nbf": 1735686000
			}`,
			expectError: false,
			expected: IDToken{
				PreferredUsername: "user@example.com",
				GivenName:         "John",
				FamilyName:        "Doe",
				MiddleName:        "",
				Name:              "John Doe",
				Nonce:             "test-nonce-123",
				Oid:               "12345678-1234-1234-1234-123456789012",
				TenantID:          "tenant-id-123",
				Subject:           "subject-123",
				UPN:               "user@example.com",
				Email:             "user@example.com",
				AlternativeID:     "",
				Issuer:            "https://login.microsoftonline.com/tenant-id-123/v2.0",
				Audience:          "client-id-123",
				ExpirationTime:    1735689600,
				IssuedAt:          1735686000,
				NotBefore:         1735686000,
				RawToken:          "",
				AdditionalFields:  nil,
			},
		},
		{
			name:  "Success: Nonce with empty string",
			nonce: "",
			payload: `{
				"preferred_username": "user@example.com",
				"name": "John Doe",
				"nonce": "",
				"oid": "12345678-1234-1234-1234-123456789012",
				"tid": "tenant-id-123",
				"sub": "subject-123",
				"iss": "https://login.microsoftonline.com/tenant-id-123/v2.0",
				"aud": "client-id-123",
				"exp": 1735689600,
				"iat": 1735686000,
				"nbf": 1735686000
			}`,
			expectError: false,
			expected: IDToken{
				PreferredUsername: "user@example.com",
				GivenName:         "",
				FamilyName:        "",
				MiddleName:        "",
				Name:              "John Doe",
				Nonce:             "",
				Oid:               "12345678-1234-1234-1234-123456789012",
				TenantID:          "tenant-id-123",
				Subject:           "subject-123",
				UPN:               "",
				Email:             "",
				AlternativeID:     "",
				Issuer:            "https://login.microsoftonline.com/tenant-id-123/v2.0",
				Audience:          "client-id-123",
				ExpirationTime:    1735689600,
				IssuedAt:          1735686000,
				NotBefore:         1735686000,
				RawToken:          "",
				AdditionalFields:  nil,
			},
		},
		{
			name:  "Success: Nonce with special characters",
			nonce: "nonce-with-special-chars!@#$%^&*()",
			payload: `{
				"preferred_username": "user@example.com",
				"name": "John Doe",
				"nonce": "nonce-with-special-chars!@#$%^&*()",
				"oid": "12345678-1234-1234-1234-123456789012",
				"tid": "tenant-id-123",
				"sub": "subject-123",
				"iss": "https://login.microsoftonline.com/tenant-id-123/v2.0",
				"aud": "client-id-123",
				"exp": 1735689600,
				"iat": 1735686000,
				"nbf": 1735686000
			}`,
			expectError: false,
			expected: IDToken{
				PreferredUsername: "user@example.com",
				GivenName:         "",
				FamilyName:        "",
				MiddleName:        "",
				Name:              "John Doe",
				Nonce:             "nonce-with-special-chars!@#$%^&*()",
				Oid:               "12345678-1234-1234-1234-123456789012",
				TenantID:          "tenant-id-123",
				Subject:           "subject-123",
				UPN:               "",
				Email:             "",
				AlternativeID:     "",
				Issuer:            "https://login.microsoftonline.com/tenant-id-123/v2.0",
				Audience:          "client-id-123",
				ExpirationTime:    1735689600,
				IssuedAt:          1735686000,
				NotBefore:         1735686000,
				RawToken:          "",
				AdditionalFields:  nil,
			},
		},
		{
			name:  "Success: Nonce with unicode characters",
			nonce: "nonce-unicode-测试-🎉",
			payload: `{
				"preferred_username": "user@example.com",
				"name": "John Doe",
				"nonce": "nonce-unicode-测试-🎉",
				"oid": "12345678-1234-1234-1234-123456789012",
				"tid": "tenant-id-123",
				"sub": "subject-123",
				"iss": "https://login.microsoftonline.com/tenant-id-123/v2.0",
				"aud": "client-id-123",
				"exp": 1735689600,
				"iat": 1735686000,
				"nbf": 1735686000
			}`,
			expectError: false,
			expected: IDToken{
				PreferredUsername: "user@example.com",
				GivenName:         "",
				FamilyName:        "",
				MiddleName:        "",
				Name:              "John Doe",
				Nonce:             "nonce-unicode-测试-🎉",
				Oid:               "12345678-1234-1234-1234-123456789012",
				TenantID:          "tenant-id-123",
				Subject:           "subject-123",
				UPN:               "",
				Email:             "",
				AlternativeID:     "",
				Issuer:            "https://login.microsoftonline.com/tenant-id-123/v2.0",
				Audience:          "client-id-123",
				ExpirationTime:    1735689600,
				IssuedAt:          1735686000,
				NotBefore:         1735686000,
				RawToken:          "",
				AdditionalFields:  nil,
			},
		},
		{
			name:  "Success: Nonce with very long string",
			nonce: "very-long-nonce-string-that-exceeds-normal-length-expectations-and-tests-the-boundaries-of-what-might-be-considered-a-valid-nonce-value-in-real-world-scenarios",
			payload: `{
				"preferred_username": "user@example.com",
				"name": "John Doe",
				"nonce": "very-long-nonce-string-that-exceeds-normal-length-expectations-and-tests-the-boundaries-of-what-might-be-considered-a-valid-nonce-value-in-real-world-scenarios",
				"oid": "12345678-1234-1234-1234-123456789012",
				"tid": "tenant-id-123",
				"sub": "subject-123",
				"iss": "https://login.microsoftonline.com/tenant-id-123/v2.0",
				"aud": "client-id-123",
				"exp": 1735689600,
				"iat": 1735686000,
				"nbf": 1735686000
			}`,
			expectError: false,
			expected: IDToken{
				PreferredUsername: "user@example.com",
				GivenName:         "",
				FamilyName:        "",
				MiddleName:        "",
				Name:              "John Doe",
				Nonce:             "very-long-nonce-string-that-exceeds-normal-length-expectations-and-tests-the-boundaries-of-what-might-be-considered-a-valid-nonce-value-in-real-world-scenarios",
				Oid:               "12345678-1234-1234-1234-123456789012",
				TenantID:          "tenant-id-123",
				Subject:           "subject-123",
				UPN:               "",
				Email:             "",
				AlternativeID:     "",
				Issuer:            "https://login.microsoftonline.com/tenant-id-123/v2.0",
				Audience:          "client-id-123",
				ExpirationTime:    1735689600,
				IssuedAt:          1735686000,
				NotBefore:         1735686000,
				RawToken:          "",
				AdditionalFields:  nil,
			},
		},
		{
			name:  "Success: Nonce missing from payload (should be empty string)",
			nonce: "",
			payload: `{
				"preferred_username": "user@example.com",
				"name": "John Doe",
				"oid": "12345678-1234-1234-1234-123456789012",
				"tid": "tenant-id-123",
				"sub": "subject-123",
				"iss": "https://login.microsoftonline.com/tenant-id-123/v2.0",
				"aud": "client-id-123",
				"exp": 1735689600,
				"iat": 1735686000,
				"nbf": 1735686000
			}`,
			expectError: false,
			expected: IDToken{
				PreferredUsername: "user@example.com",
				GivenName:         "",
				FamilyName:        "",
				MiddleName:        "",
				Name:              "John Doe",
				Nonce:             "",
				Oid:               "12345678-1234-1234-1234-123456789012",
				TenantID:          "tenant-id-123",
				Subject:           "subject-123",
				UPN:               "",
				Email:             "",
				AlternativeID:     "",
				Issuer:            "https://login.microsoftonline.com/tenant-id-123/v2.0",
				Audience:          "client-id-123",
				ExpirationTime:    1735689600,
				IssuedAt:          1735686000,
				NotBefore:         1735686000,
				RawToken:          "",
				AdditionalFields:  nil,
			},
		},
		{
			name:  "Success: Nonce with null value in JSON",
			nonce: "",
			payload: `{
				"preferred_username": "user@example.com",
				"name": "John Doe",
				"nonce": null,
				"oid": "12345678-1234-1234-1234-123456789012",
				"tid": "tenant-id-123",
				"sub": "subject-123",
				"iss": "https://login.microsoftonline.com/tenant-id-123/v2.0",
				"aud": "client-id-123",
				"exp": 1735689600,
				"iat": 1735686000,
				"nbf": 1735686000
			}`,
			expectError: false,
			expected: IDToken{
				PreferredUsername: "user@example.com",
				GivenName:         "",
				FamilyName:        "",
				MiddleName:        "",
				Name:              "John Doe",
				Nonce:             "",
				Oid:               "12345678-1234-1234-1234-123456789012",
				TenantID:          "tenant-id-123",
				Subject:           "subject-123",
				UPN:               "",
				Email:             "",
				AlternativeID:     "",
				Issuer:            "https://login.microsoftonline.com/tenant-id-123/v2.0",
				Audience:          "client-id-123",
				ExpirationTime:    1735689600,
				IssuedAt:          1735686000,
				NotBefore:         1735686000,
				RawToken:          "",
				AdditionalFields:  nil,
			},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			// Create a JWT with the payload
			encodedPayload := base64.RawURLEncoding.EncodeToString([]byte(tt.payload))
			jwt := "header." + encodedPayload + ".signature"

			// Test unmarshalling
			var idToken IDToken
			err := idToken.UnmarshalJSON([]byte(`"` + jwt + `"`))

			if tt.expectError {
				if err == nil {
					t.Errorf("Expected error but got none")
				}
				return
			}

			if err != nil {
				t.Errorf("Unexpected error: %v", err)
				return
			}

			// Verify the nonce field specifically
			if idToken.Nonce != tt.expected.Nonce {
				t.Errorf("Nonce field mismatch: got %q, want %q", idToken.Nonce, tt.expected.Nonce)
			}

			// Verify other critical fields
			if idToken.PreferredUsername != tt.expected.PreferredUsername {
				t.Errorf("PreferredUsername field mismatch: got %q, want %q", idToken.PreferredUsername, tt.expected.PreferredUsername)
			}

			if idToken.Name != tt.expected.Name {
				t.Errorf("Name field mismatch: got %q, want %q", idToken.Name, tt.expected.Name)
			}

			if idToken.Oid != tt.expected.Oid {
				t.Errorf("Oid field mismatch: got %q, want %q", idToken.Oid, tt.expected.Oid)
			}

			if idToken.TenantID != tt.expected.TenantID {
				t.Errorf("TenantID field mismatch: got %q, want %q", idToken.TenantID, tt.expected.TenantID)
			}

			if idToken.Subject != tt.expected.Subject {
				t.Errorf("Subject field mismatch: got %q, want %q", idToken.Subject, tt.expected.Subject)
			}

			if idToken.Issuer != tt.expected.Issuer {
				t.Errorf("Issuer field mismatch: got %q, want %q", idToken.Issuer, tt.expected.Issuer)
			}

			if idToken.Audience != tt.expected.Audience {
				t.Errorf("Audience field mismatch: got %q, want %q", idToken.Audience, tt.expected.Audience)
			}

			// Verify RawToken is set
			if idToken.RawToken != jwt {
				t.Errorf("RawToken field mismatch: got %q, want %q", idToken.RawToken, jwt)
			}
		})
	}
}

func TestIDTokenUnmarshalNonceWithInvalidJWT(t *testing.T) {
	tests := []struct {
		name        string
		jwt         string
		expectError bool
	}{
		{
			name:        "Error: Invalid JWT format - missing parts",
			jwt:         "invalid.jwt",
			expectError: true,
		},
		{
			name:        "Error: Invalid JWT format - too many parts",
			jwt:         "header.payload.signature.extra",
			expectError: true,
		},
		{
			name:        "Error: Invalid JWT format - empty string",
			jwt:         "",
			expectError: true,
		},
		{
			name:        "Error: Invalid JWT format - null",
			jwt:         "null",
			expectError: false, // null is handled gracefully
		},
		{
			name:        "Error: Invalid base64 in payload",
			jwt:         "header.invalid-base64.signature",
			expectError: true,
		},
		{
			name:        "Error: Invalid JSON in payload",
			jwt:         "header." + base64.RawURLEncoding.EncodeToString([]byte(`{"invalid": json}`)) + ".signature",
			expectError: true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			var idToken IDToken
			var input []byte

			if tt.jwt == "null" {
				input = []byte("null")
			} else {
				input = []byte(`"` + tt.jwt + `"`)
			}

			err := idToken.UnmarshalJSON(input)

			if tt.expectError {
				if err == nil {
					t.Errorf("Expected error but got none")
				}
			} else {
				if err != nil {
					t.Errorf("Unexpected error: %v", err)
				}
			}
		})
	}
}

func TestIDTokenUnmarshalNonceInTokenResponse(t *testing.T) {
	// Test nonce unmarshalling in the context of a full TokenResponse
	tests := []struct {
		name        string
		nonce       string
		expectError bool
	}{
		{
			name:        "Success: Nonce in TokenResponse",
			nonce:       "auth-code-nonce-123",
			expectError: false,
		},
		{
			name:        "Success: Empty nonce in TokenResponse",
			nonce:       "",
			expectError: false,
		},
		{
			name:        "Success: Nonce with special characters in TokenResponse",
			nonce:       "nonce-special-!@#$%^&*()",
			expectError: false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			// Create a JWT payload with the nonce
			payload := map[string]interface{}{
				"preferred_username": "user@example.com",
				"name":              "John Doe",
				"nonce":             tt.nonce,
				"oid":               "12345678-1234-1234-1234-123456789012",
				"tid":               "tenant-id-123",
				"sub":               "subject-123",
				"iss":               "https://login.microsoftonline.com/tenant-id-123/v2.0",
				"aud":               "client-id-123",
				"exp":               time.Now().Add(time.Hour).Unix(),
				"iat":               time.Now().Unix(),
				"nbf":               time.Now().Unix(),
			}

			payloadBytes, err := json.Marshal(payload)
			if err != nil {
				t.Fatalf("Failed to marshal payload: %v", err)
			}

			encodedPayload := base64.RawURLEncoding.EncodeToString(payloadBytes)
			jwt := "header." + encodedPayload + ".signature"

			// Create a TokenResponse JSON with the ID token
			// Use the same pattern as existing tests with fake JWT decoder
			tokenResponseJSON := `{
				"access_token": "access-token-123",
				"token_type": "Bearer",
				"expires_in": 3600,
				"id_token": "` + jwt + `",
				"client_info": {"uid": "1234567890", "utid": "tenant-id-123"}
			}`

			// Temporarily replace the JWT decoder with the fake one
			originalJWTDecoder := jwtDecoder
			jwtDecoder = jwtDecoderFake
			defer func() { jwtDecoder = originalJWTDecoder }()

			var tokenResponse TokenResponse
			err = json.Unmarshal([]byte(tokenResponseJSON), &tokenResponse)

			if tt.expectError {
				if err == nil {
					t.Errorf("Expected error but got none")
				}
				return
			}

			if err != nil {
				t.Errorf("Unexpected error: %v", err)
				return
			}

			// Verify the nonce field in the ID token
			if tokenResponse.IDToken.Nonce != tt.nonce {
				t.Errorf("Nonce field mismatch: got %q, want %q", tokenResponse.IDToken.Nonce, tt.nonce)
			}

			// Verify other fields are properly set
			if tokenResponse.AccessToken != "access-token-123" {
				t.Errorf("AccessToken field mismatch: got %q, want %q", tokenResponse.AccessToken, "access-token-123")
			}

			if tokenResponse.TokenType != "Bearer" {
				t.Errorf("TokenType field mismatch: got %q, want %q", tokenResponse.TokenType, "Bearer")
			}

			if tokenResponse.IDToken.PreferredUsername != "user@example.com" {
				t.Errorf("PreferredUsername field mismatch: got %q, want %q", tokenResponse.IDToken.PreferredUsername, "user@example.com")
			}

			if tokenResponse.IDToken.Name != "John Doe" {
				t.Errorf("Name field mismatch: got %q, want %q", tokenResponse.IDToken.Name, "John Doe")
			}

			// Verify client_info is properly set
			if tokenResponse.ClientInfo.UID != "1234567890" {
				t.Errorf("ClientInfo.UID field mismatch: got %q, want %q", tokenResponse.ClientInfo.UID, "1234567890")
			}

			if tokenResponse.ClientInfo.UTID != "tenant-id-123" {
				t.Errorf("ClientInfo.UTID field mismatch: got %q, want %q", tokenResponse.ClientInfo.UTID, "tenant-id-123")
			}
		})
	}
} 