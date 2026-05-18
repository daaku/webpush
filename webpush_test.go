package webpush

import (
	"bytes"
	"context"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"os"
	"regexp"
	"testing"
	"testing/cryptotest"
	"time"

	"github.com/daaku/ensure"
	"github.com/golang-jwt/jwt/v5"
)

var (
	validVapidKey     = must(ParseVAPIDKey("Npnu7ulDI0A5nvDXgrEreznX809sYVuIqEh7AXG2oOk"))
	validSubscription = Subscription{
		Endpoint: "https://the.push.server/capability-url",
		Keys: Keys{
			Auth:   "RW2wUiDEKNzSyDxlg7ArbQ",
			P256dh: "BOaRpSCtjsB92YouZnj8iNgCdFDNVNbid40AGxLcR47DI1S-zQkYf1CDG2G4y9GXeg74-8U_mEMzSZc-mRF_X0Y",
		},
	}
	validSubscriptionEndpointOrigin = "https://the.push.server"
	validHTTPSSubscriber            = "https://app.server/"
	validMailtoSubscriber           = "mailto:admin@app.server"
	goldTime                        = time.Date(2015, time.May, 13, 3, 15, 0, 0, time.UTC)
)

func must[T any](v T, err error) T {
	if err == nil {
		return v
	}
	panic(fmt.Sprintf("error: %+v", err))
}

type transportFunc func(*http.Request) (*http.Response, error)

func (f transportFunc) RoundTrip(r *http.Request) (*http.Response, error) {
	return f(r)
}

func TestUrgencyValid(t *testing.T) {
	ensure.True(t, UrgencyHigh.isValid())
	ensure.False(t, Urgency("").isValid())
	ensure.False(t, Urgency("foo").isValid())
}

func TestB64Decode(t *testing.T) {
	raw := []byte{0, 1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 3, 239}
	cases := []struct {
		label string
		input string
	}{
		{"base64.URLEncoding", base64.URLEncoding.EncodeToString(raw)},
		{"base64.RawURLEncoding", base64.RawURLEncoding.EncodeToString(raw)},
		{"base64.StdEncoding", base64.StdEncoding.EncodeToString(raw)},
		{"base64.RawStdEncoding", base64.RawStdEncoding.EncodeToString(raw)},
	}
	for _, c := range cases {
		t.Run(c.label, func(t *testing.T) {
			out, err := b64Decode(c.input)
			ensure.Nil(t, err)
			ensure.DeepEqual(t, out, raw)
		})
	}
}

func TestGenerateVAPIDKey(t *testing.T) {
	cryptotest.SetGlobalRandom(t, 42)
	keyB64, err := GenerateVAPIDKey()
	ensure.Nil(t, err)
	ensure.DeepEqual(t, keyB64, "IjAfuNgpeNrwB7BWFJafNAPQBiZz9VlElXmNNAwKF-g")
}

func TestParseVAPIDKey(t *testing.T) {
	keyB64, err := GenerateVAPIDKey()
	ensure.Nil(t, err)
	ensure.DeepEqual(t, len(keyB64), 43)
	key, err := ParseVAPIDKey(keyB64)
	ensure.Nil(t, err)
	ensure.NotNil(t, key)
}

func TestMakeAuthHeaderHttpsSnapshot(t *testing.T) {
	cryptotest.SetGlobalRandom(t, 42)
	header, err := makeAuthHeader(
		validSubscription.Endpoint,
		validHTTPSSubscriber,
		validVapidKey,
		goldTime,
	)
	ensure.Nil(t, err)
	ensure.DeepEqual(t, header, "vapid t=eyJhbGciOiJFUzI1NiIsInR5cCI6IkpXVCJ9.eyJhdWQiOiJodHRwczovL3RoZS5wdXNoLnNlcnZlciIsImV4cCI6MTQzMTQ4NjkwMCwic3ViIjoiaHR0cHM6Ly9hcHAuc2VydmVyLyJ9.UC4OZiYDEll6nNKEMYWNmrYmpYv84TSSy2ZyKQ4CZlNdmyBLDNt7ZxPm8cmzD27ihHNYXYYkRkZ92J6NlTfknw, k=BBRS0hDoszIXnLVNyR3EbnXnN4glsvb6AusPR9e9L93ZWHeKO4mYTWjpwa5w2xwc0sZBIBIQ-RtwDgE7BZqRWc0")
}

func TestMakeAuthHeaderMailtoSnapshot(t *testing.T) {
	cryptotest.SetGlobalRandom(t, 42)
	header, err := makeAuthHeader(
		validSubscription.Endpoint,
		validMailtoSubscriber,
		validVapidKey,
		goldTime,
	)
	ensure.Nil(t, err)
	ensure.DeepEqual(t, header, "vapid t=eyJhbGciOiJFUzI1NiIsInR5cCI6IkpXVCJ9.eyJhdWQiOiJodHRwczovL3RoZS5wdXNoLnNlcnZlciIsImV4cCI6MTQzMTQ4NjkwMCwic3ViIjoibWFpbHRvOmFkbWluQGFwcC5zZXJ2ZXIifQ.nKKgN0nz3HXp2W84ov0I6Vj3VDV7kgiaDweHmQBdRCtkZHYRlMp2QX-Cf_W-ZfP79aHXD5T6pc_GUKeR3DwiKA, k=BBRS0hDoszIXnLVNyR3EbnXnN4glsvb6AusPR9e9L93ZWHeKO4mYTWjpwa5w2xwc0sZBIBIQ-RtwDgE7BZqRWc0")
}

func TestMakeAuthHeaderCheckJWT(t *testing.T) {
	expiration := time.Now().Add(time.Hour)
	header, err := makeAuthHeader(
		validSubscription.Endpoint,
		validHTTPSSubscriber,
		validVapidKey,
		expiration,
	)
	ensure.Nil(t, err)
	tokenStr := header[8 : len(header)-91]
	token, err := jwt.Parse(tokenStr, func(token *jwt.Token) (any, error) {
		_, ok := token.Method.(*jwt.SigningMethodECDSA)
		ensure.True(t, ok, "expected ECDSA")
		return validVapidKey.Public(), nil
	})
	ensure.Nil(t, err)
	claims, ok := token.Claims.(jwt.MapClaims)
	ensure.True(t, ok, "expected MapClaims")
	ensure.DeepEqual(t, claims, jwt.MapClaims{
		"sub": validHTTPSSubscriber,
		"aud": validSubscriptionEndpointOrigin,
		"exp": float64(expiration.Unix()),
	})
}

func TestMakeAuthHeaderMissingEndpoint(t *testing.T) {
	_, err := makeAuthHeader("", "", validVapidKey, time.Now())
	ensure.Err(t, err, regexp.MustCompile("invalid endpoint"))
}

func TestMakeAuthHeaderMissingSubscriber(t *testing.T) {
	_, err := makeAuthHeader(validSubscription.Endpoint, "", validVapidKey, time.Now())
	ensure.Err(t, err, regexp.MustCompile("invalid subscriber"))
}

func TestSendDefaultsSnapshot(t *testing.T) {
	cryptotest.SetGlobalRandom(t, 42)
	err := Send(
		context.Background(),
		[]byte("Test"),
		&validSubscription,
		&Config{
			Client: &http.Client{
				Transport: transportFunc(func(r *http.Request) (*http.Response, error) {
					ensure.DeepEqual(t, r.URL.String(), validSubscription.Endpoint)
					ensure.DeepEqual(t, r.Header, http.Header{
						"Authorization":    []string{"vapid t=eyJhbGciOiJFUzI1NiIsInR5cCI6IkpXVCJ9.eyJhdWQiOiJodHRwczovL3RoZS5wdXNoLnNlcnZlciIsImV4cCI6MTQzMTQ4NjkwMCwic3ViIjoiaHR0cHM6Ly9hcHAuc2VydmVyLyJ9.T8cqkLEXgqcPAT1qLbskBOKP_eA--CEY8UcjeG_m8Ld3pxKSZDtZowcFhKCMLuSPp-1KwXdz2dAkDwALWRDGwQ, k=BBRS0hDoszIXnLVNyR3EbnXnN4glsvb6AusPR9e9L93ZWHeKO4mYTWjpwa5w2xwc0sZBIBIQ-RtwDgE7BZqRWc0"},
						"Content-Encoding": []string{"aes128gcm"},
						"Content-Type":     []string{"application/octet-stream"},
						"Ttl":              []string{"3600"},
					})
					body, err := io.ReadAll(r.Body)
					ensure.Nil(t, err)
					ensure.DeepEqual(t, base64.RawURLEncoding.EncodeToString(body), "IjAfuNgpeNrwB7BWFJafNAAAEABBBDajlIZjLlvd1IgiJYLExFbuPDgrl6lFBXkIhRULaoMS1bIsXKnermv89uUh9p_9tngznzl2WYcsinUIdf8f2qGJJtpbHUjmLdWNtA7-DjaOwgTXpBQ")
					return &http.Response{StatusCode: http.StatusCreated}, nil
				}),
			},
			VAPIDKey:        validVapidKey,
			Subscriber:      validHTTPSSubscriber,
			TTL:             time.Hour,
			VAPIDExpiration: goldTime,
		})
	ensure.Nil(t, err)
}

func TestSendTopic(t *testing.T) {
	const topic = "a-test"
	err := Send(
		context.Background(),
		[]byte("test"),
		&validSubscription,
		&Config{
			Client: &http.Client{
				Transport: transportFunc(func(r *http.Request) (*http.Response, error) {
					ensure.DeepEqual(t, r.Header.Get("Topic"), topic)
					return &http.Response{StatusCode: http.StatusCreated}, nil
				}),
			},
			VAPIDKey:   validVapidKey,
			Subscriber: validHTTPSSubscriber,
			TTL:        time.Hour,
			Topic:      topic,
		})
	ensure.Nil(t, err)
}

func TestSendUrgency(t *testing.T) {
	const urgency = UrgencyVeryLow
	err := Send(
		context.Background(),
		[]byte("test"),
		&validSubscription,
		&Config{
			Client: &http.Client{
				Transport: transportFunc(func(r *http.Request) (*http.Response, error) {
					ensure.DeepEqual(t, r.Header.Get("Urgency"), string(UrgencyVeryLow))
					return &http.Response{StatusCode: http.StatusCreated}, nil
				}),
			},
			VAPIDKey:   validVapidKey,
			Subscriber: validHTTPSSubscriber,
			TTL:        time.Hour,
			Urgency:    urgency,
		})
	ensure.Nil(t, err)
}

func TestSendErrorTooLongCustomRecordSize(t *testing.T) {
	err := Send(
		context.Background(),
		[]byte("12"),
		&validSubscription,
		&Config{RecordSize: 1},
	)
	ensure.Err(t, err, regexp.MustCompile("too long"))
}

func TestSendErrorTooLongDefaultRecordSize(t *testing.T) {
	err := Send(
		context.Background(),
		bytes.Repeat([]byte("1"), maxRecordSize),
		&validSubscription,
		&Config{},
	)
	ensure.Err(t, err, regexp.MustCompile("too long"))
}

func TestSendErrorEmptySubscription(t *testing.T) {
	err := Send(
		context.Background(),
		[]byte("1"),
		&Subscription{},
		&Config{},
	)
	ensure.Err(t, err, regexp.MustCompile("invalid subscription"))
}

func TestSendErrorInvalidAuthSecret(t *testing.T) {
	sub := validSubscription
	sub.Keys.Auth = "{}"
	err := Send(
		context.Background(),
		[]byte("1"),
		&sub,
		&Config{},
	)
	ensure.Err(t, err, regexp.MustCompile("invalid encoded auth"))
}

func TestSendErrorInvalidPublicKey(t *testing.T) {
	sub := validSubscription
	sub.Keys.P256dh = "{}"
	err := Send(
		context.Background(),
		[]byte("1"),
		&sub,
		&Config{},
	)
	ensure.Err(t, err, regexp.MustCompile("invalid encoded public key"))
}

func TestSendErrorInvalidUrgency(t *testing.T) {
	err := Send(
		context.Background(),
		[]byte("test"),
		&validSubscription,
		&Config{
			VAPIDKey:   validVapidKey,
			Subscriber: validHTTPSSubscriber,
			TTL:        time.Hour,
			Urgency:    Urgency("invalid"),
		})
	ensure.Err(t, err, regexp.MustCompile("invalid urgency"))
}

func TestRealEndpoints(t *testing.T) {
	if os.Getenv("REAL_ENDPOINTS") == "" {
		t.Skip("skipping testing real endpoints")
	}
	config := Config{
		Client:     http.DefaultClient,
		Subscriber: "https://bento.daaku.org/",
		VAPIDKey:   validVapidKey,
		// VAPIDKey: must(ParseVAPIDKey("Npnu7ulDI0A5nvDXgrEreznX809sYVuIqEh7AXG2ook")),
		TTL: 30 * time.Minute,
	}

	type Notification struct {
		Title string `json:"title"`
		Body  string `json:"body"`
		Data  any    `json:"data"`
	}
	msg, err := json.Marshal(Notification{
		Title: "Bento Notification Test",
		Body:  "This is a integration test push notification!",
		Data:  map[string]string{"url": "/"},
	})
	ensure.Nil(t, err)

	// these were generated using the above config
	const expiredApple = `{
  "endpoint": "https://web.push.apple.com/QC01kYdRpQOe1qvJ6hjhcGV3ccZ4tGq5D-H_Uy671ijCGAI-MPp83I6Jsc3MFYfQIZzfePLaQ9iEwiex0ADdVKETrQIsqUQU-xBC1yCysd1G2BDfQ7BhCT6OeEo3ni6-wbYTBWO0ZLuBGVe4urAg14xFPIDERQReHC5WRxUIpus",
  "keys": {
    "p256dh": "BNmbtO6-SUBosBADSTtC397JqaI_fAGRsbREjc_DgCqBC-Cu2jNebaTyWfAlkbWFJR21cKe-FgUpp9GPB0jMWH4",
    "auth": "F5RrPEXbdJq_ttCnxo4C1A"
  }
}`
	const expiredGoogle = `{
  "endpoint": "https://fcm.googleapis.com/fcm/send/cVGTCKN07V8:APA91bHhsj5f00xzGMQVfUTVDdEenLHAPb7uSoiZYpc1UvQla2AwnfSjnnl5ThKhH7Ih7EoQT1FVs9M3HO3Gk2vSIOJIE9VzmlsOWZGWfJt5hkosi_WJALCf31JhFbpo2mdJgKV_o6m1",
  "expirationTime": null,
  "keys": {
    "p256dh": "BBh4fvs0lg2-Grrmi_JRFujJTVunr_pa-hU1RshQfgesz6Y4pcv2tRIrF8XV8b2HU7ok5zo84baayUTSRdQ9Lcg",
    "auth": "IAv17Jx2W6K2iwwD4jzLRw"
  }
}`
	const expiredFirefox = `{
  "endpoint": "https://updates.push.services.mozilla.com/wpush/v2/gAAAAABqCo263dWI_rIfY6pY66liCmPlMAz_9GT0SDq1qLlePOltX0Jn5s_ntiYj0D_xt2elklq1L6eALr1hWGZH4CgpGLLsjD1gsNdLRIk-Op8CZ-r3neGslyeShpwE1wDDARFt1fcHTZEQhrr63M9s3baMakCISxLQWYyMsghjyaPkYb67Px8",
  "expirationTime": null,
  "keys": {
    "auth": "6kSx6ui7o_aAgHnN1Wybtg",
    "p256dh": "BHjzJbon1LmmJfEPr6VAiuguxCIT3P3PGSAObxght2MblDIxE77zk7O5X7GFRxNrdvqhNStOkEVl9TE4W1kWQ2s"
  }
}`
	cases := []struct{ name, json string }{
		{"apple", expiredApple},
		{"google", expiredGoogle},
		{"firefox", expiredFirefox},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			t.Parallel()

			var sub Subscription
			ensure.Nil(t, json.Unmarshal([]byte(c.json), &sub))

			err := Send(context.Background(), msg, &sub, &config)
			ensure.NotNil(t, err, err)
			_, ok := errors.AsType[*Error](err)
			ensure.True(t, ok, err)
		})
	}
}
