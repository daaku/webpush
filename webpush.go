// Package webpush supports Generic Event Delivery Using HTTP Push.
//
// Generic Event Delivery Using HTTP Push
// https://www.rfc-editor.org/rfc/rfc8030.html
//
// Message Encryption for Web Push
// https://www.rfc-editor.org/rfc/rfc8291.html
//
// Voluntary Application Server Identification (VAPID) for Web Push
// https://www.rfc-editor.org/rfc/rfc8292
//
// Encrypted Content-Encoding for HTTP:
// https://www.rfc-editor.org/rfc/rfc8188
//
// MDN Push API:
// https://developer.mozilla.org/en-US/docs/Web/API/Push_API
//
// Apple Push Notification Documentation:
// https://developer.apple.com/documentation/usernotifications/sending-web-push-notifications-in-web-apps-and-browsers
package webpush

import (
	"bytes"
	"context"
	"crypto/aes"
	"crypto/cipher"
	"crypto/ecdh"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/sha256"
	"encoding/base64"
	"encoding/binary"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"slices"
	"strconv"
	"strings"
	"time"

	"github.com/golang-jwt/jwt/v5"
	"golang.org/x/crypto/hkdf"
)

const (
	// Push services are not required to support more than this.
	// Apple for example does not.
	maxRecordSize = 4096

	headerLen = 86

	// header: 86 + padding: minimum 1 + AEAD_AES_128_GCM Expansion: 16
	minOverhead = 103
)

// Error returned by Send when the Push Endpoint returns an error.
type Error struct {
	StatusCode int    // HTTP StatusCode from the Endpoint.
	Body       []byte // Response Body from the Endpoint.
	Message    string // A best-guess message describing the issue.

	// EndpointHost contains the hostname as a helpful hint to debug
	// errors. Often the combination of the Push Endpoint and message
	// text together will lead to quicker diagnosis.
	EndpointHost string

	// A best-guess indicating if the error is permanent.
	// The library tries to detect such errors from various well known
	// Push Endpoint implementations used by popular User Agents.
	Permanent bool

	// Location header returned by Push Endpoint in case the subscription Endpoint
	// needs to be updated.
	Location string
}

// Error returns the error message.
func (e *Error) Error() string {
	return fmt.Sprintf("webpush: %s: %s", e.EndpointHost, e.Message)
}

var openCurly = []byte("{")

func newError(endpoint string, res *http.Response, body []byte) *Error {
	endpointHost := "<unknown-endpoint>"
	u, err := url.Parse(endpoint)
	if err == nil {
		endpointHost = u.Hostname()
	}

	var msg string
	switch {
	case bytes.HasPrefix(body, openCurly):
		var j struct {
			Message string `json:"message"` // used by Mozilla
			Reason  string `json:"reason"`  // used by Apple
		}
		_ = json.Unmarshal(body, &j)
		msg = j.Message
		if msg == "" {
			msg = j.Reason
		}
	case strings.HasPrefix(res.Header.Get("Content-Type"), "text/plain"): // used by Google
		msg = string(bytes.TrimSpace(body))
	}
	if msg == "" {
		msg = fmt.Sprintf("error from push endpoint with status=%d", res.StatusCode)
	}

	return &Error{
		StatusCode:   res.StatusCode,
		Body:         body,
		Message:      msg,
		EndpointHost: endpointHost,
		Permanent:    res.StatusCode == 404 || res.StatusCode == 410,
		Location:     res.Header.Get("Location"),
	}
}

// Urgency directly impacts battery life.
//
// https://www.rfc-editor.org/rfc/rfc8030.html#section-5.3
type Urgency string

const (
	// UrgencyVeryLow targets "On power and Wi-Fi".
	UrgencyVeryLow Urgency = "very-low"
	// UrgencyLow targets "On either power or Wi-Fi".
	UrgencyLow Urgency = "low"
	// UrgencyNormal targets "On neither power nor Wi-Fi".
	UrgencyNormal Urgency = "normal"
	// UrgencyHigh targets any state including "Low battery".
	UrgencyHigh Urgency = "high"
)

func (u Urgency) isValid() bool {
	switch u {
	case UrgencyVeryLow, UrgencyLow, UrgencyNormal, UrgencyHigh:
		return true
	}
	return false
}

func b64Encoding(s string) *base64.Encoding {
	hasPadding := len(s) > 0 && s[len(s)-1] == '='
	isURL := false

outer:
	for i := 0; i < len(s); i++ {
		switch s[i] {
		case '-', '_':
			isURL = true
			break outer
		case '+', '/':
			break outer
		}
	}

	switch {
	case isURL && hasPadding:
		return base64.URLEncoding
	case isURL && !hasPadding:
		return base64.RawURLEncoding
	case !isURL && hasPadding:
		return base64.StdEncoding
	case !isURL && !hasPadding:
		return base64.RawStdEncoding
	}
	panic("webpush: impossible case of b64 encoding")
}

// We're being permissive in the variations of B64 encoding being used.
func b64Decode(s string) ([]byte, error) {
	return b64Encoding(s).DecodeString(s)
}

// GenerateVAPIDKey will create a private VAPID key in Base64 Raw URL Encoding.
// Generate a key and store it in your configuration. Use ParseVAPIDKey on
// application startup to parse it for use in the Config.
func GenerateVAPIDKey() (string, error) {
	private, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		return "", err
	}
	privateKeyBytes, err := private.Bytes()
	if err != nil {
		return "", err
	}
	return base64.RawURLEncoding.EncodeToString(privateKeyBytes), nil
}

// ParseVAPIDKey parses a private key encoded in Base64 Raw URL Encoding.
// Use GenerateVAPIDKey to generate a key for use in your application.
func ParseVAPIDKey(privateKey string) (*ecdsa.PrivateKey, error) {
	raw, err := b64Decode(privateKey)
	if err != nil {
		return nil, err
	}
	return ecdsa.ParseRawPrivateKey(elliptic.P256(), raw)
}

func makeAuthHeader(
	endpoint,
	subscriber string,
	vapidKey *ecdsa.PrivateKey,
	expiration time.Time,
) (string, error) {
	subURL, err := url.Parse(endpoint)
	if err != nil {
		return "", err
	}
	if subURL.Scheme == "" || subURL.Host == "" {
		return "", fmt.Errorf("webpush: invalid endpoint: %q", endpoint)
	}

	// Google & Firefox allow for empty Subscriber, but Apple doesn't.
	if !strings.HasPrefix(subscriber, "https:") && !strings.HasPrefix(subscriber, "mailto:") {
		return "", fmt.Errorf("webpush: invalid subscriber: %q", subscriber)
	}

	token := jwt.NewWithClaims(jwt.SigningMethodES256, jwt.MapClaims{
		"aud": subURL.Scheme + "://" + subURL.Host,
		"exp": expiration.Unix(),
		"sub": subscriber,
	})

	jwtString, err := token.SignedString(vapidKey)
	if err != nil {
		return "", err
	}

	// TODO: memoize? weakmap?
	publicKeyBytes, err := vapidKey.PublicKey.Bytes()
	if err != nil {
		return "", err
	}
	encodedPubicKey := base64.RawURLEncoding.EncodeToString(publicKeyBytes)

	return "vapid t=" + jwtString + ", k=" + encodedPubicKey, nil
}

func hkdfExpand(length int, secret, salt, info []byte) ([]byte, error) {
	hkdfReader := hkdf.New(sha256.New, secret, salt, info)
	key := make([]byte, length)
	_, err := io.ReadFull(hkdfReader, key)
	return key, err
}

// Client specifies required and optional aspects for sending a Push Notification.
type Client struct {
	Client          *http.Client      // Required http.Client.
	VAPIDKey        *ecdsa.PrivateKey // Required VAPID Private Key.
	Subscriber      string            // Required Subscriber, https URL or mailto: email address.
	TTL             time.Duration     // Required TTL on the endpoint POST request (rounded to seconds).
	Topic           string            // Optional Topic to collapse pending messages.
	Urgency         Urgency           // Optional Urgency for message priority.
	RecordSize      int               // Optional custom RecordSize, defaults to 4096 per spec.
	VAPIDExpiration time.Time         // Optional custom expiration for VAPID JWT token (defaults to now + 12 hours).
}

// Keys are the Base64 encoded values from the User Agent.
type Keys struct {
	Auth   string `json:"auth"`
	P256dh string `json:"p256dh"`
}

// Subscription represents a PushSubscription from the User Agent.
type Subscription struct {
	Endpoint string `json:"endpoint"`
	Keys     Keys   `json:"keys"`
}

var (
	webPushInfo              = []byte("WebPush: info\x00")
	contentEncryptionKeyInfo = []byte("Content-Encoding: aes128gcm\x00")
	nonceInfo                = []byte("Content-Encoding: nonce\x00")
)

// Send a Push Notification to a Subscription.
// Send will return an error of type Error if the Endpoint returns a HTTP
// response with a status code outside the 200-299 range.
func (c *Client) Send(ctx context.Context, message []byte, s *Subscription) error {
	recordSize := c.RecordSize
	if recordSize == 0 {
		recordSize = maxRecordSize
	}

	if s.Endpoint == "" || s.Keys.Auth == "" || s.Keys.P256dh == "" {
		return fmt.Errorf(
			"webpush: invalid subscription, missing endpoint or keys")
	}

	if len(message) > recordSize-minOverhead {
		return fmt.Errorf(
			"webpush: message length of %v is too long for record size of %v",
			len(message), recordSize)
	}

	authSecret, err := b64Decode(s.Keys.Auth)
	if err != nil {
		return fmt.Errorf("webpush: invalid encoded auth in key: %w", err)
	}

	userAgentPublicKeyBytes, err := b64Decode(s.Keys.P256dh)
	if err != nil {
		return fmt.Errorf("webpush: invalid encoded public key: %w", err)
	}

	salt := make([]byte, 16)
	if _, err := io.ReadFull(rand.Reader, salt); err != nil {
		return fmt.Errorf("webpush: failed to create salt: %w", err)
	}

	// New Key for this Message
	appServerPrivateKey, err := ecdh.P256().GenerateKey(rand.Reader)
	if err != nil {
		return fmt.Errorf("webpush: failed to generate application server key: %w", err)
	}
	appServerPublicKeyBytes := appServerPrivateKey.PublicKey().Bytes()

	userAgentPublicKey, err := ecdh.P256().NewPublicKey(userAgentPublicKeyBytes)
	if err != nil {
		return fmt.Errorf("webpush: invalid user agent public key: %w", err)
	}

	// Derive Shared Secret for this Message
	sharedSecret, err := appServerPrivateKey.ECDH(userAgentPublicKey)
	if err != nil {
		return fmt.Errorf("webpush: failed to derive shared secret: %w", err)
	}

	// Derive IKM
	keyInfo := slices.Concat(webPushInfo, userAgentPublicKeyBytes, appServerPublicKeyBytes)
	ikm, err := hkdfExpand(32, sharedSecret, authSecret, keyInfo)
	if err != nil {
		return fmt.Errorf("webpush: failed to derive ikm: %w", err)
	}

	// Derive Content Encryption Key
	contentEncryptionKey, err := hkdfExpand(16, ikm, salt, contentEncryptionKeyInfo)
	if err != nil {
		return fmt.Errorf("webpush: failed to derive content encryption key: %w", err)
	}

	// Derive Nonce
	nonce, err := hkdfExpand(12, ikm, salt, nonceInfo)
	if err != nil {
		return fmt.Errorf("webpush: failed to derive nonce: %w", err)
	}

	// AES + GCM
	aesCipher, err := aes.NewCipher(contentEncryptionKey)
	if err != nil {
		return fmt.Errorf("webpush: invalid generated content encryption key: %w", err)
	}
	gcm, err := cipher.NewGCM(aesCipher)
	if err != nil {
		return fmt.Errorf("webpush: invalid content encryption cipher: %w", err)
	}

	// Single allocation byte slice in which we write the header, message,
	// delimiter and padding. We then Seal the message and write the resulting
	// ciphertext replacing the plaintext message in the same byte slice.
	record := make([]byte, 0, minOverhead+len(message))
	record = append(record, salt...)
	record = binary.BigEndian.AppendUint32(record, uint32(recordSize))
	record = append(record, byte(len(appServerPublicKeyBytes)))
	record = append(record, appServerPublicKeyBytes...)
	record = append(record, message...)
	record = append(record, '\x02')
	gcm.Seal(
		// replace plaintext in-place with ciphertext
		record[headerLen:headerLen],
		nonce,
		// pad until capacity accounting for overhead
		record[headerLen:cap(record)-gcm.Overhead()],
		nil)
	record = record[0:cap(record)] // resize to header + gcm overhead

	req, err := http.NewRequest("POST", s.Endpoint, bytes.NewReader(record))
	if err != nil {
		return fmt.Errorf("webpush: invalid endpoint request: %w", err)
	}

	req.Header.Set("Content-Encoding", "aes128gcm")
	req.Header.Set("Content-Type", "application/octet-stream")
	req.Header.Set("TTL", strconv.Itoa(int(c.TTL.Seconds())))

	if c.Topic != "" {
		req.Header.Set("Topic", c.Topic)
	}
	if c.Urgency != "" {
		if !c.Urgency.isValid() {
			return fmt.Errorf("webpush: invalid urgency %q", c.Urgency)
		}
		req.Header.Set("Urgency", string(c.Urgency))
	}

	expiration := c.VAPIDExpiration
	if expiration.IsZero() {
		expiration = time.Now().Add(time.Hour * 12)
	}

	authHeader, err := makeAuthHeader(
		s.Endpoint,
		c.Subscriber,
		c.VAPIDKey,
		expiration,
	)
	if err != nil {
		return err
	}
	req.Header.Set("Authorization", authHeader)

	res, err := c.Client.Do(req)
	if err != nil {
		return fmt.Errorf("webpush: error making request to subscription endpoint: %w", err)
	}
	defer res.Body.Close()

	body, err := io.ReadAll(io.LimitReader(res.Body, 4096))
	if err != nil {
		return fmt.Errorf("webpush: error reading response body from subscription endpoint: %w", err)
	}

	if res.StatusCode >= 200 && res.StatusCode <= 299 {
		return nil
	}

	return newError(s.Endpoint, res, body)
}
