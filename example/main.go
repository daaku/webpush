// An example server that can be used to send push notifications.
//
// - A VAPID key is generated on startup. In real use generate this key once and
//   load it at application startup. Remember to securely store it.

package main

import (
	"context"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"os"
	"time"

	"github.com/daaku/webpush"
)

// In real use, this should be generated once and stored in config.
// Here for the example we generate and cache it.
// A change in the VAPID key invalidates all your existing subscriptions.
func vapidKey() (string, error) {
	const vapidKeyCache = ".vapid.key"
	if b, err := os.ReadFile(vapidKeyCache); err == nil {
		return string(b), nil
	}
	vapidKeyPrivateB64, err := webpush.GenerateVAPIDKey()
	if err != nil {
		return "", err
	}
	if err := os.WriteFile(vapidKeyCache, []byte(vapidKeyPrivateB64), 0o600); err != nil {
		return "", err
	}
	return vapidKeyPrivateB64, nil
}

func run() error {
	vapidKeyPrivateB64, err := vapidKey()
	if err != nil {
		return err
	}

	vapidKey, err := webpush.ParseVAPIDKey(vapidKeyPrivateB64)
	if err != nil {
		return err
	}

	vapidKeyPublicBytes, err := vapidKey.PublicKey.Bytes()
	if err != nil {
		return err
	}
	vapidKeyPublicB64 := base64.RawURLEncoding.EncodeToString(vapidKeyPublicBytes)

	var mux http.ServeMux

	// serve some static files
	files := []string{
		"icon.png",
		"service-worker.js",
		"main.js",
		"app.webmanifest",
	}
	for _, filename := range files {
		mux.HandleFunc("/"+filename, func(w http.ResponseWriter, r *http.Request) {
			http.ServeFile(w, r, filename)
		})
	}

	// index page including the generated vapid public key used by the JavaScript
	mux.HandleFunc("/", func(w http.ResponseWriter, r *http.Request) {
		fmt.Fprintf(w, indexHTML, vapidKeyPublicB64)
	})

	// schedule push notification to the given subscription
	mux.HandleFunc("/push", func(w http.ResponseWriter, r *http.Request) {
		rawJSON, err := io.ReadAll(io.LimitReader(r.Body, 4096))
		if err != nil {
			w.WriteHeader(http.StatusBadRequest)
			fmt.Fprintln(w, err)
			return
		}
		fmt.Fprintf(os.Stderr, "%s\n", rawJSON)

		var sub webpush.Subscription
		if err := json.Unmarshal(rawJSON, &sub); err != nil {
			w.WriteHeader(http.StatusBadRequest)
			fmt.Fprintln(w, err)
			return
		}
		go func() {
			time.Sleep(5 * time.Second)
			msg, _ := json.Marshal(map[string]any{
				"title": "Test push from WebPush Example",
			})
			res, err := webpush.Send(context.Background(), msg, &sub, &webpush.Config{
				Client:     http.DefaultClient,
				VAPIDKey:   vapidKey,
				Subscriber: "https://github.com/daaku/webpush",
				TTL:        time.Hour,
			})
			if err != nil {
				fmt.Fprintln(os.Stderr, "webpush.Send error:", err)
			}
			defer res.Body.Close()
			io.Copy(os.Stderr, res.Body)
		}()
	})

	port := "8080"
	server := &http.Server{
		Handler: &mux,
		Addr:    ":" + port,
	}

	certFile, keyFile := os.Getenv("TLS_CERT_FILE"), os.Getenv("TLS_KEY_FILE")
	if certFile != "" {
		fmt.Println("Serving on https://127.0.0.1:" + port)
		return server.ListenAndServeTLS(certFile, keyFile)
	} else {
		fmt.Println("Serving on http://127.0.0.1:" + port)
		return server.ListenAndServe()
	}
}

func main() {
	if err := run(); err != nil {
		fmt.Fprintf(os.Stderr, "%+v\n", err)
		os.Exit(1)
	}
}

const indexHTML = `<!doctype html>
<html lang="en">
<head>
  <meta charset="utf-8">
  <meta name="viewport" content="width=device-width, initial-scale=1">
  <title>WebPush Example</title>
  <link rel="manifest" href="/app.webmanifest">
  <meta name="apple-mobile-web-app-status-bar-style" content="black-translucent">
  <link rel="icon" type="image/png" href="/icon.png">
  <link rel="apple-touch-icon" type="image/png" href="/icon.png">
  <meta data-vapid-public-key="%s">
  <style>
  .status {
    margin-block: 1rem;
  }
  #msg {
    font-family: monospace;
  }
  .push-unavailable {
    #controls {
      display: none;
    }
    #msg::after {
      color: lightcoral;
      font-weight: bold;
      content: "Push Unavailable. For iOS add the app to the home screen."
    }
  }
  .push-granted .status::after {
    color: lightseagreen;
    content: "Push Permission Granted."
  }
  </style>
</head>
<body>
  <h1>WebPush Example</h1>
  <div id="controls">
    <button id="send-push">Subscribe & Schedule Push</button>
    <button id="unsubscribe">Unsubscribe</button>
  </div>
  <div class="status"></div>
  <div id="msg"></div>
  <script src="/main.js"></script>
</body>
</html>
`
