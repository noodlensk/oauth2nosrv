package oauth2nosrv

import (
	"context"
	"crypto/tls"
	"fmt"
	"net/http"
	"time"

	rndm "github.com/nmrshll/rndm-go"
	"golang.org/x/oauth2"
)

// Defaults for OAuth2 config
const (
	DefaultHost               = "localhost"
	DefaultPort               = 14565
	DefaultRedirectURL        = "/oauth/callback"
	DefaultAuthTimeout        = time.Minute * 1
	DefaultSuccessPageContent = `
		<div style="height:100px; width:100%!; display:flex; flex-direction: column; justify-content: center; align-items:center; background-color:#2ecc71; color:white; font-size:22"><div>Success!</div></div>
		<p style="margin-top:20px; font-size:18; text-align:center">You are authenticated, you can now return to the program. This will auto-close</p>
		<script>window.onload=function(){setTimeout(this.close, 4000)}</script>
		`
)

const (
	oauthStateStringContextKey = 4562
	serverShutdownTimeout      = time.Second * 5
)

type options struct {
	host        string
	port        int
	redirectURL string

	authTimeout        time.Duration
	successPageContent string

	client *http.Client
	server *http.Server
}

// Option applies option
type Option interface{ apply(*options) }
type optionFunc func(*options)

func (f optionFunc) apply(o *options) { f(o) }

func WithHost(host string) Option {
	return optionFunc(func(o *options) {
		o.host = host
	})
}

func WithPort(port int) Option {
	return optionFunc(func(o *options) {
		o.port = port
	})
}

func WithRedirectURL(redirectURL string) Option {
	return optionFunc(func(o *options) {
		o.redirectURL = redirectURL
	})
}

func WithClient(client *http.Client) Option {
	return optionFunc(func(o *options) {
		o.client = client
	})
}

func WithServer(server *http.Server) Option {
	return optionFunc(func(o *options) {
		o.server = server
	})
}

type Server interface {
	AuthURL() string
	StartAndWaitForToken(ctx context.Context) (*oauth2.Token, error)
}

type server struct {
	oauthConfig      *oauth2.Config
	options          *options
	oauthStateString string
}

func (s *server) AuthURL() string {
	return s.oauthConfig.AuthCodeURL(s.oauthStateString, oauth2.AccessTypeOffline)
}

func (s *server) StartAndWaitForToken(ctx context.Context) (*oauth2.Token, error) {
	// add transport for self-signed certificate to context
	ctx = context.WithValue(ctx, oauth2.HTTPClient, s.options.client)
	ctx = context.WithValue(ctx, oauthStateStringContextKey, s.oauthStateString)
	return startHTTPServer(ctx, s.oauthConfig, s.options)
}

func New(oauthConfig *oauth2.Config, opts ...Option) (Server, error) {
	if oauthConfig == nil {
		return nil, fmt.Errorf("oauthConfig can't be nil")
	}

	defaultOptions := options{
		host:               DefaultHost,
		port:               DefaultPort,
		redirectURL:        DefaultRedirectURL,
		successPageContent: DefaultSuccessPageContent,
		client:             &http.Client{Transport: &http.Transport{TLSClientConfig: &tls.Config{InsecureSkipVerify: true}}},
		authTimeout:        DefaultAuthTimeout,
	}

	for _, o := range opts {
		o.apply(&defaultOptions)
	}

	if defaultOptions.server == nil {
		defaultOptions.server = &http.Server{Addr: fmt.Sprintf("%s:%d", defaultOptions.host, defaultOptions.port)}
	}

	// Redirect user to consent page to ask for permission
	// for the scopes specified above.
	oauthConfig.RedirectURL = fmt.Sprintf("http://%s:%d%s", defaultOptions.host, defaultOptions.port, defaultOptions.redirectURL)

	// Some random string, random for each request
	oauthStateString := rndm.String(8)

	return &server{
		oauthConfig:      oauthConfig,
		options:          &defaultOptions,
		oauthStateString: oauthStateString,
	}, nil
}

func startHTTPServer(ctx context.Context, conf *oauth2.Config, opts *options) (token *oauth2.Token, err error) {
	tokens := make(chan *oauth2.Token)
	errs := make(chan error)

	mux := http.NewServeMux()

	mux.Handle(opts.redirectURL, http.HandlerFunc(callbackHandler(ctx, conf, opts.successPageContent, tokens, errs)))
	srv := opts.server

	srv.Handler = mux

	newCtx, cancel := context.WithCancel(ctx)
	defer cancel()

	go func() {
		// handle server shutdown signal
		select {
		case token = <-tokens:
			cancel()
		case err = <-errs:
			cancel()
		}
	}()

	if err := serveWithContext(newCtx, srv); err != nil {
		return nil, err
	}

	return token, err
}

func serveWithContext(ctx context.Context, srv *http.Server) error {
	errs := make(chan error)

	go func() { errs <- srv.ListenAndServe() }()

	select {
	case <-ctx.Done():
		ctx, cancel := context.WithTimeout(context.Background(), serverShutdownTimeout)
		defer cancel()
		err := srv.Shutdown(ctx)
		if err != nil {
			return err
		}
	case err := <-errs:
		if err != http.ErrServerClosed {
			return err
		}
	}

	return nil
}

func callbackHandler(ctx context.Context, oauthConfig *oauth2.Config, successPage string, tokens chan *oauth2.Token, errs chan error) func(w http.ResponseWriter, r *http.Request) {
	return func(w http.ResponseWriter, r *http.Request) {
		requestStateString := ctx.Value(oauthStateStringContextKey).(string)
		responseStateString := r.FormValue("state")
		if responseStateString != requestStateString {
			errs <- fmt.Errorf("invalid oauth state, expected %q, got %q", requestStateString, responseStateString)
			http.Redirect(w, r, "/", http.StatusTemporaryRedirect)
			return
		}

		code := r.FormValue("code")
		token, err := oauthConfig.Exchange(ctx, code)
		if err != nil {
			errs <- fmt.Errorf("oauthoauthConfig.Exchange() failed with %q", err)
			http.Redirect(w, r, "/", http.StatusTemporaryRedirect)
			return
		}

		_, _ = w.Write([]byte(successPage))

		tokens <- token
	}
}
