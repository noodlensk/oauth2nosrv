package oauth2nosrv_test

import (
	"context"
	"fmt"
	"log"
	"net/http"
	"time"

	"github.com/gorilla/mux"
	"github.com/noodlensk/oauth2nosrv"
	"golang.org/x/oauth2"

	"github.com/go-oauth2/oauth2/v4/errors"
	"github.com/go-oauth2/oauth2/v4/manage"
	"github.com/go-oauth2/oauth2/v4/models"
	"github.com/go-oauth2/oauth2/v4/server"
	"github.com/go-oauth2/oauth2/v4/store"
)

func ExampleAuthenticateSimple() {
	manager := manage.NewDefaultManager()
	// token memory store
	manager.MustTokenStorage(store.NewMemoryTokenStore())

	// client memory store
	clientStore := store.NewClientStore()
	clientStore.Set("000000", &models.Client{
		ID:     "000000",
		Secret: "999999",
		Domain: "http://localhost:14565",
	})
	manager.MapClientStorage(clientStore)

	srv := server.NewDefaultServer(manager)
	srv.SetAllowGetAccessRequest(true)
	srv.SetClientInfoHandler(server.ClientFormHandler)
	srv.SetUserAuthorizationHandler(func(w http.ResponseWriter, r *http.Request) (userID string, err error) {
		userID = "000000"
		return
	})
	srv.SetInternalErrorHandler(func(err error) (re *errors.Response) {
		log.Println("Internal Error:", err.Error())
		return
	})

	srv.SetResponseErrorHandler(func(re *errors.Response) {
		log.Println("Response Error:", re)
	})

	router := mux.NewRouter()

	httpSrv := http.Server{
		Addr:    ":9096",
		Handler: router,
	}

	router.HandleFunc("/authorize", func(w http.ResponseWriter, r *http.Request) {
		err := srv.HandleAuthorizeRequest(w, r)
		if err != nil {
			http.Error(w, err.Error(), http.StatusBadRequest)
		}
	})

	router.HandleFunc("/token", func(w http.ResponseWriter, r *http.Request) {
		srv.HandleTokenRequest(w, r)
	})

	go func() {
		log.Fatal(httpSrv.ListenAndServe())
	}()

	go func() {
		time.Sleep(time.Second * 15)
		//httpSrv.Shutdown(context.Background())
	}()

	conf := &oauth2.Config{
		ClientID:     "000000",
		ClientSecret: "999999",
		Scopes:       []string{},
		Endpoint: oauth2.Endpoint{
			AuthURL:   "http://localhost:9096/authorize",
			TokenURL:  "http://localhost:9096/token",
			AuthStyle: oauth2.AuthStyleInParams,
		},
	}

	nosrv, err := oauth2nosrv.New(conf)
	if err != nil {
		log.Fatal(err)
	}

	url := nosrv.AuthURL()
	log.Println(url)
	go func() {
		time.Sleep(time.Millisecond * 100)
		_, err = http.Get(url)
		if err != nil {
			log.Fatal(err)
		}
	}()
	ctx := context.Background()

	token, err := nosrv.StartAndWaitForToken(ctx)
	if err != nil {
		log.Fatal(err)
	}
	fmt.Println(token)
}
