# oauth2nosrv

Library for obtaining oauth2 token without having server running (i.e. in cli utils)

```go

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
	// print url to user
	log.Println(url)

	ctx := context.Background()

	// wait for user clicking on url
	token, err := nosrv.StartAndWaitForToken(ctx)
	if err != nil {
		log.Fatal(err)
	}
	fmt.Println(token)
```