package services

import (
	"io/ioutil"
	"net/http"
	"net/url"

	"github.com/BNPrashanth/poc-go-oauth2/internal/logger"

	"github.com/spf13/viper"
	"golang.org/x/oauth2"
	"golang.org/x/oauth2/google"

	"fmt"
 	 "encoding/json"
	  "os"
)

var (
	oauthConfGl = &oauth2.Config{
		ClientID:     "",
		ClientSecret: "",
		RedirectURL:  "http://localhost:3001/auth/google/callback",
		Scopes:       []string{"https://www.googleapis.com/auth/plus.business.manage","https://www.googleapis.com/auth/business.manage"},
		Endpoint:     google.Endpoint,
	}
	oauthStateStringGl = ""
)

/*
InitializeOAuthGoogle Function
*/
func InitializeOAuthGoogle() {
	oauthConfGl.ClientID = viper.GetString("google.clientID")
	oauthConfGl.ClientSecret = viper.GetString("google.clientSecret")
	oauthStateStringGl = viper.GetString("oauthStateString")
}

/*
HandleGoogleLogin Function
*/
func HandleGoogleLogin(w http.ResponseWriter, r *http.Request) {
	HandleLogin(w, r, oauthConfGl, oauthStateStringGl)
}

/*
CallBackFromGoogle Function
*/
func CallBackFromGoogle(w http.ResponseWriter, r *http.Request) {
	logger.Log.Info("Callback-gl..")

	state := r.FormValue("state")
	logger.Log.Info(state)
	if state != oauthStateStringGl {
		logger.Log.Info("invalid oauth state, expected " + oauthStateStringGl + ", got " + state + "\n")
		http.Redirect(w, r, "/", http.StatusTemporaryRedirect)
		return
	}

	code := r.FormValue("code")
	logger.Log.Info(code)

	if code == "" {
		logger.Log.Warn("Code not found..")
		w.Write([]byte("Code Not Found to provide AccessToken..\n"))
		reason := r.FormValue("error_reason")
		if reason == "user_denied" {
			w.Write([]byte("User has denied Permission.."))
		}
		// User has denied access..
		http.Redirect(w, r, "/", http.StatusTemporaryRedirect)
	} else {
		
		fmt.Println("setaccess", oauth2.AccessTypeOffline)
		fmt.Println("promt", oauth2.ApprovalForce )
		token, err := oauthConfGl.Exchange(oauth2.NoContext, code)

		fmt.Println("token", token)

		if err != nil {
			logger.Log.Error("oauthConfGl.Exchange() failed with " + err.Error() + "\n")
			return
		}
		logger.Log.Info("TOKEN>> AccessToken>> " + token.AccessToken)
		logger.Log.Info("TOKEN>> Expiration Time>> " + token.Expiry.String())
		logger.Log.Info("TOKEN>> RefreshToken>> " + token.RefreshToken)

		if token.RefreshToken != "" {
			saveRefreshToken(token.RefreshToken)
		}
	
		w.Write([]byte("You can use gmb\n"))
		// w.Write([]byte(string(token.AccessToken)))
		return
	}
}


/*
CallBackFromGoogle Function
*/
func GetLocatios(w http.ResponseWriter, r *http.Request) {
	
		newToken := getNewToken()
		if  newToken == "" {
			w.Write([]byte("incorrecr refresh_token"))
		}

		link := "https://mybusinessbusinessinformation.googleapis.com/v1/accounts/117365090300665010175/locations?read_mask=name,title,latlng";

		var bearer = "Bearer " + newToken

		// Create a new request using http
		req, err := http.NewRequest("GET", link, nil)

		// add authorization header to the req
		req.Header.Add("Authorization", bearer)

		// Send req using http Client
		client := &http.Client{}
		resp, err := client.Do(req)
		if err != nil {
			fmt.Println("Error on response.\n[ERROR] -", err)
		}
		defer resp.Body.Close()

		body, err := ioutil.ReadAll(resp.Body)
		if err != nil {
			fmt.Println("Error while reading the response bytes:", err)
		}
		w.Write([]byte(string(body)))
}


func getNewToken() string{

	savedRefreshToken := readFile("refresh_token.txt")
	data := url.Values {
		"grant_type": 	{"refresh_token"},
		"client_id": {oauthConfGl.ClientID},
		"client_secret": {oauthConfGl.ClientSecret},
		"refresh_token":{savedRefreshToken},
	}

	respToken, err := http.PostForm("https://accounts.google.com/o/oauth2/token", data)

	if err != nil {
		logger.Log.Error(err.Error())
		return ""
	}
	var newToken map[string]interface{}
	json.NewDecoder(respToken.Body).Decode(&newToken)
	return newToken["access_token"].(string)
}


func saveRefreshToken(refreshToken string) {

	file, err := os.Create("refresh_token.txt")
	if err != nil {
		fmt.Println(err)
	} else {
		file.WriteString(refreshToken)
	}
	file.Close()
}

func readFile(fileName string) string {
	fContent, err := ioutil.ReadFile(fileName)
	if err != nil {
		fmt.Println(err)
	}
	fmt.Println(string(fContent))
	return string(fContent)
}