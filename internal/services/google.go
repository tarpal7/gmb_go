package services

import (
	"io/ioutil"
	"net/http"
	"net/url"
	"strings"

	"github.com/BNPrashanth/poc-go-oauth2/internal/logger"

	"github.com/spf13/viper"
	"golang.org/x/oauth2"
	"golang.org/x/oauth2/google"

	"encoding/json"
	"fmt"
	"os"
)

var (
	oauthConfGl = &oauth2.Config{
		ClientID:     "",
		ClientSecret: "",
		RedirectURL:  "",
		Scopes:       []string{"https://www.googleapis.com/auth/plus.business.manage", "https://www.googleapis.com/auth/business.manage"},
		Endpoint:     google.Endpoint,
	}
	oauthStateStringGl = ""
)

type GetLocationsStruct struct {
	Locations []struct {
		Name       string `json:"name"`
		Title      string `json:"title"`
		Categories struct {
			PrimaryCategory struct {
				Name         string `json:"name"`
				DisplayName  string `json:"displayName"`
				ServiceTypes []struct {
					ServiceTypeID string `json:"serviceTypeId"`
					DisplayName   string `json:"displayName"`
				} `json:"serviceTypes"`
				MoreHoursTypes []struct {
					HoursTypeID          string `json:"hoursTypeId"`
					DisplayName          string `json:"displayName"`
					LocalizedDisplayName string `json:"localizedDisplayName"`
				} `json:"moreHoursTypes"`
			} `json:"primaryCategory"`
			AdditionalCategories []struct {
				Name         string `json:"name"`
				DisplayName  string `json:"displayName"`
				ServiceTypes []struct {
					ServiceTypeID string `json:"serviceTypeId"`
					DisplayName   string `json:"displayName"`
				} `json:"serviceTypes,omitempty"`
				MoreHoursTypes []struct {
					HoursTypeID          string `json:"hoursTypeId"`
					DisplayName          string `json:"displayName"`
					LocalizedDisplayName string `json:"localizedDisplayName"`
				} `json:"moreHoursTypes"`
			} `json:"additionalCategories"`
			StorefrontAddress struct {
				RegionCode         string   `json:"regionCode"`
				LanguageCode       string   `json:"languageCode"`
				PostalCode         string   `json:"postalCode"`
				AdministrativeArea string   `json:"administrativeArea"`
				Locality           string   `json:"locality"`
				AddressLines       []string `json:"addressLines"`
			} `json:"storefrontAddress"`
			Latlng struct {
				Latitude  float64 `json:"latitude"`
				Longitude float64 `json:"longitude"`
			} `json:"latlng"`
		} `json:"categories,omitempty"`
	} `json:"locations"`
	NextPageToken string `json:"nextPageToken"`
}

/*
InitializeOAuthGoogle Function
*/
func InitializeOAuthGoogle() {
	oauthConfGl.ClientID = viper.GetString("google.clientID")
	oauthConfGl.ClientSecret = viper.GetString("google.clientSecret")
	oauthConfGl.RedirectURL = viper.GetString("google.redirectURL")
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
		fmt.Println("promt", oauth2.ApprovalForce)
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
	// var b bytes.Buffer

	filter := r.URL.Query().Get("filter")
	filterType := r.URL.Query().Get("filter_type")

	newToken := getNewToken()
	if newToken == "" {
		w.Write([]byte("incorrecr refresh_token"))
	}

	link := "https://mybusinessbusinessinformation.googleapis.com/v1/accounts/117365090300665010175/locations?read_mask=name,title,latlng,storefrontAddress,categories&pageSize=100"

	if filterType == "google" {
		link = link + "&filter=categories=" + filter
		fmt.Println(link)
	}

	var bearer = "Bearer " + newToken
	fmt.Println(bearer)

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

	var locationsJSON GetLocationsStruct
	var newLocationsJSON GetLocationsStruct
	json.Unmarshal([]byte(body), &locationsJSON)

	fmt.Println("req", locationsJSON.NextPageToken)

	if filterType == "map" && filter != "" {
		for i := 0; i < len(locationsJSON.Locations); i++ {
			for j := 0; j < len(locationsJSON.Locations[i].Categories.PrimaryCategory.ServiceTypes); j++ {
				if locationsJSON.Locations[i].Categories.PrimaryCategory.ServiceTypes[j].ServiceTypeID == "job_type_id:fuel_delivery" {
					x := append(newLocationsJSON.Locations, locationsJSON.Locations[i])
					newLocationsJSON.Locations = x
					// fmt.Printf("locataion --->", locationsJSON.Locations[i].Name)
				}
			}
		}
		salida, _ := json.Marshal(&newLocationsJSON)
		fmt.Printf("reqqqqqqq --->", string(salida))
		w.Write([]byte(string(salida)))
	} else {
		w.Write([]byte(string(body)))
	}

}

/*
CallBackFromGoogle Function
*/
func GetLocationById(w http.ResponseWriter, r *http.Request) {

	id := strings.TrimPrefix(r.URL.Path, "/locations/")

	newToken := getNewToken()
	if newToken == "" {
		w.Write([]byte("incorrecr refresh_token"))
	}

	link := "https://mybusinessbusinessinformation.googleapis.com/v1/locations/" + id + "?read_mask=name,title,latlng,storefrontAddress,phoneNumbers,regularHours"

	var bearer = "Bearer " + newToken
	fmt.Println(bearer)

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

func GetReviewsByIdLocation(w http.ResponseWriter, r *http.Request) {

	id := strings.TrimPrefix(r.URL.Path, "/reviews/")
	pageTokenParam := r.URL.Query().Get("pageToken")

	newToken := getNewToken()
	if newToken == "" {
		w.Write([]byte("incorrecr refresh_token"))
	}

	link := "https://mybusiness.googleapis.com/v4/accounts/117365090300665010175/locations/" + id + "/reviews"

	if pageTokenParam != "" {
		link = link + "?pageToken=" + pageTokenParam
		fmt.Println(link)
	}

	var bearer = "Bearer " + newToken
	fmt.Println(bearer)

	// Create a new request using http
	req, err := http.NewRequest("GET", link, nil)
	fmt.Println(link)

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

func getNewToken() string {

	savedRefreshToken := readFile("refresh_token.txt")
	data := url.Values{
		"grant_type":    {"refresh_token"},
		"client_id":     {oauthConfGl.ClientID},
		"client_secret": {oauthConfGl.ClientSecret},
		"refresh_token": {savedRefreshToken},
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
