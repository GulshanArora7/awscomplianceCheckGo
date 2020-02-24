package main

import (
	"bytes"
	"encoding/json"
	"fmt"
	"io/ioutil"
	"net/http"
	"os"
	"strings"
	"time"

	"github.com/aws/aws-sdk-go/aws"
	"github.com/aws/aws-sdk-go/aws/session"
	"github.com/aws/aws-sdk-go/service/cloudtrail"
)

// SliceCard struct
type SliceCard struct {
	Cards []Cards `json:"cards"`
}

// Header struct
type Header struct {
	Title    string `json:"title"`
	Subtitle string `json:"subtitle"`
	ImageURL string `json:"imageUrl"`
}

// KeyValue struct
type KeyValue struct {
	TopLabel string `json:"topLabel"`
	Content  string `json:"content"`
}

// OpenLink struct
type OpenLink struct {
	URL string `json:"url"`
}

// OnClick struct
type OnClick struct {
	OpenLink OpenLink `json:"openLink"`
}

// TextButton struct
type TextButton struct {
	Text    string  `json:"text"`
	OnClick OnClick `json:"onClick"`
}

// Buttons struct
type Buttons struct {
	TextButton TextButton `json:"textButton"`
}

// Widgets struct
type Widgets struct {
	KeyValue *KeyValue `json:"keyValue,omitempty"`
	Buttons  []Buttons `json:"buttons,omitempty"`
}

// Sections struct
type Sections struct {
	Widgets []Widgets `json:"widgets"`
}

// Cards struct
type Cards struct {
	Header   Header     `json:"header"`
	Sections []Sections `json:"sections"`
}

// =========================================

// Cidr struct
type cidr struct {
	CidrIP string `json:"cidrIp"`
}

// ipRanges struct
type ipRanges struct {
	Cidr []cidr `json:"items"`
}

// iTems struct
type iTems struct {
	FromPort int      `json:"fromPort"`
	ToPort   int      `json:"toPort"`
	IPRanges ipRanges `json:"ipRanges"`
}

// ipPermissions struct
type ipPermissions struct {
	Items []iTems `json:"items"`
}

// requestParameters struct
type requestParameters struct {
	GroupID       string        `json:"groupId"`
	IPPermissions ipPermissions `json:"ipPermissions"`
}

// userIdentity struct
type userIdentity struct {
	Type        string `json:"type"`
	PrincipalID string `json:"principalId"`
	Arn         string `json:"arn"`
	AccountID   string `json:"accountId"`
}

// cloudtraileventDetails struct
type cloudtraileventDetails struct {
	EventVersion      string            `json:"eventVersion"`
	UserIdentity      userIdentity      `json:"userIdentity"`
	EventTime         time.Time         `json:"eventTime"`
	EventSource       string            `json:"eventSource"`
	EventName         string            `json:"eventName"`
	AwsRegion         string            `json:"awsRegion"`
	SourceIPAddress   string            `json:"sourceIPAddress"`
	UserAgent         string            `json:"userAgent"`
	RequestParameters requestParameters `json:"requestParameters"`
	RequestID         string            `json:"requestID"`
	EventID           string            `json:"eventID"`
}

var blockIP = "0.0.0.0/0"

var message string

var webhook = os.Getenv("WEBHOOK_HANGOUTSCHAT")

func checkError(e error) {
	if e != nil {
		panic(e)
	}
}

func containsapiEvent(arr []string, str string) bool {
	for _, a := range arr {
		if a == str {
			return true
		}
	}
	return false
}

func postHangout(url string, body []byte) error {
	client := &http.Client{
		Timeout: time.Second * 10,
	}
	req, err := http.NewRequest("POST", url, bytes.NewBuffer(body))
	if err != nil {
		fmt.Printf("[ERROR]1 %s", err)
	}
	req.Header.Set("Content-Type", "application/json")
	resp, err := client.Do(req)
	if err != nil {
		fmt.Printf("[ERROR]2 %s", err)
	}
	if resp.StatusCode != 200 {
		bodyText, err := ioutil.ReadAll(resp.Body)
		if err != nil {
			fmt.Printf("[ERROR]3 %s", err)
		}
		s := string(bodyText)
		fmt.Printf("[LOG]: %s ; %s", resp.Status, s)
	}
	defer resp.Body.Close()
	return nil
}

func evaluateComplainceSg(cloudtrailEvents string) error {
	results := new(cloudtraileventDetails)
	json.Unmarshal([]byte(cloudtrailEvents), &results)
	var sgID string
	var ipAddr string
	var openPort string
	for _, v := range results.RequestParameters.IPPermissions.Items {
		for _, value := range v.IPRanges.Cidr {
			ipStr := fmt.Sprintf("%s", value.CidrIP)
			if strings.EqualFold(blockIP, ipStr) {
				openPort += fmt.Sprintf("From Port: %d --> To Port: %d \n", v.FromPort, v.ToPort)
				sgID = fmt.Sprintf("%s", results.RequestParameters.GroupID)
				ipAddr = fmt.Sprintf("%s", ipStr)
			}
		}
	}
	keyvalue1 := KeyValue{}
	keyvalue1.TopLabel = fmt.Sprintf("SECURITY GROUP ID")
	keyvalue1.Content = fmt.Sprintf(sgID)
	keyvalue2 := KeyValue{}
	keyvalue2.TopLabel = fmt.Sprintf("CIDR")
	keyvalue2.Content = fmt.Sprintf(ipAddr)
	keyvalue3 := KeyValue{}
	keyvalue3.TopLabel = fmt.Sprintf("PORT NUMBER")
	keyvalue3.Content = fmt.Sprintf(openPort)
	widget1 := Widgets{
		KeyValue: &keyvalue1,
	}
	widget2 := Widgets{
		KeyValue: &keyvalue2,
	}
	widget3 := Widgets{
		KeyValue: &keyvalue3,
	}
	var button []Buttons
	newbutton := Buttons{}
	newbutton.TextButton.Text = fmt.Sprintf("CHECK ON AWS")
	newbutton.TextButton.OnClick.OpenLink.URL = fmt.Sprintf("https://console.aws.amazon.com/")
	button = append(button, newbutton)
	widget4 := Widgets{
		Buttons: button,
	}
	header := Header{
		Title:    "AWS Security Alert",
		Subtitle: "SecurityGroup Issue",
		ImageURL: "https://a0.awsstatic.com/libra-css/images/logos/aws_logo_smile_1200x630.png",
	}
	section1 := Sections{
		Widgets: []Widgets{widget1},
	}
	section2 := Sections{
		Widgets: []Widgets{widget2},
	}
	section3 := Sections{
		Widgets: []Widgets{widget3},
	}
	section4 := Sections{
		Widgets: []Widgets{widget4},
	}
	card := Cards{
		Header:   header,
		Sections: []Sections{section1, section2, section3, section4},
	}
	formPost := SliceCard{
		Cards: []Cards{card},
	}

	bodymarshal, err := json.Marshal(&formPost)
	if err != nil {
		fmt.Printf("[ERROR] %s", err)
	}
	err = postHangout(webhook, bodymarshal)
	if err != nil {
		fmt.Printf("[ERROR] %s", err)
	}
	return nil
}

func main() {
	sess := session.Must(session.NewSessionWithOptions(session.Options{
		SharedConfigState: session.SharedConfigEnable,
	}))
	cloudtrailSvc := cloudtrail.New(sess)

	allowedapiEvent := []string{"AuthorizeSecurityGroupIngress", "RevokeSecurityGroupIngress"}

	input := &cloudtrail.LookupEventsInput{EndTime: aws.Time(time.Now())}
	resp, err := cloudtrailSvc.LookupEvents(input)
	if err != nil {
		fmt.Println("Got error calling CloudTrail Events:")
		fmt.Println(err.Error())
		os.Exit(1)
	}
	for _, event := range resp.Events {
		eventName := aws.StringValue(event.EventName)
		fmt.Println(eventName, event.EventTime)
		b := containsapiEvent(allowedapiEvent, eventName)
		if b == true {
			cloudtrailEvent := aws.StringValue(event.CloudTrailEvent)
			evaluateComplainceSg(cloudtrailEvent)
		}
	}
}
