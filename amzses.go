
package amzses

import (
	"os"
	"crypto/hmac"
	"encoding/base64"
	"fmt"
	"github.com/stathat/jconfig"
	"io/ioutil"
	"http"
	"url"
	"time"
)

const (
	endpoint = "https://email.us-east-1.amazonaws.com"
)

var accessKey, secretKey string

type AmazonResponse struct {
	MessageId string `xml:"SendEmailResult>MessageId>"`
	RequestId string `xml:"ResponseMetadata>RequestId>"`
}

func init() {
	config := jconfig.LoadConfig("aws.conf")
	accessKey = config.GetString("aws_access_key")
	secretKey = config.GetString("aws_secret_key")
}

func SendMail(from, to, subject, text, html string) (string, os.Error) {
	//var r AmazonResponse

	data := make(url.Values)
	data.Add("Action", "SendEmail")
	data.Add("Source", from)
	data.Add("Destination.ToAddresses.member.1", to)
	data.Add("Message.Subject.Data", subject)
	data.Add("Message.Body.Text.Data", text)
	data.Add("Message.Body.Html.Data", html)
	data.Add("AWSAccessKeyId", accessKey)
	return sesGet(data)
}

func authorizationHeader(date string) []string {
	h := hmac.NewSHA256([]uint8(secretKey))
	h.Write([]uint8(date))
	signature := base64.StdEncoding.EncodeToString(h.Sum())
	auth := fmt.Sprintf("AWS3-HTTPS AWSAccessKeyId=%s, Algorithm=HmacSHA256, Signature=%s", accessKey, signature)
	return []string{auth}
}

func sesGet(data url.Values) (string, os.Error) {
	urlstr := fmt.Sprintf("%s?%s", endpoint, data.Encode())
	endpointURL, _ := url.Parse(urlstr)
	headers := map[string][]string{}

	now := time.UTC()
	// date format: "Tue, 25 May 2010 21:20:27 +0000"
	date := now.Format("Mon, 02 Jan 2006 15:04:05 -0700")
	headers["Date"] = []string{date}

	h := hmac.NewSHA256([]uint8(secretKey))
	h.Write([]uint8(date))
	signature := base64.StdEncoding.EncodeToString(h.Sum())
	auth := fmt.Sprintf("AWS3-HTTPS AWSAccessKeyId=%s, Algorithm=HmacSHA256, Signature=%s", accessKey, signature)
	headers["X-Amzn-Authorization"] = []string{auth}

	req := http.Request{
		URL:        endpointURL,
		Method:     "GET",
		ProtoMajor: 1,
		ProtoMinor: 1,
		Close:      true,
		Header:     headers,
	}


	r, err := http.DefaultClient.Do(&req)
	if err != nil {
		//log.Printf("http error: %s", err)
		return "", err
	}

	resultbody, _ := ioutil.ReadAll(r.Body)
	r.Body.Close()

	if r.StatusCode != 200 {
		//log.Printf("error, status = %d", r.StatusCode)

		//log.Printf("error response: %s", resultbody)
		return "", os.NewError(string(resultbody))
	}

	return string(resultbody), nil
}
