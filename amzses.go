// Copyright 2011 Numrotron Inc.
// Use of this source code is governed by an MIT-style license
// that can be found in the LICENSE file.
//
// Developed at www.stathat.com by Patrick Crosby
// Contact us on twitter with any questions:  twitter.com/stat_hat

// amzses is a Go package to send emails using Amazon's Simple Email Service.

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
	data := make(url.Values)
	data.Add("Action", "SendEmail")
	data.Add("Source", from)
	data.Add("Destination.ToAddresses.member.1", to)
	data.Add("Message.Subject.Data", subject)
	data.Add("Message.Body.Text.Data", text)
	data.Add("Message.Body.Html.Data", html)
	return sesGet(data)
}

func VerifyEmail(email string) (string, os.Error) {
	data := make(url.Values)
	data.Add("Action", "VerifyEmailAddress")
	data.Add("EmailAddress", email)
	return sesGet(data)
}

func DeleteEmail(email string) (string, os.Error) {
	data := make(url.Values)
	data.Add("Action", "DeleteVerifiedEmailAddress")
	data.Add("EmailAddress", email)
	return sesGet(data)
}

func GetSendQuota() (string, os.Error) {
	data := make(url.Values)
	data.Add("Action", "GetSendQuota")
	return sesGet(data)
}

func GetSendStatistics() (string, os.Error) {
	data := make(url.Values)
	data.Add("Action", "GetSendStatistics")
	return sesGet(data)
}

func ListVerifiedEmail() (string, os.Error) {
	data := make(url.Values)
	data.Add("Action", "ListVerifiedEmailAddresses")
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
	data.Add("AWSAccessKeyId", accessKey)
	urlstr := fmt.Sprintf("%s?%s", endpoint, data.Encode())
	endpointURL, _ := url.Parse(urlstr)
	headers := map[string][]string{}

	now := time.UTC()
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
		return "", err
	}

	resultbody, _ := ioutil.ReadAll(r.Body)
	r.Body.Close()

	if r.StatusCode != 200 {
		return "", os.NewError(string(resultbody))
	}

	return string(resultbody), nil
}
