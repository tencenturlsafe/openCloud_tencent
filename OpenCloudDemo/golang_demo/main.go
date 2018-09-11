package main

import (
	"log"
	"flag"
	"os"
	"strconv"
	"github.com/liufengsoft/openCloud_tencent/OpenCloudDemo/golang_demo/lib"
)

var appKey = os.Getenv("APP_KEY")
var appID = os.Getenv("APP_ID")
var checkedURL string
var logger = log.New(os.Stdout, "safeURL", log.Ldate|log.Ltime|log.Lshortfile)

func init() {
	flag.StringVar(&checkedURL, "URL", "", "URL wating for checked")
}

func main() {
	flag.Parse()
	if checkedURL == "" {
		log.Fatalf("URL param is empty")
	}
	if appID == "" {
		logger.Fatal("can not found appId")
	}
	if appKey == "" {
		logger.Fatal("can not found appKey")
	}
	appIDInt, err := strconv.Atoi(appID)
	if err != nil {
		logger.Fatalf("appId parse error: %s", err.Error())
	}
	body, err := urlsafe.SafeQuery(checkedURL, appIDInt, appKey)
	if err != nil {
		logger.Fatalln(err.Error())
	}
	logger.Print(string(body))
}
