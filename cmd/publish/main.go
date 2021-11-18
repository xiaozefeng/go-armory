package main

import (
	"encoding/json"
	"flag"
	"fmt"
	"github.com/xiaozefeng/go-armory/cmd/publish/app"
	"io/ioutil"
	"log"
	"net/http"
	"strings"
)

var svcs string
var serviceServer string

var publishers = app.GetAllPublishers()

func main() {
	// 读取要发布的服务列表
	flag.StringVar(&svcs, "s", "", "service list")
	flag.StringVar(&serviceServer, "server", "", "service server url")
	flag.Parse()

	if svcs == "" || serviceServer == "" {
		flag.PrintDefaults()
		return
	}

	for _, v := range strings.Split(svcs, `,`) {
		if v == "" {
			continue
		}
		// 获取服务的真实ip地址
		apps, err := getApps(v)
		if err != nil {
			log.Printf("获取app失败，%v", err)
			continue
		}
		for _, v := range apps {
			log.Printf("获取app: %+v", v)
			if publisher, ok := publishers[v.Name]; ok {
				publisher.Publish(v.Ips)
			}
		}
	}
}

func getApps(appid string) ([]*App, error) {
	resp, err := http.Get(fmt.Sprintf("%s?appID=%s", serviceServer, appid))
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()
	var apps []*App
	b, err := ioutil.ReadAll(resp.Body)
	if err != nil {
		return nil, err
	}
	err = json.Unmarshal(b, &apps)
	if err != nil {
		return nil, err
	}
	return apps, nil
}

type App struct {
	Name string   `json:"name"`
	Ips  []string `json:"ips"`
}
