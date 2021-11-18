package app

import _ "github.com/xiaozefeng/go-armory/cmd/publish/app/apps"

type Publisher interface {
	Publish(ips []string)
	GetAppID() string
}

var publishers []Publisher

func Register(publisher Publisher) {
	publishers = append(publishers, publisher)
}

func GetAllPublishers() map[string]Publisher {
	var m map[string]Publisher
	for _, v := range publishers {
		m[v.GetAppID()] = v
	}
	return m
}
