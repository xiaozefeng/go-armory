package apps

import (
	"fmt"
	"github.com/xiaozefeng/go-armory/cmd/publish/app"
	"log"
	"os/exec"
)

func init()  {
	app.Register(&Booking{"hotel-platform-platform-booking"})
}

type Booking struct {
	appid string
}

func (b *Booking) Publish(ips[]string) {
	for _, ip := range ips {
		remoteCommand := fmt.Sprintf("ssh root@%s 'sh /usr/local/%s/web-skywalking.sh restart; sleep 3; exit;'", ip, b.appid)
		log.Printf("remote command: %s", remoteCommand)
		command := exec.Command("bash", "-c", remoteCommand)
		output, err := command.Output()
		if err !=nil{
			continue
		}
		fmt.Printf("%s\n", output)
	}
}

func (b *Booking) GetAppID() string  {
	return b.appid
}


