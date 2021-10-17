package main

import (
	"os"
	"os/signal"
	"syscall"

	"github.com/prometheus/client_golang/prometheus"
	"github.com/prometheus/client_golang/prometheus/push"
)

var urlAccessTime *prometheus.GaugeVec

type argStruct struct {
	urllist             string
	pushgateway         string
	location            string
	instance            string
	doNotFollowRedirect bool
}

var args = &argStruct{}

func main() {
	a := argparser("")
	args.urllist = a.get("", "urllist", "https://example.com/url.txt", "address for url list file")
	args.pushgateway = a.get("", "pushgateway", "https://gw.example.com/", "address for push gateway")
	args.instance = a.get("", "instance", "aws", "test node name")
	args.location = a.get("", "location", "montreal.ca", "test node location")
	args.doNotFollowRedirect = a.getBool("", "doNotFollowRedirect", "false", "do not follow redirect while test the url")
	a.parseArgs()

	lock := getLock()

	sgc := make(chan os.Signal, 1)
	signal.Notify(sgc, os.Interrupt, syscall.SIGTERM)
	go func(chan os.Signal) {
		<-sgc
		lg.info("Cleanup...")
		lock.acquire()
		err := push.New(args.pushgateway, "urlAccessTime").
			Grouping("instance", args.instance).
			Grouping("location", args.location).
			Delete()
		panicerr(err)
		exit(0)
	}(sgc)

	urlAccessTime = prometheus.NewGaugeVec(prometheus.GaugeOpts{
		Name: "url_access_time",
		Help: "Url Access Time",
	}, []string{"url"})

	// 如果域名无法解析或者https有问题, 则1小时内不再尝试
	hostNotFound := getTTLCache(3600)

	for {
		lg.trace("Start a new round...")
		start := now()
		if err := try(func() {
			resp := httpGet(args.urllist)
			if resp.statusCode != 200 {
				panicerr("Status code not 200 while get url list")
			}

			var urls []string
			for _, url := range strSplitlines(resp.content) {
				url = strStrip(url)
				if url != "" && !hostNotFound.exists(url) && !itemInArray(url, urls) {
					urls = append(urls, url)
				}
			}

			rl := getRateLimit(len(urls) / 15)
			for _, url := range urls {
				rl.take()
				go func(url string) {
					var establish float64
					start := now()
					if err := try(func() {
						resp = httpGet(url, httpConfig{doNotFollowRedirect: args.doNotFollowRedirect})
					}).Error; err != nil {
						lg.trace("Error while check url \""+url+"\":", err.Error())
						if strIn("no such host", err.Error()) || strIn("\": EOF >>", err.Error()) {
							hostNotFound.set(url, "")
							establish = -1 // Either the domain is not configured, or is not taken(in godaddy, it will be pointed to a default advertisement web page if not taken.)
						} else {
							establish = -2 // Other errors.
						}
					} else {
						establish = now() - start
						lg.trace("url \""+url+"\" access time:", establish)
					}

					urlAccessTime.With(prometheus.Labels{"url": url}).Set(establish)
				}(url)
			}
		}).Error; err != nil {
			lg.error(err)
		}

		lock.acquire()
		err := push.New(args.pushgateway, "urlAccessTime").
			Collector(urlAccessTime).
			Grouping("instance", args.instance).
			Grouping("location", args.location).
			Push()
		lock.release()

		if err != nil {
			lg.error("Error while push metrics:", err)
		}
		sleep(15 - (now() - start))
	}
}
