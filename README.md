Since some of our customers are in China mainland, and we use Cloudflare CDN  to provide the web service,  these days some of our customers in the China mainland reported that there are some network problems while using our product, to figure what is going on,  I decide to place some monitor nodes inside the china mainland. 

Because if we put our server inside china mainland to provide HTTP service, we should record our server's IP address and domain in the government with our company's name and it will take a long time, before that, we can not run exporter for Prometheus in the traditional way, because we are not able to open an HTTP port to export metrics for Prometheus. So I decide to deploy a push gateway outside the china mainland, push the metrics to the push gateway and make Prometheus get metrics from the push gateway.

This can take some benefits, like, I don't need to config Prometheus to scrape for every node, all I need to do is just deploy the monitor application inside the monitor node,  and all things are done, Prometheus can get the metrics and grafana can draw the images of the access time. 

First provide a URL list that can access from the internet, one URL one line, for example 

```
http://example.com
http://example1.com:8080
https://example2.com
```

 And follow [this guide](https://github.com/prometheus/pushgateway) to deploy the Prometheus gateway or just deploy the Prometheus gateway with docker 

```bash 
docker run -d -p 9091:9091 prom/pushgateway
```

Now download the pre-build binary from the release page,  or build the application yourself. 

```bash 
wget https://github.com/ChaunceyShannon/domainAccessTimeChecker/releases/download/v1.0.0/domainAccessTimeChecker-linux-amd64 
chmod 755 domainAccessTimeChecker-linux-amd64 
```

And run it  

```bash 
$ ./domainAccessTimeChecker-osx-amd64 \     
>    --urllist https://url.files.example.com/url.txt \
>    --pushgateway https://pushgateway.example.com \
>    --instance aliyun \    
>    --location shanghai.cn \
>    --doNotFollowRedirect true 
```

When it is running,  you can get some output like 

```bash 
10-17 20:46:25 3772521 [TRAC] (main.go:87) url "https://example1.com" access time: 0.5991010665893555
10-17 20:46:25 3772528 [TRAC] (main.go:87) url "https://example2.net" access time: 0.6949009895324707
10-17 20:46:26 3772482 [TRAC] (main.go:87) url "https://example3.com" access time: 1.7885558605194092
10-17 20:46:26 3772540 [TRAC] (main.go:87) url "https://example4.cc" access time: 0.4796111583709717
```

Check the Prometheus push gateway, ensure the data is there 

```bash 
push_failure_time_seconds{instance="aliyun",job="urlAccessTime",location="shanghai.cn"} 0
push_time_seconds{instance="aliyun",job="urlAccessTime",location="shanghai.cn"} 1.634474887393473e+09
url_access_time{instance="aliyun",job="urlAccessTime",location="shanghai.cn",url="http://example.com"} 0.7847859859466553
```

Configure Prometheus to scrape data from Prometheus push gateway 

```yaml 
scrape_configs:
  - job_name: "prometheus"
    static_configs:
      - targets: ["localhost:9090", "localhost:9091"] # just add the address for the prometheus gateway, because here I deploy prometheus and prometheus push gateway in the same instance, so I place localhost:9091 here.
```

At last, draw the image inside grafana, to monitor the access time in different locations for specific URL 

![image-20211017170200658](https://shareitnote.com/uploads/image.aDFT9V5wXzfgXDGZy7cT33.png)

If you deploy more nodes for monitoring, you can see more lines in the grafana.

Please note that either the domain is not configured, or is not taken(in GoDaddy, it will be pointed to a default advertisement web page if not taken), the established time will be -1, and this domain will no longer be check until 1 hour later. And if another error occurs, the established time will be -2. 

MyBlog: http://shareitnote.com

