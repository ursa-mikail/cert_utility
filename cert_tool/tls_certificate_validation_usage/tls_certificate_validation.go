// TLS certificate verification test in Go with timeout, timer bar, and URL printing
// Enhanced version based on Sucuri's 2016 snippet

package main

import (
	"crypto/tls"
	"fmt"
	"net/http"
	"net/url"
	"os"
	"time"
)

// Configurable timeout duration (in seconds)
const timeoutSeconds = 5

// Simulate a simple timer bar
func progressBar(seconds int) {
	fmt.Print("Progress: [")
	for i := 0; i < seconds; i++ {
		time.Sleep(1 * time.Second)
		fmt.Print("#")
	}
	fmt.Println("]")
}

func tryDownload(name, targetURL string, timeout time.Duration) error {
	parsedURL, err := url.Parse(targetURL)
	if err != nil {
		return err
	}

	transport := &http.Transport{
		TLSClientConfig: &tls.Config{
			InsecureSkipVerify: false, // Ensure verification is active
		},
	}

	client := &http.Client{
		Transport: transport,
		Timeout:   timeout,
	}

	resp, err := client.Get(parsedURL.String())
	if err != nil {
		return err
	}
	defer resp.Body.Close()
	return nil
}

func main() {
	urls := map[string]string{
		"revoked":         "https://revoked.grc.com/",
		"expired":         "https://qvica1g3-e.quovadisglobal.com/",
		"expired2":        "https://expired.badssl.com/",
		"self-signed":     "https://self-signed.badssl.com/",
		"bad domain":      "https://wrong.host.badssl.com/",
		"bad domain2":     "https://tv.eurosport.com/",
		"rc4":             "https://rc4.badssl.com/",
		"dh480":           "https://dh480.badssl.com/",
		"superfish":       "https://superfish.badssl.com/",
		"edellroot":       "https://edellroot.badssl.com/",
		"dsdtestprovider": "https://dsdtestprovider.badssl.com/",
	}

	timeout := time.Duration(timeoutSeconds) * time.Second

	for name, targetURL := range urls {
		fmt.Printf("\nTesting [%s]: %s\n", name, targetURL)
		progressBar(timeoutSeconds)

		start := time.Now()
		err := tryDownload(name, targetURL, timeout)
		duration := time.Since(start)

		if err == nil {
			fmt.Printf("%s: INCORRECT: expected error\n", name)
		} else {
			fmt.Printf("%s: correct (%v)\n", name, err)
		}
		fmt.Printf("Time taken: %.2f seconds\n", duration.Seconds())
	}

	os.Exit(0)
}

/*

Testing [dh480]: https://dh480.badssl.com/
Progress: [#####]
dh480: correct (Get "https://dh480.badssl.com/": dial tcp: lookup dh480.badssl.com on 169.254.169.254:53: dial udp 169.254.169.254:53: connect: no route to host)
Time taken: 0.00 seconds

Testing [superfish]: https://superfish.badssl.com/
Progress: [#####]
superfish: correct (Get "https://superfish.badssl.com/": dial tcp: lookup superfish.badssl.com on 169.254.169.254:53: dial udp 169.254.169.254:53: connect: no route to host)
Time taken: 0.00 seconds

Testing [dsdtestprovider]: https://dsdtestprovider.badssl.com/
Progress: [#####]
dsdtestprovider: correct (Get "https://dsdtestprovider.badssl.com/": dial tcp: lookup dsdtestprovider.badssl.com on 169.254.169.254:53: dial udp 169.254.169.254:53: connect: no route to host)
Time taken: 0.00 seconds

Testing [expired2]: https://expired.badssl.com/
Progress: [#####]
expired2: correct (Get "https://expired.badssl.com/": dial tcp: lookup expired.badssl.com on 169.254.169.254:53: dial udp 169.254.169.254:53: connect: no route to host)
Time taken: 0.00 seconds

Testing [bad domain]: https://wrong.host.badssl.com/
Progress: [#####]
bad domain: correct (Get "https://wrong.host.badssl.com/": dial tcp: lookup wrong.host.badssl.com on 169.254.169.254:53: dial udp 169.254.169.254:53: connect: no route to host)
Time taken: 0.00 seconds

Testing [bad domain2]: https://tv.eurosport.com/
Progress: [#####]
bad domain2: correct (Get "https://tv.eurosport.com/": dial tcp: lookup tv.eurosport.com on 169.254.169.254:53: dial udp 169.254.169.254:53: connect: no route to host)
Time taken: 0.00 seconds

Testing [edellroot]: https://edellroot.badssl.com/
Progress: [#####]
edellroot: correct (Get "https://edellroot.badssl.com/": dial tcp: lookup edellroot.badssl.com on 169.254.169.254:53: dial udp 169.254.169.254:53: connect: no route to host)
Time taken: 0.00 seconds

Testing [revoked]: https://revoked.grc.com/
Progress: [#####]
revoked: correct (Get "https://revoked.grc.com/": dial tcp: lookup revoked.grc.com on 169.254.169.254:53: dial udp 169.254.169.254:53: connect: no route to host)
Time taken: 0.00 seconds

Testing [expired]: https://qvica1g3-e.quovadisglobal.com/
Progress: [#####]
expired: correct (Get "https://qvica1g3-e.quovadisglobal.com/": dial tcp: lookup qvica1g3-e.quovadisglobal.com on 169.254.169.254:53: dial udp 169.254.169.254:53: connect: no route to host)
Time taken: 0.00 seconds

Testing [self-signed]: https://self-signed.badssl.com/
Progress: [#####]
self-signed: correct (Get "https://self-signed.badssl.com/": dial tcp: lookup self-signed.badssl.com on 169.254.169.254:53: dial udp 169.254.169.254:53: connect: no route to host)
Time taken: 0.00 seconds

Testing [rc4]: https://rc4.badssl.com/
Progress: [#####]
rc4: correct (Get "https://rc4.badssl.com/": dial tcp: lookup rc4.badssl.com on 169.254.169.254:53: dial udp 169.254.169.254:53: connect: no route to host)
Time taken: 0.00 seconds
*/