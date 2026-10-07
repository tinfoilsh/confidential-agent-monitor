// Command site serves the browser test pages for trying the browser connector by hand.
// It is test data: nothing in the monitor imports it.
package main

import (
	"embed"
	"flag"
	"log"
	"net/http"
	"time"
)

// slowPage is how long /slow takes to answer, long enough to pause during the load.
const slowPage = 10 * time.Second

//go:embed *.html
var pages embed.FS

func main() {
	listen := flag.String("listen", "127.0.0.1:8765", "address to serve the test pages on")
	flag.Parse()
	http.Handle("/", http.FileServerFS(pages))
	http.HandleFunc("/slow", func(w http.ResponseWriter, r *http.Request) {
		time.Sleep(slowPage)
		http.Redirect(w, r, "/index.html", http.StatusFound)
	})
	log.Printf("test pages on http://%s/", *listen)
	log.Fatal(http.ListenAndServe(*listen, nil))
}
