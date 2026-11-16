module github.com/tinfoilsh/confidential-agent-monitor/connector/browser

go 1.27.3

require (
	github.com/chromedp/cdproto v0.157.8
	github.com/chromedp/chromedp v0.20.1
	github.com/tinfoilsh/confidential-agent-monitor v0.0.0
)

require github.com/go-json-experiment/json v0.0.0-20260213210345-44df1a37e875 // indirect

replace github.com/tinfoilsh/confidential-agent-monitor => ../..
