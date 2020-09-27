# webfuzz

This is a fuzzer against web applications.
It uses request URI and response to infer some coverage to guid fuzzing
It uses libFuzzer extra counters

Utils
------

* Pcap2corp : takes a pcap as input and extracts a seed corpus out of it (ie the HTTP requests)
* stringdict : parses a Go file and extract the constant strings out of them to generate a libFuzzer dictionary  

TODOs
------

* use the replies to infer URIs and parameters (ie add them to the dictionary) ie crawling capabilities
* have a flexible way to get more valid requests (ie less fuzzing of the HTTP protocol, and the json parser...)
* find duplicate coverage (ie if uri /foo/bar, /foo/baz and /foo/whatever are aliases to the same code)
* create an authenticated session (without needing to reuse the cookie from the seed corpus)
