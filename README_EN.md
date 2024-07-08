<!-- Improved compatibility of back to top link: See: https://github.com/emo-crab/observer_ward/pull/73 -->
<a name="readme-top"></a>
<!--
*** Thanks for checking out the observer_ward. If you have a suggestion
*** that would make this better, please fork the repo and create a pull request
*** or simply open an issue with the tag "enhancement".
*** Don't forget to give the project a star!
*** Thanks again! Now go create something AMAZING! :D
-->



<!-- PROJECT SHIELDS -->
<!--
*** I'm using markdown "reference style" links for readability.
*** Reference links are enclosed in brackets [ ] instead of parentheses ( ).
*** See the bottom of this document for the declaration of the reference variables
*** for contributors-url, forks-url, etc. This is an optional, concise syntax you may use.
*** https://www.markdownguide.org/basic-syntax/#reference-style-links
-->
[![Contributors][contributors-shield]][contributors-url]
[![Forks][forks-shield]][forks-url]
[![Stargazers][stars-shield]][stars-url]
[![Issues][issues-shield]][issues-url]
[![MIT License][license-shield]][license-url]




<!-- PROJECT LOGO -->
<br />
<div align="center">
  <a href="https://github.com/emo-crab/observer_ward">
    <img src="images/logo.svg" alt="Logo">
  </a>

<h3 align="center">observer_ward(侦查守卫)</h3>

  <p align="center">
    Customizable fingerprint scan tool based on yaml
    <br />
    <a href="https://github.com/emo-crab/observer_ward"><strong>Explore the docs »</strong></a>
    <br />
    <br />
    <a href="https://github.com/emo-crab/observer_ward">View Demo</a>
    ·
    <a href="https://github.com/emo-crab/observer_ward/issues">Report Bug</a>
    ·
    <a href="https://github.com/emo-crab/observer_ward/issues">Request Feature</a>
  </p>
</div>

<!-- ABOUT THE PROJECT -->

## About The Project

![Product Name Screen Shot][product-screenshot]

- like nuclei yaml template
- web and server fingerprint
- common platform enumeration ([CPE](https://scap.kali-team.cn/cpe/)) binding name
- community based [fingerprint](https://github.com/0x727/FingerprintHub)
- integrated [Nuclei](https://github.com/projectdiscovery/nuclei) verification vulnerability

<p align="right">(<a href="#readme-top">back to top</a>)</p>

<!-- INSTALL -->

## Install

- build from source, more: GitHub
  action [workflow](https://github.com/emo-crab/observer_ward/blob/main/.github/workflows/post-release.yml)

```bash,no-run
cargo build --release --manifest-path=observer_ward/Cargo.toml
```

- download from [release](https://github.com/emo-crab/observer_ward/releases)
- install from homebrew on macOS

```bash,no-run
brew install observer_ward
```

<!-- GETTING STARTED -->

## Getting Started
```bash,no-run
➜  observer_ward git:(main) ✗ ./observer_ward -t https://www.example.com/                                 
[INFO  observer_ward] probes loaded: 2223
[INFO  observer_ward] target loaded: 1
[INFO  observer_ward] optimized probes: 7
target: https://www.example.com/
 |_ uri:[ https://www.example.com/ [0example]  <Example Domain> (200 OK) ] 
```
- using

```bash,no-run
➜  observer_ward git:(main) ✗ ./observer_ward --help                                                                      
Usage: observer_ward [-l <list>] [-t <target...>] [-p <probe-path>] [--probe-dir <probe-dir>] [--ua <ua>] [--mode <mode>] [--timeout <timeout>] [--thread <thread>] [--proxy <proxy>] [--or] [--plugin <plugin>] [-o <output>] [--format <format>] [--no-color] [--nuclei-args <nuclei-args>] [--silent] [--debug] [--config-dir <config-dir>] [--update-self] [-u] [--update-plugin]

observer_ward

Options:
  -l, --list        multiple targets from file path
  -t, --target      the target (required)
  -p, --probe-path  customized fingerprint json file path
  --probe-dir       customized fingerprint yaml file dir
  --ua              customized ua
  --mode            mode probes option[index,danger,all] defaule: all
  --timeout         set request timeout.
  --thread          number of concurrent threads.
  --proxy           proxy to use for requests
                    (ex:[http(s)|socks5(h)]://host:port)
  --or              omit request/response pairs in output
  --plugin          customized template dir
  -o, --output      export to the file
  --format          output format option[json,csv,txt] default: txt
  --no-color        disable output content coloring
  --nuclei-args     poc nuclei engine additional args
  --silent          silent mode
  --debug           debug mode
  --config-dir      customized template dir
  --update-self     update self
  -u, --update-fingerprint
                    update fingerprint
  --update-plugin   update plugin
  --help            display usage information
```

### update fingerprint

- download fingerprint from GitHub

```bash,no-run
➜  observer_ward git:(main) ✗ ./observer_ward -u
```

| platforms | path                                                                           |
|-----------|--------------------------------------------------------------------------------|
| Windows   | C:\Users\Alice\AppData\Roaming\observer_ward\fingerprint_v4.json               |
| Linux     | /home/alice/.config/observer_ward/fingerprint_v4.json                          |
| macOS     | /Users/Alice/Library/Application Support/observer_ward/fingerprint_v4.json     |

- convert YAML files to JSON files, `--probe-dir` specify yaml folder,and `--probe-path` specify save json path
- then copy the json file to the configuration folder
```base,no-run
➜  observer_ward git:(main) ✗ ./observer_ward --probe-dir fingerprint --probe-path fingerprint_v4.json
[INFO  observer_ward::helper] convert the 2223 yaml file of the probe directory to a json file fingerprint_v4.json
➜  observer_ward git:(main) ✗ cp fingerprint_v4.json /home/kali-team/.config/observer_ward/
```

<!-- USAGE EXAMPLES -->

### Debug

- enable debug mode show more information

<details>

```bash,no-run
➜  observer_ward git:(main) ✗ ./observer_ward -t https://www.example.com/ -p fingerprint/00_unknown/0example.yaml --debug 
[INFO  observer_ward] probes loaded: 1                                                                                                   
[INFO  observer_ward] target loaded: 1                                                                                                   
[INFO  observer_ward] optimized probes: 2                                                                                                
[DEBUG observer_ward] start: https://www.example.com/                                                                                    
[DEBUG observer_ward] Request {                                                                                         00:27:02 [55/298]
        uri: https://www.example.com/,                                                                                                   
        version: HTTP/1.1,                                                                                                               
        method: GET,
        headers: {
            "accept": "text/html,application/xhtml+xml,application/xml;q=0.9,image/avif,image/webp,*/*;q=0.8",
        },
        body: None,
        raw_request: None,
    }
[DEBUG observer_ward] Response {                                                                                        00:27:02 [45/298]
        version: HTTP/1.1,
        uri: https://www.example.com/,
        status_code: 200,
        headers: {
            "age": "502712",
            "cache-control": "max-age=604800",
            "content-type": "text/html; charset=UTF-8",
            "date": "Tue, 02 Jul 2024 16:27:01 GMT",
            "etag": "\"3147526947+ident\"",
            "expires": "Tue, 09 Jul 2024 16:27:01 GMT",
            "last-modified": "Thu, 17 Oct 2019 07:18:26 GMT",
            "server": "ECAcc (sac/2533)",
            "vary": "Accept-Encoding",
            "x-cache": "HIT",
            "content-length": "1256",
        },
        extensions: Extensions,
        body: Some(
            <!doctype html>
            <html>
            <head>
                <title>Example Domain</title>
             
                <meta charset="utf-8" />
                <meta http-equiv="Content-type" content="text/html; charset=utf-8" />
                <meta name="viewport" content="width=device-width, initial-scale=1" />
                <style type="text/css">
                body {                                                                                                                   
                    background-color: #f0f0f2;                                                                                           
                    margin: 0;                                                                                                           
                    padding: 0;                                                                                                          
                    font-family: -apple-system, system-ui, BlinkMacSystemFont, "Segoe UI", "Open Sans", "Helvetica Neue", Helvetica, Arial, sans-serif;                                                                                                          
                }                                                                                                                        
                div {                                                                                                                    
                    width: 600px;                                                                                                        
                    margin: 5em auto;                                                                                                    
                    padding: 2em;                                                                                                        
                    background-color: #fdfdff;                                                                                           
                    border-radius: 0.5em;                                                                                                
                    box-shadow: 2px 3px 7px 2px rgba(0,0,0,0.02);                                                                        
                }
                a:link, a:visited {
                    color: #38488f;
                    text-decoration: none;
                }
                @media (max-width: 700px) {
                    div {
                        margin: 0 auto;
                        width: auto;
                    }
                }
                </style>    
            </head>
            
            <body>
            <div>
                <h1>Example Domain</h1>
                <p>This domain is for use in illustrative examples in documents. You may use this
                domain in literature without prior coordination or asking for permission.</p>
                <p><a href="https://www.iana.org/domains/example">More information...</a></p>
            </div>
            </body>
            </html>
            ,
        ),
    }
[DEBUG observer_ward] end: https://www.example.com/
target: https://www.example.com/
 |_ uri:[ https://www.example.com/ [0example]  <Example Domain> (200 OK) ] 
```
</details>

<p align="right">(<a href="#readme-top">back to top</a>)</p>

### Input

- `--target` or `-t`

```bash,no-run
➜  observer_ward git:(main) ✗ ./observer_ward -t https://www.example.com/ -t http://httpbin.org
[INFO  observer_ward] probes loaded: 2223
[INFO  observer_ward] target loaded: 2
[INFO  observer_ward] optimized probes: 7
target: http://httpbin.org/
 |_ uri:[ http://httpbin.org/ [swagger]  <httpbin.org> (200 OK) ] 
target: https://www.example.com/
 |_ uri:[ https://www.example.com/ [0example]  <Example Domain> (200 OK) ] 
```

- `--list` or `-l`

```bash,no-run
➜  observer_ward git:(main) ✗ ./observer_ward -l /home/kali-team/target.txt
[INFO  observer_ward] probes loaded: 2223
[INFO  observer_ward] target loaded: 2
[INFO  observer_ward] optimized probes: 7
target: http://httpbin.org/
 |_ uri:[ http://httpbin.org/ [swagger]  <httpbin.org> (200 OK) ] 
target: https://www.example.com/
 |_ uri:[ https://www.example.com/ [0example]  <Example Domain> (200 OK) ] 
```

- from stdio
```bash,no-run
➜  observer_ward git:(main) ✗ echo https://www.example.com/ | ./observer_ward
[INFO  observer_ward] probes loaded: 2223
[INFO  observer_ward] target loaded: 1
[INFO  observer_ward] optimized probes: 7
target: https://www.example.com/
 |_ uri:[ https://www.example.com/ [0example]  <Example Domain> (200 OK) ] 
```

<p align="right">(<a href="#readme-top">back to top</a>)</p>
### Output

- `--output` or `-o`

```bash,no-run
➜  observer_ward git:(main) ✗ ./observer_ward -t https://www.example.com/ -o output.txt
[INFO  observer_ward] probes loaded: 2223
[INFO  observer_ward] target loaded: 1
[INFO  observer_ward] optimized probes: 7
➜  observer_ward git:(main) ✗ cat output.txt 
target: https://www.example.com/
 |_ uri:[ https://www.example.com/ [0example]  <Example Domain> (200 OK) ] 
```

- automatically adapt output format based on file extension, or use `--format` support: `txt`,`json`,`csv`

```bash,no-run
➜  observer_ward git:(main) ✗ ./observer_ward -t https://www.example.com/ -o output.json --or
[INFO  observer_ward] probes loaded: 2223
[INFO  observer_ward] target loaded: 1
[INFO  observer_ward] optimized probes: 7
➜  observer_ward git:(main) ✗ cat output.json                                                               
{"target":"https://www.example.com/","matched_result":{"https://www.example.com/":{"title":["Example Domain"],"status":200,"favicon":{},"fingerprints":[{"matcher-results":[{"template":"0example","info":{"name":"0example","author":"cn-kali-team","tags":"detect,tech,0example","severity":"info","metadata":{"product":"0example","vendor":"00_unknown","verified":true}},"matcher-name":["<title>example domain</title>"],"extractor":{}}],"matched-at":"https://www.example.com/"}],"nuclei-result":{}}}}
```

<p align="right">(<a href="#readme-top">back to top</a>)</p>

### Integrated nuclei

- `--plugin`,enable nuclei,`plugins` is the folder where the nuclei-template is stored

```bash,no-run
➜  observer_ward git:(main) ✗ ./observer_ward -t http://172.17.0.3/ --plugin plugins 
[INFO  observer_ward] probes loaded: 2223
[INFO  observer_ward] target loaded: 1
[INFO  observer_ward] optimized probes: 7
target: http://172.17.0.3/
 |_ uri:[ http://172.17.0.3/ [apache-http]  <> (200 OK) ] 
 |_ uri:[ http://172.17.0.3/ [thinkphp]  <> (200 OK) ] 
  |_ vulnerabilities: [Critical] thinkphp-5023-rce: ThinkPHP 5.0.23 - Remote Code Execution
   |_ matched-at: http://172.17.0.3/index.php?s=captcha
   |_ command: curl -X 'POST' -d '_method=__construct&filter[]=phpinfo&method=get&server[REQUEST_METHOD]=1' -H 'Accept: */*' -H 'Accept-Language: en' -H 'Content-Type: application/x-www-form-urlencoded' -H 'User-Agent: Mozilla/5.0 (Macintosh; Intel Mac OS X 10_12_6) AppleWebKit/605.1.15 (KHTML, like Gecko) Version/9.1.2 Safari/605.1.15' 'http://172.17.0.3/index.php?s=captcha'
```

<!-- CONTRIBUTING -->

## Contributing

Contributions are what make the open source community such an amazing place to learn, inspire, and create. Any
contributions you make are **greatly appreciated**.

If you have a suggestion that would make this better, please fork the repo and create a pull request. You can also
simply open an issue with the tag "enhancement".
Don't forget to give the project a star! Thanks again!

1. Fork the Project
2. Create your Feature Branch (`git checkout -b feature/AmazingFeature`)
3. Commit your Changes (`git commit -m 'Add some AmazingFeature'`)
4. Push to the Branch (`git push origin feature/AmazingFeature`)
5. Open a Pull Request

<p align="right">(<a href="#readme-top">back to top</a>)</p>



<!-- LICENSE -->

## License

Distributed under the `GPL-3.0-only` License. See `LICENSE` for more information.

<p align="right">(<a href="#readme-top">back to top</a>)</p>



<!-- CONTACT -->

## Contact

Your Name - [@Kali_Team](https://twitter.com/Kali_Team) - root@kali-team.cn

Project Link: [https://github.com/emo-crab/observer_ward](https://github.com/emo-crab/observer_ward)

<p align="right">(<a href="#readme-top">back to top</a>)</p>

<!-- ACKNOWLEDGMENTS -->

## Acknowledgments

* [slinger](https://github.com/emo-crab/slinger)
* [nuclei](https://github.com/projectdiscovery/nuclei)

<p align="right">(<a href="#readme-top">back to top</a>)</p>



<!-- MARKDOWN LINKS & IMAGES -->
<!-- https://www.markdownguide.org/basic-syntax/#reference-style-links -->

[contributors-shield]: https://img.shields.io/github/contributors/emo-crab/observer_ward.svg?style=for-the-badge

[contributors-url]: https://github.com/emo-crab/observer_ward/graphs/contributors

[forks-shield]: https://img.shields.io/github/forks/emo-crab/observer_ward.svg?style=for-the-badge

[forks-url]: https://github.com/emo-crab/observer_ward/network/members

[stars-shield]: https://img.shields.io/github/stars/emo-crab/observer_ward.svg?style=for-the-badge

[stars-url]: https://github.com/emo-crab/observer_ward/stargazers

[issues-shield]: https://img.shields.io/github/issues/emo-crab/observer_ward.svg?style=for-the-badge

[issues-url]: https://github.com/emo-crab/observer_ward/issues

[license-shield]: https://img.shields.io/github/license/emo-crab/observer_ward.svg?style=for-the-badge

[license-url]: https://github.com/emo-crab/observer_ward/blob/master/LICENSE.txt

[product-screenshot]: images/screenshot.png

[crates-shield]: https://img.shields.io/crates/v/observer_ward.svg?style=for-the-badge

[crates-url]: https://crates.io/crates/observer_ward
