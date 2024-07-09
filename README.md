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
    服务和Web应用指纹识别工具
    <br />
    <a href="https://github.com/emo-crab/observer_ward">View Demo</a>
    ·
    <a href="https://github.com/emo-crab/observer_ward/issues">Report Bug</a>
    ·
    <a href="https://github.com/emo-crab/observer_ward/issues">Request Feature</a>
  </p>
</div>

<!-- ABOUT THE PROJECT -->

## 关于这个项目

- 郑重声明：文中所涉及的技术、思路和工具仅供以安全为目的的学习交流使用，任何人不得将其用于非法用途以及盈利等目的，否则后果自行承担。

| 类别 | 说明                                                              |
| ---- | ----------------------------------------------------------------- |
| 作者 | [三米前有蕉皮](https://github.com/cn-kali-team)                   |
| 团队 | [0x727](https://github.com/0x727) 未来一段时间将陆续开源工具      |
| 定位 | 社区化[指纹库](https://github.com/0x727/FingerprintHub)识别工具。 |
| 语言 | Rust                                                              |
| 功能 | 服务和Web应用指纹识别工具                                         |

![Product Name Screen Shot][product-screenshot]

- 基于yaml编写探针，匹配规则和提取器
- 支持服务和Web应用版本识别
- 使用nvd标准通用平台枚举 ([CPE](https://scap.kali-team.cn/cpe/)) 命名规范
- [社区化指纹库](https://github.com/0x727/FingerprintHub)和nmap服务探针
- 集成 [Nuclei](https://github.com/projectdiscovery/nuclei) 验证漏洞

<p align="right">(<a href="#readme-top">back to top</a>)</p>

<!-- INSTALL -->

## 安装

-

从源码编译安装，更多可以查看github的action工作流文件 [workflow](https://github.com/emo-crab/observer_ward/blob/main/.github/workflows/post-release.yml)

```bash,no-run
cargo build --release --manifest-path=observer_ward/Cargo.toml
```

- 从发布页面下载 [release](https://github.com/emo-crab/observer_ward/releases)
- 如果是Mac系统可以通过brew安装

```bash,no-run
brew install observer_ward
```

<!-- GETTING STARTED -->

## 入门

```bash,no-run
➜  ~ ./observer_ward -t http://httpbin.org/
[INFO ] 📇probes loaded: 6183
[INFO ] 🎯target loaded: 1
[INFO ] 🚀optimized probes: 8
🏹: http://httpbin.org/
 |_🎯:[ http://httpbin.org/ [0example,swagger]  <httpbin.org> (200 OK) ]
```

- 使用帮助

```bash,no-run
➜ ./observer_ward --help                                                                      
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

### 更新指纹库

- 从github下载指纹库

```bash,no-run
➜ ./observer_ward -u
```

| 操作系统 | 保存路径                                                                                  |
| -------- | ----------------------------------------------------------------------------------------- |
| Windows  | C:\Users\Alice\AppData\Roaming\observer_ward\web_or_service_fingerprint_v4.json           |
| Linux    | /home/alice/.config/observer_ward/web_or_service_fingerprint_v4.json                      |
| macOS    | /Users/Alice/Library/Application Support/observer_ward/web_or_service_fingerprint_v4.json |

- 指定yaml文件夹`--probe-dir`和单个json文件`--probe-path`参数将全部yaml文件转换为一个单json文件，方便携带
- 然后将这个json文件复制到配置文件夹

```base,no-run
➜ ./observer_ward --probe-dir web_fingerprint --probe-dir service_fingerprint/null -p fingerprint_v4.json
[INFO ] ℹ️ convert the 6183 yaml file of the probe directory to a json file fingerprint_v4.json
```

<!-- USAGE EXAMPLES -->

### 调试模式

- 使用`--debug`开启调试模式，可以看到更详细的输出结果

<details>

```bash,no-run
➜ ./observer_ward -t http://httpbin.org -p observer_ward/examples/json.yaml --debug           
[INFO ] 📇probes loaded: 1                                                                                                               
[INFO ] 🎯target loaded: 1                                                                                                               
[INFO ] 🚀optimized probes: 1                                                                                                            
[DEBUG] start: http://httpbin.org/                                                                                                       
[DEBUG] Request {                                                                                                                        
        uri: http://httpbin.org/ip,                                                                                                      
        version: HTTP/1.1,                                                                                                               
        method: GET,                                                                                                                     
        headers: {                                                                                                                       
            "accept": "text/html,application/xhtml+xml,application/xml;q=0.9,image/avif,image/webp,*/*;q=0.8",                           
            "content-type": "application/json",                                                                                          
        },                                                                                                                               
        body: None,                                                                                                                      
        raw_request: None,                                                                                                               
    }
[DEBUG] Response {
        version: HTTP/1.1,
        uri: http://httpbin.org/ip,
        status_code: 200,
        headers: {
            "date": "Mon, 08 Jul 2024 13:19:59 GMT",
            "content-type": "application/json",
            "content-length": "32",
            "connection": "keep-alive",
            "server": "gunicorn/19.9.0",
            "access-control-allow-origin": "*",
            "access-control-allow-credentials": "true",
        },
        extensions: Extensions,
        body: Some(
            {
              "origin": "1.1.1.1"
            }
            ,
        ),
    }
[DEBUG] end: http://httpbin.org/
🏹: http://httpbin.org/
 |_🎯:[ http://httpbin.org/]
 |_🎯:[ http://httpbin.org/ip [httpbin-ip]  <>]
  |_📰: ip:["1.1.1.1"]
```

</details>

<p align="right">(<a href="#readme-top">back to top</a>)</p>

### 目标输入

- 使用`--target`或者`-t`指定一个或者多个uri目标

```bash,no-run
➜  ~ ./observer_ward -t https://www.example.com/ -t http://httpbin.org                                            
[INFO ] 📇probes loaded: 6183
[INFO ] 🎯target loaded: 2
[INFO ] 🚀optimized probes: 8
🏹: https://www.example.com/
 |_🎯:[ https://www.example.com/ <Example Domain>  (200 OK) ]
🏹: http://httpbin.org/
 |_🎯:[ http://httpbin.org/ [0example,swagger]  <httpbin.org> (200 OK) ]
```

- 使用`--list`或者`-l`指定一个目标列表文件

```bash,no-run
➜  ~ ./observer_ward -l target.txt                                            
[INFO ] 📇probes loaded: 6183
[INFO ] 🎯target loaded: 3
[INFO ] 🚀optimized probes: 8
🏹: tcp://127.0.0.1:22/
 |_🎯:[ tcp://127.0.0.1:22/ [ssh]  <SSH-2.0-OpenSSH_9.7>]
  |_📰: version:[9.7] info:[protocol 2.0] 
🏹: http://172.17.0.2/
 |_🎯:[ http://172.17.0.2/ [apache-http]  <>]
 |_🎯:[ http://172.17.0.2/ [thinkphp]  <>]
🏹: http://httpbin.org/
 |_🎯:[ http://httpbin.org/ [swagger,0example]  <httpbin.org> (200 OK) ]
```

- 从标准输入读取目标

```bash,no-run
➜  ~ echo http://172.17.0.2 | ./observer_ward        
[INFO ] 📇probes loaded: 6183
[INFO ] 🚀optimized probes: 8
[INFO ] 🎯target loaded: 1
🏹: http://172.17.0.2/
 |_🎯:[ http://172.17.0.2/ [apache-http]  <>]
 |_🎯:[ http://172.17.0.2/ [thinkphp]  <>]
```

<p align="right">(<a href="#readme-top">back to top</a>)</p>

### 结果输出

- 使用`--output`或者`-o`将结果保存到指定文件路径

```bash,no-run
➜  ~ ./observer_ward -t https://www.example.com/ -o output.txt
[INFO ] 📇probes loaded: 6183
[INFO ] 🚀optimized probes: 8
[INFO ] 🎯target loaded: 1
➜  ~ cat output.txt 
🏹: https://www.example.com/
 |_🎯:[ https://www.example.com/ <Example Domain>  (200 OK) ]
```

- 如果是保存到文件输出格式会根据文件后缀自动切换，也可以使用`--format`参数指定输出格式，支持: `txt`,`json`,`csv`

```bash,no-run
➜  ~ ./observer_ward -t https://www.example.com/ -o output.json --or --oc
[INFO ] 📇probes loaded: 6183
[INFO ] 🚀optimized probes: 8
[INFO ] 🎯target loaded: 1
➜  ~ cat output.json 
{"target":"https://www.example.com/","matched_result":{"https://www.example.com/":{"title":["Example Domain"],"status":200,"favicon":{},"fingerprints":[],"nuclei-result":{}}}}
```

- 使用`--webhook`指定要将结果发送到的服务器url，如果webhook服务器有认证也可以使用`--webhook-auth`添加值到`Authorization`
  请求头

```python
from flask import Flask, request

app = Flask(__name__)


@app.route("/webhook", methods=['POST'])
def observer_ward_webhook():
    print("Authorization: ", request.headers.get("Authorization"))
    print(request.json)
    return 'ok'


if __name__ == '__main__':
    app.run()
```

- 例如先在本地启动一个简易webhook服务器

```bash,no-run
➜  observer_ward git:(main) ✗ python observer_ward/examples/webhook.py
 * Serving Flask app 'webhook'
 * Debug mode: off
WARNING: This is a development server. Do not use it in a production deployment. Use a production WSGI server instead.
 * Running on http://127.0.0.1:5000
Press CTRL+C to quit
```

- 将结果发送到本地webhook服务器：`http://127.0.0.1:5000`，当识别完成后你将可以在webhook服务器接收到结果

```bash,no-run
➜  ~ ./observer_ward -t http://httpbin.org --webhook http://127.0.0.1:5000/webhook --webhook-auth 22e038328151a7a06fd4ebfa63a10228
[INFO ] 📇probes loaded: 6183
[INFO ] 🚀optimized probes: 8
[INFO ] 🎯target loaded: 1
🏹: http://httpbin.org/
 |_🎯:[ http://httpbin.org/ [swagger,0example]  <httpbin.org> (200 OK) ]
```

<p align="right">(<a href="#readme-top">back to top</a>)</p>

### 集成nuclei验证漏洞

- 使用`--plugin`指定nuclei的template文件夹开启nuclei,这个`plugins`文件夹可以到社区指纹库项目下载
- 文件夹结构为`厂商/产品/nuclei的yaml文件`，如果识别到的指纹解析cpe后得到了厂商和产品在这个文件夹可以找到就会调用这个文件夹下面的yaml进行漏洞验证
- 例如：指纹识别到了`tomcat`，通过解析cpe得到厂商为`apache`和产品为`tomcat`，调用`apache/tomcat`文件夹下面的全部yaml验证漏洞

```bash,no-run
➜  ~ ./observer_ward -t http://172.17.0.2/ --plugin IdeaProjects/observer_ward/plugins
[INFO ] 📇probes loaded: 6183
[INFO ] 🚀optimized probes: 8
[INFO ] 🎯target loaded: 1
🏹: http://172.17.0.2/
 |_🎯:[ http://172.17.0.2/ [apache-http]  <>]
 |_🎯:[ http://172.17.0.2/ [thinkphp]  <>]
  |_🐞: [Critical] thinkphp-5023-rce: ThinkPHP 5.0.23 - Remote Code Execution
   |_🔥: http://172.17.0.2/index.php?s=captcha
   |_🐚: curl -X 'POST' -d '_method=__construct&filter[]=phpinfo&method=get&server[REQUEST_METHOD]=1' -H 'Accept: */*' -H 'Accept-Language: en' -H 'Content-Type: application/x-www-form-urlencoded' -H 'User-Agent: Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/605.1.15 (KHTML, like Gecko) Version/16.5 Safari/605.1.15 Ddg/17.4' 'http://172.17.0.2/index.php?s=captcha'
```

### 开启Web服务

- 使用`--api-server`指定监听IP和端口，`--token`设置api的`Bearer`认证

```bash,no-run
➜  ~ ./observer_ward --api-server 127.0.0.1:8000 --token 22e038328151a7a06fd4ebfa63a10228
[INFO ] 📇probes loaded: 6183
[INFO ] 🚀optimized probes: 8
[INFO ] 🌐API service has been started:http://127.0.0.1:8000/v1/observer_ward
[INFO ] 📤:
[INFO ] 📔:curl --request POST \
      --url http://127.0.0.1:8000/v1/observer_ward \
      --header 'Authorization: Bearer 22e038328151a7a06fd4ebfa63a10228' \
      --header 'Content-Type: application/json' \
      --data '{"target":["https://httpbin.org/"],"or":true,"oc":true}'
[INFO ] 📥:
[INFO ] 🗳:[result...]
```

- 使用curl请求api，同时设置`Authorization`参数

```bash,no-run
➜  ~ curl --request POST \                                                                                                     
  --url http://127.0.0.1:8000/v1/observer_ward \
  --header 'Authorization: Bearer 22e038328151a7a06fd4ebfa63a10228' \
  --header 'Content-Type: application/json' \
  --data '{"target":["https://httpbin.org/"],"or":true,"oc":true}'
[{"target":"https://httpbin.org/","matched_result":{"https://httpbin.org/":{"title":["httpbin.org"],"status":200,"favicon":{"https://httpbin.org/static/favicon.ico":{"md5":"3aa2067193b2ed83f24c30bd238a717c","mmh3":"-1296740046"}},"fingerprints":[{"matcher-results":[{"template":"swagger","info":{"name":"swagger","author":"cn-kali-team","tags":"detect,tech,swagger","severity":"info","metadata":{"product":"swagger","vendor":"00_unknown","verified":true}},"matcher-name":["swagger-ui.css"],"extractor":{}}],"matched-at":"https://httpbin.org/"},{"matcher-results":[{"template":"0example","info":{"name":"0example","author":"cn-kali-team","tags":"detect,tech,0example","severity":"info","metadata":{"product":"0example","vendor":"00_unknown","verified":true}},"matcher-name":["3aa2067193b2ed83f24c30bd238a717c","https://httpbin.org/static/favicon.ico"],"extractor":{}}],"matched-at":"https://httpbin.org/"}],"nuclei-result":{}}}}]
```

- 通过api获取当前config，这些字段都是可以通过每次的POST请求创建识别任务中配置

```bash,no-run
➜  ~ curl --request GET \
  --url http://127.0.0.1:8000/v1/config \
  --header 'Authorization: Bearer 22e038328151a7a06fd4ebfa63a10228' \
  --header 'Content-Type: application/json'
{"target":[],"ua":"Mozilla/5.0 (X11; Linux x86_64; rv:94.0) Gecko/20100101 Firefox/94.0","timeout":10,"thread":4,"or":false,"oc":false,"update-fingerprint":false,"update-plugin":false,"webhook":null,"webhook-auth":null}
```

- 设置`update-plugin`和`update-fingerprint`为`true`更新指纹库和nuclei的插件库

```bash,no-run
➜  ~ curl --request POST \
  --url http://127.0.0.1:8000/v1/config \
  --header 'Authorization: Bearer 22e038328151a7a06fd4ebfa63a10228' \
  --header 'Content-Type: application/json' \
  --data '{"target":[],"update-plugin":true,"update-fingerprint":true}'
{"target":[],"ua":"Mozilla/5.0 (X11; Linux x86_64; rv:94.0) Gecko/20100101 Firefox/94.0","timeout":10,"thread":4,"or":false,"oc":false,"update-fingerprint":true,"update-plugin":true,"webhook":null,"webhook-auth":null
```

<!-- CONTRIBUTING -->

## 提交指纹

- observer_ward使用到的指纹规则全部来自[FingerprintHub](https://github.com/0x727/FingerprintHub)项目。
- 如果需要获取指纹库和提交指纹规则，请查看[FingerprintHub](https://github.com/0x727/FingerprintHub)项目。

## 为observer_ward做贡献

### 提交代码

- 点击Fork按钮克隆这个项目到你的仓库

```bash,no-run
git clone git@github.com:你的个人github用户名/observer_ward.git
```

- 添加上游接收更新

```bash,no-run
cd observer_ward
git remote add upstream git@github.com:emo-crab/observer_ward.git
git fetch upstream
```

- 配置你的github个人信息

```bash,no-run
git config --global user.name "$GITHUB_USERNAME"
git config --global user.email "$GITHUB_EMAIL"
git config --global github.user "$GITHUB_USERNAME"
```

- 拉取所有分支的规则

```bash,no-run
git fetch --all
git fetch upstream
```

- **不要**直接在`main`分支上修改，例如我想修改某个bug，创建一个新的分支并切换到新的分支。

```bash,no-run
git checkout -b dev
```

- 修改完成后，测试通过
- 跟踪修改和提交Pull-Requests。

```bash,no-run
git add 你添加或者修改的文件名
git commit -m "添加你的描述"
git push origin dev
```

- 打开你Fork这个项目的地址，点击与上游合并，等待审核合并代码。

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

- [slinger](https://github.com/emo-crab/slinger)
- [nuclei](https://github.com/projectdiscovery/nuclei)

<p align="right">(<a href="#readme-top">back to top</a>)</p>

## Stargazers over time

[![Stargazers over time](https://starchart.cc/emo-crab/observer_ward.svg)](https://github.com/emo-crab/observer_ward)

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
