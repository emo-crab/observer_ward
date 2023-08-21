![logo](docs/images/logo.png)

[中文简体](./README.md)

# ObserverWard

| 类别  | 说明                                                     |
|-----|--------------------------------------------------------|
| 作者  | [三米前有蕉皮](https://github.com/cn-kali-team)              |
| 团队  | [0x727](https://github.com/0x727) 未来一段时间将陆续开源工具        |
| 定位  | 社区化[指纹库](https://github.com/0x727/FingerprintHub)识别工具。 |
| 语言  | Rust                                                   |
| 功能  | 命令行Web指纹识别工具                                           |

## 安装

### 1. 源码手动安装

```bash
git clone https://github.com/0x727/ObserverWard
cd ObserverWard
cargo build --target x86_64-unknown-linux-musl --release --all-features
```

- 更多安装细节请查看当前项目的Actions自动化编译构建流程[文件](https://github.com/0x727/ObserverWard/blob/main/.github/workflows/basic.yml)

### 2. 下载二进制安装

- 因为添加了`--update-self`参数，方便更新固定了标签，每次更新代码都会自动重新编译发布到`default`版本，所以`default`
  永远是最新的版本。
- [发行版本](https://github.com/0x727/ObserverWard/releases)下载页面。

### 3. Mac系统

```shell
brew install observer_ward
```

## 使用方法

```bash
Usage: observer_ward [-t <target>] [--stdin] [--fpath <fpath>] [--yaml <yaml>] [--path <path>] [--verify <verify>] [-f <file>] [-u] [-c <csv>] [-j <json>] [--proxy <proxy>] [--timeout <timeout>] [--plugins <plugins>] [--update-plugins] [--update-self] [--thread <thread>] [--webhook <webhook>] [--service] [-s <api-server>] [--token <token>] [--ua <ua>] [--daemon] [--danger] [--silent] [--filter] [--irr]

observer_ward

Options:
  -t, --target      the target (required, unless --stdin used)
  --stdin           read target(s) from STDIN
  --fpath           customized fingerprint file path
  --yaml            customized fingerprint yaml directory (slow)
  --gen             generate json format fingerprint library from yaml
                    format(requires yaml parameter)
  --path            customized nuclei template file path
  --verify          validate the specified yaml file or grep keyword
  -f, --file        read the target from the file
  -u, --update-fingerprint
                    update web fingerprint
  -c, --csv         export to the csv file or Import form the csv file
  -j, --json        export to the json file or Import form the json file
  --proxy           proxy to use for requests
                    (ex:[http(s)|socks5(h)]://host:port)
  --timeout         set request timeout.
  --plugins         the 'plugins' directory is used when the parameter is the
                    default
  --update-plugins  update nuclei plugins
  --update-self     update self
  --thread          number of concurrent threads.
  --webhook         send results to webhook server
                    (ex:https://host:port/webhook)
  --service         using nmap fingerprint identification service (slow)
  -s, --api-server  start a web API service (ex:127.0.0.1:8080)
  --token           api Bearer authentication
  --ua              customized ua
  --daemon          api background service
  --danger          danger mode
  --silent          silent mode
  --filter          filter mode,Display only the fingerprint that is not empty
  --irr             include request/response pairs in the JSONL output
  --help            display usage information
  --nargs           nuclei args

```

### 更新指纹

- 使用`-u`
  参数从指纹库中更新指纹，也可以自己从[指纹库项目](https://0x727.github.io/FingerprintHub/web_fingerprint_v3.json)
  下载当前系统对应目录，新版也会将tags.yaml下载到配置目录文件夹。
- 如果在程序的运行目录有`web_fingerprint_v3.json`文件会使用运行目录下的指纹库，不会读取下面表格中系统对于的目录。

| 系统      | 路径                                                                             |
|---------|--------------------------------------------------------------------------------|
| Windows | C:\Users\Alice\AppData\Roaming\observer_ward\web_fingerprint_v3.json           |
| Linux   | /home/alice/.config/observer_ward/web_fingerprint_v3.json                      |
| macOS   | /Users/Alice/Library/Application Support/observer_ward/web_fingerprint_v3.json |

```bash
➜  ~ ./observer_ward_amd64 -u    
https://0x727.github.io/FingerprintHub/plugins/tags.yaml:=> /home/kali-team/.config/observer_ward/tags.yaml' file size => 4761
https://0x727.github.io/FingerprintHub/web_fingerprint_v3.json:=> /home/kali-team/.config/observer_ward/web_fingerprint_v3.json' file size => 978084
```

### 更新插件

- 使用`--update-plugins`
  从[指纹库项目](https://github.com/0x727/FingerprintHub/releases/download/default/plugins.zip)下载插件压缩包到用户配置目录。
- 并自动解压到当前系统对应目录，当使用`--plugins default`参数时会默认使用这个目录下的插件。
- 更新会删除原来的目录，重新解压覆盖。

| 系统      | 路径                                                             |
|---------|----------------------------------------------------------------|
| Windows | C:\Users\Alice\AppData\Roaming\observer_ward\plugins           |
| Linux   | /home/alice/.config/observer_ward/plugins                      |
| macOS   | /Users/Alice/Library/Application Support/observer_ward/plugins |

### 验证指纹是否有效

- `--verify`指定要验证的指纹yaml文件路径，`-t`指定要识别的目标，输出请求过程和识别结果。
- `--fpath`指定自己的`web_fingerprint_v3.json`文件。
- `--yaml`指定`FingerprintHub`的`web_fingerprint`文件夹，加载全部yaml文件，比较慢，只适合本地测试。
- `--gen`参数可以配合`--yaml`参数将指定yaml目录中的全部yaml指纹规则生成单个json文件，主要方便自定义指纹，生成便携单文件。

```bash
➜  ~ ./observer_ward --yaml /home/kali-team/IdeaProjects/FingerprintHub/web_fingerprint --gen web_fingerprint_v3.json
➜  ~ jq length web_fingerprint_v3.json
3448
```

- `/home/kali-team/IdeaProjects/FingerprintHub/web_fingerprint`是存放yaml的目录，`web_fingerprint_v3.json`是生成的文件路径。

```bash
➜  ~ ./observer_ward -t https://www.example.com --verify 0example.yaml
Url: https://www.example.com/
Headers:
x-cache: HIT
accept-ranges: bytes
age: 212697
cache-control: max-age=604800
content-type: text/html; charset=UTF-8
date: Thu, 14 Apr 2022 03:09:03 GMT
etag: "3147526947"
expires: Thu, 21 Apr 2022 03:09:03 GMT
last-modified: Thu, 17 Oct 2019 07:18:26 GMT
server: ECS (sab/5783)
vary: Accept-Encoding
StatusCode: 200 OK
Text:
<!doctype html>
<html>
<head>
    <title>example domain</title>

    <meta charset="utf-8" />
    <meta http-equiv="content-type" content="text/html; charset=utf-8" />
    <meta name="viewport" content="width=device-width, initial-scale=1" />
    <style type="text/css">
    body {
        background-color: #f0f0f2;
        margin: 0;
        padding: 0;
        font-family: -apple-system, system-ui, blinkmacsystemfont, "segoe ui", "open sans", "helvetica neue", helvetica, arial, sans-serif;
        
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
    <h1>example domain</h1>
    <p>this domain is for use in illustrative examples in documents. you may use this
    domain in literature without prior coordination or asking for permission.</p>
    <p><a href="https://www.iana.org/domains/example">more information...</a></p>
</div>
</body>
</html>
Favicon: {}

Matching fingerprintV3WebFingerPrint {
    name: "0example",
    priority: 3,
    request: WebFingerPrintRequest {
        path: "/",
        request_method: "get",
        request_headers: {},
        request_data: "",
    },
    match_rules: WebFingerPrintMatch {
        status_code: 0,
        favicon_hash: [],
        headers: {},
        keyword: [
            "<title>Example Domain</title>",
        ],
    },
}
[ https://www.example.com |["0example"] | 1256 | 200 | example domain ]
Important technology:

+-------------------------+----------+--------+-------------+----------------+----------+
| url                     | name     | length | status_code | title          | priority |
+=========================+==========+========+=============+================+==========+
| https://www.example.com | 0example | 1256   | 200         | example domain | 5        |
+-------------------------+----------+--------+-------------+----------------+----------+

```

### 单个目标识别

```bash
➜  ~ ./observer_ward -t https://httpbin.org
[ https://httpbin.org |["swagger"] | 9593 | 200 | httpbin.org ]
Important technology:

+---------------------+---------+--------+-------------+-------------+----------+
| url                 | name    | length | status_code | title       | priority |
+=====================+=========+========+=============+=============+==========+
| https://httpbin.org | swagger | 9593   | 200         | httpbin.org | 5        |
+---------------------+---------+--------+-------------+-------------+----------+
```

### 从文件获取要识别的目标

```bash
➜  ~ ./observer_ward -f target.txt
```

### 从标准输出获取识别目标

```bash
➜  ~ cat target.txt| ./observer_ward --stdin
```

- 结果和从文件获取的效果一样，这里不再截图展示。

### 导出结果到JSON文件

```bash
➜  ~ ./observer_ward -t https://httpbin.org -j result.json
[ https://httpbin.org |["swagger"] | 9593 | 200 | httpbin.org ]
Important technology:

+---------------------+---------+--------+-------------+-------------+----------+
| url                 | name    | length | status_code | title       | priority |
+=====================+=========+========+=============+=============+==========+
| https://httpbin.org | swagger | 9593   | 200         | httpbin.org | 5        |
+---------------------+---------+--------+-------------+-------------+----------+
➜  ~ cat result.json
[{"url":"https://httpbin.org","name":["swagger"],"priority":5,"length":9593,"title":"httpbin.org","status_code":200,"is_web":true,"plugins":[]}]
```

### 导出结果到CSV文件

```bash
➜  ~ ./observer_ward -t https://httpbin.org -c result.csv
[ https://httpbin.org |["swagger"] | 9593 | 200 | httpbin.org ]
Important technology:

+---------------------+---------+--------+-------------+-------------+----------+
| url                 | name    | length | status_code | title       | priority |
+=====================+=========+========+=============+=============+==========+
| https://httpbin.org | swagger | 9593   | 200         | httpbin.org | 5        |
+---------------------+---------+--------+-------------+-------------+----------+
➜  ~ cat result.csv 
url,name,length,status_code,title,priority
https://httpbin.org,swagger,9593,200,httpbin.org,5
```

- 关于打开csv文件中文乱码问题，和系统环境变量有关，会导致保存文件的编码为UTF-8，Mac系统或者Linux可以使用以下命令转换导出文件编码：

```bash
iconv -f UTF-8 -t GB18030 Result.csv > Result.csv
```

- Window系统可以使用记事本打开csv文件后另存为，选择保存编码ANSI或者Unicode。

### 调用Nuclei检测漏洞

- **请确保nuclei更新至`2.5.3`以上版本**
- 如果需要使用[nuclei](https://github.com/projectdiscovery/nuclei)检测漏洞，需要首先安装`Nuclei`
  到当前目录，或者是加入环境变量里面，让`observe_ward`可以正常调用。
- 再下载[指纹库中的插件](https://github.com/0x727/FingerprintHub/tree/main/plugins)
  到当前目录下，或者使用`--update-plugins`插件。
- 在[指纹库](https://github.com/0x727/FingerprintHub/tree/main/plugins)中已经对部分组件的插件进行了分类。
- 如果识别到的组件在`plugins`目录下存在和组件同名的文件夹，会对目标调用Nuclei使用匹配到的插件进行检测，存在漏洞会输出到屏幕。
- 因为经过测试在指纹识别过程中同时调用nuclei检测漏洞会影响Web指纹识别的效果，也会拉长识别的时间，所以选择识别完Web指纹后将结果保存到文件，再解析文件调用nuclei检测。
- 目前支持将Web指纹识别的结果保存为`json`和`csv`格式，所以只能解析这两种格式。
- `--nargs`可以添加nuclei扩展参数， 比如：`--nargs "-etags intrusive"`，排除有入侵危险的template。

```bash
➜  ~ ./observer_ward_amd64 -t https://httpbin.org --csv result.csv --plugins 0x727/FingerprintHub/plugins
 __     __     ______     ______     _____
/\ \  _ \ \   /\  __ \   /\  == \   /\  __-.
\ \ \/ ".\ \  \ \  __ \  \ \  __<   \ \ \/\ \
 \ \__/".~\_\  \ \_\ \_\  \ \_\ \_\  \ \____-
  \/_/   \/_/   \/_/\/_/   \/_/ /_/   \/____/
Community based web fingerprint analysis tool.
_____________________________________________
:  https://github.com/0x727/FingerprintHub  :
:  https://github.com/0x727/ObserverWard    :
 --------------------------------------------
[ https://httpbin.org |["swagger"] | 9593 | 200 | httpbin.org ]
Important technology:

+---------------------+---------+--------+-------------+-------------+----------+
| url                 | name    | length | status_code | title       | priority |
+=====================+=========+========+=============+=============+==========+
| https://httpbin.org | swagger | 9593   | 200         | httpbin.org | 5        |
+---------------------+---------+--------+-------------+-------------+----------+
Important technology:

+---------------------+---------+--------+-------------+-------------+----------+------------+
| url                 | name    | length | status_code | title       | priority | plugins    |
+=====================+=========+========+=============+=============+==========+============+
| https://httpbin.org | swagger | 9593   | 200         | httpbin.org | 5        | swagger-api|
+---------------------+---------+--------+-------------+-------------+----------+------------+

```

- 同理`json`格式也可以。

```bash
➜  ~ ./observer_ward_amd64 -f target.txt --json result.json --plugins 0x727/FingerprintHub/plugins
```

- 使用默认插件目录`default`

```bash
➜  ~ ./observer_ward_amd64 -f target.txt --json result.json --plugins default
```

- 将nuclei的请求和响应的payload保存到json结果`--irr`

```bash
➜  ~ ./observer_ward_amd64 -f target.txt --json result.json --plugins default --irr
```

- 指定`--path`参数设置路径，使用官方的`nuclei-templates`，会加载tags.yaml文件，根据nuclei的`-tags`参数调用插件，
  感谢功能建议：[j4vaovo](https://github.com/0x727/ObserverWard/issues/143)

```bash
➜  ~ ./observer_ward_amd64 -f target.txt --path /home/kali-team/nuclei-templates

```

### WebHook

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

- 开启webhook后，添加`--webhook`参数，将识别的结果发送到webhook服务器。

```shell
➜  ~ ./observer_ward_amd64 -f target.txt --webhook http://127.0.0.1:5000/webhook
```

Webhook json格式：

``` json
{
    "is_web":true,
    "length":9593,
    "name":[
        "swagger"
    ],
    "plugins":[

    ],
    "priority":5,
    "status_code":200,
    "title":"httpbin.org",
    "url":"https://httpbin.org/"
}
```

### 开启API服务

- 使用`-s`参数提供监听地址和端口开启rest-api服务，使用`--daemon`参数将服务放到后台进程（不支持Window系统）。
- 如果需要支持`https`协议,需要生成`cert.pem`和`key.pem`
  文件放到程序配置目录，例如：Linux系统下的`/home/alice/.config/observer_ward/`。
- 生成证书文件

```shell
# mkcert 命令生成
mkcert -key-file key.pem -cert-file cert.pem localhost
# openssl 命令生成
openssl req -x509 -newkey rsa:2048 -keyout key.pem -out cert.pem -days 365
```

```shell
➜  ~ ./observer_ward -s 127.0.0.1:8000 --token 22e038328151a7a06fd4ebfa63a10228
 __     __     ______     ______     _____
/\ \  _ \ \   /\  __ \   /\  == \   /\  __-.
\ \ \/ ".\ \  \ \  __ \  \ \  __<   \ \ \/\ \
 \ \__/".~\_\  \ \_\ \_\  \ \_\ \_\  \ \____-
  \/_/   \/_/   \/_/\/_/   \/_/ /_/   \/____/
Community based web fingerprint analysis tool.
_____________________________________________
:  https://github.com/0x727/FingerprintHub  :
:  https://github.com/0x727/ObserverWard    :
 --------------------------------------------
API service has been started:https://127.0.0.1:8000/v1/observer_ward
Request:
curl --request POST \
  --url https://127.0.0.1:8000/v1/observer_ward \
  --header 'Authorization: Bearer 22e038328151a7a06fd4ebfa63a10228' \
  --header 'Content-Type: application/json' \
  --data '{"target":"https://httpbin.org/"}'
Response:
[{"url":"http://httpbin.org/","name":["swagger"],"priority":5,"length":9593,"title":"httpbin.org","status_code":200,"is_web":true,"plugins":[]}]
```

- 更新配置接口，更新配置时会对识别服务上锁，`GET`方法可以回去当前配置，`POST`方法对配置全量更新，未设置的字段为默认值。

```shell
curl --request POST \
  --url http://127.0.0.1:8000/v1/config \
  --header 'Authorization: Bearer 22e038328151a7a06fd4ebfa63a10228' \
  --header 'Content-Type: application/json' \
  --data '{
    "update_fingerprint": false
}'
```

- 其他可选参数，`update_fingerprint`，`update_plugins`只能在更新配置接口下使用；其他参数可以在提交任务时和目标附加在一起。
- 当`webhook`不为空时会异步将结果推到设置的WebHook服务器，并立即返回提示响应。

```json
{
  "targets": [],
  "update_fingerprint": false,
  "proxy": "",
  "timeout": 10,
  "plugins": "",
  "update_plugins": false,
  "thread": 100,
  "webhook": "",
  "webhook_auth": "",
  "service": false
}
```

- 在添加任务时可以指定`webhook_auth`字段用来标识不同的任务,字符串必须符合HTTP请求头值

```bash
curl --request POST \
  --url http://127.0.0.1:8000/v1/observer_ward \
  --header 'Authorization: Bearer 22e038328151a7a06fd4ebfa63a10228' \
  --header 'Content-Type: application/json' \
  --data '{"target":"https://www.example.com/","webhook_auth":"ID"}'
```

- 现在你可以在你的webhook服务器中读取请求头中的`Authorization`字段就可以得到他的值为`ID`

- 一次API请求中添加多个目标：`targets`，会自动和`target`字段合并去重

```bash
➜  ~ curl --request POST \ 
  --url http://127.0.0.1:8000/v1/observer_ward \
  --header 'Authorization: Bearer 22e038328151a7a06fd4ebfa63a10228' \
  --header 'Content-Type: application/json' \
  --data '{"target":"https://127.0.0.1:9443/","webhook_auth":"ID","targets":["https://127.0.0.1:8000/","http://127.0.0.1:9200/"]}'
```

### 危险模式

- `--danger`参数会加上敏感请求头，有可能会被Web防火墙拦截，默认不加。

### 自定义UA

- `--ua`参数可以自定义请求头里面的`USER_AGENT`
  ，默认是`Mozilla/5.0 (X11; Linux x86_64; rv:94.0) Gecko/20100101 Firefox/94.0`。

### 静默模式

- `--silent`参数为静默模式，不会输出任何信息，结果需要保存在文件，方便在webshell执行。

## 提交指纹

- ObserverWard使用到的指纹规则全部来自[FingerprintHub](https://github.com/0x727/FingerprintHub)项目。
- 如果需要获取指纹库和提交指纹规则，请查看[FingerprintHub](https://github.com/0x727/FingerprintHub)项目。

## 为ObserverWard_0x727做贡献

### 提交代码

- 点击Fork按钮克隆这个项目到你的仓库

```bash
git clone git@github.com:你的个人github用户名/ObserverWard.git
```

- 添加上游接收更新

```bash
cd ObserverWard
git remote add upstream git@github.com:0x727/ObserverWard.git
git fetch upstream
```

- 配置你的github个人信息

```bash
git config --global user.name "$GITHUB_USERNAME"
git config --global user.email "$GITHUB_EMAIL"
git config --global github.user "$GITHUB_USERNAME"
```

- 拉取所有分支的规则

```bash
git fetch --all
git fetch upstream
```

- **不要**直接在`main`分支上修改，例如我想修改某个bug，创建一个新的分支并切换到新的分支。

```bash
git checkout -b dev
```

- 修改完成后，测试通过
- 跟踪修改和提交Pull-Requests。

```
git add 你添加或者修改的文件名
git commit -m "添加你的描述"
git push origin dev
```

- 打开你Fork这个项目的地址，点击与上游合并，等待审核合并代码。

### 提交建议

ObserverWard 是一个免费且开源的项目，我们欢迎任何人为其开发和进步贡献力量。

- 在使用过程中出现任何问题，可以通过 issues 来反馈。
- Bug 的修复可以直接提交 Pull Request 到 dev 分支。
- 如果是增加新的功能特性，请先创建一个 issue 并做简单描述以及大致的实现方法，提议被采纳后，就可以创建一个实现新特性的 Pull
  Request。
- 欢迎对说明文档做出改善，帮助更多的人使用 ObserverWard，特别是英文文档。
- 贡献代码请提交 PR 至 dev 分支，master 分支仅用于发布稳定可用版本。
- 如果你有任何其他方面的问题或合作，欢迎发送邮件至 0x727Team@gmail.com 。

## Stargazers over time

[![Stargazers over time](https://starchart.cc/0x727/ObserverWard.svg)](https://github.com/0x727/ObserverWard)
