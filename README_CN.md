![logo](./doc/images/logo.png)

[English](./README.md) | [中文简体](./README_CN.md)

# ObserverWard_0x727

| 类别 | 说明 |
| ---- | --- |
| 作者 | [三米前有蕉皮](https://github.com/cn-kali-team) |
| 团队 | [0x727](https://github.com/0x727) 未来一段时间将陆续开源工具 |
| 定位 | 社区化[指纹库](https://github.com/0x727/FingerprintHub)识别工具。 |
| 语言 | Rust |
| 功能 | 命令行，API服务Web指纹识别工具 |

### 1. 源码手动安装

```bash
git clone https://github.com/0x727/ObserverWard_0x727
cd ObserverWard_0x727
cargo build --target  x86_64-unknown-linux-musl --release --all-features
```

- 更多安装细节请查看当前项目的Actions自动化编译构建流程[文件](https://github.com/0x727/ObserverWard_0x727/blob/main/.github/workflows/basic.yml)。

### 2. 下载二进制安装

- [发行版本](https://github.com/0x727/ObserverWard_0x727/releases)下载页面。

## 使用方法

```bash
➜  ~ ./observer_ward -h
ObserverWard 0.0.1
author: Kali-Team

USAGE:
    observer_ward [FLAGS] [OPTIONS]

FLAGS:
    -h, --help       Prints help information
        --stdin      Read url(s) from STDIN
    -u, --update     Update web fingerprint
    -V, --version    Prints version information

OPTIONS:
    -c, --csv <CSV>          Export to the csv file
    -f, --file <FILE>        Path to the file
    -j, --json <JSON>        Export to the json file
    -s, --server <SERVER>    Start a web API service (127.0.0.1:8080)
    -t, --target <TARGET>    The target URL(s) (required, unless --stdin used)

```

| 命令行参数    | 描述                                                         |
| ------------- | ------------------------------------------------------------ |
| -h, --help    | 打印帮助信息                                                 |
| --stdin       | 从标准输出获取要识别的目标                                   |
| -u, --update  | 从远程[指纹库](https://github.com/0x727/FingerprintHub)更新最新指纹，也可以手动从[Github](https://0x727.github.io/FingerprintHub/web_fingerprint_v2.json)下载 |
| -V, --version | 打印版本                                                     |
| -c, --csv     | 将识别结果导出csv文件，接受一个文件路径                      |
| -f, --file    | 从文件里面读取要识别的目标                                   |
| -j, --json    | 将识别结果导出json文件，接受一个文件路径                     |
| -s, --server  | 开启api服务，接收要监听的IP和端口，例如：127.0.0.1:8080      |
| -t, --target  | 识别单个目标                                                 |

### 开启API服务

```bash
➜  ~ ./observer_ward -s 127.0.0.1:8080
API service has been started:http://127.0.0.1:8080/what_web
Instructions:
curl --request POST \
  --url http://127.0.0.1:8080/what_web \
  --header 'Content-Type: application/json' \
  --data '{"targets":["https://httpbin.org/"]}'
Result:
[{"url":"https://httpbin.org/","what_web_name":["swagger"],"priority":2,"length":9593,"title":"httpbin.org"}]
```

- 服务开启后会在提供的IP和端口上开启Web指纹识别的API服务。

![image-20210821173531800](./doc/README.assets/image-20210821173531800.png)

- API接口地址为`http://127.0.0.1:8080/what_web`，请求方式为`POST`，接受json数据结构如下：

```json
{
  "targets": [
    "https://gitea.com/",
    "https://httpbin.org"
  ]
}
```

![image-20210821173903713](./doc/README.assets/image-20210821173903713.png)

- 返回结果速度取决于本地服务与要识别目标的网络状况，提交多个时会等待全部目标识别完成后才会返回。

### 单个目标识别

```bash
➜  ~ ./observer_ward -t https://httpbin.org
[ https://httpbin.org | ["swagger"] | 9593 | httpbin.org |

高关注组件:

+---------------------+---------+--------+-------------+----------+
| Url                 | Name    | Length | Title       | Priority |
+=====================+=========+========+=============+==========+
| https://httpbin.org | swagger | 9593   | httpbin.org | 2        |
+---------------------+---------+--------+-------------+----------+
```

![image-20210821130602444](./doc/README.assets/image-20210821130602444.png)

### 从文件获取要识别的目标

```bash
➜  ~ ./observer_ward -f target.txt
```

![image-20210821172459511](./doc/README.assets/image-20210821172459511.png)

![image-20210821172601830](./doc/README.assets/image-20210821172601830.png)

### 从标准输出获取识别目标

```bash
➜  ~ cat target.txt| ./observer_ward --stdin
```

- 结果和从文件获取的效果一样，这里不再截图展示。

### 导出结果到JSON文件

```bash
➜  ~ ./observer_ward -t https://httpbin.org -j result.json
[ https://httpbin.org/ | ["swagger"] | 9593 | httpbin.org |

高关注组件:

+----------------------+---------+--------+-------------+----------+
| Url                  | Name    | Length | Title       | Priority |
+======================+=========+========+=============+==========+
| https://httpbin.org/ | swagger | 9593   | httpbin.org | 2        |
+----------------------+---------+--------+-------------+----------+
➜  ~ cat result.json
[{"url":"https://httpbin.org/","what_web_name":["swagger"],"priority":2,"length":9593,"title":"httpbin.org"}]%
```

### 导出结果到CSV文件

```bash
➜  ~ ./observer_ward -t https://httpbin.org -c result.csv
[ https://httpbin.org/ | ["swagger"] | 9593 | httpbin.org |

高关注组件:

+----------------------+---------+--------+-------------+----------+
| Url                  | Name    | Length | Title       | Priority |
+======================+=========+========+=============+==========+
| https://httpbin.org/ | swagger | 9593   | httpbin.org | 2        |
+----------------------+---------+--------+-------------+----------+
➜  ~ cat result.csv 
Url,Name,Length,Title,Priority
https://httpbin.org/,swagger,9593,httpbin.org,2
```

## 提交指纹

-
ObserverWard_0x727使用到的指纹规则全部来自[FingerprintHub](https://github.com/0x727/FingerprintHub)项目，如果需要获取指纹库和提交指纹规则，请查看[FingerprintHub](https://github.com/0x727/FingerprintHub)项目。

## 为ObserverWard_0x727做贡献

ObserverWard_0x727 是一个免费且开源的项目，我们欢迎任何人为其开发和进步贡献力量。

- 在使用过程中出现任何问题，可以通过 issues 来反馈。
- Bug 的修复可以直接提交 Pull Request 到 dev 分支。
- 如果是增加新的功能特性，请先创建一个 issue 并做简单描述以及大致的实现方法，提议被采纳后，就可以创建一个实现新特性的 Pull Request。
- 欢迎对说明文档做出改善，帮助更多的人使用 ObserverWard_0x727，特别是英文文档。
- 贡献代码请提交 PR 至 dev 分支，master 分支仅用于发布稳定可用版本。
- 如果你有任何其他方面的问题或合作，欢迎发送邮件至 0x727Team@gmail.com 。

## Stargazers over time

[![Stargazers over time](https://starchart.cc/0x727/ObserverWard_0x727.svg)](https://github.com/0x727/ObserverWard_0x727)