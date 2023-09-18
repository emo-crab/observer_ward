# Change Log

<!-- next-header -->

## [Unreleased] - ReleaseDate

## [2023.9.18] - 2023.9.18

### Fixes

- 修复charset没覆盖的情况，感谢@zema1

## [2023.8.21] - 2023.8.21

### Fixes

- 修复webhook判断
- 添加`webhook_auth`字段用来标识任务，还可以作为webhook的认证
- 添加从API读取多个目标支持`targets`字段

## [2023.8.14] - 2023.8.14

### Fixes

- 修复获取html编码charset属性时存在双引号导致gb2312解码乱码
- 修复favicon响应错误没有保存命中到缓存，导致多次请求同一个url，浪费请求资源

## [2023.8.3] - 2023.8.3

### Fixes

- 添加字段：extracted-results

## [2023.7.21] - 2023.7.21

### Fixes

- `--gen`参数可以配合`--yaml`参数将指定yaml目录中的全部yaml指纹规则生成单个json文件，主要方便自定义指纹，生成便携单文件。
- `/home/kali-team/IdeaProjects/FingerprintHub/web_fingerprint`是存放yaml的目录，`web_fingerprint_v3.json`是生成的文件路径。

```bash
➜  ~ ./observer_ward --yaml /home/kali-team/IdeaProjects/FingerprintHub/web_fingerprint --gen web_fingerprint_v3.json
➜  ~ jq length web_fingerprint_v3.json
3448
```

- 添加如果本地没有指纹库，会自动更新指纹。防止跑完发现没有下载指纹，白跑了目标。

## [2023.6.20] - 2023.6.20

### Fixes

- `--nargs`可以添加nuclei扩展参数， 比如：`--nargs "-etags intrusive"`，排除有入侵危险的template。

## [2023.6.13] - 2023.6.13

### Fixes

- 使用nuclei的`-tc`表达式过滤`templates`
- 修复部分js跳转

## [2023.5.27] - 2023.5.27

### Fixes

- `--yaml`指定`FingerprintHub`的`web_fingerprint`文件夹，加载全部yaml文件，比较慢，只适合本地测试。
- 修复空tags跑了全部poc

## [2023.5.24] - 2023.5.24

### Fixes

- `--ua`参数可以自定义请求头里面的`USER_AGENT`
  ，默认是`Mozilla/5.0 (X11; Linux x86_64; rv:94.0) Gecko/20100101 Firefox/94.0`。
- `--danger`参数会加上敏感请求头，有可能会被Web防火墙拦截，默认不加。

## [2023.5.19] - 2023.5.19

### Fixes

- 更新nuclei版本到`v2.9.4`，需要将`-json`改为`-jsonl`

## [2023.4.27] - 2023.4.27

### Fixes

- 无论http和https都添加特殊路径请求
- 添加`--fpath`指定`web_fingerprint_v3.json`指纹库文件
- 添加`--path`指定官方的`nuclei-templates`，根据指纹读取`tags.yaml`的添加`--tags`参数到nuclei的命令行

## [2022.10.10] - 2022.10.10

### Fixes

- 更新命令行解析库为argh

## [2022.9.26] - 2022.9.26

### Fixes

- 添加请求过程关键词高亮

## [2022.8.16] - 2022.8.16

### Fixes

- 添加只显示有指纹的参数，`--filter`

## [2022.7.7] - 2022.7.7

### Fixes

- 从_html获取标题
- 取消覆盖https的状态码和标题
- 优化URL跳转正则

## [2022.6.29] - 2022.6.29

### Fixes

- 内置apache-shiro的指纹
- 判断icon响应是否为图片格式
- 修复跳转链接提取

## [2022.6.22] - 2022.6.22

### Fixes

- 从meta标签获取标题
- 如果api的webhook不为空，则将任务结果异步推送到webhook服务器

## [2022.6.1] - 2022.6.1

### Fixes

- 修复URL跳转正则，替换URL中的单引号
- URL提取后再转小写

## [2022.5.19] - 2022.5.19

### Fixes

- 修改严重程度的颜色
- 减少蜜罐触发阀值到5
- 添加静默模式，方便在webshell执行

## [2022.5.5] - 2022.5.5

### Fixes

- 替换终端颜色输出依赖库
- 添加漏洞严重程度等级
- 添加浮现命令补丁

## [2022.4.28] - 2022.4.28

### Fixes

- 在特殊请求中匹配全部关键词

## [2022.4.19] - 2022.4.19

### Fixes

- 合并@kekeimiku的优化代码
- web服务添设置32个workers
- homebrew自动推送

## [2022.4.14] - 2022.4.14

### Fixes

- 在`--verify`验证模式下输出请求过程和匹配到的规则
- 兼容带协议Url跳转，增加最大跳转次数为`5`

## [2022.4.11] - 2022.4.11

### Fixes

- 修复自更新bug
- 修复请求头转字符串转义
- 匹配ICON图标正则

## [2022.3.16] - 2022-03-15

### Fixes

- 如果当前目录有指纹库会使用当前目录的指纹库
- 修改匹配请求头里的Set-Cookie为查找匹配
- 添加URL跳转正则

## [2022.3.15] - 2022-03-15

### Fixes

- 添加更新日志，依赖机器人
- 修改`observer_ward_aarch64_darwin`，到更新列表
- 将https证书路径设置为程序配置目录