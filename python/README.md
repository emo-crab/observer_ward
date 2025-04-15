# observer-ward-py

Python绑定库，用于web技术指纹识别。这是[ObserverWard](https://github.com/emo-crab/observer_ward)项目中observer-ward库的Python接口。

## 安装

- 请看 [BUILDING.md](BUILDING.md)文件

## 用法

### 基本用法

```python
import os
from observer_ward import ObserverWard

with open('examples/test_fingerprints.json', 'r') as f:
    content = f.read()

# 初始化ObserverWard对象
# 不提供参数时，会尝试从默认位置加载指纹库
observer_ward = ObserverWard(content)

# 从HTML内容识别web技术
html_content = """
<!DOCTYPE html>
<html>
<head>
    <meta charset="utf-8">
    <meta name="generator" content="WordPress 5.8.2">
    <title>示例网页</title>
</head>
<body>
    <div class="container">
        <h1>Hello World</h1>
    </div>
</body>
</html>
"""

# 提供HTTP头 (可选)
headers = [
    ("Server", "nginx/1.18.0"),
    ("X-Powered-By", "PHP/7.4.0")
]

# 执行指纹识别
results = observer_ward.execute(html_content, headers)

# 打印匹配结果
for result in results:
    print(f"名称: {result['name']}")
    print(f"模板: {result['template']}")
    print(f"标签: {', '.join(result['tags'])}")
    print(f"匹配关键词: {', '.join(result['matcher_names'])}")
    
    if result['extractor']:
        print("提取数据:")
        for key, values in result['extractor'].items():
            print(f"  {key}: {values}")
    
    print("-" * 40)
```

### 使用自定义指纹库

```python
from observer_ward import ObserverWard
import json

# 读取自定义指纹库
with open("my_fingerprints.json", "r") as f:
    json_content = f.read()

# 使用自定义指纹库初始化ObserverWard
observer_ward = ObserverWard(json_content)

# 执行指纹识别
results = observer_ward.execute(html_content, headers)

# 打印结果
print(f"找到 {len(results)} 个匹配结果")
for result in results:
    print(f"名称: {result['name']}")
    # ...其他处理代码
```

## 构建开发版本

```bash
cd python
maturin develop
```
