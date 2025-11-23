# 构建和使用说明

本文档提供了如何构建和使用`observer_ward`的Python绑定库的详细说明。

## 前提条件

- Rust 工具链 (推荐使用 rustup 安装)
- Python 3.8 或更高版本
- pip
- 可选: virtualenv 或 conda 用于创建虚拟环境

## 开发环境设置

1. 克隆仓库:

```bash
git clone https://github.com/emo-crab/observer_ward.git
```

2. 安装 maturin:

```bash
pip install maturin
```

3. 在开发模式下构建Python扩展:

```bash
cd python
maturin develop
```

这会将Python扩展模块安装到当前的Python环境中，便于开发和测试。

## 测试绑定

构建完成后，你可以运行示例脚本来测试绑定:

```bash
python example.py
```

## 构建发布版本

要构建可以分发的wheel包:

```bash
# 构建当前平台的wheel包
maturin build --release

# 或者构建兼容更多平台的wheel包
maturin build --release --compatibility manylinux2014
```

构建好的wheel包会保存在`target/wheels/`目录中。

## 安装发布版本

```bash
pip install target/wheels/observer_ward-0.1.0-*.whl
```

## 打包为PyPI包

1. 确保你有一个PyPI账号和必要的凭证。

2. 构建wheel包:

```bash
maturin build --release
```

3. 上传到PyPI:

```bash
maturin publish
```

或者手动上传使用twine:

```bash
pip install twine
twine upload target/wheels/observer_ward-0.1.0-*.whl
```

## 在其他项目中使用

安装后，你可以在任何Python项目中这样使用:

```python
from observer_ward import ObserverWard

# 从HTML内容识别web技术
html_content = """网页内容..."""
headers = [("Server", "nginx/1.18.0")]

observer_ward = ObserverWard()

# 执行指纹识别
results = observer_ward.execute(html_content, headers)

# 处理结果
for result in results:
    print(f"名称: {result['name']}")
    # ... 其他处理代码
```
