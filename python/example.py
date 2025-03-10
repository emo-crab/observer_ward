#!/usr/bin/env python3
# -*- coding: utf-8 -*-

"""
测试observer_ward Python绑定的示例脚本
"""

import os
import sys
from pathlib import Path

# 确保可以导入开发中的模块
current_dir = Path(__file__).parent
sys.path.insert(0, str(current_dir))

try:
    from observer_ward import ObserverWard
except ImportError:
    print("无法导入observer_ward模块。请先运行'maturin develop'构建模块。")
    sys.exit(1)

# 示例HTML内容
html_content = """
<!DOCTYPE html>
<html>
<head>
    <meta charset="utf-8">
    <meta name="generator" content="WordPress 5.8.2">
    <title>示例网页</title>
    <script src="https://cdn.jsdelivr.net/npm/jquery@3.6.0/dist/jquery.min.js"></script>
    <link rel="stylesheet" href="https://cdn.jsdelivr.net/npm/bootstrap@5.1.3/dist/css/bootstrap.min.css">
</head>
<body>
    <div class="container">
        <h1>Hello World</h1>
    </div>
    <script src="https://cdn.jsdelivr.net/npm/bootstrap@5.1.3/dist/js/bootstrap.bundle.min.js"></script>
</body>
</html>
"""

# 示例HTTP头
headers = [
    ("Server", "nginx/1.18.0"),
    ("X-Powered-By", "PHP/7.4.0"),
    ("Set-Cookie", "PHPSESSID=abcdef123456; path=/"),
]

def main():
    print("开始测试observer_ward Python绑定...")
    
    # 加载指纹库
    fingerprint_path = Path(__file__) / "examples" / "test_fingerprints.json"
    
    try:
        if not fingerprint_path.exists():
            print(f"找不到指纹库文件: {fingerprint_path}")
            print("尝试初始化ObserverWard，将使用默认位置的指纹库...")
            observer_ward = ObserverWard()
        else:
            print(f"使用指纹库: {fingerprint_path}")
            with open(fingerprint_path, "r", encoding="utf-8") as f:
                json_content = f.read()
            # 初始化ObserverWard类
            observer_ward = ObserverWard(json_content)
        
        # 执行指纹识别
        results = observer_ward.execute(html_content, headers)
        
        # 打印结果
        print(f"\n找到 {len(results)} 个匹配结果:")
        for result in results:
            print("\n" + "=" * 50)
            print(f"应用名称: {result['name']}")
            print(f"模板: {result['template']}")
            
            if result['tags']:
                print(f"标签: {', '.join(result['tags'])}")
            
            print(f"匹配关键词: {', '.join(result['matcher_names'])}")
            
            if result['extractor']:
                print("\n提取的数据:")
                for key, values in result['extractor'].items():
                    print(f"  {key}: {values}")
            
            print("=" * 50)
    
    except Exception as e:
        print(f"执行过程中出错: {e}")
        import traceback
        traceback.print_exc()

if __name__ == "__main__":
    main() 
