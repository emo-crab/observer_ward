## 为什么会有些https网站无法访问

- 该项目底层使用openssl提供安全连接，默认安全策略拒绝使用小于2048位的DH密钥，这是为了防止弱密钥攻击。
- 你可以修改OpenSSL的配置文件来允许使用较小的DH密钥。请注意，这样做可能会降低系统的安全性。
- 找到你的 OpenSSL 配置文件（通常位于 /etc/ssl/openssl.cnf 或 /usr/local/ssl/openssl.cnf），然后编辑它，添加或修改以下配置：

```ini
[system_default_sect]
CipherString = DEFAULT@SECLEVEL=1
```

- 然后通过设置环境变量指定配置文件的路径

```bash,no-run
export OPENSSL_CONF=/path/to/your/openssl.cnf
```

- 例如：openssl.cnf

```ini
openssl_conf = openssl_init

[openssl_init]
ssl_conf = ssl_sect

[ssl_sect]
system_default = system_default_sect

[system_default_sect]
CipherString = DEFAULT@SECLEVEL=1
```

- 再次提醒，降低安全级别可能会带来安全风险，最好在可能的情况下升级密钥大小以满足当前的安全标准。