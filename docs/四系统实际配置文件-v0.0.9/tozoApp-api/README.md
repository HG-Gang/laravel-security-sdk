# App 端 API（tozo-app-api）

两个环境的接入文件：

- `production/`：生产环境，占位域名为 example.com
- `testing/`：测试环境，占位域名为 example.test

两套配置的唯一差异是 `environment` 与 `peers` 的域名。
`environment` 参与密钥命名空间，因此两个环境不共用任何密钥文件。
