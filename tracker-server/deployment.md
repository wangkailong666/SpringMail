# NovaMail Tracker Server — 部署指南

## 架构概述

追踪服务器接收邮件客户端加载追踪像素时的 HTTP 请求，记录打开事件，返回 1x1 透明 GIF。

```
邮件客户端 → GET /track?e=42&t=abc...&s=64hex... → 追踪服务器 → 验证签名 → 记录事件 → 返回 GIF
                                                              ↓
                                                       R2 / JSON 文件
```

## 选项 A: Cloudflare Workers + R2（推荐）

### 前提条件

- [Cloudflare](https://cloudflare.com) 账号
- [wrangler CLI](https://developers.cloudflare.com/workers/wrangler/) 已安装
- R2 订阅（免费额度 10GB 存储，每月 1000 万次读请求）

### 部署步骤

```bash
cd tracker-server/cloudflare

# 1. 安装依赖
npm install

# 2. 登录 Cloudflare
npx wrangler login

# 3. 创建 R2 bucket
npx wrangler r2 bucket create novamail-tracker-logs

# 4. 设置 API token（用于 /stats 端点认证）
npx wrangler secret put STATS_API_TOKEN
# 输入一个随机生成的 token（例如用: openssl rand -hex 32）

# 5. 设置 HMAC 签名密钥（可选，推荐）
npx wrangler secret put HMAC_SECRET
# 输入一个随机密钥（例如用: openssl rand -hex 32）
# 该密钥必须与 NovaMail 客户端设置中的 "HMAC Signing Secret" 一致

# 6. 部署
npx wrangler deploy

# 7. （可选）配置自定义域名
# 在 wrangler.toml 中取消 routes 注释，或通过 Cloudflare Dashboard 添加
```

### 环境变量

| 变量 | 说明 | 默认值 |
|------|------|--------|
| `STATS_API_TOKEN` | /stats 端点的认证 token | 无（必填） |
| `HMAC_SECRET` | HMAC-SHA256 签名验证密钥（M3-10） | 空（不验证） |

### 端点

| 端点 | 说明 |
|------|------|
| `GET /track?e={mail_id}&t={token}&s={hmac}` | 记录打开事件，返回 1x1 GIF |
| `GET /stats?api_token={key}&mail_id={id}` | 返回聚合统计 JSON |
| `GET /health` | 健康检查 |

### 测试

```bash
# 测试像素端点
curl -s -o /dev/null -w "%{http_code}" \
  "https://your-worker.workers.dev/track?e=42&t=$(openssl rand -base64 32 | tr '+/' '-_' | cut -c1-43)"

# 测试统计端点（使用你设置的 API token）
curl "https://your-worker.workers.dev/stats?api_token=YOUR_TOKEN&mail_id=42"
```

## 选项 B: 自建 VPS（Go + Docker）

### 前提条件

- Linux 服务器（或任何支持 Docker 的系统）
- Docker + Docker Compose

### 部署步骤

```bash
cd tracker-server/vps

# 1. 设置 API token
export STATS_API_TOKEN=$(openssl rand -hex 32)
echo "STATS_API_TOKEN=$STATS_API_TOKEN"

# (可选) 设置 HMAC 签名密钥
export HMAC_SECRET=$(openssl rand -hex 32)
echo "HMAC_SECRET=$HMAC_SECRET"

#部署Docker
docker compose up -d --build


# 2. 启动服务/停止服务
启动：docker compose up -d
docker compose start

停止：docker compose stop

# 3. 验证
curl http://localhost:8080/health
```

### 环境变量

| 变量 | 说明 | 默认值 |
|------|------|--------|
| `PORT` | 监听端口 | `8080` |
| `DATA_DIR` | 数据存储目录 | `./data` |
| `STATS_API_TOKEN` | /stats 端点认证 token | 空（不启用认证） |
| `HMAC_SECRET` | HMAC-SHA256 签名验证密钥（M3-10） | 空（不验证） |

### Nginx 反向代理配置

```nginx
server {
    listen 443 ssl;
    server_name tracker.yourdomain.com;

    ssl_certificate /path/to/cert.pem;
    ssl_certificate_key /path/to/key.pem;

    location / {
        proxy_pass http://127.0.0.1:8080;
        proxy_set_header Host $host;
        proxy_set_header X-Real-IP $remote_addr;
        proxy_set_header X-Forwarded-For $proxy_add_x_forwarded_for;
    }
}
```

### 数据持久化

docker volume `tracker-data` 将日志文件持久化到宿主机。日志格式为 JSON Lines：

```json
{"mail_id":42,"token":"abc...","ip":"1.2.3.4","country":"US","user_agent":"Mozilla/5.0...","timestamp":1700000000000}
```

## NovaMail 客户端配置

在 NovaMail 设置中配置追踪服务器 URL（后续 M3-08 实现）：

```
Settings → Read Tracking → Tracker Server URL
输入: https://tracker.example.com/track
```

目前 M3-02 中 `MailEngine::send()` 使用默认 URL `https://tracker.example.com/track`，后续可通过设置或 `MailCompose.tracker_url` 覆盖。

## 安全注意事项

1. **Token 长度 43 字符**：32 字节随机数，base64url 编码，暴力破解不可行
2. **HMAC-SHA256 签名**（M3-10）：追踪 URL 包含 `s=` 参数（64 字符十六进制 HMAC-SHA256 签名），伪造的 `mail_id` 或 `token` 会被追踪服务器拒绝，不会记录任何事件。客户端和追踪服务器需配置相同的 `HMAC_SECRET`
3. **/stats 端点**：必须设置 `STATS_API_TOKEN` 防止未授权访问
4. **返回像素永不失败**：即使参数无效也返回 GIF，不暴露追踪存在
5. **无用户识别**：仅记录 IP 和 User-Agent，不设置 Cookie 或跟踪用户身份