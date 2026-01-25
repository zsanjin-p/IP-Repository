# 🌐 IP 白名单管理系统

自动收集多设备公网 IP 并整合到统一白名单的完整解决方案。
适用多设备，城域网，软路由等ip变动场景访问敏感服务。

![image](https://github.com/zsanjin-p/IP-Repository/blob/main/doc/2026-01-25%20225318.png)


## 📋 系统概述

这是一个**客户端-服务端**架构的 IP 收集系统：

- **客户端**：在各设备上运行 Shell 脚本，自动检测公网 IP 并上传
- **服务端**：接收、整合、展示所有设备的 IP 数据
- **支持方式**：FTP 上传 或 HTTP API 上传

---

## 🚀 快速开始

### 1️⃣ 服务端部署

#### 上传文件到服务器

将以下 2 个 PHP 文件上传到你的服务器：

```
/www/wwwroot/myip.xxxx.com/
├── index.php              # 主API文件（前端+接口）
└── api/
    └── processor.php      # FTP文件处理脚本（可选）
```

#### 配置 API 密钥

编辑 `index.php`，修改：

```php
define('API_KEY', 'your_secret_api_key_here');  // 改成你的密钥
```

#### 目录权限设置

```bash
chmod 755 /www/wwwroot/myip.xxxx.com/api
chmod 755 /www/wwwroot/myip.xxxx.com/api/ip_data
chmod 755 /www/wwwroot/myip.xxxx.com/api/uploads  # 如果使用FTP
```

#### 设置定时任务（如果使用 FTP 方式）

添加到 crontab宝塔定时任务：

根据自身情况定时访问url即可自动整理一次当前ip数据库，需使用User-Agent访问
url：https://myip.xxxx.com/api/processor.php?mode=process


---

### 2️⃣ 客户端部署

#### Linux/macOS 用户

```bash
chmod +x collect_ip.sh
./collect_ip.sh
```

---



#### Windows 用户（使用 Git Bash或者wsl）

1. **下载安装** [Git for Windows](https://git-scm.com/download/win)
2. **右键选择** "Git Bash Here"
3. **运行脚本**：
   ```bash
   bash collect_ip.sh
   ```


## ⚙️ 客户端配置

编辑 `collect_ip.sh`，根据你的上传方式选择配置：

### 方式一：FTP 上传（推荐）

```bash
# 约第 8 行：选择上传方式
UPLOAD_METHOD="ftp"

# 约第 10-14 行：配置 FTP 信息
FTP_HOST="1.2.3.4"          # FTP服务器地址
FTP_PORT=21                         # FTP端口
FTP_USER="USER"         # FTP用户名
FTP_PASS="your_ftp_password"       # FTP密码
FTP_UPLOAD_DIR="/api/uploads"      # 上传目录
```

### 方式二：HTTP API 上传

```bash
# 约第 8 行：选择上传方式
UPLOAD_METHOD="http"

# 约第 6-7 行：配置 API
UPLOAD_URL="https://myip.xxxx.com/api/upload-ip"
API_KEY="your_secret_api_key_here"  # 与服务端一致
```

### 工作目录配置（约第 17 行）

```bash
# Linux
WORK_DIR="/root/myiplist"
```

---

## 🔄 设置自动运行

### Linux/WSL - 使用 Crontab或者宝塔定时任务运行，下面是Crontab为例子

```bash
# 编辑定时任务
crontab -e

# 每5分钟执行一次
*/5 * * * * /path/to/collect_ip.sh >> /path/to/collector.log 2>&1

# 或每小时执行
0 * * * * /path/to/collect_ip.sh
```


## 🌐 访问 Web 界面

部署完成后，访问以下地址查看数据：

### 📊 Web 管理界面
```
https://myip.xxxx.com/
```

显示内容：
- 总 IP 数量和设备数量
- 所有收集到的 IP 列表
- 各设备详细信息
- 最后更新时间

### 📄 API 接口

| 接口 | 说明 |
|------|------|
| `?action=ips` | 纯文本 IP 列表（一行一个） |
| `?action=json` | 完整 JSON 数据 |
| `?action=stats` | 统计信息 |
| `?action=list` | JSON 格式（兼容旧版） |
| `?action=list&format=txt` | TXT 格式（兼容旧版） |

**示例**：
```bash
# 获取所有IP（文本格式）
curl https://myip.xxxx.com/?action=ips

# 获取JSON数据
curl https://myip.xxxx.com/?action=json

# 获取统计信息
curl https://myip.xxxx.com/?action=stats
```

---

## 📁 文件结构

### 服务端
```
/www/wwwroot/myip.xxxx.com/
├── index.php                    # 主API + Web界面
├── api/
│   ├── processor.php           # FTP文件处理器（可选）
│   ├── ip_data/                # 数据存储目录
│   │   ├── merged_ips.json    # 整合后的IP数据
│   │   ├── ip_list.txt        # 简易IP列表
│   │   ├── device1.json       # 设备1的数据
│   │   └── device2.json       # 设备2的数据
│   └── uploads/                # FTP上传临时目录
```

### 客户端
```
/your/work/dir/
├── collect_ip.sh              # 收集脚本
├── ip_history.txt            # IP历史记录
├── ip_list.txt               # 导出的IP列表
├── ip_data.json              # 导出的JSON数据
├── collector.log             # 运行日志
└── device_id.txt             # 设备唯一ID
```

---

## 🔧 功能特性

### ✅ 客户端功能
- 🔍 多源 IP 检测（15+ 国内外服务）
- 🔄 自动重试机制
- 📝 IP 历史记录
- 🆔 设备唯一标识
- 📤 双上传方式（FTP/HTTP）
- 📊 JSON 和 TXT 双格式导出

### ✅ 服务端功能
- 📥 接收多设备数据
- 🔀 自动去重整合
- 🌐 可视化 Web 界面
- 🚦 频率限制保护
- 📡 多种 API 输出格式
- 🔐 API 密钥验证

---

## 🛠️ 故障排查
见日志文件
---

## 📝 使用场景

- 🏠 **家庭网络**：收集家中多台设备的动态公网 IP
- 🏢 **企业环境**：管理分支机构的出口 IP 白名单
- 🔒 **安全访问**：为 SSH/VPN 等服务维护动态白名单
- ☁️ **云服务**：自动更新防火墙规则

---

## ⚠️ 安全建议

1. **修改默认 API 密钥**：使用强随机字符串
2. **限制 IP 访问**：在 Web 服务器配置访问控制
3. **使用 HTTPS**：保护数据传输安全
4. **定期清理日志**：避免日志文件过大
5. **备份数据**：定期备份 `ip_data` 目录

---

## 📄 许可证

MIT License - 自由使用和修改

---

## 🤝 贡献

欢迎提交 Issue 和 Pull Request！

---

## 📮 联系方式

如有问题，请通过 GitHub Issues 联系。

---

**⭐ 如果这个项目对你有帮助，请给个 Star！**
