# LAN Device Scanner / 局域网设备扫描器

[English](#english) | [中文](#中文)

---

## English

A network scanning tool for discovering and identifying devices on the local network.

### Features

- **Automatic Network Detection**: Automatically detects the local network interface and subnet
- **Multi-Subnet Scanning**: Support scanning multiple subnets in one run
- **Device Discovery**: Discovers all active devices on the network using nmap
- **Detailed Information**: Collects IP, MAC, hostname, vendor, OS, open ports, and latency
- **Markdown Reports**: Generates formatted Markdown reports with scan results (in Chinese)
- **Progress Display**: Shows real-time scan progress
- **Graceful Interruption**: Saves partial results when interrupted with Ctrl+C

### Requirements

- Python 3.6+
- Linux (tested on Kali Linux)
- nmap
- Root/sudo privileges (recommended for full functionality)

### Installation

1. Clone or download this repository

2. Install Python dependencies:
```bash
pip install -r requirements.txt
```

3. Ensure nmap is installed:
```bash
sudo apt install nmap
```

### Usage

#### Basic Usage

```bash
sudo python scan.py
```

#### Command Line Options

```
usage: scan.py [-h] [-i INTERFACE] [-s SUBNET [SUBNET ...]] [-o OUTPUT] 
               [-t {1,2,3,4,5}] [-q] [-v]

options:
  -h, --help            Show help message and exit
  -i, --interface       Network interface (e.g., eth0, wlan0). Auto-detected if not specified
  -s, --subnet          Subnet(s) to scan in CIDR notation. Can specify multiple
                        Example: -s 192.168.1.0/24 192.168.2.0/24 10.0.0.0/24
  -o, --output          Output file path for the Markdown report
  -t, --intensity       Scan intensity (1=slowest, 5=fastest). Default: 4
  -q, --quiet           Suppress progress output
  -v, --version         Show version number and exit
```

#### Examples

```bash
# Scan with default settings (auto-detect subnet)
sudo python scan.py

# Scan multiple subnets
sudo python scan.py -s 192.168.1.0/24 192.168.2.0/24 10.0.0.0/24

# Specify interface and output file
sudo python scan.py -i eth0 -o my_scan.md

# Fast scan with quiet mode
sudo python scan.py -t 5 -q -o results.md
```

---

## 中文

用于发现和识别局域网内设备的网络扫描工具。

### 功能特性

- **自动网络检测**: 自动检测本地网络接口和子网
- **多子网扫描**: 支持一次扫描多个子网
- **设备发现**: 使用 nmap 发现网络上所有活跃设备
- **详细信息**: 收集 IP、MAC、主机名、厂商、操作系统、开放端口和延迟
- **Markdown 报告**: 生成格式化的中文 Markdown 扫描报告
- **进度显示**: 实时显示扫描进度
- **优雅中断**: 按 Ctrl+C 中断时保存已扫描的部分结果

### 系统要求

- Python 3.6+
- Linux (在 Kali Linux 上测试)
- nmap
- Root/sudo 权限 (推荐，以获得完整功能)

### 安装

1. 克隆或下载本仓库

2. 安装 Python 依赖:
```bash
pip install -r requirements.txt
```

3. 确保已安装 nmap:
```bash
sudo apt install nmap
```

### 使用方法

#### 基本用法

```bash
sudo python scan.py
```

#### 命令行参数

```
用法: scan.py [-h] [-i 接口] [-s 子网 [子网 ...]] [-o 输出文件] 
              [-t {1,2,3,4,5}] [-q] [-v]

参数:
  -h, --help            显示帮助信息并退出
  -i, --interface       指定网络接口 (如 eth0, wlan0)，不指定则自动检测
  -s, --subnet          指定要扫描的子网 (CIDR 格式)，可指定多个
                        示例: -s 192.168.1.0/24 192.168.2.0/24 10.0.0.0/24
  -o, --output          输出报告文件路径
  -t, --intensity       扫描强度 (1=最慢/最隐蔽, 5=最快/最激进)，默认: 4
  -q, --quiet           静默模式，不显示进度
  -v, --version         显示版本号并退出
```

#### 使用示例

```bash
# 使用默认设置扫描 (自动检测子网)
sudo python scan.py

# 扫描多个子网
sudo python scan.py -s 192.168.1.0/24 192.168.2.0/24 10.0.0.0/24

# 指定接口和输出文件
sudo python scan.py -i eth0 -o my_scan.md

# 快速扫描，静默模式
sudo python scan.py -t 5 -q -o results.md
```

### 输出示例

```markdown
# 局域网设备扫描报告

## 扫描信息

- **扫描时间**: 2025-12-15 10:30:45
- **扫描子网**: 192.168.1.0/24
- **网络接口**: eth0

## 扫描摘要

- **发现设备总数**: 5
- **扫描耗时**: 2分15秒

## 发现的设备

| IP 地址 | MAC 地址 | 主机名 | 厂商 | 操作系统 | 开放端口 | 延迟 |
|---------|----------|--------|------|----------|----------|------|
| 192.168.1.1 | AA:BB:CC:DD:EE:FF | router | Cisco | Linux | 22/tcp, 80/tcp | TTL: 64 |
```

### 项目结构

```
.
├── scan.py                    # 主入口
├── requirements.txt           # Python 依赖
├── README.md                  # 本文件
├── lan_scanner/               # 核心模块
│   ├── __init__.py           # 包初始化，定义版本号
│   ├── models.py             # 数据模型 (DeviceInfo, PortInfo, ScanInfo)
│   ├── network_interface.py  # 网络接口检测
│   ├── scanner.py            # nmap 扫描
│   ├── vendor_lookup.py      # MAC 厂商查询
│   └── markdown_report.py    # 报告生成
└── tests/                     # 测试套件
    ├── test_models.py
    ├── test_network_interface.py
    ├── test_scanner.py
    ├── test_vendor_lookup.py
    └── test_markdown_report.py
```

### 故障排除

#### "nmap 未安装"
```bash
sudo apt install nmap
```

#### "未找到默认网关"
检查网络配置:
```bash
ip route show
```

#### "接口未配置 IPv4 地址"
确保指定的接口有 IP 地址:
```bash
ip addr show
```

#### 不使用 sudo 时扫描结果有限
使用管理员权限运行以获得完整功能:
```bash
sudo python scan.py
```

### 许可证

MIT License
