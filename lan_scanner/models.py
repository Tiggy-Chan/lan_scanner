"""
局域网设备扫描器 - 数据模型

包含用于存储设备信息和扫描元数据的数据类。
"""

from dataclasses import dataclass, field
from datetime import datetime
from typing import List


@dataclass
class PortInfo:
    """设备开放端口信息。
    
    Attributes:
        port: 端口号 (1-65535)
        protocol: 协议类型 (tcp/udp)
        service: 端口上运行的服务名称
        state: 端口状态 (open/closed/filtered)
    """
    port: int
    protocol: str = "tcp"
    service: str = "未知"
    state: str = "open"
    
    def __post_init__(self):
        """验证端口号并规范化字段。"""
        if not isinstance(self.port, int) or not (1 <= self.port <= 65535):
            raise ValueError(f"无效的端口号: {self.port}，必须在 1-65535 之间。")
        self.protocol = str(self.protocol).lower()
        self.service = str(self.service) if self.service else "未知"
        self.state = str(self.state).lower() if self.state else "open"


@dataclass
class DeviceInfo:
    """发现的网络设备信息。
    
    Attributes:
        ip: 设备 IP 地址 (必填)
        mac: 设备 MAC 地址
        hostname: 通过反向 DNS 解析的主机名
        vendor: 通过 OUI 查询的设备厂商
        os: 通过指纹识别的操作系统
        open_ports: 发现的开放端口列表
        latency: 响应延迟
    """
    ip: str
    mac: str = "未知"
    hostname: str = "未知"
    vendor: str = "未知"
    os: str = "未知"
    open_ports: List[PortInfo] = field(default_factory=list)
    latency: str = "未知"
    
    def __post_init__(self):
        """验证 IP 地址并规范化字段。"""
        # 验证 IP 地址格式
        if not self.ip or not isinstance(self.ip, str):
            raise ValueError("IP 地址是必填项且必须是字符串。")
        
        # 基本 IP 格式验证
        parts = self.ip.split('.')
        if len(parts) != 4:
            raise ValueError(f"无效的 IP 地址格式: {self.ip}")
        for part in parts:
            try:
                num = int(part)
                if not (0 <= num <= 255):
                    raise ValueError(f"无效的 IP 地址: {self.ip}")
            except ValueError:
                raise ValueError(f"无效的 IP 地址: {self.ip}")
        
        # 规范化字段 - 确保是字符串，空值默认为 "未知"
        self.mac = str(self.mac) if self.mac else "未知"
        self.hostname = str(self.hostname) if self.hostname else "未知"
        self.vendor = str(self.vendor) if self.vendor else "未知"
        self.os = str(self.os) if self.os else "未知"
        self.latency = str(self.latency) if self.latency else "未知"
        
        # 确保 open_ports 是列表
        if self.open_ports is None:
            self.open_ports = []


@dataclass
class ScanInfo:
    """网络扫描元数据。
    
    Attributes:
        subnet: 扫描的子网范围 (CIDR 格式)
        interface: 用于扫描的网络接口
        start_time: 扫描开始时间
        end_time: 扫描结束时间
        total_hosts: 发现的设备数量
    """
    subnet: str
    interface: str = "未知"
    start_time: datetime = field(default_factory=datetime.now)
    end_time: datetime = None
    total_hosts: int = 0
    
    def __post_init__(self):
        """验证并规范化扫描信息字段。"""
        if not self.subnet or not isinstance(self.subnet, str):
            raise ValueError("子网是必填项且必须是字符串。")
        
        self.interface = str(self.interface) if self.interface else "未知"
        
        if self.start_time is None:
            self.start_time = datetime.now()
        
        if not isinstance(self.total_hosts, int) or self.total_hosts < 0:
            self.total_hosts = 0
    
    @property
    def duration(self) -> str:
        """计算扫描耗时并返回格式化字符串。"""
        if self.end_time is None:
            return "进行中"
        delta = self.end_time - self.start_time
        seconds = int(delta.total_seconds())
        if seconds < 60:
            return f"{seconds}秒"
        minutes = seconds // 60
        remaining_seconds = seconds % 60
        return f"{minutes}分{remaining_seconds}秒"
