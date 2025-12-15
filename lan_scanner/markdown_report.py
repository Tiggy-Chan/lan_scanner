"""
局域网设备扫描器 - Markdown 报告生成模块

根据扫描结果生成格式化的 Markdown 报告。
"""

from datetime import datetime
from typing import List, Optional
import sys

from lan_scanner.models import DeviceInfo, ScanInfo


class MarkdownReport:
    """根据扫描结果生成 Markdown 报告。
    
    Attributes:
        devices: 发现的设备列表
        scan_info: 扫描元数据
    """
    
    def __init__(self, devices: List[DeviceInfo], scan_info: ScanInfo):
        """初始化报告生成器。
        
        Args:
            devices: 扫描得到的 DeviceInfo 对象列表
            scan_info: 包含扫描元数据的 ScanInfo 对象
        """
        self.devices = devices if devices else []
        self.scan_info = scan_info
    
    def _escape_markdown(self, text: str) -> str:
        """转义 Markdown 特殊字符。
        
        Args:
            text: 要转义的文本
            
        Returns:
            转义后的文本
        """
        if not text:
            return ""
        # 转义管道符，避免破坏表格格式
        text = str(text).replace("|", "\\|")
        # 转义换行符
        text = text.replace("\n", " ").replace("\r", "")
        return text
    
    def _generate_header(self) -> str:
        """生成报告头部。
        
        Returns:
            头部的 Markdown 字符串
        """
        timestamp = self.scan_info.start_time.strftime("%Y-%m-%d %H:%M:%S")
        
        header = f"""# 局域网设备扫描报告

## 扫描信息

- **扫描时间**: {timestamp}
- **扫描子网**: {self._escape_markdown(self.scan_info.subnet)}
- **网络接口**: {self._escape_markdown(self.scan_info.interface)}
"""
        return header

    def _generate_summary(self) -> str:
        """生成摘要部分。
        
        Returns:
            摘要的 Markdown 字符串
        """
        device_count = len(self.devices)
        duration = self.scan_info.duration
        
        summary = f"""
## 扫描摘要

- **发现设备总数**: {device_count}
- **扫描耗时**: {duration}
"""
        return summary

    def _format_ports(self, device: DeviceInfo) -> str:
        """将开放端口格式化为逗号分隔的字符串。
        
        Args:
            device: DeviceInfo 对象
            
        Returns:
            格式化的端口字符串
        """
        if not device.open_ports:
            return "无"
        
        port_strs = []
        for port in device.open_ports:
            port_strs.append(f"{port.port}/{port.protocol}")
        return ", ".join(port_strs)
    
    def _generate_device_table(self) -> str:
        """生成设备表格部分。
        
        Returns:
            设备表格的 Markdown 字符串
        """
        if not self.devices:
            return "\n## 发现的设备\n\n未发现任何设备。\n"
        
        table = """
## 发现的设备

| IP 地址 | MAC 地址 | 主机名 | 厂商 | 操作系统 | 开放端口 | 延迟 |
|---------|----------|--------|------|----------|----------|------|
"""
        for device in self.devices:
            ip = self._escape_markdown(device.ip)
            mac = self._escape_markdown(device.mac)
            hostname = self._escape_markdown(device.hostname)
            vendor = self._escape_markdown(device.vendor)
            os_info = self._escape_markdown(device.os)
            ports = self._escape_markdown(self._format_ports(device))
            latency = self._escape_markdown(device.latency)
            
            table += f"| {ip} | {mac} | {hostname} | {vendor} | {os_info} | {ports} | {latency} |\n"
        
        return table

    def generate(self) -> str:
        """生成完整的 Markdown 报告。
        
        Returns:
            完整的 Markdown 报告字符串
        """
        report = self._generate_header()
        report += self._generate_summary()
        report += self._generate_device_table()
        return report
    
    def save(self, filepath: Optional[str] = None) -> bool:
        """保存报告到文件。
        
        Args:
            filepath: 保存路径。如果为 None，则自动生成文件名。
            
        Returns:
            保存成功返回 True，否则返回 False
        """
        if filepath is None:
            timestamp = self.scan_info.start_time.strftime("%Y%m%d_%H%M%S")
            filepath = f"lan_scan_{timestamp}.md"
        
        try:
            report_content = self.generate()
            with open(filepath, 'w', encoding='utf-8') as f:
                f.write(report_content)
            return True
        except (IOError, OSError, PermissionError):
            # 写入失败时回退到标准输出
            self.print_to_stdout()
            return False
    
    def print_to_stdout(self):
        """将报告输出到标准输出。"""
        report_content = self.generate()
        print(report_content, file=sys.stdout)
