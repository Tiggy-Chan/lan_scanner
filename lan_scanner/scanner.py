"""
局域网设备扫描器 - 扫描模块

使用 nmap 提供网络扫描功能，支持并行扫描以提高速度。
"""

import os
import shutil
from concurrent.futures import ThreadPoolExecutor, as_completed
from typing import Callable, List, Optional

import nmap

from lan_scanner.models import DeviceInfo, PortInfo


class ScannerError(Exception):
    """扫描器基础异常类。"""
    pass


class NmapNotFoundError(ScannerError):
    """nmap 未安装时抛出的异常。"""
    pass


class PrivilegeError(ScannerError):
    """需要管理员权限时抛出的异常。"""
    pass


class Scanner:
    """使用 nmap 进行设备发现和信息收集的网络扫描器。
    
    Attributes:
        subnet: 目标子网 (CIDR 格式，如 '192.168.1.0/24')
        _scanner: 内部 nmap.PortScanner 实例
        max_workers: 并行扫描的最大线程数
    """
    
    # 默认并行线程数
    DEFAULT_WORKERS = 50
    
    def __init__(self, subnet: str, max_workers: int = None):
        """使用目标子网初始化扫描器。
        
        Args:
            subnet: 目标子网 (CIDR 格式，如 '192.168.1.0/24')
            max_workers: 并行扫描的最大线程数，默认 50
            
        Raises:
            NmapNotFoundError: 系统未安装 nmap
            PrivilegeError: 需要管理员权限但未获得
        """
        self.subnet = subnet
        self.max_workers = max_workers or self.DEFAULT_WORKERS
        self._scanner = None
        
        # 检查 nmap 是否可用
        if not self._check_nmap_available():
            raise NmapNotFoundError(
                "nmap 未安装，请使用以下命令安装: sudo apt install nmap"
            )
        
        # 初始化 nmap 扫描器
        try:
            self._scanner = nmap.PortScanner()
        except nmap.PortScannerError as e:
            raise NmapNotFoundError(f"初始化 nmap 失败: {e}")

    def _check_nmap_available(self) -> bool:
        """检查系统是否安装了 nmap。
        
        Returns:
            bool: 如果 nmap 可用返回 True，否则返回 False
        """
        return shutil.which('nmap') is not None
    
    def check_privileges(self) -> bool:
        """检查扫描器是否具有管理员权限。
        
        某些 nmap 功能 (如操作系统检测、MAC 地址获取) 需要 root/sudo 权限。
        
        Returns:
            bool: 如果以管理员权限运行返回 True
        """
        return os.geteuid() == 0
    
    def discover_hosts(self) -> List[str]:
        """使用 ping 扫描发现网络上的活跃主机。
        
        使用 nmap 的 -sn (ping 扫描) 快速发现主机，不进行端口扫描。
        使用 -T5 最激进时序和 --min-parallelism 提高速度。
        
        Returns:
            List[str]: 活跃主机的 IP 地址列表
            
        Raises:
            ScannerError: 扫描失败时抛出
        """
        try:
            # -sn: Ping 扫描 - 禁用端口扫描
            # -T5: 最激进时序 (insane)
            # --min-parallelism 100: 最小并行探测数
            # --max-retries 1: 减少重试次数
            self._scanner.scan(
                hosts=self.subnet, 
                arguments='-sn -T5 --min-parallelism 100 --max-retries 1'
            )
            
            # 获取所有在线主机
            active_hosts = []
            for host in self._scanner.all_hosts():
                if self._scanner[host].state() == 'up':
                    active_hosts.append(host)
            
            return active_hosts
            
        except nmap.PortScannerError as e:
            raise ScannerError(f"主机发现失败: {e}")
    
    def scan_device(self, ip: str) -> DeviceInfo:
        """对单个设备进行详细扫描。
        
        提取 MAC 地址、主机名、厂商、操作系统、开放端口和延迟。
        缺失数据会优雅处理，使用 "未知" 作为默认值。
        
        Args:
            ip: 要扫描的设备 IP 地址
            
        Returns:
            DeviceInfo: 包含所有可用数据的设备信息对象
            
        Raises:
            ScannerError: 扫描失败时抛出
        """
        # 每个线程需要独立的 scanner 实例
        scanner = nmap.PortScanner()
        
        try:
            # 扫描参数 (优化速度):
            # -sS: TCP SYN 扫描 (需要 root)
            # -T5: 最激进时序
            # --top-ports 20: 只扫描前 20 个常用端口 (大幅减少时间)
            # --max-retries 1: 减少重试
            # --host-timeout 30s: 单主机超时 30 秒
            # -O --osscan-limit: 操作系统检测，但限制只对有开放端口的主机
            
            # 检查是否有 root 权限以进行高级扫描
            if self.check_privileges():
                arguments = '-sS -T5 --top-ports 20 --max-retries 1 --host-timeout 30s -O --osscan-limit'
            else:
                # 回退到 TCP 连接扫描，不进行操作系统检测
                arguments = '-sT -T5 --top-ports 20 --max-retries 1 --host-timeout 30s'
            
            scanner.scan(hosts=ip, arguments=arguments)
            
            # 提取设备信息
            return self._parse_device_info_from_scanner(scanner, ip)
            
        except nmap.PortScannerError as e:
            raise ScannerError(f"设备扫描失败 {ip}: {e}")

    def _parse_device_info(self, ip: str) -> DeviceInfo:
        """将 nmap 扫描结果解析为 DeviceInfo 对象 (使用实例 scanner)。
        
        Args:
            ip: 被扫描设备的 IP 地址
            
        Returns:
            DeviceInfo: 解析后的设备信息
        """
        return self._parse_device_info_from_scanner(self._scanner, ip)
    
    def _parse_device_info_from_scanner(self, scanner: nmap.PortScanner, ip: str) -> DeviceInfo:
        """将 nmap 扫描结果解析为 DeviceInfo 对象。
        
        Args:
            scanner: nmap.PortScanner 实例
            ip: 被扫描设备的 IP 地址
            
        Returns:
            DeviceInfo: 解析后的设备信息
        """
        # 默认值
        mac = "未知"
        hostname = "未知"
        vendor = "未知"
        os_info = "未知"
        latency = "未知"
        open_ports = []
        
        # 检查主机是否在扫描结果中
        if ip not in scanner.all_hosts():
            return DeviceInfo(ip=ip)
        
        host_info = scanner[ip]
        
        # 提取 MAC 地址和厂商
        if 'addresses' in host_info:
            mac = host_info['addresses'].get('mac', '未知')
        
        if 'vendor' in host_info and host_info['vendor']:
            # vendor 是一个字典 {mac: vendor_name}
            vendor_dict = host_info['vendor']
            if vendor_dict:
                vendor = list(vendor_dict.values())[0]
        
        # 提取主机名
        if 'hostnames' in host_info and host_info['hostnames']:
            for hostname_entry in host_info['hostnames']:
                name = hostname_entry.get('name', '')
                if name:
                    hostname = name
                    break
        
        # 提取操作系统信息
        if 'osmatch' in host_info and host_info['osmatch']:
            # 获取最佳匹配的操作系统
            best_match = host_info['osmatch'][0]
            os_info = best_match.get('name', '未知')
        
        # 提取延迟
        if 'status' in host_info:
            reason_ttl = host_info['status'].get('reason_ttl', '')
            if reason_ttl:
                latency = f"TTL: {reason_ttl}"
        
        # 尝试从 tcp/udp 扫描结果获取实际延迟
        for proto in ['tcp', 'udp']:
            if proto in host_info:
                # 延迟可能在主机信息中
                pass
        
        # 提取开放端口
        for proto in ['tcp', 'udp']:
            if proto in host_info:
                for port, port_data in host_info[proto].items():
                    if port_data.get('state') == 'open':
                        port_info = PortInfo(
                            port=port,
                            protocol=proto,
                            service=port_data.get('name', '未知'),
                            state=port_data.get('state', 'open')
                        )
                        open_ports.append(port_info)
        
        return DeviceInfo(
            ip=ip,
            mac=mac,
            hostname=hostname,
            vendor=vendor,
            os=os_info,
            open_ports=open_ports,
            latency=latency
        )
    
    def scan_all(self, progress_callback: Optional[Callable[[int, int, str], None]] = None) -> List[DeviceInfo]:
        """扫描所有发现的主机并收集设备信息。
        
        Args:
            progress_callback: 可选的回调函数，每扫描一台设备时调用。
                              签名: callback(current: int, total: int, ip: str)
                              
        Returns:
            List[DeviceInfo]: 所有发现主机的设备信息列表
        """
        # 首先发现所有活跃主机
        active_hosts = self.discover_hosts()
        total = len(active_hosts)
        devices = []
        
        for i, ip in enumerate(active_hosts, 1):
            # 如果提供了回调函数则调用
            if progress_callback:
                progress_callback(i, total, ip)
            
            # 扫描设备
            try:
                device_info = self.scan_device(ip)
                devices.append(device_info)
            except ScannerError:
                # 扫描失败时添加最小信息
                devices.append(DeviceInfo(ip=ip))
        
        return devices
    
    def scan_devices_parallel(
        self, 
        hosts: List[str], 
        progress_callback: Optional[Callable[[int, int, str], None]] = None
    ) -> List[DeviceInfo]:
        """并行扫描多个主机。
        
        使用线程池并行扫描，大幅提高扫描速度。
        
        Args:
            hosts: 要扫描的主机 IP 列表
            progress_callback: 可选的回调函数，每完成一台设备时调用。
                              签名: callback(completed: int, total: int, ip: str)
                              
        Returns:
            List[DeviceInfo]: 所有主机的设备信息列表
        """
        total = len(hosts)
        results = {}
        completed = 0
        
        def scan_single(ip: str) -> DeviceInfo:
            """扫描单个主机的包装函数。"""
            try:
                return self.scan_device(ip)
            except ScannerError:
                return DeviceInfo(ip=ip)
        
        with ThreadPoolExecutor(max_workers=self.max_workers) as executor:
            # 提交所有扫描任务
            future_to_ip = {executor.submit(scan_single, ip): ip for ip in hosts}
            
            # 收集结果
            for future in as_completed(future_to_ip):
                ip = future_to_ip[future]
                completed += 1
                
                try:
                    device_info = future.result()
                    results[ip] = device_info
                except Exception:
                    results[ip] = DeviceInfo(ip=ip)
                
                # 调用进度回调
                if progress_callback:
                    progress_callback(completed, total, ip)
        
        # 按原始顺序返回结果
        return [results.get(ip, DeviceInfo(ip=ip)) for ip in hosts]


def parse_nmap_output(scan_result: dict, ip: str) -> DeviceInfo:
    """将原始 nmap 扫描输出字典解析为 DeviceInfo。
    
    这是一个独立函数，用于测试 nmap 输出解析。
    
    Args:
        scan_result: 单个主机的原始 nmap 扫描结果字典
        ip: 主机的 IP 地址
        
    Returns:
        DeviceInfo: 解析后的设备信息
    """
    # 默认值
    mac = "未知"
    hostname = "未知"
    vendor = "未知"
    os_info = "未知"
    latency = "未知"
    open_ports = []
    
    # 提取 MAC 地址
    if 'addresses' in scan_result:
        mac = scan_result['addresses'].get('mac', '未知')
    
    # 提取厂商
    if 'vendor' in scan_result and scan_result['vendor']:
        vendor_dict = scan_result['vendor']
        if vendor_dict:
            vendor = list(vendor_dict.values())[0]
    
    # 提取主机名
    if 'hostnames' in scan_result and scan_result['hostnames']:
        for hostname_entry in scan_result['hostnames']:
            name = hostname_entry.get('name', '')
            if name:
                hostname = name
                break
    
    # 提取操作系统信息
    if 'osmatch' in scan_result and scan_result['osmatch']:
        best_match = scan_result['osmatch'][0]
        os_info = best_match.get('name', '未知')
    
    # 提取延迟
    if 'status' in scan_result:
        reason_ttl = scan_result['status'].get('reason_ttl', '')
        if reason_ttl:
            latency = f"TTL: {reason_ttl}"
    
    # 提取开放端口
    for proto in ['tcp', 'udp']:
        if proto in scan_result:
            for port, port_data in scan_result[proto].items():
                if port_data.get('state') == 'open':
                    port_info = PortInfo(
                        port=port,
                        protocol=proto,
                        service=port_data.get('name', '未知'),
                        state=port_data.get('state', 'open')
                    )
                    open_ports.append(port_info)
    
    return DeviceInfo(
        ip=ip,
        mac=mac,
        hostname=hostname,
        vendor=vendor,
        os=os_info,
        open_ports=open_ports,
        latency=latency
    )
