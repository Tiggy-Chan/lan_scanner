#!/usr/bin/env python3
"""
LAN Device Scanner - 主入口

局域网设备扫描器主入口，用于发现和识别局域网内的设备。
"""

import argparse
import os
import signal
import sys
from datetime import datetime
from typing import List, Optional

from lan_scanner import __version__
from lan_scanner.models import DeviceInfo, ScanInfo
from lan_scanner.network_interface import (
    NetworkInterfaceError,
    get_default_interface,
    get_interface_info,
    calculate_subnet,
)
from lan_scanner.scanner import Scanner, ScannerError, NmapNotFoundError, PrivilegeError
from lan_scanner.markdown_report import MarkdownReport


# 全局变量，用于中断处理时保存扫描结果
_current_devices: List[DeviceInfo] = []
_current_scan_info: Optional[ScanInfo] = None


def parse_args() -> argparse.Namespace:
    """解析命令行参数。
    
    Returns:
        argparse.Namespace: 解析后的命令行参数
    """
    parser = argparse.ArgumentParser(
        prog='scan.py',
        description='LAN Device Scanner - 局域网设备扫描器',
        epilog='示例: sudo python scan.py -o scan_results.md'
    )
    
    parser.add_argument(
        '-i', '--interface',
        type=str,
        default=None,
        help='指定网络接口 (如 eth0, wlan0)，不指定则自动检测'
    )
    
    parser.add_argument(
        '-s', '--subnet',
        type=str,
        nargs='+',
        default=None,
        help='指定要扫描的子网 (CIDR格式)，可指定多个子网。'
             '示例: -s 192.168.1.0/24 192.168.2.0/24 10.0.0.0/24'
    )
    
    parser.add_argument(
        '-o', '--output',
        type=str,
        default=None,
        help='输出报告文件路径，不指定则自动生成'
    )
    
    parser.add_argument(
        '-t', '--intensity',
        type=int,
        choices=[1, 2, 3, 4, 5],
        default=4,
        help='扫描强度 (1=最慢/最隐蔽, 5=最快/最激进)，默认: 4'
    )
    
    parser.add_argument(
        '-w', '--workers',
        type=int,
        default=50,
        help='并行扫描线程数，默认: 50，可根据网络情况调整'
    )
    
    parser.add_argument(
        '-q', '--quiet',
        action='store_true',
        help='静默模式，不显示进度'
    )
    
    parser.add_argument(
        '-v', '--version',
        action='version',
        version=f'%(prog)s {__version__}'
    )
    
    return parser.parse_args()


def check_privileges() -> bool:
    """检查是否以管理员权限运行。
    
    Returns:
        bool: 如果以 root/sudo 运行返回 True，否则返回 False
    """
    return os.geteuid() == 0


def print_privilege_warning():
    """显示权限不足的提示信息。"""
    print("\n" + "=" * 60)
    print("⚠️  警告: 建议使用管理员权限运行")
    print("=" * 60)
    print("""
部分扫描功能需要 root/sudo 权限:
  - MAC 地址检测
  - 操作系统指纹识别
  - SYN 隐蔽扫描

使用完整功能请运行:
  sudo python scan.py

当前以受限模式继续扫描...
""")


def progress_callback(current: int, total: int, ip: str):
    """显示扫描进度。
    
    Args:
        current: 当前正在扫描的设备序号
        total: 总设备数
        ip: 正在扫描的设备 IP 地址
    """
    percentage = (current / total) * 100 if total > 0 else 0
    bar_length = 30
    filled = int(bar_length * current / total) if total > 0 else 0
    bar = '█' * filled + '░' * (bar_length - filled)
    
    print(f"\r[{bar}] {percentage:5.1f}% ({current}/{total}) 正在扫描: {ip:<15}", end='', flush=True)


def handle_interrupt(signum, frame):
    """处理键盘中断 (Ctrl+C)，优雅退出。
    
    保存中断前已收集的扫描结果。
    """
    global _current_devices, _current_scan_info
    
    print("\n\n" + "=" * 60)
    print("⚠️  扫描被用户中断 (Ctrl+C)")
    print("=" * 60)
    
    if _current_devices and _current_scan_info:
        print(f"\n正在保存已扫描的 {len(_current_devices)} 台设备...")
        
        # 更新扫描信息
        _current_scan_info.end_time = datetime.now()
        _current_scan_info.total_hosts = len(_current_devices)
        
        # 生成并保存部分报告
        report = MarkdownReport(_current_devices, _current_scan_info)
        timestamp = _current_scan_info.start_time.strftime("%Y%m%d_%H%M%S")
        filepath = f"lan_scan_partial_{timestamp}.md"
        
        if report.save(filepath):
            print(f"✅ 部分结果已保存至: {filepath}")
        else:
            print("⚠️  无法保存文件，结果已输出到屏幕。")
    else:
        print("\n尚未扫描到任何设备。")
    
    sys.exit(130)  # Ctrl+C 的标准退出码


def run_scan(interface: Optional[str], subnets: Optional[List[str]], output_file: Optional[str], quiet: bool = False, workers: int = 50) -> int:
    """执行扫描流程。
    
    Args:
        interface: 要使用的网络接口 (None 表示自动检测)
        subnets: 要扫描的子网列表 (None 表示从接口自动检测)
        output_file: 输出文件路径 (None 表示自动生成)
        quiet: 如果为 True，不显示进度输出
        workers: 并行扫描线程数
        
    Returns:
        int: 退出码 (0 表示成功，非零表示错误)
    """
    global _current_devices, _current_scan_info
    
    try:
        # 步骤 1: 检测或验证网络接口
        if not quiet:
            print("\n🔍 正在检测网络配置...")
        
        if interface:
            # 使用指定的接口
            try:
                ip, netmask = get_interface_info(interface)
            except NetworkInterfaceError as e:
                print(f"\n❌ 错误: {e}")
                return 1
        else:
            # 自动检测接口
            try:
                interface = get_default_interface()
                ip, netmask = get_interface_info(interface)
            except NetworkInterfaceError as e:
                print(f"\n❌ 错误: {e}")
                print("\n请检查网络配置或使用 -i 参数指定接口")
                return 1
        
        # 确定要扫描的子网
        if subnets:
            # 使用用户指定的子网
            subnets_to_scan = subnets
            subnet_display = ", ".join(subnets_to_scan)
        else:
            # 从接口计算子网
            subnet_display = calculate_subnet(ip, netmask)
            subnets_to_scan = [subnet_display]
        
        if not quiet:
            print(f"   网络接口: {interface}")
            print(f"   IP 地址: {ip}")
            print(f"   扫描子网: {subnet_display}")
        
        # 步骤 2: 初始化扫描信息
        _current_scan_info = ScanInfo(
            subnet=subnet_display,
            interface=interface,
            start_time=datetime.now()
        )
        
        # 步骤 3: 初始化扫描器并发现所有子网中的主机
        if not quiet:
            print(f"\n🚀 正在初始化扫描器 (并行线程数: {workers})...")
        
        all_active_hosts = []
        first_scanner = None
        
        for subnet in subnets_to_scan:
            try:
                scanner = Scanner(subnet, max_workers=workers)
                if first_scanner is None:
                    first_scanner = scanner
                    
                # 步骤 4: 检查权限 (只检查一次)
                if first_scanner == scanner:
                    if not scanner.check_privileges():
                        if not quiet:
                            print_privilege_warning()
                    else:
                        if not quiet:
                            print("   已获得管理员权限 ✓")
                
                # 步骤 5: 发现主机 (带进度显示)
                if not quiet:
                    print(f"\n📡 正在发现 {subnet} 上的主机...")
                
                # 主机发现进度回调
                def discovery_progress(completed: int, total: int, current_subnet: str):
                    if not quiet and total > 1:
                        percentage = (completed / total) * 100
                        bar_length = 20
                        filled = int(bar_length * completed / total)
                        bar = '█' * filled + '░' * (bar_length - filled)
                        print(f"\r   [{bar}] {percentage:5.1f}% ({completed}/{total}) {current_subnet}", end='', flush=True)
                
                active_hosts = scanner.discover_hosts(progress_callback=discovery_progress if not quiet else None)
                
                if not quiet:
                    print(f"\r   发现 {len(active_hosts)} 台活跃主机" + " " * 40)
                all_active_hosts.extend(active_hosts)
                
            except NmapNotFoundError as e:
                print(f"\n❌ 错误: {e}")
                return 1
        
        # 去重并保持顺序
        seen = set()
        unique_hosts = []
        for host in all_active_hosts:
            if host not in seen:
                seen.add(host)
                unique_hosts.append(host)
        all_active_hosts = unique_hosts
        
        host_count = len(all_active_hosts)
        
        if not quiet:
            print(f"\n📊 唯一主机总数: {host_count}")
        
        if host_count == 0:
            print("\n⚠️  未发现任何活跃主机。")
            _current_scan_info.end_time = datetime.now()
            _current_scan_info.total_hosts = 0
            
            # 仍然生成报告，显示无设备
            report = MarkdownReport([], _current_scan_info)
            if output_file:
                report.save(output_file)
                print(f"\n📄 报告已保存至: {output_file}")
            else:
                report.print_to_stdout()
            return 0
        
        # 步骤 6: 并行扫描每台设备
        if not quiet:
            print(f"\n🔬 正在并行扫描 {host_count} 台设备 ({workers} 线程)...\n")
        
        # 使用第一个扫描器进行设备扫描
        scanner = first_scanner
        
        # 并行扫描进度回调
        def parallel_progress(completed: int, total: int, ip: str):
            if not quiet:
                percentage = (completed / total) * 100 if total > 0 else 0
                bar_length = 30
                filled = int(bar_length * completed / total) if total > 0 else 0
                bar = '█' * filled + '░' * (bar_length - filled)
                print(f"\r[{bar}] {percentage:5.1f}% ({completed}/{total}) 已完成: {ip:<15}", end='', flush=True)
        
        # 使用并行扫描
        _current_devices = scanner.scan_devices_parallel(
            all_active_hosts, 
            progress_callback=parallel_progress if not quiet else None
        )
        
        if not quiet:
            print("\n")  # 进度条后换行
        
        # 步骤 7: 完成扫描信息
        _current_scan_info.end_time = datetime.now()
        _current_scan_info.total_hosts = len(_current_devices)
        
        # 步骤 8: 生成并保存报告
        if not quiet:
            print("📝 正在生成报告...")
        
        report = MarkdownReport(_current_devices, _current_scan_info)
        
        if output_file:
            filepath = output_file
        else:
            timestamp = _current_scan_info.start_time.strftime("%Y%m%d_%H%M%S")
            filepath = f"lan_scan_{timestamp}.md"
        
        if report.save(filepath):
            if not quiet:
                print(f"\n✅ 扫描完成!")
                print(f"   发现设备: {len(_current_devices)} 台")
                print(f"   扫描耗时: {_current_scan_info.duration}")
                print(f"   报告已保存至: {filepath}")
        else:
            if not quiet:
                print("\n⚠️  无法保存文件，结果已输出到屏幕。")
        
        return 0
        
    except Exception as e:
        print(f"\n❌ 未知错误: {e}")
        return 1


def main() -> int:
    """局域网设备扫描器主入口。
    
    协调所有模块，显示进度，优雅处理错误。
    
    Returns:
        int: 退出码 (0 表示成功，非零表示错误)
    """
    # 解析命令行参数
    args = parse_args()
    
    # 设置 Ctrl+C 信号处理
    signal.signal(signal.SIGINT, handle_interrupt)
    
    # 打印横幅
    if not args.quiet:
        print("=" * 60)
        print(f"  LAN Device Scanner v{__version__}")
        print("  局域网设备扫描器")
        print("=" * 60)
    
    # 检查权限并提示
    if not check_privileges() and not args.quiet:
        print("\n💡 提示: 使用 sudo 运行可获得完整扫描功能")
    
    # 执行扫描
    return run_scan(
        interface=args.interface,
        subnets=args.subnet,
        output_file=args.output,
        quiet=args.quiet,
        workers=args.workers
    )


if __name__ == "__main__":
    sys.exit(main())
