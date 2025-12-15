"""
局域网设备扫描器 - 网络接口模块

处理网络接口检测和子网计算。
"""

import ipaddress
from typing import Optional, Tuple

import netifaces


class NetworkInterfaceError(Exception):
    """网络接口检测失败时抛出的异常。"""
    pass


def get_default_interface() -> str:
    """获取默认网络接口名称。
    
    检测与默认网关关联的网络接口。
    
    Returns:
        str: 默认网络接口名称 (如 'eth0', 'wlan0')
        
    Raises:
        NetworkInterfaceError: 未找到默认网关或接口时抛出
    """
    try:
        gateways = netifaces.gateways()
        
        if 'default' not in gateways:
            raise NetworkInterfaceError(
                "未找到默认网关，请检查网络配置。"
            )
        
        # 获取默认 IPv4 网关
        if netifaces.AF_INET not in gateways['default']:
            raise NetworkInterfaceError(
                "未找到 IPv4 默认网关，请检查网络配置。"
            )
        
        # 返回 (gateway_ip, interface_name)
        _, interface = gateways['default'][netifaces.AF_INET]
        
        if not interface:
            raise NetworkInterfaceError(
                "无法确定默认网关的网络接口。"
            )
        
        return interface
        
    except KeyError as e:
        raise NetworkInterfaceError(
            f"检测网络接口失败: {e}"
        )


def get_interface_info(interface: str) -> Tuple[str, str]:
    """获取网络接口的 IP 地址和子网掩码。
    
    Args:
        interface: 网络接口名称 (如 'eth0')
        
    Returns:
        Tuple[str, str]: (ip_address, netmask) 元组
        
    Raises:
        NetworkInterfaceError: 接口不存在或没有 IPv4 地址时抛出
    """
    try:
        addrs = netifaces.ifaddresses(interface)
        
        if netifaces.AF_INET not in addrs:
            raise NetworkInterfaceError(
                f"接口 '{interface}' 未配置 IPv4 地址。"
            )
        
        # 获取第一个 IPv4 地址
        ipv4_info = addrs[netifaces.AF_INET][0]
        
        ip_address = ipv4_info.get('addr')
        netmask = ipv4_info.get('netmask')
        
        if not ip_address:
            raise NetworkInterfaceError(
                f"无法获取接口 '{interface}' 的 IP 地址。"
            )
        
        if not netmask:
            raise NetworkInterfaceError(
                f"无法获取接口 '{interface}' 的子网掩码。"
            )
        
        return ip_address, netmask
        
    except ValueError as e:
        raise NetworkInterfaceError(
            f"接口 '{interface}' 不存在: {e}"
        )


def calculate_subnet(ip: str, netmask: str) -> str:
    """根据 IP 和子网掩码计算 CIDR 格式的子网。
    
    Args:
        ip: IP 地址 (如 '192.168.1.100')
        netmask: 子网掩码 (如 '255.255.255.0')
        
    Returns:
        str: CIDR 格式的子网 (如 '192.168.1.0/24')
        
    Raises:
        ValueError: IP 或子网掩码无效时抛出
    """
    try:
        # 从 IP 和子网掩码创建接口对象
        interface = ipaddress.IPv4Interface(f"{ip}/{netmask}")
        
        # 获取带前缀长度的网络地址
        network = interface.network
        
        return str(network)
        
    except (ipaddress.AddressValueError, ipaddress.NetmaskValueError) as e:
        raise ValueError(f"无效的 IP 地址或子网掩码: {e}")


def get_local_subnet() -> Tuple[str, str, str]:
    """获取本地子网信息的便捷函数。
    
    Returns:
        Tuple[str, str, str]: (interface_name, ip_address, subnet_cidr) 元组
        
    Raises:
        NetworkInterfaceError: 网络检测失败时抛出
    """
    interface = get_default_interface()
    ip, netmask = get_interface_info(interface)
    subnet = calculate_subnet(ip, netmask)
    
    return interface, ip, subnet
