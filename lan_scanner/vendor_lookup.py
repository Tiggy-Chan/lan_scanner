"""
局域网设备扫描器 - MAC 厂商查询模块

提供通过 OUI (组织唯一标识符) 数据库查询 MAC 地址对应设备厂商的功能。
"""

import re
import subprocess
from typing import Optional


def normalize_mac(mac: str) -> Optional[str]:
    """将 MAC 地址规范化为大写冒号分隔格式。
    
    Args:
        mac: 各种格式的 MAC 地址 (XX:XX:XX:XX:XX:XX, XX-XX-XX-XX-XX-XX 等)
        
    Returns:
        规范化的 MAC 地址 (XX:XX:XX:XX:XX:XX) 或无效时返回 None
    """
    if not mac or not isinstance(mac, str):
        return None
    
    # 移除常见分隔符并转为大写
    cleaned = mac.upper().replace('-', '').replace(':', '').replace('.', '')
    
    # 检查是否正好有 12 个十六进制字符
    if len(cleaned) != 12:
        return None
    
    # 验证十六进制字符
    if not all(c in '0123456789ABCDEF' for c in cleaned):
        return None
    
    # 格式化为 XX:XX:XX:XX:XX:XX
    return ':'.join(cleaned[i:i+2] for i in range(0, 12, 2))


def is_valid_mac(mac: str) -> bool:
    """检查字符串是否为有效的 MAC 地址。
    
    Args:
        mac: 要验证的字符串
        
    Returns:
        如果是有效的 MAC 地址格式返回 True，否则返回 False
    """
    return normalize_mac(mac) is not None


def get_oui_prefix(mac: str) -> Optional[str]:
    """从 MAC 地址中提取 OUI 前缀 (前 3 字节)。
    
    Args:
        mac: 任意有效格式的 MAC 地址
        
    Returns:
        OUI 前缀 (XX:XX:XX) 或无效 MAC 时返回 None
    """
    normalized = normalize_mac(mac)
    if normalized is None:
        return None
    return normalized[:8]  # 前 8 个字符 = XX:XX:XX


def lookup_vendor(mac: str) -> str:
    """查询给定 MAC 地址的厂商/制造商。
    
    使用 nmap 内置的 OUI 数据库 (nmap-mac-prefixes 文件)。
    无法识别的 MAC 返回 "未知"。
    
    Args:
        mac: MAC 地址，格式如 XX:XX:XX:XX:XX:XX 或类似格式
        
    Returns:
        厂商名称字符串，未找到或无效 MAC 时返回 "未知"
    """
    # 规范化 MAC 地址
    normalized = normalize_mac(mac)
    if normalized is None:
        return "未知"
    
    # 获取 OUI 前缀用于查询
    oui = get_oui_prefix(normalized)
    if oui is None:
        return "未知"
    
    # 尝试使用 nmap 的 mac-prefixes 数据库
    vendor = _lookup_nmap_database(oui)
    if vendor:
        return vendor
    
    return "未知"


def _lookup_nmap_database(oui: str) -> Optional[str]:
    """在 nmap 的 mac-prefixes 数据库中查询厂商。
    
    Args:
        oui: OUI 前缀，格式为 XX:XX:XX
        
    Returns:
        厂商名称，未找到时返回 None
    """
    # 将 OUI 转换为 nmap 数据库使用的格式 (无冒号，大写)
    oui_key = oui.replace(':', '').upper()
    
    # nmap mac-prefixes 文件的常见路径
    nmap_paths = [
        '/usr/share/nmap/nmap-mac-prefixes',
        '/usr/local/share/nmap/nmap-mac-prefixes',
        '/opt/homebrew/share/nmap/nmap-mac-prefixes',
    ]
    
    for path in nmap_paths:
        try:
            with open(path, 'r', encoding='utf-8', errors='ignore') as f:
                for line in f:
                    line = line.strip()
                    if not line or line.startswith('#'):
                        continue
                    # 格式: XXXXXX VendorName
                    parts = line.split(' ', 1)
                    if len(parts) == 2 and parts[0].upper() == oui_key:
                        return parts[1].strip()
        except (FileNotFoundError, PermissionError, IOError):
            continue
    
    return None
