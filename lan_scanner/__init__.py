"""
LAN Device Scanner - 局域网设备扫描工具

用于发现和识别局域网内设备的网络扫描工具。
"""

# 统一版本号，所有模块应引用此变量
__version__ = "1.0.0"

from lan_scanner.models import DeviceInfo, PortInfo, ScanInfo
from lan_scanner.network_interface import (
    NetworkInterfaceError,
    get_default_interface,
    get_interface_info,
    calculate_subnet,
    get_local_subnet,
)
from lan_scanner.scanner import (
    Scanner,
    ScannerError,
    NmapNotFoundError,
    PrivilegeError,
    parse_nmap_output,
)
from lan_scanner.vendor_lookup import (
    lookup_vendor,
    normalize_mac,
    is_valid_mac,
    get_oui_prefix,
)
from lan_scanner.markdown_report import MarkdownReport

__all__ = [
    "DeviceInfo",
    "PortInfo",
    "ScanInfo",
    "NetworkInterfaceError",
    "get_default_interface",
    "get_interface_info",
    "calculate_subnet",
    "get_local_subnet",
    "Scanner",
    "ScannerError",
    "NmapNotFoundError",
    "PrivilegeError",
    "parse_nmap_output",
    "lookup_vendor",
    "normalize_mac",
    "is_valid_mac",
    "get_oui_prefix",
    "MarkdownReport",
]
