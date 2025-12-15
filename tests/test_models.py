"""
Property-based tests for data models.

Tests the correctness properties defined in the design document.
"""

import pytest
from hypothesis import given, strategies as st, settings

from lan_scanner.models import DeviceInfo, PortInfo, ScanInfo


# Strategies for generating valid test data
valid_ip_octet = st.integers(min_value=0, max_value=255)
valid_ip = st.tuples(valid_ip_octet, valid_ip_octet, valid_ip_octet, valid_ip_octet).map(
    lambda t: f"{t[0]}.{t[1]}.{t[2]}.{t[3]}"
)

valid_mac_byte = st.integers(min_value=0, max_value=255).map(lambda x: f"{x:02X}")
valid_mac = st.tuples(*[valid_mac_byte for _ in range(6)]).map(lambda t: ":".join(t))

optional_string = st.one_of(st.none(), st.text(min_size=0, max_size=50))
non_empty_string = st.text(min_size=1, max_size=50)

valid_port = st.integers(min_value=1, max_value=65535)
protocol = st.sampled_from(["tcp", "udp", "TCP", "UDP"])
port_state = st.sampled_from(["open", "closed", "filtered", "Open", "OPEN"])


class TestDeviceInfoCompleteness:
    """
    **Feature: lan-device-scanner, Property 2: Device info completeness**
    
    *For any* DeviceInfo object created by the scanner, all required fields 
    (ip, mac, hostname, vendor, os, open_ports, latency) SHALL be present, 
    with missing data defaulting to "Unknown" or empty list.
    
    **Validates: Requirements 1.3, 1.4, 2.1, 2.2, 2.3, 2.5, 4.1**
    """

    @given(
        ip=valid_ip,
        mac=optional_string,
        hostname=optional_string,
        vendor=optional_string,
        os_info=optional_string,
        latency=optional_string
    )
    @settings(max_examples=100)
    def test_device_info_completeness_with_optional_fields(
        self, ip, mac, hostname, vendor, os_info, latency
    ):
        """
        **Feature: lan-device-scanner, Property 2: Device info completeness**
        
        Test that DeviceInfo always has all required fields present with proper defaults.
        """
        # Create DeviceInfo with various optional field values (including None)
        device = DeviceInfo(
            ip=ip,
            mac=mac,
            hostname=hostname,
            vendor=vendor,
            os=os_info,
            latency=latency
        )
        
        # All fields must be present (not None)
        assert device.ip is not None, "IP must be present"
        assert device.mac is not None, "MAC must be present"
        assert device.hostname is not None, "Hostname must be present"
        assert device.vendor is not None, "Vendor must be present"
        assert device.os is not None, "OS must be present"
        assert device.open_ports is not None, "open_ports must be present"
        assert device.latency is not None, "Latency must be present"
        
        # String fields must be strings
        assert isinstance(device.ip, str), "IP must be a string"
        assert isinstance(device.mac, str), "MAC must be a string"
        assert isinstance(device.hostname, str), "Hostname must be a string"
        assert isinstance(device.vendor, str), "Vendor must be a string"
        assert isinstance(device.os, str), "OS must be a string"
        assert isinstance(device.latency, str), "Latency must be a string"
        
        # open_ports must be a list
        assert isinstance(device.open_ports, list), "open_ports must be a list"
        
        # Empty/None values should default to "Unknown"
        if mac is None or mac == "":
            assert device.mac == "Unknown", "Empty MAC should default to Unknown"
        if hostname is None or hostname == "":
            assert device.hostname == "Unknown", "Empty hostname should default to Unknown"
        if vendor is None or vendor == "":
            assert device.vendor == "Unknown", "Empty vendor should default to Unknown"
        if os_info is None or os_info == "":
            assert device.os == "Unknown", "Empty OS should default to Unknown"
        if latency is None or latency == "":
            assert device.latency == "Unknown", "Empty latency should default to Unknown"

    @given(ip=valid_ip)
    @settings(max_examples=100)
    def test_device_info_minimal_creation(self, ip):
        """
        **Feature: lan-device-scanner, Property 2: Device info completeness**
        
        Test that DeviceInfo created with only IP has all fields with defaults.
        """
        device = DeviceInfo(ip=ip)
        
        # All fields must have proper defaults
        assert device.ip == ip
        assert device.mac == "Unknown"
        assert device.hostname == "Unknown"
        assert device.vendor == "Unknown"
        assert device.os == "Unknown"
        assert device.open_ports == []
        assert device.latency == "Unknown"

    @given(
        ip=valid_ip,
        ports=st.lists(
            st.tuples(valid_port, protocol, non_empty_string, port_state),
            min_size=0,
            max_size=10
        )
    )
    @settings(max_examples=100)
    def test_device_info_with_ports(self, ip, ports):
        """
        **Feature: lan-device-scanner, Property 2: Device info completeness**
        
        Test that DeviceInfo properly stores port information.
        """
        port_infos = [
            PortInfo(port=p[0], protocol=p[1], service=p[2], state=p[3])
            for p in ports
        ]
        
        device = DeviceInfo(ip=ip, open_ports=port_infos)
        
        # open_ports should contain all provided ports
        assert len(device.open_ports) == len(ports)
        for port_info in device.open_ports:
            assert isinstance(port_info, PortInfo)
            assert port_info.port is not None
            assert port_info.protocol is not None
            assert port_info.service is not None
            assert port_info.state is not None
