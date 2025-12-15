"""
Property-based tests for MarkdownReport module.

Tests the correctness properties defined in the design document.
"""

import pytest
from datetime import datetime, timedelta
from hypothesis import given, strategies as st, settings

from lan_scanner.models import DeviceInfo, PortInfo, ScanInfo
from lan_scanner.markdown_report import MarkdownReport


# Strategies for generating valid test data
valid_ip_octet = st.integers(min_value=0, max_value=255)
valid_ip = st.tuples(valid_ip_octet, valid_ip_octet, valid_ip_octet, valid_ip_octet).map(
    lambda t: f"{t[0]}.{t[1]}.{t[2]}.{t[3]}"
)

valid_mac_byte = st.integers(min_value=0, max_value=255).map(lambda x: f"{x:02X}")
valid_mac = st.tuples(*[valid_mac_byte for _ in range(6)]).map(lambda t: ":".join(t))

# Safe text that won't break markdown (no pipe characters or newlines in base)
safe_text = st.text(
    alphabet=st.characters(blacklist_categories=('Cs',), blacklist_characters='|\n\r'),
    min_size=1,
    max_size=30
)

valid_port = st.integers(min_value=1, max_value=65535)
protocol = st.sampled_from(["tcp", "udp"])

# Strategy for generating PortInfo
port_info_strategy = st.builds(
    PortInfo,
    port=valid_port,
    protocol=protocol,
    service=safe_text,
    state=st.sampled_from(["open", "closed", "filtered"])
)

# Strategy for generating DeviceInfo
device_info_strategy = st.builds(
    DeviceInfo,
    ip=valid_ip,
    mac=st.one_of(valid_mac, st.just("Unknown")),
    hostname=st.one_of(safe_text, st.just("Unknown")),
    vendor=st.one_of(safe_text, st.just("Unknown")),
    os=st.one_of(safe_text, st.just("Unknown")),
    open_ports=st.lists(port_info_strategy, min_size=0, max_size=5),
    latency=st.one_of(st.just("Unknown"), st.integers(min_value=1, max_value=1000).map(lambda x: f"{x}ms"))
)


# Strategy for generating ScanInfo
@st.composite
def scan_info_strategy(draw):
    subnet = draw(st.from_regex(r'192\.168\.[0-9]{1,3}\.0/24', fullmatch=True))
    interface = draw(st.sampled_from(["eth0", "wlan0", "enp0s3", "Unknown"]))
    start_time = draw(st.datetimes(
        min_value=datetime(2020, 1, 1),
        max_value=datetime(2025, 12, 31)
    ))
    # End time is 1-3600 seconds after start
    duration_seconds = draw(st.integers(min_value=1, max_value=3600))
    end_time = start_time + timedelta(seconds=duration_seconds)
    total_hosts = draw(st.integers(min_value=0, max_value=255))
    
    return ScanInfo(
        subnet=subnet,
        interface=interface,
        start_time=start_time,
        end_time=end_time,
        total_hosts=total_hosts
    )


class TestMarkdownReportContainsAllDevices:
    """
    **Feature: lan-device-scanner, Property 4: Markdown report contains all devices**
    
    *For any* list of DeviceInfo objects, the generated Markdown report SHALL 
    contain an entry for each device with its IP address visible in the output.
    
    **Validates: Requirements 3.1**
    """

    @given(
        devices=st.lists(device_info_strategy, min_size=1, max_size=20),
        scan_info=scan_info_strategy()
    )
    @settings(max_examples=100)
    def test_report_contains_all_device_ips(self, devices, scan_info):
        """
        **Feature: lan-device-scanner, Property 4: Markdown report contains all devices**
        
        Test that every device's IP address appears in the generated report.
        """
        report = MarkdownReport(devices, scan_info)
        report_content = report.generate()
        
        for device in devices:
            assert device.ip in report_content, f"Device IP {device.ip} not found in report"

    @given(scan_info=scan_info_strategy())
    @settings(max_examples=100)
    def test_empty_device_list_handled(self, scan_info):
        """
        **Feature: lan-device-scanner, Property 4: Markdown report contains all devices**
        
        Test that empty device list produces valid report with "No devices found".
        """
        report = MarkdownReport([], scan_info)
        report_content = report.generate()
        
        assert "No devices found" in report_content



class TestReportSummaryAccuracy:
    """
    **Feature: lan-device-scanner, Property 5: Report summary accuracy**
    
    *For any* scan result, the Markdown report summary SHALL contain a device 
    count that equals the actual number of DeviceInfo objects in the input list.
    
    **Validates: Requirements 3.2**
    """

    @given(
        devices=st.lists(device_info_strategy, min_size=0, max_size=50),
        scan_info=scan_info_strategy()
    )
    @settings(max_examples=100)
    def test_device_count_matches_input(self, devices, scan_info):
        """
        **Feature: lan-device-scanner, Property 5: Report summary accuracy**
        
        Test that the device count in summary matches the actual device list length.
        """
        report = MarkdownReport(devices, scan_info)
        report_content = report.generate()
        
        expected_count = len(devices)
        # The summary should contain the exact count
        assert f"**Total Devices Found**: {expected_count}" in report_content, \
            f"Expected device count {expected_count} not found in summary"

    @given(
        devices=st.lists(device_info_strategy, min_size=0, max_size=20),
        scan_info=scan_info_strategy()
    )
    @settings(max_examples=100)
    def test_duration_present_in_summary(self, devices, scan_info):
        """
        **Feature: lan-device-scanner, Property 5: Report summary accuracy**
        
        Test that scan duration is present in the summary.
        """
        report = MarkdownReport(devices, scan_info)
        report_content = report.generate()
        
        assert "**Scan Duration**:" in report_content, "Scan duration not found in summary"



class TestReportTableStructureValidity:
    """
    **Feature: lan-device-scanner, Property 6: Report table structure validity**
    
    *For any* non-empty list of DeviceInfo objects, the generated Markdown SHALL 
    contain valid table formatting with header row and separator row.
    
    **Validates: Requirements 3.3**
    """

    @given(
        devices=st.lists(device_info_strategy, min_size=1, max_size=20),
        scan_info=scan_info_strategy()
    )
    @settings(max_examples=100)
    def test_table_has_header_and_separator(self, devices, scan_info):
        """
        **Feature: lan-device-scanner, Property 6: Report table structure validity**
        
        Test that the device table has proper header and separator rows.
        """
        report = MarkdownReport(devices, scan_info)
        report_content = report.generate()
        
        # Check for table header
        assert "| IP Address |" in report_content, "Table header not found"
        assert "| MAC Address |" in report_content, "MAC Address column not found"
        assert "| Hostname |" in report_content, "Hostname column not found"
        assert "| Vendor |" in report_content, "Vendor column not found"
        assert "| OS |" in report_content, "OS column not found"
        assert "| Open Ports |" in report_content, "Open Ports column not found"
        assert "| Latency |" in report_content, "Latency column not found"
        
        # Check for separator row (contains dashes)
        assert "|---" in report_content, "Table separator row not found"

    @given(
        devices=st.lists(device_info_strategy, min_size=1, max_size=10),
        scan_info=scan_info_strategy()
    )
    @settings(max_examples=100)
    def test_table_row_count_matches_devices(self, devices, scan_info):
        """
        **Feature: lan-device-scanner, Property 6: Report table structure validity**
        
        Test that the number of data rows matches the number of devices.
        """
        report = MarkdownReport(devices, scan_info)
        report_content = report.generate()
        
        # Count rows by counting lines that start with | and contain device IPs
        lines = report_content.split('\n')
        data_rows = [line for line in lines if line.startswith('|') and 
                     any(device.ip in line for device in devices)]
        
        assert len(data_rows) == len(devices), \
            f"Expected {len(devices)} data rows, found {len(data_rows)}"



class TestReportHeaderCompleteness:
    """
    **Feature: lan-device-scanner, Property 7: Report header completeness**
    
    *For any* ScanInfo object, the generated report header SHALL contain 
    the subnet string and scan timestamp.
    
    **Validates: Requirements 3.5, 5.1, 5.3**
    """

    @given(
        devices=st.lists(device_info_strategy, min_size=0, max_size=10),
        scan_info=scan_info_strategy()
    )
    @settings(max_examples=100)
    def test_header_contains_subnet(self, devices, scan_info):
        """
        **Feature: lan-device-scanner, Property 7: Report header completeness**
        
        Test that the report header contains the subnet information.
        """
        report = MarkdownReport(devices, scan_info)
        report_content = report.generate()
        
        assert scan_info.subnet in report_content, \
            f"Subnet {scan_info.subnet} not found in report header"

    @given(
        devices=st.lists(device_info_strategy, min_size=0, max_size=10),
        scan_info=scan_info_strategy()
    )
    @settings(max_examples=100)
    def test_header_contains_timestamp(self, devices, scan_info):
        """
        **Feature: lan-device-scanner, Property 7: Report header completeness**
        
        Test that the report header contains the scan timestamp.
        """
        report = MarkdownReport(devices, scan_info)
        report_content = report.generate()
        
        # Check that the formatted timestamp is in the report
        expected_timestamp = scan_info.start_time.strftime("%Y-%m-%d %H:%M:%S")
        assert expected_timestamp in report_content, \
            f"Timestamp {expected_timestamp} not found in report header"

    @given(
        devices=st.lists(device_info_strategy, min_size=0, max_size=10),
        scan_info=scan_info_strategy()
    )
    @settings(max_examples=100)
    def test_header_contains_interface(self, devices, scan_info):
        """
        **Feature: lan-device-scanner, Property 7: Report header completeness**
        
        Test that the report header contains the interface information.
        """
        report = MarkdownReport(devices, scan_info)
        report_content = report.generate()
        
        assert scan_info.interface in report_content, \
            f"Interface {scan_info.interface} not found in report header"
