"""
Integration tests for LAN Device Scanner.

Tests the full scan workflow and error handling scenarios.

**Validates: Requirements 4.1, 4.2, 4.3, 4.4**
"""

import os
import sys
import tempfile
from datetime import datetime
from io import StringIO
from unittest.mock import MagicMock, patch, PropertyMock

import pytest

from lan_scanner.models import DeviceInfo, PortInfo, ScanInfo
from lan_scanner.scanner import Scanner, ScannerError, NmapNotFoundError, PrivilegeError
from lan_scanner.markdown_report import MarkdownReport
from lan_scanner.network_interface import NetworkInterfaceError


class TestFullScanWorkflow:
    """Integration tests for the complete scan workflow with mocked nmap."""

    def test_full_workflow_with_mocked_scanner(self):
        """
        Test complete scan workflow: discover hosts -> scan devices -> generate report.
        
        **Validates: Requirements 4.1**
        """
        # Create mock devices
        devices = [
            DeviceInfo(
                ip="192.168.1.1",
                mac="AA:BB:CC:DD:EE:FF",
                hostname="router",
                vendor="Cisco",
                os="Linux",
                open_ports=[PortInfo(port=22, protocol="tcp", service="ssh", state="open")],
                latency="TTL: 64"
            ),
            DeviceInfo(
                ip="192.168.1.100",
                mac="11:22:33:44:55:66",
                hostname="desktop",
                vendor="Dell",
                os="Windows 10",
                open_ports=[
                    PortInfo(port=135, protocol="tcp", service="msrpc", state="open"),
                    PortInfo(port=445, protocol="tcp", service="microsoft-ds", state="open")
                ],
                latency="TTL: 128"
            ),
        ]
        
        # Create scan info
        scan_info = ScanInfo(
            subnet="192.168.1.0/24",
            interface="eth0",
            start_time=datetime.now(),
            end_time=datetime.now(),
            total_hosts=len(devices)
        )
        
        # Generate report
        report = MarkdownReport(devices, scan_info)
        report_content = report.generate()
        
        # Verify all devices are in the report
        for device in devices:
            assert device.ip in report_content
            assert device.mac in report_content
            assert device.hostname in report_content
        
        # Verify report structure
        assert "# LAN Device Scan Report" in report_content
        assert "## Scan Information" in report_content
        assert "## Summary" in report_content
        assert "## Discovered Devices" in report_content
        assert f"**Total Devices Found**: {len(devices)}" in report_content

    def test_workflow_with_no_devices_found(self):
        """
        Test workflow when no devices are discovered.
        
        **Validates: Requirements 4.1**
        """
        scan_info = ScanInfo(
            subnet="192.168.1.0/24",
            interface="eth0",
            start_time=datetime.now(),
            end_time=datetime.now(),
            total_hosts=0
        )
        
        report = MarkdownReport([], scan_info)
        report_content = report.generate()
        
        assert "No devices found" in report_content
        assert "**Total Devices Found**: 0" in report_content


class TestDeviceNotResponding:
    """
    Tests for handling devices that don't respond to certain probes.
    
    **Validates: Requirements 4.1**
    """

    def test_device_with_unknown_fields(self):
        """
        Test that devices with missing data have fields marked as 'Unknown'.
        
        IF a device does not respond to certain probes, THEN THE LAN Scanner 
        SHALL mark those fields as "Unknown" and continue scanning.
        """
        # Device with minimal info (simulating partial response)
        device = DeviceInfo(ip="192.168.1.50")
        
        # All optional fields should default to "Unknown"
        assert device.mac == "Unknown"
        assert device.hostname == "Unknown"
        assert device.vendor == "Unknown"
        assert device.os == "Unknown"
        assert device.latency == "Unknown"
        assert device.open_ports == []

    def test_report_with_partial_device_info(self):
        """
        Test that report handles devices with partial information correctly.
        """
        devices = [
            DeviceInfo(ip="192.168.1.1", mac="AA:BB:CC:DD:EE:FF", hostname="router"),
            DeviceInfo(ip="192.168.1.50"),  # Minimal info
            DeviceInfo(ip="192.168.1.100", vendor="Apple", os="macOS"),
        ]
        
        scan_info = ScanInfo(
            subnet="192.168.1.0/24",
            interface="eth0",
            start_time=datetime.now(),
            end_time=datetime.now(),
            total_hosts=len(devices)
        )
        
        report = MarkdownReport(devices, scan_info)
        report_content = report.generate()
        
        # All devices should be in the report
        for device in devices:
            assert device.ip in report_content
        
        # Unknown values should appear in the report
        assert "Unknown" in report_content


class TestPrivilegeHandling:
    """
    Tests for privilege checking and guidance.
    
    **Validates: Requirements 4.2**
    """

    @patch('os.geteuid')
    def test_privilege_check_as_root(self, mock_geteuid):
        """Test that privilege check returns True when running as root."""
        mock_geteuid.return_value = 0
        
        with patch('shutil.which', return_value='/usr/bin/nmap'):
            with patch('nmap.PortScanner'):
                scanner = Scanner("192.168.1.0/24")
                assert scanner.check_privileges() is True

    @patch('os.geteuid')
    def test_privilege_check_as_user(self, mock_geteuid):
        """Test that privilege check returns False when not running as root."""
        mock_geteuid.return_value = 1000
        
        with patch('shutil.which', return_value='/usr/bin/nmap'):
            with patch('nmap.PortScanner'):
                scanner = Scanner("192.168.1.0/24")
                assert scanner.check_privileges() is False


class TestNmapAvailability:
    """
    Tests for nmap availability checking.
    
    **Validates: Requirements 4.2**
    """

    def test_nmap_not_found_raises_error(self):
        """Test that NmapNotFoundError is raised when nmap is not installed."""
        with patch('shutil.which', return_value=None):
            with pytest.raises(NmapNotFoundError) as exc_info:
                Scanner("192.168.1.0/24")
            
            assert "nmap is not installed" in str(exc_info.value)


class TestFileWriteFailure:
    """
    Tests for file write failure handling.
    
    **Validates: Requirements 4.4**
    """

    def test_save_to_invalid_path_falls_back_to_stdout(self, capsys):
        """
        Test that report falls back to stdout when file write fails.
        
        IF writing the output file fails, THEN THE LAN Scanner SHALL 
        display the results to standard output as a fallback.
        """
        devices = [DeviceInfo(ip="192.168.1.1", hostname="test")]
        scan_info = ScanInfo(
            subnet="192.168.1.0/24",
            interface="eth0",
            start_time=datetime.now(),
            end_time=datetime.now(),
            total_hosts=1
        )
        
        report = MarkdownReport(devices, scan_info)
        
        # Try to save to an invalid path
        result = report.save("/nonexistent/directory/report.md")
        
        # Should return False and print to stdout
        assert result is False
        
        captured = capsys.readouterr()
        assert "192.168.1.1" in captured.out
        assert "LAN Device Scan Report" in captured.out

    def test_save_to_valid_path_succeeds(self):
        """Test that report saves successfully to a valid path."""
        devices = [DeviceInfo(ip="192.168.1.1")]
        scan_info = ScanInfo(
            subnet="192.168.1.0/24",
            interface="eth0",
            start_time=datetime.now(),
            end_time=datetime.now(),
            total_hosts=1
        )
        
        report = MarkdownReport(devices, scan_info)
        
        with tempfile.NamedTemporaryFile(mode='w', suffix='.md', delete=False) as f:
            filepath = f.name
        
        try:
            result = report.save(filepath)
            assert result is True
            
            # Verify file contents
            with open(filepath, 'r') as f:
                content = f.read()
            
            assert "192.168.1.1" in content
            assert "LAN Device Scan Report" in content
        finally:
            os.unlink(filepath)


class TestNetworkInterfaceErrors:
    """
    Tests for network interface error handling.
    
    **Validates: Requirements 1.5**
    """

    def test_network_interface_error_message(self):
        """Test that NetworkInterfaceError provides helpful message."""
        error = NetworkInterfaceError("No default gateway found")
        assert "No default gateway found" in str(error)

    def test_scanner_error_hierarchy(self):
        """Test that scanner errors have proper hierarchy."""
        assert issubclass(NmapNotFoundError, ScannerError)
        assert issubclass(PrivilegeError, ScannerError)


class TestScanInfoDuration:
    """Tests for scan duration calculation."""

    def test_duration_in_seconds(self):
        """Test duration formatting for short scans."""
        start = datetime(2025, 1, 1, 10, 0, 0)
        end = datetime(2025, 1, 1, 10, 0, 45)
        
        scan_info = ScanInfo(
            subnet="192.168.1.0/24",
            interface="eth0",
            start_time=start,
            end_time=end,
            total_hosts=5
        )
        
        assert scan_info.duration == "45s"

    def test_duration_in_minutes(self):
        """Test duration formatting for longer scans."""
        start = datetime(2025, 1, 1, 10, 0, 0)
        end = datetime(2025, 1, 1, 10, 2, 30)
        
        scan_info = ScanInfo(
            subnet="192.168.1.0/24",
            interface="eth0",
            start_time=start,
            end_time=end,
            total_hosts=50
        )
        
        assert scan_info.duration == "2m 30s"

    def test_duration_in_progress(self):
        """Test duration when scan is still in progress."""
        scan_info = ScanInfo(
            subnet="192.168.1.0/24",
            interface="eth0",
            start_time=datetime.now(),
            end_time=None,
            total_hosts=0
        )
        
        assert scan_info.duration == "In progress"


class TestReportSpecialCharacters:
    """Tests for handling special characters in report generation."""

    def test_pipe_character_escaped(self):
        """Test that pipe characters in data are escaped in markdown table."""
        device = DeviceInfo(
            ip="192.168.1.1",
            hostname="test|host",
            vendor="Company|Inc"
        )
        
        scan_info = ScanInfo(
            subnet="192.168.1.0/24",
            interface="eth0",
            start_time=datetime.now(),
            end_time=datetime.now(),
            total_hosts=1
        )
        
        report = MarkdownReport([device], scan_info)
        content = report.generate()
        
        # Pipe should be escaped
        assert "test\\|host" in content
        assert "Company\\|Inc" in content

    def test_empty_ports_displayed_as_none(self):
        """Test that devices with no open ports show 'None'."""
        device = DeviceInfo(ip="192.168.1.1", open_ports=[])
        
        scan_info = ScanInfo(
            subnet="192.168.1.0/24",
            interface="eth0",
            start_time=datetime.now(),
            end_time=datetime.now(),
            total_hosts=1
        )
        
        report = MarkdownReport([device], scan_info)
        content = report.generate()
        
        assert "None" in content


class TestMockedScannerOperations:
    """Tests for scanner operations with mocked nmap."""

    @patch('shutil.which', return_value='/usr/bin/nmap')
    @patch('nmap.PortScanner')
    def test_discover_hosts_returns_active_ips(self, mock_scanner_class, mock_which):
        """Test that discover_hosts returns list of active IP addresses."""
        mock_scanner = MagicMock()
        mock_scanner_class.return_value = mock_scanner
        
        # Mock scan results
        mock_scanner.all_hosts.return_value = ['192.168.1.1', '192.168.1.100']
        mock_scanner.__getitem__ = lambda self, key: MagicMock(state=lambda: 'up')
        
        scanner = Scanner("192.168.1.0/24")
        
        # Configure mock for discover_hosts
        mock_scanner.scan.return_value = None
        
        # Create a mock that returns 'up' for state()
        host_mock = MagicMock()
        host_mock.state.return_value = 'up'
        mock_scanner.__getitem__ = MagicMock(return_value=host_mock)
        
        hosts = scanner.discover_hosts()
        
        assert len(hosts) == 2
        assert '192.168.1.1' in hosts
        assert '192.168.1.100' in hosts

    @patch('shutil.which', return_value='/usr/bin/nmap')
    @patch('nmap.PortScanner')
    def test_scan_all_with_progress_callback(self, mock_scanner_class, mock_which):
        """Test that scan_all calls progress callback for each device."""
        mock_scanner = MagicMock()
        mock_scanner_class.return_value = mock_scanner
        
        # Mock discover_hosts to return 2 hosts
        mock_scanner.all_hosts.return_value = ['192.168.1.1', '192.168.1.2']
        host_mock = MagicMock()
        host_mock.state.return_value = 'up'
        mock_scanner.__getitem__ = MagicMock(return_value=host_mock)
        
        scanner = Scanner("192.168.1.0/24")
        
        # Track progress callback calls
        progress_calls = []
        def track_progress(current, total, ip):
            progress_calls.append((current, total, ip))
        
        # Mock scan_device to return minimal DeviceInfo
        with patch.object(scanner, 'scan_device', side_effect=lambda ip: DeviceInfo(ip=ip)):
            devices = scanner.scan_all(progress_callback=track_progress)
        
        # Verify progress was called for each device
        assert len(progress_calls) == 2
        assert progress_calls[0] == (1, 2, '192.168.1.1')
        assert progress_calls[1] == (2, 2, '192.168.1.2')
        
        # Verify devices were returned
        assert len(devices) == 2
