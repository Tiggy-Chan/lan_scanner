"""
Property-based tests for Scanner module.

Tests the correctness properties defined in the design document.
"""

import pytest
from hypothesis import given, strategies as st, settings, assume

from lan_scanner.scanner import parse_nmap_output
from lan_scanner.models import DeviceInfo, PortInfo


# Strategy for generating valid IP addresses
valid_ip_octet = st.integers(min_value=0, max_value=255)
valid_ip = st.tuples(valid_ip_octet, valid_ip_octet, valid_ip_octet, valid_ip_octet).map(
    lambda t: f"{t[0]}.{t[1]}.{t[2]}.{t[3]}"
)

# Strategy for generating valid MAC addresses
valid_mac_byte = st.integers(min_value=0, max_value=255).map(lambda x: f"{x:02X}")
valid_mac = st.tuples(*[valid_mac_byte for _ in range(6)]).map(lambda t: ":".join(t))

# Strategy for generating hostnames
valid_hostname = st.text(
    alphabet=st.sampled_from("abcdefghijklmnopqrstuvwxyz0123456789-"),
    min_size=1,
    max_size=20
).filter(lambda s: not s.startswith('-') and not s.endswith('-'))

# Strategy for generating vendor names
valid_vendor = st.text(min_size=1, max_size=30).filter(lambda s: s.strip() != "")

# Strategy for generating OS names
valid_os = st.text(min_size=1, max_size=50).filter(lambda s: s.strip() != "")

# Strategy for generating port numbers
valid_port = st.integers(min_value=1, max_value=65535)

# Strategy for generating service names
valid_service = st.sampled_from([
    "http", "https", "ssh", "ftp", "smtp", "dns", "mysql", "postgresql",
    "telnet", "rdp", "vnc", "smb", "nfs", "ldap", "snmp"
])

# Strategy for generating port state
port_state = st.sampled_from(["open", "closed", "filtered"])

# Strategy for generating TTL values
valid_ttl = st.integers(min_value=1, max_value=255).map(str)


def build_nmap_scan_result(
    ip: str,
    mac: str = None,
    hostname: str = None,
    vendor: str = None,
    os_name: str = None,
    ttl: str = None,
    ports: list = None
) -> dict:
    """Build a mock nmap scan result dictionary."""
    result = {}
    
    # Add addresses
    addresses = {'ipv4': ip}
    if mac:
        addresses['mac'] = mac
    result['addresses'] = addresses
    
    # Add vendor (keyed by MAC)
    if mac and vendor:
        result['vendor'] = {mac: vendor}
    else:
        result['vendor'] = {}
    
    # Add hostnames
    if hostname:
        result['hostnames'] = [{'name': hostname, 'type': 'PTR'}]
    else:
        result['hostnames'] = []
    
    # Add OS match
    if os_name:
        result['osmatch'] = [{'name': os_name, 'accuracy': '95'}]
    else:
        result['osmatch'] = []
    
    # Add status with TTL
    result['status'] = {'state': 'up', 'reason': 'syn-ack'}
    if ttl:
        result['status']['reason_ttl'] = ttl
    
    # Add ports
    if ports:
        tcp_ports = {}
        for port_num, service, state in ports:
            tcp_ports[port_num] = {
                'state': state,
                'name': service,
                'product': '',
                'version': ''
            }
        result['tcp'] = tcp_ports
    
    return result


# Strategy for generating complete nmap scan results
@st.composite
def nmap_scan_result_strategy(draw):
    """Generate a complete nmap scan result with all optional fields."""
    ip = draw(valid_ip)
    
    # Optionally include each field
    mac = draw(st.one_of(st.none(), valid_mac))
    hostname = draw(st.one_of(st.none(), valid_hostname))
    vendor = draw(st.one_of(st.none(), valid_vendor)) if mac else None
    os_name = draw(st.one_of(st.none(), valid_os))
    ttl = draw(st.one_of(st.none(), valid_ttl))
    
    # Generate ports
    ports = draw(st.lists(
        st.tuples(valid_port, valid_service, port_state),
        min_size=0,
        max_size=10,
        unique_by=lambda x: x[0]  # Unique port numbers
    ))
    
    scan_result = build_nmap_scan_result(
        ip=ip,
        mac=mac,
        hostname=hostname,
        vendor=vendor,
        os_name=os_name,
        ttl=ttl,
        ports=ports
    )
    
    return ip, scan_result, {
        'mac': mac,
        'hostname': hostname,
        'vendor': vendor,
        'os_name': os_name,
        'ttl': ttl,
        'ports': ports
    }


class TestNmapOutputParsing:
    """
    **Feature: lan-device-scanner, Property 3: Nmap output parsing consistency**
    
    *For any* valid nmap XML/text output containing device information, 
    the parser SHALL extract all device entries and their associated data 
    without data loss.
    
    **Validates: Requirements 1.2, 2.4**
    """

    @given(data=nmap_scan_result_strategy())
    @settings(max_examples=100)
    def test_nmap_parsing_extracts_all_provided_data(self, data):
        """
        **Feature: lan-device-scanner, Property 3: Nmap output parsing consistency**
        
        Test that parse_nmap_output extracts all provided data without loss.
        """
        ip, scan_result, expected = data
        
        # Parse the scan result
        device_info = parse_nmap_output(scan_result, ip)
        
        # Verify IP is always preserved
        assert device_info.ip == ip, "IP address must be preserved"
        
        # Verify MAC is extracted when provided
        if expected['mac']:
            assert device_info.mac == expected['mac'], \
                f"MAC should be '{expected['mac']}', got '{device_info.mac}'"
        else:
            assert device_info.mac == "Unknown", \
                "Missing MAC should default to 'Unknown'"
        
        # Verify hostname is extracted when provided
        if expected['hostname']:
            assert device_info.hostname == expected['hostname'], \
                f"Hostname should be '{expected['hostname']}', got '{device_info.hostname}'"
        else:
            assert device_info.hostname == "Unknown", \
                "Missing hostname should default to 'Unknown'"
        
        # Verify vendor is extracted when provided
        if expected['vendor'] and expected['mac']:
            assert device_info.vendor == expected['vendor'], \
                f"Vendor should be '{expected['vendor']}', got '{device_info.vendor}'"
        else:
            assert device_info.vendor == "Unknown", \
                "Missing vendor should default to 'Unknown'"
        
        # Verify OS is extracted when provided
        if expected['os_name']:
            assert device_info.os == expected['os_name'], \
                f"OS should be '{expected['os_name']}', got '{device_info.os}'"
        else:
            assert device_info.os == "Unknown", \
                "Missing OS should default to 'Unknown'"
        
        # Verify latency/TTL is extracted when provided
        if expected['ttl']:
            assert expected['ttl'] in device_info.latency, \
                f"TTL '{expected['ttl']}' should be in latency '{device_info.latency}'"
        
        # Verify all open ports are extracted
        open_ports_expected = [p for p in expected['ports'] if p[2] == 'open']
        assert len(device_info.open_ports) == len(open_ports_expected), \
            f"Expected {len(open_ports_expected)} open ports, got {len(device_info.open_ports)}"
        
        # Verify each open port's data
        extracted_ports = {p.port: p for p in device_info.open_ports}
        for port_num, service, state in open_ports_expected:
            assert port_num in extracted_ports, \
                f"Port {port_num} should be in extracted ports"
            assert extracted_ports[port_num].service == service, \
                f"Port {port_num} service should be '{service}'"
            assert extracted_ports[port_num].state == state, \
                f"Port {port_num} state should be '{state}'"

    @given(ip=valid_ip)
    @settings(max_examples=100)
    def test_nmap_parsing_handles_empty_result(self, ip):
        """
        **Feature: lan-device-scanner, Property 3: Nmap output parsing consistency**
        
        Test that parse_nmap_output handles empty/minimal scan results gracefully.
        """
        # Minimal scan result with no optional data
        scan_result = {
            'addresses': {'ipv4': ip},
            'vendor': {},
            'hostnames': [],
            'osmatch': [],
            'status': {'state': 'up', 'reason': 'syn-ack'}
        }
        
        device_info = parse_nmap_output(scan_result, ip)
        
        # All fields should have proper defaults
        assert device_info.ip == ip
        assert device_info.mac == "Unknown"
        assert device_info.hostname == "Unknown"
        assert device_info.vendor == "Unknown"
        assert device_info.os == "Unknown"
        assert device_info.open_ports == []

    @given(
        ip=valid_ip,
        ports=st.lists(
            st.tuples(valid_port, valid_service, st.just("open")),
            min_size=1,
            max_size=20,
            unique_by=lambda x: x[0]
        )
    )
    @settings(max_examples=100)
    def test_nmap_parsing_preserves_all_open_ports(self, ip, ports):
        """
        **Feature: lan-device-scanner, Property 3: Nmap output parsing consistency**
        
        Test that all open ports in the scan result are preserved in the output.
        """
        scan_result = build_nmap_scan_result(ip=ip, ports=ports)
        
        device_info = parse_nmap_output(scan_result, ip)
        
        # All ports should be extracted (all are 'open' in this test)
        assert len(device_info.open_ports) == len(ports), \
            f"Expected {len(ports)} ports, got {len(device_info.open_ports)}"
        
        # Verify port numbers match
        expected_port_nums = {p[0] for p in ports}
        actual_port_nums = {p.port for p in device_info.open_ports}
        assert expected_port_nums == actual_port_nums, \
            "All port numbers should be preserved"

    @given(data=nmap_scan_result_strategy())
    @settings(max_examples=100)
    def test_nmap_parsing_returns_valid_device_info(self, data):
        """
        **Feature: lan-device-scanner, Property 3: Nmap output parsing consistency**
        
        Test that parse_nmap_output always returns a valid DeviceInfo object.
        """
        ip, scan_result, _ = data
        
        device_info = parse_nmap_output(scan_result, ip)
        
        # Result must be a DeviceInfo instance
        assert isinstance(device_info, DeviceInfo), \
            "Result must be a DeviceInfo instance"
        
        # All required fields must be present and non-None
        assert device_info.ip is not None
        assert device_info.mac is not None
        assert device_info.hostname is not None
        assert device_info.vendor is not None
        assert device_info.os is not None
        assert device_info.open_ports is not None
        assert device_info.latency is not None
        
        # All string fields must be strings
        assert isinstance(device_info.ip, str)
        assert isinstance(device_info.mac, str)
        assert isinstance(device_info.hostname, str)
        assert isinstance(device_info.vendor, str)
        assert isinstance(device_info.os, str)
        assert isinstance(device_info.latency, str)
        assert isinstance(device_info.open_ports, list)
