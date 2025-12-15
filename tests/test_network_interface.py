"""
Property-based tests for NetworkInterface module.

Tests the correctness properties defined in the design document.
"""

import ipaddress
import pytest
from hypothesis import given, strategies as st, settings, assume

from lan_scanner.network_interface import calculate_subnet


# Strategy for generating valid IP octets
valid_ip_octet = st.integers(min_value=0, max_value=255)

# Strategy for generating valid IP addresses
valid_ip = st.tuples(valid_ip_octet, valid_ip_octet, valid_ip_octet, valid_ip_octet).map(
    lambda t: f"{t[0]}.{t[1]}.{t[2]}.{t[3]}"
)

# Strategy for generating valid netmasks (common subnet masks)
# Valid netmasks have contiguous 1s followed by contiguous 0s
valid_prefix_lengths = st.integers(min_value=8, max_value=30)

def prefix_to_netmask(prefix: int) -> str:
    """Convert a prefix length to a dotted-decimal netmask."""
    mask = (0xFFFFFFFF << (32 - prefix)) & 0xFFFFFFFF
    return f"{(mask >> 24) & 0xFF}.{(mask >> 16) & 0xFF}.{(mask >> 8) & 0xFF}.{mask & 0xFF}"

valid_netmask = valid_prefix_lengths.map(prefix_to_netmask)


class TestSubnetCalculation:
    """
    **Feature: lan-device-scanner, Property 1: Subnet calculation produces valid CIDR notation**
    
    *For any* valid IP address and netmask combination, the subnet calculation 
    function SHALL produce a valid CIDR notation string (e.g., "192.168.1.0/24").
    
    **Validates: Requirements 1.1**
    """

    @given(ip=valid_ip, prefix=valid_prefix_lengths)
    @settings(max_examples=100)
    def test_subnet_calculation_produces_valid_cidr(self, ip, prefix):
        """
        **Feature: lan-device-scanner, Property 1: Subnet calculation produces valid CIDR notation**
        
        Test that calculate_subnet always produces valid CIDR notation.
        """
        netmask = prefix_to_netmask(prefix)
        
        # Calculate the subnet
        result = calculate_subnet(ip, netmask)
        
        # Result must be a non-empty string
        assert isinstance(result, str), "Result must be a string"
        assert len(result) > 0, "Result must not be empty"
        
        # Result must be valid CIDR notation (parseable by ipaddress module)
        try:
            network = ipaddress.IPv4Network(result, strict=True)
        except (ipaddress.AddressValueError, ipaddress.NetmaskValueError, ValueError) as e:
            pytest.fail(f"Result '{result}' is not valid CIDR notation: {e}")
        
        # The prefix length in the result should match the input
        assert network.prefixlen == prefix, \
            f"Prefix length mismatch: expected {prefix}, got {network.prefixlen}"
        
        # The network address should be the network portion of the input IP
        expected_network = ipaddress.IPv4Interface(f"{ip}/{prefix}").network
        assert network == expected_network, \
            f"Network mismatch: expected {expected_network}, got {network}"

    @given(ip=valid_ip, prefix=valid_prefix_lengths)
    @settings(max_examples=100)
    def test_subnet_contains_slash(self, ip, prefix):
        """
        **Feature: lan-device-scanner, Property 1: Subnet calculation produces valid CIDR notation**
        
        Test that the result contains a slash separating network and prefix.
        """
        netmask = prefix_to_netmask(prefix)
        result = calculate_subnet(ip, netmask)
        
        # CIDR notation must contain exactly one slash
        assert result.count('/') == 1, \
            f"CIDR notation must contain exactly one slash, got: {result}"
        
        # Split and validate parts
        network_part, prefix_part = result.split('/')
        
        # Network part must be a valid IP
        try:
            ipaddress.IPv4Address(network_part)
        except ipaddress.AddressValueError:
            pytest.fail(f"Network part '{network_part}' is not a valid IP address")
        
        # Prefix part must be a valid integer
        try:
            prefix_int = int(prefix_part)
            assert 0 <= prefix_int <= 32, f"Prefix {prefix_int} out of range"
        except ValueError:
            pytest.fail(f"Prefix part '{prefix_part}' is not a valid integer")

    @given(ip=valid_ip, prefix=valid_prefix_lengths)
    @settings(max_examples=100)
    def test_original_ip_in_calculated_subnet(self, ip, prefix):
        """
        **Feature: lan-device-scanner, Property 1: Subnet calculation produces valid CIDR notation**
        
        Test that the original IP address is contained within the calculated subnet.
        """
        netmask = prefix_to_netmask(prefix)
        result = calculate_subnet(ip, netmask)
        
        # Parse the result as a network
        network = ipaddress.IPv4Network(result, strict=True)
        
        # The original IP should be within this network
        original_ip = ipaddress.IPv4Address(ip)
        assert original_ip in network, \
            f"Original IP {ip} should be in calculated subnet {result}"
