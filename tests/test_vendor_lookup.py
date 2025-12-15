"""
Property-based tests for MAC vendor lookup module.

Tests the correctness properties defined in the design document.
"""

import pytest
from hypothesis import given, strategies as st, settings, assume

from lan_scanner.vendor_lookup import (
    lookup_vendor,
    normalize_mac,
    is_valid_mac,
    get_oui_prefix,
)


# Strategy for generating valid MAC address bytes (hex)
valid_mac_byte = st.integers(min_value=0, max_value=255).map(lambda x: f"{x:02X}")

# Strategy for generating valid MAC addresses in colon-separated format
valid_mac_colon = st.tuples(*[valid_mac_byte for _ in range(6)]).map(
    lambda t: ":".join(t)
)

# Strategy for generating valid MAC addresses in dash-separated format
valid_mac_dash = st.tuples(*[valid_mac_byte for _ in range(6)]).map(
    lambda t: "-".join(t)
)

# Strategy for generating valid MAC addresses in various formats
valid_mac_any_format = st.one_of(
    valid_mac_colon,
    valid_mac_dash,
    # Lowercase colon format
    valid_mac_colon.map(str.lower),
    # Lowercase dash format
    valid_mac_dash.map(str.lower),
)

# Strategy for generating arbitrary strings (including invalid MACs)
arbitrary_string = st.text(min_size=0, max_size=50)


class TestMacVendorLookupConsistency:
    """
    **Feature: lan-device-scanner, Property 8: MAC vendor lookup consistency**
    
    *For any* valid MAC address (format XX:XX:XX:XX:XX:XX), the vendor lookup 
    function SHALL return either a vendor name string or "Unknown", never 
    raising an exception.
    
    **Validates: Requirements 2.2**
    """

    @given(mac=valid_mac_any_format)
    @settings(max_examples=100)
    def test_lookup_vendor_returns_string_for_valid_mac(self, mac):
        """
        **Feature: lan-device-scanner, Property 8: MAC vendor lookup consistency**
        
        Test that lookup_vendor always returns a string for valid MAC addresses.
        """
        result = lookup_vendor(mac)
        
        # Result must be a string
        assert isinstance(result, str), \
            f"lookup_vendor must return a string, got {type(result)}"
        
        # Result must be non-empty
        assert len(result) > 0, \
            "lookup_vendor must return a non-empty string"
        
        # Result must be either a vendor name or "Unknown"
        # (vendor names are non-empty strings, so this is always satisfied)

    @given(mac=valid_mac_any_format)
    @settings(max_examples=100)
    def test_lookup_vendor_never_raises_for_valid_mac(self, mac):
        """
        **Feature: lan-device-scanner, Property 8: MAC vendor lookup consistency**
        
        Test that lookup_vendor never raises an exception for valid MAC addresses.
        """
        # This should never raise an exception
        try:
            result = lookup_vendor(mac)
            # If we get here, no exception was raised
            assert True
        except Exception as e:
            pytest.fail(f"lookup_vendor raised an exception for valid MAC '{mac}': {e}")

    @given(text=arbitrary_string)
    @settings(max_examples=100)
    def test_lookup_vendor_handles_arbitrary_input(self, text):
        """
        **Feature: lan-device-scanner, Property 8: MAC vendor lookup consistency**
        
        Test that lookup_vendor handles arbitrary input gracefully without raising.
        """
        # This should never raise an exception, even for invalid input
        try:
            result = lookup_vendor(text)
            # Result must be a string
            assert isinstance(result, str), \
                f"lookup_vendor must return a string, got {type(result)}"
            # For invalid input, should return "Unknown"
            if not is_valid_mac(text):
                assert result == "Unknown", \
                    f"Invalid MAC '{text}' should return 'Unknown', got '{result}'"
        except Exception as e:
            pytest.fail(f"lookup_vendor raised an exception for input '{text}': {e}")

    @given(mac=valid_mac_any_format)
    @settings(max_examples=100)
    def test_lookup_vendor_result_is_vendor_or_unknown(self, mac):
        """
        **Feature: lan-device-scanner, Property 8: MAC vendor lookup consistency**
        
        Test that lookup_vendor returns either a vendor name or "Unknown".
        """
        result = lookup_vendor(mac)
        
        # Result must be a non-empty string
        assert isinstance(result, str) and len(result) > 0, \
            "Result must be a non-empty string"
        
        # If result is not "Unknown", it should be a reasonable vendor name
        # (contains printable characters, not just whitespace)
        if result != "Unknown":
            assert result.strip() != "", \
                "Vendor name should not be just whitespace"


class TestNormalizeMac:
    """Unit tests for MAC address normalization."""

    @given(mac=valid_mac_colon)
    @settings(max_examples=100)
    def test_normalize_preserves_valid_colon_format(self, mac):
        """Test that normalize_mac preserves valid colon-separated MACs."""
        result = normalize_mac(mac)
        assert result is not None
        assert result == mac.upper()

    @given(mac=valid_mac_dash)
    @settings(max_examples=100)
    def test_normalize_converts_dash_to_colon(self, mac):
        """Test that normalize_mac converts dash-separated to colon-separated."""
        result = normalize_mac(mac)
        assert result is not None
        assert ':' in result
        assert '-' not in result

    @given(text=arbitrary_string)
    @settings(max_examples=100)
    def test_normalize_returns_none_for_invalid(self, text):
        """Test that normalize_mac returns None for invalid input."""
        # Skip if text happens to be a valid MAC
        if is_valid_mac(text):
            return
        
        result = normalize_mac(text)
        assert result is None, \
            f"Invalid MAC '{text}' should normalize to None, got '{result}'"


class TestIsValidMac:
    """Unit tests for MAC address validation."""

    @given(mac=valid_mac_any_format)
    @settings(max_examples=100)
    def test_valid_mac_returns_true(self, mac):
        """Test that is_valid_mac returns True for valid MACs."""
        assert is_valid_mac(mac) is True

    def test_invalid_mac_returns_false(self):
        """Test that is_valid_mac returns False for invalid MACs."""
        invalid_macs = [
            "",
            "invalid",
            "AA:BB:CC",  # Too short
            "AA:BB:CC:DD:EE:FF:GG",  # Too long
            "GG:HH:II:JJ:KK:LL",  # Invalid hex
            None,
        ]
        for mac in invalid_macs:
            assert is_valid_mac(mac) is False, \
                f"'{mac}' should be invalid"
