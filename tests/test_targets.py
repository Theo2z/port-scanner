"""Tests for target and port parsing. Pure functions: no network needed."""

import pytest

from portscanner.targets import MAX_HOSTS, TargetError, parse_ports, parse_targets


# @pytest.mark.parametrize runs one test function once per case, and
# reports each case separately when it fails.
@pytest.mark.parametrize(
    ("spec", "expected"),
    [
        ("80", [80]),
        ("1-5", [1, 2, 3, 4, 5]),
        ("443,22,80", [22, 80, 443]),  # sorted
        ("80,80,79-81", [79, 80, 81]),  # de-duplicated
        (" 22 , 8000-8002 ", [22, 8000, 8001, 8002]),  # whitespace tolerated
        ("65535", [65535]),
    ],
)
def test_parse_ports_valid(spec, expected):
    assert parse_ports(spec) == expected


def test_parse_ports_full_range():
    assert len(parse_ports("1-65535")) == 65535


@pytest.mark.parametrize(
    ("spec", "message"),
    [
        ("0", "outside"),
        ("65536", "outside"),
        ("90-80", "backwards"),
        ("http", "not a port"),
        ("1-", "not a port"),
        ("", "no port"),
        (",,", "no port"),
    ],
)
def test_parse_ports_invalid(spec, message):
    with pytest.raises(TargetError, match=message):
        parse_ports(spec)


def test_single_ip_and_hostname_pass_through():
    assert parse_targets("10.0.0.1") == ["10.0.0.1"]
    assert parse_targets("scanme.nmap.org") == ["scanme.nmap.org"]


def test_cidr_excludes_network_and_broadcast():
    # /30 = 4 addresses: .0 network, .1 and .2 hosts, .3 broadcast
    assert parse_targets("192.168.1.0/30") == ["192.168.1.1", "192.168.1.2"]


def test_cidr_24_has_254_hosts():
    hosts = parse_targets("10.1.2.0/24")
    assert len(hosts) == 254
    assert hosts[0] == "10.1.2.1" and hosts[-1] == "10.1.2.254"


def test_cidr_32_and_31_keep_every_address():
    assert parse_targets("10.0.0.5/32") == ["10.0.0.5"]
    assert parse_targets("10.0.0.4/31") == ["10.0.0.4", "10.0.0.5"]


def test_cidr_with_host_bits_set_is_accepted():
    # strict=False: 192.168.1.77/30 means the /30 that contains .77
    assert parse_targets("192.168.1.77/30") == ["192.168.1.77", "192.168.1.78"]


def test_targets_are_deduplicated_in_order():
    assert parse_targets("b.com, 10.0.0.1/32,b.com,a.com") == ["b.com", "10.0.0.1", "a.com"]


@pytest.mark.parametrize(
    ("spec", "message"),
    [
        ("10.0.0.0/8", "limit"),  # 16M hosts: almost certainly a typo
        ("999.1.1.1/24", "invalid CIDR"),
        ("10.0.0.0/33", "invalid CIDR"),
        ("::1/128", "only IPv4"),
        ("", "no target"),
    ],
)
def test_parse_targets_invalid(spec, message):
    with pytest.raises(TargetError, match=message):
        parse_targets(spec)


def test_host_cap_applies_across_comma_separated_ranges():
    # Each /16 is allowed alone (65,534 hosts), but two together exceed the cap.
    assert MAX_HOSTS == 65536
    with pytest.raises(TargetError, match="too many hosts"):
        parse_targets("10.0.0.0/16,10.1.0.0/16")
