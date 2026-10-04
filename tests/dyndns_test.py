import pytest
import dyndns


@pytest.mark.parametrize("hostname,expected", [("localhost", True), ("nsnsn schmu.net", False)])
def test_is_resolvable(hostname, expected):
    assert dyndns.is_resolvable(hostname) == expected


@pytest.mark.parametrize("host, user, expected", [
    ('schmu.net', 'test', False),
    ('host1.dyn.example.com', 'admin', True),
    ('host1.dyn.example.com', 'admin1', False),
    ('host1.dyn.example.com', 'd_admin@dyn.example.com', True),
    ('host1.dyn2.example.com', 'd_admin@dyn.example.com', False),
    ('host1.dyn.example.com', 'host1@dyn.example.com', True),
    ('host1.dyn.example.com', 'host2@dyn.example.com', False),
    ('host1.dyn.example.com', None, False),
    ('host1.dyn.example.com', '', False),
])
def test_validate_user(host, user, expected):
    import dyndns_config
    dyndns_config.full_access_user = ['admin', 'Admin1']
    dyndns_config.domain_access_user = ['d_admin@dyn.example.com']
    assert dyndns.validate_user(host, user) == expected


@pytest.mark.parametrize("fqdn, expected", [
    ('dyn.example.com', 'example.com'),
    ('dyn.example.com.', 'example.com'),
])
def test_domain_from_fqdn(fqdn, expected):
    assert dyndns.domain_from_fqdn(fqdn) == expected


@pytest.mark.parametrize(
    "ipv6_suffix, expected_host",
    [
        (False, "host.dyn.example.com."),
        (True, "host-ipv6.dyn.example.com."),
    ],
)
def test_update_ipv6_suffix(monkeypatch, ipv6_suffix, expected_host):
    queued_updates = []
    monkeypatch.setattr(dyndns, "validate_user", lambda host, user: True)
    monkeypatch.setattr(dyndns, "get_queue_path", lambda path: "/queue")
    monkeypatch.setattr(dyndns, "dns_is_changed", lambda host, ip: True)
    monkeypatch.setattr(
        dyndns,
        "write_queue_file",
        lambda path, host, ip, record_type: queued_updates.append(
            (path, host, ip, record_type)
        ) or "queued",
    )

    result = dyndns.update(
        host="host.dyn.example.com.",
        ipv6="2001:db8::1",
        user="host@dyn.example.com",
        ipv6_suffix=ipv6_suffix,
    )

    assert result[0] == "good"
    assert queued_updates == [
        ("/queue", expected_host, "2001:db8::1", "AAAA")
    ]


def test_update_ipv6_suffix_leaves_ipv4_hostname_unchanged(monkeypatch):
    queued_updates = []
    monkeypatch.setattr(dyndns, "validate_user", lambda host, user: True)
    monkeypatch.setattr(dyndns, "get_queue_path", lambda path: "/queue")
    monkeypatch.setattr(dyndns, "dns_is_changed", lambda host, ip: True)
    monkeypatch.setattr(
        dyndns,
        "write_queue_file",
        lambda path, host, ip, record_type: queued_updates.append(
            (host, record_type)
        ) or "queued",
    )

    dyndns.update(
        host="host.dyn.example.com",
        ipv4="192.0.2.1",
        ipv6="2001:db8::1",
        user="host@dyn.example.com",
        ipv6_suffix=True,
    )

    assert queued_updates == [
        ("host.dyn.example.com", "A"),
        ("host-ipv6.dyn.example.com", "AAAA"),
    ]
