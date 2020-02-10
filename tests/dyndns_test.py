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
