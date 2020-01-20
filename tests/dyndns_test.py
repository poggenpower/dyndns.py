import pytest
import dyndns


def test_is_resolvable():
    assert dyndns.is_resolvable('localhost') == True