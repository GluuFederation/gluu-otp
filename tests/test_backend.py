import os

from nose.tools import assert_equal

from yubikeyedup.backend import Backend


def teardown_module():
    os.remove('dummy_db')


def test_intitialization():
    """Test the init function of the Backend Class
    """
    b = Backend('SQLITE', 'dummy_db')
    assert_equal(b.driver, 'SQLITE')

    b = Backend('LDAP', 'ldap://localhost:8080')
    assert_equal(b.driver, 'LDAP')

    b = Backend('NON SENSE DRIVER', 'dummy_db')  # should default to SQLITE
    assert_equal(b.driver, 'SQLITE')
