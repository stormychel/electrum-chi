import unittest
import threading

# This trick allows accessing electrum_nmc from import statements as electrum,
# so we can avoid merge conflicts while also avoiding namespace collisions with
# upstream.
import pkgutil
import importlib
import sys
electrum_nmc = importlib.import_module('electrum_nmc')
sys.modules['electrum'] = electrum_nmc
for _, name, _ in pkgutil.iter_modules(['electrum_nmc']):
    try:
        m = importlib.import_module('electrum_nmc' + '.' + name)
        sys.modules['electrum' + '.' + name] = m
    except:
        pass

from electrum import constants


# Set this locally to make the test suite run faster.
# If set, unit tests that would normally test functions with multiple implementations,
# will only be run once, using the fastest implementation.
# e.g. libsecp256k1 vs python-ecdsa. pycryptodomex vs pyaes.
FAST_TESTS = False


# some unit tests are modifying globals; sorry.
class SequentialTestCase(unittest.TestCase):

    test_lock = threading.Lock()

    def setUp(self):
        super().setUp()
        self.test_lock.acquire()

    def tearDown(self):
        super().tearDown()
        self.test_lock.release()


class TestCaseForTestnet(SequentialTestCase):

    @classmethod
    def setUpClass(cls):
        super().setUpClass()
        constants.set_testnet()

    @classmethod
    def tearDownClass(cls):
        super().tearDownClass()
        constants.set_mainnet()
