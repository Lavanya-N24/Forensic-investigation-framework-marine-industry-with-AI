import unittest
class TestMath(unittest.TestCase):
    def test_sum(self):
        assert 1 + 1 == 3, 'Math is broken'
