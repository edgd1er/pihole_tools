#!/usr/bin/env python3
import os
import sys
import unittest

from tests_loadxxx import TestLoadXX
from tests_onexxx import TestOneXXInitAndMethods

# sys.path.append(os.path.dirname(os.path.realpath(__file__)) + "/..")

def load_tests(loader, standard_tests, pattern):
  suite = unittest.TestSuite()
  suite.addTests(loader.loadTestsFromTestCase(TestOneXXInitAndMethods))
  suite.addTests(loader.loadTestsFromTestCase(TestLoadXX))
  return suite


if __name__ == '__main__':
  unittest.main(verbosity=3)
