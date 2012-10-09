##############################################################################
#
# Copyright (c) 2012 Zope Foundation and Contributors.
# All Rights Reserved.
#
# This software is subject to the provisions of the Zope Public License,
# Version 2.1 (ZPL).  A copy of the ZPL should accompany this distribution.
# THIS SOFTWARE IS PROVIDED "AS IS" AND ANY AND ALL EXPRESS OR IMPLIED
# WARRANTIES ARE DISCLAIMED, INCLUDING, BUT NOT LIMITED TO, THE IMPLIED
# WARRANTIES OF TITLE, MERCHANTABILITY, AGAINST INFRINGEMENT, AND FITNESS
# FOR A PARTICULAR PURPOSE.
#
##############################################################################
"""Package Setup
"""
import os
from setuptools import setup, find_packages

def read(*rnames):
    return open(os.path.join(os.path.dirname(__file__), *rnames)).read()

setup(
    name='cipher.googlepam',
    version='1.5.1.dev0',
    description='Google PAM Module',
    long_description=(
        read('README.txt')
        + '\n\n' +
        read('CHANGES.txt')),
    classifiers=[
      "Development Status :: 4 - Beta",
      "Programming Language :: Python",
      "Topic :: Internet",
      "Topic :: Security",
      "Topic :: System :: Systems Administration :: Authentication/Directory"
      ],
    author='Stephan Richter',
    author_email = "stephan.richter@gmail.com",
    url='http://pypi.python.org/pypi/cipher.googlepam',
    keywords='pam google',
    packages = find_packages('src'),
    package_dir = {'':'src'},
    namespace_packages = ['cipher'],
    include_package_data=True,
    zip_safe=False,
    extras_require = dict(
        test = (
            'zope.testing',
            ),
        ),
    install_requires=[
          'gdata',
          'py-bcrypt',
          'python-memcached',
          'setuptools',
          ],
    entry_points = """
    [console_scripts]
    add-google-users=cipher.googlepam.addusers:main
    """
    )
