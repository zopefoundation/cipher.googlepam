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
"""Google PAM Tests
"""
import doctest
import sys
import os
import tempfile
import ConfigParser
import shutil

from cipher.googlepam import pam_google
from gdata.apps.service import AppsForYourDomainException
from gdata.service import BadAuthentication, CaptchaRequired

HERE = os.path.dirname(__file__)

class GooglePAMStub(object):
    def __init__(self, config={}):
        self.config = ConfigParser.ConfigParser()
        for section, d in config.items():
            self.config.add_section(section)
            for k, v in d.items():
                self.config.set(section, k, v)

class FakePamMessage(object):
    def __init__(self, flags, prompt):
        pass

class FakePamResponse(object):
    def __init__(self, resp):
        self.resp = resp

class FakePamHandle(object):

    PAM_SUCCESS = 0
    PAM_SERVICE_ERR = 3
    PAM_AUTH_ERR = 9
    PAM_USER_UNKNOWN = 13
    PAM_CRED_UNAVAIL = 14
    PAM_IGNORE = 25

    PAM_PROMPT_ECHO_OFF = 1

    collected_authtok = 'good-pwd'
    Message = FakePamMessage
    Response = FakePamResponse

    def __init__(self, user=None, collected_authtok=None):
        self.user = user
        self.authtok = None
        if collected_authtok:
            self.collected_authtok = collected_authtok

    def conversation(self, message):
        return self.Response(self.authtok or self.collected_authtok)

class FakeAppsService(object):

    def __init__(self, domain, email, password):
        self.domain = domain
        self.email = email
        self.password = password

    def ClientLogin(self, email, password, account_type, source):
        if email == 'user1@example.com' and password == 'good-pwd':
            return
        if email == 'user2@example.com' and password == 'good-pwd':
            return
        if email == 'user3@example.com':
            raise CaptchaRequired()
        if email == 'error@example.com':
            raise ValueError(email)
        raise BadAuthentication()

class FakeGroupsService(object):

    def __init__(self, domain, email, password):
        self.domain = domain
        self.email = email
        self.password = password

    def ProgrammaticLogin(self):
        if self.email == 'admin@example.com' and self.password == 'good-pwd':
            return
        if self.email == 'shady@example.com':
            raise CaptchaRequired()
        raise BadAuthentication()

    def IsMember(self, username, group):
        if self.email != 'admin@example.com' or username == 'notallowed':
            raise AppsForYourDomainException(self.email)
        if username in ('user1', 'user3', 'error') and group == 'group1':
            return True
        if username in ('user1', 'user2') and group == 'group2':
            return True
        if username == 'user4' and group == 'group3':
            return True
        return False


def doctest_pam_sm_authenticate():
    """pam_sm_authenticate(pamh, flags, argv)

    First, we succeed:

      >>> pam_google.pam_sm_authenticate(
      ...     FakePamHandle('user1'),
      ...     0,
      ...     ['googlepam.py'])
      INFO - Authentication succeeded: user1
      0

    Now we have a wrong username:

      >>> pam_google.pam_sm_authenticate(
      ...     FakePamHandle('user2'),
      ...     0,
      ...     ['googlepam.py'])
      INFO - User "user2" is not a member of group "group1".
      9

    Some users are excluded from Google auth, such as root:

      >>> pam_google.pam_sm_authenticate(
      ...     FakePamHandle('root'),
      ...     0,
      ...     ['googlepam.py'])
      INFO - User is in excluded list: root
      25
    """

def doctest_pam_sm_setcred():
    """pam_sm_setcred(pamh, flags, argv)

    Always succeeds:

      >>> pam_google.pam_sm_setcred(FakePamHandle(), 0, ['googlepam.py'])
      0
    """

def doctest_pam_sm_acct_mgmt():
    """pam_sm_acct_mgmt(pamh, flags, argv)

    Not supported:

      >>> pam_google.pam_sm_acct_mgmt(FakePamHandle(), 0, ['googlepam.py'])
      INFO - `acct_mgmt` is not supported.
      3
    """

def doctest_pam_sm_chauthtok():
    """pam_sm_chauthtok(pamh, flags, argv)

    Not supported:

      >>> pam_google.pam_sm_chauthtok(FakePamHandle(), 0, ['googlepam.py'])
      INFO - `chauthtok` is not supported.
      3
    """

def doctest_pam_sm_open_session():
    """pam_sm_open_session(pamh, flags, argv)

    Not supported:

      >>> pam_google.pam_sm_open_session(FakePamHandle(), 0, ['googlepam.py'])
      INFO - `open_session` is not supported.
      3
    """

def doctest_pam_sm_close_session():
    """pam_sm_close_session(pamh, flags, argv)

    Not supported:

      >>> pam_google.pam_sm_close_session(FakePamHandle(), 0, ['googlepam.py'])
      INFO - `close_session` is not supported.
      3
    """

def doctest_GooglePAM_authenticate():
    """class GooglePAM: authenticate()

      >>> pam = pam_google.GooglePAM(
      ...     FakePamHandle(), 0,
      ...     ['script', '-c', os.path.join(HERE, 'file-cache.conf')])

    This test goes through all scenarios top to bottom.

    User is in excludes list:

      >>> pam.pamh = FakePamHandle('root', 'pwd')
      >>> pam.authenticate()
      INFO - User is in excluded list: root
      25

    User is in the wrong group:

      >>> pam.pamh = FakePamHandle('user2', 'good-pwd')
      >>> pam.authenticate()
      INFO - User "user2" is not a member of group "group1".
      9

    Admin has no proper credentials to look up group info:

      >>> pam.pamh = FakePamHandle('notallowed', 'good-pwd')
      >>> pam.authenticate()
      ERROR - Admin user has insufficient priviledges.
      Traceback (most recent call last):
      ...
      AppsForYourDomainException: admin@example.com
      9

    Bad Authentication:

      >>> pam.pamh = FakePamHandle('user1', 'bad-pwd')
      >>> pam.authenticate()
      INFO - Authentication failed for: user1
      9

    Captcha Required:

      >>> pam.pamh = FakePamHandle('user3', 'bad-pwd')
      >>> pam.authenticate()
      ERROR - Captcha Required: user3
      9

    An arbitrary error occured:

      >>> pam.pamh = FakePamHandle('error', 'bad-pwd')
      >>> pam.authenticate()
      ERROR - Unknown Exception: error
      Traceback (most recent call last):
      ...
      ValueError: error@example.com
      9

    Successful authentication:

      >>> pam.pamh = FakePamHandle('user1', 'good-pwd')
      >>> pam.authenticate()
      INFO - Authentication succeeded: user1
      0

    Now the cache kicks in:

      >>> pam.pamh = FakePamHandle('user1', 'good-pwd')
      >>> pam.authenticate()
      INFO - Authentication (via cache) succeeded: user1
      0

    But even with the cache, the password is checked:

      >>> pam.pamh = FakePamHandle('user1', 'bad-pwd')
      >>> pam.authenticate()
      INFO - Authentication (via cache) failed: user1
      9

    We are back to normal authentication, when the cache value times out:

      >>> pam._cache.lifespan = 0
      >>> pam.pamh = FakePamHandle('user1', 'good-pwd')
      >>> pam.authenticate()
      INFO - Deleting timed out cache entry: user1
      INFO - Authentication succeeded: user1
      0

    Clear the file cache:

      >>> pam._cache.clear()

    """

def doctest_GooglePAM_authenticate_multiple_groups():
    """class GooglePAM: authenticate()

      >>> pam = pam_google.GooglePAM(
      ...     FakePamHandle(), 0,
      ...     ['script', '-c', os.path.join(HERE, 'multi-group.conf')])

    User is in the wrong group:

      >>> pam.pamh = FakePamHandle('user4', 'good-pwd')
      >>> pam.authenticate()
      INFO - User "user4" is not a member of any of groups "group1", "group2".
      9

    Successful authentication:

      >>> pam.pamh = FakePamHandle('user1', 'good-pwd')
      >>> pam.authenticate()
      INFO - Authentication succeeded: user1
      0

      >>> pam.pamh = FakePamHandle('user2', 'good-pwd')
      >>> pam.authenticate()
      INFO - Authentication succeeded: user2
      0

    """

def doctest_FileCache():
    """class FileCache

      >>> pam = pam_google.GooglePAM(
      ...     FakePamHandle(), 0,
      ...     ['script', '-c', os.path.join(HERE, 'file-cache.conf')])

      >>> pam._cache
      <cipher.googlepam.pam_google.FileCache object at ...>

      >>> pam._cache.authenticate('user', 'pwd')

      >>> pam._cache.register('user', 'pwd')
      >>> pam._cache.authenticate('user', 'pwd')
      True
      >>> pam._cache.authenticate('user', 'bad')
      False

    Regression test: truncated usernames do not match

      >>> pam._cache.authenticate('use', 'pwd')

    When the cache entry times out, the cache behaves as it has no entry:

      >>> pam._cache.lifespan = 0
      >>> pam._cache.authenticate('user', 'pwd')
      INFO - Deleting timed out cache entry: user

    We can also clear the file:

      >>> pam._cache.clear()
    """

def doctest_FileCache_get_user_info_file_does_not_exist():
    """Test for FileCache._get_user_info

        >>> pam = GooglePAMStub({'file-cache': {
        ...     'file': 'nosuchfile',
        ...     'lifespan': '600',
        ... }})
        >>> fc = pam_google.FileCache(pam)
        >>> fc._get_user_info('bob')

    """

def doctest_FileCache_get_user_info_file_goes_away():
    """Test for FileCache._get_user_info

        >>> orig_exists = os.path.exists

        >>> pam = GooglePAMStub({'file-cache': {
        ...     'file': 'nosuchfile',
        ...     'lifespan': '600',
        ... }})
        >>> fc = pam_google.FileCache(pam)
        >>> os.path.exists = lambda filename: True

    Look-before-you-leap is prone to race conditions: the file might be
    deleted after you check for its existence

        >>> fc._get_user_info('bob')

        >>> os.path.exists = orig_exists

    """

def doctest_FileCache_add_user_info():
    r"""Test for FileCache._add_user_info

        >>> tempdir = tempfile.mkdtemp(prefix='cipher.googlepam-test-')
        >>> cachefile = os.path.join(tempdir, 'cache')

        >>> pam = GooglePAMStub({'file-cache': {
        ...     'file': cachefile,
        ...     'lifespan': '600',
        ... }})
        >>> fc = pam_google.FileCache(pam)
        >>> fc._add_user_info('bob', 's3cr3t')
        >>> print open(cachefile).read().strip()
        bob::...::...

    you can't poison the cache with trick usernames

        >>> fc._add_user_info('bob::0::mypasswordhash', 's3cr3t')
        >>> fc._add_user_info('fred\nroot', 's3cr3t')
        >>> print len(open(cachefile).readlines())
        1

        >>> shutil.rmtree(tempdir)

    """

def doctest_FileCache_del_user_info_file_goes_away():
    """Test for FileCache._del_user_info

        >>> orig_exists = os.path.exists

        >>> pam = GooglePAMStub({'file-cache': {
        ...     'file': '/nosuchfile',
        ...     'lifespan': '600',
        ... }})
        >>> fc = pam_google.FileCache(pam)
        >>> os.path.exists = lambda filename: True

    Look-before-you-leap is prone to race conditions: the file might be
    deleted after you check for its existence

        >>> fc._del_user_info('bob')

        >>> os.path.exists = orig_exists

    """

def doctest_FileCache_del_user_info_prefix_safety():
    """Test for FileCache._del_user_info

        >>> tempdir = tempfile.mkdtemp(prefix='cipher.googlepam-test-')
        >>> cachefile = os.path.join(tempdir, 'cache')

        >>> pam = GooglePAMStub({'file-cache': {
        ...     'file': cachefile,
        ...     'lifespan': '600',
        ... }})
        >>> fc = pam_google.FileCache(pam)
        >>> fc._add_user_info('bob', 's3cr3t')

    Now we try to delete 'bo', which is a prefix of 'bob'

        >>> fc._del_user_info('bo')

    and we should still have the 'bob' line in the cache file

        >>> print len(open(cachefile).readlines())
        1

        >>> shutil.rmtree(tempdir)

    """

def doctest_MemcacheCache():
    """class MemcacheCache

    This is a bit tricky: when pam_python.so loads the module, its name
    ends up being simply 'pam_google' instead of 'cipher.googlepam.pam_google'.
    This can break unpickling of classes defined in that module, since
    pam_python.so doesn't add the directory containing pam_google.py to
    sys.path, and it doesn't add pam_google itself to sys.modules.

      >>> sys.path.insert(0, os.path.dirname(pam_google.__file__))
      >>> import pam_google
      >>> pam_google.__name__
      'pam_google'
      >>> del sys.path[0]
      >>> del sys.modules['pam_google']

    Now that we have an approximation of that environment, let's go on

      >>> pam = pam_google.GooglePAM(
      ...     FakePamHandle(), 0,
      ...     ['script', '-c', os.path.join(HERE, 'mem-cache.conf')])

      >>> pam._cache
      <pam_google.MemcacheCache object at ...>

      >>> pam._cache.authenticate('user', 'pwd')

      >>> pam._cache.register('user', 'pwd')
      >>> pam._cache.authenticate('user', 'pwd')
      True
      >>> pam._cache.authenticate('user', 'bad')
      False
      >>> pam._cache.authenticate('other', 'pwd')

    When the cache entry times out, the cache behaves as it has no entry:

      >>> pam._cache.lifespan = 0
      >>> pam._cache.authenticate('user', 'pwd')
      INFO - Deleting timed out cache entry: user

    """

def setUp(test):
    test.orig_AppsService = pam_google.GooglePAM.AppsService
    pam_google.GooglePAM.AppsService = FakeAppsService
    test.orig_GroupsService = pam_google.GooglePAM.GroupsService
    pam_google.GooglePAM.GroupsService = FakeGroupsService
    conf_file = os.path.join(HERE, 'googlepam.conf')
    pam_google.parser.set_default('config_file', conf_file)

def tearDown(test):
    pam_google.GooglePAM.AppsService = test.orig_AppsService
    pam_google.GooglePAM.GroupsService = test.orig_GroupsService
    pam_google.parser.set_default('config_file', pam_google.DEFAULT_CONFIG)

def test_suite():
    return doctest.DocTestSuite(
        setUp=setUp, tearDown=tearDown,
        optionflags=(doctest.NORMALIZE_WHITESPACE|
                     doctest.ELLIPSIS|
                     doctest.REPORT_ONLY_FIRST_FAILURE)
        )

