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
"""Google PAM Module

# here are the per-package modules (the "Primary" block)
auth    [success=1 default=ignore]      pam_python.so /path/to/pam_google.py

"""
import ConfigParser
import bcrypt
import collections
import logging
import logging.config
import memcache
import optparse
import os
import time

from gdata.apps.groups.service import GroupsService
from gdata.apps.service import AppsService, AppsForYourDomainException
from gdata.service import BadAuthentication, CaptchaRequired

DEFAULT_CONFIG = os.path.join(os.path.dirname(__file__), 'googlepam.conf')
SECTION_NAME = 'googlepam'
LOG = logging.getLogger('cipher.googlepam.PAM')

parser = optparse.OptionParser()
parser.usage = '%prog [options]'

parser.add_option(
    '-c', '--config-file', action='store',
    dest='config_file', default=DEFAULT_CONFIG,
    help='The file containing all configuration.')

UserInfo = collections.namedtuple('UserInfo', ['created', 'pw_hash'])


class BaseCache(object):

    SECTION_NAME = 'cache'

    def __init__(self, pam):
        self.pam = pam
        self.lifespan = self.pam.config.getint(self.SECTION_NAME, 'lifespan')

    def _get_user_info(self, username):
        raise NotImplemented

    def _add_user_info(self, username, password):
        raise NotImplemented

    def _del_user_info(self, username):
        raise NotImplemented

    def register(self, username, password):
        LOG.debug('Register cache entry: %s', username)
        self._add_user_info(username, password)

    def authenticate(self, username, password):
        info = self._get_user_info(username)
        if info is None:
            return None
        if info.created + self.lifespan < time.time():
            LOG.info('Deleting timed out cache entry: %s', username)
            self._del_user_info(username)
            return None
        return bcrypt.hashpw(password, info.pw_hash) == info.pw_hash


class FileCache(BaseCache):

    SECTION_NAME = 'file-cache'

    def __init__(self, pam):
        super(FileCache, self).__init__(pam)
        self._filename = self.pam.config.get(self.SECTION_NAME, 'file')

    def _get_user_info(self, username):
        if not os.path.exists(self._filename):
            return
        with open(self._filename, 'r') as file:
            for line in file:
                if line.startswith(username):
                    username, created, pw_hash = line.strip().split('::', 2)
                    return UserInfo(float(created), pw_hash)
        return None

    def _add_user_info(self, username, password):
        with open(self._filename, 'a') as file:
            file.write('%s::%f::%s\n' %(
                    username,
                    time.time(),
                    bcrypt.hashpw(password, bcrypt.gensalt())
                    ))

    def _del_user_info(self, username):
        if not os.path.exists(self._filename):
            return
        with open(self._filename, 'r') as file:
            lines = [line for line in file
                     if not line.startswith(username)]
        with open(self._filename, 'w') as file:
            file.writelines(lines)

    def clear(self):
        os.remove(self._filename)


class MemcacheCache(BaseCache):

    SECTION_NAME = 'memcache-cache'

    def __init__(self, pam):
        super(MemcacheCache, self).__init__(pam)
        self._client = memcache.Client(
                ['%s:%s' %(self.pam.config.get(self.SECTION_NAME, 'host'),
                           self.pam.config.get(self.SECTION_NAME, 'port'))],
                debug = self.pam.config.getboolean(self.SECTION_NAME, 'debug'))

    def _get_key(self, username):
        return self.pam.config.get(self.SECTION_NAME, 'key-prefix')

    def _get_user_info(self, username):
        return self._client.get(self._get_key(username))

    def _add_user_info(self, username, password):
        self._client.set(
            self._get_key(username),
            UserInfo(time.time(), bcrypt.hashpw(password, bcrypt.gensalt())))

    def _del_user_info(self, username):
        self._client.delete(self._get_key(username))


class GooglePAM(object):

    password_prompt = 'Password:'
    _cache = None

    cache_classes = {
        'file': FileCache,
        'memcache': MemcacheCache
        }

    # Testing Hooks
    AppsService = AppsService
    GroupsService = GroupsService

    def __init__(self, pamh, flags, argv):
        self.pamh = pamh
        self.flags = flags
        self.argv = argv
        self.initialize()

    def initialize(self):
        self.options, self.args = parser.parse_args(self.argv[1:])
        self.config = ConfigParser.ConfigParser()
        self.config.xform = str
        self.config.read(self.options.config_file)
        if self.config.has_option(SECTION_NAME, 'prompt'):
            self.password_prompt = self.config.get(SECTION_NAME, 'prompt')
        # no world-readable log and cache files please
        os.umask(0o077)
        logging.config.fileConfig(
            self.options.config_file, disable_existing_loggers=False)
        if self.config.has_option(SECTION_NAME, 'cache'):
            klass = self.cache_classes[self.config.get(SECTION_NAME, 'cache')]
            self._cache = klass(self)

    def _get_email(self, user):
        return user+'@'+self.config.get(SECTION_NAME, 'domain')

    def authenticate(self):
        LOG.debug('Start authentication via Google PAM: %s, %s',
                  self.flags, self.argv)

        if (not self.config.has_option(SECTION_NAME, 'domain') or
            not self.config.has_option(SECTION_NAME, 'admin-username') or
            not self.config.has_option(SECTION_NAME, 'admin-password')):
                LOG.info('Google PAM not configured')
                return self.pamh.PAM_IGNORE

        # 0. We do not authenticate excluded users.
        if self.config.has_option(SECTION_NAME, 'excludes'):
            excluded = [
                user.strip()
                for user in self.config.get(SECTION_NAME, 'excludes').split(',')]
            if self.pamh.user in excluded:
                LOG.info('User is in excluded list: %s', self.pamh.user)
                return self.pamh.PAM_IGNORE

        # 1. Get the password.
        if self.pamh.authtok == None:
            LOG.debug('No auth token was found. Starting conversation.')
            msg = self.pamh.Message(
                self.pamh.PAM_PROMPT_ECHO_OFF, self.password_prompt + ' ')
            response = self.pamh.conversation(msg)
            self.pamh.authtok = response.resp
            LOG.debug('Got password: %s', self.pamh.authtok)

        # 2. If we have a cache setup, try to find the answer there first.
        if self._cache:
            LOG.debug('Checking authentication cache: %s', self.pamh.user)
            auth = self._cache.authenticate(self.pamh.user, self.pamh.authtok)
            if auth == True:
                LOG.info(
                    'Authentication (via cache) succeeded: %s', self.pamh.user)
                return self.pamh.PAM_SUCCESS
            if auth == False:
                LOG.info(
                    'Authentication (via cache) failed: %s', self.pamh.user)
                return self.pamh.PAM_AUTH_ERR

            LOG.debug('No entry in authentication cache: %s', self.pamh.user)

        # 3. If a group has been specified, check that the user is in the
        # group, otherwise we do not even have to proceed.
        # Note: We could do that check before asking for the password, but
        # then we would give away the fact that the username is incorrect.
        if self.config.has_option(SECTION_NAME, 'group'):
            group = self.config.get(SECTION_NAME, 'group')
            LOG.debug('Group found: %s', group)
            service = self.GroupsService(
                domain=self.config.get(SECTION_NAME, 'domain'),
                email=self._get_email(
                    self.config.get(SECTION_NAME, 'admin-username')),
                password=self.config.get(SECTION_NAME, 'admin-password')
                )
            service.ProgrammaticLogin()
            try:
                if not service.IsMember(self.pamh.user, group):
                    LOG.info(
                        'User "%s" is not a member of group "%s".',
                        self.pamh.user, group)
                    return self.pamh.PAM_AUTH_ERR
            except AppsForYourDomainException, err:
                LOG.exception('Admin user has insufficient priviledges.')
                return self.pamh.PAM_AUTH_ERR
            LOG.debug(
                'User "%s" is a member of group "%s".', self.pamh.user, group)

        service = self.AppsService(
            domain=self.config.get(SECTION_NAME, 'domain'),
            email=self._get_email(
                self.config.get(SECTION_NAME, 'admin-username')),
            password=self.config.get(SECTION_NAME, 'admin-password')
            )

        try:
            service.ClientLogin(
                self._get_email(self.pamh.user),
                self.pamh.authtok,
                account_type='HOSTED', source='cipher-google-pam')

        except BadAuthentication, e:
            LOG.info('Authentication failed for: %s', self.pamh.user)
            return self.pamh.PAM_AUTH_ERR
        except CaptchaRequired, e:
            LOG.error('Captcha Required: %s', self.pamh.user)
            return self.pamh.PAM_AUTH_ERR
        except:
            LOG.exception('Unknown Exception: %s', self.pamh.user)
            return self.pamh.PAM_AUTH_ERR

        # Store the good credentials in the cache.
        if self._cache:
            self._cache.register(self.pamh.user, self.pamh.authtok)

        LOG.info('Authentication succeeded: %s', self.pamh.user)
        return self.pamh.PAM_SUCCESS

    def setcred(self):
        # Always return success, since it is called upon authentication
        # success.
        return self.pamh.PAM_SUCCESS

    def acct_mgmt(self):
        LOG.info("`acct_mgmt` is not supported.")
        return self.pamh.PAM_SERVICE_ERR

    def chauthtok(self):
        LOG.info("`chauthtok` is not supported.")
        return self.pamh.PAM_SERVICE_ERR

    def open_session(self):
        LOG.info("`open_session` is not supported.")
        return self.pamh.PAM_SERVICE_ERR

    def close_session(self):
        LOG.info("`close_session` is not supported.")
        return self.pamh.PAM_SERVICE_ERR


# Official pam_python API.

def pam_sm_authenticate(pamh, flags, argv):
    return GooglePAM(pamh, flags, argv).authenticate()

def pam_sm_setcred(pamh, flags, argv):
    return GooglePAM(pamh, flags, argv).setcred()

def pam_sm_acct_mgmt(pamh, flags, argv):
    return GooglePAM(pamh, flags, argv).acct_mgmt()

def pam_sm_chauthtok(pamh, flags, argv):
    return GooglePAM(pamh, flags, argv).chauthtok()

def pam_sm_open_session(pamh, flags, argv):
    return GooglePAM(pamh, flags, argv).open_session()

def pam_sm_close_session(pamh, flags, argv):
    return GooglePAM(pamh, flags, argv).close_session()
