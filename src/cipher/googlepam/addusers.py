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
"""Add Google users to system."""
import logging
import optparse
import subprocess
import sys

from gdata.apps.groups.service import GroupsService
from gdata.apps.service import AppsService, AppsForYourDomainException
from gdata.service import BadAuthentication, CaptchaRequired

parser = optparse.OptionParser()
parser.usage = '%prog [options]'

log = logging.getLogger("add-google-users")

ADDUSER_CMD = ('adduser --firstuid 2000 --disabled-password '
               '--gecos "%(full_name)s" %(user_name)s')
ADDADMIN_CMD = 'usermod -a -G %(admin-group)s %(user_name)s'

class CMDError(Exception):
    pass

def do(cmd, cwd=None, capture_output=True, dry_run=False):
    if capture_output:
        stdout = stderr = subprocess.PIPE
    else:
        stdout = stderr = None
    log.debug('Starting: %s' %cmd)
    if dry_run:
        return
    p = subprocess.Popen(
        cmd, stdout=stdout, stderr=stderr,
        shell=True, cwd=cwd)
    stdout, stderr = p.communicate()
    if stdout is None:
        stdout = "See output above"
    if stderr is None:
        stderr = "See output above"
    if p.returncode != 0:
        log.error(u'An error occurred while running command: %s' %cmd)
        log.error('Error Output: \n%s' % stderr)
        raise CMDError(p.returncode, stdout+'\n'+stderr)

    log.debug('Result:\n%s' %stdout)
    return stdout

def setupLogging(level=logging.INFO):
    log.setLevel(level)

    handler = logging.StreamHandler(sys.stdout)
    formatter = logging.Formatter('%(levelname)s - %(message)s')
    handler.setFormatter(formatter)
    log.addHandler(handler)

def addusers(options):
    # 1. Get a full list of all users to be added.
    log.info('Getting members of group: %s', options.group)
    groups_srv = GroupsService(
        domain=options.domain,
        email=options.user+'@'+options.domain,
        password=options.password
        )
    groups_srv.ProgrammaticLogin()
    members_feed = groups_srv.RetrieveAllMembers(options.group, False)
    emails = [user_dict['memberId']
             for user_dict in members_feed]
    log.info('Found members: %s',
             ', '.join(email.split('@')[0] for email in emails))
    # 2. Now we get all the meta-data associated with the user.
    apps_srv = AppsService(
        domain=options.domain,
        email=options.user+'@'+options.domain,
        password=options.password
        )
    apps_srv.ProgrammaticLogin()
    users = []
    for email in emails:
        entry = apps_srv.RetrieveUser(email.split('@')[0])
        users.append({
            'full_name': '%s %s' %(entry.name.given_name,
                                   entry.name.family_name),
            'user_name': entry.login.user_name,
            'admin-group': options.admin_group,
            })
        log.debug('Found user data: %r', users[-1])
    # 3. Create a new user account for each account.
    for user in users:
        try:
            do(options.command %user, dry_run=options.dry_run)
        except CMDError, err:
            # We do not want to fail, if the user already exists.
            if err.args[0] != 1:
                raise
        do(ADDADMIN_CMD %user, dry_run=options.dry_run)

parser.add_option(
    '-d', '--domain', action='store', dest='domain',
    help='The Google domain in which the users belong.')

parser.add_option(
    '-u', '--admin-user', action='store', dest='user',
    help='The username of the Google admin user.')

parser.add_option(
    '-p', '--admin-password', action='store', dest='password',
    help='The password of the Google admin user.')

parser.add_option(
    '-g', '--group', action='store',
    dest='group', default='security',
    help='The group all users belong to.')

parser.add_option(
    '-a', '--admin-group', action='store',
    dest='admin_group', default='admin',
    help='The group to which the user will be added.')

parser.add_option(
    '-c', '--command', action='store',
    dest='command', default=ADDUSER_CMD,
    help='The command used to create the user.')

parser.add_option(
    '--dry-run', action='store_true',
    dest='dry_run', default=False,
    help='A flag, when set, does not execute commands.')

parser.add_option(
    "-q","--quiet", action="store_true",
    dest="quiet", default=False,
    help="When specified, no messages are displayed.")

parser.add_option(
    "-v","--verbose", action="store_true",
    dest="verbose", default=False,
    help="When specified, debug information is created.")

def main(args=None):
    if args is None:
        args = sys.argv[1:]

    options, args = parser.parse_args(args)

    # Set up logging.
    setupLogging()
    if options.verbose:
        log.setLevel(logging.DEBUG)
    if options.quiet:
        log.setLevel(logging.FATAL)

    addusers(options)
