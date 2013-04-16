Google PAM Module
=================

This package implements a Python PAM module to authenticate users against a
Google domain. The following features are provided:

- Select any Google domain.

- Allow only users from a certain group.

- A script to install all Google users as system users.

- Password caching using files or memcached.

- Advanced logging setup.

The code was inspired by the ``python_pam.so`` examples and the
``TracGoogleAppsAuthPlugin`` trac authentication plugin.


Configuring Google PAM on Ubuntu 12.04 LTS
------------------------------------------

1. Install a few required packages::

     # apt-get install python-setuptools python-gdata python-bcrypt \
                       python-memcache libpam-python

2. Now install ``cipher.googlepam`` using easy install::

     # easy_install cipher.googlepam

3. Add all users to the system::

     # add-google-users -v -d <domain> -u <admin-user> -p <admin-pwd> \
                        -g <google-group> -a <system-admin-group>

   Note: Use the ``-h`` option to discover all options.

4. Create a ``/etc/pam_google.conf`` configuration file::

     [googlepam]
     domain=<domain>
     admin-username=<admin-user>
     admin-password=<admin-pwd>
     group=<google-group>
     excludes = root [<user> ...]
     prompt = Google Password:
     cache = file|memcache

     [file-cache]
     file = /var/lib/pam_google/user-cache
     lifespan = 1800

     [memcache-cache]
     key-prefix = googlepam.
     host = 127.0.0.1
     port = 11211
     debug = false
     lifespan = 1800

     [loggers]
     keys = root, pam

     [logger_root]
     handlers = file
     level = INFO

     [logger_pam]
     qualname = cipher.googlepam.PAM
     handlers = file
     propagate = 0
     level = INFO

     [handlers]
     keys = file

     [handler_file]
     class = logging.handlers.RotatingFileHandler
     args = ('/var/log/pam-google.log', 'a', 10*1024*1024, 5)
     formatter = simple

     [formatters]
     keys = simple

     [formatter_simple]
     format = %(asctime)s %(levelname)s - %(message)s
     datefmt = %Y-%m-%dT%H:%M:%S

5. Hide contents of the config file from the curious users::

     # chmod 600 /etc/pam_google.conf

6. Put the Google PAM module in a sensible location::

     # ln -s /usr/local/lib/python2.7/dist-packages/cipher.googlepam-<version>-py2.7.egg/cipher/googlepam/pam_google.py /lib/security/pam_google.py

7. Enable pam_google for all authentication. Add the following rule as the
   first rule in file ``/etc/pam.d/common-auth``::

     auth    sufficient   pam_python.so /lib/security/pam_google.py -c /etc/pam_google.conf


Building a Debian package
-------------------------

1. Install a few required packages::

     # apt-get install build-essential debhelper devscripts fakeroot quilt

2. Download the latest cipher.googlepam tarball from PyPI (or build one with
   ``python setup.py sdist``)

3. Rename the tarball ``cipher.googlepam_VERSION.orig.tar.gz`` (note: underscore
   instead of the hyphen!), put it in the parent directory of the source tree
   (if you don't have a source tree, just untar the tarball).

4. Go to the source tree, run ``dch -i``, make sure the version number in the
   changelog matches the package version, make sure your name and email are
   correct, write a changelog entry itself (e.g. something like 'New upstream
   release'.)

5. Run ``debuild``.  If everything's fine, you should get a ``deb`` file in the
   parent directory.

Install the deb with ``sudo dpkg -i cipher.googlepam...deb; sudo apt-get -f
install``.  Then edit ``/etc/cipher-googlepam/pam_google.conf`` and run
``add-google-users``.  You don't need to manually edit PAM configuration if you
use the .deb package.

