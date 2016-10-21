Changelog
=========

1.7.0 (unreleased)
------------------

- Remove all the code because it is now totally broken
  (https://github.com/zopefoundation/cipher.googlepam/issues/1).


1.6.0 (2013-04-16)
------------------

- Extracted a reusable helper ``cipher.googlepam.pam_google.GoogleAuth``
  that you can use to implement Google authentication in applications that do
  not use PAM.


1.5.1 (2012-10-11)
------------------

- MemCache reliability fixes:

  + **SECURITY FIX**: do not use the same cache key for all users.

    Previously when one user logged in successfully, others could not log in
    using their own passwords -- but the first user could now use her password
    to log in as anyone else.

  + Do not store custom classes in memcached so we don't get unpickling
    errors caused by the special execution environment set up by
    pam_python.so.  Previously the cached value was a subclass of tuple,
    now it's a plain tuple, so old caches will continue to work with the
    new code.

- FileCache reliability fixes:

  + Avoid incorrect cache lookups (or invalidations) when a username is a
    proper prefix of some other username.

  + Avoid cache poisoning if usernames contain embedded '::' separators or
    newlines.

  + Avoid exceptions on a race condition if the cache file disappears after
    we check for its existence but before we open it for reading.

- Add missing test file for multi-group support.  It was accidentally left
  out of the last release causing a test failure.

- Make add-google-users skip users that already exist without printing
  scary error messages that make it seem the script aborted early.


1.5.0 (2012-10-09)
------------------

- Support multiple Google groups.  The authenticating user has to be a member
  of any one of them for access to be allowed.

- Added add-google-users new option --exclude to skip adding some users
  (e.g. the 'admin' user might clash with an existing 'admin' group, causing
  the script to fail).

- Added add-google-users option --add-to-group as a more meaningful alias for
  the old --admin-group option.

- Added add-google-users option --add-to-group-command for completeness.


1.4.0 (2012-10-08)
------------------

- Set umask to avoid world-readable log and cache files.

- Add a space after the PAM prompt.

- The add-google-users script now reads the pam_google config file to get the
  domain, username, password and group.  You can also use -C/--config-file to
  specify a different config file.

- add-google-users does not break if you don't specify --admin-group.

- Added Debian packaging.


1.3.0 (2012-04-24)
------------------

- Added ability to cache authentication result, since some uses, such as
  Apache authentication can cause a lot of requests. File- and
  memcached-based caches have been implemented and are available/configurable
  in the configuration file.

- Fully stubbed out the Google API for faster and simpler testing.

- Removed all traces of Cipher's specific account details.

- Changed all headers to ZPL.

- The package is ready for public release.


1.2.0 (2012-04-17)
------------------

- Do not fail if the username already exists.


1.1.0 (2012-04-17)
------------------

- Make the admin group configurable.


1.0.0 (2012-04-17)
------------------

- PAM module authenticating against users in a group of a particular Google
  domain.

- Script to add all users of a group within a Google domain as system users.
