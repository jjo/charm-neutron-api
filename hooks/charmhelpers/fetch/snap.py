# Copyright 2014-2017 Canonical Limited.
#
# Licensed under the Apache License, Version 2.0 (the "License");
# you may not use this file except in compliance with the License.
# You may obtain a copy of the License at
#
#  http://www.apache.org/licenses/LICENSE-2.0
#
# Unless required by applicable law or agreed to in writing, software
# distributed under the License is distributed on an "AS IS" BASIS,
# WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
# See the License for the specific language governing permissions and
# limitations under the License.
"""
Charm helpers snap for classic charms.

If writing reactive charms, use the snap layer:
https://lists.ubuntu.com/archives/snapcraft/2016-September/001114.html
"""
import subprocess
from os import environ
from time import sleep
from charmhelpers.core.hookenv import log

__author__ = 'Joseph Borg <joseph.borg@canonical.com>'

SNAP_NO_LOCK = 1  # The return code for "couldn't acquire lock" in Snap (hopefully this will be improved).
SNAP_NO_LOCK_RETRY_DELAY = 10  # Wait X seconds between Snap lock checks.
SNAP_NO_LOCK_RETRY_COUNT = 30  # Retry to acquire the lock X times.


class CouldNotAcquireLockException(Exception):
    pass


def _snap_exec(commands):
    """
    Execute snap commands.

    :param commands: List commands
    :return: Integer exit code
    """
    assert type(commands) == list

    retry_count = 0
    return_code = None

    while return_code is None or return_code == SNAP_NO_LOCK:
        try:
            return_code = subprocess.check_call(['snap'] + commands, env=environ)
        except subprocess.CalledProcessError as e:
            retry_count += + 1
            if retry_count > SNAP_NO_LOCK_RETRY_COUNT:
                raise CouldNotAcquireLockException('Could not aquire lock after %s attempts' % SNAP_NO_LOCK_RETRY_COUNT)
            return_code = e.returncode
            log('Snap failed to acquire lock, trying again in %s seconds.' % SNAP_NO_LOCK_RETRY_DELAY, level='WARN')
            sleep(SNAP_NO_LOCK_RETRY_DELAY)

    return return_code


def snap_install(packages, *flags):
    """
    Install a snap package.

    :param packages: String or List String package name
    :param flags: List String flags to pass to install command
    :return: Integer return code from snap
    """
    if type(packages) is not list:
        packages = [packages]

    flags = list(flags)

    message = 'Installing snap(s) "%s"' % ', '.join(packages)
    if flags:
        message += ' with option(s) "%s"' % ', '.join(flags)

    log(message, level='INFO')
    return _snap_exec(['install'] + flags + packages)


def snap_remove(packages, *flags):
    """
    Remove a snap package.

    :param packages: String or List String package name
    :param flags: List String flags to pass to remove command
    :return: Integer return code from snap
    """
    if type(packages) is not list:
        packages = [packages]

    flags = list(flags)

    message = 'Removing snap(s) "%s"' % ', '.join(packages)
    if flags:
        message += ' with options "%s"' % ', '.join(flags)

    log(message, level='INFO')
    return _snap_exec(['remove'] + flags + packages)


def snap_refresh(packages, *flags):
    """
    Refresh / Update snap package.

    :param packages: String or List String package name
    :param flags: List String flags to pass to refresh command
    :return: Integer return code from snap
    """
    if type(packages) is not list:
        packages = [packages]

    flags = list(flags)

    message = 'Refreshing snap(s) "%s"' % ', '.join(packages)
    if flags:
        message += ' with options "%s"' % ', '.join(flags)

    log(message, level='INFO')
    return _snap_exec(['refresh'] + flags + packages)
