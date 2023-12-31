# Unix SMB/CIFS implementation. Tests for xattr manipulation
# Copyright (C) Matthieu Patou <mat@matws.net> 2009
#
# This program is free software; you can redistribute it and/or modify
# it under the terms of the GNU General Public License as published by
# the Free Software Foundation; either version 3 of the License, or
# (at your option) any later version.
#
# This program is distributed in the hope that it will be useful,
# but WITHOUT ANY WARRANTY; without even the implied warranty of
# MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
# GNU General Public License for more details.
#
# You should have received a copy of the GNU General Public License
# along with this program.  If not, see <http://www.gnu.org/licenses/>.
#

"""Tests for samba.xattr_native and samba.xattr_tdb."""

import samba.xattr_native
import samba.xattr_tdb
import samba.posix_eadb
from samba.xattr import copytree_with_xattrs
from samba.dcerpc import xattr
from samba.ndr import ndr_pack
from samba.tests import (
    SkipTest,
    TestCase,
    TestCaseInTempDir,
)
import random
import shutil
import os


class XattrTests(TestCase):

    def _tmpfilename(self):
        random.seed()
        path = os.environ['SELFTEST_PREFIX']
        return os.path.join(path, "pytests" +str(int(100000 * random.random())))

    def _eadbpath(self):
        return os.path.join(os.environ['SELFTEST_PREFIX'], "eadb.tdb")

    def test_set_xattr_native(self):
        if not samba.xattr_native.is_xattr_supported():
            raise SkipTest()
        ntacl = xattr.NTACL()
        ntacl.version = 1
        tempf = self._tmpfilename()
        open(tempf, 'w').write("empty")
        try:
            samba.xattr_native.wrap_setxattr(tempf, "user.unittests",
                                             ndr_pack(ntacl))
        except IOError:
            raise SkipTest("the filesystem where the tests are run does not "
                           "support XATTR")
        os.unlink(tempf)

    def test_set_and_get_native(self):
        if not samba.xattr_native.is_xattr_supported():
            raise SkipTest()
        tempf = self._tmpfilename()
        reftxt = b"this is a test"
        open(tempf, 'w').write("empty")
        try:
            samba.xattr_native.wrap_setxattr(tempf, "user.unittests", reftxt)
            text = samba.xattr_native.wrap_getxattr(tempf, "user.unittests")
            self.assertEqual(text, reftxt)
        except IOError:
            raise SkipTest("the filesystem where the tests are run does not "
                           "support XATTR")
        os.unlink(tempf)

    def test_set_xattr_tdb(self):
        tempf = self._tmpfilename()
        eadb_path = self._eadbpath()
        ntacl = xattr.NTACL()
        ntacl.version = 1
        open(tempf, 'w').write("empty")
        try:
            samba.xattr_tdb.wrap_setxattr(eadb_path,
                                          tempf, "user.unittests", ndr_pack(ntacl))
        finally:
            os.unlink(tempf)
        os.unlink(eadb_path)

    def test_set_tdb_not_open(self):
        tempf = self._tmpfilename()
        ntacl = xattr.NTACL()
        ntacl.version = 1
        open(tempf, 'w').write("empty")
        try:
            self.assertRaises(IOError, samba.xattr_tdb.wrap_setxattr,
                              os.path.join("nonexistent", "eadb.tdb"), tempf,
                              "user.unittests", ndr_pack(ntacl))
        finally:
            os.unlink(tempf)

    def test_set_and_get_tdb(self):
        tempf = self._tmpfilename()
        eadb_path = self._eadbpath()
        reftxt = b"this is a test"
        open(tempf, 'w').write("empty")
        try:
            samba.xattr_tdb.wrap_setxattr(eadb_path, tempf, "user.unittests",
                                          reftxt)
            text = samba.xattr_tdb.wrap_getxattr(eadb_path, tempf,
                                                 "user.unittests")
            self.assertEqual(text, reftxt)
        finally:
            os.unlink(tempf)
        os.unlink(eadb_path)

    def test_set_posix_eadb(self):
        tempf = self._tmpfilename()
        eadb_path = self._eadbpath()
        ntacl = xattr.NTACL()
        ntacl.version = 1
        open(tempf, 'w').write("empty")
        try:
            samba.posix_eadb.wrap_setxattr(eadb_path,
                                           tempf, "user.unittests", ndr_pack(ntacl))
        finally:
            os.unlink(tempf)
        os.unlink(eadb_path)

    def test_set_and_get_posix_eadb(self):
        tempf = self._tmpfilename()
        eadb_path = self._eadbpath()
        reftxt = b"this is a test"
        open(tempf, 'w').write("empty")
        try:
            samba.posix_eadb.wrap_setxattr(eadb_path, tempf, "user.unittests",
                                           reftxt)
            text = samba.posix_eadb.wrap_getxattr(eadb_path, tempf,
                                                  "user.unittests")
            self.assertEqual(text, reftxt)
        finally:
            os.unlink(tempf)
        os.unlink(eadb_path)


class TestCopyTreeWithXattrs(TestCaseInTempDir):

    def test_simple(self):
        os.chdir(self.tempdir)
        os.mkdir("a")
        os.mkdir("a/b")
        os.mkdir("a/b/c")
        f = open('a/b/c/d', 'w')
        try:
            f.write("foo")
        finally:
            f.close()
        copytree_with_xattrs("a", "b")
        shutil.rmtree("a")
        shutil.rmtree("b")
