
import mock

try:
    import unittest2 as unittest
except ImportError:  # pragma: no cover
    import unittest

import nagiosplugin
from nagiosplugin.metric import Metric
from nagiosplugin import CheckError

from checkpkgaudit import checkpkgaudit

no_jails = "   JID  IP Address      Hostname        Path"

jails = ("    JID  IP Address      Hostname         Path\n",
         "     50  10.0.0.93       masterdns        /usr/jails/masterdns\n",
         "     51  -               hastd: disk1 (primary)        /var/empty\n",
         "     52  10.0.0.25       smtp             /usr/jails/smtp\n",
         "     54  10.0.0.53       ns0              /usr/jails/ns0\n",
         "     55  10.0.0.153      ns1              /usr/jails/ns1\n",
         "     57  10.0.0.80       http             /usr/jails/http\n",
         "     59  10.0.0.20       supervision      /usr/jails/supervision\n",
         "     61                  formationpy      /usr/jails/formationpy\n")


class Test__getjails(unittest.TestCase):

    def test__get_jls_no_running_jails(self):
        meth = checkpkgaudit._get_jails
        mocked = "checkpkgaudit.checkpkgaudit.subprocess"
        with mock.patch(mocked) as subprocess:
            subprocess.check_output.return_value = no_jails
            self.assertEqual(meth(), [])

    def test__get_jls_running_jails(self):
        meth = checkpkgaudit._get_jails
        mocked = "checkpkgaudit.checkpkgaudit.subprocess"
        jls = [{'hostname': 'masterdns', 'jid': '50'},
               {'hostname': 'smtp', 'jid': '52'},
               {'hostname': 'ns0', 'jid': '54'},
               {'hostname': 'ns1', 'jid': '55'},
               {'hostname': 'http', 'jid': '57'},
               {'hostname': 'supervision', 'jid': '59'},
               {'hostname': 'formationpy', 'jid': '61'}]
        with mock.patch(mocked) as subprocess:
            subprocess.check_output.return_value = ''.join(jails)
            self.assertEqual(meth(), jls)


class Test_CheckPkgAudit(unittest.TestCase):

    def test_pkg_audit_not_installed(self):
        check = checkpkgaudit.CheckPkgAudit()
        err_message = ("pkg: vulnxml file /var/db/pkg/vuln.xml does not exist."
                       " Try running 'pkg audit -F' first")
        with mock.patch("checkpkgaudit.checkpkgaudit._popen") as _popen:
            _popen.return_value = '', err_message
            with self.assertRaises(CheckError):
                check.pkg_audit()  # NOQA

    def test_pkg_audit_not_installed_in_jail(self):
        check = checkpkgaudit.CheckPkgAudit()
        err_message = ("pkg: vulnxml file /var/db/pkg/vuln.xml does not exist."
                       " Try running 'pkg audit -F' first")
        with mock.patch("checkpkgaudit.checkpkgaudit._popen") as _popen:
            _popen.return_value = '', err_message
            with self.assertRaises(CheckError):
                check.pkg_audit(jail='supervision')  # NOQA

    def test_pkg_audit_not_authorised_inside_jail(self):
        check = checkpkgaudit.CheckPkgAudit()
        err_message = "pkg: jail_attach(masterdns): Operation not permitted"
        with mock.patch("checkpkgaudit.checkpkgaudit._popen") as _popen:
            _popen.return_value = '', err_message
            with self.assertRaises(CheckError):
                check.pkg_audit(jail='masterdns')  # NOQA

    def test_pkg_audit_no_problems(self):
        check = checkpkgaudit.CheckPkgAudit()
        ok_message = "0 problem(s) in the installed packages found."
        with mock.patch("checkpkgaudit.checkpkgaudit._popen") as _popen:
            _popen.return_value = ok_message, ''
            self.assertEqual(check.pkg_audit(), 0)

    def test_pkg_audit_no_problems_inside_jail(self):
        check = checkpkgaudit.CheckPkgAudit()
        ok_message = "0 problem(s) in the installed packages found."
        with mock.patch("checkpkgaudit.checkpkgaudit._popen") as _popen:
            _popen.return_value = ok_message, ''
            self.assertEqual(check.pkg_audit('masterdns'), 0)

    def test_pkg_audit_with_problems(self):
        check = checkpkgaudit.CheckPkgAudit()
        pb = ("bind910-9.10.1P1_1 is vulnerable:\n",
              "bind -- denial of service vulnerability\n",
              "CVE: CVE-2015-1349\n",
              "WWW: http://vuxml.FreeBSD.org/freebsd/58033a95",
              "-bba8-11e4-88ae-d050992ecde8.html\n",
              "\n",
              "1 problem(s) in the installed packages found.\n")

        with mock.patch("checkpkgaudit.checkpkgaudit._popen") as _popen:
            _popen.return_value = ''.join(pb), ''
            self.assertEqual(check.pkg_audit(), 1)

    def test_pkg_audit_with_problems_inside_jail(self):
        check = checkpkgaudit.CheckPkgAudit()
        pb = ("bind910-9.10.1P1_1 is vulnerable:\n",
              "bind -- denial of service vulnerability\n",
              "CVE: CVE-2015-1349\n",
              "WWW: http://vuxml.FreeBSD.org/freebsd/58033a95",
              "-bba8-11e4-88ae-d050992ecde8.html\n",
              "\n",
              "1 problem(s) in the installed packages found.\n")

        with mock.patch("checkpkgaudit.checkpkgaudit._popen") as _popen:
            _popen.return_value = ''.join(pb), ''
            self.assertEqual(check.pkg_audit(), 1)

    def test_probe_host(self):
        check = checkpkgaudit.CheckPkgAudit()
        check.hostname = 'hostname.domain.tld'
        mocked = "checkpkgaudit.checkpkgaudit._get_jails"
        with mock.patch(mocked) as _get_jails:
            _get_jails.return_value = []

            mocked = "checkpkgaudit.checkpkgaudit.CheckPkgAudit.pkg_audit"
            with mock.patch(mocked) as pkg_audit:
                pkg_audit.return_value = 0

                probe = check.probe()
                host = next(probe)
                self.assertEqual(type(host), Metric)
                self.assertEqual(host.name, 'hostname.domain.tld')
                self.assertEqual(host.value, 0)

    def test_probe_host_with_jails(self):
        check = checkpkgaudit.CheckPkgAudit()
        check.hostname = 'hostname.domain.tld'
        mocked = "checkpkgaudit.checkpkgaudit._get_jails"
        with mock.patch(mocked) as _get_jails:
            _get_jails.return_value = [{'hostname': 'masterdns', 'jid': '50'}]

            mocked = "checkpkgaudit.checkpkgaudit.CheckPkgAudit.pkg_audit"
            with mock.patch(mocked) as pkg_audit:
                pkg_audit.return_value = 0
                probe = check.probe()
                host = next(probe)
                self.assertIsNotNone(host)
                jail = next(probe)
                self.assertIsNotNone(jail)


class Test_AuditSummary(unittest.TestCase):

    def test_ok(self):
        from nagiosplugin.result import Result, Results
        from nagiosplugin.state import Ok
        from checkpkgaudit.checkpkgaudit import AuditSummary
        results = Results()
        ok_r1 = Result(Ok, '', nagiosplugin.Metric('met1', 0))
        ok_r2 = Result(Ok, '', nagiosplugin.Metric('met1', 0))
        results.add(ok_r1)
        results.add(ok_r2)
        summary = AuditSummary()
        sum_ok = summary.ok(results)
        self.assertEqual(sum_ok, '0 vulnerabilities found !')

    def test_problem_unknown(self):
        from nagiosplugin.result import Result, Results
        from nagiosplugin.state import Critical, Unknown
        from checkpkgaudit.checkpkgaudit import AuditSummary
        hint = 'masterdns pkg: jail_attach(masterdns): Operation not permitted'
        results = Results()
        r1 = Result(Critical, '', nagiosplugin.Metric('met1', 1))
        r2 = Result(Unknown, hint, nagiosplugin.Metric('met1', 0))
        results.add(r1)
        results.add(r2)
        summary = AuditSummary()
        sum_unknown = summary.problem(results)
        self.assertEqual(sum_unknown, hint)

    def test_problem_crit(self):
        from nagiosplugin.result import Result, Results
        from nagiosplugin.state import Critical
        from checkpkgaudit.checkpkgaudit import AuditSummary
        message = "found 2 vulnerable(s) pkg(s) in : ns1, ns2"
        results = Results()
        r1 = Result(Critical, '', nagiosplugin.Metric('ns1', 1))
        r2 = Result(Critical, '', nagiosplugin.Metric('ns2', 1))
        results.add(r1)
        results.add(r2)
        summary = AuditSummary()
        sum_crit = summary.problem(results)
        self.assertEqual(sum_crit, message)
