#!/usr/bin/env python
# -*- coding: utf-8 -*-

"""Check FreeBSD pkg audit plugin.
"""

import argparse
import logging
import platform
import subprocess

import nagiosplugin

__docformat__ = 'restructuredtext en'

_log = logging.getLogger('nagiosplugin')


def _popen(cmd):  # pragma: no cover
    """Try catched subprocess.popen."""
    try:
        proc = subprocess.Popen(cmd,
                                stdin=subprocess.PIPE,
                                stdout=subprocess.PIPE,
                                stderr=subprocess.PIPE)
        stdout, stderr = proc.communicate()
        return stdout, stderr

    except OSError as e:
        message = "%s" % e
        raise nagiosplugin.CheckError(message)


def _get_jails():
    """Provides running jails."""
    jailargs = []
    jls = subprocess.check_output('jls')
    jails = jls.splitlines()[1:]
    if jails:
        jailargs = list()
        for jail in jails:
            host_idx = 1 if len(jail.split()) == 3 else 2
            if not jail.split()[host_idx].startswith('hastd:'):
                jailargs.append({'jid': jail.split()[0],
                                 'hostname': jail.split()[host_idx]})
    return jailargs


class CheckPkgAudit(nagiosplugin.Resource):
    """Check FreeBSD pkg audit plugin."""

    hostname = platform.node()

    def pkg_audit(self, jail=None):
        """Run pkg audit.

           We choose here to raise UNKNOWN status if we encoutered a host|jail
           which in pkg audit -F has not been runned.
        """
        self.audit_cmd = 'pkg audit'
        if jail is not None:
            self.audit_cmd = 'pkg -j %s audit' % jail
            self.hostname = jail

        _log.debug('querying system with "%s" command', self.audit_cmd)

        stdout, stderr = _popen(self.audit_cmd.split())

        if stderr:
            message = stderr.splitlines()[-1]

            if message.startswith('pkg: vulnxml file'):
                # message = "Try running 'pkg audit -F' first"
                message = stderr.split('.')[-1]
            message = "%s %s" % (self.hostname, message)
            _log.info(message)
            raise nagiosplugin.CheckError(message)

        else:
            stdout = stdout.splitlines()[-1]
            problems = int(stdout.split()[0])

            return problems

    def probe(self):
        """Runs pkg audit over host and running jails."""

        yield nagiosplugin.Metric(self.hostname, self.pkg_audit(),
                                  min=0, context="pkg_audit")
        # yield running jails
        jails = _get_jails()
        if jails:
            for jail in jails:
                yield nagiosplugin.Metric(jail['hostname'],
                                          self.pkg_audit(jail['jid']),
                                          min=0, context="pkg_audit")


class AuditSummary(nagiosplugin.Summary):
    """Status line conveying pkg audit informations.

    We specialize the `ok` method to present all figures (hostname and jails)
    in one handy tagline.

    In case of UKNOWN raised by "pkg audit -F first":
    the single-load text from the context works well.

    In case of problems : we sum pkg problems and list each concerned host.
    """

    def ok(self, results):
        """Summarize OK(s)."""
        return '0 vulnerabilities found !'

    def problem(self, results):
        """Summarize UNKNOWN(s) or CRITICAL(s)."""

        if results.most_significant_state.code == 3:
            return results.first_significant.hint

        else:
            problems = sum(result.metric.value for result
                           in results.most_significant)
            hosts = ', '.join(sorted((result.metric.name for result
                                      in results.most_significant)))
            return 'found %d vulnerable(s) pkg(s) in : %s' % (problems, hosts)


def parse_args():  # pragma: no cover
    """Arguments parser."""
    argp = argparse.ArgumentParser(description=__doc__)
    argp.add_argument('-v', '--verbose', action='count', default=0,
                      help='increase output verbosity (use up to 3 times)')

    return argp.parse_args()


@nagiosplugin.guarded
def main():  # pragma: no cover
    """Runs check.

    Critical argument is volontary hardcoded here, one pkg vulnerability
    is enough to have a problem, isn't it ?

    Debug me with: check.main(verbose=args.verbose, timeout=0)
    default timeout (10s) is inherited from nagiosplugin.
    """

    args = parse_args()
    check = nagiosplugin.Check(CheckPkgAudit(),
                               nagiosplugin.ScalarContext('pkg_audit', None,
                                                          '@1:'),
                               AuditSummary())
    check.main(verbose=args.verbose)

if __name__ == '__main__':  # pragma: no cover
    main()

# vim:set et sts=4 ts=4 tw=80:
