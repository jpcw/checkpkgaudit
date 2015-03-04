#!/usr/bin/env python
# -*- coding: utf-8 -*-

"""Check FreeBSD pkg audit plugin.
"""

__docformat__ = 'restructuredtext en'

import argparse
import logging
import platform
import subprocess

import nagiosplugin


_log = logging.getLogger('nagiosplugin')
hostname = platform.node()


class CheckPkgAudit(nagiosplugin.Resource):
    """Check FreeBSD pkg audit plugin."""

    def pkg_audit(self, jail=None):
        """Run pkg audit.

           We choose here to raise UNKNOWN status if we encoutered a host|jail
           which in pkg audit -F has not been runned.
        """
        self.audit_cmd = 'pkg audit'
        if jail is not None:
            self.audit_cmd = 'pkg -j %s audit' % jail
            hostname = jail

        _log.debug('querying system with "%s" command', self.audit_cmd)  # pragma: no cover

        try:
            proc = subprocess.Popen(self.audit_cmd.split(),
                                    stdin=subprocess.PIPE,
                                    stdout=subprocess.PIPE,
                                    stderr=subprocess.PIPE)
            stdout, stderr = proc.communicate()

            if stderr:
                message = stderr.splitlines()[-1]

                if message.startswith('pkg: vulnxml file'):
                    # message = "Try running 'pkg audit -F' first"
                    message = stderr.split('.')[-1]
                message = "%s %s" % (hostname, message)
                _log.info(message)  # pragma: no cover
                raise nagiosplugin.CheckError(message)

            else:
                stdout = stdout.splitlines()[-1]
                problems = int(stdout.split()[0])

                return problems

        except OSError, e:
            message = "%s" % e
            raise nagiosplugin.CheckError(message)

    def probe(self):
        """Run pkg audit for host and running jails."""

        yield nagiosplugin.Metric(hostname, self.pkg_audit(), min=0,
                                  context="pkg_audit")

        # yield running jails
        jls = subprocess.check_output('jls')
        jails = jls.splitlines()[1:]
        if jails:
            jailnames = [jail.split()[2] for jail in jails]
            for jailname in jailnames:
                yield nagiosplugin.Metric(jailname, self.pkg_audit(jailname),
                                          min=0, context="pkg_audit")


class AuditSummary(nagiosplugin.Summary):
    """Status line conveying pkg audit informations.

    We specialize the `ok` method to present all figures (hostname and jails)
    in one handy tagline.

    In case of UKNOWN raised by "pkg audit -F first":
    the single-load text from the context works well.

    In case of problems : we sum pks problems and list each conercened host.
    """

    def ok(self, results):
        """Summarize OK(s)."""

        return '0 vulnerabilities found !'

    def problem(self, results):
        """Summarize UNKNOWN or CRITICALS."""

        if results.most_significant_state.code == 3:
            return results.first_significant.hint

        else:
            problems = sum(result.metric.value for result
                           in results.most_significant)
            hosts = ', '.join(sorted((result.metric.name for result
                                      in results.most_significant)))
            return 'found %d vulnerable(s) pkg(s) in : %s ' % (problems, hosts)


def parse_args():
    """Arguments parser."""
    argp = argparse.ArgumentParser(description=__doc__)
    argp.add_argument('-v', '--verbose', action='count', default=0,
                      help='increase output verbosity (use up to 3 times)')

    return argp.parse_args()


@nagiosplugin.guarded
def main():
    """Run check.

    critical argument is volontary hardcoded here, one pkg vulnerability
    is enough to have a problem, isn't it ?
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
