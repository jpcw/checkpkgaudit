.. contents::

Introduction
============

Check FreeBSD pkg audit Nagios|Icinga|shinken|etc plugin.

usage
-------

This check runs pkg audit over your host and its runnung jails

sample outputs :

+ Ok
 ::
  
 CHECKPKGAUDIT OK - 0 vulnerabilities found ! | 'centaure.treshautdebit.com'=0;;@1:;0 http=0;;@1:;0 masterdns=0;;@1:;0 ns0=0;;@1:;0 ns1=0;;@1:;0 ns2=0;;@1:;0 smtp=0;;@1:;0


+ Critical
 
 ::

   CHECKPKGAUDIT CRITICAL - found 2 vulnerable(s) pkg(s) in : ns2, ns3 | 'centaure.treshautdebit.com'=0;;@1:;0 http=0;;@1:;0 masterdns=0;;@1:;0 ns0=0;;@1:;0 ns1=0;;@1:;0 ns2=1;;@1:;0 ns3=1;;@1:;0 smtp=0;;@1:;0

 Notice that summary show the total amount problems and concerned host and jails :
 found *2* vulnerable(s) pkg(s) in : *ns2, ns3* 
 
 but performance data is detailled by host|jail



.. image:: https://pypip.in/license/<PYPI_PKG_NAME>/badge.svg
    :target: https://pypi.python.org/pypi/<PYPI_PKG_NAME>/
        :alt: License

.. image:: https://pypip.in/egg/<PYPI_PKG_NAME>/badge.svg
    :target: https://pypi.python.org/pypi/<PYPI_PKG_NAME>/
        :alt: Egg Status

.. image:: https://pypip.in/status/<PYPI_PKG_NAME>/badge.svg
    :target: https://pypi.python.org/pypi/<PYPI_PKG_NAME>/
        :alt: Development Status

.. image:: https://pypip.in/implementation/<PYPI_PKG_NAME>/badge.svg
    :target: https://pypi.python.org/pypi/<PYPI_PKG_NAME>/
        :alt: Supported Python implementations

.. image:: https://pypip.in/py_versions/<PYPI_PKG_NAME>/badge.svg
    :target: https://pypi.python.org/pypi/<PYPI_PKG_NAME>/
        :alt: Supported Python versions
        
+ version 
  
  .. image:: https://pypip.in/version/<PYPI_PKG_NAME>/badge.svg
      :target: https://pypi.python.org/pypi/<PYPI_PKG_NAME>/
          :alt: Latest Version

+ tested on Travis |travisstatus|_

  .. |travisstatus| image:: https://api.travis-ci.org/jpcw/checkpkgaudit.svg?branch=master
  .. _travisstatus:  http://travis-ci.org/jpcw/checkpkgaudit

+ coverage tracked on coveralls.io |coveralls|_.

  .. |coveralls| image:: https://coveralls.io/repos/jpcw/checkpkgaudit/badge.png?branch=master
  .. _coveralls: https://coveralls.io/r/jpcw/checkpkgaudit

  .. image:: https://www.codacy.com/project/badge/2c6988a6b9664d7f8af4651e50f63b17 
      :target: https://www.codacy.com/public/jpcamguilhem/checkpkgaudit
          :alt: codacy

Install
-------

easy_install | pip within or not a virtualenv::
    
    easy_install | pip install  check_pkgaudit

checkpkgaudit is located at /usr/local/bin/check_pkgaudit


Nagios|icinga like configuration
-----------------------------------

check_pkgaudit could be called localy or remotely via check_by_ssh or NRPE.

here a sample definition to check remotely by ssh 

Command definition ::
    
