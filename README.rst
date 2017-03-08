
==========================================================
Check FreeBSD pkg audit Nagios|Icinga|shinken|etc plugin.
==========================================================

.. image:: https://img.shields.io/pypi/l/checkpkgaudit.svg
    :target: https://pypi.python.org/pypi/checkpkgaudit/

.. image:: https://img.shields.io/pypi/implementation/checkpkgaudit.svg
    :target: https://pypi.python.org/pypi/checkpkgaudit/

.. image:: https://img.shields.io/pypi/pyversions/checkpkgaudit.svg
    :target: https://pypi.python.org/pypi/checkpkgaudit/

.. image:: https://img.shields.io/pypi/v/checkpkgaudit.svg
      :target: https://pypi.python.org/pypi/checkpkgaudit/

.. image:: https://img.shields.io/pypi/status/checkpkgaudit.svg
    :target: https://pypi.python.org/pypi/checkpkgaudit/

.. image:: https://img.shields.io/coveralls/jpcw/checkpkgaudit.svg
      :target: https://coveralls.io/r/jpcw/checkpkgaudit

.. image:: https://api.travis-ci.org/jpcw/checkpkgaudit.svg?branch=master
      :target: http://travis-ci.org/jpcw/checkpkgaudit

+ Source: https://github.com/jpcw/checkpkgaudit

+ Bugtracker: https://github.com/jpcw/checkpkgaudit/issues

.. contents::

usage
-------

This check runs pkg audit over your host and its running jails

sample outputs :

+ Ok
    
    ::
      
      CHECKPKGAUDIT OK - 0 vulnerabilities found ! | 'host.domain.tld'=0;;@1:;0 http=0;;@1:;0 masterdns=0;;@1:;0 ns0=0;;@1:;0 ns1=0;;@1:;0 ns2=0;;@1:;0 smtp=0;;@1:;0
    

+ Critical
    
    Critical state is reached with first vulnerable pkg. No warning, no configurable threasold, why waiting 2 or more vulnerabilities ?
 
    We are talking about security vulnerabilities !
    
    Of course, the plugin sum all the vulnerabilities and details each host|jail concerned

    
    ::
      
      CHECKPKGAUDIT CRITICAL - found 2 vulnerable(s) pkg(s) in : ns2, ns3 | 'host.domain.tld'=0;;@1:;0 http=0;;@1:;0 masterdns=0;;@1:;0 ns0=0;;@1:;0 ns1=0;;@1:;0 ns2=1;;@1:;0 ns3=1;;@1:;0 smtp=0;;@1:;0
    
    Notice that summary returns the total amount problems :
    
    found **2** vulnerable(s) pkg(s) in : **ns2, ns3** but performance data is detailled by host|jail

+ Unknown
    
    if an error occured during pkg audit, the plugin raises a check error, which returns an UNKNOWN state.
    
    typically UNKNOWN causes
    
        + *pkg audit -F* has not been runned on host or a jail
        
        ::
          
          CHECKPKGAUDIT UNKNOWN - jailname  Try running 'pkg audit -F' first | 'host.domain.tld'=0;;@1:;0 http=0;;@1:;0 masterdns=0;;@1:;0 ns0=0;;@1:;0 ns1=0;;@1:;0 ns2=0;;@1:;0 smtp=0;;@1:;0
        
        + *pkg -j jailname audit* runned as a non sudoer user
        
        ::
          
          CHECKPKGAUDIT UNKNOWN - jailname pkg: jail_attach(jailname): Operation not permitted | 'host.domain.tld'=0;;@1:;0
        
        If you have running jails, sudo is your friend to run this plugin with an unprivileged user. A sample config here ::
          
          icinga ALL = NOPASSWD: /usr/local/bin/check_pkgaudit
          

Install
------------

**checkpkgaudit** can be installed via 
either **easy_install** or **pip** .

Within or not a virtualenv:

.. code-block:: console    

    easy_install checkpkgaudit 
    # or
    pip install checkpkgaudit

**check_pkgaudit** is located at /usr/local/bin/check_pkgaudit

.. warning:: SSL certificate error

    If you encountered an ssl certificate error with easy_install,
    you probably need to install the Root certificate bundle 
    from the Mozilla Project:

.. code-block:: console
  
  pkg install -y ca_root_nss
  ln -s /usr/local/share/certs/ca-root-nss.crt /etc/ssl/cert.pem


Nagios|icinga like configuration
-----------------------------------

**check_pkgaudit** could be called localy or remotely 
via **check_by_ssh** or **NRPE**.

**check_by_ssh**

here a sample definition to check remotely by ssh 

Command definition ::
    
    define command{
        command_name    check_ssh_pkgaudit
        command_line    $USER1$/check_by_ssh -H $HOSTADDRESS$ -i /var/spool/icinga/.ssh/id_rsa -C "sudo /usr/local/bin/check_pkgaudit"
    }

the service itself ::
    
    define service{
        use                     my-service
        host_name               hostname
        service_description     pkg audit
        check_command           check_ssh_pkgaudit!
    }
    
icinga2 command ::
    
	object CheckCommand "pkgaudit" {
        import "plugin-check-command"
        import "ipv4-or-ipv6"
        command = [ PluginDir + "/check_by_ssh" ]
        arguments = {
            "-H" = "$address$"
            "-i" = "$ssh_id$"
            "-p" = "$ssh_port$"
            "-C" = "$ssh_command$"
    	    }
        vars.address = "$check_address$"
        vars.ssh_id = "/var/spool/icinga/.ssh/id_rsa"
        vars.ssh_port = "$vars.ssh_port$"
        vars.ssh_command = "sudo /usr/local/bin/check_pkgaudit"
	}

icinga2 service ::
	
	apply Service "pkgaudit" {
  	    check_command = "pkgaudit"
  	    assign where host.name == "hostname"
	}
    

**NRPE**

add this line to /usr/local/etc/nrpe.cfg ::
     
    ...
    command[check_pkgaudit]=/usr/local/bin/check_pkgaudit
    ...

nagios command definition ::
    
    define command{
        command_name    check_nrpe_pkgaudit
        command_line    $USER1$/check_nrpe -H $HOSTADDRESS$ -c check_pkgaudit
    }

the service itself ::
    
    define service{
        use                     my-service
        host_name               hostname
        service_description     pkg audit
        check_command           check_nrpe_pkgaudit
    }   

testing
---------

.. code-block:: shell

    python bootstrap-buildout.py --setuptools-version=33.1.1 --buildout-version=2.5.2
    bin/buildout -N
    bin/test

