#!/usr/bin/env python
###############################################################################
### COPYRIGHT NOTICE FOLLOWS.  DO NOT REMOVE
###############################################################################
### Copyright (c) 2012 - 2017, SQLEXEC LLC
###
### This program is bound by the following licenses:
###    GNU GENERAL PUBLIC LICENSE Version 3, 29 June 2007
###    MIT licensing privileges also conveyed on top of GNU V3.
###
### Permission to use, copy, modify, and distribute this software and its
### documentation for any purpose, without fee, and without a written agreement
### is hereby granted, provided that the above copyright notice and this paragraph
### and the following two paragraphs appear in all copies.
###
### IN NO EVENT SHALL SQLEXEC LLC BE LIABLE TO ANY PARTY FOR DIRECT, INDIRECT,
### SPECIAL, INCIDENTAL, OR CONSEQUENTIAL DAMAGES, INCLUDING LOST PROFITS,
### ARISING OUT OF THE USE OF THIS SOFTWARE AND ITS DOCUMENTATION, EVEN IF
### SQLEXEC LLC HAS BEEN ADVISED OF THE POSSIBILITY OF SUCH DAMAGE.
###
### SQLEXEC LLC SPECIFICALLY DISCLAIMS ANY WARRANTIES, INCLUDING, BUT NOT
### LIMITED TO, THE IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A
### PARTICULAR PURPOSE. THE SOFTWARE PROVIDED HEREUNDER IS ON AN "AS IS" BASIS,
### AND SQLEXEC LLC HAS NO OBLIGATIONS TO PROVIDE MAINTENANCE, SUPPORT, UPDATES,
### ENHANCEMENTS, OR MODIFICATIONS.
###
#######################################G########################################
# Original Author: Michael Vitale, michael@sqlexec.com
#
# Description: pg_alert.py is a PG monitoring script that sends email alerts based on 
#              monitored elements in a log file, host metrics, or db queries.
#
# Assumptions and Restrictions:
#   1. linux distros only, no windows
#   2. python 2.7.x only
#   3. Tested with python 2.7.3 and PostgreSQL 9.4.10
#   4. psycopg must be installed (apt-get install python-psycopg2)
#   5. psutil must be installed (apt-get install python-psutil)
#   6. PG log file prefix must start with timestamp.
#   7. grep filter is valid in configuation file, no checking
#   8. user,password,dbname in .pgpass
#   9. Provides filtering on sqlstate if specified in log_line_prefix and pg_alert.conf file.
#      example: log_line_prefix = '%m %u@%d[%p: %i ] %r [%a]   %e tx:%x : '
#  10. only get one line, the line with ERROR on it, and not get subsequent lines that might be related.
#  11. PG log file must be defined as a day type log file, postgresql-Wednesday.log, postgresql-2016-1122.log, postgresql-2016-11-22.log
#      It will not work with hour, minute, or second specifiers, since it is based on grepping a pg log file persistent for one day.
#  12. sysstat, lvm2 packages must be installed so iostat, lvdisplay commands are available.
#  13. pip install sh to use sh import module, which is not used at the present time
#  14. multiple instances on same host not supported.
#
# Input:
#    * config file (-c --configfile), required input specifying configuration file for pg_alert
#
#    The following command line parameters override configuration specifications:
#    * time in minutes (-m --minutes), specifies how long to run the tail
#    * db name (-d --dbname), specified database name
#    * db user (-u --dbuser), specified db user
#    * dbhost  (-s --dbhost), specifies machine host name
#    * verbose (-v --verbose), specifies logging verbosity
#
# example call:
# /var/lib/postgresql/scripts/pg_alert.py -m 1439 -c /var/lib/postgresql/scripts/pg_alert.conf
#
# Cron Job Info:
#    start the cron at midnight and run to 23:59
#    00 00 * * * /var/lib/postgresql/scripts/pg_alert.py -m 1439 -c /var/lib/postgresql/scripts/pg_alert.conf
#    00 00 * * * python /var/lib/postgresql/scripts/pg_alert.pyc -m 1439 -c /var/lib/postgresql/scripts/pg_alert.conf
#
#    start cron at 8am and run for 12 hours to 8pm: 
#    00 08 * * * /var/lib/postgresql/scripts/pg_alert.py -m 720 -c /var/lib/postgresql/scripts/pg_alert.conf
#
#    View cron job output: view /var/log/cron
#
# NOTES:
#   1. email status can be viewed here: /var/log/exim4/mainlog
#   2. You may need to source the environment variables file in the crontab to get this program to work.
#          #!/bin/bash
#          source /home/user/.bash_profile
#      OR create a bash script and invoke it from there:
#          export PATH=/usr/lib64/qt-3.3/bin:/usr/local/bin:/bin:/usr/bin:/usr/local/sbin:/usr/sbin:/sbin
#          cd /localhost/home/postgres/pgalert
#          ./pg_alert.py  -d -c /localhost/home/postgres/pgalert -l /localhost/home/postgres/pgalert
#          exit 0
#   3. Compile script:
#      >>> import py_compile;py_compile.compile('pg_alert.py')
#      Then invoke it with python interpreter:
#      python pg_alert.pyc
#      Then run like this:
#      python /var/lib/postgresql/scripts/pg_alert.pyc -m 1 -c /var/lib/postgresql/scripts/pg_alert.conf
#
#   4. Create python source distribution package for pg_alert: Assumes setup.py is already created for pg_alert
#      python setup.py sdist
#
#   5. For some executables like ssmtp, you might need to modify user path (add to .bashrc:
#      export PATH=/usr/sbin:$PATH
#
# MONITORING:
#      ps -ef | grep 'pg_alert\|timeout'
#      tail -f /pgarchive/alerts/alerts-history-$(date +"%Y-%m%d").log
#
# TODOs:
#   1. Allow more flexibility in log file format for day names and date formats
#   2. 
#
# main loop:
#    self.bypass = False
#    if not a line or too many messages requiring a pause:
#        checkotherstuff() calls checkconnections()
#    else
#        call alertvalidated(msg)
#             calls sqlstatebypass(msg)
#             calls evaluatelog()
#                   calls lastcheck() for application names
#
# Modifications History:
# Date          Programmer        Description of Change
# ==========    ==========        =====================
# 2012-06-22    Michael Vitale	  Original Coding. version 1.0
# 2016-11-20    Michael Vitale    Major rewrite. version 2.0
#                                 Parse output of tail|grep instead of parsing PG log file directly
#                                 Use psycopg2 instead of PyGreSQL DB client driver.
# 2016-12-16    Michael Vitale    Added sqlstate checking logic to bypass certain sqlstate logs
# 2016-12-19    Michael Vitale    Added wait lock detection
# 2016-12-20    Michael Vitale    Added linux metrics detection
# 2016-12-22    Michael Vitale    Added slave support
# 2016-12-25    Michael Vitale    Added application and query filtering support
# 2016-12-30    Michael Vitale    Replaced hard-coded PG log filename with dynamic dateformat string replacement
# 2017-01-06    Michael Vitale    Bug fixes. Allow pg_alert log directory to be different than PG log directory 
# 2017-01-07    Michael Vitale    Multi-version support: 9.4, 9.6
# 2017-01-11    Michael Vitale    More bug fixes.
# 2017-01-21    Michael Vitale    More bug fixes. Added sytem check support: windows, packages, versions.
# 2017-01-28    Michael Vitale    More bug fixes. Added ssmtp, smtp support for email options.
# 2017-02-01    Michael Vitale    V 2.1: Enhancements. Changed connection logic: program does not abort if it cannot
#                                 connect to the db. db checks are just disabled for this session.
#                                 New logic uses pids instead of sockets for avoiding duplicate instances.
################################################################################################################
import string, sys, os, time, datetime, exceptions, socket, commands, argparse
import random, math, signal, platform, glob, stat, imp
# import sh
import ConfigParser, smtplib, subprocess
from subprocess import *
# from subprocess import Popen, PIPE
from optparse import OptionParser
from email.MIMEMultipart import MIMEMultipart
from email.MIMEText import MIMEText
# psycopg2 and psutil imported directly in function where needed since we test for it using imp to avoid exception 

OK  = 0
ERR = 1
NOTFOUND = -1
INTERRUPT = -2
NOPROGLOCK = -3


########################
def get_lock(processname):
    get_lock._lock_socket = socket.socket(socket.AF_UNIX, socket.SOCK_DGRAM)
    # get_lock._lock_socket = socket.socket(socket.AF_INET,socket.SOCK_STREAM)
    get_lock._lock_socket.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    try:
        get_lock._lock_socket.bind('\0' + processname)
        sock.bind(server_address)
        p.printit("socket: %s" % sock.getsockname())
    except socket.error, msg:
        # p.printit('Lock exists (%s) %s. Program is already running. Exiting...' % (p.processname, sock.getsockname()))
        p.printit('Lock exists (%s) Error=%s.  Program is already running. Exiting...' % (p.processname, msg))
        return NOPROGLOCK
    return OK

class pgmon:
    def __init__(self):
        self.version       = "pg_alert (V 2.1 Feb. 12, 2017)"
        self.system         = platform.system()
        self.python_version = platform.python_version()
        self.description   = "%s is a PostgreSQL alerting tool" % self.version
        self.options       = None
        self.args          = 0
        self.filedatefmt   = datetime.datetime.now().strftime("%Y-%m%d")    
        self.mail_method   = ""
        self.mailbin       = 'mail'

        # SMTP STUFF
        self.smtp_server   = ""
        self.smtp_account  = ""
        self.smtp_port     = -1
        self.smtp_password = ""
        self.sms           = ""

        self.configfile    = ""
        self.logfile       = ""
        self.logalert      = ""
        self.loghistory    = ""
        self.sendemail     = False
        self.ignore_autovacdaemon = True
        self.ignore_uservac = True
        self.minutes       = 0 
        self.keeplogdays   = -1
        self.seconds       = 0
        self.startd        = datetime.datetime.now()
        self.start         = self.startd.strftime("%Y-%m-%d %H:%M:%S")
        self.start_date    = self.startd.strftime("%Y-%m-%d")
        self.endd          = self.startd + datetime.timedelta(0,1)
	self.end_date      = self.endd.strftime("%Y-%m-%d")    
        self.end           = self.endd.strftime("%Y-%m-%d %H:%M:%S")    
        self.time_start    = time.time()
        self.refreshed     = time.time()
        self.alert         = None
        self.processname   = "pg_alert"
        self.to            = ""
        self.subject       = 'pg_alert'
        self.from_         = ""
        self.conn          = None
        self.dbname        = ""
	self.dbuser        = ""
        self.dbhost        = ""
        self.pgport        = ""
        self.clusterid     = ""
        self.grepfilter    = "FATAL:"
        self.sqlstate      = ""
        self.sqlclass      = ""
        self.sqlstates     = []
        self.sqlclasses    = []
        self.sqlstateprefix  = ""
        self.sqlstatepostfix = ""
        self.check_sqlstate  = False
        self.data_directory  = ""
        self.pglog_directory = ""
        self.alert_directory = ""
        self.pg_tmp          = ""
        self.log_line_prefix = ""
        self.max_alerts      = 100
        self.verbose         = False
        self.monitorlag      = False
        self.alert_stmt_timeout = False
        self.lockwait        = 1
        self.tempbytesthreshold = 999999999999
        self.server_version  = ''
	self.server_version_num = -1
	self.log_filename    = ''
        
        self.slaves          = ''
        self.ignoreusers     = ''
        self.ignoreapps      = ''
        self.ignorequeries   = ''
        
        self.lockfilter      = ''

        # stat variables
        self.alertcnt        = 0
        self.cpus            = 0        
        self.loadmax         = 0
        self.load1           = 0
        self.load5           = 0
        self.load15          = 0
        self.maxconn         = 0
        self.totalconn       = 0
        self.activeconn      = 0
        
        self.pgsql_tmp_threshold  = -1
        self.loadthreshold        = 100
        self.dirthreshold         = 99
        self.idletransthreshold   = 9999
        self.querytransthreshold  = 9999
        self.checkinterval        = 300
        
        self.lastconntotalert     = None
        self.lastconnactivealert  = None        
        self.lastconnidlealert    = None
        self.lastconnqueryalert   = None        
        self.lastloadalert        = None
        self.lastslavealert       = None
        
        self.suspended            = False
        self.bypass               = False
        self.connected            = False
        
        
        # db stats ordered array: datname,numbackends,conflicts,temp_bytes,deadlocks
        self.dbstats = []

    ########################
    def get_pidlock(self):
        pid = str(os.getpid())
        self.pidfile = "/tmp/%s.pid" % self.processname

        if os.path.isfile(self.pidfile):
            self.printit('Pid file exists (%s).  Program is already running. Exiting...' % (self.pidfile))            
            return NOPROGLOCK
        
        try:
            file(self.pidfile, 'w').write(pid)
        except Exception as e:
            self.printit('Unable to obtain pid lock (%s)' % (e))            
            return NOPROGLOCK
        return OK

    ##########################
    def setupOptionParser(self):
        parser = OptionParser(self.description)
        parser.add_option("-c","--configfile",dest="configfile", help="pg_alert config file", default="",metavar="CONFIGFILE")
        parser.add_option("-m","--minutes",dest="minutes", help="duration of tailing in minutes", default=0,metavar="MINUTES")
        parser.add_option("-d","--dbname",dest="dbname", help="database name", default="",metavar="DBNAME")
        parser.add_option("-u","--dbuser",dest="dbuser", help="database user", default="",metavar="DBUSER")
        parser.add_option("-s","--dbhost",dest="dbhost", help="database host", default="",metavar="DBHOST")
        parser.add_option("-v","--verbose",dest="verbose",help="optional parameter indicating whether verbose messaging is turned on. Default is false",metavar="verbose", default=False, action="store_true")
        return parser

    ##########################
    def getlogfilename(self):
        # parse log_filename to get the right PG log file to open.
        # self.log_filename
        # postgresql-%Y-%m%d.log --> postgresql-2016-1230.log
        # postgresql-%a.log      --> postgresql-Fri.log  postgresql-Thu.log  postgresql-Wed.log
        # hard-coded expectation of log file at the present time: postgresql-YYYY-MMDD.log
        dayname=datetime.datetime.now().strftime("%a")
        year = datetime.datetime.now().strftime("%Y")
        month = datetime.datetime.now().strftime("%m")
        day = datetime.datetime.now().strftime("%d")
        filename = self.log_filename
        filename = filename.replace("%a", dayname)
        filename = filename.replace("%Y", year)
        filename = filename.replace("%m", month)
        filename = filename.replace("%d", day)
        return OK, filename        

    ##########################
    def testcmd (self, cmd):
        command = "which %s" % cmd
        try: 
            subprocess.check_output(command,shell=True)
            return OK
        except: 
            self.printit("ERROR: executable (%s) not found. Make sure %s is installed and in your path." % (cmd, cmd))
            return ERR

    ##########################
    def prunelogs(self):
        now = datetime.datetime.now().strftime("%Y-%m-%d %H:%M:%S")        
        if self.keeplogdays > -1:
            # delete all old logs
            if self.verbose:
                self.printit("%s: Pruning old pg_alert log files...\n" % (now))
            for filename in os.listdir(self.alert_directory):
                curr_file = os.path.join(self.alert_directory, filename)
                file_modified = datetime.datetime.fromtimestamp(os.path.getmtime(curr_file))
                dayage = (time.time() - os.stat(curr_file)[stat.ST_MTIME]) / 60 / 60 /24
                dayage = int(round(dayage))
                if filename.startswith("alerts-") and (filename.endswith(".log") or filename.endswith(".gz")):
                    if curr_file == self.logalert or curr_file == self.loghistory:
                        # self.printit("bypassing current log file=%s" % filename)
                        pass
                    else:
                        # found candidates to purge
                        if dayage > self.keeplogdays:
                            self.printit("deleting file older than %d days: %s" % (dayage, curr_file))
                            os.remove(curr_file)
                        else:
                            pass
                            # self.printit("%d days old. Bypassing purge candidate=%s" % (dayage, curr_file))
                else:
                    # self.printit("bypassing non purge candidate=%s" % curr_file)
                    pass
        else:
            # do nothing for now, add logic later for specifying exactness of logs to prune
            self.printit("%s: No log file pruning specified.\n" % (now))
    
        return OK

    ##########################
    def checksystem(self):

        if self.system == 'Windows':
            self.printit("Unsupported platform, Windows.")
            return ERR
            
        try:
            imp.find_module('psycopg2')
            found = True
            global psycopg2
            import psycopg2

        except ImportError:
            found = False        
        if not found:
            self.printit("psycopg2 package is required.")
            return ERR
        
        try:
            imp.find_module('psutil')
            found = True
            global psutil
            import psutil            
        except ImportError:
            found = False        
        if not found:
            self.printit("python-psutil package is required.")
            return ERR
        
        # we only support python 2.7 flavors      
        if self.python_version[0:3] <> '2.7':
            self.printit("Unsupported python version, %s.  Only 2.7.x are supported at the present time." % (self.python_version))
            return ERR
        return OK    

    ##########################
    def getdbinfo(self):
           
        # get some PG stuff
        cur = self.conn.cursor()
        sql = "select name, setting from pg_settings where name in ('data_directory','log_directory','log_filename','log_line_prefix','server_version','server_version_num' ) order by name"
	try:
	    cur.execute(sql)
	except psycopg2.Error, e:
            cur.close()
	    self.printit("SQL Error: unable to retrieve PG Glucs: %s" % (e))
	    self.cleanup(1)                

        glucs = cur.fetchall()
        if not glucs:
            cur.close()
	    self.printit("SQL Error: no glucs found.")
	    self.cleanup(1)                        

        for agluc in glucs:
            if agluc[0] == 'data_directory':
                self.data_directory = agluc[1]
            elif agluc[0] == 'log_directory':
                if self.pglog_directory == '':
                    self.pglog_directory = agluc[1]
                    if self.pglog_directory == 'pg_log':
                        # need to preappend data dir
                        self.pglog_directory = self.data_directory + '/' + self.pglog_directory
            elif agluc[0] == 'log_line_prefix':
                self.log_line_prefix = agluc[1]
            elif agluc[0] == 'server_version':
                self.server_version = agluc[1]
            elif agluc[0] == 'server_version_num':
                self.server_version_num = int(agluc[1])                
            elif agluc[0] == 'log_filename':
                self.log_filename = agluc[1]                                
            else:
                cur.close
                self.printit("Program Error: Unexpected gluc: %s" % agluc[0])
                self.cleanup(1)        
                
        self.pg_tmp = self.data_directory + '/base/pgsql_tmp'

        return OK

    ##########################
    def initandvalidate(self):

        rc = self.checksystem()
        if rc <> OK:
            sys.exit(rc)

        # register signal handler to catch interrupts so we can end gracefully.
        # signal.signal(signal.SIGUSR1, self.catch)
        # signal.siginterrupt(signal.SIGUSR1, False)
        signal.signal(signal.SIGINT, self.catch)
        signal.siginterrupt(signal.SIGINT, False)        

        optionParser    = self.setupOptionParser()
        (self.options,self.args)  = optionParser.parse_args() 

        self.configfile = self.options.configfile
        if self.configfile == "":
            self.printit("config file not specified.")
            sys.exit(ERR)

        # validate and get stuff from config file not specified on command line
        if not os.path.exists(self.configfile):
            self.printit("pg_alert config file does not exist: %s" % self.configfile)
            sys.exit(ERR)

        if self.options.dbname <> "":
            self.dbname     = self.options.dbname
        if self.options.dbuser <> "":
            self.dbuser     = self.options.dbuser
        if self.options.dbhost <> "":
            self.dbhost     = self.options.dbhost
                
        config = ConfigParser.SafeConfigParser({'sqlstate':'', 'sqlclass':'', 'lockwait':'', 'checkinterval':'', \
                 'loadthreshold':'', 'dirthreshold':'', 'idletransthreshold':'', 'querytransthreshold':'', 'pgsql_tmp_threshold':'', 'lockfilter':'', \
                 'pglog_directory':'', 'alert_directory':'', 'ignore_autovacdaemon':'True', 'ignore_uservac':'True', 'tempbytesthreshold':'', 'slaves':'', \
                 'monitorlag':'False', 'alert_stmt_timeout':'False', 'ignoreapps':'', 'ignoreusers':'','ignorequeries':'', 'suspended':'False', \
                 'mail_method':'', 'smtp_server':'', 'smtp_account':'', 'smtp_port':'', 'smtp_password':'', 'sms':''})        
        
        config.read(self.configfile)
        
        self.clusterid  = config.get("required", "clusterid",1)
        if self.clusterid == "":
            self.printit("Invalid config input (CLUSTERID). Expected a short descriptor field like PROD.")
            sys.exit(ERR)
        self.to         = config.get("required", "to",1)            
        if self.to == "":
            self.printit("Invalid config input (TO). Expected at least one email address.")
            sys.exit(ERR)
                
        self.sendemail  = config.getboolean('required', 'emailalerts')
        self.alert_directory = config.get("required", "alertlog_directory",1)
        if not os.path.isdir(self.alert_directory):
	    self.printit("Alert log directory is invalid directory: %s" % self.alert_directory)
            sys.exit(ERR)

        self.pglog_directory = config.get("optional", "pglog_directory",1)
        if self.pglog_directory <> '':
            if not os.path.isdir(self.pglog_directory):
	        self.printit("PG log directory specified is invalid. Please remove to use postgresql.conf setting: %s" % self.pglog_directory)
                sys.exit(ERR)

        self.mail_method   = config.get('optional', 'mail_method').lower()
        
        self.smtp_server   = config.get('optional', 'smtp_server')
        self.smtp_account  = config.get('optional', 'smtp_account')
        self.smtp_port     = config.get('optional', 'smtp_port')
        if self.smtp_port.isdigit():
            self.smtp_port = int(self.smtp_port)
        else:
            if self.mail_method == 'smtp':
                self.printit("SMTP_PORT must be a number: %s" % self.smtp_port)
                sys.exit(ERR)
        self.smtp_password = config.get('optional', 'smtp_password')
        self.sms           = config.get('optional', 'sms')
        
        if self.sendemail and self.mail_method == "":
            self.printit("Email alerts turned on, but no mail method selected.")
            sys.exit(ERR)        
        elif self.mail_method <> 'mail' and self.mail_method <> 'smtp'  and self.mail_method <> 'ssmtp':
            self.printit("Email method not valid.  Choices are MAIL, SMTP, or SSMPT: %s" % self.mail_method)
            sys.exit(ERR)                

        if self.mail_method == 'ssmtp':
            rc = self.testcmd('ssmtp')
            if rc <> OK:
                sys.exit(ERR)
        elif self.mail_method == 'mail':
            # see if we can use bsd version of mailx to avoid syntax problems with heirloom version
            rc = self.testcmd('/usr/bin/bsd-mailx')
            if rc == OK:
                self.mailbin ='/usr/bin/bsd-mailx'
        
        
        self.ignore_autovacdaemon = config.getboolean('optional', 'ignore_autovacdaemon')
        self.ignore_uservac       = config.getboolean('optional', 'ignore_uservac')
        self.monitorlag = config.getboolean('optional', 'monitorlag')
        self.verbose    = config.getboolean('required', 'verbose')
        self.alert_stmt_timeout = config.getboolean('optional', 'alert_stmt_timeout')
        self.suspended   = config.getboolean('optional', 'suspended')
        
        self.slaves     = config.get('optional', 'slaves')
        self.slaves      = self.slaves.strip()
        self.ignoreusers = config.get('optional', 'ignoreusers')
        self.ignoreusers = self.ignoreusers.strip()
        self.ignoreapps = config.get('optional', 'ignoreapps')
        self.ingoreapps = self.ignoreapps.strip()
        self.ignorequeries = config.get('optional', 'ignorequeries')
        self.ignorequeries = self.ignorequeries.strip()
        
                
        # we only override verbose if true is passed via command line
        if not self.verbose:
            self.verbose = self.options.verbose

        if self.dbname == '':
            self.dbname     = config.get("required", "dbname",1)
        if self.dbuser == '':            
            self.dbuser     = config.get("required", "dbuser",1)
        if self.dbhost == '':                        
            self.dbhost     = config.get("required", "dbhost",1)
        if self.pgport == '':                        
            self.pgport     = config.get("optional", "pgport",1)
        if self.pgport == "":
            self.pgport = "5432"

        # open db connection: assumes password in .pgpass
        connstr = "dbname=%s user=%s host=%s port=%s" % (self.dbname, self.dbuser, self.dbhost, self.pgport)
        try:
            self.conn = psycopg2.connect(connstr)
            self.connected = True
            self.conn.autocommit = True
        except psycopg2.Error as e:
            now = datetime.datetime.now().strftime("%Y-%m-%d %H:%M:%S")                    
            self.printit("Database Connection Error: %s" % (e))
            self.printit("using connection string: %s" % connstr)
            
            # v2.1 enhancement: do not abort if we cannot connect, just disable db checking stuff
            self.printit("%s: NOTICE. DB session checks are disabled for this instance of pg_alert." % now)
            self.connected = False
            # self.cleanup(1)          

        if  self.connected:
            rc = self.getdbinfo()
            if rc <> OK:
                self.cleanup(1)
        interim = config.get("required", "minutes",1)
        if interim == "":
            self.minutes = 0
        elif interim.isdigit():
            self.minutes = int(interim)
        else:
            self.printit("Invalid minutes config input(%s). Expected a positive number indicating duration minutes." % interim)
            self.cleanup(1)                
    
        keeplogdays = config.get("optional", "keeplogdays",1)
        if keeplogdays == "":
            self.keeplogdays = -1
        elif keeplogdays.isdigit():
            self.keeplogdays = int(keeplogdays)
        else:
            self.printit("Invalid keeplogdays config input(%s). Expected a non-negative number indicating the number of days to keep pg_alert log files." % keeplogdays)
            self.cleanup(1)                    
    
        self.lockfilter = config.get("optional", "lockfilter",1)
    
        value = config.get("optional", "max_alerts",1)                
        if len(value) > 0 and value.isdigit():
            self.max_alerts = int(value)

        value = config.get("optional", "lockwait",1)                
        # must be > 0 seconds
        if len(value) > 0 and value.isdigit():
            if int(value) > 0:
                self.lockwait = int(value)            

        value = config.get("optional", "tempbytesthreshold",1)                
        # must be > 100K bytes
        if len(value) > 0 and value.isdigit():
            if int(value) > 100000:
                self.tempbytesthreshold = int(value)            

        value = config.get("optional", "checkinterval",1)                
        # must be at least 30 seconds
        if len(value) > 0 and value.isdigit():
            if int(value) > 29:
                self.checkinterval = int(value)

        value = config.get("optional", "loadthreshold",1)                
        # must be at least 10%
        if len(value) > 0 and value.isdigit():
            if int(value) > 9:
                self.loadthreshold = int(value)
                
        value = config.get("optional", "dirthreshold",1)                
        # must be < 100%
        if len(value) > 0 and value.isdigit():
            if int(value) < 100:
                self.dirthreshold = int(value)                
                
        value = config.get("optional", "idletransthreshold",1)                
        # must be > 2 seconds
        if len(value) > 0 and value.isdigit():
            if int(value) >1:
                self.idletransthreshold = int(value)                                
                
        value = config.get("optional", "querytransthreshold",1)                
        # must be > 1 seconds
        if len(value) > 0 and value.isdigit():
            if int(value) > 1:
                self.querytransthreshold = int(value)                                          
    
        value = config.get("optional", "pgsql_tmp_threshold",1)                
        if len(value) > 0 and value.isdigit():
            if int(value) > 0:
                self.pgsql_tmp_threshold = int(value)
    
        self.from_      = config.get("required", "from",1)                
        self.grepfilter = config.get("optional", "grep",1)
        if self.grepfilter == '':
            pass

        # put states and classes in arrays
        self.sqlstate   = config.get("optional", "sqlstate",1)
        if self.sqlstate.strip() <> '':
            self.sqlstates  = self.sqlstate.split(",")
            for index, item in enumerate(self.sqlstates):
                self.sqlstates[index] = item.strip()
        
        self.sqlclass   = config.get("optional", "sqlclass",1)
        if self.sqlclass.strip() <> '':
            self.sqlclasses = self.sqlclass.split(",")
            for index, item in enumerate(self.sqlclasses):
                self.sqlclasses[index] = item.strip()
                if len(self.sqlclasses[index].split(' ')) > 1:
                    # user may have accidentally put the keyword class there or something else, so regard as error
                    self.printit("sqlclass values must be numbers separated by commas.  Current value: %s" % item)
                    self.cleanup(1)                
                elif len(self.sqlclasses[index]) <> 2:
                    # assume sqlstates not valid for this session
                    #self.printit("sqlclass values must be 2 digit numbers separated by commas.  Current value: %s" % item)
                    #self.cleanup(1)                
                    pass
           
        # get command line options that override configuration file values
        if self.options.minutes <> 0:
            if self.options.minutes.isdigit():
                self.minutes = int(self.options.minutes)
                if self.minutes == 0:
                    self.printit("Minutes must be greater than 0.")
                    self.cleanup(1)                
            else:        
                self.printit("Invalid minutes input(%s). Expected a positive number indicating duration minutes." % self.options.minutes)
                self.cleanup(1)                

        if self.minutes < 1:
            self.printit("Invalid minutes input(%s). Expected a positive number indicating duration minutes." % self.minutes)
            self.cleanup(1)                

        if not os.path.isdir(self.pglog_directory):
            self.printit("PG log directory is invalid directory: %s" % self.pglog_directory)
            self.cleanup(1)                
        if self.dbname == "":
            self.printit("Database Name must be specified (-d <dbname>)")
            self.cleanup(1)                
        elif self.dbhost == "":
            self.printit("Database Host must be specified (-h <database host>)")
            self.cleanup(1)                
        elif self.dbuser == "":
            self.printit("Database User must be specified (-u <database user>)")
            self.cleanup(1)                

        if self.from_ == "":
            self.from_ = "PostgreSQL Administrator <%s@%s>" % (self.dbuser, self.dbhost)

        # parse log_filename to get the right PG log file to open.
        rc, log_filename = self.getlogfilename()
        if rc <> OK:
            self.cleanup(1)
        self.logfile = "%s/%s" % (self.pglog_directory, log_filename)
        if not os.path.exists(self.logfile):
            self.printit("PG log file does not exist: %s" % self.logfile)
            self.cleanup(1)    
        self.logalert     = "%s/alerts-%s.log" % (self.alert_directory,self.filedatefmt)
        self.loghistory   = "%s/alerts-history-%s.log" % (self.alert_directory,self.filedatefmt)

        rc = self.get_pidlock()
        if rc <> OK:
            self.cleanup(rc)                
            
        # remove alert file if exists and clear out history file as well
        cmd = "echo '' > %s" % (self.logalert)
        rc,out,errs = self.executecmd(cmd,False)
        if rc <> 0:
            self.cleanup(1)                

        now = datetime.datetime.now().strftime("%Y-%m-%d %H:%M:%S")                    
        msg = "%s: %s" % (now,self.version)
        print msg
        cmd = "echo '%s' > %s" % (msg, self.loghistory)
        rc,out,errs = self.executecmd(cmd,False)  
        if rc <> 0:
            self.cleanup(1)                

        try:
            self.alert = open(self.logalert, 'r')
        except IOError as e:
           self.printit("Unable to open alert file(%s). I/O error({0}): {1}".format(e.errno, e.strerror) % self.logalert)
           self.cleanup(1)                

        except: 
           self.printit("Unable to open alert file(%s). Unexpected error:", (self.logalert, sys.exc_info()[0]))
           self.cleanup(1)                
        
        # convert minutes to seconds        
        self.seconds = self.minutes * 60
        # reject minutes if it would overlap into next day
        self.endd = self.startd + datetime.timedelta(0,self.seconds)
        self.end_date = self.endd.strftime("%Y-%m-%d")    
        self.end = self.endd.strftime("%Y-%m-%d %H:%M:%S")    
        if self.end_date <> self.start_date:
            self.printit("Minutes cannot overlap days. Enter a lower minutes value or start at an earlier time of day.")
            self.printit("minutes=%d start=%s  end=%s" % (self.minutes, self.start, self.end))
            self.cleanup(1)                
	
	# test with this string that doesnt work because previous %<code> has no other characters associated with it.  Consider invalid in these cases.
	# self.log_line_prefix = '%m %u@%d[%p:%i] [%l-1] %r %a tx=%x,ss=%e: '
	# self.log_line_prefix = '%m %u@%d[%p: %i ] %r [%a]   %e tx:%x : '
	sep = "***"
	seplen = len(sep)
	key = sep + 'e'
	# self.printit("DEBUG: before replacement:'%s'" % self.log_line_prefix)
        prefix = self.log_line_prefix.replace("%",sep)
        # self.printit("DEBUG: after  replacement:'%s'" % prefix)
	index = prefix.find(key)
	if index > -1:
	    index = prefix.find(key)
            after = prefix[index+4:]
            # self.printit("DEBUG: after  ='%s'" % after)
            before = prefix[0:index]
            # self.printit("DEBUG: before ='%s'" % before)
            index = before.rfind(sep)
            before = before[index+seplen+1:]
            index = after.find(sep)
            if index > -1:
                # after = after[index+seplen+1:]
                after = after[0:index]
            self.sqlstateprefix  = before
            self.sqlstatepostfix = after
            # self.printit("DEBUG: prefix  ='%s'" % self.sqlstateprefix)
            # self.printit("DEBUG: postfix ='%s'" % self.sqlstatepostfix)

        if (len(self.sqlstates) <> 0 or len(self.sqlclasses) <> 0) and (self.sqlstateprefix <> '' and self.sqlstatepostfix <> ''):
            # must be valid sqlstate checking
            self.check_sqlstate  = True                
        else:
            self.check_sqlstate  = False            

        # final check, make sure we do not have more than 1 find for the prefix
        if self.check_sqlstate:
            matches = self.log_line_prefix.count(self.sqlstateprefix)
            if matches > 1:
                self.printit("Multiple prefixes found for sqlstate. SQLstates/SQLClasses are disabled until a better log_line_prefix is used.")
                self.check_sqlstate  = False            

        # finally purge old alert logs if specified
        self.prunelogs()
        
        return OK


    ##########################
    def initrefresh(self):
        # The only thing we can override on the command line parm is verbose.
        # We never refresh db connection parameters.  Connections last for the duration of the program.
        self.printit("Refreshing configuration values...")

        # re-initiate reading of config file
        config = ConfigParser.SafeConfigParser({'sqlstate':'', 'sqlclass':'', 'lockwait':'', 'checkinterval':'', \
                 'loadthreshold':'', 'dirthreshold':'', 'idletransthreshold':'', 'querytransthreshold':'', 'pgsql_tmp_threshold':'', 'lockfilter':'', \
                 'pglog_directory':'', 'alert_directory':'', 'ignore_autovacdaemon':'True', 'ignore_uservac':'True', 'tempbytesthreshold':'', 'slaves':'', \
                 'monitorlag':'False', 'alert_stmt_timeout':'False', 'ignoreapps':'', 'ignoreusers':'','ignorequeries':'', 'suspended':'False', \
                 'mail_method':'', 'smtp_server':'', 'smtp_account':'', 'smtp_port':'', 'smtp_password':'', 'sms':''})                         
        config.read(self.configfile)

        # do not override verbose if provided by command line
        if not self.verbose:
            self.verbose = self.options.verbose

        self.ignore_autovacdaemon = config.getboolean('optional', 'ignore_autovacdaemon')
        self.ignore_uservac       = config.getboolean('optional', 'ignore_uservac')
        self.monitorlag = config.getboolean('optional', 'monitorlag')
        self.verbose    = config.getboolean('required', 'verbose')
        self.alert_stmt_timeout = config.getboolean('optional', 'alert_stmt_timeout')
        self.lockfilter = config.get("optional", "lockfilter",1)
    
        self.suspended     = config.getboolean('optional', 'suspended')
        self.slaves        = config.get('optional', 'slaves')
        self.slaves        = self.slaves.strip()
        self.ignoreusers   = config.get('optional', 'ignoreusers')
        self.ignoreusers   = self.ignoreusers.strip()
        self.ignoreapps    = config.get('optional', 'ignoreapps')
        self.ignoreapps    = self.ignoreapps.strip()
        self.ignorequeries = config.get('optional', 'ignorequeries')
        self.ignorequeries = self.ignorequeries.strip()
    
        value = config.get("optional", "max_alerts",1)                
        if len(value) > 0 and value.isdigit():
            self.max_alerts = int(value)

        value = config.get("optional", "lockwait",1)                
        # must be > 0 seconds
        if len(value) > 0 and value.isdigit():
            if int(value) > 0:
                self.lockwait = int(value)            

        value = config.get("optional", "tempbytesthreshold",1)                
        # must be > 100K bytes
        if len(value) > 0 and value.isdigit():
            if int(value) > 100000:
                self.tempbytesthreshold = int(value)            

        value = config.get("optional", "checkinterval",1)                
        # must be at least 30 seconds
        if len(value) > 0 and value.isdigit():
            if int(value) > 29:
                self.checkinterval = int(value)

        value = config.get("optional", "loadthreshold",1)                
        # must be at least 10%
        if len(value) > 0 and value.isdigit():
            if int(value) > 9:
                self.loadthreshold = int(value)
                
        value = config.get("optional", "dirthreshold",1)                
        # must be < 100%
        if len(value) > 0 and value.isdigit():
            if int(value) < 100:
                self.dirthreshold = int(value)                
                
        value = config.get("optional", "idletransthreshold",1)                
        # must be > 2 seconds
        if len(value) > 0 and value.isdigit():
            if int(value) >1:
                self.idletransthreshold = int(value)                                
                
        value = config.get("optional", "querytransthreshold",1)                
        # must be > 1 seconds
        if len(value) > 0 and value.isdigit():
            if int(value) > 1:
                self.querytransthreshold = int(value)                                          
    
        value = config.get("optional", "pgsql_tmp_threshold",1)                
        if len(value) > 0 and value.isdigit():
            if int(value) > 0:
                self.pgsql_tmp_threshold = int(value)
    
        self.sqlstate      = ""
        self.sqlclass      = ""
        self.sqlstates     = []
        self.sqlclasses    = []
        
        # put states and classes in arrays
        self.sqlstate   = config.get("optional", "sqlstate",1)
        if self.sqlstate.strip() <> '':
            self.sqlstates  = self.sqlstate.split(",")
            for index, item in enumerate(self.sqlstates):
                self.sqlstates[index] = item.strip()
        
        self.sqlclass   = config.get("optional", "sqlclass",1)
        if self.sqlclass.strip() <> '':
            self.sqlclasses = self.sqlclass.split(",")
            for index, item in enumerate(self.sqlclasses):
                self.sqlclasses[index] = item.strip()
                if len(self.sqlclasses[index].split(' ')) > 1:
                    # user may have accidentally put the keyword class there or something else, so regard as error
                    self.printit("sqlclass values must be numbers separated by commas.  Current value: %s" % item)
                    self.cleanup(1)                
                elif len(self.sqlclasses[index]) <> 2:
                    # assume sqlstates not valid for this session
                    #self.printit("sqlclass values must be 2 digit numbers separated by commas.  Current value: %s" % item)
                    #self.cleanup(1)                
                    pass
           
        if (len(self.sqlstates) <> 0 or len(self.sqlclasses) <> 0) and (self.sqlstateprefix <> '' and self.sqlstatepostfix <> ''):
            # must be valid sqlstate checking
            self.check_sqlstate  = True                
        else:
            self.check_sqlstate  = False            
        
        self.showparms();
        
        return OK

    ########################
    def printit(self,message):
        if self.loghistory == '':
            print message
            return OK
        print message
        cmd = 'echo "%s" >> %s' % (message, self.loghistory)
        rc = subprocess.call(cmd, shell=True)  
        if rc <> 0:
            msg = "Unable to print message (%s). subprocess.call error return code = %d" % (message,rc)
            print msg
            sysmsg = "cat %s > %s\n" % (msg,self.loghistory)
            os.system(sysmgs)
            self.cleanup(1)                
        else:
            return OK
                
    
    ########################
    def executecmd(self,cmd,results):
        if results:
            p = Popen(cmd, shell=True, stdout=PIPE)
            out, err = p.communicate()
            if err is not None:            
                self.printit("%s: popen.communicate error %s" % (err))
                return ERR,"",err            
            return OK, out, ""    
        else:
            rc = subprocess.call(cmd, shell=True,bufsize=0)  
            if rc <> 0:
                self.printit("%s: subprocess.call error rc=%d cmd=%s" % (self.start,rc, cmd))
                return ERR,"",""
            return OK,"",""

    ########################
    def sendSMSmsg(self, message):
        smtp_server  = self.smtp_server
        smtp_account = self.smtp_account
        smtp_port    = self.smtp_port
        smtp_password= self.smtp_password
        fromaddr     = self.smtp_account
        toaddr       = self.sms
 
        msg_subject = 'pg_alert (%s)' % self.clusterid
        msg_text = "%s  %s" % (msg_subject, message)
 
        headers = ['From: {}'.format(fromaddr),
                   'To: {}'.format(toaddr),
                   'MIME-Version: 1.0',
                   'Content-Type: text/html']               
 
        msg_body = '\r\n'.join(headers) + '\r\n\r\n' + msg_text
 
        server = smtplib.SMTP(smtp_server, smtp_port)
        server.ehlo()
        server.starttls()
        server.ehlo()
        server.login(fromaddr, smtp_password)
        server.sendmail(fromaddr, toaddr, msg_body)
        server.quit()

        return OK
    

    ########################
    def sendSMTPmsg(self, message):
        
        smtp_server  = self.smtp_server
        smtp_account = self.smtp_account
        smtp_port    = self.smtp_port
        smtp_password= self.smtp_password
        fromaddr     = self.smtp_account
        toaddr       = self.to
    
        msg = MIMEMultipart()
        msg['From'] = fromaddr
        msg['To'] = toaddr
        msg['Subject'] = 'pg_alert (%s)' % self.clusterid
        
        body = message
        msg.attach(MIMEText(body, 'plain'))
        step = ''
        text = ''
        try:
            step = "smtplib.SMTP"
            server = smtplib.SMTP(smtp_server, smtp_port)
            if self.verbose:
                server.set_debuglevel(1)    
            step = "starttls"            
            server.starttls()
            step = "login"            
            server.login(fromaddr, smtp_password)
            text = msg.as_string()
            step = "sendmail"            
            server.sendmail(fromaddr, toaddr, text)
            server.quit()

            if self.verbose:
                self.printit("Sent SMTP email from: %s to: %s. subject: %s Text = %s" % (fromaddr,toaddr,msg['Subject'],text))
    
            if self.sms <> '':
                rc = self.sendSMSmsg(message)
                return rc
        
        except smtplib.SMTPServerDisconnected, e:
            # exceptiontype = "SMTPServerDisconnected Error: %d %s" % (e.smtp_code, e.smtp_error)
            exceptiontype = "SMTPServerDisconnected Error: %s" % (e)
        except smtplib.SMTPSenderRefused, e:
            exceptiontype = "SMTPSenderRefused Error: %s" % (e)
        except smtplib.SMTPRecipientsRefused, e:
            exceptiontype = "SMTPRecipientsRefused Error: %s" % (e)
        except smtplib.SMTPDataError, e:
            exceptiontype = "SMTPDataError Error: %s" % (e)
        except smtplib.SMTPHeloError, e:
            exceptiontype = "SMTPHeloError Error: %s" % (e)
        except smtplib.SMTPAuthenticationError, e:
            exceptiontype = "SMTPAuthenticationError Error: %s" % (e)
        except smtplib.SMTPConnectError, e:
            exceptiontype = "SMTPConnectError Error: %s" % (e)
        except smtplib.SMTPResponseException, e:
            exceptiontype = "SMTPResponseException smtplib.Error: %s" % (e)
        except smtplib.SMTPException, e:
            exceptiontype = "SMTPexception smtplib.Error: %s" % (e)
        except:
            exceptiontype = "GENERAL SMTP Exception"

        if exceptiontype <> '':
            amsg = "%s Error: %s" % (step, exceptiontype)
            self.printit("SMTP Send Error: %s" % amsg)
            self.printit("SMTP Error Details: TO:%s\nFROM:%s]nSUBJECT:%s\nTEXT:%s" % (fromaddr, toaddr, msg['Subject'], text))
            return ERR
        else:
            amsg = "%s Error: %s" % (step, 'UNKNOWN EXCEPTION')
            self.printit("SMTP Send Error: %s" % amsg)
            self.printit("SMTP Error Details: TO:%s\nFROM:%s]nSUBJECT:%s\nTEXT:%s" % (fromaddr, toaddr, msg['Subject'], text))
            return ERR        

    ########################
    def sendalert(self,msg):
        if not self.sendemail:
            return OK
    
        if self.mail_method == 'mail':
            # echo "This is the message body" | mail -s "This is the subject" michael.vitale@assurant.com -a "From: xxx@xxx.commail.tld"
            subject = self.subject + ' (' + self.clusterid + ')'
            cmd = 'echo "%s" | %s -s "%s" %s -a "From: %s"' % (msg, self.mailbin, subject, self.to, self.from_)
            rc,out,errs = self.executecmd(cmd,False)
            if rc <> 0:
                return ERR;
        elif self.mail_method == 'ssmtp':                
            # ssmtp protocol
            # echo -e 'To: michael@sqlexec.com\nFrom: xxx@xxx.com\nSubject: my subject\n\nThis is my text message' | ssmtp -vvv michael@sqlexec.com
            subject = 'pg_alert (%s)' % self.clusterid
            if self.verbose:
                cmd = "echo -e 'To: %s\nFrom: %s\nSubject: %s\n\n%s' | ssmtp -vvv %s" % (self.to, self.from_, subject, msg, self.to)
            else:
                cmd = "echo -e 'To: %s\nFrom: %s\nSubject: %s\n\n%s' | ssmtp %s" % (self.to, self.from_, subject, msg, self.to)
            # self.printit("SSMTP Alert Command --> %s" % cmd)
            rc,out,errs = self.executecmd(cmd,False)
            if rc <> 0:
                return ERR;            
        else:
            # assume SMTP
            rc = self.sendSMTPmsg(msg)
            if rc <> 0:
                return ERR;

        self.alertcnt = self.alertcnt + 1
        now = datetime.datetime.now().strftime("%Y-%m-%d %H:%M:%S")        
        self.printit("%s: ***ALERT(%d) SENT***: %s\n" % (now, self.alertcnt, msg))    
        return OK

    ########################
    def checkdbstats(self):
        # compare dbstats with current ones
        cur = self.conn.cursor()
        sql = "select datname, numbackends, conflicts, temp_bytes, deadlocks from pg_stat_database order by datname"
	try:
	    cur.execute(sql)
	except psycopg2.Error, e:
            cur.close()
	    self.printit("SQL Error: unable to retrieve db stats: %s" % (e))
	    return ERR

        rows = cur.fetchall()
        if not rows:
            cur.close()
	    self.printit("PROGRAM Error: no db stats found.")
	    return ERR

        now = datetime.datetime.now().strftime("%Y-%m-%d %H:%M:%S")                    
        if len(self.dbstats) == 0:
            # populate and exit
            for arow in rows:
                self.dbstats.append([arow[0], arow[1], arow[2], arow[3], arow[4]])
            cur.close()
            self.printit("%s: dbstats initialization. Found %d databases for dbstats." % (now,len(self.dbstats)))
            return OK

        for arow in rows:
            datname     = arow[0]
            numbackends = arow[1]
            conflicts   = arow[2]
            temp_bytes  = arow[3]
            deadlocks   = arow[4]
            for stat in self.dbstats:
                cdatname     = stat[0]
                cnumbackends = stat[1]
                cconflicts   = stat[2]
                ctemp_bytes  = stat[3]
                cdeadlocks   = stat[4]

                # now compare and issue alerts accordingly.
                if cdatname == datname:            
                    if conflicts  <> cconflicts:
                        msg = "%s: db stat alert: %d conflicts detected in %s." % (now, conflicts - cconflicts, datname)
                        rc = self.sendalert(msg)
                    if temp_bytes <> ctemp_bytes:
                        if (ctemp_bytes - temp_bytes) > self.tempbytesthreshold:
                            msg = "%s: db stat alert: %d conflicts detected in %s." % (now, temp_bytes - ctemp_bytes, datname)
                            rc = self.sendalert(msg)                
                    if deadlocks  <> cdeadlocks:
                        msg = "%s: db stat alert: %d deadlocks detected in %s." % (now, deadlocks - cdeadlocks, datname)
                        rc = self.sendalert(msg)                

        # repopulate dbstats list
        self.dbstats = []
        for arow in rows:
            self.dbstats.append([arow[0], arow[1], arow[2], arow[3], arow[4]])
        
        cur.close()
        return OK

    ########################
    def isvalidlog(self, msg):
        if len(msg) > 4:
            value = (msg[0:4])
            if value.isdigit():
                year = datetime.datetime.today().year
                logyear = int(value)
                if logyear == year:
                    return True
        if self.verbose:
            now = datetime.datetime.now().strftime("%Y-%m-%d %H:%M:%S")        
            self.bypass = True
            self.printit("%s: Bypassing invalid log line: ***%s***\n" % (now,msg))
        return False

    ########################
    def getlockwaitseconds(self, searchstring, msg):
        # acquired ShareLock on transaction\| acquired ExclusiveLock 
        # 2016-12-18 20:37:03.079 CST blackjack_prod@blackjack_prod[29561:SELECT waiting] [2912-1] 10.80.129.28(44672) 
        # B::Backend::Job::AppraiserStaitisticsCollector tx=0,ss=00000: LOG:  process 29561 acquired ShareLock on transaction 3219951272 after 1569.367 ms
        pos = msg.find(searchstring)
        if pos > 0:
            s1  = msg[pos+len(searchstring):]            
            pos = s1.find('after ')
            if pos < 0:
                self.printit("could not find time waited(1). Alert will not be triggered. %s % searchstring")                    
                return NOTFOUND
            s1  = s1[pos+len('after '):]
            s1 = s1.strip()
            pos = s1.find(' ms')
            if pos < 0:
                self.printit("could not find time waited(2). Alert will not be triggered. %s % searchstring")                    
                return NOTFOUND
            s1 = s1[0:pos]
            s1 = s1.strip()
            pos = s1.find('.')
            if pos < 0:
                self.printit("could not find time waited(3). Alert will not be triggered. %s % searchstring")                    
                return NOTFOUND            
            s1 = s1[0:pos]
            s1 = s1.strip()                      
            if s1.isdigit():
                milliseconds = int(s1)            
            else:
                self.printit("could not find time waited(4). Alert will not be triggered. %s % searchstring")                    
                return NOTFOUND
            if milliseconds < 1000:
                return OK
            seconds = milliseconds / 1000
            return seconds
        else:
            now = datetime.datetime.now().strftime("%Y-%m-%d %H:%M:%S")                    
            self.printit("%s: could not find time waited(5). Alert will not be triggered. %s" % (now, searchstring))
            return NOTFOUND
    
        return NOTFOUND

    ########################
    def getSqlstate(self, msg):
        # This is a bad prefix since the prefix occurs multiple times with the second one being the correct one.
        # '%m %u@%d[%p: %i ] %r [%a] %e tx:%x : '
        pos = msg.find(self.sqlstateprefix)
        if pos < 0:
            if self.verbose:
                now = datetime.datetime.now().strftime("%Y-%m-%d %H:%M:%S")                    
                self.printit("%s: VERBOSE: could not find beginning of sqlstate, *%s*, in msg, %s\n" % (now, self.sqlstateprefix, msg))
            return ""
        s1 = msg[pos+len(self.sqlstateprefix):]            
        # print "DEBUG1: pos=%d prefix=%s s1=%s" % (pos,self.sqlstateprefix, s1)
        pos = s1.find(self.sqlstatepostfix)
        if pos < 0:
            if self.verbose:
                now = datetime.datetime.now().strftime("%Y-%m-%d %H:%M:%S")                    
                self.printit("%s: VERBOSE: could not find end of sqlstate in msg, %s\n" % (now, msg))        
            return ""
        s1 = s1[0:pos]
        # print "DEBUG2: s1=%s" % s1
        s1 = s1.strip()
        # v2.1 enhancement: turn off sqlchecking if log_line_prefix is not setup up correctly resulting in an sqlstate that is not alphanumeric
        if not s1.isalnum():
            self.check_sqlstate = False
            self.printit("%s: Invalid sqlstate found: %s.  SQLSTATE checking is disabled. Fix log_line_prefix so SQLSTATE can be found correctly next time.\n" % (now, s1))        
        if s1 == '00000':
            return s1
        else:
            if self.verbose:
                now = datetime.datetime.now().strftime("%Y-%m-%d %H:%M:%S")                    
                if self.check_sqlstate:
                    self.printit("%s: VERBOSE: found sqlstate(%s) in msg, %s\n" % (now, s1, msg))        
                else:
                    self.printit("%s: VERBOSE: found sqlstate(%s) in msg but sqlstate checking is disabled, %s\n" % (now, s1, msg))        
        return s1

    ########################
    def sqlstatebypass(self,msg):

        sqlstate = self.getSqlstate(msg)
        
        # if sqlstate checking not enabled, cannot bypass
        if not self.check_sqlstate:
            return self.bypass, sqlstate

        # evaluate sqlstate if applicable
        now = datetime.datetime.now().strftime("%Y-%m-%d %H:%M:%S")                    
        
        if self.check_sqlstate and sqlstate == "":
            # nothing more to do here
            return self.bypass, sqlstate

        # sqlstate = 00000, requires further analysis for other reasons to alert on.
        if sqlstate == '00000':
            return self.bypass, sqlstate

        # check if class is found
        for item in self.sqlclasses:
            index = sqlstate.find(item)
            if index == 0:
                # we found a state class match so bypass
                self.printit("%s: Bypassing found filtered sqlclass, %s. msg= %s\n" % (now,item,msg))
                return True, sqlstate
                     
        # match sqlstate with the ones we are filtering out
        for item in self.sqlstates:
            if item == sqlstate:
                self.printit("%s: Bypassing sqlstate, %s. msg= %s\n" % (now,sqlstate,msg))
                return True, sqlstate

        # Handle statement timeouts in evaluatelog
        # sqlstate == '57014'

        # default to whatever bypass was set to before this function call
        return self.bypass, sqlstate

    ########################
    def lastcheck(self, msg, sqlstate):
        
        # check if application name in the error message.
        if len(self.ignoreapps) == 0:
            return self.bypass
        apps= self.ignoreapps.split('*|*')
        appcnt = len(apps)
        if appcnt == 0:
            return self.bypass
        for app in apps:
            index = msg.find(app)
	    if index > -1:
	        # must have already bypassed this application, so bypass it again
	        return True

        # bypass could have already been set so send back what it was before this function started
        return self.bypass


    ########################
    def evaluatelog(self, msg, sqlstate):
        # return true if alert valid, otherwise false
        now = datetime.datetime.now().strftime("%Y-%m-%d %H:%M:%S")                    
        # parse log looking for time waited before sharelock or exclusive lock was obtained
        # send alert if wait time greater than input lock wait time
        if self.grepfilter.find('acquired ShareLock on transaction\|') > 0 and msg.find('acquired ShareLock on transaction') > 0:
            # see if a lockfilter applies to it
            if msg.find(self.lockfilter) > 0:
                # found lock filter so bypass it
                self.bypass = True
                self.printit("%s: Bypassing found lock filter\n" % (now))
                return False

            seconds = self.getlockwaitseconds('acquired ShareLock on transaction',msg)
            if seconds == NOTFOUND:
                # assume textual context so do not alert. Message is logged to alerts-history file.
                return False
            elif seconds >= self.lockwait:
                return True
            else:
                self.bypass = True
                self.printit("%s: Bypassing lock wait seconds (%d) below threshold (%d).\n" % (now, seconds, self.lockwait))
                return False
                
        if self.grepfilter.find('acquired ExclusiveLock on\|') > 0 and msg.find('acquired ExclusiveLock on ') > 0:
            # see if a lockfilter applies to it
            if msg.find(self.lockfilter) > 0:
                # found lock filter so bypass it
                self.bypass = True
                self.printit("%s: Bypassing found lock filter\n")
                return False
        
            seconds = self.getlockwaitseconds('acquired ExclusiveLock on ',msg)
            if seconds >= self.lockwait:
                return True
            else:
                self.bypass = True
                self.printit("%s: Bypassing lock wait seconds (%d) below threshold (%d).\n" % (now, seconds, self.lockwait))
                return False

        if self.grepfilter.find('still waiting for \|') > 0 and msg.find('still waiting for ') > 0:
            # see if a lockfilter applies to it
            if msg.find(self.lockfilter) > 0:
                # found lock filter so bypass it
                self.bypass = True
                self.printit("%s: Bypassing found lock filter\n" % now)
                return False
        
            seconds = self.getlockwaitseconds('still waiting for ',msg)
            if seconds >= self.lockwait:
                return True
            else:
                self.bypass = True
                self.printit("%s: Bypassing lock wait seconds (%d) below threshold (%d).\n" % (now, seconds, self.lockwait))
                return False

        # handle sqlstate = 57014, for statement timeouts. Consider bypassing statement timeouts, but always report user requested ones
        if sqlstate == '57014':
            if self.alert_stmt_timeout:
                if self.verbose:
                    self.printit("%s: VERBOSE: alert on statement timeout is turned on. Sending alert for msg: %s\n" % (now,msg))
                return True
            else:
                if msg.find('ERROR:  canceling statement due to user request') > 0:
                    # report user initiated timeouts
                    return True
                elif msg.find('ERROR:  canceling statement due to statement timeout') > 0:
                    # bypass these since it is system or application context controlled
                    self.bypass = True
                    if self.verbose:
                        self.printit("%s: VERBOSE: bypassing application or system initiated statement timout." % now)
                    return False
                else:
                    # for anything else unforeseen, report it
                    if self.verbose:
                        self.printit("%s: VERBOSE: defaulting action for sqlstate, 57014.  Sending alert for msg: %s\n" % (now,msg))
                    return True

        # before defaulting to alert valid, check if we already bypasses stuff like application names in checkconnections.
        self.bypass = self.lastcheck(msg, sqlstate)
        if self.bypass:
            if self.verbose:
                self.printit("%s: VERBOSE: bypass for msg: %s\n" % (now,msg))            
            return False
        else:
            if self.verbose:        
                self.printit("%s: VERBOSE: general default alert. Sending alert for msg: %s\n" % (now,msg))
            return True


    ########################
    def stillsuspended(self):
    
        # re-initiate reading of config file
        config = ConfigParser.SafeConfigParser({'sqlstate':'', 'sqlclass':'', 'lockwait':'', 'checkinterval':'', \
                 'loadthreshold':'', 'dirthreshold':'', 'idletransthreshold':'', 'querytransthreshold':'', 'pgsql_tmp_threshold':'', 'lockfilter':'',  \
                 'log_directory':'', 'alert_directory':'', 'ignore_autovacdaemon':'True', 'ignore_uservac':'True', 'tempbytesthreshold':'', 'slaves':'', \
                 'monitorlag':'False', 'alert_stmt_timeout':'False', 'ignoreapps':'', 'ignoreusers':'','ignorequeries':'', 'suspended':'False'})        
        config.read(self.configfile)
    
        self.suspended = config.getboolean('optional', 'suspended')
        return self.suspended

    ########################
    def alertvalidated(self,msg):
    
        #check if we are in suspended state and if so wait
        while True:
            if self.stillsuspended():
                now = datetime.datetime.now().strftime("%Y-%m-%d %H:%M:%S")                    
                self.printit("%s: pg_alert in user-initiated suspended state.\n" % (now))
                time.sleep(60)
            else:
                break
    
        # make sure we have a valid log line, must start with date
        if not self.isvalidlog(msg):
            return False

        self.bypass, sqlstate = self.sqlstatebypass(msg)
        if self.bypass:
            return False

        # check for obvious things like deadlocks
        # 2016-12-29 08:02:06.542 CST blackjack_prod@blackjack_prod[10513:UPDATE waiting] [3692-1] 10.80.129.86(46448) B::Backend::Job::AppraiserStatisticsCollector tx=3245985290,ss=00000: LOG:  process 10513 detected deadlock while waiting for ShareLock on transaction 3245985292 after 1000.098 ms
        if msg.find('detected deadlock while waiting for') > 0:
            self.printit("%s: Detected deadlock: %s\n" % (now,msg))
            return True

        alertvalid = self.evaluatelog(msg, sqlstate)
        if alertvalid and not self.bypass:
            return True
        else:
            return False        
            

    ########################
    def linuxload(self):

       # first get number of CPUs:
        cmd = "cat /proc/cpuinfo | grep processor | wc -l"
        rc, cpus, err = self.executecmd(cmd, True)
        if rc <> 0:
            self.printit("Unable to get linux cpu info: %s" % err)
            return ERR, -1, 0.00, 0.00, 0.00

        # now get load averages for 1, 5 and 15 minute intervals
        cmd = "uptime"
        rc, out, err = self.executecmd(cmd, True)
        if rc <> 0:
            self.printit("Unable to get linux load info: %s" % err)        
            return ERR, cpus, 0.00, 0.00, 0.00
        
        # output will look like this -->  12:34:25 up 53 days, 16:18,  6 users,  load average: 1.45, 1.61, 1.67
        #                                 20:21:12 up 55 days, 10 min,  9 users,  load average: 1.27, 1.50, 1.52
        parts  = out.split()
        atime  = parts[0].strip()
        index = 0
        for apart in parts:
            if 'average' in apart:
                load1  = parts[index + 1].strip()
                load1  = load1.replace(',','')
                load5  = parts[index + 2].strip()
                load5  = load5.replace(',','')
                load15 = parts[index + 3].strip()
                break
            index = index + 1            
        
        return OK, int(cpus), float(load1), float(load5), float(load15)

    ########################
    def checkslaves(self):
        if self.slaves == '' or len(self.slaves) == 0:
            return OK
        
        cur = self.conn.cursor()
        sql = "select usename, application_name, client_addr, client_hostname, state, sent_location, write_location, " \
              "flush_location, replay_location, sync_priority, sync_state from pg_stat_replication order by application_name"
	try:
	    cur.execute(sql)
	except psycopg2.Error, e:
            cur.close()
	    self.printit("SQL Error: unable to retrieve slave stats: %s" % (e))
	    return ERR

        timenow = time.time()
        now = datetime.datetime.now().strftime("%Y-%m-%d %H:%M:%S")                    
        rows = cur.fetchall()
        if not rows:
            cur.close()
            msg = "%s: No slaves active. Expected %s" % (now,self.slaves)
            if self.lastslavealert is None or int(timenow - self.lastslavealert) > self.checkinterval:
                self.lastslavealert = time.time()            
  	        self.printit(msg)
	        rc = self.sendalert(msg)
	        return OK

        slaves = self.slaves.split(',')
        slavecnt = len(slaves)

        for aslave in slaves:
            aslave = aslave.strip()
            foundit = False
            for arow in rows:
                usename          = arow[0]
                application_name = arow[1]
                client_addr      = arow[2]
                client_hostname  = arow[3]
                state            = arow[4]
                if state is None:
	            state = ''
                sent_location    = arow[5]
                write_location   = arow[6]
                flush_location   = arow[7]    
                replay_location  = arow[8]
                sync_priority    = arow[9]
                sync_state       = arow[10]
                if sync_state is None:
                    sync_state = ''
                if aslave == client_addr:
                    foundit = True
                    break
            if not foundit:
                if self.lastslavealert is None or int(timenow - self.lastslavealert) > self.checkinterval:
                    self.lastslavealert = time.time()            
                    msg = "%s: Slave (%s) not active." % (now, aslave)
       	            self.printit(msg)
	            rc = self.sendalert(msg)
	    else:
	        if self.verbose:
	            msg = "%s: VERBOSE: state=%s sync_state=%s client_addr=%s application_name=%s sent_location=%s write_location=%s" \
	                  % (now, state, sync_state, client_addr, application_name, sent_location, write_location)
	            self.printit(msg)
	            
	        # check for replication state and lag
                if state <> 'streaming':
                    if self.lastslavealert is None or int(timenow - self.lastslavealert) > self.checkinterval:
                        self.lastslavealert = time.time()                            
                        msg = "%s: %s slave (%s) not streaming (%s)." % (now, sync_state, aslave, state)
                        self.printit(msg)
                        rc = self.sendalert(msg)                    
                elif sent_location <> write_location:
                    if self.monitorlag:
                        if self.lastslavealert is None or int(timenow - self.lastslavealert) > self.checkinterval:
                            self.lastslavealert = time.time()            
                            # minimally ensure sent and write locations are the same, even if flush and replay are not the same
                            msg = "%s: %s slave (%s) is lagging (%s). sent=%s/write=%s." % (now, sync_state, aslave, state, sent_location, write_location)
                            self.printit(msg)
                            rc = self.sendalert(msg)                                    
        cur.close()
        return OK
    
    
    ########################
    def checkconnections(self):
        now = datetime.datetime.now().strftime("%Y-%m-%d %H:%M:%S")    
        # get total connections
	cur = self.conn.cursor()
	sql = "select aa.totalconnections, bb.activeconnections, cc.maxconnections from " \
	      "(select count(*) as totalconnections from pg_stat_activity) aa, " \
	      "(select count(*) as activeconnections from pg_stat_activity where state = 'active') bb, " \
	      "(select setting::int as maxconnections from pg_settings where name = 'max_connections') cc;"
	try:
	    cur.execute(sql)
	except psycopg2.Error, e:
	    self.printit("SQL Error: unable to retrieve total connections: %s" % (e))
	    return ERR
	
	row = cur.fetchone()
        self.totalconn   = row[0]
        self.activeconn  = row[1]
        self.maxconn     = row[2]
        cur.close()

        # check for exceeding threshold for connections compared to max connections allowed
        result = float(self.totalconn) / self.maxconn
        perc   = int(math.floor(result * 100))
        timenow = time.time()
        if perc > 90:
            if self.lastconntotalert is None or int(timenow - self.lastconntotalert) > self.checkinterval:
                msg = "%s: current connections (%d) exceed 90%% threshold." % (now,self.totalconn)
                self.lastconntotalert = time.time()
                self.sendalert(msg)
        
        # compare active connections in light of number of CPUs
        if self.activeconn > self.cpus:
            if self.lastconnactivealert is None or int(timenow - self.lastconnactivealert) > self.checkinterval:
                msg = "%s: active connections (%d) exceeds CPUs (%d)." % (now, self.activeconn, self.cpus)
                self.lastconnactivealert = time.time()
                self.sendalert(msg)        
        
        # check for long running idle in transactions
        cur = self.conn.cursor()
        sql = "select count(*) from pg_stat_activity where state = \'idle in transaction\' and round(EXTRACT(EPOCH FROM (now() - query_start))) > %d" \
              % self.idletransthreshold
	try:
	    cur.execute(sql)
	except psycopg2.Error, e:
	    self.printit("SQL Error: unable to retrieve long idle in transaction count: %s" % (e))
	    return ERR
	
	row = cur.fetchone()
        if  row[0] > 0:
            if self.lastconnidlealert is None or int(timenow - self.lastconnidlealert) > self.checkinterval:        
                msg = "%s: %d idle in transactions longer than %d seconds detected." % (now,row[0], self.idletransthreshold)
                self.lastconnidlealert = time.time()
                self.sendalert(msg)        
        cur.close()

        # check for long running active transactions
        cur = self.conn.cursor()
        s1 = " "  
        s2 = " "
        if self.ignore_autovacdaemon:
            s1 = " and query not ilike 'autovacuum: %' "
        if self.ignore_uservac:
            s2 = " and query not ilike 'vacuum analyze %' and query not ilike 'analyze %' "            

        if len(self.ignoreapps) == 0:
            s3 = " "
        else:            
            apps= self.ignoreapps.split('*|*')
            appcnt = len(apps)            
            s3 = " "
            if appcnt > 0:
                s3 = " and application_name not in ("
                cnt = 0
                for app in apps:
                    cnt = cnt + 1
                    a1 = app.strip()
                    if cnt == 1:
                        s3 = s3 + "'" + a1 + "'"
                    else:
                        s3 = s3 + ", '" + a1 + "'"            
                    if cnt == appcnt:
                        s3 = s3 + ") "

        if len(self.ignorequeries) == 0:
            s4 = " "
        else:            
            queries= self.ignorequeries.split('*|*')
            querycnt = len(queries)            
            s4 = " "
            if querycnt > 0:
                cnt = 0
                s4 = " and ("
                for query in queries:
                    cnt = cnt + 1
                    a1 = query.strip()
                    # escape string quotes
                    a1 = a1.replace("'", "''")
                    if cnt == 1:
                        s4 = s4 + " query <> '" + a1 + "'"
                    else:
                        s4 = s4 + " and query <> '" + a1 + "'"
                    if cnt == querycnt:
                        s4 = s4 + ") "

        if len(self.ignoreusers) == 0:
            s5 = " "
        else:            
            users= self.ignoreusers.split('*|*')
            usercnt = len(users)
            s5 = " "
            if usercnt > 0:
                s5 = " and usename not in ("
                cnt = 0
                for user in users:
                    cnt = cnt + 1
                    a1 = user.strip()
                    if cnt == 1:
                        s5 = s5 + "'" + a1 + "'"
                    else:
                        s5 = s5 + ", '" + a1 + "'"            
                    if cnt == usercnt:
                        s5 = s5 + ") "
                   
        sql = "select pid, datname, usename, state, coalesce(application_name,' ') as application_name, client_addr, round(EXTRACT(EPOCH FROM (now() - query_start))) as seconds, " \
              "substring(query,1,9999) as query from pg_stat_activity where state = 'active' %s %s %s %s %s and " \
              "round(EXTRACT(EPOCH FROM (now() - query_start))) > %d" % (s1,s2,s3,s4,s5,self.querytransthreshold)
        if self.verbose:
            self.printit("%s: VERBOSE: long query check: %s\n" % (now,sql))
	try:
	    cur.execute(sql)
	except psycopg2.Error, e:
	    self.printit("SQL Error: unable to retrieve long active transaction count: %s" % (e))
	    return ERR
	
	rows = cur.fetchall()
	rowcnt = cur.rowcount
	results = ''
        if rows:
            for arow in rows:
                pid              = arow[0]
                datname          = arow[1]
                usename          = arow[2]
                state            = arow[3]
                application_name = arow[4]
                client_addr      = arow[5]
                if len(application_name.strip()) == 0:
                    application_name = 'n/a'
                seconds          = arow[6]
                query            = arow[7]
                rowvalues = "pid=%d db=%s user=%s seconds=%d app=%s client_addr=%s seconds=%d \n\nquery=%s\n\n" % \
                            (pid, datname, usename, seconds, application_name, client_addr, seconds, query)
                results = results + rowvalues
            if self.lastconnqueryalert is None or int(timenow - self.lastconnqueryalert) > self.checkinterval:        
                msg = "%s: %d query transactions longer than %d seconds detected.\n%s" % (now,rowcnt, self.querytransthreshold, results)
                self.lastconnqueryalert = time.time()
                self.sendalert(msg)        
        cur.close()

        return OK
        
        
    ########################
    def checkpgdirs(self):
        # check size of data directory, pg_xlog, and pg temp 
        now = datetime.datetime.now().strftime("%Y-%m-%d %H:%M:%S")                    
        # use df for mount points percentages
        # df -h /pgdata | tail -n1 | awk '{print "Size="$2 ",Used=" $3 ",Avail=" $4 ",Usedpct=" $5}' --> Size=2.4T,Used=1.6T,Avail=815G,Usedpct=67%
        # df /pgdata | tail -n1 | awk '{print "Size="$2 ",Used=" $3 ",Avail=" $4 ",Usedpct=" $5}' --> Size=2541300736,Used=1687344084,Avail=853956652,Usedpct=67%
        # df /pgdata | tail -n1 | awk '{print $5}' --> 67%
        cmd = "df -h " + self.data_directory + " | tail -n1 | awk '{print $5}'"
        rc,data_dir_perc,errs = self.executecmd(cmd, True)
        if rc <> 0:
            return ERR

        res = data_dir_perc.split('%')
        if int(res[0]) > self.dirthreshold:
            msg = "%s: data directory usage threshold (%d%%) exceeded (%d%%)." % (now, self.dirthreshold, int(res[0]))
            self.sendalert(msg)             
        
        # get real path of pg_xlog directory.  If it is not a symlink and not a mount point, the entire mount point for the data directory mount point is returned.
        # otherwise it is the mount point for the symlinked pg_xlog directory
        pg_xlog = os.path.realpath(self.data_directory + "/pg_xlog")
        cmd = "df -h " + pg_xlog + " | tail -n1 | awk '{print $5}'"
        rc,pg_xlog_perc,errs = self.executecmd(cmd, True)
        if rc <> 0:
            return ERR
        
        res = pg_xlog_perc.split('%')
        if int(res[0]) > self.dirthreshold:
            msg = "%s: pg_xlog directory usage threshold (%d%%) exceeded (%d%%)." % (now, self.dirthreshold, int(res[0]))
            self.sendalert(msg)       
        
        # use du for other directories sizes
        # NOTE: pgsql_tmp directory may not exist if never used yet, i.e., new major upgrades, etc.
        if os.path.isdir(self.data_directory + "/base/pgsql_tmp"):
            # du -s  /pgdata/lenderx/base/pgsql_tmp | awk '{print($1)}' --> 1685752
            cmd = "du -s " + self.data_directory + "/base/pgsql_tmp | awk '{print($1)}'"
            rc, pg_temp_bytes, errs = self.executecmd(cmd, True)
            if rc <> 0:
                return ERR
        
            res = pg_temp_bytes.strip()
            tmplen = len(res)
            bytes = int(res)
            
            # alert if threshold reached
            if bytes > self.pgsql_tmp_threshold and self.pgsql_tmp_threshold <> -1:
                threshold="{:,}".format(self.pgsql_tmp_threshold)
                if bytes > 999999999:
                    gbs =  float(bytes)/1024/1024/1024
                    msg = "%s: pgsql_tmp directory size exceeds threshold (%s bytes): %.2f GB" % (now,threshold,gbs)
                    self.sendalert(msg)                   
                elif bytes > 999999:
                    mbs = float(bytes)/1024/1024
                    msg = "%s: pgsql_tmp directory size exceeds threshold (%s bytes): %.2f MB" % (now,threshold,mbs)
                    self.sendalert(msg)                   
                else:
                    msg = "%s: pgsql_tmp directory size exceeds threshold (%s bytes): %d bytes" % (now,threshold,bytes)
                    self.sendalert(msg)          
       
        return OK


    ########################
    def checklinux(self):
        # get linux load
        rc, self.cpus, self.load1, self.load5, self.load15 = self.linuxload()
        if rc <> 0:
            return ERR
                
        loadthreshold = round(.01 * float(self.loadthreshold), 2)
        self.loadmax = float(round(loadthreshold * self.cpus,2))

        if self.load1 > self.loadmax or self.load5 > self.loadmax or self.load15 > self.loadmax:
            if self.lastloadalert is None or int(timenow - self.lastloadalert) > self.checkinterval:
                msg = "%d%% load exceeded (%.2f) exceeded. cpus(%d) load1min(%.2f) load5min(%.2f) load15min(%.2f)" \
                      % (self.loadthreshold, self.loadmax, self.cpus, self.load1, self.load5, self.load15)
                self.lastloadalert = time.time()
                self.sendalert(msg)             
        
        rc = self.checkpgdirs()
        if rc <> 0:
            return ERR        
        
        return OK    

    ########################
    def checkotherstuff(self):

        # only do a refresh every 15 minutes/900 seconds
        timenow = time.time()
        if int(timenow - self.refreshed) > 900:
            rc = self.initrefresh()
            self.refreshed = time.time()
            if rc <> 0:
                return rc;        
        if self.connected:
            rc = self.checkdbstats()
            if rc <> 0:
                return rc;        
            
        rc = self.checklinux()
        if rc <> 0:
            return rc;

        if self.connected:
            rc = self.checkconnections()
            if rc <> 0:
                return rc;        

        if self.connected:
            rc = self.checkslaves()
            if rc <> 0:
                return rc;                    

        if self.verbose:
            now = datetime.datetime.now().strftime("%Y-%m-%d %H:%M:%S")                    
            if self.connected:
                msg = "%s: VERBOSE: cpus(%d)  load1min(%.2f)  Load5min(%.2f)  Load15min(%.2f) loadthreshold(%d%%) loadmax(%.2f) maxconn=%d  totalconn=%d  activeconn=%d\n" \
                      % (now, self.cpus, self.load1, self.load5, self.load15, self.loadthreshold, self.loadmax, self.maxconn, self.totalconn, self.activeconn)
            else:
                msg = "%s: VERBOSE: cpus(%d)  load1min(%.2f)  Load5min(%.2f)  Load15min(%.2f) loadthreshold(%d%%) loadmax(%.2f)  DB info not available.\n" \
                      % (now, self.cpus, self.load1, self.load5, self.load15, self.loadthreshold, self.loadmax)            
            self.printit(msg)        

        return OK

    ########################
    def terminatetail(self):
        now = datetime.datetime.now().strftime("%Y-%m-%d %H:%M:%S")                                
        for proc in psutil.process_iter():
            try:
                pinfo = proc.as_dict(attrs=['pid', 'name'])
                apid  = pinfo['pid']
                name = pinfo['name']
                afile = '/proc/' + str(apid) + '/cmdline'
                if name == 'timeout':
                    try:
                        # /proc/<pid>/cmdline contains complete command without spaces like this:
                        # timeout120tail-f/pglog/lenderx/postgresql-2016-1223.logpostgres@msp0llexp022:/proc/1275
                        if not os.path.exists(afile):
                            # do nothing. Might be another instance trying to start and this tail never started.
                            return OK
                        print "%s: pid=%s  name=%s" % (now, str(apid),name)
                        pidfile = open(afile, 'r')
                        info = str(pidfile.readline())
                        print "%s: pidinfo: " % now, info
                        try:
                            self.printit("%s: Terminating tail pid(%s)." % (now,str(apid)))
                            p = psutil.Process(apid)
                            p.terminate()
                            return OK
                        except Exception as e:
                            self.printit("%s: unable to terminate pid, %s. %s" % (now,str(apid),e))
                            return ERR
                        return OK
                    except Exception as e:
                        self.printit("%s: unable to open pidfile(%s). %s" % (now,afile,e))
                        return ERR
                    return OK    
            except psutil.NoSuchProcess:
                self.printit("%s: Unable to terminate tail pid: no such process." % now)
                return ERR
        self.printit("%s: Tail pid not found. Nothing to terminate." % now)            
        return NOTFOUND

    ########################
    def showparms(self):
        now = datetime.datetime.now().strftime("%Y-%m-%d %H:%M:%S")                    
        msg = '%s: verbose=%s sendmail=%s check_sqlstate=%s max_alerts=%d clusterid=%s  pgport=%s  from_=%s  to=%s  minutes=%d  keeplogdays=%d log_dir=%s alert_dir=%s data_directory=%s  ' \
              'dbname=%s  dbuser=%s  dbhost=%s sqlstates=%s sqlclasses=%s prefix=***%s*** postfix=***%s*** log_line_prefix=%s lockwait=%d checkinterval=%d  loadthreshold=%d  ' \
              'dirthreshold=%d  idletransthreshold=%d querytransthreshold=%d  pgsql_tmp_threshold=%d ignore_autovacdaemon=%s ignore_uservac=%s slaves=%s ignoreapps=%s ' \
              'ignoreusers=%s monitorlag=%s alert_stmt_timeout=%s ignorequeries=%s server_version=%s server_version_num=%d suspended=%s mail_method=%s smtp_server=%s, smtp_account=%s\n' \
              % (now,self.verbose, self.sendemail, self.check_sqlstate, self.max_alerts, self.clusterid, self.pgport, self.from_, self.to, self.minutes, self.keeplogdays, self.pglog_directory, self.alert_directory ,\
                 self.data_directory, self.dbname, self.dbuser, self.dbhost, self.sqlstates, self.sqlclasses, self.sqlstateprefix, self.sqlstatepostfix, self.log_line_prefix, \
                 self.lockwait, self.checkinterval, self.loadthreshold, self.dirthreshold, self.idletransthreshold, self.querytransthreshold, self.pgsql_tmp_threshold, \
                 self.ignore_autovacdaemon, self.ignore_uservac, self.slaves, self.ignoreapps, self.ignoreusers, self.monitorlag, self.alert_stmt_timeout, self.ignorequeries, \
                 self.server_version, self.server_version_num, self.suspended, self.mail_method, self.smtp_server, self.smtp_account)
        self.printit(msg)
        return


    ########################
    def cleanup(self, rc):
        now = datetime.datetime.now().strftime("%Y-%m-%d %H:%M:%S")                    
        self.printit("%s: Cleanup in progress..." % now)
        if self.alert is not None:
            self.alert.close()
        if self.conn is not None:
            self.conn.close()
    
        if rc <> NOPROGLOCK:
            rc2 = self.terminatetail()
            self.printit("%s: removing pidfile, %s" % (now,self.pidfile))
            try:
                os.unlink(self.pidfile)
            except OSError, e:
                self.printit("%s: OSError attempting to remove pidfile, %s. %s" % (now,self.pidfile, e))
            except e:
                self.printit("%s: Unknown exception trying to remove pid file, %s.  %s" % (now, self.pidfile, e))
        now = datetime.datetime.now().strftime("%Y-%m-%d %H:%M:%S")                    
        self.printit("%s: pg_alert ended." % now)
        sys.exit(rc)

    ########################
    def catch(self, signum, frame):
        print("xxxx", self, signum, frame)
        self.printit('User-initiated interrupt detected.')
        self.cleanup(INTERRUPT)        


#####################################
######### MAIN ENTRY POINT ##########
#####################################

# get the class instantiation
p = pgmon()

rc = p.initandvalidate()
if rc <> 0:
    p.cleanup(1)    

# deprecated call
# rc = get_lock(p.processname)
# if rc <> 0:
#     p.cleanup(rc)    

p.showparms()

# Start the tail of the pg log file: file format expected: postgresql-YY-MMDD.log
cmd= "timeout %d tail -f %s | grep --line-buffered '%s' > %s 2>&1 &" % (p.seconds,p.logfile,p.grepfilter, p.logalert)
msg = "%s: %s\n" % (p.start,cmd)
p.printit(msg)
rc,out,errs = p.executecmd(cmd,False)
if rc <> 0:
    p.cleanup(rc)    

# delay for a few secs before attempting to access the alerts log file
time.sleep(2)
now = datetime.datetime.now().strftime("%Y-%m-%d %H:%M:%S")    
p.printit("%s: Background tail started successfully.  Tailing alerts file now...\n" % now)
    
timeout = time.time() + p.seconds + 2
# outer loop is for duration of the tail of pg log

tailfinished = 0
bAbort = False
while True:
    if time.time() > timeout:
        break
    elif bAbort:
        break
    buffstart = time.time()
    buffcnt  = 0
    sleepsec = 0
    while True:
        if tailfinished:
            break
        # sleep 1 sec between each iteration
        if not tailfinished:
            time.sleep(1)
            sleepsec = sleepsec + 1
        # p.printit("time.time=%s timeout=%s sleepsec=%s" % (time.time(),timeout,sleepsec))
        if time.time() > (timeout + sleepsec):
            break
        now = time.time()            
        delta = round(now - buffstart)
        # p.printit("delta=%d  buffcnt=%d" % (delta,buffcnt))
        p.bypass = False
        if delta < 60:
            if buffcnt > 20:
                # too much activity in short duration, back off for awhile, but notify admin
                now = datetime.datetime.now().strftime("%Y-%m-%d %H:%M:%S")    
                msg = "%s: too many alerts (%d) in short interim. Sleeping for 10 minutes..." % (now, buffcnt)
                p.sendalert(msg)
                if not tailfinished:
                    sleepsec = sleepsec + 600                
                    time.sleep(600)
                    rc = p.checkotherstuff();
                    if rc <> 0:
                        p.printit("Errors encountered.  Program will abort.")
                        p.cleanup(1)    
        elif p.alertcnt > p.max_alerts:
            # exceeded maximum alerts for this iteration of program
            now = datetime.datetime.now().strftime("%Y-%m-%d %H:%M:%S")    
            msg = "%s: Max Alerts (%d) exceeded. Program terminating prematurely." % (now, p.max_alerts)
            p.sendalert(msg)
            bAbort = True
            break;            
        else:
            # restart the buffer timer
            buffstart = time.time()
            buffcnt   = 0
    
        where = p.alert.tell()
        line = p.alert.readline()
        now = datetime.datetime.now().strftime("%Y-%m-%d %H:%M:%S")    
        if not line:
            if tailfinished:
                break;
            else:    
                time.sleep(15)
                sleepsec = sleepsec + 15

                # check for other things here
                rc = p.checkotherstuff();
                if rc <> 0:
                    p.printit("Errors encountered.  Program will abort.")
                    p.cleanup(1)    
            
            time_now = time.time()
            time_delta = round(time_now - p.time_start)
            if time_delta > p.seconds:
                if not tailfinished:
                    p.printit("%s: Tail finished." % now)
                tailfinished = 1
            p.alert.seek(where)
        else:
            p.printit("%s evaluating msg: %s" % (now, line.strip()))
            if p.alertvalidated(line.strip()):
                buffcnt = buffcnt + 1    
                rc = p.sendalert(line.strip())
                if rc <> 0:
                    p.cleanup(1)    
            else:
                now = datetime.datetime.now().strftime("%Y-%m-%d %H:%M:%S")                    
                if p.bypass:
                    if p.verbose:
                        p.printit("%s: VERBOSE: bypass for %s\n" % (now,line.strip()))
                # pass
                
now = datetime.datetime.now().strftime("%Y-%m-%d %H:%M:%S")    
p.printit("%s: Daily Monitoring ending. %d alert(s) detected." % (now, p.alertcnt))
p.cleanup(0)
