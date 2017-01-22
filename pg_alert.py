#!/usr/bin/env python
###############################################################################
### COPYRIGHT NOTICE FOLLOWS.  DO NOT REMOVE
###############################################################################
### Copyright (c) 2012-2017 SQLEXEC LLC
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
###############################################################################
#
# Original Author: Michael Vitale, michael@sqlexec.com
#
# Description: pg_alert.py is a PG monitoring script that sends email alerts based on 
#              monitored elements in a log file, host metrics, or db queries.
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
################################################################################################################
import string, sys, os, time, datetime, exceptions, socket, commands, argparse
import random, math, signal, platform, glob, stat, imp
# import sh
import ConfigParser, smtplib, subprocess
from subprocess import *
# from subprocess import Popen, PIPE
from optparse import OptionParser
# psycopg2 and psutil imported as globals after package validation

OK  = 0
ERR = 1
NOTFOUND = -1
INTERRUPT = -2
NOPROGLOCK = -3

sys.exit(0)
