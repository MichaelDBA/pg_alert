# pg_alert
This python program monitors the PostgreSQL log file and sends email alerts based on user-set configuration parameters.  You can get it here:
`git clone https://github.com/MichaelDBA/pg_alert.git pg_alert`

(c) 2012-2016, 2017 SQLEXEC LLC
<br/>
GNU V3 and MIT licenses are conveyed accordingly.
<br/>
Bugs can be reported @ michael@sqlexec.com

## History
The first version of this program was created back in 2012.  It was big and messy since the logic was based upon parsing the current PG log file.  A major rewrite was undertaken in 2016 using the new tail logic. Since then it has been uploaded to this public github repo to share with the rest of the PG community.  It has been tested extensively with Ubuntu/Debian distros using PG 9.x.  Please provide details of errors with other distros or PG versions so we can update accordingly.

## Overview
Most programs that monitor log files do so directly.  This program incurs a much less footprint by only monitoring the output of a provided grep command against the PG log file tail.  Here is a simple example of the grep command that will be used derived from the pg_alert configuration file:
<br/>
`GREP=ERROR:\|FATAL:\|WARN:`
<br/><br/>
The ensuing output is what pg_alert monitors. So, we have 2 processes:
<br/>
* pg_alert
<br/>
* grepping the PG log file tail
<br/><br/>

The configuration file, **pg_alert.conf**, is where all the filtering is done on the resulting grepped tail output of the PG log file.  This configuration file contains detailed comments about each configurable field.

The program generates 2 output files:

1. alerts-YYYY-MMDD.log (the output of the grepped pg log tail)
2. alerts-history-YYYY-MMDD.log (output from the pg_alert program, shows things evaluated and alerted on)
<br/><br/>

pg_alert analyzes and alerts primarily on PG log file contents.  It also analyzes and alerts on pg session info (connections, queries, etc.) and host metrics (load, etc.).  

## Requirements
1. Linux, no windows pg server monitoring at the present time.
2. mail utility (mailutils)
3. python 2.7
4. python packages: python-psutil, psycopg2
5. PG Log file format that does not extent to time, i.e., hours, minutes, seconds.  
log_filename='postgresql-%Y-%m-%d.log'
<br/>
log_filename='postgresql-%a.log'

## Inputs
All input fields are taken from the associated configuration file, pg_alert.conf.  You can override some parameters on the command line.  The only required parameter is the location of the configuration file.
`-c --configfile`
<br/>
`-m --minutes`
<br/>
`-d --dbname`
<br/>
`-u --dbuser`
<br/>
`-s --dbhost`
<br/>
`-v --verbose`
<br/>

## Examples
In these examples, pg_alert will run for 60 minutes.
>pg_alert.py -m 60 -c /var/lib/postgresql/scripts/pg_alert.conf
<br/>
>python pg_alert.pyc -m 60 -c /var/lib/postgresql/scripts/pg_alert.conf
<br/>
>nohup python pg_alert.pyc -m 60 -c /var/lib/postgresql/scripts/pg_alert.conf &
 
## Details
This section gets into the nuances of pg_alert. 

It's a good idea to configure it very restrictive at first (bigger GREP statement, application, user restrictions, sqlstate/sqlclass codes) so as not to generate a lot of emails at first.  Then pull back the filtering bit by bit until you get the right kind and amount of alerts that you can work with.

pg_alert will temporarily suspend emails for a few minutes if too many alerts are triggered in a very short period of time.  You can modify pg_alert.conf and many changes will be picked up dynamically by a running pg_alert program every 5 minutes or so.  Thus if you get a lot of alerts, you can add more filtering to restrict alerts without having to stop and restart the program and its spawned tail process.


### POSTGRESQL.CONF SETTINGS
To gain the most analysis of the PG log file, these settings should be set in **postgresql.conf**. 
* log_min_duration_statement = 5  # 0-whatever, that gets you visibility into the depth of the SQL you want to analyze.
* log_checkpoints = on
* log_connections = on
* log_disconnections = on
* log_lock_waits = on
* log_statement = 'none'
* log_temp_files = 0
* log_autovacuum_min_duration = 2    # 0-whatever, that gets you visibility into the depth of the autovacuum processes you want to analyze.
* log_line_prefix = '%m %u@%d[%p:%i] %r [%a]&nbsp;&nbsp;&nbsp;%e tx:%x : '  # this is just a working example, compatible with pgbadger


### SQLSTATES
The **SQLSTATES** configuration parameter is probably one of the most powerful filtering features of pg_alert.  Here you can filter out SQLSTATES and entire SQLCLASSES.  SQLCODES are reported in the postgresql log file as sqlstate. You can also specify a class to ignore based on official postgresql documentation:
[PostgreSQL Error Codes](http://www.postgresql.org/docs/9.6/static/errcodes-appendix.html)

SQLSTATES is only applicable if you have the correct **log_line_prefix** defined, where the sqlstate can be identified by a **pre** and  **post** delimiter.  You do not have to specify the delimiter since pg_alert will determine that, but you do have to make sure that there are delimiters and that the delimiter are not shared with any other **%** value.  Otherwise, SQLSTATE filtering is disabled during the pg_alert session.  Here are some good examples. Note the second example uses 3 spaces as a **pre** delimiter to uniquely identify it.

        >        log_line_prefix = '%m %u@%d[%p: %i ] %r [%a] sqlstate=%e tx:%x : '

        >        log_line_prefix = '%m %u@%d[%p: %i ] %r [%a]   %e tx:%x : '

### MAIL ALERTS
The whole point of pg_alert is to send email alerts. pg_alert also supports SMS text messages as well. The current version supports 3 types of mail protocol:
* mail (mailx)
* ssmtp
* smtp

MAIL is really **mailx** since there is a symlink pointing to a particular mailx version.  Two common ones are **bsd-mailx** and **heriloom-mailx**.  **bsd-mailx** is the more stable version. If you have a choice please make your symlinks point to the bsd version.  Otherwise, pg_alert will try to find and use it, but this is not guaranteed.
>lrwxrwxrwx 1 root root 22 Mar  1  2016 /usr/bin/mail -> /etc/alternatives/mail
<br /><br />
>lrwxrwxrwx 1 root root 23 Mar  1  2016 /etc/alternatives/mail -> /usr/bin/heirloom-mailx
<br /><br />

Note that the example above is really using the **heirloom** version of mailx.

**ssmtp** is a simple mail transfer agent (MTA) to deliver mail from a computer to a mail hub (SMTP server). It is not as robust as SMTP.
<br /><br />
**smtp** designates to use the python email delivery protocol, **smtplib** – Simple Mail Transfer Protocol client.  
<br /><br />
It may be necessary to edit **/etc/ssmtp/ssmtp.conf** to get mail to work properly.


