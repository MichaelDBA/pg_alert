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

## Requirements
1. Linux, no windows pg server monitoring at the present time.
2. mail utility (mailutils)
3. python 2.7
4. python packages: python-psutil, psycopg2
5. PG Log file format that does not extent do time, i.e., hours, minutes, seconds.  
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
### SQLSTATES
The **SQLSTATES** configuration parameter is probably one of the most powerful filtering features of pg_alert.  Here you can filter out SQLSTATES and entire SQLCLASSES.  SQLCODES are reported in the postgresql log file as sqlstate. You can also specify a class to ignore based on official postgresql documentation:
[PostgreSQL Error Codes](http://www.postgresql.org/docs/9.6/static/errcodes-appendix.html)

