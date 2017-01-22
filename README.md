# pg_alert
This python program monitors the PostgreSQL log file and sends email alerts based on user-set configuration parameters.  You can get it here:
`git clone https://github.com/MichaelDBA/pg_alert.git pg_alert`

(c) 2012-2016, 2017 SQLEXEC LLC
<br/>
GNU V3 and MIT licenses are conveyed accordingly.
<br/>
Bugs can be reported @ michael@sqlexec.com

## History
The first version of this program was created back in 2012.  It was big and messy since the logic was based upon parsing the current PG log file.  A major rewrite was undertaken in 2016 using the new tail logic. Since then it has been uploaded to this public github repo to share with the rest of the PG community.

## Overview
Most programs that monitor log files do so directly.  This program incurs a much less footprint by only monitoring the output of a provided grep command against the PG log file tail.  Here is a simple example of the grep command that will be used derived from the configuration file:
<br/>
`GREP=ERROR:\|FATAL:\|WARN:`
<br/><br/>
The ensuing output is what pg_alert monitors. So, we have 2 processes:
<br/>
1. pg_alert
<br/>
2. grepping the tail the PG log file
<br/><br/>
The configuration file, pg_alert.conf, is where all the filtering is done on the resulting grepped tail output of the PG log file.
<br/><br/>

## Requirements
1. python 2.6 or 2.7
2. packages: pthon-psutil, psycopg2
3. PG Log file format that does not extent do time, i.e., hours, minutes, seconds.  
<br/>
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
