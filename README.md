# pg_alert
This python program monitors the PostgreSQL log file and sends email alerts based on user-set configuration parameters.  You can get it here:
`git clone https://github.com/MichaelDBA/pg_alert.git pg_alert`

(c) 2016, 2017 SQLEXEC LLC

Bugs can be reported @ michael@sqlexec.com

## Overview
Most programs that monitor log files do so directly.  This program incurs a much less footprint by only monitoring the output of a provided grep command against the PG log file from the configuration file.  Here is a simple example:
`GREP=ERROR:\|FATAL:\|WARN:`
The ensuing output is what pg_alert monitors. So, we have 2 proceses:
1. pg_alert
2. tailing the PG log file

## Requirements
1. python 2.6 or 2.7
2. packages: pthon-psutil, psycopg2

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
In this example, pg_alert will run for 60 minutes.
pg_alert.py -m 60 -c /var/lib/postgresql/scripts/pg_alert.conf


