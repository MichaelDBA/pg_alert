# pg_alert
This python program monitors the PostgreSQL log file and sends email alerts based on user-set configuration parameters.  You can get it here:
`git clone https://github.com/MichaelDBA/pg_alert.git pg_alert`

(c) 2016, 2017 SQLEXEC LLC

Bugs can be reported @ michael@sqlexec.com

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
pg_alert.py -m 60 -c /var/lib/postgresql/scripts/pg_alert.conf

