#!/bin/bash 
# ./get_awslogs_cli_parts.sh <PROFILE> <DBID> <LOG FILE>
# based on mod to this script: https://github.com/aws/aws-cli/issues/2268#issuecomment-278831175

COUNTER=1
LASTFOUNDTOKEN=0
PREVIOUSTOKEN=0

PROFILE=$1
DBID=$2
SCRIPTDIR=$3
FILE=$4

LOGFILE="${SCRIPTDIR}/get_awslogs_cli_parts.log"
exec 1>>$LOGFILE
exec 2>&1

rm -f ${SCRIPTDIR}/${FILE}
#echo "`date +'%Y-%m-%d %H:%M:%S'`  Getting log parts for log, $FILE"
while [  $COUNTER -lt 200 ]; do
	#echo "The starting-token will be set to ${LASTFOUNDTOKEN}"
	PREVIOUSTOKEN=${LASTFOUNDTOKEN}
	
	if [ $PROFILE == "NA" ]; then
	    aws rds download-db-log-file-portion --db-instance-identifier ${DBID} --log-file-name error/${FILE} --starting-token ${LASTFOUNDTOKEN}  --debug --output text 2>>${SCRIPTDIR}/${FILE}.${COUNTER}.debug >> ${SCRIPTDIR}/${FILE}.${COUNTER}
        else
	    aws rds download-db-log-file-portion --profile $PROFILE --db-instance-identifier ${DBID} --log-file-name error/${FILE} --starting-token ${LASTFOUNDTOKEN}  --debug --output text 2>>${SCRIPTDIR}/${FILE}.${COUNTER}.debug >> ${SCRIPTDIR}/${FILE}.${COUNTER}
        fi

	LASTFOUNDTOKEN=`grep -o "<Marker>[0-9]*:[0-9]*</Marker>" ${SCRIPTDIR}/${FILE}.${COUNTER}.debug | tail -1 | tr -d "<Marker>" | tr -d "/" | tr -d " "`	
        exitcode=$?
        if [ $exitcode -ne 0 ]; then echo "`date +'%Y-%m-%d %H:%M:%S'`  ERROR: grep lastfoundtoken: $exitcode"; exit 1; fi

	#echo "LASTFOUNDTOKEN is ${LASTFOUNDTOKEN}"
	#echo "PREVIOUSTOKEN is ${PREVIOUSTOKEN}"
	
	if [ ${PREVIOUSTOKEN} == ${LASTFOUNDTOKEN} ]; then
		#echo "No more new markers, exiting"
		rm -f ${SCRIPTDIR}/${FILE}.${COUNTER}.debug
		rm -f ${SCRIPTDIR}/${FILE}.${COUNTER}
		echo "`date +'%Y-%m-%d %H:%M:%S'`  Received ${COUNTER} parts for log, $FILE"
		#echo "logfile=${SCRIPTDIR}/${FILE}"
		exit 0
	else
		#echo "Marker is ${LASTFOUNDTOKEN} more to come ... "
		#echo " "
		rm -f ${SCRIPTDIR}/${FILE}.${COUNTER}.debug
		PREVIOUSTOKEN=${LASTFOUNDTOKEN}
	fi
	
	cat ${SCRIPTDIR}/${FILE}.${COUNTER} >> ${SCRIPTDIR}/${FILE}
	rm -f ${SCRIPTDIR}/${FILE}.${COUNTER}
	
	let COUNTER=COUNTER+1
done
echo "`date +'%Y-%m-%d %H:%M:%S'`  Unexpected end of getting log parts for log, $FILE"
exit 1
