#! /bin/bash
# cat /var/log/secure|awk '/Failed/{print $(NF-3)}'|sort|uniq -c|awk '{print $2"="$1;}' > /usr/local/bin/black.txt
# for i in `cat  /usr/local/bin/black.txt`
# do
#   IP=`echo $i |awk -F= '{print $1}'`
#   NUM=`echo $i|awk -F= '{print $2}'`
#    if [ $NUM -gt 5 ];then
#       grep $IP /etc/hosts.deny > /dev/null
#     if [ $? -gt 0 ];then
#       echo "sshd:$IP:deny" >> /etc/hosts.deny
#     fi
#   fi
# done


#!/bin/bash
IFS_old=$IFS      #将原IFS值保存，以便用完后恢复
IFS=$'\n'        #更改IFS值为$’\n’ ，注意，以回车做为分隔符，IFS必须为：$’\n’

cat /var/log/auth.log  | grep "Failed password\|Accepted password" > ssh_login_file 
for line in `cat ssh_login_file`  #for each line
do
	echo $line | grep "Accepted password">/dev/null
	if [ $? -eq 0 ];then
		echo $line| awk -F" " '{print "ip:"$11 ":" $13 "\t"   "user:" $9 "\t" "state:Accepted"}'
	else
		echo $line | grep "invalid user" > /dev/null
		if [ $? -eq 0 ];then
			echo $line| awk -F" " '{print "ip:"$13 ":" $15 "\t"   "user:" $11 "\t" "state:Accepted"}'
		else
			echo $line| awk -F" " '{print "ip:"$11 ":" $13 "\t"   "user:" $9 "\t" "state:Failed"}'
		fi
	fi
done
IFS=$IFS_old      #恢复原IFS值

