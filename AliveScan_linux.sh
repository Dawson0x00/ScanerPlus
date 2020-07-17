#!/bin/bash

# 内网存活段自动探测脚本 [Linux] 
# By Klion
# 2020.7.1

for i in {0..255}  
do
	for j in {0..255}
	do
		ping -c 1 -w 1 10.$i.$j.1 | grep "ttl=" >/dev/null 2>&1 || ping -c 1 -w 1 10.$i.$j.254 | grep "ttl=" >/dev/null 2>&1
		if [ $? -eq 0 ];then
			echo 10.$i.$j.0/24 is alive ! >> aliveHost.txt
		else
			echo 10.$i.$j.0/24 May be sleeping !
		fi
	done
done  

for k in {16..31}  
do
	for u in {0..255}
	do
		ping -c 1 -w 1 172.$k.$u.1 | grep "ttl=" >/dev/null 2>&1 || ping -c 1 -w 1 172.$k.$u.254 | grep "ttl=" >/dev/null 2>&1
		if [ $? -eq 0 ];then
			echo 172.$k.$u.0/24 is alive ! >> aliveHost.txt
		else
			echo 172.$k.$u.0/24 May be sleeping !
		fi
	done
done


for t in {0..255}
do
	ping -c 1 -w 1 192.168.$t.1 | grep "ttl=" >/dev/null 2>&1 || ping -c 1 -w 1 192.168.$t.254 | grep "ttl=" >/dev/null 2>&1
	if [ $? -eq 0 ];then
		echo 192.168.$t.0/24 is alive ! >> aliveHost.txt
	else
		echo 192.168.$t.0/24 May be sleeping !
	fi
done

