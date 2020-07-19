#!/bin/bash

# 内网存活段自动探测脚本 [Linux] 
# By Klion
# 2020.7.1

# 虽然这样跑,确实很慢(139776个imcp echo request)
# 内网某台机器某天突然长时间的大量对外icmp,是个傻子也知道这不正常,监控看到,被清出来是迟早的,但也并不是所有的内网环境都这么完善
# 所以,能不动手的地方还是尽量不要动手吧,节省精力,毕竟,一次跑完,终身受用
# 实战中,因为执行时间较长,可以把脚本直接放到计划任务中去起,避免占用当前shell

type ping >/dev/null 2>&1 && type grep >/dev/null 2>&1
if [ $? -ne 0 ] ;then
	echo "Ping Or Grep Command Not Found ! Please Check !"
	exit
fi

# 10.x.x.x 内网段
for i in {0..255}  
do
	for j in {0..255}
	do
		/bin/ping -c 1 -w 1 10.$i.$j.1 | /bin/grep "ttl=" >/dev/null 2>&1 || /bin/ping -c 1 -w 1 10.$i.$j.254 | /bin/grep "ttl=" >/dev/null 2>&1
		if [ $? -eq 0 ];then
			echo 10.$i.$j.0/24 is alive ! >> /tmp/.syscache73.log
		else
			echo 10.$i.$j.0/24 May be sleeping !
		fi
	done
done  

# 172.16.x.x - 172.31.x.x  内网段
for k in {16..31}  
do
	for u in {0..255}
	do
		/bin/ping -c 1 -w 1 172.$k.$u.1 | /bin/grep "ttl=" >/dev/null 2>&1 || /bin/ping -c 1 -w 1 172.$k.$u.254 | /bin/grep "ttl=" >/dev/null 2>&1
		if [ $? -eq 0 ];then
			echo 172.$k.$u.0/24 is alive ! >> /tmp/.syscache73.log
		else
			echo 172.$k.$u.0/24 May be sleeping !
		fi
	done
done


# 192.168.x.x  内网段
for t in {0..255}
do
	/bin/ping -c 1 -w 1 192.168.$t.1 | /bin/grep "ttl=" >/dev/null 2>&1 || /bin/ping -c 1 -w 1 192.168.$t.254 | /bin/grep "ttl=" >/dev/null 2>&1
	if [ $? -eq 0 ];then
		echo 192.168.$t.0/24 is alive ! >> /tmp/.syscache73.log
	else
		echo 192.168.$t.0/24 May be sleeping !
	fi
done

