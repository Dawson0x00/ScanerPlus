@echo off

goto evl
自动发现当前内网的所有存活段 [Windows] 
By Klion
2020.7.1

虽然这样跑,确实很慢(139776个imcp echo request)
内网某台机器某天突然长时间的大量对外icmp,是个傻子也知道这不正常,监控看到,被清出来是迟早的,但也并不是所有的内网环境都这么完善
所以,能不动手的地方还是尽量不要动手吧,节省精力,毕竟,一次跑完,终身受用

:evl

setlocal enabledelayedexpansion

rem 10.x.x.x 内网段
for /l %%i in (0,1,255) do (
	for /l %%k in (0,1,255) do (
		ping -w 1 -n 1 10.%%i.%%k.1 | findstr "TTL=" >nul || ping -w 1 -n 1 10.%%i.%%k.254 | findstr "TTL=" >nul
		if !errorlevel! equ 0 (echo 10.%%i.%%k.0/24 is alive ! >> alive.txt ) else (echo 10.%%i.%%k.0/24 May be sleeping ! )
	)
)

rem 172.16.x.x - 172.31.x.x  内网段
for /l %%s in (16,1,31) do (
	for /l %%d in (0,1,255) do (
		ping -n 1 -w 1 172.%%s.%%d.1  | findstr "TTL=" >nul || ping -w 1 -n 1 172.%%s.%%d.254 | findstr "TTL=" >nul
		if !errorlevel! equ 0 (echo 172.%%s.%%d.0/24 is alive ! >> alive.txt ) else (echo 172.%%s.%%d.0/24 May be sleeping ! )
	)
)

rem 192.168.x.x  内网段
for /l %%t in (0,1,255) do (
	ping -n 1 -w 1 192.168.%%t.1  | findstr "TTL=" >nul || ping -n 1 -w 1 192.168.%%t.254 | findstr "TTL=" >nul
	if !errorlevel! equ 0 (echo 192.168.%%t.0/24 is alive ! >> alive.txt ) else (echo 192.168.%%t.0/24 May be sleeping ! )
)
