@echo off

rem 内网存活段自动发现脚本 [Windows] 
rem By Klion
rem 2020.7.1

setlocal enabledelayedexpansion

for /l %%i in (0,1,255) do (
	for /l %%k in (0,1,255) do (
		ping -w 1 -n 1 10.%%i.%%k.1 | findstr "TTL=" >nul || ping -w 1 -n 1 10.%%i.%%k.254 | findstr "TTL=" >nul
		if !errorlevel! equ 0 (echo 10.%%i.%%k.0/24 is alive ! >> alive.txt ) else (echo 10.%%i.%%k.0/24 May be sleeping ! )
	)
)

for /l %%s in (16,1,31) do (
	for /l %%d in (0,1,255) do (
		ping -n 1 -w 1 172.%%s.%%d.1  | findstr "TTL=" >nul || ping -w 1 -n 1 172.%%s.%%d.254 | findstr "TTL=" >nul
		if !errorlevel! equ 0 (echo 172.%%s.%%d.0/24 is alive ! >> alive.txt ) else (echo 172.%%s.%%d.0/24 May be sleeping ! )
	)
)

for /l %%t in (0,1,255) do (
	ping -n 1 -w 1 192.168.%%t.1  | findstr "TTL=" >nul || ping -n 1 -w 1 192.168.%%t.254 | findstr "TTL=" >nul
	if !errorlevel! equ 0 (echo 192.168.%%t.0/24 is alive ! >> alive.txt ) else (echo 192.168.%%t.0/24 May be sleeping ! )
)
