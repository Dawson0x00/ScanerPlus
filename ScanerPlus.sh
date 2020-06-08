#!/bin/bash

# 适用于在内/外网快速搜集目标基础端口服务信息(如,直接通过无线,VPN接入目标内网)

if [ $# -eq 0 ] || [ $# != 3 ];then
    echo -e "\n\e[94m################################################################################################\e[0m"
    echo -e "\e[94m#											       #\e[0m"
    echo -e "\e[94m#    PortScan & Service Brute (Tested on Ubuntu 16.04 64bit )			               #\e[0m"
    echo -e "\e[94m#					Author : klion				               #\e[0m"
    echo -e "\e[94m#					2020.2.1				               #\e[0m"
    echo -e "\e[94m################################################################################################\e[0m"
    echo -e "\e[94m#											       #\e[0m"	
    echo -e "\e[94m#    Usage:  										       #\e[0m"
    echo -e "\e[94m#       nohup ./ScanerPlus.sh 端口列表 目标真实ip[ip段]列表 保存扫描结果的目录名[随意]  &      #\e[0m"
    echo -e "\e[94m#       nohup ./ScanerPlus.sh TargetPorts.txt TargetIplist.txt Final & 		               #\e[0m"
    echo -e "\e[94m#       tail -f nohup.out 								       #\e[0m"
    echo -e "\e[94m################################################################################################\e[0m\n"
    exit
fi

# 判断当前用户权限
if [ `id -u` -ne 0 ];then
	echo -e "\n\033[33m请以 root 权限 运行该脚本! \033[0m\n"
	exit
fi

# 安装各类基础工具及相关依赖
mkdir $3
apt-get update >/dev/null 2>&1
apt-get install git p7zip-full gcc make libpcap-dev clang openssl libssh2-1-dev build-essential build-essential libssl-dev libpq5 libpq-dev libssh2-1 libssh2-1-dev libgcrypt11-dev libgnutls-dev libsvn-dev freerdp-x11 libfreerdp-dev git libssl-dev libssh-dev libidn11-dev libpcre3-dev libgtk2.0-dev libmysqlclient-dev libpq-dev libsvn-dev firebird-dev libgcrypt11-dev libncurses5-dev -y >/dev/null 2>&1
if [ $? -eq 0 ];then
    echo -e "\n\e[94m所有基础工具及相关依赖已成功安装 ! \e[0m"
	sleep 1
else
    echo -e "安装错误,请仔细检查后重试! "
    exit
fi

# 安装masscan
which "masscan" > /dev/null
if [ $? -eq 0 ];then
    echo -e "\e[94m当前系统已安装过 Masscan ! \e[0m"
	sleep 1
else
	git clone https://github.com/robertdavidgraham/masscan.git >/dev/null 2>&1
	if [ $? -eq 0 ];then
		cd masscan/ && make >/dev/null 2>&1 && mv bin/masscan /usr/bin/
		if [ $? -eq 0 ];then
			echo -e "\e[94mMasscan 已成功安装 ! \e[0m"
			cd ..
			rm -fr masscan*
		else
			echo -e "Masscan安装失败 ! 请仔细检查后重试 !"
			exit
		fi
	fi 
fi

# 安装nmap ( 把已经事先处理好的nmap[剔除扫描时的典型指纹特征]传到vps上 )
which "nmap" > /dev/null
if [ $? -eq 0 ];then
    echo -e "\e[94m当前系统已安装过 Nmap ! \e[0m"
	sleep 1
else
	7z x nmap-7.80.7z && cd nmap-7.80 && chmod +x ./* && ./configure >/dev/null 2>&1 && make >/dev/null 2>&1 && make install >/dev/null 2>&1
	if [ $? -eq 0 ];then
		echo -e "\e[94mNmap已成功安装 ! \e[0m"
		cd ..
		rm -fr nmap-7.80*
	else
		echo -e "Nmap安装失败 ! 请确认nmap-7.80.7z是否已事先放到脚本同目录下 ! "
		exit
	fi
fi

# 安装medusa
which "medusa" > /dev/null
if [ $? -eq 0 ];then
    echo -e "\e[94m当前系统已安装过 Medusa ! \e[0m"
	sleep 1
else
	wget http://www.foofus.net/jmk/tools/medusa-2.2.tar.gz >/dev/null 2>&1
	if [ $? -eq 0 ];then
		tar xf medusa-2.2.tar.gz && cd medusa-2.2/ && ./configure  >/dev/null 2>&1 && make >/dev/null 2>&1  && make install >/dev/null 2>&1
		if [ $? -eq 0 ];then
			echo -e "\e[94mMedusa 已成功安装 ! \e[0m"
			cd ..
			rm -fr medusa-2.2*
		else
			echo -e "Medusa 安装失败 ! 请仔细检查后重试 ! "
			exit
		fi
	fi
fi

# 安装hydra
which "hydra" > /dev/null
if [ $? -eq 0 ];then
    echo -e "\e[94m当前系统已安装过 Hydra ! \e[0m"
	sleep 1
else
	git clone https://github.com/vanhauser-thc/thc-hydra.git  >/dev/null 2>&1
	if [ $? -eq 0 ];then
		cd thc-hydra && chmod +x ./* && ./configure >/dev/null 2>&1 && make >/dev/null 2>&1 && make install >/dev/null 2>&1
		if [ $? -eq 0 ];then
			echo -e "\e[94mHydra已成功安装 ! \e[0m"
			cd ..
			rm -fr thc-hydra*
		else
			echo -e "Hydra 安装失败 ! 请仔细检查后重试 ! "
			exit
		fi
	fi
fi

# 扫描[此处的所有爆破操作,暂只用nmap自带脚本,字典数量都非常小]
starttime=`date +'%Y-%m-%d %H:%M:%S'`
times=$(date +%Y)

for port in `cat TargetPorts.txt`
do
	# 为尽量避免过早触发对方防护报警,所以针对所有ip每次只扫一个端口
    starts=`date +'%Y-%m-%d %H:%M:%S'`
    echo -e "\n\e[94m=========================================================================\e[0m\n"
    echo -e "\033[47;34m开始扫描 $port 端口 ! \033[0m\n"
    while read -r ip
    do
        echo -e "\e[92m正在扫描 $ip 段,扫描端口为 $port,过程稍慢,请耐心等待... \e[0m"
        random=$(openssl rand -base64 40|sed 's#[^a-z]##g'|cut -c 6-11)

		# 此处速率可根据自己vps的实际带宽情况进行针对性调整
		masscan -p $port --banners --rate=1000 -sS -Pn --http-user-agent "Mozilla/5.0 (Windows NT 6.1; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/79.0.3945.130 Safari/537.36" --open-only -oL ${times}_${random}_${port}_Final.txt $ip >/dev/null 2>&1
        if [  $? -eq 0 ] ;then  echo -e "\e[92m$ip 段扫描完毕! 开始扫描下个段,请稍后... \e[0m\n"; else  echo -e "\e[91m扫描错误 ! 请仔细检查后重试 ! \e[0m\n" ; fi
    done < $2
    grep "open tcp ${port}" *_${port}_*.txt | awk -F " " {'print $4'} > ./${3}/${port}.txt
    rm -fr *_${port}_*.txt
    
	# 如下基本已覆盖大部分常用Web端口
    if [ $port -ge 79 -a  $port -le 91 ] || [ $port -ge 8079 -a $port -le 8091 ] || [ $port -eq 443 ] || [ $port -eq 31999 ] || [ $port -eq 9443 ] || [ $port -eq 1158 ] || [ $port -eq 8443 ] || [ $port -eq 4443 ] || [ $port -ge 8001 -a $port -le 8010 ] || [ $port -eq 8100 ] || [ $port -eq 8333 ] || [ $port -eq 8222 ] || [ $port -eq 10000 ] || [ $port -eq 9999 ] ;then
	echo -e "\e[94m常规Web端口扫描开始 ..... \e[0m"
	# 因为反解 + 加载脚本 会耗时很久,所以此处只加了选项和部分脚本
    nmap -p $port -iL ./${3}/${port}.txt -Pn -sS -sV -n -vv --open --script=http-waf-detect.nse,http-vuln-cve2017-5638.nse,http-vuln-cve2017-1001000.nse,vmware-version.nse,ssl-heartbleed.nse,http-shellshock.nse,http-cisco-anyconnect.nse,http-headers.nse,http-title.nse,http-robots.txt.nse,http-iis-webdav-vuln.nse -oN ./Web_${port}.txt >/dev/null 2>&1 
	# 信息搜集脚本
    # citrix-enum-servers-xml.nse,ssl-heartbleed.nse,http-shellshock.nse,http-cisco-anyconnect.nse,http-waf-detect.nse,http-waf-fingerprint.nse
    # http-axis2-dir-traversal.nse,http-backup-finder.nse,http-wordpress-users.nse,vmware-version.nse
    # http-methods.nse,http-webdav-scan.nse,http-iis-shortame-brute.nse,http-git.nse,jdwp-version.nse

	# 漏洞检测脚本 
	# tomcat-cve-2017-12615.nse,http-pulse_ssl_vpn.nse,CVE-2019-19781.nse,struts2-scan.nse,cisco-cve-2019-1937.nse,cve_2019_1653.nse
	# http-vuln-cve2017-8917.nse,http-vuln-cve2017-5638.nse,http-vuln-cve2017-1001000.nse
    fi

    # ELK常用端口
    if [ $port -ge 9200 -a $port -le 9300 ] ;then
		echo -e "\e[94mELK 端口扫描开始 ..... \e[0m"
        nmap -p $port -iL ./${3}/${port}.txt -Pn -sS -n -sV -vv --open --script= -oN ./ELK_${port}.txt >/dev/null 2>&1
    fi

	# Weblogic常用端口
    if [ $port -ge 7001 -a $port -le 7010 ];then
		echo -e "\e[94mWeblogic 端口扫描开始 ..... \e[0m"
        nmap -p $port -iL ./${3}/${port}.txt -Pn -sS -n -sV  -vv --open --script=weblogic-CNVD-C-2019-48814.nse -oN ./Weblogic.txt >/dev/null 2>&1
        # 相关漏洞探测脚本 , weblogic-cve-2018-2894.nse , weblogic-CNVD-C-2019-48814.nse
    fi

    # SSH 默认端口,弱口令字典需要事先自行精心准备(亦可用提供的字典生成脚本针对性生成),之后把nmap的默认字典全部替换掉即可,切记,量先不要太大,容易卡住
    if [ $port -eq 22 ];then
		echo -e "\e[94mSSH 端口扫描开始 ..... \e[0m"
        nmap -p $port -iL ./${3}/${port}.txt -Pn -sS -sV -n -vv --open -oN ./SSH.txt >/dev/null 2>&1
        # echo -e "\033[35m尝试爆破目标 Ssh,请耐心等待...\033[0m"
		# echo root > /usr/local/share/nmap/nselib/data/usernames.lst
		# echo admin >> /usr/local/share/nmap/nselib/data/usernames.lst
		# nmap -p 22 -iL ./${3}/${port}.txt -Pn -sS -sV  -vv --open --script=ssh-brute.nse --script-args userdb=usernames.lst,passdb=passwords.lst --script-args ssh-brute.timeout=5s -oN ./SSH_login.txt >/dev/null 2>&1
        # echo -e "\033[35mSsh 爆破完毕 ! 结果已存到当前目录的SSH_login.txt文件中\033[0m"
    fi

	# Sangfor SSH 默认端口,爆破速度一般 [默认只扫描不启用爆破]
	if [ $port -eq 22345 ];then
		echo -e "\e[94mSangfor SSH 端口扫描开始 ..... \e[0m"
        nmap -p $port -iL ./${3}/${port}.txt -Pn -sS -sV -n -vv --open -oN ./Sangfor_SSH.txt >/dev/null 2>&1
		# echo -e "\033[35m尝试爆破目标 Sangfor Ssh,请耐心等待...\033[0m"
		# echo admin > /usr/local/share/nmap/nselib/data/usernames.lst
		# echo root >> /usr/local/share/nmap/nselib/data/usernames.lst
		# nmap -p 22345 -iL ./${3}/${port}.txt -Pn -sS -sV  -vv --open --script=ssh-brute.nse --script-args userdb=usernames.lst,passdb=passwords.lst --script-args ssh-brute.timeout=5s -oN ./Sangfor_SSH_login.txt >/dev/null 2>&1
		# echo -e "\033[35mSangforSsh 爆破完毕 ! 结果已存到当前目录的Sangfor_SSH_login.txt文件中\033[0m"
	fi

	# Sangfor VPN默认管理端口
	if [ $port -eq 4430 ];then
		echo -e "\e[94mSangfor VPN 端口扫描开始 ..... \e[0m"
        nmap -p $port -iL ./${3}/${port}.txt -Pn -sS -sV -n -vv --open -oN ./SangforVpn_admin.txt >/dev/null 2>&1
    fi

	# PPTP VPN默认连接端口
	if [ $port -eq 1723 ];then
		echo -e "\e[94mPptp 端口扫描开始 ..... \e[0m"
        nmap -p $port -iL ./${3}/${port}.txt -Pn -sS -sV -n -vv --open -oN ./PptpVpn.txt >/dev/null 2>&1
    fi

	# Svn默认端口
	if [ $port -eq 3690 ];then
		echo -e "\e[94mSvn 端口扫描开始 ..... \e[0m"
        nmap -p $port -iL ./${3}/${port}.txt -Pn -sS -sV -n -vv --open -oN ./Svn.txt >/dev/null 2>&1
    fi

    # RDP默认端口
    if [ $port -eq 3389 ];then
        echo -e "\e[94mRdp 端口扫描开始 ..... \e[0m"
        nmap -p $port -iL ./${3}/${port}.txt -Pn -sS -sV -n -vv --open -oN ./RDP.txt >/dev/null 2>&1
        # 可选检测脚本 rdp-vuln-ms12-020.nse
    fi

    # Mssql默认端口,爆破速度还行
    if [ $port -eq 1433 ];then
		echo -e "\e[94mMssql 端口扫描开始 ..... \e[0m"
        nmap -p $port -iL ./${3}/${port}.txt -Pn -sS -sV -n -vv --open --script=ms-sql-empty-password.nse -oN ./Mssql.txt >/dev/null 2>&1
        echo -e "\033[35m尝试爆破目标 Mssql,请耐心等待...\033[0m"
		echo sa > /usr/local/share/nmap/nselib/data/usernames.lst
		nmap -p 1433 -iL ./${3}/${port}.txt -Pn -sS -sV -n -vv --open --script=ms-sql-empty-password.nse,ms-sql-brute.nse --script-args userdb=usernames.lst,passdb=passwords.lst --script-args ssh-brute.timeout=5s -oN ./Mssql_login.txt >/dev/null 2>&1
        echo -e "\033[35mMssql 爆破完毕 ! 结果已存到当前目录的Mssql_login.txt文件中\033[0m"
    fi

    # MySQL Login 爆破速度稍慢
    if [ $port -ge 3306 -a $port -le 3308 ] ;then
		echo -e "\e[94mMysql 端口扫描开始 ..... \e[0m"
        nmap -p $port -iL ./${3}/${port}.txt -Pn -sS -sV -n -vv --open --script=mysql-empty-password.nse -oN ./MySQL.txt >/dev/null 2>&1
        echo -e "\033[35m尝试爆破目标 MySQL,请耐心等待...\033[0m"
		echo root > /usr/local/share/nmap/nselib/data/usernames.lst
		nmap -p 3306 -iL ./${3}/${port}.txt -Pn -sS -sV -n -vv --open --script=mysql-empty-password.nse,mysql-brute.nse --script-args ssh-brute.timeout=5s -oN ./MySQL_login.txt >/dev/null 2>&1
        echo -e "\033[35mMySQL 爆破完毕 ! 结果已存到当前目录的MySQL_login.txt文件中\033[0m"
    fi

    # Redis Login 爆破速度很快
    if [ $port -eq 6379 ];then
		echo -e "\e[94mRedis 端口扫描开始 ..... \e[0m"
        nmap -p $port -iL ./${3}/${port}.txt -Pn -sS -sV -n -vv --open --script=redis-info.nse -oN ./Redis.txt >/dev/null 2>&1
        echo -e "\033[35m尝试爆破目标 Redis,请耐心等待...\033[0m"
		nmap -p 6379 -iL ./${3}/${port}.txt -Pn -sS -sV -n -vv --open --script=redis-info.nse,redis-brute.nse --script-args ssh-brute.timeout=5s -oN ./Redis_login.txt >/dev/null 2>&1
        echo -e "\033[35mRedis 爆破完毕 ! 结果已存到当前目录的Redis_login.txt文件中\033[0m"
    fi

    # Postgresql Login 爆破速度很快
    if [ $port -eq 5432 ];then
		echo -e "\e[94mPgsql 端口扫描开始 ..... \e[0m"
        nmap -p $port -iL ./${3}/${port}.txt -Pn -sS -sV -n -vv --open -oN ./Postgresql.txt >/dev/null 2>&1
        echo -e "\033[35m尝试爆破目标 Postgresql,请耐心等待...\033[0m"
		echo postgres > /usr/local/share/nmap/nselib/data/usernames.lst
		nmap -p 5432 -iL ./${3}/${port}.txt -Pn -sS -sV -n -vv --open --script=pgsql-brute.nse --script-args ssh-brute.timeout=5s -oN ./Postgresql_login.txt >/dev/null 2>&1
        echo -e "\033[35mPostgresql 爆破完毕 ! 结果已存到当前目录的Postgresql_login.txt文件中\033[0m"
    fi

    # SMB Login 爆破基本不可用,漏扫可以,内网用
    if [ $port -eq 445 ];then
		echo -e "\e[94mSMB 端口扫描开始 ..... \e[0m"
        nmap -p $port -iL ./${3}/${port}.txt -Pn -sS -sV -n -vv --open -oN ./Smb.txt >/dev/null 2>&1
        # echo -e "\033[35m尝试爆破目标 SMB,请耐心等待...\033[0m"
		# echo administrator > /usr/local/share/nmap/nselib/data/usernames.lst
		# nmap -p U:137,T:139,445 ./${3}/${port}.txt -Pn -sS -sV  -vv --open --script=smb-brute.nse,smb-vuln-ms17-010.nse,smb-vuln-ms08-067.nse,smb-os-discovery.nse -oN ./Smb_login.txt >/dev/null 2>&1
        # echo -e "\033[35mSMB 爆破完毕 ! 结果已存到当前目录的Smb_login.txt文件中\033[0m"
    fi

    # Telnet默认端口
    if [ $port -eq 23 ];then
		echo -e "\e[94mTelnet 端口扫描开始 ..... \e[0m"
        nmap -p $port -iL ./${3}/${port}.txt -Pn -sS -sV -n -vv --open -oN ./Telnet.txt >/dev/null 2>&1
    fi

    # ldap默认端口,爆破基本不可用
    if [ $port -eq 389 ];then
		echo -e "\e[94mLdap 端口扫描开始 ..... \e[0m"
        nmap -p $port -iL ./${3}/${port}.txt -Pn -sS -sV -n -vv --open -oN ./Ldap.txt >/dev/null 2>&1
    fi

    # Oracle默认端口,爆破基本不可用
    if [ $port -eq 1521 ];then
		echo -e "\e[94mOracle 端口扫描开始 ..... \e[0m"
        # 可选检测脚本 oracle-sid-brute.nse
        nmap -p $port -iL ./${3}/${port}.txt -Pn -sS -sV -n -vv --open -oN ./Oracle.txt >/dev/null 2>&1
    fi

    # MongoDB默认端口,爆破速度一般(有漏报)
    if [ $port -eq 27017 ];then
		echo -e "\e[94mMongoDB 端口扫描开始 ..... \e[0m"
        nmap -p $port -iL ./${3}/${port}.txt -Pn -sS -sV  -vv --open --script=mongodb-info.nse -oN ./MongoDB.txt >/dev/null 2>&1
        echo -e "\033[35m尝试爆破目标 MongoDB,请耐心等待...\033[0m"
		echo root > /usr/local/share/nmap/nselib/data/usernames.lst
		echo admin >> /usr/local/share/nmap/nselib/data/usernames.lst
		nmap -p 27017 -iL ./${3}/${port}.txt -Pn -sS -sV  -vv --open --script=mongodb-brute.nse --script-args ssh-brute.timeout=5s -oN ./MongoDB_login.txt >/dev/null 2>&1
		echo -e "\033[35mMongoDB 爆破完毕 ! 结果已存到当前目录的MongoDB_login.txt文件中\033[0m"
	fi

	# Memcached 
	if [ $port -eq 11211 ];then
		echo -e "\e[94mMemcached 端口扫描开始 ..... \e[0m"
        nmap -p $port -iL ./${3}/${port}.txt -Pn -sS -sV -n -vv --open --script=memcached-info.nse -oN ./Memcached.txt >/dev/null 2>&1
    fi

    # FTP
    if [ $port -eq 21 ];then
		echo -e "\e[94mFTP 端口扫描开始 ..... \e[0m"
        nmap -p $port -iL ./${3}/${port}.txt -Pn -sS -sV -n -vv --open --script=ftp-anon.nse,ftp-proftpd-backdoor.nse,ftp-vsftpd-backdoor.nse -oN Ftp.txt >/dev/null 2>&1
    fi

    # Rsync
    if [ $port -eq 873 ];then
		echo -e "\e[94mRsync 端口扫描开始 ..... \e[0m"
        nmap -p $port -iL ./${3}/${port}.txt -Pn -sS -sV -n -vv --open --script=rsync-list-modules.nse -oN ./Rsync.txt >/dev/null 2>&1
    fi

    # NFS
    if [ $port -eq 2049 ]  || [ $port -eq 111 ];then
		echo -e "\e[94mNFS 端口扫描开始 ..... \e[0m"
        nmap -p $port -iL ./${3}/${port}.txt -Pn -sS -sV -n -vv --open --script=nfs-showmount.nse -oN ./Nfs.txt >/dev/null 2>&1
    fi

    # POP3
    if [ $port -eq 110 ] || [ $port -eq 995 ];then
		echo -e "\e[94mPOP3 端口扫描开始 ..... \e[0m"
        nmap -p $port -iL ./${3}/${port}.txt -Pn -sS -sV -n -vv --open -oN ./Pop3.txt >/dev/null 2>&1
    fi

    # IMAP
    if [ $port -eq 143 ] || [ $port -eq 993 ];then
		echo -e "\e[94mIMAP 端口扫描开始 ..... \e[0m"
		nmap -p $port -iL ./${3}/${port}.txt -Pn -sS -sV -n -vv --open -oN ./Imap.txt >/dev/null 2>&1
    fi

    # SMTP
    if [ $port -eq 25 ]  || [ $port -eq 465 ] || [ $port -eq 587 ];then
        echo -e "\e[94mSMTP 端口扫描开始 ..... \e[0m"
		nmap -p $port -iL ./${3}/${port}.txt -Pn -sS -sV -n -vv --open -oN ./Smtp.txt >/dev/null 2>&1
        # 可选检测脚本 smtp-vuln-cve2019-15846.nse
    fi
	
	# Zimbra 默认管理控制台
    if [ $port -eq 7071 ] ;then
		echo -e "\e[94mZimbra 端口扫描开始 ..... \e[0m"
        nmap -p $port -iL ./${3}/${port}.txt -Pn -sS -sV -n -vv --open --script=http-headers.nse,http-title.nse -oN ./Zimbra.txt >/dev/null 2>&1
    fi
	
    # VNC
    if [ $port -eq 5900 ];then
		echo -e "\e[94mVNC 端口扫描开始 ..... \e[0m"
        nmap -p $port -iL ./${3}/${port}.txt -Pn -sS -sV -n -vv --open -oN ./Vnc.txt >/dev/null 2>&1
    fi

    # DNS
    if [ $port -eq 53 ];then
		echo -e "\e[94mDNS 端口扫描开始 ..... \e[0m"
        nmap -p $port -iL ./${3}/${port}.txt -Pn -sS -sV -n -vv --open -oN ./DNS.txt >/dev/null 2>&1
    fi

    # CouchDB
    if [ $port -eq 5984 ];then
		echo -e "\e[94mCouchDB 端口扫描开始 ..... \e[0m"
        nmap -p $port -iL ./${3}/${port}.txt -Pn -sS -sV -n -vv --open -oN ./CouchDB.txt >/dev/null 2>&1
    fi

    # FortiOS SSLVPN
    if [ $port -eq 10443 ];then
		echo -e "\e[94mFortiOS SSLVPN 端口扫描开始 ..... \e[0m"
        nmap -p $port -iL ./${3}/${port}.txt -Pn -sS -sV  -vv --open --script=http-vuln-cve2018-13379.nse -oN ./FortiVpn.txt >/dev/null 2>&1
        # 可选检测脚本 http-vuln-cve2018-13379.nse
    fi

    # ike-version
    if [ $port -eq 500 ];then
		echo -e "\e[94mike-version 端口扫描开始 ..... \e[0m"
        nmap -p $port -iL ./${3}/${port}.txt -Pn -sS -sV -n -vv --open -oN ./Ike.txt >/dev/null 2>&1
        # 可选检测脚本 ike-version.nse
    fi

    # SOCKS
    if [ $port -eq 1080 ];then
		echo -e "\e[94mSOCKS 端口扫描开始 ..... \e[0m"
        nmap -p $port -iL ./${3}/${port}.txt -Pn -sS -sV -n -vv --open -oN ./Socks.txt >/dev/null 2>&1
    fi

    # Nessus
    if [ $port -eq 1241 ];then
		echo -e "\e[94mNessus 端口扫描开始 ..... \e[0m"
        nmap -p $port -iL ./${3}/${port}.txt -Pn -sS -sV -n -vv --open -oN ./Nessus.txt >/dev/null 2>&1
    fi

	# JavaRmi
    if [ $port -eq 1099 ];then
		echo -e "\e[94mJavaRmi 端口扫描开始 ..... \e[0m"
        nmap -p $port -iL ./${3}/${port}.txt -Pn -sS -sV -n -vv --open -oN ./JavaRmi.txt >/dev/null 2>&1
    fi

	# Vmware Exsi
    if [ $port -eq 902 ] ;then
		echo -e "\e[94mVmware Exsi 端口扫描开始 ..... \e[0m"
        nmap -p $port -iL ./${3}/${port}.txt -Pn -sS -sV -n -vv --open --script=vmware-version.nse,vmauthd-brute.nse -oN ./Vmware_Exsi.txt >/dev/null 2>&1
        echo -e "\033[35m尝试爆破目标 Vmware Exsi,请耐心等待...\033[0m"
		echo root > /usr/local/share/nmap/nselib/data/usernames.lst
		nmap -p 902 -iL ./${3}/${port}.txt -Pn -sS -sV -n -vv --open --script=vmware-version.nse,vmauthd-brute.nse --script-args ssh-brute.timeout=5s -oN ./Vmware_Exsi_login.txt >/dev/null 2>&1
		echo -e "\033[35mVmware Exsi 爆破完毕 ! 结果已存到当前目录的Vmware_Exsi_login.txt文件中\033[0m"
    fi

    ends=`date +'%Y-%m-%d %H:%M:%S'`
    start_sec=$(date --date="$starts" +%s);
    end_sec=$(date --date="$ends" +%s);
    final=$((end_sec-start_sec));
    echo -e "\033[33$port端口扫描完毕, 共计耗时 $final 秒 \033[0m\n"

done

echo -e "\n\n\n\e[94m===================================================================================\e[0m"
endtime=`date +'%Y-%m-%d %H:%M:%S'`
start_seconds=$(date --date="$starttime" +%s);
end_seconds=$(date --date="$endtime" +%s);
sec=$((end_seconds-start_seconds));
val=$(((end_seconds-start_seconds)/60));
echo -e "\n\e[91m所有端口 & IP段已全部扫描完毕, 共计耗时 $val 分 | $sec 秒 \e[0m\n"
echo -e "\e[94m===================================================================================\e[0m\n\n"

# 删除空文件
for file in  ./${3}/*.txt
do
    if [ ! -s $file ]
	then
		rm -fr $file
	fi
done


