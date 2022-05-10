疑问问题：

针对的是  服务器的优麒麟







## 日志命令



### rsyslog服务

rsyslog 采集内存中的系统日志  写入文件中  如果不开启  则不会写入文件

### rsyslog日志采集策略

采集规则如何设定？： 

/var/log/message  ##服务器信息日志

/var/log/secure  	##系统登入日志

/var/log/cron  		##定时任务日志

/var/log/maillog 	##邮件日志

/var/log/boot.log	##系统启动日志

vim  /etc/syslog.conf

RULES下  日志类型.日志级别             存放目录

auth.info 		/var/log/mylog



日志远程同步 也可以使用UDP  也可以TCP

可以采用自定义日志格式



journalctl 查看日志

journalctl --since 13:30 --until  13:36

journalctl     ==> /sshd

journalct -o verbose   ==> /pid  /3039

-p err 查看错误日志

journalctl  _PID=3132  -COMM=sshd



## Linux Shell编程

1.bash xx.sh 不需要执行权限  直接把文件给Bash去执行

2.如果是./去执行  则需要chmod a+x file

#!/bin/bash



##### 系统变量  

###### 查看系统变量 set

$HOME  $PWD  $SHELL $USER

##### 自定义变量

var=value     unset 变量   

1.字母数字下划线  2.等号两侧不能空格 3.Bash中变量默认都是字符串类型 4.变量的值有空格用引号或括号包裹  5.环境变量名建议大写

将变量提升为环境变量  供其他Shell 程序使用  

export 变量名

##### 特殊变量$n   

$0  代表脚本名       $1-9 代表参数

 $# 代表参数的个数

$* 和 $@ 代表所有的参数   区别：  $*把所有参数看成一个整体        $@ 把所有参数区分对待

$?   上一条正确执行返回0    没有正确执行返回非零值



### 运算符

1.$((运算式))  或 $[运算式)]

2.expr +,-,\\*,/,%  运算符之间需要有空格

```
expr `expr 3 \* 2` \* 4
s=$[(3*2)*4] #赋值之间不能有空格
echo $ss
```



### 条件判断

[ condition ]   condition 前后一定要空格

= 字符串比较   

-lt=>小于(less than)	-le=>小于等于(less equal) 	 -eq(equal)  -gt(greater than) 	

-ge(greater equal)   -gt(greater thab) -ne(not equal)

按照权限判断 	-r  -w  -x

按照文件类型判断 	-f 文件存在并且是常规文件(file)	-e文件存在(existense)	-d 文件存在并且是个目录

```
[root@localhost ~]# [ 23 -le 22 ]
[root@localhost ~]# echo $?
1

权限
[root@localhost ~]# [ -r run.sh ]
[root@localhost ~]# echo $?
0
[root@localhost ~]# [ -x run.sh ]
[root@localhost ~]# echo $?
1

文件类型
[root@localhost ~]# [ -e run1.py ]
[root@localhost ~]# echo $?
1
[root@localhost ~]# [ -e run.sh ]
[root@localhost ~]# echo $?
0

多条命令
[ condition ] || [  ]  && [  ]
```



### 流程控制

if

```
#!/bin/bash
if [ $1 -eq 1 ];then
        echo "hello 111"
elif    [ $1 -eq 2 ]
then
        echo " helllo 222"
fi
```

case

```
case $1 in 
"值1")
	todo
	;;
"值2")
	todo
	;;
*)
	todo 
	;;
esac

case $1 in
"1")#可以直接写1 默认都是字符串
        echo "1111"
        ;;
"2")
        echo "2222"
        ;;
*)
        echo "input none" 
        ;;
esac

```

for循环

```
for(( xx; xx ; xx))
	do
	xxx
	done
	 
s=0
for((a=1;a<=100;a++ ))
do
        # s= 赋值两边一定不能有括号
        s=$[$sum+$a]#不是expr 加号两边不用括号
done
echo $s # $sum 取值
               
for $1  in val1 val2  val3
do
	xxx
done

for i in $*   #分割成多个参数
do
        echo "hello $i"
done

for i in "$*"  #所有参数看为整体
do
        echo "hello $i"

done

for j in $@  # 加不加引号 都是分割的参数
do  
        echo "hello $j" 
done


```

while 循环

```
s=0
while [ $s -ne 10 ]
do
        echo $s 
        s=$[$s+1] #只有for循环里面可以使用i++
done

```



### read读取控制台输入

-t 延时等待  -p 提示信息   变量名

```
read  -p "input" -t 5  NAME
echo $NAME
```



### 函数

##### 系统函数

```
basename
basename [string/pathname][suffix]  找到最后一个'/'  截取后面的文件名  指定了suffix会删除后缀
dirname 返回剩下的路劲 
二者一般组合使用
```



##### 自定义函数

```
必须先定义函数再执行 	要注意顺序
函数返回值只能通过 $?系统变量获得  可以显示加:return返回  不加 将以最后一条命令的结果作为返回值 return后面跟[0-255]
[ function ] funname[()]
{
	Action;
	[return int;] #  #?
}


function sum()
{
        s=0
        s=$[$1+$2]
        echo $s
}
read -p "input p1" P1
read -p "input p2" P2
sum P1 P2

```



### Cut 命令

cut [参数] filename

-f 列号  取第几列

-d 分隔符  默认制表符

```
cut -d " " -f 1 cut.txt
cat xx | grep xx | cut -d  -f
获取第三列之后所有的 3-
cut -d ":" -f 3- cut.txt
切取ip地址
ifconfig ens33  | grep "inet "  | cut -d " " -f 10

```



### Sed命令

sed  [参数-e]  command filename

命令 a (增加)    d（删除）  s(查找并替换)

```

[root@localhost ~]# sed "2a mei nv" sed.txt
hello world 

mei nv
原文件没有改变

sed操作的默认是一行  删除还有"wo"的行
sed "/wo/d" sed.txt

把wo 替换为 ni
sed "s/wo/ni/g"  sed.txt
加g为全局 替换  不加只替换第一个

多个命令使用-e
sed  -e "2d"  -e "s/wo/ni/g" sed.txt

```



### awk命令

逐行读入  默认空格切片

-F 指定分隔符   -v 赋值一个用户定义的变量



```
切分以root开头的行 切完后 打印第七个数
[root@localhost ~]# awk -F ":" '/^root/ {print $7}'  /etc/passwd 
/bin/bash

[root@localhost ~]# awk -F ":" '/^root/ {print $1","$7}'  /etc/passwd 
root,/bin/bash


[root@localhost ~]# awk -F :  'BEGIN{print "user,shell"} {print $1","$7}  END{print "end of file"}' /etc/passwd
user,shell
root,/bin/bash
bin,/sbin/nologin
daemon,/sbin/nologin
adm,/sbin/nologin
lp,/sbin/nologin
sync,/bin/sync
shutdown,/sbin/shutdown
halt,/sbin/halt
mail,/sbin/nologin
operator,/sbin/nologin
games,/sbin/nologin
ftp,/sbin/nologin
nobody,/sbin/nologin
systemd-network,/sbin/nologin
dbus,/sbin/nologin
polkitd,/sbin/nologin
postfix,/sbin/nologin
sshd,/sbin/nologin
end of file



指定变量  注意 -v指定的变量  如果再{} 中使用$3代表对应的列   变量值就为1
[root@localhost ~]# awk -F : -v i=1 '{print $3+i}' /etc/passwd
1
2
3
4
5
6
7
8
9
12
13
15
100
193
82
1000
90
75


内置变量 
FILENAME 文件名
NR  已读的记录数
NF  切割后的列数
[root@localhost ~]# awk -F : '{print FILENAME  NR " " NF }' /etc/passwd


查看空行所在的行号
awk '/^$/ {print NR}' /etc/passwd
```





### sort 命令 

文件内容排序

-r 相反顺序 -n 数值大小 -t 排序时的分隔符  -k 需要排序的列

```
sort -t : -nrk  2 sort.txt
```



实战

```
awk '/^$/ {print NR}' passwd.txt

统计第二列的和
awk -F " " 'sum+=$2 END{print sum}' passwd.txt

shell 脚本检查文件是否存在 
if [ -e 1.txt ];then
	touch 1.txt

排序并综合
sort -n test.txt | 	awk 'sum+=$1;{print $1} END{print "Sum="sum}'

查找目录下面 所有包含“shen” 的文件 的名称
grep -r "sshd" /var/log | 

[root@localhost ~]# grep -r "sshd" /var/log| cut -d ":" -f 1|uniq -c
    586 /var/log/audit/audit.log
      3 /var/log/messages
     77 /var/log/secure
      4 /var/log/anaconda/journal.log


```













