#encoding: utf-8
#! /usr/bin/python
#
#  文件名:    LinuxLogs.py
#  版本:     1.0
#  介绍: 它是一个整合Linux日志的工具，使取证调查者能够查询所有事件
#在一个事件周围的时间窗口内(即+/- 3秒，用户可调)的所有日志。LinuxLogs能够
#搜索感兴趣的字符串。“脏话”、“黑名单”、“黑名单”等)，因为所有的事件都在一个方便的
# 关系数据库。
#
#               a  project for 数字取证  at NYU.edu
#
#               The following Linux logs are processed:
#
#                     '/var/log/dmesg'
#                     '/var/log/messages'
#                     '/var/log/syslog'
#                     '/var/log/auth'
#                     '/var/log/daemon'
#                     '/var/log/dpkg'
#                     '/var/log/kern'
#                     '/var/log/Xorg'
#                     '/var/log/alternatives'
#                     '/var/log/cups'
#                     '/var/log/cron'
#                     '/var/log/wtmp'
#                     '/var/run/utmp'
#                     '/var/log/btmp'
#                     '/var/log/user'
#                     '/var/log/secure'
#                     
#  
#  Notes/Observations:
#
#      1) 未来的改进
            # a)合并两个offset类
            # b)将RTC相关的变量从父类中重构到offset类中
            # c)支持输出。csv格式的查询结果
            # d)添加支持日志趋势按天/周/月/季度/年
            # e)添加对自动监控和显著性触发和变更的支持
            # d)添加GUI支持
            # f)添加对许多许多其他日志的支持
#
#      2) 部分日志为二进制或加密日志。使用“last -f /path/to/log”命令以可读的格式访问它们的内容
            # /var/run/utmp
            # /var/log/wtmp
            # /var/log/btmp
            #此外，/var/log/btmp需要根权限来在活动系统上进行读访问;然而，在法医分析日志时
            #(从一个磁盘映像并将所有文件解压缩到一个目录中)这个脚本将使用——root选项读取/var/log/btmp日志

#      3) 以下日志的内容中没有日期和/或时间，因此不适合此脚本的目的
        # a)/var/log/boot
        # b) /var/log/lastlog
#
#       4) /var/log/anaconda.log在我开发的Ubuntu Linux发行版中没有使用。因此，它没有被包括在内
        #在这个脚本的1.0版本中。但是，/var/log/anaconda.log处理将在未来的版本中加入到这个脚本中。

      # 5)日志/var/log/faillog被排除，因为它提供了当前的/var/log/btmp文件已经提供的信息

#被解析的日志文件。
#
#
#
#
#
#  更新日志:
#               06/15/2014   Create initial version. Created LinuxLog shell class and tested reading-in all logs
#               06/23/2014   Add support to parse /var/log/dmesg
#               06/24/2014   Add support to normalize time in /var/log/dmesg by using "RTC time: 14:13:21, date: 06/28/14"
#                            along with the event offset i.e. [    0.178863]
#               06/27/2014   Add support for 4 additional types of logs
#               07/03/2014   Desig database tables along with drop/create capabilities
#               07/05/2014   Parsed log data in a db friendly format
#               07/08/2014   Add support to store log file metadata to the parent LOG database table
#               07/12/2014   Add support to store event logs to child LOGEVENTS database table while maintaining the
#                            database relationship between the parent LOG record and the  children records in LOGEVENTS table
#               07/15/2014   Add support for arguments and all options along with their respective arguments if applicable.
#                            Validate all arguments to minimize avoid
#               07/19/2014   Add support for custom root directory other than the default Linux root directory, '/'. This
#                            feature is essential for Forensic Investigators in which they would extract a disk image
#                            either with a 'dd', a 'tar' or similar commands.
#               07/20/2014   Add support to read each log's archive version which come in two flavors: logname.version and logname.version.gz
#                            The reasoning behind this is to be complete and capture all log events.
#               07/20/2014   Add support to remove duplicates cause by reading in all archived versions of a log
#               07/21/2014   Timing analysis for dmesg log family and made some minor adjustments.
#               07/24/2014   Added support for utmp, wtmp and btmp logs
#
#
#
#



# /var/log/messages—包含全局系统消息，包括系统启动时记录的消息。在/var/log/messages中记录了一些内容，包括邮件、cron、守护进程、kern、auth等。
# /var/log/dmesg -内核环缓冲区信息。当系统启动时，它会在屏幕上打印一些消息，这些消息显示内核在启动过程中检测到的硬件设备的信息。这些消息在内核循环缓冲区中可用，每当新消息出现时，旧消息就会被覆盖。您也可以使用dmesg命令查看该文件的内容。
# /var/log/auth.log -系统授权信息，包括用户登录和使用的认证机制。
# /var/log/boot.log—系统启动时记录的信息
# /var/log/daemon.log—包含系统上运行的各种后台守护进程的日志信息
# /var/log/dpkg.log -使用dpkg命令安装或删除包时记录的信息
# /var/log/kern.log—内核的日志信息。对您排除自定义内核故障很有帮助。
# /var/log/lastlog—显示所有用户最近的登录信息。这不是一个ascii文件。您应该使用lastlog命令来查看该文件的内容。
# /var/log/maillog /var/log/mail.log—系统运行的邮件服务器的日志信息。例如，sendmail记录所有发送到此文件的项目的信息
# /var/log/user.log -包含所有用户级别的日志信息
# /var/log/Xorg.x.log - X . Log日志
# /var/log/alternatives.log -更新的信息被记录到这个日志文件。在Ubuntu上，update-alternatives维护决定默认命令的符号链接。
# /var/log/btmp—该文件包含登录失败的信息。使用最后一条命令查看btmp文件。例如，" last -f /var/log/btmp | more "
# /var/log/cups—所有打印机和打印相关的日志信息
# /var/log/anaconda.log—安装Linux操作系统时，所有与安装相关的消息都保存在该日志文件中
# /var/log/yum.log -包含使用yum安装包时记录的信息
# /var/log/cron—每当cron守护进程(或anacron)启动cron作业时，它都会将有关cron作业的信息记录在这个文件中
# /var/log/secure—包含与认证和授权权限相关的信息。例如，sshd记录这里的所有消息，包括不成功的登录。
# /var/log/wtmp或/var/log/utmp -登录记录。使用wtmp可以找出谁登录了系统。Who命令使用该文件显示信息。
# /var/log/faillog—包含用户登录失败的次数。使用faillog命令显示该文件的内容。




# 使用的库文件
from __future__ import print_function
import gc
import os
import re
import sys
from sys import stdout
import glob
import gzip
import sets
import time
import types
from datetime import datetime, date
import datetime
import sqlite3
import logging
import argparse
import subprocess




# feng *__

# -- dbLogs 类 --------------------------------------------------------------------------------------------
class dbLogs(object):
    """类将所有direcect接口封装到数据库"""
    def __init__(self, **kwargs):
        """sqlite3 构造器 连接数据库"""
        self.connection = sqlite3.connect('LinuxLogs.db') # 连接数据库
        self.cursor = self.connection.cursor() # 获取游标


    def createDBitems(self):
        """创建表 和索引"""
        try:
            self.cursor.execute("""
                CREATE TABLE LOGS (
                    id                   INTEGER PRIMARY KEY,
                    log_file             varchar(60)  NOT NULL,
                    log_name             varchar(30)  NOT NULL,
                    log_description      varchar(400) NOT NULL);
                    """)
        except Exception as e:
            pass

        try:
            self.cursor.execute("""
                CREATE TABLE LOGEVENTS (
                    id                   integer PRIMARY KEY AUTOINCREMENT,
                    fk_logid             integer NOT NULL , 
                    event_datetime       datetime NOT NULL,
                    event_description    varchar(400),
                    
                    FOREIGN KEY ( fk_logid ) REFERENCES LOGS( id ) ON DELETE CASCADE ON UPDATE CASCADE);
            """)
        except Exception as e:
            pass

        try:
            self.cursor.execute(
            """
                    CREATE INDEX idx_LOGEVENTS ON LOGEVENTS ( fk_logid );
            """)
        except Exception as e:
            pass
        finally:
            pass


    def dropDBitems(self):
        """删除表和索引的方法"""
        try:
            self.cursor.execute("DROP INDEX idx_LOGEVENTS;")
        except Exception as e:
            pass

        try:
            self.cursor.execute("DROP TABLE LOGEVENTS;")
        except Exception as e:
            pass

        try:
            self.cursor.execute("DROP TABLE LOGS;")
        except Exception as e:
            pass

    #LOGS table 上增加一条记录
    def createParentRecord(self, logName, logLocationAbsolutePath, logDescription):
        """
        参数：
        @param: string - 日志名
        @param: string - 日志全路劲（包括名字）
        @param: string - 日志描述
        """
        parentID = 0 # init
        #find new key value for a new parent record
        self.cursor.execute("SELECT MAX(id) FROM LOGS;")
        parentID = self.cursor.fetchone()[0] # fetchone 获取一条消息
        if parentID == None: # 如果表中没有记录
            parentID = 1
        else:
            parentID += 1
        print("[*] new parent ID={0} for log: '{1}'".format(parentID, logLocationAbsolutePath))
        try:
            # add parent record
            # 单引号需要转义
            logDescription = logDescription.replace("'", "")
            # 插入一条record 记录
            sql_statement = "INSERT INTO LOGS (id, log_name, log_file, log_description) VALUES ( {0}, '{1}', '{2}', '{3}');" \
                            .format(parentID, logName, logLocationAbsolutePath, logDescription)
            self.cursor.execute( sql_statement )
            self.connection.commit()
        except Exception as e:
            pass
        finally:
            pass
        return parentID


    #  父记录和子记录的区别是什么？
    def saveEvent( self, parentID, eventTime, eventDescription ):

        """LOGEVENTS 表中添加一条事件记录

        @param: string - absolute path including name of the log
        @param: string - description of the log"""
        try:
            # # 添加子记录
            # 注意：eventTime 需要是以下格式的字符串：yyyy-MM-dd HH：mm：ss
            print('******',parentID,eventTime,eventDescription)
            eventDescription = eventDescription.replace("'", "")
            sql_statement = "INSERT INTO LOGEVENTS (fk_logid, event_datetime, event_description) VALUES ( {0}, '{1}', '{2}');" \
                            .format(parentID, eventTime.strftime("%Y-%m-%d %H:%M:%S"), eventDescription)
            self.cursor.execute( sql_statement )
            self.connection.commit()
        except Exception as e:
            pass
        finally:
            pass


    # feng@function :传入日志ID  根据LogID 查询到所有的events事件
    def displayLogContents( self, logID):
        """
            This method displays every record in LOGEVENTS associated with a log file
            两张表 通过外键连接起来
        """
        self.cursor.execute("SELECT id, event_datetime, event_description FROM LOGEVENTS WHERE fk_logid=={0} ORDER BY event_datetime;".format(logID))
        rows = self.cursor.fetchall()
        for eventID, eventDateTime, eventDescription in rows:
            print(eventID, eventDateTime, eventDescription) # 打印事件id 事件 描述信息


    # @function   显示LOGS表中的所有日志id与记录
    def listLogIDs( self ):
        """此方法仅显示所有 LogID 和存储在 'LinuxLogs.py'"""
        self.cursor.execute("SELECT id, log_file FROM LOGS ORDER BY id;")
        rows = self.cursor.fetchall()
        for logID, logName in rows:
            print(logID, logName)

    #  feng @ 此方法显示给定开始日期和结束日期内的所有日志中的每个事件
    # 参数 startDateTime      endDateTime
    def queryEventsDateTimeWindow( self, startDateTime, endDateTime):
        # 连表查询 id 连接
        queryStr = "SELECT LOGS.id, LOGS.log_name, LOGEVENTS.event_datetime, LOGEVENTS.event_description " +\
                   "FROM LOGS, LOGEVENTS WHERE LOGS.id = LOGEVENTS.fk_logid AND "
        # 使用Datetime函数 转化成Datetime类型
        queryStr = queryStr + "LOGEVENTS.event_datetime >= Datetime('{0}') AND LOGEVENTS.event_datetime <= Datetime('{1}') ".format(startDateTime, endDateTime)
        # 根据事件进行排序
        queryStr = queryStr + "ORDER BY LOGEVENTS.event_datetime;"
        self.cursor.execute( queryStr )
        rows = self.cursor.fetchall() # 获取所有数据
        for logID, logName, eventDateTime, eventDescription in rows:
            print("{0:>3}  {1:<20}  {2}    {3}".format(logID, logName, eventDateTime, eventDescription))


    # 根据字符串在数据库中查找
    def queryEventsSalientStr( self, stringMatch ):
        """在 LinuxLogs.db 数据库中搜索在其描述中包含指定字符串的所有事件。
        例如，如果要搜索  其事件描述字段中含有root字段的所有事件，请使用‘root’。
        """
        queryStr = "SELECT LOGS.id, LOGS.log_name, LOGEVENTS.event_datetime, LOGEVENTS.event_description " +\
                   "FROM LOGS, LOGEVENTS WHERE LOGS.id = LOGEVENTS.fk_logid AND "
        # 通过like查询    %str% 的方式全局匹配   并且根据事件类型排序
        queryStr = queryStr + "LOGEVENTS.event_description LIKE '%{0}%' ".format(stringMatch)
        queryStr = queryStr + "ORDER BY LOGEVENTS.event_datetime;"
        self.cursor.execute( queryStr )
        rows = self.cursor.fetchall()
        for logID, logName, eventDateTime, eventDescription in rows:
            print("{0:>3}  {1:<20}  {2}    {3}".format(logID, logName, eventDateTime, eventDescription))






# -- 父级-日志解析器类LogReaderStdParser 为所有日志读取器定义通用方法  其他解析器类均以此为参数 --------------------------------------------------------------------------------------------
class LogReaderStdParser:
    """这个类知道如何以下面的格式解析日志条目，并为所有日志读取器定义通用方法。
        实例化所有日志日志实体的格式如下：
        'Jul 11 17:54:32 <servername> <LogEntrySource>: <LogEntryDescription>'
    For example:
        'Jul 11 17:54:32 SpiderMan kernel: imklog 5.8.11, log source = /proc/kmsg started.'
    """


    def __init__(self, logName, logLocationAbsolutePath, logDescription):
        """LogReader类和所有继承类的构造函数
        @param: string - The name of the log
        @param: string - The absolute path to the log (i.e. '/log/var/dmesg')
        @param: string - The description of the log"""
        
        global db
        self.logName = logName
        self.logLocationAbsolutePath = logLocationAbsolutePath
        self.logDescription = logDescription
        self.count = 0
        self.parentRecordID = db.createParentRecord(self.logName, self.logLocationAbsolutePath, self.logDescription)
        self.events = set()
        self.readLogFile()
        self.saveEventsToDB()

    def readLogFile(self):
        """从日志文件（及其所有目录，即auth.log、auth.log.1、auth.log.2.gz等）读取日志实体，对其进行解析并将其保存到数据库中"""

        filenamePattern = self.logLocationAbsolutePath+"*"

        for file in glob.glob(filenamePattern):
            # 我们有一个新文件，所以需要重置RTC，因为RTC与它们所在的一个文件相关
            self.waitingForRTC = True; 
            self.preRTC = []
            c=0
            try:
                if( file.endswith('.gz')):
                    with gzip.open(file) as file_object:
                        for line in file_object:
                            c+=1
                            print("    [*] {0:>12,} log entires parsed for file: '{1}'.".format(c, file), end="\r")
                            line = line.rstrip() # remove training whitespaces including '\n'
                            self.decode_entry(line)
                else:
                    with open(file) as file_object:
                        for line in file_object:
                            c+=1
                            print("    [*] {0:>12,} log entires parsed for file: '{1}'.".format(c, file), end="\r")
                            line = line.rstrip() # remove training whitespaces including '\n'
                            self.decode_entry(line)
            except Exception as e:
                pass
            else:
                print(" ")


    def getLogName(self):
        """Returns the name of the log"""
        logName = self.logName
        return logName


    def getLoglogLocationAbsolutePath(self):
        """Returns the absolute path of the log"""
        logName = self.logLocationAbsolutePath
        return logName


    def getRecordCount(self):
        """Returns the number of records associated with this log"""
        count = self.count
        return count


    def saveEventsToDB( self ):
        """This method interfaces with db to save the events that have been gathered so far"""
        c=0
        
        try:
            global db
            for logID, eventDateTime, eventDescription in self.events:
                c+=1
                print("[*] saving {0:>8,} unique log entires for the '{1}' system log to 'LinuxLogs.db'".format(c, self.logLocationAbsolutePath), end = "\r")
                db.saveEvent( logID, eventDateTime, eventDescription )
        except Exception as e:
            pass
        print("[*] saved {0:>8,} unique log entires for the '{1}' system log to 'LinuxLogs.db'".format(c, self.logLocationAbsolutePath))
        print(" ")
        


    def saveEvent( self, logID, eventDateTime, eventDescription ):
        """将日志事件保存到内部“事件”集中。这里使用Set的唯一属性，以避免处理归档版本的日志可能引入的重复
        @param: datetime - The date and time at which the log event occured
        @param: string - The description of the log event"""
        try:
            self.events.add((logID, eventDateTime, eventDescription))
        except Exception as e:
            pass


    def decode_entry(self, singleLogEntry):
        """此方法知道如何以以下格式解析日志条目      @param: string - The log entry (event date/time and description)"""
        eventTime = 0
        eventDescription = ""
        try:
            # format string obtained from https://docs.python.org/2/library/datetime.html#strftime-and-strptime-behavior
            # target data '2014 Jul 11 17:54:32'
            eventTime = datetime.datetime.strptime(str(date.today().year)+ " " + singleLogEntry[:15], "%Y %b %d %H:%M:%S")
            
            #description is after the fourth space
            splitOnSpaces = singleLogEntry.split(' ')
            eventDescription = (' '.join(splitOnSpaces[:4]), ' '.join(splitOnSpaces[4:]))[1]
            self.saveEvent( self.parentRecordID, eventTime, eventDescription)
        except Exception as e:
            pass
        finally:
            return eventTime, eventDescription




# -- LogReaderParser classes --------------------------------------------------------------------------------------------
class LogReaderParserYYYYMMDD(LogReaderStdParser):
    """该类继承LogReaderStdParser类的形式，并覆盖必要的方法
        要分析格式的日志实体，请执行以下操作：
    Use this class to read all log entires of the format:
        'YYYY-MM-DD HH:MM:SS <LogEntryDescription>'
    For example:
        '2014-07-07 20:00:15 install simplescreenrecorder:i386 <none> 0.3.0-4~ppa1~saucy1'"""
        
    def decode_entry(self, singleLogEntry):
        """此方法解析表单的日志条目: 'YYYY-MM-DD HH:MM:SS <LogEntryDescription>'
        @param: string - The log entry (event date/time and description)"""
        try:
            #format string obtained from https://docs.python.org/2/library/datetime.html#strftime-and-strptime-behavior
            eventDescription = singleLogEntry[20:]
            eventTime = datetime.datetime.strptime(singleLogEntry[:19], "%Y-%m-%d %H:%M:%S")
            self.saveEvent( self.parentRecordID, eventTime, eventDescription)
        except Exception as e:
            pass




# -- LogReaderParserTextDate classes --------------------------------------------------------------------------------------------
class LogReaderParserTextYYYYMMDD(LogReaderStdParser):
    """该类继承LogReaderStdParser类的形式，并覆盖必要的方法解析格式的日志实体:
    
        'some-text YYYY-MM-DD HH:MM:SS <LogEntryDescription>'
         
    For example:
    
        'update-alternatives 2014-07-01 15:43:11: link group wish updated to point to /usr/bin/wish8.5'
    """

    def decode_entry(self, singleLogEntry):
        """This method parses a log entry of the form: 'some-text YYYY-MM-DD HH:MM:SS <LogEntryDescription>'
        @param: string - The log entry (event date/time and description)"""
        try:
            splitOnSpaces = singleLogEntry.split(' ')
            eventDescription = ' '.join(splitOnSpaces[3:])
            #format string obtained from https://docs.python.org/2/library/datetime.html#strftime-and-strptime-behavior
            eventTime = datetime.datetime.strptime(splitOnSpaces[1] + ' ' + splitOnSpaces[2][:8], "%Y-%m-%d %H:%M:%S")
            self.saveEvent( self.parentRecordID, eventTime, eventDescription)
        except Exception as e:
            pass


# -- LogReaderParserTextDateInSquareBrackets classes --------------------------------------------------------------------------------------------
class LogReaderParserTextDateInSquareBrackets(LogReaderStdParser):
    """This class inherits form the LogReaderStdParser class and overwrides the necessary methods
    to parse the log entires of the format:
    
    Use this class to read all log entires of the format:
    
        'some-text [MM/MMM/YYYY:HH:MM:SS -UTC] some-text'
         
    For example:
    
        'localhost - - [12/Jul/2014:06:52:52 -0700] "POST / HTTP/1.1" 401 186 Renew-Subscription successful-ok'
    """

    def decode_entry(self, singleLogEntry):
        """This method parses a log entry of the form: 'some-text YYYY-MM-DD HH:MM:SS <LogEntryDescription>'
        @param: string - The log entry (event date/time and description)"""
        try:
            start = singleLogEntry.find('[')
            end =  singleLogEntry.find(']')
            
            eventDescription = singleLogEntry[end+3:]
            #format string obtained from https://docs.python.org/2/library/datetime.html#strftime-and-strptime-behavior
            #target format: '12/Jul/2014:06:52:52'
            eventTime = datetime.datetime.strptime(singleLogEntry[start+1:end-6], "%d/%b/%Y:%H:%M:%S")
            self.saveEvent( self.parentRecordID, eventTime, eventDescription)
        except Exception as e:
            pass


# -- LogReaderOffsetParserDMESG classes --------------------------------------------------------------------------------------------
class LogReaderOffsetParserDMESG(LogReaderStdParser):
    """This class inherits form the LogReaderStdParser class but overwrides the necessary methods to parse logs that are
    offset-based instead of date-time based as in the parent class.
    
    Use this class to read all log entires of the format:
    
        '[ offset sec]  <LogEntrySource>: <LogEntryDescription>'
         
    For example:
    
        '[    0.178426] RTC time: 22:01:31, date: 07/10/14           <-- notice RTC time comes in eventually!'
    """


    def __init__(self, logName, logLocationAbsolutePath, logDescription):
        """Constructor for the class that knows how to parse the /var/log/dmesg log, this is a child class of LogReaderOffsetParserDMESG
        @param: string - The name of the log
        @param: string - The absolute path to the log (i.e. '/log/var/dmesg')
        @param: string - The description of the log
        """
        self.waitingForRTC = True
        self.RTC = 0
        self.preRTC = []
        LogReaderStdParser.__init__(self, logName, logLocationAbsolutePath, logDescription)


    def extractTimeFromLogEntry(self, singleLogEntry):
        """ extract offset and description and store them into a preRTS list as a temporarily holding structure
        until we read-in RTC which will enable us to convert from offset to evnet time
        @param: string - The description of a log entry"""

        endOfseconds = singleLogEntry.find("]")
        
        # note: Rounding is more appropriate for our case than truncating
        try:
            offsetSecondsSincePowerOn = int( round( float(singleLogEntry[1:endOfseconds]) ) )
        except Exception as e:
            offsetSecondsSincePowerOn = 0
        return offsetSecondsSincePowerOn


    def decode_entry(self, singleLogEntry):
        """This method normalizees time in /var/log/dmesg by using "RTC time: 14:13:21, date: 06/28/14
        @param: string - The description of a log entry"""
        if( self.waitingForRTC == True ):
            #look for RTC
            foundRTCat = singleLogEntry.find("RTC time:")  
            if( foundRTCat != -1 ):
                # if did found clock time then store it for future events, and use it to calculate event
                # timestamps of all previously stored event logs in 'preRTC' list this will put us up-to-date 
                self.RTCstr = singleLogEntry[ foundRTCat+10: ]
                if( self.RTCstr[0]==' '):
                    self.RTCstr = self.RTCstr.lstrip()
                    self.RTCstr = "0"+self.RTCstr
                try:
                    #format string obtained from https://docs.python.org/2/library/datetime.html#strftime-and-strptime-behavior
                    self.RTC = datetime.datetime.strptime(self.RTCstr, "%H:%M:%S, date: %m/%d/%y")
                    self.waitingForRTC = False;
                    self.saveEvent( self.parentRecordID, self.RTC, singleLogEntry[foundRTCat:])

                    # adjust/normalize from offset to local time
                    for item in self.preRTC:
                        eventTime = self.RTC + datetime.timedelta(0, item[0])
                        self.saveEvent( self.parentRecordID, eventTime, item[1])
                    # empty the preRTC because all items have been saved and reset it for the next possible log file within this log family
                    self.preRTC = []
                except Exception as e:
                    pass
            else:
                # extract offset and description and store them into a preRTS list as a temporarily holding structure
                # until we read-in RTC which will enable us to convert from offset to evnet time
                endOfseconds = singleLogEntry.find("]")
                eventDescription = singleLogEntry[endOfseconds+2:]
                
                # note: Rounding is more precise if we want to query on a plus or minus windows in seconds
                offsetSecondsSincePowerOn = self.extractTimeFromLogEntry( singleLogEntry )
                self.preRTC.append( [offsetSecondsSincePowerOn, eventDescription])
        else:
            #if already have clock, then use it to calculate time of log entry
            eventDescription = singleLogEntry[singleLogEntry.find("]")+2:]
            offsetSecondsSincePowerOn = self.extractTimeFromLogEntry( singleLogEntry )
            eventTime = self.RTC + datetime.timedelta(0,offsetSecondsSincePowerOn)
            self.saveEvent(self.parentRecordID, eventTime, eventDescription)
        pass


# -- LogReaderOffsetParserXORG classes --------------------------------------------------------------------------------------------
class LogReaderOffsetParserXORG(LogReaderStdParser):
    """This class inherits form the LogReaderStdParser class but overwrides the necessary methods to parse logs that are
    offset-based instead of date-time based as in the parent class.
    
    Use this class to read all log entires of the format:
    
        '[ offset sec]  <LogEntrySource>: <LogEntryDescription>'
         
    For example:
    
        [     4.124] (==) Log file: "/var/log/Xorg.0.log", Time: Mon Jul 14 20:48:05 2014   <-- notice RTC time comes in eventually!
    """


    def __init__(self, logName, logLocationAbsolutePath, logDescription):
        """Constructor for the class that knows how to parse the /var/log/dmesg log, this is a child class of LogReaderOffsetParserDMESG
        @param: string - The name of the log
        @param: string - The absolute path to the log (i.e. '/log/var/dmesg')
        @param: string - The description of the log
        """
        self.waitingForRTC = True
        self.RTC = 0
        self.preRTC = []
        LogReaderStdParser.__init__(self, logName, logLocationAbsolutePath, logDescription)


    def extractTimeFromLogEntry(self, singleLogEntry):
        """ extract offset and description and store them into a preRTS list as a temporarily holding structure
        until we read-in RTC which will enable us to convert from offset to evnet time
        @param: string - The description of a log entry"""

        endOfseconds = singleLogEntry.find("]")
        
        # note: Rounding is more appropriate for our case than truncating
        try:
            offsetSecondsSincePowerOn = int( round( float(singleLogEntry[1:endOfseconds]) ) )
        except Exception  as e:
            offsetSecondsSincePowerOn = 0
        return offsetSecondsSincePowerOn


    def decode_entry(self, singleLogEntry):
        """This method normalizees time in /var/log/dmesg by using 'Log file: "/var/log/Xorg.0.log", Time: Mon Jul 14 20:48:05 2014'
        @param: string - The description of a log entry"""
        if( self.waitingForRTC == True ):
            #look for RTC
            marker1 = singleLogEntry.find("Log file:")  
            if( marker1 != -1 ):
                foundRTCat = singleLogEntry.find(", Time: ")
                if( foundRTCat!= -1): 
                    
                    # if did found clock time then store it for future events, and use it to calculate event
                    # timestamps of all previously stored event logs in 'preRTC' list this will put us up-to-date 
                    self.RTCstr = singleLogEntry[ foundRTCat+8: ] #this should give us something of the form 'Mon Jul 14 20:48:05 2014' w/o quotes
                    try:
                        #format string obtained from https://docs.python.org/2/library/datetime.html#strftime-and-strptime-behavior
                        self.RTC = datetime.datetime.strptime(self.RTCstr, "%a %b %d %H:%M:%S %Y")
                        self.waitingForRTC = False;
                        self.saveEvent( self.parentRecordID, self.RTC, singleLogEntry[marker1-5:])
    
                        # adjust/normalize from offset to local time
                        for item in self.preRTC:
                            eventTime = self.RTC + datetime.timedelta(0, item[0])
                            self.saveEvent( self.parentRecordID, eventTime, item[1])
                    except Exception as e:
                        pass
            else:
                # extract offset and description and store them into a preRTS list as a temporarily holding structure
                # until we read-in RTC which will enable us to convert from offset to evnet time
                endOfseconds = singleLogEntry.find("]")
                if( endOfseconds!=-1):
                    eventDescription = singleLogEntry[endOfseconds+2:]
                    if( eventDescription!="" ): 
                        # note: Rounding is more precise if we want to query on a plus or minus windows in seconds
                        offsetSecondsSincePowerOn = self.extractTimeFromLogEntry( singleLogEntry )
                        self.preRTC.append( [offsetSecondsSincePowerOn, eventDescription])
        else:
            #if already have clock, then use it to calculate time of log entry
            eventDescription = singleLogEntry[singleLogEntry.find("]")+2:]
            offsetSecondsSincePowerOn = self.extractTimeFromLogEntry( singleLogEntry )
            eventTime = self.RTC + datetime.timedelta(0,offsetSecondsSincePowerOn)
            self.saveEvent(self.parentRecordID, eventTime, eventDescription)
        pass



# -- LogReader_UTMP_WTMP_Parser classes --------------------------------------------------------------------------------------------
class LogReader_UTMP_WTMP_Parser (LogReaderStdParser):
    """该类继承了LogReaderStdParser类的形式，但过度使用了必要的方法来解析

在父类中，基于偏移量而不是基于日期时间。

/var/run/utmp文件将为您提供用户登录终端的完整图片，

注销、系统事件和系统当前状态、系统启动时间（正常运行时间使用）等。

使用“last-f/var/run/utmp”查看内容。

/var/log/wtmp提供utmp的历史数据。使用“last-f/var/log/wtmp”查看内容。

注意：last-f/var/log/wtmp===just last
    
    Example 'last' command output:

    carlos   pts/0        :0               Tue Jul 22 20:03   still logged in   
    carlos   pts/1        :0               Tue Jul 22 18:53 - 20:18  (01:25)    
    reboot   system boot  3.11.0-23-generi Tue Jul 22 18:53 - 20:43  (01:50)    
    carlos   pts/3        :0               Tue Jul 22 16:48 - 18:52  (02:03)    
    carlos   pts/3        :0               Mon Jul 21 15:21 - 21:05  (05:44)

    wtmp begins Wed Jul  2 23:30:12 2014 """


    def readLogFile(self):
        """This method reads every line of text of every log files associated with this class"""
        try:
            subprocess_output = subprocess.check_output(["last"]) # note: last -f /var/log/wtmp ====  last
            c=0
            for line in subprocess_output.splitlines():
                c += 1
                print("    [*] {0:>12,} log entires parsed for file: '{1}'.".format(c, file), end="\r")
                self.decode_entry( line )
        except Exception as e:
            pass


    def decode_entry(self, singleLogEntry):
        """This method decodes log entries for the /var/log/wtmp log file"
        @param: string - The a single line in the log containing the date, time and description of the event"""
        try:
            #extract one event only: log-in
            #format string obtained from https://docs.python.org/2/library/datetime.html#strftime-and-strptime-behavior
            eventTime =  datetime.datetime.strptime(singleLogEntry[39:55]+":00 "+str(date.today().year) , "%a %b %d %H:%M:%S %Y") # of the form 'Tue Jul 22 20:03:00 2014'
            self.saveEvent( self.parentRecordID, eventTime, "Log-in: "+singleLogEntry)
    
            if( singleLogEntry.find("still logged in") == -1 ):
                #extract extra event: log-out
                #                                                   'Tue Jul 22'  '20:18'
                eventTime =  datetime.datetime.strptime(singleLogEntry[39:49]+" "+singleLogEntry[58:63]+ ":00 "+str(date.today().year) , "%a %b %d %H:%M:%S %Y") # of the form 'Tue Jul 22 20:03:00 2014'
                self.saveEvent( self.parentRecordID, eventTime, "Log-off: "+singleLogEntry)
        except Exception as e:
            pass
        pass




# -- LogReader_BTMP_Parser classes --------------------------------------------------------------------------------------------
class LogReader_BTMP_Parser(LogReaderStdParser):
    """The /var/log/btmp records only failed login attempts. Use 'last -f /var/log/btmp' to view contents.
    Use 'last -f /var/log/btmp' to view contents. Note: there may be more logs in this family, so use
    a pattern of last -f /var/log/btmp* to select them.
    
    Example 'last -f /var/log/btmp' command output:

    carlos   ssh:notty    localhost        Tue Jul 22 20:04    gone - no logout"""

    def readLogFile(self):
        """This method reads every line of text of every log files associated with this class"""
        filenamePattern = self.logLocationAbsolutePath+"*"
        for file in glob.glob(filenamePattern):
            c=0
            try:
                with open(file) as file_object:
                    for line in file_object:
                        c+=1
                        print("    [*] {0:>12,} log entires parsed for file: '{1}'.".format(c, file), end="\r")
                        line = line.rstrip() # remove training whitespaces including '\n'
                        try:
                            subprocess_output = subprocess.check_output(["last", "-f", file]) 
                            for line in subprocess_output.splitlines():
                                self.decode_entry( line )
                        except Exception as e:
                            pass
            except Exception  as e:
                pass
            else:
                print(" ")


    def decode_entry(self, singleLogEntry):
        """This method decodes log entries for the /var/log/wtmp log file"
        @param: string - The a single line in the log containing the date, time and description of the event"""
        try:
            #extract one event only: log-in
            #format string obtained from https://docs.python.org/2/library/datetime.html#strftime-and-strptime-behavior
            eventTime =  datetime.datetime.strptime(singleLogEntry[39:55]+":00 "+str(date.today().year) , "%a %b %d %H:%M:%S %Y") # of the form 'Tue Jul 22 20:03:00 2014'
            self.saveEvent( self.parentRecordID, eventTime, "Faild login: "+singleLogEntry)
        except Exception as e:
            pass
        pass







#--[ start of main program ]-----------------------------------------------------------------------------------------------------

db = dbLogs() # 实例化数据库对象  产生LinuxLogs.db

def readLogs( customRootDir="" ):
    """
        使用列表来实例化和保存我们所有的日志对象
        如果/var的文件被拷贝到其他目录了  我们就可以指定customRootDir 对指定目录下的log文件进行分析
    """
    # 创建文件路径变量，这些变量会考虑由 --rootDir 选项传入的参数
    # 常用方法
    filepath_dmesg        = "{0}/var/log/dmesg".format(customRootDir)
    filepath_cron         = "{0}/var/log/cron".format(customRootDir)
    filepath_messages     = "{0}/var/log/messages".format(customRootDir)
    filepath_syslog       = "{0}/var/log/syslog".format(customRootDir)
    filepath_auth         = "{0}/var/log/auth".format(customRootDir)
    filepath_dpkg         = "{0}/var/log/dpkg".format(customRootDir)
    filepath_kern         = "{0}/var/log/kern".format(customRootDir)
    filepath_deamon       = "{0}/var/log/daemon".format(customRootDir)
    filepath_xorg         = "{0}/var/log/Xorg".format(customRootDir)
    filepath_alternatives = "{0}/var/log/alternatives".format(customRootDir)
    filepath_cupsaccess   = "{0}/var/log/cups/access_log".format(customRootDir)
    filepath_utmp_wtmp    = "{0}/var/log/wtmp".format(customRootDir)
    filepath_btmp         = "{0}/var/log/btmp".format(customRootDir)
    filepath_user         = "{0}/var/log/user".format(customRootDir)


    # 开始实例化不同类型的日志读取器，每个实例化
    # 分析日志并将其存储到数据库中。请注意，父类
    # 有一些我们没有使用的额外帮助程序方法，但可用
    # 适用于此脚本的其他开发人员
    #
    #
    
    # dmesg log 解析器
    LogReaderOffsetParserDMESG( 
        "dmesg log", filepath_dmesg, "内核环缓冲区 ring buffer 信息。当系统启动时，它会在屏幕上打印一些消息\
        ，这些消息显示内核在启动过程中检测到的硬件设备的信息。这些消息在内核循环缓冲区中可用，\
        每当新消息出现时，旧消息就会被覆盖。您也可以使用dmesg命令查看该文件的内容。")

        #样例数据 :
        #$ cat /var/log/dmesg
        #[    0.177904] PM: Registering ACPI NVS region [mem 0x49f4e000-0x49f54fff] (28672 bytes)
        #[    0.178401] regulator-dummy: no parameters
        #[    0.178426] RTC time: 22:01:31, date: 07/10/14    <-- notice RTC time comes in eventually!
        #[    0.178448] NET: Registered protocol family 16
        #...
    #gc 释放内存
    logReader = 0
    gc.collect()


    # xorg log 解析器
    LogReaderOffsetParserXORG("xorg log", filepath_xorg, "Contains a log of messages from the X"),
        #sample log:
        #$ cat Xorg.0.log
        #...
        #[     4.124] Current version of pixman: 0.30.2
        #[     4.124] Before reporting problems, check http://wiki.x.org
        #[     4.124] Markers: (--) probed, (**) from config file, (==) default setting,
        #[     4.124] (==) Log file: "/var/log/Xorg.0.log", Time: Mon Jul 14 20:48:05 2014   <-- notice RTC time comes in eventually!
        #[     4.124] (==) Using config file: "/etc/X11/xorg.conf"
        #[     4.124] (==) Using system config directory "/usr/share/X11/xorg.conf.d"
    #deallocate/release memory that we do not need anymore
    logReader = 0
    gc.collect()

    # messages log 解析器
    logReader = LogReaderStdParser(
        "messages log", filepath_messages, "Contains global system messages, "+ \
        "including the messages that are logged during system startup. Several "+ \
        "things are in this log, such as: mail, cron, daemon, kern, auth, etc."),
        #sample log:
        #$ head /var/log/messages
        #Jul 11 17:54:32 SpiderMan kernel: imklog 5.8.11, log source = /proc/kmsg started.
        #Jul 11 17:54:32 SpiderMan rsyslogd: [origin software="rsyslogd" swVersion="5.8.11" x-pid="8532" x-info="http://www.rsyslog.com"] start
        #Jul 11 17:54:32 SpiderMan rsyslogd: rsyslogd's groupid changed to 103
        #Jul 11 17:54:32 SpiderMan rsyslogd: rsyslogd's userid changed to 101
    #gc 释放内存
    logReader = 0
    gc.collect()


    #syslog log 解析器
    logReader = LogReaderStdParser(
        "syslog log", filepath_syslog, "Syslog is a way for network devices to send "+ \
        "event messages to a logging server, usually known as a Syslog server. Most "+ \
        "network equipment, like routers and switches, can send Syslog messages. Not only "+ \
        "that, but *nix servers also have the ability to generate Syslog data, as do most "+ \
        "firewalls, some printers, and even web-servers like Apache. "),
        #sample log:
        #$ head /var/log/syslog
        #Jun 29 07:39:42 SpiderMan rsyslogd: [origin software="rsyslogd" swVersion="5.8.11" x-pid="580" x-info="http://www.rsyslog.com"] rsyslogd was HUPed
        #Jun 29 07:39:48 SpiderMan anacron[11496]: Job `cron.daily' terminated
        #Jun 29 07:39:48 SpiderMan anacron[11496]: Normal exit (1 job run)
        #Jun 29 07:43:36 SpiderMan whoopsie[978]: online
    logReader = 0
    gc.collect()


    # auth log 认证日志解析器
    logReader = LogReaderStdParser(
        "auth log", filepath_auth, "Contains system authorization information, "+ \
        "including user logins and authentication machinsm that were used."),
        #sample log:
        #$ head /var/log/auth.log
        #Jul 11 17:53:22 SpiderMan sudo: pam_unix(sudo:session): session opened for user root by carlos(uid=0)
        #Jul 11 17:54:32 SpiderMan sudo:   carlos : TTY=pts/3 ; PWD=/home/carlos ; USER=root ; COMMAND=/sbin/restart rsyslog
        #Jul 11 17:54:32 SpiderMan sudo: pam_unix(sudo:session): session opened for user root by carlos(uid=0)
        #Jul 11 18:34:59 SpiderMan dbus[507]: [system] Rejected send message, 3 matched rules; type="method_return", sender=":1.66" (uid=1000 pid=2090 comm="/usr/bin/pulseaudio --start --log-target=syslog ") interface="(unset)" member="(unset)" error name="(unset)" requested_reply="0" destination=":1.2" (uid=0 pid=622 comm="/usr/sbin/bluetoothd ")
    #deallocate/release memory that we do not need anymore
    logReader = 0
    gc.collect()


    # dpkg log 解析器
    logReader = LogReaderParserYYYYMMDD(
        "dpkg log", filepath_dpkg, "Records all the apt activities, such as installs "+ \
        "or upgrades, for the various package managers (dpkg, apt-get, synaptic, aptitude)."),
        #sample log:
        #$ head /var/log/dpkg.log
        #2014-07-04 16:55:36 trigproc desktop-file-utils:i386 0.21-1ubuntu3 0.21-1ubuntu3
        #2014-07-04 16:55:36 status half-configured desktop-file-utils:i386 0.21-1ubuntu3
        #2014-07-04 16:55:36 status installed desktop-file-utils:i386 0.21-1ubuntu3
        #2014-07-04 16:55:36 trigproc gnome-menus:i386 3.8.0-1ubuntu5 3.8.0-1ubuntu5
    #deallocate/release memory that we do not need anymore
    logReader = 0
    gc.collect()


    # kern log  内核日志解析器
    logReader = LogReaderStdParser(
        "kern log", filepath_kern, "Contains information logged by the kernel. "+ \
        "Helpful for you to troubleshoot a custom-built kernel."),
        #sample log:
        #$ head /var/log/kern.log
        #Jul 10 15:01:36 SpiderMan kernel: [    5.052266] wlan0: authenticate with 10:bf:48:53:c7:90
        #Jul 10 15:01:36 SpiderMan kernel: [    5.055880] wlan0: send auth to 10:bf:48:53:c7:90 (try 1/3)
        #Jul 10 15:01:36 SpiderMan kernel: [    5.058578] wlan0: authenticated
        #Jul 10 15:01:36 SpiderMan kernel: [    5.058631] wlan0: waiting for beacon from 10:bf:48:53:c7:90
        #Jul 10 15:01:36 SpiderMan kernel: [    5.109448] wlan0: associate with 10:bf:48:53:c7:90 (try 1/3)
        #Jul 10 15:01:36 SpiderMan kernel: [    5.112845] wlan0: RX AssocResp from 10:bf:48:53:c7:90 (capab=0x411 status=0 aid=4)
        #Jul 10 15:01:36 SpiderMan kernel: [    5.114950] wlan0: associated
    #deallocate/release memory that we do not need anymore
    logReader = 0
    gc.collect()


    # cron log 解析器
    logReader = LogReaderStdParser(
        "cron log", filepath_cron, "Whenever cron daemon (or anacron) starts a cron job, it "+ \
        "logs the information about the cron job in this file"),
        #sample log:
        #$ head /var/log/cron.log
        #Jul 12 08:17:01 SpiderMan CRON[5040]: (root) CMD (   cd / && run-parts --report /etc/cron.hourly)
    #deallocate/release memory that we do not need anymore
    logReader = 0
    gc.collect()


    # daemon log 线程日志解析器
    logReader = LogReaderStdParser(
        "daemon log", filepath_deamon, "Contains information logged by the "+ \
        "various background daemons that runs on the system"),
        #sample log:
        #$ head /var/log/daemon.log
        #Jul 12 08:04:20  whoopsie[1020]: last message repeated 4 times
        #Jul 12 08:05:20  whoopsie[1020]: last message repeated 2 times
        #Jul 12 08:09:02 SpiderMan whoopsie[1020]: online
        #Jul 12 08:15:16  whoopsie[1020]: last message repeated 5 times
    #deallocate/release memory that we do not need anymore
    logReader = 0
    gc.collect()


    # alternatives log 变更日志(比入软硬链接等) 解析器
    logReader = LogReaderParserTextYYYYMMDD(
        "alternatives log", filepath_alternatives, "Information by the "+ \
        "update-alternatives are logged into this log file. On Ubuntu, update-alternatives "+ \
        "maintains symbolic links determining default commands."),
        #sample log:
        #$ head /var/log/alternatives.log
        #update-alternatives 2014-07-01 15:43:11: link group tclsh updated to point to /usr/bin/tclsh8.5
        #update-alternatives 2014-07-01 15:43:11: link group wish updated to point to /usr/bin/wish8.5
        #update-alternatives 2014-07-02 23:29:03: run with --remove x-www-browser /usr/bin/chromium-browser
        #update-alternatives 2014-07-04 07:53:48: link group mailx updated to point to /usr/bin/heirloom-mailx
    #deallocate/release memory that we do not need anymore
    logReader = 0
    gc.collect()


    # cups access log 解析器
    logReader = LogReaderParserTextDateInSquareBrackets(
        "cups access log", filepath_cupsaccess, "The access_log file lists each HTTP resource that "+ \
        "is accessed by a web browser or client. Each line is in an extended version of the so-called 'Common "+ \
        "Log Format' used by many web servers and web reporting tools")
        #sample log:
        #$ head /var/log/cups/access_log
        #localhost - - [12/Jul/2014:06:52:52 -0700] "POST / HTTP/1.1" 401 186 Renew-Subscription successful-ok
        #localhost - carlos [12/Jul/2014:06:52:52 -0700] "POST / HTTP/1.1" 200 186 Renew-Subscription successful-ok
        #localhost - - [12/Jul/2014:07:06:52 -0700] "POST / HTTP/1.1" 401 186 Renew-Subscription successful-ok
        #localhost - carlos [12/Jul/2014:07:06:52 -0700] "POST / HTTP/1.1" 200 186 Renew-Subscription successful-ok
    #deallocate/release memory that we do not need anymore
    logReader = 0
    gc.collect()


    # 用户日志解析器
    logReader = LogReaderStdParser(
        "user log", filepath_user, "Contains information about all user level logs")
        #sample log:
        #$ head /var/log/cups/access_log
        #Jul 20 12:23:50 SpiderMan mtp-probe: bus: 3, device: 8 was not an MTP device
        #Jul 21 18:10:31 SpiderMan pulseaudio[2114]: [bluetooth] bluetooth-util.c: Failed to release transport /org/bluez/656/hci0/dev_00_0C_8A_6E_0E_B5/fd10: Method "Release" with signature "s" on interface "org.bluez.MediaTransport" doesn't exist
        #Jul 22 18:53:07 SpiderMan mtp-probe: checking bus 3, device 6: "/sys/devices/pci0000:00/0000:00:14.0/usb3/3-9/3-9.1"
        #Jul 22 18:53:12 SpiderMan pulseaudio[1845]: [pulseaudio] pid.c: Daemon already running.
    #deallocate/release memory that we do not need anymore
    logReader = 0
    gc.collect()


    # utmp  wtmp 日志 解析器
    logReader = LogReader_UTMP_WTMP_Parser(
        "utmp & wtmp logs", filepath_utmp_wtmp, "The /var/run/utmp file will give you " +\
        "complete picture of users logins at which terminals, logouts, system events and " +\
        "current status of the system, system boot time (used by uptime) etc. Use 'last " +
        "\-f /var/run/utmp' to view contents. The /var/log/wtmp gives historical data of utmp ")
        #sampel log:
        #$ last -f /var/log/wtmp
        #
        #carlos   pts/0        :0               Tue Jul 22 20:03   still logged in   
        #carlos   pts/1        :0               Tue Jul 22 18:53 - 20:18  (01:25)    
        #reboot   system boot  3.11.0-23-generi Tue Jul 22 18:53 - 20:43  (01:50)    
        #carlos   pts/3        :0               Tue Jul 22 16:48 - 18:52  (02:03)    
        #carlos   pts/3        :0               Mon Jul 21 15:21 - 21:05  (05:44)
        #
        #wtmp begins Wed Jul  2 23:30:12 2014 """
    #deallocate/release memory that we do not need anymore
    logReader = 0
    gc.collect()


    # BTMP 日志解析器
    logReader = LogReader_BTMP_Parser(
        "btmp log", filepath_btmp, "The /var/log/btmp records only failed login attempts. " +\
        "Use 'last -f /var/log/btmp' to view contents. Use 'last -f /var/log/btmp' to view " +\
        "contents. Note: there may be more logs in this family, so use a pattern of last  " +\
        "-f /var/log/btmp* to select them.")
    #deallocate/release memory that we do not need anymore
    logReader = 0
    gc.collect()


def databaseReset():
    """
    重置数据库  建立一个空的库
    """
    db.dropDBitems()
    db.createDBitems()


def main(argv):
    """main 函数      解析用户输入"""
    # reference: https://docs.python.org/2/howto/argparse.html
    parser = argparse.ArgumentParser(description='Linux系统日志分析&取证系统')
    parser.add_argument("--resetDB",help="删除数据库并重新读取日志",  action='store_true') #optional
    parser.add_argument("--contents",help="显示LinuxLogs的内容。LogID指定的一个日志的db",
                                                        type=int, metavar="logID")  #optional w/argument
    parser.add_argument("--query",help="搜索LinuxLogs数据库，数据库中的所有事件，在 +- N秒内"+\
                                                       "从特定日期/时间开始。“dateTimeStr”应该是这种格式 'YYYY-MM-DD hh:mm:ss, N' "+\
                                                       "例如: '2014-02-19 19:07:05, 3' 将列出所有日志时间处于"+\
                                                       "'2014-02-19 19:07:02' 和 '2014-02-19 19:07:08' (含)之间的所有事件.", \
                                                       type=str, metavar="dateTimeStr")  #optional w/argument
    parser.add_argument("--logs",help="列出LinuxLogs.db中存储的所有Logid和相关日志名。", action='store_true')  #optional
    parser.add_argument("--rootDir",help="将Linux磁盘映像解压缩到所选目录时，请使用此选项。必须提供您具有读取权限的绝对路径。警告：这将导致“LinuxLogs”。要在新的根目录中擦除的数据库和要重新读取的日志。\
                                        例如：如果将磁盘映像提取到主目录中名为“forensicTree”的子目录中，则应使用“/home/yourname/forensicTree”", type=str, metavar="newRootDir")  #optional w/argument
    parser.add_argument("--stringMatch",help="搜索“LinuxLogs”。数据库中包含描述中包含字符串的所有事件。例如，如果要在事件描述字段中的任何位置搜索包含“root”的所有事件，请使用“root”。", \
                                        type=str, metavar="descriptionStr")  #optional w/argument

    try:
        args=parser.parse_args()
    except Exception as e:
        pass

    if( args.resetDB ):
        print("[*] resetDB detected")
        databaseReset()
        readLogs()

    if( args.logs ):
        print("[*] logs detected")
        db.listLogIDs()

    if( args.contents!=None ):
        print("[*] contents with LogID={0} detected".format(args.contents))
        db.displayLogContents(args.contents)

    if( args.query!=None ):
        print("[*] query with datetimeStr='{0}' detected".format(args.query))
        #validate input
        formatAccepted = False
        splitQueryStr = args.query.split(',')
        try:
            parsedDateTime = datetime.datetime.strptime(splitQueryStr[0], "%Y-%m-%d %H:%M:%S")
        except Exception as e:
            print("Opps! The DATE-TIME part of the query string you typed does not conform to the format: 'YYYY-MM-DD hh:mm:ss', please try again.")
        else:
            try:
                isInteger = isinstance( int(splitQueryStr[1]), (int, long))
            except Exception  as e:
                print("Opps! The 'N' part of the query string you typed was not recognized and an integer, please try again.")
            else:
                print("[*]format accepted")
                #compute START-of-window-datetime and END-of-window-datetime
                try:
                    startOfWindow = parsedDateTime - datetime.timedelta(0, int(splitQueryStr[1]))
                    endOfWindow   = parsedDateTime + datetime.timedelta(0, int(splitQueryStr[1]))
                    print("[*]startOfWindow = '{0}' to endOfWindow = '{1}'".format(str(startOfWindow), str(endOfWindow)))
                    db.queryEventsDateTimeWindow( startOfWindow, endOfWindow)
                except Exception as e:
                    pass

    if( args.stringMatch!=None ):
        print("[*] query with stringMatch='{0}' detected".format(args.stringMatch))
        db.queryEventsSalientStr( args.stringMatch )

    if( args.rootDir!=None):
        print("[*] rootDir detected with '{0}'".format(args.rootDir))
        databaseReset()
        readLogs(args.rootDir)

    if( args.resetDB==False and
        args.logs==False and
        args.contents==None and
        args.query==None and
        args.stringMatch==None and
        args.rootDir==None ):
        
        print("[*] 未检测到任何选项，请输入 'LinuxLogs.py --help' 来获取有关如何使用此脚本的帮助 \n\n用户引导:\n\n" +\
              "如果你是取证人员, \n\n" +\
              "     以下是您必须按照指定顺序执行的步骤:\n\n" +\
              "     1. 将磁盘映像中的所有文件提取到子目录，例如，将它们提取到FooBarDir \n\n" +\
              "     2. 让这个脚本读取、解析并将日志存储到数据库“LinuxLogs”中。使用以下命令： $python LinuxLogs.py --rootDir 'FooBarDir' \n\n" +\
              
              "如果您是网络安全人员或系统管理员，\n\n" +\
              "     你必须先做这一步:\n\n" +\
              "     1. 让这个脚本读取、解析并将日志存储到“LinuxLogs”中。 数据库最好以root用户身份运行:  $sudo python LinuxLogs.py --resetDB (以root权限运行上述命令将授予您对/var/log/btmp日志文件的读取权限)\n\n" +\

              "一旦数据库被填充（见上文），您可以按照您想要的任何顺序多次执行以下任何或所有操作:\n\n" +\
              "     A. 查询哪些日志被解析并存储到“LinuxLogs”中'\n" +\
              "        使用这个命令:  $python LinuxLogs.py --logs \n\n" +\
              "     B. 查询整个日志以显示仅与存储在“LinuxLogs”中的一个logID关联的所有事件\n" +\
              "        使用这个命令:  $python LinuxLogs.py --contents 8 \n\n" +\
              "     C. 查询“LinuxLogs”。所有事件的数据库访问在日期/时间窗口内发生的所有日志 " +\
              "        使用这个命令:  $python LinuxLogs.py --query '2014-07-24 17:45:06, 2000' \n\n" +\
              "     D. 查询“LinuxLogs”。用于在其描述字段中包含感兴趣字符串的所有事件。\n"+\
              "        使用这个命令:  $python LinuxLogs.py --stringMatch 'chown' \n")


if __name__ == '__main__':
   main(sys.argv)
