
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
                    fk_logid             integer NOT NULL ,  # 外键 对应LOGS( id )
                    event_datetime       datetime NOT NULL,
                    event_description    varchar(400),
                    # 级联删除 级联更新
                    FOREIGN KEY ( fk_logid ) REFERENCES LOGS( id ) ON DELETE CASCADE ON UPDATE CASCADE);
            """)
        except Exception as e:
            pass

        # 在fk_logid 上建立索引 ？
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


    def saveEvent( self, parentID, eventTime, eventDescription ):
        """This method adds add a record to the LOGS table
        @param: string - absolute path including name of the log
        @param: string - description of the log"""
        try:
            # add child record
            # note: eventTime needs to be a string of this format: yyyy-MM-dd HH:mm:ss
            # format string obtained from https://docs.python.org/2/library/datetime.html#strftime-and-strptime-behavior
            eventDescription = eventDescription.replace("'", "")
            sql_statement = "INSERT INTO LOGEVENTS (fk_logid, event_datetime, event_description) VALUES ( {0}, '{1}', '{2}');" \
                            .format(parentID, eventTime.strftime("%Y-%m-%d %H:%M:%S"), eventDescription)
            self.cursor.execute( sql_statement )
            self.connection.commit()
        except Exception as e:
            pass
        finally:
            pass


    def displayLogContents( self, logID):
        """This method displays every record in LOGEVENTS associated with a log file
        @param: string - THe LogID associated with all the events you want to see"""
        self.cursor.execute("SELECT id, event_datetime, event_description FROM LOGEVENTS WHERE fk_logid=={0} ORDER BY event_datetime;".format(logID))
        rows = self.cursor.fetchall()
        for eventID, eventDateTime, eventDescription in rows:
            print(eventID, eventDateTime, eventDescription)



    def listLogIDs( self ):
        """This method displays all LogIDs only and associated names stored in the 'LinuxLogs.py'"""
        self.cursor.execute("SELECT id, log_file FROM LOGS ORDER BY id;")
        rows = self.cursor.fetchall()
        for logID, logName in rows:
            print(logID, logName)


    def queryEventsDateTimeWindow( self, startDateTime, endDateTime):
        """This method displays every event accross all Logs that are within the given start and end dates (inclusive)
        @param: datetime - Start date/time of the window you wish events be displayed
        @param: datetime - End date/time of the window you wish events be displayed"""
        queryStr = "SELECT LOGS.id, LOGS.log_name, LOGEVENTS.event_datetime, LOGEVENTS.event_description " +\
                   "FROM LOGS, LOGEVENTS WHERE LOGS.id = LOGEVENTS.fk_logid AND "
        queryStr = queryStr + "LOGEVENTS.event_datetime >= Datetime('{0}') AND LOGEVENTS.event_datetime <= Datetime('{1}') ".format(startDateTime, endDateTime)
        queryStr = queryStr + "ORDER BY LOGEVENTS.event_datetime;"
        self.cursor.execute( queryStr )
        rows = self.cursor.fetchall()
        for logID, logName, eventDateTime, eventDescription in rows:
            print("{0:>3}  {1:<20}  {2}    {3}".format(logID, logName, eventDateTime, eventDescription))


    def queryEventsSalientStr( self, stringMatch ):
        """Searches the 'LinuxLogs.db' database for all events that contain a string within their description.
        Use 'root' if, for example, you want to search for all events that contain 'root' anywhere within their event description field.
        @param: string - a keyword representing an item from a 'hit list' or 'black list'"""
        queryStr = "SELECT LOGS.id, LOGS.log_name, LOGEVENTS.event_datetime, LOGEVENTS.event_description " +\
                   "FROM LOGS, LOGEVENTS WHERE LOGS.id = LOGEVENTS.fk_logid AND "
        queryStr = queryStr + "LOGEVENTS.event_description LIKE '%{0}%' ".format(stringMatch)
        queryStr = queryStr + "ORDER BY LOGEVENTS.event_datetime;"
        self.cursor.execute( queryStr )
        rows = self.cursor.fetchall()
        for logID, logName, eventDateTime, eventDescription in rows:
            print("{0:>3}  {1:<20}  {2}    {3}".format(logID, logName, eventDateTime, eventDescription))

