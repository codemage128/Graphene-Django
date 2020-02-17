import sqlite3
from sqlite3 import Error
import time
from plugin_setting import dbfilename
import json

def create_connection(db_file):
   conn = None
   try:
      conn = sqlite3.connect(db_file)
      return conn
   except Error as e:
      print(e)
   return conn
def create_table(conn, creat_table_sql):
   try:
      c = conn.cursor()
      c.execute(creat_table_sql)
      conn.commit()
   except Error as e:
      print(e)
def main():
   # time.sleep(6)
   database = dbfilename
   sql_create_results = """CREATE TABLE IF NOT EXISTS results(
      id integer PRIMARY KEY,
      uuid text,
      task integer,
      host text,
      port text,
      nvt text,
      type text,
      description text,
      report text,
      nvt_version text,
      severity text,
      qod integer,
      qod_type text,
      owner integer,
      date integer
   );"""
   sql_create_nvt_cves = """CREATE TABLE IF NOT EXISTS nvt_cves(
      nvt text,
      oid text,
      cve_name text);"""
   conn = create_connection(database)
   if conn is not None:
      create_table(conn, sql_create_results)
      create_table(conn, sql_create_nvt_cves)
      for row in range(20):
         uuid1 = "uuid234"
         task = str(row)
         host = "192.16.16.8"
         port = "8000"
         nvt = "nvt" + str(row)
         type = "Type" + str(row)
         report = "report" + str(row)
         nvt_version = "Version" + str(row)
         severity = "8.0" 
         qod = "1"
         qod_type = "firmanalyzer_detection"
         owner = "Mine"
         data = "Today"
         description = '{"firmware_version": "1.5.6","manufacturer": "microsoft","model": "hp4.6"}'
         sql_insert_result = "INSERT into results (uuid, task,  host,  port,  nvt,  type,  report,  nvt_version , severity, description, qod, qod_type, owner, date) VALUES (" + "'" + uuid1 + "','" + task  + "','" + host + "','" + port  + "','" + nvt + "','" + type  + "','" + report  + "','" + nvt_version + "','" + severity  + "','" + description + "','" + qod  + "','" + qod_type  + "','" + owner  + "','" + data + "')"
         #create_table(conn, sql_insert_result);
   else:
      print("Error! Can not create the database connection")
if __name__ == '__main__':
    main()