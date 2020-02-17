from assets.models import AssetImport, Asset
from scans.models import Asset_OV_Vulnerabilites, OV_Vulnerabilities ,Vulnerabilities, Asset_Vulnerabilites, Asset_FirmwareDetail, FirmwareComponentDetail, Scan
from celery import shared_task
import os
import sys
import json
import subprocess 
import sqlite3
from sqlite3 import Error
from graphqlclient import GraphQLClient
from plugin_setting import dbfilename
import ipaddress

from django.conf import settings
GRAPHQl_SERVER_URL =  settings.SERVER_URL
GRAPHQl_SERVER_URL = 'http://localhost:4000/graphql'
API_KEY = settings.API_KEY
def connect_sqllite(database):
   conn = None
   try:
      conn = sqlite3.connect(database)
      return conn
   except Error as e:
      print(e)
   return conn
@shared_task
def versionDetection(idlist, scanid):
   scan = Scan.objects.get(pk=scanid)
   ovid = scan.ovid
   os.system('python versionDetection.py')
   database = dbfilename
   conn = connect_sqllite(database)
   if conn is not None:
      print("Database Connection Successfull!")
      cursor = conn.cursor()
      for item in idlist:
         asset = Asset.objects.get(pk=item)
         ipAddress =asset.ipAddress
         _bufIp = "";
         for ip in ipAddress.split("."):
            _bufIp = _bufIp +str(int(ip)) + "."
         _bufIp = _bufIp[:len(_bufIp) - 1]
         sql = "SELECT description from results where task=" + str(ovid) + " and host=" + "'" + _bufIp + "'" +  " and qod_type='firmanalyzer_detection'"
         cursor.execute(sql)
         for row in cursor:
            firmwareversion = json.loads(row[0])['firmware_version']
            asset.firmwareVersion = firmwareversion
            asset.save()
      return True
   else:
      print("Error! Can not create the database connection")
      return False
@shared_task
def fullactiveScan(idlist, scanid):
   scan = Scan.objects.get(pk=scanid)
   ovid = scan.ovid
   os.system('python fullactiveScan.py')
   database = dbfilename
   conn = connect_sqllite(database)
   if conn is not None:
      print("Database Connection Successfull!")
      cursor = conn.cursor()
      for item in idlist:
         asset = Asset.objects.get(pk=item)
         idAddress =asset.ipAddress
         _bufIp = "";
         for ip in idAddress.split("."):
            _bufIp = _bufIp + str(int(ip)) + "."
         _bufIp = _bufIp[:len(_bufIp) - 1]
         sql = "SELECT nvt_cves.cve_name, results.severity, results.host, results.port, results.description from results join nvt_cves on results.nvt = nvt_cves.oid where task=" + str(ovid) + " and host=" + "'" + _bufIp + "'"
         cursor.execute(sql)
         for row in cursor:
            cveid = row[0]
            severity = row[1]
            host = row[2]
            port = row[3]
            location = host + ":" +  port
            description = row[4]
            ov_vul = OV_Vulnerabilities(cveid=cveid, vulnname="None", severity=severity, location=location, description=description)
            ov_vul.save()
            asset_ov_vul = Asset_OV_Vulnerabilites(assetid_id=asset.id, ovid_id=ov_vul.id, scanid=scanid)
            asset_ov_vul.save()
   else:
      print("Error! Can not create the database connection")
@shared_task
def vulnerabilityscan(idlist, scanid):
   client = GraphQLClient(GRAPHQl_SERVER_URL)
   _strquery = "SELECT A.id as id,  cveid, A.id as aid from assets_asset as A join scans_asset_ov_vulnerabilites as B on A.id = B.assetid_id join scans_ov_vulnerabilities as C on C.id = B.ovid_id"
   for ovitem in Asset_OV_Vulnerabilites.objects.raw(_strquery):
      cveid = ovitem.cveid
      asset_id = ovitem.aid
      query = """query{getVulnerabilities(cveid: """ + '"' + cveid + '"'  +""", apikey: """ + '"' + API_KEY + '"' + """){
            cveid
            cvss
            cwe
            references
            summary
         }
      }"""
      res = client.execute(query)
      vulList = json.loads(res)['data']['getVulnerabilities']
      for item in vulList:
         cveid = item['cveid']
         cvss = item['cvss']
         cwe = item['cwe']
         references = item['references']
         summary = item['summary']
         vul = Vulnerabilities(cveid=cveid, cwe=cwe, cvss=cvss, summary=summary, references=references)
         vul.save()
         asset_vul = Asset_Vulnerabilites(assetid_id=asset_id, vulid_id=vul.id, scanid=scanid)
         asset_vul.save()
@shared_task
def firmwarescan(idlist, scanid):
   client = GraphQLClient(GRAPHQl_SERVER_URL)
   for row in idlist:
      asset = Asset.objects.get(pk=row)
      _manufacturer = asset.manufacturer
      _model = asset.model
      _version = asset.firmwareVersion
      queryversion = """query{
        getLastestVersion(apikey: """ + '"' + API_KEY + '"' + """){
          version
        }
      }"""
      resultversion = client.execute(queryversion)
      versionList = json.loads(resultversion)['data']['getLastestVersion']
      lastestversion = versionList[0]['version']
      if asset.firmwareVersion != lastestversion:
         asset.lastestfirmwareversion = lastestversion
         asset.outdated = True
         asset.save()
      query = """
      query{
         getFirmwareHash(manufacturer: """ + '"' + _manufacturer + '", model: "' + _model + '", version: "' + _version + '"' +  """, apikey: """ + '"' + API_KEY + '"' +"""){
            manufacturer
            model
            version
            firmware_name
            firmware_hash
            release_date
            discontinued
         }
      }"""
      res = client.execute(query)
      firmwarelist = json.loads(res)['data']['getFirmwareHash']
      for firmware in firmwarelist:
         manufacture = firmware['manufacturer']
         model = firmware['model']
         version = firmware['version']
         if manufacture == _manufacturer and model == _model and version == _version:
            firmware_name = firmware['firmware_name']
            firmware_hash = firmware['firmware_hash']
            asset.discontinued = firmware['discontinued']
            query_analyzed = """
               query{
                  getAnlyzedFirmwares(firmware_hash: """ +'"' + firmware_hash + '"'+""", apikey: """ + '"' + API_KEY + '"' +"""){
                     firmware_name
                     firmware_hash
                     checksum
                     ComponentName
                     Version
                     vulnerabilities
                     issues{
                        name
                        warning
                     }
                  }
               }"""
            res_analyzed = client.execute(query_analyzed)
            firmwareanalyzedlist = json.loads(res_analyzed)['data']['getAnlyzedFirmwares']
            for analyzed in firmwareanalyzedlist:
               if firmware_name == analyzed['firmware_name']:
                  firmwaredetail = FirmwareComponentDetail(firmwarename=firmware_name, firmwarehash=firmware_hash, checksum=analyzed['checksum'], componentname=analyzed['ComponentName'], version=analyzed['Version'], vulnerabilities=','.join(analyzed['vulnerabilities']), issues=json.dumps(analyzed['issues']))
                  firmwaredetail.save()
                  asset_firmwareDetail = Asset_FirmwareDetail(assetid_id=asset.id, fdetailid_id=firmwaredetail.id, scanid=scanid)
                  asset_firmwareDetail.save()
                  _hash = analyzed['firmware_hash'];
                  _cveid = analyzed['vulnerabilities'];
                  for id in _cveid:
                     query = """query{getVulnerabilities(cveid: """ + '"' + id + '"'  +"""){
                              cveid
                              cvss
                              cwe
                              references
                              summary
                           }
                        }"""
                     res = client.execute(query)
                     vulList = json.loads(res)['data']['getVulnerabilities']
                     for item in vulList:
                        cveid = item['cveid']
                        cvss = item['cvss']
                        cwe = item['cwe']
                        references = item['references']
                        summary = item['summary']
                        vul = Vulnerabilities(cveid=cveid, cwe=cwe, cvss=cvss, summary=summary, references=references)
                        vul.save()
                  if firmware_hash is not analyzed['firmware_hash']:
                     asset.isFirmwareScanned = True
            asset.save()