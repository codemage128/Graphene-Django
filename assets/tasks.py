import string
import pyodbc

from assets.models import AssetImport, Asset
from celery import shared_task

@shared_task
def connectMSDB(assetimportId):
   assetimport = AssetImport.objects.get(pk=assetimportId)
   information = assetimport.info
   dbinfo = information.split(", ")
   server = dbinfo[0]
   database = dbinfo[1]
   connectionString = "Driver={ODBC Driver 17 for SQL Server};Server=" + server + ";Database=" + database + ";Trusted_Connection=yes;";
   conn = pyodbc.connect(connectionString)
   cursor = conn.cursor()
   cursor.execute('SELECT * FROM dbo.tblAssets')
   my_object = []
   for row in cursor:
      my_object.append(row)
      name = row.AssetName
      ipAddress = "row.IPAddress"
      macAddress = "row.Mac"
      manufacturer = "None"
      model = "None"
      assetType = "row.Assettype"
      operatingSystem = "row.OScode"
      firmwareVersion = "None"
      description = "row.Description"
      isFirmwareScanned = True
      asset = Asset(name=name, ipAddress=ipAddress, macAddress=macAddress, manufacturer=manufacturer, model=model, firmwareVersion=firmwareVersion,
      isFirmwareScanned=isFirmwareScanned, assetType=assetType, operatingSystem=operatingSystem, description=description)
      asset.save()