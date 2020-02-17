import graphene
from graphene_django.types import DjangoObjectType
from assets.models import AssetGroup, AssetImport, Asset
from graphene_file_upload.scalars import Upload
import pandas as pd
import csv
from io import StringIO
import json
from .tasks import connectMSDB
from datetime import date
import xlrd
from openpyxl import load_workbook
import numpy as np

class AssetType(DjangoObjectType):
   class Meta:
      model=Asset
class AssetGroupType(DjangoObjectType):
   class Meta:
      model = AssetGroup
class AssetImportType(DjangoObjectType):
   class Meta:
      model = AssetImport
class CreateAssetGroup(graphene.Mutation):
   assetGroup = graphene.Field(AssetGroupType)
   class Arguments:
      id = graphene.Int()
      name = graphene.String(required=True)
      tag = graphene.Int(required=True)
      description = graphene.String(required=True)
      definition = graphene.String(required=True)
      username = graphene.String(required=True)
   create_success = graphene.Boolean()
   def mutate(self, info, id, name, tag, description, definition, username):
      if(id == 0):
         assetGroup = AssetGroup(name=name, tag=tag, description=description, definition=definition, username=username)
      if(id != 0):
         assetGroup = AssetGroup.objects.get(pk=id)
         assetGroup.name = name
         assetGroup.tag = tag
         assetGroup.description = description
         assetGroup.definition = definition
         assetGroup.username = username
      assetGroup.save()
      create_success = True
      return CreateAssetGroup(assetGroup=assetGroup, create_success=create_success)
class CreateAssetImport(graphene.Mutation):
   assetImport = graphene.Field(AssetImportType)
   class Arguments:
      id = graphene.Int()
      name = graphene.String(required=True)
      product = graphene.String(required=True)
      importtype = graphene.String(required=True)
      information = graphene.String(required=True)
      fileupload = Upload()
      username = graphene.String(required=True)
   create_success = graphene.Boolean()
   def mutate(self, info, id, name, product, importtype, information, fileupload, username):
      if(id == 0):
         if(importtype == "2"):
            try:
               _file = pd.read_csv(fileupload[0])
               _file.fillna("", inplace=True)
            except:
               try:
                  _file = pd.read_excel(fileupload[0])
                  _file.fillna("", inplace=True)
               except:
                  print("Sorry Type error")
            colnames = ['Name', 'Type', 'Domain', 'OS', 'Model', 'Manufacturer', 'IP Address', 'MAC Address', 'OU', 'Description', 'DNS Name', 'Serialnumber']
            df = pd.DataFrame(_file, columns=colnames)
            for index in range(len(df['MAC Address'].tolist())):
               assetname= df['Name'].tolist()[index] if df['Name'].tolist()[index] != 'nan' else ""
               ipAddress= df['IP Address'].tolist()[index]
               _realip = []
               for divip in ipAddress.split("."):
                  _realip.append('{:03d}'.format(int(divip)))
               ipAddress = ".".join(_realip)
               macAddress= df['MAC Address'].tolist()[index]
               manufacturer= df['Manufacturer'].tolist()[index]
               model= df['Model'].tolist()[index]
               assetType= df['Type'].tolist()[index]
               operatingSystem= df['OS'].tolist()[index]
               firmwareVersion = df['Serialnumber'].tolist()[index]
               if firmwareVersion == np.nan:
                  print(firmwareVersion)
               description= df['Description'].tolist()[index]
               isFirmwareScanned = False
               string = "SELECT * FROM assets_asset where username=" + "'" + username + "' and " + '"' + 'macAddress' + '"' + "=" + "'" + macAddress + "'";
               for _asset in Asset.objects.raw(string):
                  _asset.name = assetname
                  _asset.ipAddress = ipAddress
                  _asset.manufacturer = manufacturer
                  _asset.model = model
                  _asset.assetType = assetType
                  _asset.operatingSystem = operatingSystem
                  _asset.firmwareVersion = firmwareVersion
                  _asset.description = description
                  _asset.save()
               if (len(Asset.objects.raw(string)) == 0):
                  asset = Asset(name=assetname, ipAddress=ipAddress, macAddress=macAddress, manufacturer=manufacturer,
                                model=model, assetType=assetType, operatingSystem=operatingSystem,
                                firmwareVersion=firmwareVersion, description=description,
                                isFirmwareScanned=isFirmwareScanned, discontinued=False, outdated=False, username=username)
                  asset.save()
         if(importtype == "1"):
            connectMSDB(assetImport.id)
         assetImport = AssetImport(name=name, product=product, importtype=importtype, info=information, username=username)
      if(id != 0):
         assetImport = AssetImport.objects.get(pk=id)
         assetImport.name = name
         assetImport.product = product
         assetImport.importtype = importtype
         assetImport.info = information
      assetImport.save()
      create_success = True
      return CreateAssetImport(assetImport=assetImport, create_success=create_success)
class Query(graphene.ObjectType):
   all_assetGroupList = graphene.List(AssetGroupType, username=graphene.String())
   all_assetImportList = graphene.List(AssetImportType, username=graphene.String())
   get_assetGroupDetailList = graphene.List(AssetType, id=graphene.Int())
   get_assetInfo = graphene.Field(AssetType, id=graphene.Int())
   def resolve_all_assetGroupList(self,info, username, **kwargs):
      return AssetGroup.objects.raw("select * from assets_assetgroup where username=" + "'"  + username + "'")
   def resolve_all_assetImportList(self, info, username, **kwargs):
      return AssetImport.objects.raw("select * from assets_assetimport where username=" + "'"  + username + "'")
   def resolve_get_assetInfo(self, info, id):
      return Asset.objects.get(pk=id)
   def resolve_get_assetGroupDetailList(self, info, id):
      assetGroup = AssetGroup.objects.get(pk=id)
      conditionString = " "
      definition = json.loads(assetGroup.definition)
      conditionLength = len(definition)
      for i in range(len(definition)):
         def_type = '"' + definition[i]['type'] + '"'
         def_operator1 = definition[i]['operator1']
         def_value = definition[i]['value']
         def_value_start = definition[i]['value_start']
         def_value_end = definition[i]['value_end'];
         def_operator2 = definition[i]['operator2']
         conditionString = ''
         if(def_type == '"ipAddress"'):
            _realip_start = []
            _count1 = len(def_value_start.split("."))
            for divip in def_value_start.split("."):
               _realip_start.append('{:03d}'.format(int(divip)))
            def_value_start = ".".join(_realip_start)
            for x in range(_count1, 4):
               def_value_start += ".___"
            _realip_end = []
            _count2 = len(def_value_end.split("."))
            for divip in def_value_end.split("."):
               _realip_end.append('{:03d}'.format(int(divip)))
            def_value_end = ".".join(_realip_end)
            for x in range(_count2, 4):
               def_value_end += ".___"
            conditionString = conditionString + '"ipAddress" > ' + "'" + def_value_start + "'" + ' and ' + '"ipAddress" < ' + "'" +  def_value_end + "'";
         else:
            conditionString = conditionString + def_type + " like " + "'" + def_value + "_'"
         if(conditionLength - 1 != i):
            conditionString = conditionString + " " +  def_operator2 + " "
      my_objects = []
      string = "SELECT * FROM assets_asset where" + conditionString
      for row in Asset.objects.raw(string):
         my_objects.append(row)
      return my_objects
      
class Mutation(graphene.ObjectType):
    create_assetGroup = CreateAssetGroup.Field()
    create_assetImport = CreateAssetImport.Field()
schema = graphene.Schema(query=Query, mutation=Mutation)
