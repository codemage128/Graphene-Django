import graphene 
from graphene import ObjectType
from graphene_django.types import DjangoObjectType
from scans.models import Scan, Vulnerabilities, OV_Vulnerabilities, FirmwareComponentDetail, Asset_OV_Vulnerabilites, Asset_Vulnerabilites, Asset_FirmwareDetail
from assets.models import Asset, AssetGroup
import json
from .tasks import versionDetection, fullactiveScan, vulnerabilityscan, firmwarescan
from celery.result import AsyncResult

class ScanType(DjangoObjectType):
   class Meta:
      model = Scan
class AssetDetailType(DjangoObjectType):
   class Meta:
      model=Asset
class VulnerabilitiesType(DjangoObjectType):
   class Meta: 
      model = Vulnerabilities
class OVVulnerabilitiesType(DjangoObjectType):
   class Meta: 
      model = OV_Vulnerabilities
class FirmwareDetailType(DjangoObjectType):
   class Meta: 
      model = FirmwareComponentDetail
class AssetVulnerabilitiesType(DjangoObjectType):
   class Meta: 
      model = Asset_Vulnerabilites
class AsssetOVVulnerabilitiesType(DjangoObjectType):
   class Meta:
      model = Asset_OV_Vulnerabilites
class AssetFirmwareDetailType(DjangoObjectType):
   class Meta:
      model = Asset_FirmwareDetail

class TopManuType(graphene.ObjectType):
   manufacturer = graphene.String()
   count = graphene.Int()
class TopDeviceType(graphene.ObjectType):
   name = graphene.String()
   count = graphene.Int()
class resultType(graphene.ObjectType):
   status = graphene.String()
class MostActiveScanType(graphene.ObjectType):
   ipAddress = graphene.String()
   manufacturer = graphene.String()
   model = graphene.String()
   critical = graphene.Float()
   medium = graphene.Float()
   high = graphene.Float()
def get_most_activeScan():
   return 
def get_top_manufactures():
   return Asset.objects.raw("""SELECT 1 as id, manufacturer, count(manufacturer) as count from assets_asset group by manufacturer order by count desc limit 10""")
def get_top_devices():
   return Asset.objects.raw("""SELECT 1 as id, "assetType" as name, count("assetType") as count from assets_asset group by "assetType" order by count desc limit 10""")
class CreateScan(graphene.Mutation):
   scan = graphene.Field(ScanType)
   class Arguments:
      id = graphene.Int()
      name = graphene.String()
      assetgroupid = graphene.Int()
      iprange = graphene.String()
      scantype = graphene.String()
      tasktype = graphene.Int()
      username = graphene.String()
   create_success = graphene.Boolean()
   def mutate(self, info, id, name, assetgroupid, iprange, scantype, tasktype, username):
      if(id == 0):
         scan = Scan(name=name, assetgroupid=assetgroupid, iprange=iprange, scantype=scantype, tasktype=tasktype, ovid=11, username=username)
      if(id != 0):
         scan = Scan.objects.get(pk=id)
         scan.name = name
         scan.assetgroupid = assetgroupid
         scan.iprange = iprange
         scan.scantype = scantype
         scan.tasktype = tasktype
      scan.save()
      _scanTypeList = scan.scantype.split(",")
      _assets = []
      if(assetgroupid == -1): # search by iprange
         _iprange = scan.iprange.split(",")
         _start = _iprange[0]
         _end = _iprange[1]
         _realip = []
         for divip in _start.split("."):
            _realip.append('{:03d}'.format(int(divip)))
         _start = ".".join(_realip)
         _realip1 = []
         for divip in _end.split("."):
            _realip1.append('{:03d}'.format(int(divip)))
         _end = ".".join(_realip1)
         querystring = '"ipAddress" > ' + "'" + _start + "'" + ' and ' + '"ipAddress" < ' + "'" +  _end + "'";
         querystring = "SELECT * FROM assets_asset where username=" + "'" + username + "' and " + querystring;
         assets = Asset.objects.raw(querystring)
         for _asset in assets:
            _assets.append(_asset)
      else:
         assetGroup = AssetGroup.objects.get(pk=assetgroupid)
         conditionString = ""
         definition = json.loads(assetGroup.definition)
         conditionLength = len(definition)
         for i in range(len(definition)):
            def_type = '"' + definition[i]['type'] + '"'
            def_operator1 = definition[i]['operator1']
            def_value = definition[i]['value']
            def_value_start = definition[i]['value_start'];
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
         string = "SELECT * FROM assets_asset where username=" + "'" + username + "' and " + conditionString
         for row in Asset.objects.raw(string):
            _assets.append(row)
      _assets_dict = []
      for item in _assets:
         _assets_dict.append(item.id)
      for row in _scanTypeList:
         #status = []
         if(row == "lightweight"):
            taskresult = versionDetection.apply_async(args=[_assets_dict, scan.id])
            if taskresult.state == 'PENDING':
               scan.status = 1
               #status.append(taskresult.id)
         if(row == "fullactive"):
            taskresult = fullactiveScan.apply_async(args=[_assets_dict, scan.id])
            if taskresult.state == 'PENDING':
               scan.status = 1
            #status.append(taskresult.id)
         if(row == "vulnerabilityscan"):
            taskresult = vulnerabilityscan.apply_async(args=[_assets_dict, scan.id])
            if taskresult.state == 'PENDING':
               scan.status = 1
            #status.append(taskresult.id)
         if(row == "firmwarescan"):
            taskresult = firmwarescan.apply_async(args=[_assets_dict, scan.id])
            if taskresult.state == 'PENDING':
               scan.status = 1
            #status.append(taskresult.id)
         #scan.status = status
         scan.save()
      create_success = True
      return CreateScan(scan=scan, create_success=create_success)
class Query(graphene.ObjectType):
   all_scanList = graphene.List(ScanType, username=graphene.String())
   all_vulList = graphene.List(VulnerabilitiesType, username=graphene.String())
   get_scanDetailList = graphene.List(AssetDetailType, id=graphene.Int(), username=graphene.String())
   get_assetVulList = graphene.Field(AssetDetailType, id=graphene.Int())
   get_getInfo = graphene.List(AssetDetailType, data=graphene.String())
   get_allAsset = graphene.List(AssetDetailType)
   get_topManufactureType = graphene.List(TopManuType, username=graphene.String())
   get_topDeviceType = graphene.List(TopDeviceType, username=graphene.String())
   get_mostActiveScan = graphene.List(AssetDetailType, username=graphene.String())
   get_passiveScan = graphene.List(AssetDetailType, username=graphene.String())
   get_firmwareDetail = graphene.List(AssetDetailType, username=graphene.String())
   # get_task_result = graphene.List(resultType, task=graphene.String())
   #
   # def resolve_get_task_result(self, info, task, **kwargs):
   #    print(task.split(','))
   def resolve_get_firmwareDetail(self, info, username,  **kwargs):
      query = "select 1 as id,  assetid_id, count(assetid_id) from scans_asset_firmwaredetail group by assetid_id order by count desc limit 10"
      result = Asset.objects.raw(query)
      res = [];
      for row in result:
         print(row.assetid_id)
         res.append(Asset.objects.get(pk=row.assetid_id))
         query1 = "select 1 as id, vulnerabilities as vul from scans_firmwarecomponentdetail where id in (select fdetailid_id from scans_asset_firmwaredetail where assetid_id = " + str(row.assetid_id) + ")"
         result1 = Asset.objects.raw(query1)
         for item in result1:
            vullist = item.vul.split(",")
            for vul in vullist:
               querycvss = "select * from scans_vulnerabilities where cveid = " + "'" + vul + "'"
               resultcvss = Asset.objects.raw(querycvss)
               print(len(resultcvss))
               print("###")
               for cvsslist in resultcvss:
                  cvss = cvsslist.cvss
                  # print(cvsslist.cvss)
                  # if (cvss >= 4 and cvss <= 6.9):
                  #    m = m + cvss
                  # if (cvss >= 7 and cvss <= 8.9):
                  #    h = h + cvss
                  # if (cvss >= 9 and cvss <= 10):
                  #    c = c + cvss
   def resolve_get_passiveScan(self, info, username, **kwargs):
      query = "select 1 as id,  assetid_id, count(assetid_id) from scans_asset_vulnerabilites group by assetid_id order by count desc limit 10"
      result = Asset.objects.raw(query)
      res = [];
      for row in result:
         res.append(Asset.objects.get(pk=row.assetid_id))
      return res

   def resolve_get_mostActiveScan(self, info, username, **kwargs):
      query = "SELECT 1 as id, assetid_id, count(assetid_id) FROM scans_asset_ov_vulnerabilites group by assetid_id order by count desc limit 10;"
      result = Asset.objects.raw(query)
      res = [];
      for row in result:
         res.append(Asset.objects.get(pk=row.assetid_id))
      return res

   def resolve_get_topDeviceType(self, info, username, **kwargs):
      return get_top_devices()

   def resolve_get_topManufactureType(self, info, username, **kwargs):
      return get_top_manufactures()

   def resolve_get_allAsset(self, info, **kwargs):
      return Asset.objects.all()

   def resolve_get_getInfo(self, info,  data, **kwargs):
      data = json.loads(data)
      type = data['type']
      operator = data['operator'] # =
      value = data['value']
      value_start = data['value_start']
      value_end = data['value_end']
      _assetList = []
      if type == "ipAddress":
         _realip = []
         for divip in value_start.split("."):
            _realip.append('{:03d}'.format(int(divip)))
         _start = ".".join(_realip)
         _realip1 = []
         for divip in value_end.split("."):
            _realip1.append('{:03d}'.format(int(divip)))
         _end = ".".join(_realip1)
         querystring = '"ipAddress" > ' + "'" + _start + "'" + ' and ' + '"ipAddress" < ' + "'" +  _end + "'";
         querystring = "SELECT * FROM assets_asset where " + querystring;
         assets = Asset.objects.raw(querystring)
         for _asset in assets:
            _assetList.append(_asset)
      else:
         string = "SELECT * from assets_asset where " + '"' +  type + '"' + " like " + "'" +  value + "_'"
         for row in Asset.objects.raw(string):
            _assetList.append(row)
      return _assetList

   def resolve_all_scanList(self, info, username, **kwargs):
      return Scan.objects.raw("select * from scans_scan where username=" + "'" + username + "'")

   def resolve_all_vulList(self, info, username, **kwargs):
      return Vulnerabilities.objects.raw("select * from scans_vulnerabilities where username=" + "'" + username + "'")

   def resolve_get_assetVulList(self, info, id, **kwargs):
      return Asset.objects.get(pk=id)

   def resolve_get_scanDetailList(self, info, id, username, **kwargs):
      scan = Scan.objects.get(pk=id)
      assetgroupid = scan.assetgroupid;
      _scanTypeList = scan.scantype.split(",")
      _assets = []
      _return = []
      _asset_vulnerabilities = []
      _firmware_vulnerabilities = []
      if(assetgroupid == -1): # search by iprange
         _iprange = scan.iprange.split(",")
         _start = _iprange[0]
         _end = _iprange[1]
         _realip = []
         for divip in _start.split("."):
            _realip.append('{:03d}'.format(int(divip)))
         _start = ".".join(_realip)
         _realip1 = []
         for divip in _end.split("."):
            _realip1.append('{:03d}'.format(int(divip)))
         _end = ".".join(_realip1)
         querystring = '"ipAddress" > ' + "'" + _start + "'" + ' and ' + '"ipAddress" < ' + "'" +  _end + "'";
         querystring = "SELECT * FROM assets_asset where username = " +  "'" + username + "' and " + querystring;
         assets = Asset.objects.raw(querystring)
         for _asset in assets:
            _assets.append(_asset)
      else:
         assetGroup = AssetGroup.objects.get(pk=assetgroupid)
         conditionString = " "
         definition = json.loads(assetGroup.definition)
         conditionLength = len(definition)
         for i in range(len(definition)):
            def_type = '"' + definition[i]['type'] + '"'
            def_operator1 = definition[i]['operator1']
            def_value = definition[i]['value']
            def_value_start = definition[i]['value_start'];
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
         string = "SELECT * FROM assets_asset where  username = " +  "'" + username + "' and " +conditionString
         for row in Asset.objects.raw(string):
            _assets.append(row)
      for asset in _assets:
         for vulnerbiliy in Asset_Vulnerabilites.objects.raw("SELECT * from scans_asset_vulnerabilites where assetid_id=" + str(asset.id)):
            _asset_vulnerabilities.append(vulnerbiliy)
      return _assets
class Mutation(graphene.ObjectType):
   create_scan = CreateScan.Field()
schema = graphene.Schema(query=Query, mutation=Mutation)
