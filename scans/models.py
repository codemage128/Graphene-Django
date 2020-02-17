from django.db import models
from assets.models import Asset

# Create your models here.
class Scan(models.Model):
   name = models.TextField(null=True)
   assetgroupid = models.IntegerField(null=True)
   iprange = models.TextField(null=True)
   status = models.TextField(null=True)
   scantype = models.TextField(null=True)
   tasktype = models.IntegerField()
   tags = models.TextField(null=True)
   ovid = models.IntegerField()
   created_at = models.DateTimeField(auto_now_add=True)
   updated_at = models.DateTimeField(auto_now=True)
   username = models.TextField()

class Vulnerabilities(models.Model):
   cveid = models.TextField(null=True)
   cwe = models.TextField(null=True)
   cvss = models.FloatField(null=True)
   summary = models.TextField(null=True)
   references = models.TextField(null=True)
   username = models.TextField()

class OV_Vulnerabilities(models.Model):
   cveid = models.TextField(null=True)
   vulnname = models.TextField(null=True)
   severity = models.FloatField(null=True)
   location = models.TextField(null=True)
   description = models.TextField(null=True)
   username = models.TextField()
   
class FirmwareComponentDetail(models.Model):
   firmwarename = models.TextField(null=True)
   firmwarehash = models.TextField(null=True)
   checksum = models.TextField(null=True)
   componentname = models.TextField(null=True)
   version = models.TextField(null=True)
   vulnerabilities = models.TextField(null=True) #cveid
   issues = models.TextField(null=True)
   username = models.TextField()

class Asset_Vulnerabilites(models.Model):
   assetid = models.ForeignKey(Asset, on_delete=models.CASCADE)
   vulid=models.ForeignKey(Vulnerabilities, on_delete=models.CASCADE)
   scanid = models.IntegerField()
   username = models.TextField()

class Asset_OV_Vulnerabilites(models.Model):
   assetid = models.ForeignKey(Asset, on_delete=models.CASCADE)
   ovid=models.ForeignKey(OV_Vulnerabilities, on_delete=models.CASCADE)
   scanid = models.IntegerField()
   username = models.TextField()

class Asset_FirmwareDetail(models.Model):
   assetid = models.ForeignKey(Asset, on_delete=models.CASCADE)
   fdetailid = models.ForeignKey(FirmwareComponentDetail, on_delete=models.CASCADE)
   scanid = models.IntegerField()
   username = models.TextField()


