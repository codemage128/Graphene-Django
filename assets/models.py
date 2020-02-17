from django.db import models
# Create your models here.
class AssetGroup(models.Model):
   name = models.CharField(max_length=255)
   description = models.TextField(blank=True, null=True)
   tag = models.TextField(blank=True, null=True)
   ipCount = models.IntegerField(default=0, blank=True, null=True)
   created_at = models.DateTimeField(auto_now_add=True)
   updated_at = models.DateTimeField(auto_now=True)
   definition = models.TextField(max_length=255)
   username = models.TextField()

class AssetImport(models.Model):
   name = models.CharField(max_length=255)
   product = models.TextField(blank=True, null=True)
   importtype = models.TextField(blank=True, null=True)
   info = models.TextField(blank=True, null=True)
   created_at = models.DateTimeField(auto_now_add=True)
   updated_at = models.DateTimeField(auto_now=True)
   username = models.TextField()

class Asset(models.Model):
   name = models.CharField(max_length=255)
   ipAddress = models.TextField(max_length=255)
   macAddress = models.TextField(max_length=255)
   manufacturer = models.TextField(max_length=255)
   model = models.TextField(max_length=255)
   assetType = models.TextField(max_length=255)
   operatingSystem = models.TextField(max_length=255)
   firmwareVersion = models.TextField(max_length=255)
   description = models.TextField(max_length=255)
   isFirmwareScanned = models.BooleanField()
   discontinued = models.BooleanField(blank=True, null=True)
   outdated = models.BooleanField(blank=True, null=True)
   created_date = models.DateTimeField(auto_now_add=True)
   lastestfirmwareversion = models.TextField()
   username = models.TextField()