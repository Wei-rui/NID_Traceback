from django.db import models
import os


'''
# query from RPKI
class Domain(models.Model):
    domainIP = models.GenericIPAddressField(protocol="ipv6")
    domainName = models.CharField(max_length=32)


# query from one AS (whose ip is naIP)
class IDEA(models.Model):
    naIP = models.GenericIPAddressField(protocol="ipv6")
    ideaKey = models.CharField(max_length=128)
    startTime = models.DateTimeField()
    endTime = models.DateTimeField()


class Group(models.Model):
    naIP = models.GenericIPAddressField(protocol="ipv6")
    groupName = models.CharField(max_length=32)
    dividePart = models.CharField(max_length=32)
    orgPart = models.CharField(max_length=32)


class User(models.Model):
    naIP = models.GenericIPAddressField(protocol="ipv6")
    userName = models.CharField(max_length=64)
    userDID = models.CharField(max_length=32)
    groupID = models.BigIntegerField()
    userPart = models.CharField(max_length=64)
'''


class asDomain(models.Model):
    domainPrefix = models.GenericIPAddressField()
    domainIP = models.GenericIPAddressField()
    domainName = models.CharField(max_length=32)


class asIDEA(models.Model):
    ideaKey = models.CharField(max_length=128)
    startTime = models.DateTimeField()
    endTime = models.DateTimeField()


class asGroup(models.Model):
    groupName = models.CharField(max_length=32)
    dividePart = models.CharField(max_length=32)
    orgPart = models.CharField(max_length=32)


class asUser(models.Model):
    userName = models.CharField(max_length=64)
    userDID = models.CharField(max_length=32)
    groupID = models.BigIntegerField()
    userPart = models.CharField(max_length=64)
