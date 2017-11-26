from __future__ import unicode_literals

from django.db import models
import datetime
import math
import json

def Entropy(text):
    log2=lambda x:math.log(x)/math.log(2)
    exr={}
    infoc=0
    for each in text:
        try:
            exr[each]+=1
        except:
            exr[each]=1
    textlen=len(text)
    for k,v in exr.items():
        freq  =  1.0*v/textlen
        infoc+=freq*log2(freq)
    infoc*=-1
    return infoc

class Inmemoryprocess(models.Model):
    pid = models.IntegerField(db_column='PID')  
    ppid = models.IntegerField(db_column='PPID')  
    grrworkstation = models.CharField(db_column='GRRWorkstation', max_length=50)  
    grrhunt = models.CharField(db_column='GRRHunt', max_length=50)  
    processname = models.CharField(db_column='ProcessName', max_length=50)  
    processstarttime = models.DateTimeField(db_column='ProcessStartTime')  
    cmdline = models.CharField(db_column='cmdline', max_length=320)  
    cmdlineEntropy = models.DecimalField(db_column='cmdlineEntropy', max_digits=10, decimal_places=8)
    sha256 = models.CharField(db_column='sha256', max_length=320)  
    ctime = models.BigIntegerField(db_column='ctime')

    class Meta:
        managed = False
        db_table = 'InMemoryProcess'

    def printProcess():
        return pid

    @classmethod
    def create(cls, pid, ppid, grrworkstation, processname, processstarttime):
    	process = cls(pid=pid, ppid=ppid, grrworkstation=grrworkstation, processname=processname, processstarttime=processstarttime)
    	return process

    def __str__(self):
    	return "pid : " + str(self.pid) + " ppid : " + str(self.ppid)

    def LoadFromCSVLine(self, csvline):
        #type, md5, process, path, sha1, arguments
        self.pid = csvline["pid"]
        self.grrhunt = csvline["metadata.source_urn"]
        self.ppid = csvline["ppid"]
        self.processname = csvline["name"]
        self.grrworkstation = csvline["metadata.client_urn"]
        self.cmdline = csvline["cmdline"]
        self.cmdlineEntropy = Entropy(self.cmdline)
        #self.cmdline = csvline["ctime"]
        #self.processstarttime = datetime.datetime.fromtimestamp(int(csvline["ctime"]))

    def LoadHashFromCSVLine(self, csvline, workstation, hunt):
        #type, md5, process, path, sha1, arguments
        self.pid = csvline["pid"]
        self.grrhunt = hunt
        self.ppid = csvline["ppid"]
        self.processname = csvline["name"]
        self.grrworkstation = workstation
        #self.cmdline = csvline["cmdline"]
        self.cmdlineEntropy = Entropy(self.cmdline)
        #self.processstarttime = datetime.datetime.fromtimestamp(int(csvline["ctime"]))

    def AddHashFromCSVLine(self, csvline, ctime):
        #"type, pid, processName, Path, CommandLine, sha256"
        self.sha256 = csvline["sha256"]

        #self.processstarttime = datetime.datetime.fromtimestamp(int(csvline["ctime"]))




class Socket(models.Model):
    grrworkstation = models.CharField(db_column='GRRWorkstation', max_length=50)  
    port = models.IntegerField(db_column='Port')  
    grrhunt = models.CharField(db_column='GRRHunt', max_length=50)  
    remoteaddress = models.CharField(db_column='RemoteAddress', max_length=25, blank=True, null=True)  
    protocol = models.CharField(db_column='Protocol', max_length=25, blank=True, null=True)  
    state = models.CharField(db_column='State', max_length=25, blank=True, null=True)  
    pid = models.IntegerField(db_column='PID', blank=True, null=True)  
    account = models.CharField(db_column='Account', max_length=50, blank=True, null=True)  

    class Meta:
        managed = False
        db_table = 'Socket'

    def LoadFromCSVLine(self, csvline):
        #type, md5, process, path, sha1, arguments
        self.grrworkstation = csvline["metadata.client_urn"]
        self.grrhunt = csvline["metadata.source_urn"]
        self.port = csvline["local_address.port"]
        self.state = csvline["state"]
        self.pid = csvline["pid"]
        #self.remoteaddress = csvline["remote_address.ip"]
        self.protocol = csvline["family"]
        self.account = csvline["metadata.usernames"].replace("'", "")


class Workstation(models.Model):
    idgrr = models.CharField(db_column='IDGRR', max_length=50)  
    name = models.CharField(db_column='Name', max_length=50)  
    os = models.CharField(db_column='OS', max_length=50, blank=True, null=True)  
    osdetail = models.CharField(db_column='OSDetail', max_length=50, blank=True, null=True)  
    sockets = []
    class Meta:
        managed = False
        db_table = 'Workstation'

    def LoadFromCSVLine(self, csvline):
        #type, md5, process, path, sha1, arguments
        self.idgrr = csvline["metadata.client_urn"]
        self.name = csvline["metadata.hostname"]
        self.os = csvline["metadata.os"]
        self.osdetail = csvline["metadata.uname"]


class Hunt(models.Model):
    huntid = models.CharField(db_column='HuntID', max_length=50)  
    datehunt = models.DateField(db_column='DateHunt')  

    class Meta:
        managed = False
        db_table = 'Hunt'

    def LoadFromCSVLine(self, csvline):
        #type, md5, process, path, sha1, arguments
        self.huntid = csvline["metadata.client_urn"]
        self.datehunt = csvline["metadata.timestamp"]

class Hash(models.Model):
    sha256 = models.CharField(db_column='SHA256', max_length=65)  # Field name made lowercase.
    permalink = models.TextField(db_column='permalink', blank=True, null=True)  # Field name made lowercase.
    positives = models.IntegerField(db_column='positives')  
    
    class Meta:
        managed = False
        db_table = 'Hash'


    def LoadFromCSVLine(self, csvline):
        #type, md5, process, path, sha1, arguments
        self.sha256 = csvline["hash_sha256"]


    def UpdateFromVirusTotal(self, jsonTXT):
        #print jsonTXT
        data = json.loads(jsonTXT)
        #print data
        if(int(data["response_code"]) == 200):
            self.sha256 = data["results"]["sha256"]
            self.positives = data["results"]["positives"]
            self.permalink = data["results"]["permalink"]

class HashWorkstationLink(models.Model):
    sha256 = models.CharField(db_column='SHA256', max_length=65)  # Field name made lowercase.
    filename = models.CharField(db_column='FileName', max_length=50, blank=True, null=True)  # Field name made lowercase.
    if not filename:
        filename="No name"
    pathfile = models.TextField(db_column='PathFile', blank=True, null=True)  # Field name made lowercase.
    grrworkstation = models.CharField(db_column='GRRWorkstation', max_length=50)  # Field name made lowercase.
    grrhunt = models.CharField(db_column='GRRHunt', max_length=50)  # Field name made lowercase.

    class Meta:
        managed = False
        db_table = 'HashWorkstationLink'

    def LoadFromCSVLine(self, csvline):
        #type, md5, process, path, sha1, arguments
        self.sha256 = csvline["hash_sha256"]
        self.filename = csvline["basename"]
        self.pathfile = csvline["urn"]
        self.grrhunt = csvline["metadata.source_urn"]
        self.grrworkstation = csvline["metadata.client_urn"]

class Registrykey(models.Model):
    idgrr = models.CharField(db_column='IDGRR', max_length=50)  # Field name made lowercase.
    huntid = models.CharField(db_column='HuntID', max_length=50)  # Field name made lowercase.
    lastmodified = models.DateField(db_column='LastModified')  # Field name made lowercase.
    name = models.CharField(db_column='Name', max_length=255)  # Field name made lowercase.
    typeReg = models.CharField(db_column='Type', max_length=50)  # Field name made lowercase.
    data = models.TextField(db_column='Data', blank=True, null=True)  # Field name made lowercase.
    pathregistry = models.TextField(db_column='PathRegistry', blank=True, null=True)  # Field name made lowercase.

    class Meta:
        managed = False
        db_table = 'RegistryKey'

    def LoadFromCSVLine(self, csvline):
        #type, md5, process, path, sha1, arguments
        self.idworkstation = csvline["metadata.client_urn"]
        self.huntid = csvline["metadata.source_urn"]
        self.lastmodified = csvline["last_modified"]
        self.name = csvline["urn"].split("/").last()
        self.data = csvline["mdata"]
        self.pathregistry = csvline["urn"].split("/registry/")[1]


class DjangoMigrations(models.Model):
    app = models.CharField(max_length=255)
    name = models.CharField(max_length=255)
    applied = models.DateTimeField()

    class Meta:
        managed = False
        db_table = 'django_migrations'

class node_Process:

	def __init__(self, process):
		self.process = process

	def __hash__(self):
		return self.process.pid

	def __eq__(self, other):
		return self.process.pid == other


