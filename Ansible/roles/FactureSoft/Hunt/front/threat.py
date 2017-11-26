#!/usr/bin/python


from virus_total_apis import PublicApi as VirusTotalPublicApi
import time
import json
from front.models import Hash



class VirusTotalConnexion:

    def __init__(self, apikey):
        self.vt = VirusTotalPublicApi(apikey)
        self.counter = 0
        self.timestamp = 0.0

    def isReady(self):
        if(self.counter < 4):
            return True
        else:
            if(time.time() - self.timestamp > 60):
                self.counter = 0
                return True
            else:
                return False

    def asksha256(self, sha256):
        if(self.isReady()):
            response = self.vt.get_file_report(sha256)
            self.timestamp = time.time()
            self.counter += 1
            return json.dumps(response, sort_keys=False, indent=4)

    def parseJson(self, jsonFile):
        data = json.load(jsonFile)

class VirusTotalManager:

    APIKeyMatrix = ["20af57c8f98e5a08ed6cb0f06a4493d38059cff46a7e6917c03f94179ef4184f","6c6d93580478620a7b3d5c1f2255214159f2d6e327859e3d53c71d3216ba2f8e","8d0048b80303c205b6e02c16845e3458be25d65eed50609ef468911e13661a50","F8ba432c861718b6d3446a0d3b63a849bbc7e1cfb75c05c215bde42afdee3309","675ddb0c2f867d9936580eba6d5e5f6bc91a5a89a9f5d4a6bd1fda216da029dc", "895101248d071b60ff0510ebc7540c4da7cd54f0e2cc1842e806acf0ae573ea3"]
    
    def __init__(self):
        self.VTConnexions = []
        for key in self.APIKeyMatrix:
            self.VTConnexions.append(VirusTotalConnexion(key))

    def checkMD5(self, md5):
        for vtconnexion in self.VTConnexions:
            if(vtconnexion.isReady()):
                print("Getting VT result")
                return vtconnexion.asksha256(md5)
        time.sleep(5)
        #Recursif call until resolve
        checkMD5(md5)

    def checkHash(self, hashObject):
        try:
          jsonDump = self.checkMD5(hashObject.sha256)
          #print(jsonDump)
          hashObject.UpdateFromVirusTotal(jsonDump)
        except:
          return


# vtManager = VirusTotalManager()
# threat = Threat(9999, "44d88612fea8a8f36de82e1278abb02f")
# threat2 = Threat(1, "44d88612fea8a8f36de82e1278abb02f")
# threat = vtManager.checkThreat(threat)
# threatlist = ThreatList()
# threatlist.addNewThreat(threat)
# threatlist.addNewThreat(threat2)
# threatlist.checkAndUpdateList(vtManager)

# print threatlistss
