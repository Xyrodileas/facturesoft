from django.http import HttpResponse
from django.http import JsonResponse
from django.shortcuts import render
from django.template import loader, Context
import networkx as nx
from networkx.readwrite import json_graph
import csv
from django.db import connection
from django import forms
import codecs
from front.models import Inmemoryprocess, node_Process, Workstation, Socket, Hunt, Hash, HashWorkstationLink
from front.threat import VirusTotalManager

from io import StringIO

def index(request):
	template = loader.get_template('home.html')
	listpid = []
	listppid = []
	listName = []
	test = Inmemoryprocess.objects.all()
	for record in test:
		listpid.append(record.pid)
		listppid.append(record.ppid)
		listName.append(record.processname) 
	context = {'pid':listpid,
				'ppid':listppid,
				'name':listName }
	return HttpResponse(template.render(context, request))


def tree(request, workstation="undefined"):
	template = loader.get_template('tree.html')
	
	class NameForm(forms.Form):
		#your_name = forms.CharField(label='Machine', max_length=100)
		array_workstation = []
		x = 1
		for work in Workstation.objects.order_by('name'):
			array_workstation.append(tuple((work.idgrr,work.name)))
			x+=1
		#array_workstation.append(tuple(("test","test")))
		machine = forms.ChoiceField(choices=array_workstation)

	#Generate context for the tree	
	context = {'graph':"/front/json/"+workstation,
				'form':NameForm(),
			}

	return HttpResponse(template.render(context, request))


def socket_csv(request, hunt="undefined"):
	# Create the HttpResponse object with the appropriate CSV header.
    response = HttpResponse(content_type='text/csv')
    response['Content-Disposition'] = 'attachment; filename="somefilename.csv"'
    writer = csv.writer(response)
    writer.writerow(['Socket distribution'])
    writer.writerow([''])
    writer.writerow([''])
    writer.writerow([''])
    writer.writerow(['Socket', 'Occurency'])
    print(hunt)
    with connection.cursor() as c:
        if hunt=="undefined" :
            result = c.execute("SELECT Port, COUNT(*) AS occurency FROM Socket GROUP BY Port")
        else :
        	result = c.execute("SELECT Port, COUNT(*) AS occurency FROM Socket WHERE GRRHunt='"+hunt+"' GROUP BY Port")
        for row in c:
            if row[1] < 150 :
                if row[1] >2 :
                    writer.writerow(row)
    
    return response

def sockets(request, hunt=""):
	template = loader.get_template('sockets.html')
	
	class NameForm(forms.Form):
		#your_name = forms.CharField(label='Machine', max_length=100)
		array_hunt = []
		x = 1
		for hunt in Hunt.objects.all():
			print(hunt.huntid)
			array_hunt.append(tuple((hunt.huntid,hunt.huntid)))
			x+=1
		print(array_hunt)
		#array_workstation.append(tuple(("test","test")))
		Hunt = forms.ChoiceField(choices=array_hunt)

	#Generate context for the tree	
	context = {'graph':"/front/csv/sockets/"+hunt,
				'form':NameForm(),
			}

	return HttpResponse(template.render(context, request))

def json(request, workstation="undefined"):
	template = loader.get_template('tree.html')
	if(workstation!="undefined"):
		listNode = {}
		listProcessDict = {}
		G=nx.DiGraph()
		nx.set_node_attributes(G, 'name', "Unknown")
		#G.add_node(1)
		ListProcess = Inmemoryprocess.objects.all().filter(grrworkstation=workstation)
		#print(ListProcess)

		Orphan = Inmemoryprocess.create(pid=4,ppid=4,grrworkstation="",processname="Oprhan",processstarttime="")
		OrphanNode = node_Process(Orphan)
		# G.add_node(Orphan.pid, name=Orphan.processname)
		G.add_node(-1, name=workstation)
		# G.add_node(6, name="Orphan.processname")
		# G.add_node(7, name="Orphan.processname")
		# G.add_edge(4,5)
		# G.add_edge(4,6)
		# G.add_edge(4,7)

		for process in ListProcess:
			tmpNode = node_Process(process)
			listNode[process.pid] = tmpNode
			socketsResult = Socket.objects.all().filter(grrworkstation=workstation, pid=process.pid)
			nbrSocket = str(socketsResult.count())
			listSockets = []
			for sock in socketsResult:
				listSockets.append(sock.port)

			try:
				G.add_node(process.pid, name=process.processname, nbrSocket=nbrSocket, sockets=str(listSockets), cmdline=process.cmdline)
			except KeyError:
				print("")
		for process in ListProcess:
			try:
				listNode[process.ppid]
				G.add_edge(process.ppid,process.pid)
			except :
				G.add_edge(-1,process.pid)


		# nodeToRemove = []
		# for node in G:
		# 	print(G.predecessors(node))
		# 	if G.predecessors(node) == []:
		# 		if int(nx.get_node_attributes(G,'nbrSocket')[0]) < 1:
		# 			nodeToRemove.append(node)
		# 			print("Remove)")
		#G.remove_nodes_from(nodeToRemove)
		print("lolilol")
		context = json_graph.tree_data(G, -1)

	else:
		context = {}
	return JsonResponse(context)

def tree_json_with_open_port(request, workstation="undefined"):
	template = loader.get_template('tree.html')
	print("test")
	if(workstation!="undefined"):
		listNode = {}
		listProcessDict = {}
		G=nx.DiGraph()
		nx.set_node_attributes(G, 'name', "Unknown")
		#G.add_node(1)
		ListProcess = Inmemoryprocess.objects.all().filter(grrworkstation=workstation)
		#print(ListProcess)

		Orphan = Inmemoryprocess.create(pid=4,ppid=4,grrworkstation="",processname="Oprhan",processstarttime="")
		OrphanNode = node_Process(Orphan)
		# G.add_node(Orphan.pid, name=Orphan.processname)
		G.add_node(-1, name=workstation)
		# G.add_node(6, name="Orphan.processname")
		# G.add_node(7, name="Orphan.processname")
		# G.add_edge(4,5)
		# G.add_edge(4,6)
		# G.add_edge(4,7)

		for process in ListProcess:
			tmpNode = node_Process(process)
			listNode[process.pid] = tmpNode
			socketsResult = Socket.objects.all().filter(grrworkstation=workstation, pid=process.pid)
			nbrSocket = str(socketsResult.count())
			listSockets = []
			for sock in socketsResult:
				listSockets.append(sock.port)

			try:
				G.add_node(process.pid, name=process.processname, nbrSocket=nbrSocket, sockets=str(listSockets), cmdline=process.cmdline)
			except KeyError:
				print("")
		for process in ListProcess:
			try:
				listNode[process.ppid]
				G.add_edge(process.ppid,process.pid)
			except :
				G.add_edge(-1,process.pid)

		def haveChildWithOpenPort(G, node):
			if int(nx.get_node_attributes(G,"nbrSocket")[node]) > 0:
				return True
			childs = G.successors(node)
			ChildwithPort = False
			for child in childs:
				if haveChildWithOpenPort(G, child):
					ChildwithPort = True
			return ChildwithPort

		print(nx.nodes(G))
		listToRemove = []
		for node in nx.nodes(G):
			if node == -1:
				print("Original node")
				break
			elif not haveChildWithOpenPort(G, node):
				#print("Remove :" + str(node) + "With nbr :" + str(nx.get_node_attributes(G, "nbrSocket")[node]))
				listToRemove.append(node)
		for node in listToRemove:
			G.remove_node(node)
		print(listToRemove)
		# nodeToRemove = []
		# for node in G:
		# 	print(G.predecessors(node))
		# 	if G.predecessors(node) == []:
		# 		if int(nx.get_node_attributes(G,'nbrSocket')[0]) < 1:
		# 			nodeToRemove.append(node)
		# 			print("Remove)")
		#G.remove_nodes_from(nodeToRemove)
		print(json_graph.node_link_data(G))
		context = json_graph.tree_data(G, -1)

	else:
		context = {}
	return JsonResponse(context)


def uniquify(seq):
   # not order preserving
   set = {}
   map(set.__setitem__, seq, [])
   return set.keys()



def upload_hunt(request):
	template = loader.get_template('upload_hunt.html')
	
	class UploadHuntSocketForm(forms.Form):
		HuntSocket = forms.FileField(label='Sockets')

	class UploadHuntProcessForm(forms.Form):
		HuntProcess = forms.FileField(label='Process')

	class UploadHuntHashForm(forms.Form):
		HuntHash = forms.FileField(label='Hash')

	class UploadHuntRegistryForm(forms.Form):
		HuntRegistry = forms.FileField(label='Registry')

	#Generate context for the tree	
	context = {'SocketHunt':UploadHuntSocketForm(),
				'ProcessHunt':UploadHuntProcessForm(),
				'HashHunt':UploadHuntHashForm(),
				'RegistryHunt':UploadHuntRegistryForm(),
			}

	return HttpResponse(template.render(context, request))

def upload_hunt_success(request):
	template = loader.get_template('UploadDone.html')
	uploadType = "none"
	#Generate context
	context = {	}
	WorkstationDict = {}

	if request.method == 'POST':
		
		csvfile = 0
		test = request.FILES
		try:
			#csvfile =  StringIO(request.FILES['HuntSocket'].read().decode('utf-8'))
			csvfile = StringIO(request.FILES['HuntSocket'].read().decode('utf-8'))
			uploadType = "Socket"
		except :
			try :
				csvfile = StringIO(request.FILES['HuntProcess'].read().decode('utf-8'))
				uploadType = "Process"
			except :
				try :
					csvfile = StringIO(request.FILES['HuntHash'].read().decode('utf-8'))
					uploadType = "Hash"
				except :
					csvfile = StringIO(request.FILES['Registry'].read().decode('utf-8'))
					uploadType = "Registry"


		#dialect = csv.Sniffer().sniff(codecs.EncodedFile(csvfile, "utf-8").read(1024))
		
		dicfile = csv.DictReader(csvfile)

		#data = [row for row in csv.reader(csvfile.read().splitlines())]
		#reader = csv.reader(codecs.EncodedFile(csvfile, "utf-8"), delimiter=',')
		vtManager = VirusTotalManager()
		HuntID = ""
		for row in dicfile:

			#Insert campagn
			if HuntID == "" :
				NbrCampagn = Hunt.objects.filter(huntid = row['metadata.source_urn']).count()
				if NbrCampagn < 1 :
					HuntID = row['metadata.source_urn']
					h = Hunt()
					h.LoadFromCSVLine(row)
					h.save

			#Insert new Workstation
			NbrWorkstation = Workstation.objects.filter(idgrr = row['metadata.client_urn']).count()
			if NbrWorkstation < 1 :
				w = Workstation()
				w.LoadFromCSVLine(row)
				w.save()
			if uploadType == "Socket" :
				#Insert socket
				NbrSocket = Socket.objects.filter(grrhunt = row['metadata.source_urn'], grrworkstation = row['metadata.client_urn'], port=row["local_address.port"]).count()
				if NbrSocket < 1 :
					s = Socket()
					s.LoadFromCSVLine(row)
					s.save()
			elif uploadType == "Process" :
				#Insert socket
				NbrProcess = Inmemoryprocess.objects.filter(grrhunt = row['metadata.source_urn'], grrworkstation = row['metadata.client_urn'], pid=row["pid"]).count()
				if NbrProcess < 1 :
					p = Inmemoryprocess()
					p.LoadFromCSVLine(row)
					p.save()
			elif uploadType == "Hash" :
				NbrHash = Hash.objects.all().filter(sha256=row["hash_sha256"]).count()
				print(row["hash_sha256"] + " nbr: " + str(NbrHash))
				if NbrHash < 1 :
					h = Hash()
					h.LoadFromCSVLine(row)
					h.save()
				hl = HashWorkstationLink()
				hl.LoadFromCSVLine(row)
				hl.save()
			elif uploadType == "Registry" :
				NbrRegistre = Hash.objects.all().filter(pathregistry=row["urn"].split("/registry/")[1]).filter(idworkstation=row["metadata.client_urn"]).count()
				if NbrRegistre < 1 :
					r = Hash()
					r.LoadFromCSVLine(row)
					r.save()


					
					

				# #Insert Hash
				# #dictProcessHash = csv.DictReader()
				# currentWorkstation = row['metadata.client_urn']
				# currentHunt = row['metadata.source_urn']
				# reader = csv.DictReader(row['stdout'].split('\n'), delimiter=',')
				# import time, datetime

				# for rowProcess in reader:
				# 	print(rowProcess)
				# 	ctime_date = rowProcess['st_ctime']
				# 	#2017-03-20  8:09:38 PM
				# 	ctimeProcess = time.mktime(datetime.datetime.strptime(s, "%Y-%m-%d  %I:%m:%S %p").timetuple())

				# 	process = Inmemoryprocess.objects.get(grrhunt = currentHunt, grrworkstation = currentWorkstation, ctime=ctimeProcess, processname__contains=rowProcess['basename'][:-3])
				# 	if process :
				# 		process.AddHashFromCSVLine(row, ctimeProcess)
				# 		p.save()
				# 	else :
				# 		print("Miss!")
				# 		p = Inmemoryprocess()
				# 		p.LoadHashFromCSVLine(row, currentWorkstation, currentHunt)
				# 		p.save()

			else:
				print("Err")
		#Check Hash	
		if uploadType == "Hash" :
			HashList = Hash.objects.all()
			print("Starting checking hash")
			counter = 0
			for hashObject in HashList:
				print("Processing hash " + str(counter))
				print(hashObject)
				vtManager.checkHash(hashObject)
				hashObject.save()

				
				#print("Positive :" + str(h.positives))

	return HttpResponse(template.render(context, request))

def heatmap_page(request) :
	processRequest = request.GET.get("process", "tt")
	template = loader.get_template('workstations.html')
	ArrayWorkstations = []
	listProcess = []
	listWorkstation = []
	ListSockets = {}
	#if(processRequest == "tt"):

	WantedTree= ["lwsmd", "lwsmd"]
	StarterString = "SELECT x0.GRRWorkstation FROM InMemoryProcess AS x0"
	JoinString = " JOIN InMemoryProcess AS present  "
	ConditionString = " ON father.ppid=son.pid" 
	MatchProcessString = " WHERE x0.ProcessName LIKE 'ProcNameCST'"
	SonMatchString = " AND child.ProcessName LIKE 'ProcNameCST'"
	MatchSameWorkstation = "AND father.GRRWorkstation=son.GRRWorkstation"
	SecondPart = ""
	JoinPart = ""
	RequestSQL = StarterString
	WherePart = MatchProcessString
	WherePart = WherePart.replace("ProcNameCST", WantedTree[0])
	
	for x in range(1, len(WantedTree)):
		JoinPart = JoinPart + JoinString
		JoinPart = JoinPart.replace("present", "x" + str(x))
		CondJoin = ConditionString
		CondJoin = CondJoin.replace("father", "x" + str(x-1))
		CondJoin = CondJoin.replace("son",  "x" + str(x))
		JoinPart = JoinPart + CondJoin

		WherePart = WherePart + SonMatchString
		WherePart = WherePart.replace("child", "x" + str(x)).replace("ProcNameCST", WantedTree[x])
		WherePart = WherePart + MatchSameWorkstation
		WherePart = WherePart.replace("father", "x" + str(x-1)).replace("son", "x" + str(x))

	RequestSQL = RequestSQL + JoinPart + WherePart + " GROUP BY GRRWorkstation;"
	listWorkstation = []
	with connection.cursor() as c:
		result = c.execute(RequestSQL)
		for row in c:
			listWorkstation.append(row[0])
			print(row[0])

	print(RequestSQL)

	
	
	G=nx.DiGraph()
	nx.set_node_attributes(G, 'name', "Unknown")

	graphToCheck=nx.DiGraph()
	nx.set_node_attributes(G, 'name', "Unknown")

	#listWorkstation = Workstation.objects.all().filter(IDGRR=Result)

	template = loader.get_template('heatmap_process.html')
	#G.add_node(1)
	#ListProcess = Inmemoryprocess.objects.all().filter(grrworkstation=workstation)
	#G.add_node(-1, name=workstation)
	# G.add_node(6, name="Orphan.processname")
	# G.add_node(7, name="Orphan.processname")
	# G.add_edge(4,5)
	# G.add_edge(4,6)
	# G.add_edge(4,7)
	# ListProcess = Inmemoryprocess.objects.all().filter(grrworkstation=workstation)
	# for process in WantedTree:
	# 	graphToCheck.add_node()

	# G.add_node(-1, name=workstation)
	# for process in ListProcess:
	# 	tmpNode = node_Process(process)
	# 	listNode[process.pid] = tmpNode
	# 	nbrSocket = str(Socket.objects.all().filter(grrworkstation=workstation, pid=process.pid).count())
	# 	try:
	# 		G.add_node(process.pid, name=process.processname, nbrSocket=nbrSocket)
	# 	except KeyError:
	# 		print("")
	# for process in ListProcess:
	# 	try:
	# 		listNode[process.ppid]
	# 		G.add_edge(process.ppid,process.pid)
	# 	except :
	# 		G.add_edge(-1,process.pid)
	class SearchProcessForm(forms.Form):
		#your_name = forms.CharField(label='Machine', max_length=100)
		processes = forms.CharField(label='Process Tree', max_length=100)


	#Generate context for the tree	
	context = {'workstations':listWorkstation,'form':SearchProcessForm()
				}

	return HttpResponse(template.render(context, request))

def entropy(request):
	entropy = request.GET.get("entropy", "")
	listWorkstation = []
	DictProcess = {}

	if(entropy != ""):
		Listprocess = Inmemoryprocess.objects.all().filter(cmdlineEntropy__gte=entropy)
		print(Listprocess)
		for process in Listprocess:
			workname = Workstation.objects.get(idgrr=process.grrworkstation).name
			listWorkstation.append(workname)
			try:
				if DictProcess[workname] :
					DictProcess[workname].append(process)
			except KeyError:
					DictProcess[workname] = []
					DictProcess[workname].append(process)
		print(DictProcess)

	#Generate context for the tree	
	context = {'workstations':listWorkstation,'processes':DictProcess
				}

	template = loader.get_template('entropy.html')

	return HttpResponse(template.render(context, request))

def hashs(request):
	processRequest = request.GET.get("process", "")
	
	class SearchProcessForm(forms.Form):
		#your_name = forms.CharField(label='Machine', max_length=100)
		machine = forms.CharField(label='Process', max_length=100)


	ArrayWorkstations = []
	listProcess = []
	listWorkstation = []
	ListSockets = {}

	from django.db.models import Q

	template = loader.get_template('process_hash.html')
	listHash = Hash.objects.all().filter(~Q(positives="0") | Q(permalink__isnull=True))
	HashWorkstation = {}
	HashOccurency = {}
	HashNbr = {}
	for hashObject in listHash:
		occurencyList = []
		occurencyList.append(hashObject)
		HashLink = HashWorkstationLink.objects.all().filter(sha256=hashObject.sha256)
		HashNbr[hashObject.sha256] = HashLink.count()
		workstationList = []
		for link in HashLink:
			occurencyList.append(link)
			workstationObj = Workstation.objects.get(idgrr=link.grrworkstation)
			workstationList.append(workstationObj)
			break

		HashWorkstation[hashObject.sha256] = workstationList 
		HashOccurency[hashObject.sha256] = occurencyList
	DicTHashs = {}
	context = {'hashs':listHash,'form':SearchProcessForm(), 'hashWorkstation':HashWorkstation, 'hashOccurency':HashOccurency, 'Occurency':HashNbr}
	
	return HttpResponse(template.render(context, request))

def persistence(request):
	#Generate context for the persistence	
	context = {}

	template = loader.get_template('persistence.html')

	return HttpResponse(template.render(context, request))


def overview(request):
	workstation_id = request.GET.get("workstation", "")
	workstation_search = request.GET.get("workstation_search", "")
	class SearchWorkstationForm(forms.Form):
		#your_name = forms.CharField(label='Machine', max_length=100)
		machine = forms.CharField(label='Workstationsearch', max_length=100)


	ArrayWorkstations = []
	listProcess = []
	listWorkstation = []
	ListSockets = {}
	if(workstation_search == ""):
		print("void")
		template = loader.get_template('overview.html')
		listWorkstation = Workstation.objects.all().order_by("name")
		DicTreeProcess = {}

		sockets = []
		for workstation in listWorkstation:
			sockets = Socket.objects.all().filter(grrworkstation=workstation.idgrr)
			workstation.sockets = sockets.count()


		context = {'workstations':listWorkstation,'form':SearchWorkstationForm(initial={'machine':workstation_search})}
	else:
		print(workstation_search)
		template = loader.get_template('overview.html')
		listWorkstation = Workstation.objects.all().filter(name__contains=workstation_search).order_by("name")
		DicTreeProcess = {}

		sockets = []
		for workstation in listWorkstation:
			sockets = Socket.objects.all().filter(grrworkstation=workstation.idgrr)
			workstation.sockets = sockets.count()


		context = {'workstations':listWorkstation,'form':SearchWorkstationForm(initial={'machine':workstation_search})}


	return HttpResponse(template.render(context, request))

def overview_workstation(request, workstation="undefined"):


	ArrayWorkstations = []
	listProcess = []
	listWorkstation = []
	ListSockets = {}
	if(workstation != "undefined"):
		workstation_object = Workstation.objects.get(idgrr=workstation)
		template = loader.get_template('workstation.html')
		DicTreeProcess = {}

		sockets = []
		sockets = Socket.objects.all().filter(grrworkstation=workstation_object.idgrr)
		workstation_object.sockets = []
		for socket in sockets:
			workstation_object.sockets.append(socket)
		context = {'workstation':workstation_object,'sockets':sockets}


	return HttpResponse(template.render(context, request))

def registry(request):
	processRequest = request.GET.get("process", "")
	
	class SearchProcessForm(forms.Form):
		#your_name = forms.CharField(label='Machine', max_length=100)
		machine = forms.CharField(label='Registry', max_length=100)


	ArrayWorkstations = []
	listProcess = []
	listWorkstation = []
	ListSockets = {}
	if(processRequest == ""):
		template = loader.get_template('RegistryKey.html')
		listWorkstation = Workstation.objects.all().order_by("name")
		DicTreeProcess = {}

		sockets = []
		for workstation in listWorkstation:
			registries = RegistryKey.objects.all().filter(grrworkstation=workstation.idgrr)
			workstation.sockets = []
			for registry in registries:
				workstation.sockets.append(socket)

		context = {'workstations':listWorkstation,'form':SearchProcessForm(initial={'machine':processRequest}),'sockets':DicTreeProcess}

	else:
		template = loader.get_template('RegistryKey.html')

		context = {'workstations':listWorkstation,'form':SearchProcessForm(initial={'machine':processRequest}),'sockets':DicTreeProcess}


	# for proc in listProcess:
	# 	try:
	# 		ArrayWorkstations.append(proc.grrworkstation)
	# 	except:
	# 		pass
	


	

	return HttpResponse(template.render(context, request))
