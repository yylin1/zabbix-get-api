from keystoneauth1 import loading
from keystoneauth1 import session
from novaclient import client

import ceilometerclient.client

import json
import urllib2
from urllib2 import URLError
import sys

import threading 
import time

class NovaManager(object):

	def __init__(self, username, password, project_name, auth_url):
		self.username = username
		self.password = password
		self.project_name = project_name
		self.auth_url = auth_url
		self.novaConnection = self.connect()

	def connect(self):
		loader = loading.get_plugin_loader('password')
		auth = loader.load_from_options(auth_url=self.auth_url,username=self.username,password=self.password,project_name=self.project_name)
		sess = session.Session(auth=auth)
		nova = client.Client(2, session=sess)
		return nova

	def get_interface(self):
		servers_info=[]
		servers=self.novaConnection.servers.list()

		for i in range(0,len(servers)):
		
			server_id=servers[i].id
			server_id=server_id.encode('ascii','ignore')
			server_name=servers[i].name
			server_name=server_name.encode('ascii','ignore')
			server_dict=servers[i].to_dict()
			whitch_host=server_dict.get('OS-EXT-SRV-ATTR:host')
			whitch_host=whitch_host.encode('ascii','ignore')
			
			diagnostics=self.novaConnection.servers.diagnostics(servers[i])
			server_memory=diagnostics[1].get("memory")
			server_memory=server_memory/1024
			servers_info.append([server_id,server_name,whitch_host,server_memory])

		return servers_info,servers

	def get_interface_detail(self,interface):
		interface_info=self.novaConnection.servers.diagnostics(interface)
		return interface_info

	def do_live_migrate(self,move_to_host,server):

		#nova.servers.live_migrate(host=move_to_host,block_migration=False,server=server_id)
		server.live_migrate(host=move_to_host)
		return True


	def get_compute_usage(self):
		compute_usage=[]

		hosts=self.novaConnection.hosts.list()
		for i in range(0,len(hosts)):
			
			service=hosts[i].service
			if(service=="compute"): 
				host_name=hosts[i].host_name
				host_name=host_name.encode('ascii','ignore')
				host_info=self.novaConnection.hosts.get(host_name)
				memory_total=host_info[0].memory_mb
				memory_used_now=host_info[1].memory_mb
				memory_free = memory_total-memory_used_now

				cpu_total=host_info[0].cpu
				cpu_used_now=host_info[1].cpu
				cpu_free = cpu_total-cpu_used_now

				disk_total=host_info[0].disk_gb
				disk_used_now=host_info[1].disk_gb
				disk_free = disk_total-disk_used_now
				

				compute_usage.append([host_name,memory_free,cpu_free,disk_free])
		return compute_usage



class CeilometerManager(object):

	def __init__(self, os_username, os_password, os_tenant_name, os_auth_url):
		self.os_username = os_username
		self.os_password = os_password
		self.os_tenant_name = os_tenant_name
		self.os_auth_url = os_auth_url
		self.ceilometeraConnection = self.connect()


	def connect(self):
		cclient = ceilometerclient.client.get_client(2, 
			os_username=self.os_username, 
			os_password=self.os_password, 
			os_tenant_name=self.os_tenant_name, 
			os_auth_url=self.os_auth_url)

		return cclient

	def get_data(self, interface_id, meter_type, num_limit):

		query = [dict(field='resource_id', op='eq', value=interface_id), dict(field='meter',op='eq',value=meter_type)]
		results=self.ceilometeraConnection.new_samples.list(q=query, limit=num_limit)

		return results

	def processing_data(self, datas):

		volume,timestamp="",""
		#print(datas)
		for data in datas:
			#print(data)
			data_dict=data.to_dict()
			volume=data_dict.get('volume')
			#volume=volume.encode('ascii','ignore')

			timestamp=data_dict.get('timestamp')
			timestamp=timestamp.encode('ascii','ignore')		

		return volume,timestamp



class ZabbixTools:
	def __init__(self,address,username,password):

		self.address = address
		self.username = username
		self.password = password

		self.url = '%s/api_jsonrpc.php' % self.address
		self.header = {"Content-Type":"application/json"}



	def user_login(self):
		data = json.dumps({
							"jsonrpc": "2.0",
							"method": "user.login",
							"params": {
										"user": self.username,
										"password": self.password
										},
							"id": 0
							})

		request = urllib2.Request(self.url, data)
		for key in self.header:
			request.add_header(key, self.header[key])

		try:
			result = urllib2.urlopen(request)
		except URLError as e:
			print "Auth Failed, please Check your name and password:", e.code
		else:
			response = json.loads(result.read())
			result.close()
			#print response['result']
			print('\n')
			self.authID = response['result']
			return self.authID

	def trigger_get(self):
		description=""
		status=""
		data = json.dumps({
							"jsonrpc":"2.0",
							"method":"trigger.get",
							"params":{
										"output": [
													"triggerid",
													"description",
													"status",
													"priority"
										 			],
										"filter": {
													"value": 1
													},
										"sortfield": "priority",
										"sortorder": "DESC",
										"min_severity": 4,
										"skipDependent": 1,
										"monitored": 1,
										"active": 1,
										"expandDescription": 1,
										"selectHosts": ['host'],
										"selectGroups": ['name'],
										"only_true": 1
									},
							"auth": self.user_login(),
							"id":1
		})

		request = urllib2.Request(self.url, data)
		for key in self.header:
			request.add_header(key, self.header[key])

		try:
			result = urllib2.urlopen(request)
		except URLError as e:
			print "Error as ", e
		else:
			response = json.loads(result.read())
			#print (response, "\n")
			result.close()
			issues = response['result']
			content = ''
			if issues:
				#print (issues)
				#print (len(issues))
				for line in issues:
					#content = content + "%s:%s:%s:%s\n---------------\n" % (line['groups'],line['hosts'],line['description'],str(line['status']))
					print ("Trigger message list:  [ %s ] view :status %s" % (line['description'],line['status']))
					description=line['description']
					status=line['status']
				#print ('line print ',line)
			else:
				print ("No Trigger load high problem in list.")
			return content,description,status


def detection_vm():

##load server,compute data
	nv=NovaManager('admin','admin','admin','http://192.168.0.8:35357/')
	interface,servre=nv.get_interface()
	compute_usage=nv.get_compute_usage()

	print(interface)
	print("----------------")
	#print(interface[0])
	#print("----------------")
	#print(interface[0][1])
	#print("----------------")

	print(compute_usage)
	print("----------------")
	#print(compute_usage[0])
	#print("----------------")
	#print(compute_usage[0][1])
	#print("----------------")

## use zabbix
	zt = ZabbixTools(address="http://10.111.200.8/zabbix/api_jsonrpc.php", username="admin", password="zabbix")
	content,description_str,status = zt.trigger_get()
	#print (content)

	if(status=="0"):
		uselessstr,description = description_str.split(':')
		print(description)
##find target compute's server
		insex_list=[]
		for i in range(0,len(interface)):
			if(description==interface[i][2]): insex_list.append(i)
		print(insex_list)
## find whitch vm's cpu usage is max
		interface_state=[]
		cm=CeilometerManager('admin','admin','admin','http://192.168.0.8:5000/')
		for i in range(0,len(insex_list)):
	
			cpu_util=cm.get_data(interface[insex_list[i]][0],'cpu_util',1)
			cpu_volume,cpu_timestamp=cm.processing_data(cpu_util)
			memory_usage=cm.get_data(interface[insex_list[i]][0],'memory.usage',1)
			memory_volume,memory_timestamp=cm.processing_data(memory_usage)
			interface_state.append([interface[insex_list[i]][0],interface[insex_list[i]][1],cpu_volume,cpu_timestamp,memory_volume,memory_timestamp])
	
		cpu_max=0
		cpu_max_index=0
		for i in range(0,len(interface_state)):
			if(interface_state[i][2]>cpu_max):
				cpu_max=interface_state[i][2]
				cpu_max_index=i
	
		print(interface_state)
		print("----------------")
		#print(interface_state[0])
		#print("----------------")
		#print(interface_state[0][1])
	
	
## find free compute
		cpu_free=0
		cpu_free_index=0
		for i in range(0,len(compute_usage)):
			if(compute_usage[i][2]>cpu_free and compute_usage[i][0]!=description):
				cpu_free=compute_usage[i][2]
				cpu_free_index=i
	
	
## do live migrate
		print(interface[insex_list[cpu_max_index]][1])
		print(compute_usage[cpu_free_index][0])
		nv.do_live_migrate(compute_usage[cpu_free_index][0],servre[insex_list[cpu_max_index]])
		#nv.do_live_migrate(compute_usage[0][0],servre[0])

	global timer
	timer = threading.Timer(900, detection_vm)
	timer.start()



def main():
	timer = threading.Timer(1,detection_vm)
	timer.start()
	
	time.sleep(800) 
	timer.cancel()


if __name__ == '__main__':
	main()
