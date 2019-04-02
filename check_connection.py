import threading
import json
import time
from netmiko import ConnectHandler
import socket

class Connections(): 
	def __init__(self):
		self.connections = {}
		self.connection_status = {}
		self.close_connection = 1
	def setup_connection_with_servers(self):
		'''Create connection with each server.
		   Each connection is a separate thread and the thread is running till the time connection is up.
		   If the connection goes down, new connection will be created along with the thread.
		'''
        	while self.close_connection==1:
            		if not self.connections:

                		with open ("connection_details.txt") as json_file:
                    			self.server_data=json.load(json_file)

                    		for i in self.server_data:
                        		#self.connection_thread_with_servers(self.server_data[i])
                        		t = threading.Thread(target=self.connection_thread_with_servers, args = (self.server_data[i],))
                        		t.daemon=True
                        		t.start()
				time.sleep(10)
            		else:
                		for i in self.server_data:
					if self.server_data[i]["ip"] not in self.connections or not self.server_data[i]["ip"]:
                    				#self.connection_thread_with_servers(self.server_data[i])
                    				t = threading.Thread(target=self.connection_thread_with_servers, args = (self.server_data[i],))
                    				t.daemon=True
                    				t.start()
				




	def connection_thread_with_servers(self, server_data):
		'''Function for creating a separate thread for each connection.
		   The thread will also check if the connection is up.
		   If the connection goes down, the function will exit.
		'''
		print(server_data["ip"])
		connection_up = 0
		self.connections[server_data["ip"]] = ""
		
        	self.connections[server_data["ip"]] = ConnectHandler(**server_data)
		print(self.connections)
		connection_up = 1
		
		print("BBBBBBBBBB")	
		#del self.connections[server_data["ip"]]
			
        	null = chr(0)
        	while connection_up==1 and self.close_connection==1 and self.connections[server_data["ip"]]:
       			try:
                		self.connections[server_data["ip"]].write_channel(null)
                		print("***********************")
                		time.sleep(1)
				self.connection_status[server_data["ip"]] = connection_up
                        	with open ('connection_status.txt', 'w') as json_file:
                                	json.dump(self.connection_status, json_file)

        		except (socket.error, EOFError):
				print("AAAAAAAAAA")
				connection_up = 0
                		del self.connections[server_data["ip"]]
                		break
		
		if not self.connections[server_data["ip"]]:
			connection_up = 0
			del self.connections[server_data["ip"]]
		self.connection_status[server_data["ip"]] = connection_up
                with open ('connection_status.txt', 'w') as json_file:
                	json.dump(self.connection_status, json_file)
		
		return

if __name__=="__main__":
	try:
		connection = Connections()
		connection.setup_connection_with_servers()
	except KeyboardInterrupt:
		print("Closing Connections to Servers")
		connection.close_connection=0
