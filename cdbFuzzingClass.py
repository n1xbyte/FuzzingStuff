class cdbfuzz:
	def __init__(self,app,crashd,debugger):
		if os.path.exists(app) == True & os.path.exists(crashd) == True & os.path.exists(debugger) == True:
			global programname
			global crashdir
			global cdblocation
		else:
			print "[+] Please check all given paths"
			exit()
		programname = app
		print "[+] Target application path =>",programname
		crashdir = crashd
		print "[+] Crash Dir => ",crashdir
		cdblocation = debugger
		print "[+] Debugger path => ",cdblocation
	def startapp(self,input_file):
		cmd = cdblocation+' '+'-c ".logopen '+crashdir+'temp.log;g;.logclose '+crashdir+'temp.log" '+programname+' '+input_file
		process = subprocess.Popen(cmd)
		return process
	def kill(self,proc_obj):
		proc_obj.terminate()
	def wascrash(self):#Did the prog. crash last time ??
		log = open(crashdir+'temp.log').read()
		if "Access violation - code" in log:
			return True
	def dumpcrash(self,crash_filename):
		prog = programname.split('\\')[-1:][0]
		shutil.copyfile(crash_filename, crashdir+prog+'_'+datetime.now().strftime("%y-%m-%d-%H-%M")+'_Crash'+".m3u")
