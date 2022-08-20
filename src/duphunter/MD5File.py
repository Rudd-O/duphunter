#!/usr/bin/env python

from os.path import *
import os

class FileObjectError(Exception):
     def __init__(self, value):
         self.value = value
     def __str__(self):
         return repr(self.value)


class FileObject:
	filename = None
	fullpathname = None
	path = None
	md5sum = None
	size = None
	
	def __init__ (self,pathname,sum):
		if pathname is None:
			raise FileObjectError("Path passed to FileObject cannot be None")
		f  = open(pathname)
		f.close()
		
		self.fullpathname = pathname
		self.filename = basename(pathname)
		if self.filename is None:
			raise FileObjectError("Calculated basename is None")
		
		self.path = dirname(pathname)
		self.md5sum = sum
		self.size = os.stat(pathname).st_size
		
	def getFilename (self):
		#if self.filename is None:
			#raise FileObjectError, "Calculated basename is None"
		return self.filename
	
	def getFullPathname (self):
		#if self.filename is None:
			#raise FileObjectError, "Calculated basename is None"
		return self.fullpathname
	
	def getPath (self):
		return self.path
	
	def getSum (self):
		return self.md5sum

	def getSize (self):
		return self.size


class MD5FileProcessor:
	file = None
	filehandle = None
	lines = None
	dictionary = None
	def __init__(self,filename):
		self.file = filename
		self.filehandle = open("Sumas")
		self.lines = self.filehandle.readlines()
		
	def getDictionary(self):
		tel = dict()
		for line in self.lines:
			if len(line) > 1:
				hash = line[0:32]
				filename = line[34:-1]
				try:
					fileobject = FileObject(filename,hash)
					#if fileobject is None:
					#	print "Not opened file " + filename
					#else:
					if (hash in tel):
						matches = tel[hash]
					else:
						matches = []
						tel[hash] = matches
					#print "appending instance " + fileobject.fullpathname
					matches.append(fileobject)
				except IOError:
					pass
					#print "skipping appending " + filename
				
		self.dictionary = tel
		return tel

	def getDupes(self):
		dictionary = self.getDictionary();
		filtered = dict()
		
		for a in dictionary:
			if len(dictionary[a]) > 1:
				filtered[a] = dictionary[a]
		
		return filtered

def shell_escape(string):
	"""Return an escaped string suitable for passing as a parameter in a BASH shell command line"""
	unallowed_chars = "\$`\\\""
	deststring = ""
	
	for char in string:
		if char in unallowed_chars: newchar = "\\"+char
		else: newchar = char
		deststring = deststring + newchar
	return '"' + deststring + '"'
	

def mp3sum(file):
	import subprocess
	frames = 385
	status,output = subprocess.getstatusoutput("mpg321 -sq -n %d %s | md5sum -"%(frames,shell_escape(file)))
	output = output.split(" ",1)
	if status != 0:
		raise Exception("Error in mp3sum: return code %s"%(status))
	return output[0][0:32]

# setfattr -n user.Dupfinder.mp3sum -v %s %s

from extattr import getfattr,setfattr

from queue import Queue, Empty

class MD5FileProcessor2:
	file = None
	lines = None
	dictionary = None
	
	def __init__(self,path):
		self.path_queue = Queue()
		self.appendPath(path)
# 		self.filehandle = open("Sumas")
# 		self.lines = self.filehandle.readlines()
	
	def startScan(self,notify_function,notify_end,notify_new_dupe):
		from threading import Thread
		t = Thread(target=self._doScan,args=(notify_function,notify_end,notify_new_dupe))
		t.setDaemon(True)
		t.start()
		
	def appendPath(self,path):
		self.path_queue.put(path)
		
	def _doScan(self,notify_function,notify_end,notify_new_dupe):
		import os
		self.dictionary = dict()
		
		while True:
			try: thepath = self.path_queue.get_nowait()
			except Empty: break
		
			for root, dirs, files in os.walk(thepath):
				for file in files:
					if not file[-4:] in [ ".mp3" , ".MP3" ]: continue
					thefile = os.path.join(root,file)
					if os.path.islink(thefile): continue
					try:
						try:
							thehash = getfattr(thefile,"user.Dupfinder.mp3sum")
		# 					print "Got from cache: %s"%thehash
						except KeyError:
							thehash = mp3sum(thefile)
							setfattr(thefile,"user.Dupfinder.mp3sum",thehash)
		# 					print "Set into cache: %s"%thehash
					except IOError as e:  # catch eoperation not supported
						if e.errno == 95: thehash = mp3sum(thefile) # just do the hash, and do not cache it
						else: raise
	# 				print "scanned %s with sum %s"%(thefile,thehash)
					notify_function("scanned %s with sum %s"%(thefile,thehash))
					if thehash in self.dictionary:
						self.dictionary[thehash].append(FileObject(thefile,thehash))
						notify_new_dupe()
					else: self.dictionary[thehash] = [FileObject(thefile,thehash)]
		
		notify_end()

	def getDupes(self):
		dictionary = self.dictionary
		filtered = dict()
		
		for a in dictionary:
			if len(dictionary[a]) > 1:
				filtered[a] = dictionary[a]
		
		return filtered
