#!/usr/bin/env python

import gobject

import pygtk
pygtk.require('2.0')


import gtk
import gnome.ui

from inspect import *

import string


import os
from os import *

import demos
import MD5File

TITLE_COLUMN = 0
MODULE_COLUMN = 1





#for a in getmembers(gnome):
#	print a
#help(gnome.Program)
#exit
#print gnome.__doc__






class PyGtkDemo(gnome.ui.App):
    program = None
    mainview = None
    treeview = None
    statusbar = None
    
    def __init__(self,program,name,title):
	
	self.program = program
	gnome.ui.App.__init__(self,name,title)
	
	menubar = gtk.MenuBar()
	self.set_menus(menubar)
	
	statusbar = gtk.Statusbar()
	self.statusbar = statusbar
	self.set_statusbar(statusbar)
	
        self.connect('destroy', lambda w: gtk.main_quit())
        self.set_default_size(600, 400)

        self.mainview = gtk.HPaned()

	#vbox.pack_start(menubar,FALSE,TRUE)
	#vbox.add(hbox)
	#vbox.pack_end(statusbar,FALSE,TRUE)

#	self.show_all()
	
#	print "Showing window"
	
#	self.show()
	
	treeview = self.create_treeview()
        self.treeview = treeview.get_children()[0]
	self.mainview.pack1(treeview)
	
	self.set_contents(self.mainview)
	
	
    
    def notificarStatus(self,message):
		e = self.statusbar.get_context_id("e")
		self.statusbar.push( e,message)
		
    def borrar(self,w):
	
		duplicatelist = self.duplicatelist
		filecontrol = w.filecontrol
		fileobject = filecontrol.fileobject
		matchlist = duplicatelist[fileobject.getSum()]
	
		try:
			remove(fileobject.getFullPathname())
		except Exception:
			self.notificarStatus("Could not remove " + fileobject.getFullPathname())
			return
			
		matchlist.remove(fileobject)
		self.notificarStatus("Removed file " + fileobject.getFullPathname())
		
		if matchlist == []:
			del duplicatelist[fileobject.getSum()]
			selection = self.treeview.get_selection()
			selected = selection.get_selected()
			model, iter = selected
			model.remove(iter)
		
		if len(matchlist) == 1:
			selection = self.treeview.get_selection()
			selected = selection.get_selected()
			model, iter = selected
			#arbol iter path
			#con el iter saco el path
			#con el path muevo next
			#como saco el path
			#con el iter
			path1, = model.get_path(iter)
			path1 = path1 + 1
			pathtuple = path1,
			self.treeview.set_cursor(pathtuple,None,0)
			

		filecontrol.parent.remove(filecontrol)
		
		self.treeview.grab_focus()
		
    def tocar(self,w):
		fileobject = w.parent.parent.parent.fileobject
		pid = os.spawnlp(os.P_NOWAIT,"xmms","xmms",path.abspath(fileobject.getFullPathname()))
		pass
	
    def openfolder(self,w):
		fileobject = w.parent.parent.parent.fileobject
		pid = os.spawnlp(os.P_NOWAIT,"konqueror","konqueror",path.abspath(fileobject.getPath()))
		pass
		
    def retag(self,w):
		fileobject = w.parent.parent.parent.fileobject
		pid = os.spawnlp(os.P_NOWAIT,"easytag","easytag",path.abspath(fileobject.getPath()))
		pass
    
    
    def _create_buttonbox(self,file_control):
	buttonbox = gtk.VButtonBox()
        buttonbox.set_size_request(-1, 40)

        bborrar = gtk.Button("Eliminar","gtk-delete")
	bborrar.filecontrol = file_control
	bborrar.connect('clicked', self.borrar)
        btocar = gtk.Button("Reproducir")
	btocar.filecontrol = file_control
	btocar.connect('clicked', self.tocar)
        bretag = gtk.Button("Etiquetar")
	bretag.filecontrol = file_control
	bretag.connect('clicked', self.retag)
        bopenfolder = gtk.Button("Ver carpeta")
	bopenfolder.filecontrol = file_control
	bopenfolder.connect('clicked', self.openfolder)
	buttonbox.pack_start(bborrar)
	buttonbox.pack_start(btocar)
	buttonbox.pack_start(bretag)
	buttonbox.pack_start(bopenfolder)

	return buttonbox    
    
    

    def create_treeview(self):
        model = gtk.ListStore(gobject.TYPE_STRING,
                              gobject.TYPE_STRING)
        
        #adjustable = gtk.Adjustment(1,0,400,20,50,50)
	layout = gtk.ScrolledWindow()
	treeview = gtk.TreeView(model)
	layout.add(treeview)
        #treeview.connect('row-activated', self.row_activated_cb)
        selection = treeview.get_selection()
        selection.set_mode('single')
        layout.set_size_request(200, 400)
	treeview.show()
        
        cell = gtk.CellRendererText()
        column = gtk.TreeViewColumn("Ocurrencia", cell, text=TITLE_COLUMN)
        treeview.append_column(column)

        selection.connect('changed', self.selection_changed_cb)
        self.model = model
        return layout
    
    def fill_treeview(self,keys):
	self.duplicatelist = keys
        model = self.treeview.get_model()
	model.clear()
	
	for hash in keys:
            iter = model.append()
            match = self.duplicatelist[hash]
	    firstobject = match[0]
	    
	    model.set_value(iter, TITLE_COLUMN, firstobject.getFilename())
            model.set_value(iter, MODULE_COLUMN, hash)
    
    def create_text(self, is_source=False):
        scrolled_window = gtk.ScrolledWindow()
        scrolled_window.set_policy(gtk.POLICY_AUTOMATIC, gtk.POLICY_AUTOMATIC)
        scrolled_window.set_shadow_type(gtk.SHADOW_IN)

        text_view = gtk.TextView()
        
	scrolled_window.add(text_view)

        buffer = gtk.TextBuffer(None)
        text_view.set_buffer(buffer)
        text_view.set_editable(False)
        text_view.set_cursor_visible(False)

        text_view.set_wrap_mode(not is_source)

        return scrolled_window, buffer

    def selection_changed_cb(self, selection):
        selection = selection.get_selected()
        if not selection:
            return
        
        model, iter = selection

	if model is not None and iter is not None:
		sum = model.get_value(iter, MODULE_COLUMN)
		self.display(sum)

    def read_module(self, module):
        filename = module.__file__
        if filename[-4:] == '.pyc':
            filename = filename[:-1]
        fd = open(filename)
        return fd.read()
    
    def display(self, sum):
	n = gtk.VBox()
	
	filelist = self.duplicatelist[sum]

	for iter in filelist:
		scrolled_window, bla = self.create_text(False)
	        scrolled_window.set_size_request(400, 100)
		scrolled_window.textbuffer = bla
		tag = bla.create_tag('title')
		tag.set_property('font', 'Sans 18')
		self.fill_textbuffer(bla,iter)
		
		n.scrolled_window = scrolled_window
		
		file_control= gtk.HBox()
		file_control.fileobject = iter
		
	        
		controls = self._create_buttonbox(file_control)
		alignment= gtk.Alignment(0.5,0.5,0.5,0.5)
		alignment.add(controls)
		file_control.pack_start(alignment,False,True)
		file_control.pack_end(scrolled_window,True,True)
		
		n.add(file_control)
        
	child = self.mainview.get_children()
	if len(child) > 1:
		self.mainview.remove(child[1])
	
	self.mainview.pack2(n,True,True)
	
	self.notebook = n
	self.show_all()
	
	
	

    def fill_textbuffer(self,buffer,fileobject):
	#buffer = self.info_buffer
        iter = buffer.get_iter_at_offset(0)

	#lines = [module]
	#print lines[0]
        buffer.insert(iter, fileobject.getFilename())
        start = buffer.get_iter_at_offset(0)
        buffer.apply_tag_by_name('title', start, iter)
        buffer.insert(iter, '\n')
        buffer.insert(iter, '\n')
        buffer.insert(iter, '\n')
        buffer.insert(iter, "Folder: " + fileobject.getPath())
        buffer.insert(iter, '\n')
        buffer.insert(iter, "MP3 hash: " + fileobject.getSum())
        buffer.insert(iter, '\n')
        buffer.insert(iter, "File size: " + str(fileobject.getSize()))
        buffer.insert(iter, '\n')




       
            
class Dupfinder(gnome.Program):
	window_titlebar = "Duplicate MP3 finder"
	window = None
	id = "Dupfinder"
	version = "0.0.1"
	duplicatekeys = None
	
	def __init__(self):
		gnome.program_init(self.id,self.version)
		self.window = PyGtkDemo(self,self.id,self.window_titlebar)
		
# 	def cargarArchivo(self,archivo):
# 		self.window.notificarStatus("Loading file " + archivo +"...")
# 		processor = MD5File.MD5FileProcessor(archivo)
# 		self.duplicatekeys= processor.getDupes()
# 		self.window.fill_treeview(self.duplicatekeys)
# 		self.window.notificarStatus("Loaded file sumas: " + str(   len(self.duplicatekeys)    ) + " duplicates matched")
	
	def notify_scan(self,string):
		gobject.idle_add(self.window.notificarStatus,string)
		
	def _notify_scan(self,string):
		"""Main thread version"""
		self.window.notificarStatus(string)
	
	def notify_end(self):
		gobject.idle_add(self._notify_end)

	def _notify_end(self):
		"""Main thread version"""
		self.window.notificarStatus("Finished scanning")
		self.window.fill_treeview(self.processor.getDupes())
	
	def notify_new_dupe(self):
		gobject.idle_add(self._notify_new_dupe)

	def _notify_new_dupe(self):
		"""Main thread version"""
		self.window.notificarStatus("New dupe!")
		self.window.fill_treeview(self.processor.getDupes())
	
	def scanDir(self,path):
		
		if not hasattr(self,"processor"):
		
			self.window.notificarStatus("Scanning directory: " + path  +"...")
			self.processor = MD5File.MD5FileProcessor2(path)
			notify_function = self.notify_scan
			end_function = self.notify_end
			dupe_function = self.notify_new_dupe
	# 		self.window.notificarStatus("Loaded directory: " + str(   len(self.duplicatekeys)    ) + " duplicates matched")
			self.processor.startScan(notify_function,end_function,dupe_function)
	# 		self.duplicatekeys= processor.getDupes()
		else:
			#race condition, but what the fuck!
			self.window.notificarStatus("Appending to scanner: " + path  +"...")
			self.processor.appendPath(path)
	
	
			
	def start(self):
		self.window.show_all()
		#self.scanDir("/media/MUSIC/audio")
		#self.scanDir("/home/rudd-o/Musica")
		#self.scanDir("/home/rudd-o/download/DC")
		self.scanDir("/home/rudd-o/download/gtk-gnutella/complete")
		#self.scanDir("/home/rudd-o/Needs attention/Inbox/Musica")
		gtk.main()




gtk.threads_init()
d = Dupfinder()
d.start()

