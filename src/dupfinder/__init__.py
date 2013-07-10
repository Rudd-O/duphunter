#!/usr/bin/env python

import sys
import os
import hashlib
import signal
import collections
import time
from PyQt4 import QtCore
from PyQt4.QtCore import QObject, pyqtSignal, QString, QTimer
from PyQt4 import uic
from PyQt4 import QtGui
from PyQt4.QtGui import QApplication, QFileDialog, QProgressBar
from threading import Thread, Lock

def md5ify(filepath):
    f = open(filepath, 'rb')
    h = hashlib.md5()
    s = 'arsentarsntirsa'
    while s != '':
        s = f.read(16384)
        h.update(s)
    return h.hexdigest()

def estimate_scan_dir(folder, filter_func):
    counter = 0
    for path, subfolders, files in os.walk(folder):
        for f in files:
            full_path = os.path.join(path, f)
            if not filter_func(full_path): continue
            if os.path.isfile(full_path) and not os.path.islink(full_path):
                counter = counter + 1
    return counter

def scan_dir(folder, filter_func, hashfunc):
    '''Scans a folder's files recursively and synchronously, adding the
    files' hash func results to the `sums` dictionary of lists, where the
    key is the result of the hash func, and the value is the list of files
    that compute to that hash func result.'''
    for path, subfolders, files in os.walk(folder):
        for f in files:
            full_path = os.path.join(path, f)
            if not filter_func(full_path): continue
            if os.path.isfile(full_path) and not os.path.islink(full_path):
                sum_ = md5ify(full_path)
                yield full_path, sum_


class TreeHasher(QObject):
    '''Asynchronously scans a tree of files for their crypto sums, in a thread.

    While the scan is taking place, each hashed file causes two signals to be
    emitted:
      hashed (path, sum)
      progress (files scanned, total files)
    When the process begins, the signal begun is emitted.
    When the process ends, the signal finished is emitted.
    When the process experiences an error, the signal error is emitted, with
    the accompanying exception being its sole parameter.

    If the scanner is stopped with stop(), then no signals are emitted anymore.
    '''

    hashed = pyqtSignal((str, str))
    progress = pyqtSignal((int,int))
    begun = pyqtSignal()
    finished = pyqtSignal()
    error = pyqtSignal((BaseException,))

    def __init__(self, directory, filter_func=lambda: True, hasher=md5ify):
        '''Initializes a duplicate finder for a particular directory.

        The hasher is a hash function which will take a path as only parameter
        and provide a hash in return.

        The filter_func parameter is a function which will take a path and
        return any value that boolean-evaluates to True if the path is to be
        scanned.
        '''
        QObject.__init__(self)
        self.hasher = hasher
        self.directory = directory
        self.filter_func = filter_func
        self.t = None
        self.stopped = False

    def _scan(self):
        if not self.stopped: self.begun.emit()
        try:
            numfiles = estimate_scan_dir(self.directory, self.filter_func)
            counter = 0
            for full_path, sum_ in scan_dir(self.directory, self.filter_func, self.hasher):
                if self.stopped: break
                counter = counter + 1
                self.hashed.emit(full_path, sum_)
                self.progress.emit(counter, numfiles)
            if not self.stopped: self.finished.emit()
        except BaseException, e:
            if not self.stopped: self.error.emit(e)
            raise

    def start(self):
        '''Dispatches the scan.  It is an error to call this twice. Seriously,
        your program will be fucked.'''
        self.t = Thread(target=self._scan)
        self.t.setDaemon(True)
        self.t.start()
    
    def stop(self):
        '''Stops the scan.  It is an error to call this if the scan is not ongoing.'''
        self.stopped = True
    
    def wait(self):
        '''Joins the scanner thread until it stops.  It is an error to call this
        if the scan has not been stopped with stop().'''
        assert self.t, "wait() called when scan not ongoing"
        self.t.join()


class DuplicateDetector(QObject):
    '''
    Receives pairs of (hash, path) through its add() method.  Emits signal duplicate_found for each received pair (hash, path) if the hash is seen more than once.  If the path sent via
    add() is already known and has the same hash, it is ignored.
    '''

    duplicate_found = pyqtSignal((str, str))

    def __init__(self):
        QObject.__init__(self)
        self.dupes = {}

    def add(self, sum_, path):
        '''Add the pair sum, path to the duplicate detector, trigger signal
        if appropriate.'''
        if sum_ not in self.dupes: self.dupes[sum_] = []
        paths = self.dupes[sum_]
        if path in paths: return
        paths.append(path)
        if len(paths) < 2: return
        if len(paths) == 2: self.duplicate_found.emit(sum_, paths[0])
        self.duplicate_found.emit(sum_, paths[-1])


class HashAggregator(QObject):
    '''
    Incrementally aggregates pairs of (hash, path) into a TreeModel structure
    self.model.  Emits signal added (hash, path) when a hash, path pair is added.
    '''

    added = pyqtSignal((str, str))

    def __init__(self):
        '''Pass the TreeModel instance here'''
        QObject.__init__(self)
        self.model = QtGui.QStandardItemModel()
        header = [QtGui.QStandardItem(),QtGui.QStandardItem()]
        header[0].setText("Matches")
        header[1].setText("Folder")
        self.model.setHorizontalHeaderItem(0, header[0])
        self.model.setHorizontalHeaderItem(1, header[1])

    def add(self, sum_, path):
        '''Aggregate the sum and the path to the self.model structure.'''
        try:
            item = [ self.model.item(x)
                 for x in xrange(self.model.rowCount())
                 if self.model.item(x).data() == sum_
            ][0]
        except IndexError, e:
            item = QtGui.QStandardItem()
            item.setText(sum_)
            item.setData(sum_)
            self.model.appendRow(item)
        str_path = str(path.toUtf8())
        fn = os.path.basename(str_path)
        dn = os.path.dirname(str_path)
        fitem = QtGui.QStandardItem()
        ditem = QtGui.QStandardItem()
        fitem.setData(path)
        ditem.setData(path)
        fitem.setText(fn)
        ditem.setText(dn)
        ditem.setTextAlignment(QtCore.Qt.AlignRight)
        item.insertRow(item.rowCount(), [fitem, ditem])


class DupfinderApp(QApplication):
    def __init__(self, *args, **kwargs):
        QApplication.__init__(self, *args, **kwargs)
        self.main_window = uic.loadUi(
            os.path.join(
                os.path.dirname(__file__), "dupfinder.ui"
            )
        )
        self.progressbar = QProgressBar()
        self.progressbar.setVisible(False)
        self.main_window.statusbar.addPermanentWidget(self.progressbar)
        self.main_window.pushButton.clicked.connect(self.pushButton_clicked)
        self.dupedetector = DuplicateDetector()
        self.aggregator = HashAggregator()
        self.main_window.treeView.setModel(self.aggregator.model)
        header = self.main_window.treeView.header()
        header.setResizeMode(QtGui.QHeaderView.ResizeToContents)
        self.aggregator.model.rowsInserted.connect(self._autoexpand_rows)
        self.dupedetector.duplicate_found.connect(self.aggregator.add)
        self.aggregator.added.connect(self.on_duplicate_found)
        self.scanners = {}
        self.aboutToQuit.connect(self.stop_scanners)

    def _autoexpand_rows(self, modelindex, start_int, end_int):
        '''Autoexpands rows added to the treeview as they are added'''
        self.main_window.treeView.expand(modelindex)

    def stop_scanners(self):
        # this is the only thing that stops the program from dying when closed
        # abruptly when very recently open.  to stop the scanners!
        for s in list(self.scanners.keys()):
            s.stop()
        for s in list(self.scanners.keys()):
            s.wait()
            del self.scanners[s]

    def dispatch_scan(self, qstr_directory):
        chosen_directory = os.path.normpath(str(qstr_directory.toUtf8()))
        flt = lambda p: not os.path.basename(p).startswith(".")
        scanner = TreeHasher(chosen_directory, flt)
        scanner.hashed.connect(lambda p,s: self.dupedetector.add(s,p))
        scanner.begun.connect(lambda: self.on_scan_begun(scanner))
        scanner.finished.connect(lambda: self.on_scan_finished(scanner))
        scanner.error.connect(lambda e: self.on_scan_error(scanner,e))
        scanner.progress.connect(lambda x,y: self.on_progress_updated(scanner,x,y))
        self.scanners[scanner] = [0,1]
        self.progressbar.setVisible(True)
        scanner.start()

    def pushButton_clicked(self):
        chosen_directory = QFileDialog.getExistingDirectory(
            self.main_window,
            "Select folder to scan",
             options=QFileDialog.ShowDirsOnly | QFileDialog.DontResolveSymlinks
        )
        return self.dispatch_scan(chosen_directory)
    
    def on_scan_begun(self, scanner):
        name = os.path.basename(scanner.directory)
        self.main_window.statusbar.showMessage(
            QString("Scanning ") + QString(name) + QString("...")
        )

    def on_scan_finished(self, scanner):
        name = os.path.basename(scanner.directory)
        self.main_window.statusbar.showMessage(
            QString("Done scanning ") + QString(name)
        )
        del self.scanners[scanner]
        self.progressbar.setVisible(bool(self.scanners.keys()))

    def on_scan_error(self, scanner, e):
        name = os.path.basename(scanner.directory)
        self.main_window.statusbar.showMessage(
            QString("Error scanning ") + QString(name) + QString(": ") + QString(unicode(e))
        )
        del self.scanners[scanner]
        self.progressbar.setVisible(bool(self.scanners.keys()))

    def on_progress_updated(self, scanner, done, allfiles):
        self.scanners[scanner] = [done, allfiles]
        done = sum([ x[0] for x in self.scanners.values() ])
        allfiles = sum([ x[1] for x in self.scanners.values() ])
        self.progressbar.setMaximum(allfiles)
        self.progressbar.setValue(done)

    def on_duplicate_found(self, sum_, path):
        # really, there is nothing to do here
        pass

    def exec_(self):
        self.main_window.show()
        for path in self.arguments()[1:]:
            QTimer.singleShot(0, lambda path=path: self.dispatch_scan(path))
        return QApplication.exec_()


def main():
    app = DupfinderApp(sys.argv)
    return app.exec_()

if __name__ == "__main__":
    sys.exit(main())
