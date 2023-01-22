#!/usr/bin/env python

import datetime
import sys
import os
import hashlib
from PyQt5 import QtCore
from PyQt5.QtCore import QObject, pyqtSignal, QTimer, QItemSelectionModel
from PyQt5 import uic
from PyQt5 import QtGui
from PyQt5.QtWidgets import QApplication, QFileDialog, QProgressBar
from threading import Thread, Lock
import pickle
from pkg_resources import resource_filename, DistributionNotFound

__version__ = "0.1.8"


class HashCache:
    def __init__(self):
        self.store = {}
        self.lock = Lock()

    def load(self, path):
        with self.lock:
            with open(path, "rb") as cachefile:
                self.store = pickle.load(cachefile)

    def save(self, path):
        with self.lock:
            with open(path, "wb") as cachefile:
                pickle.dump(self.store, cachefile)
                cachefile.flush()

    def get_cached_entry(self, cachename, obj, revision):
        """Returns a cached value from a particular cache, so long as
        the revision hasn't changed"""
        with self.lock:
            if cachename not in self.store:
                self.store[cachename] = {}
            cache = self.store[cachename]
            if obj not in cache:
                return None
            rev, value = cache[obj]
            if rev != revision:
                del cache[obj]
                return None
            return value

    def set_cached_entry(self, cachename, obj, revision, value):
        with self.lock:
            if cachename not in self.store:
                self.store[cachename] = {}
            cache = self.store[cachename]
            cache[obj] = (revision, value)


def md5ify(filepath):
    with open(filepath, "rb") as f:
        h = hashlib.md5()
        s = b"arsentarsntirsa"
        while s != b"":
            s = f.read(16384)
            h.update(s)
    return h.hexdigest()


def estimate_scan_dir(folder, filter_func):
    counter = 0
    for path, subfolders, files in os.walk(folder):
        for f in files:
            full_path = os.path.join(path, f)
            if os.path.isfile(full_path) and not os.path.islink(full_path):
                if not filter_func(full_path):
                    continue
                counter = counter + 1
    return counter


def scan_dir(folder, filter_func, hashfunc, cacheobject=None):
    """Scans a folder's files recursively and synchronously, adding the
    files' hash func results to the `sums` dictionary of lists, where the
    key is the result of the hash func, and the value is the list of files
    that compute to that hash func result."""
    try:
        hashfuncname = hashfunc.__name__
    except AttributeError:
        try:
            hashfuncname = hashfunc.__name__
        except AttributeError:
            hashfuncname = None

    for path, subfolders, files in os.walk(folder):
        for f in files:
            full_path = os.path.join(path, f)
            if os.path.isfile(full_path) and not os.path.islink(full_path):
                if not filter_func(full_path):
                    continue
                if cacheobject and hashfuncname:
                    mtime = os.stat(full_path).st_mtime
                    sum_ = cacheobject.get_cached_entry(
                        hashfuncname,
                        full_path,
                        mtime,
                    )
                    if sum_ is not None:
                        yield full_path, sum_, mtime
                        continue
                sum_ = md5ify(full_path)
                if cacheobject and hashfuncname:
                    cacheobject.set_cached_entry(
                        hashfuncname,
                        full_path,
                        mtime,
                        sum_,
                    )
                yield full_path, sum_, mtime


class TreeHasher(QObject):
    """Asynchronously scans a tree of files for their crypto sums, in a thread.

    While the scan is taking place, each hashed file causes two signals to be
    emitted:
      hashed (path, sum)
      progress (files scanned, total files)
    When the process begins, the signal begun is emitted.
    When the process ends, the signal finished is emitted.
    When the process experiences an error, the signal error is emitted, with
    the accompanying exception being its sole parameter.

    If the scanner is stopped with stop(), then no signals are emitted anymore.
    """

    hashed = pyqtSignal((str, str, float))
    progress = pyqtSignal((int, int))
    begun = pyqtSignal()
    finished = pyqtSignal()
    error = pyqtSignal((BaseException,))

    def __init__(
        self,
        directory,
        filter_func=lambda: True,
        hasher=md5ify,
        cacheobject=None,
    ):
        """Initializes a duplicate finder for a particular directory.

        The hasher is a hash function which will take a path as only parameter
        and provide a hash in return.

        The filter_func parameter is a function which will take a path and
        return any value that boolean-evaluates to True if the path is to be
        scanned.

        cacheobject must be an instance of HashCache.
        """
        QObject.__init__(self)
        self.hasher = hasher
        self.directory = directory
        self.filter_func = filter_func
        self.t = None
        self.stopped = False
        self.cache = cacheobject

    def _scan(self):
        if not self.stopped:
            self.begun.emit()
        try:
            numfiles = estimate_scan_dir(self.directory, self.filter_func)
            counter = 0
            for full_path, sum_, mtime in scan_dir(
                self.directory, self.filter_func, self.hasher, self.cache
            ):
                if self.stopped:
                    break
                counter = counter + 1
                self.hashed.emit(full_path, sum_, mtime)
                self.progress.emit(counter, numfiles)
            if not self.stopped:
                self.finished.emit()
        except BaseException as e:
            if not self.stopped:
                self.error.emit(e)
            raise

    def start(self):
        """Dispatches the scan.  It is an error to call this twice. Seriously,
        your program will be fucked."""
        self.t = Thread(target=self._scan)
        self.t.setDaemon(True)
        self.t.start()

    def stop(self):
        """
        Stops the scan.
        It is an error to call this if the scan is not ongoing.
        """
        self.stopped = True

    def wait(self):
        """Joins the scanner thread until it stops.  It is an error to call this
        if the scan has not been stopped with stop()."""
        assert self.t, "wait() called when scan not ongoing"
        self.t.join()


class DuplicateDetector(QObject):
    """
    Receives pairs of (hash, path) through its add() method.  Emits signal
    duplicateFound for each received pair (hash, path) if the hash is seen
    more than once.  If the path sent via add() is already known and has
    the same hash, it is ignored.
    """

    duplicateFound = pyqtSignal((str, str, float))

    def __init__(self):
        QObject.__init__(self)
        self.dupes = {}

    def add(self, sum_, path, mtime):
        """Add the pair sum, path to the duplicate detector, trigger signal
        if appropriate."""
        if sum_ not in self.dupes:
            self.dupes[sum_] = dict()
        paths = self.dupes[sum_]
        if path in paths:
            return
        if len(paths) < 1:
            paths[path] = mtime
            return
        if len(paths) == 1:
            first = list(paths.items())[0]
            self.duplicateFound.emit(sum_, *first)
        paths[path] = mtime
        self.duplicateFound.emit(sum_, path, mtime)


ACTION_KEEP = 1
ACTION_REMOVE = 2


class HashAggregator(QtGui.QStandardItemModel):
    """
    Incrementally aggregates pairs of (hash, path) into a TreeModel structure
    self.model.
    """

    def __init__(self):
        """Pass the TreeModel instance here"""
        QtGui.QStandardItemModel.__init__(self)
        self.hashes = {}
        header = [
            QtGui.QStandardItem(),
            QtGui.QStandardItem(),
            QtGui.QStandardItem(),
            QtGui.QStandardItem(),
        ]
        for n, t in enumerate(["Action", "Matches", "Folder", "Modification time"]):
            header[n].setText(t)
            self.setHorizontalHeaderItem(n, header[n])

    def add(self, sum_, path, mtime):
        """Aggregate the sum and the path to the self.model structure."""
        try:
            item = self.hashes[sum_]
        except KeyError:
            item = QtGui.QStandardItem()
            item.setText(sum_)
            item.setData(sum_)
            item.setSelectable(False)
            self.appendRow(item)
            self.hashes[sum_] = item
        str_path = str(path)  # here I *know* the path is a regular string
        fitem = QtGui.QStandardItem()
        ditem = QtGui.QStandardItem()
        mtimeitem = QtGui.QStandardItem()
        fitem.setData(path)
        ditem.setData(path)
        mtimeitem.setData(mtime)
        fitem.setText(os.path.basename(str_path))
        ditem.setText(os.path.dirname(str_path))
        mtimeitem.setText(datetime.datetime.fromtimestamp(mtime).isoformat())
        aitem = QtGui.QStandardItem()
        aitem.setText("Keep")
        aitem.setData(ACTION_KEEP)
        # count = item.rowCount()
        item.appendRow([aitem, fitem, ditem, mtimeitem])


class TreeSortFilterProxyModel(QtCore.QSortFilterProxyModel):
    def __init__(self, *args, **kwargs):
        QtCore.QSortFilterProxyModel.__init__(self, *args, **kwargs)
        self.text_filter = ""

    def filterAcceptsRow(self, sourceRow, sourceParent):
        """Search every match row for text, substring, and if it matches,
        show the row"""
        index1 = self.sourceModel().index(sourceRow, 1, sourceParent)
        i = self.sourceModel().itemFromIndex
        is_hash = not i(index1).text()
        if is_hash:
            return True  # we always show the hash, temporarily at least
        string = i(index1).data()
        if self.text_filter in string:
            return True
        return False

    def setTextFilter(self, text_filter):
        self.text_filter = text_filter
        self.invalidateFilter()


class DupfinderApp(QApplication):
    def __init__(self, *args, **kwargs):
        QApplication.__init__(self, *args, **kwargs)
        self.settings = QtCore.QSettings("duphunter", "duphunter")
        try:
            uifile = resource_filename(__name__, "duphunter.ui")
        except DistributionNotFound:
            uifile = os.path.join(os.path.dirname(__file__), "duphunter.ui")
        self.main_window = uic.loadUi(uifile)
        self.progressbar = QProgressBar()
        self.progressbar.setVisible(False)
        self.main_window.statusbar.addPermanentWidget(self.progressbar)
        self.main_window.addFolder.clicked.connect(self.addFolder_clicked)
        self.main_window.removeThis.clicked.connect(self.removeThis_clicked)
        self.main_window.keepThis.clicked.connect(self.keepThis_clicked)
        self.main_window.selectOldest.clicked.connect(self.selectOldest_clicked)
        self.main_window.selectFirst.clicked.connect(self.selectFirst_clicked)
        self.main_window.invertSelection.clicked.connect(
            self.invertSelection_clicked,
        )
        self.main_window.execute.clicked.connect(self.execute_clicked)
        self.main_window.cancel.clicked.connect(self.cancel_clicked)
        self.main_window.filter.textChanged.connect(self.filter_textChanged)

        # create dupe detector and aggregator, wire them together
        self.dupedetector = DuplicateDetector()
        self.aggregator = HashAggregator()
        self.dupedetector.duplicateFound.connect(self.aggregator.add)

        # set up the aggregator and then the filter model to filter the
        # aggregator model
        self.filter_model = TreeSortFilterProxyModel()
        self.filter_model.setSourceModel(self.aggregator)
        self.main_window.treeView.setModel(self.filter_model)

        # ensure that rows autoexpand...
        def autoexpand_rows(parent, start_int, end_int):
            self.main_window.treeView.expandRecursively(parent)

        self.filter_model.rowsInserted.connect(autoexpand_rows)

        # restore window state
        mainwindowgeo = self.settings.value("mainWindowGeometry")
        if mainwindowgeo:
            self.main_window.restoreGeometry(mainwindowgeo)
        mainwindowstate = self.settings.value("mainWindowState")
        if mainwindowstate:
            self.main_window.restoreState(mainwindowstate)

        # finesse the column widths...
        self.main_window.treeView.setColumnWidth(0, 50)
        self.main_window.treeView.setColumnWidth(1, 300)
        self.main_window.treeView.header().setStretchLastSection(True)

        # but restore their state
        for col in range(3):
            cw = self.settings.value("columnWidth%s" % col)
            if cw is None:
                if col == 0:
                    cw = 100
                else:
                    continue
            colwidth = int(cw)
            self.main_window.treeView.setColumnWidth(col, colwidth)

        # restore cache
        self.cache = HashCache()
        try:
            self.cache.load(os.path.expanduser("~/.duphunter.cache"))
        except (IOError, EOFError):
            pass

        # set up scanners
        self.scanners = {}

        def stop_scanners():
            # this is the only thing that stops the program from dying when
            # closed abruptly when very recently open.  to stop the scanners!
            for s in list(self.scanners.keys()):
                s.stop()
            for s in list(self.scanners.keys()):
                s.wait()
                del self.scanners[s]

        self.aboutToQuit.connect(stop_scanners)

        self.main_window.closeEvent = self.main_window_closed

    def main_window_closed(self, event):
        self.settings.setValue(
            "mainWindowGeometry",
            self.main_window.saveGeometry(),
        )
        self.settings.setValue("mainWindowState", self.main_window.saveState())
        for col in range(3):
            self.settings.setValue(
                "columnWidth%s" % col,
                self.main_window.treeView.columnWidth(col),
            )
        event.accept()

    def dispatch_scan(self, qstr_directory):
        def flt(p):
            bname = os.path.basename(p)
            return not bname.startswith(".") and os.stat(p).st_size > 0

        scanner = TreeHasher(qstr_directory, flt, cacheobject=self.cache)
        scanner.hashed.connect(lambda p, s, m: self.dupedetector.add(s, p, m))
        scanner.begun.connect(lambda: self.on_scan_begun(scanner))
        scanner.finished.connect(lambda: self.on_scan_finished(scanner))
        scanner.error.connect(lambda e: self.on_scan_error(scanner, e))
        scanner.progress.connect(
            lambda x, y: self.on_progress_updated(scanner, x, y),
        )
        self.scanners[scanner] = [0, 1]
        self.progressbar.setVisible(True)
        scanner.start()

    def addFolder_clicked(self):
        chosen_directory = QFileDialog.getExistingDirectory(
            self.main_window,
            "Select folder to scan",
            options=QFileDialog.ShowDirsOnly | QFileDialog.DontResolveSymlinks,
        )
        return self.dispatch_scan(chosen_directory)

    def _setSelectionAction(self, action_id, action_text):
        source_model = self.filter_model.sourceModel()
        fltselection = self.main_window.treeView.selectionModel().selection()
        for index in fltselection.indexes():
            if index.column() != 0:
                continue
            source_index = self.filter_model.mapToSource(index)
            item = source_model.itemFromIndex(source_index)
            item.setText(action_text)
            item.setData(action_id)

    def keepThis_clicked(self):
        return self._setSelectionAction(ACTION_KEEP, "Keep")

    def removeThis_clicked(self):
        return self._setSelectionAction(ACTION_REMOVE, "Remove")

    def execute_clicked(self):
        """commits actions to disk"""
        source_model = self.filter_model.sourceModel()
        paths_to_delete = []
        for n in range(source_model.rowCount()):
            index = source_model.index(n, 0)
            for m in reversed(range(source_model.rowCount(index))):
                rowmarker = source_model.index(m, 0, index)
                action = source_model.index(m, 0, index)
                path = source_model.index(m, 1, index)
                action = int(source_model.itemFromIndex(action).data())
                path = source_model.itemFromIndex(path).data()
                if action == ACTION_REMOVE:
                    paths_to_delete.append((rowmarker, path))
        self.progressbar.setVisible(True)
        deleted = 0
        not_deleted = 0
        for n, pair in enumerate(paths_to_delete):
            index, p = pair
            fn = os.path.basename(p)
            try:
                os.unlink(p)
                self.main_window.statusbar.showMessage("Removed " + fn + "...")
                row = index.row()
                parentindex = index.parent()
                source_model.removeRows(row, 1, parentindex)
                deleted = deleted + 1
            except Exception as e:
                self.main_window.statusbar.showMessage(
                    "Error removing " + fn + ": %s" % e
                )
                not_deleted = not_deleted + 1
            self.progressbar.setMaximum(len(paths_to_delete))
            self.progressbar.setValue(n + 1)
        self.main_window.statusbar.showMessage(
            "Removed %s files" % (deleted,)
            + (
                ", could not remove %s files" % (not_deleted,)
                if not_deleted > 0
                else ""
            )
        )
        self.progressbar.setVisible(bool(list(self.scanners.keys())))

    def cancel_clicked(self):
        self.main_window.close()

    def selectFirst_clicked(self):
        selection_model = self.main_window.treeView.selectionModel()
        """selects every first visible match on every toplevel item"""
        for n in range(self.filter_model.rowCount()):
            index = self.filter_model.index(n, 0)
            if self.filter_model.hasChildren(index):
                first_child = self.filter_model.index(0, 0, index)
                selection_model.select(
                    first_child,
                    QItemSelectionModel.Select | QItemSelectionModel.Rows,
                )

    def selectOldest_clicked(self):
        selection_model = self.main_window.treeView.selectionModel()
        """selects every oldest visible match on every toplevel item"""
        for n in range(self.filter_model.rowCount()):
            index = self.filter_model.index(n, 0)
            if self.filter_model.hasChildren(index):
                mtimes = []
                for i in range(self.filter_model.rowCount(index)):
                    thechild = self.filter_model.index(i, 0, index)
                    child = self.filter_model.index(i, 3, index)
                    realchild = self.filter_model.mapToSource(child)
                    mtime = (
                        self.filter_model.sourceModel()
                        .itemFromIndex(
                            realchild,
                        )
                        .data()
                    )
                    mtimes.append((mtime, thechild))
                mtimes = list(sorted(mtimes))
                oldest = mtimes[0][1]
                selection_model.select(
                    oldest,
                    QItemSelectionModel.Select | QItemSelectionModel.Rows,
                )

    def invertSelection_clicked(self):
        selection_model = self.main_window.treeView.selectionModel()
        """selects every first visible match on every toplevel item"""
        select_rows = QItemSelectionModel.Select | QItemSelectionModel.Rows
        deselect_rows = QItemSelectionModel.Deselect | QItemSelectionModel.Rows
        for n in range(self.filter_model.rowCount()):
            index = self.filter_model.index(n, 0)
            if self.filter_model.hasChildren(index):
                for m in range(self.filter_model.rowCount(index)):
                    child = self.filter_model.index(m, 0, index)
                    if selection_model.isSelected(child):
                        selection_model.select(
                            child,
                            deselect_rows,
                        )
                    else:
                        selection_model.select(
                            child,
                            select_rows,
                        )

    def filter_textChanged(self, new_text):
        self.filter_model.setTextFilter(new_text)

    def on_scan_begun(self, scanner):
        name = os.path.basename(scanner.directory)
        self.main_window.statusbar.showMessage("Scanning %s..." % name)

    def on_scan_finished(self, scanner):
        name = os.path.basename(scanner.directory)
        self.main_window.statusbar.showMessage("Done scanning %s" % name)
        del self.scanners[scanner]
        self.progressbar.setVisible(bool(list(self.scanners.keys())))

    def on_scan_error(self, scanner, e):
        name = os.path.basename(scanner.directory)
        self.main_window.statusbar.showMessage(
            "Error scanning %s: %s" % (name, e),
        )
        del self.scanners[scanner]
        self.progressbar.setVisible(bool(list(self.scanners.keys())))

    def on_progress_updated(self, scanner, done, allfiles):
        self.scanners[scanner] = [done, allfiles]
        done = sum([x[0] for x in list(self.scanners.values())])
        allfiles = sum([x[1] for x in list(self.scanners.values())])
        self.progressbar.setMaximum(allfiles)
        self.progressbar.setValue(done)

    def exec_(self):
        self.main_window.show()
        for path in self.arguments()[1:]:
            QTimer.singleShot(0, lambda path=path: self.dispatch_scan(path))
        retval = QApplication.exec_()
        try:
            self.cache.save(os.path.expanduser("~/.duphunter.cache"))
        except IOError:
            raise
        return retval


def main():
    app = DupfinderApp(sys.argv)
    return app.exec_()


if __name__ == "__main__":
    sys.exit(main())
