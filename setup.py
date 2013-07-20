#!/usr/bin/env python

from setuptools import setup
import os

dir = os.path.dirname(__file__)
path_to_main_file = os.path.join(dir, "src/dupfinder/__init__.py")
path_to_readme = os.path.join(dir, "README.md")
for line in open(path_to_main_file):
	if line.startswith('__version__'):
		version = line.split()[-1].strip("'").strip('"')
		break
else:
	raise ValueError, '"__version__" not found in "src/dupfinder/__init__.py"'
readme = open(path_to_readme).read(-1)

classifiers = [
'Intended Audience :: End Users/Desktop',
'Intended Audience :: System Administrators',
'License :: OSI Approved :: GNU General Public License (GPL)',
'Operating System :: POSIX :: Linux',
'Programming Language :: Python :: 2 :: Only',
'Programming Language :: Python :: 2.7',
'Topic :: Utilities',
]

setup(
	name = 'dupfinder',
	version=version,
	description = 'An application that finds and lets you delete duplicate files',
	long_description = readme,
	author='Manuel Amador (Rudd-O)',
	author_email='rudd-o@rudd-o.com',
	license="GPL",
	url = 'http://github.com/Rudd-O/dupfinder',
	package_dir=dict([
					("dupfinder", "src/dupfinder"),
					]),
	classifiers = classifiers,
	packages = ["dupfinder"],
	scripts = ["bin/dupfinder"],
	keywords = "duplicate file management",
	zip_safe=False,
	include_package_data = True,
)