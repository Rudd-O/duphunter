#!/usr/bin/env python

import platform
from setuptools import setup
import os

dir = os.path.dirname(__file__)
path_to_main_file = os.path.join(dir, "src/duphunter/__init__.py")
path_to_readme = os.path.join(dir, "README.md")
for line in open(path_to_main_file):
	if line.startswith('__version__'):
		version = line.split()[-1].strip("'").strip('"')
		break
else:
	raise ValueError('"__version__" not found in "src/duphunter/__init__.py"')
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

data_files = (
    [
        (
            "/usr/share/applications",
            ["applications/%s.desktop" % p for p in ["duphunter"]],
        ),
    ]
    if platform.system() != "Darwin"
    else []
)

setup(
	name = 'duphunter',
	version=version,
	description = 'An application that finds and lets you delete duplicate files',
	long_description = readme,
	author='Manuel Amador (Rudd-O)',
	author_email='rudd-o@rudd-o.com',
	license="GPL",
	url = 'http://github.com/Rudd-O/duphunter',
	package_dir=dict([
					("duphunter", "src/duphunter"),
					]),
	classifiers = classifiers,
	packages = ["duphunter"],
	scripts = ["bin/duphunter"],
	keywords = "duplicate file management",
	data_files=data_files,
	zip_safe=False,
	include_package_data = True,
)
