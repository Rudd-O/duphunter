# Duphunter

Duphunter is a very simple application that finds and lets you delete duplicate files interactively, using a very efficient list interface where you can mark files for preservation or deletion, and later commit your changes.  The scanning process should scale well into the millions of files.

The repository, bug tracker and Web site for this tool is at [http://github.com/Rudd-O/duphunter](http://github.com/Rudd-O/duphunter).

## Setting up

1. Install PyQt5
2. Install this package using `pip`, `python setup.py install` or `python setup.py bdist_rpm`

## Running

Run the command `duphunter` on the command line, optionally specifying paths to scan as arguments to the command.
