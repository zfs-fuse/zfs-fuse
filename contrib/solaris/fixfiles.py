#!/usr/bin/env python

import sys, os
from stat import *

def remove_comments(fin, fout):
	sin = fin.read()
	sout = ''

	while 1:
		# Here we are at the start of a line
		i = sin.find('\n')
		if i == -1:
			# File ended
			sout += sin
			break

		line = sin[:i]

		ignore_cchar = False

		if line.lstrip().startswith('#'):
			# The line is a preprocessor directive, the comment character is ignored
			ignore_cchar = True

		i2 = line.find('/')
		if i2 == -1:
			# Add the whole line
			sout += sin[:i + 1]
			sin = sin[i + 1:]
			continue

		# Check if it's a /* token
		if (i2 + 1) < len(line) and line[i2 + 1] == '*':
			i3 = sin.find('*/', i2 + 2)
			if i3 == -1:
				# File ended
				sout += sin
				break

			# Add everything until the end of the comment
			sout += sin[:i3 + 2]
			sin = sin[i3 + 2:]
			continue

		if not ignore_cchar:
			# This line has a valid comment character
			sout += line[:i2].rstrip() + '\n'
		else:
			# Otherwise, add the whole line
			sout += sin[:i + 1]

		sin = sin[i + 1:]

	fout.write(sout)

def remove_pragmas(fin, fout):
	s = fin.readline()
	while s != '':
		for pragma in ('ident', 'rarely_called'):
			if s.startswith('#pragma ' + pragma):
				s = '\n'
				break

		fout.write(s)
		s = fin.readline()

def replace_file(finname, fun):
	mode = os.lstat(finname)[ST_MODE]

	if not S_ISREG(mode):
		return

	foutname = finname + '.bak'
	fin = file(finname, 'r')
	fout = file(foutname, 'w')

	fun(fin, fout)

	fin.close()
	fout.close()

	os.rename(foutname, finname)

for root, dirs, files in os.walk(sys.argv[1]):
	for filename in files:
		name = os.path.join(root, filename)

		ext = os.path.splitext(name)[1]

		if ext in ('.c', '.h'):
			replace_file(name, remove_pragmas)
		elif ext == '.S':
			replace_file(name, remove_comments)
