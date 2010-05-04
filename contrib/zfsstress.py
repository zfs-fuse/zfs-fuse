#!/usr/bin/env python
#
#  ZFS stress tester

import sys, subprocess, os, random, re, time

#######################
def randName(len = 10):
	import string
	charset = string.uppercase + string.lowercase + string.digits
	s = ''
	for i in range(len): s += random.choice(charset)
	return(s)

################
def call(*args):
	cmd = ' '.join(args)
	print cmd; sys.stdout.flush()
	p = subprocess.Popen(cmd, shell = True)
	#ret = os.waitpid(p.pid, 0)[1]
	ret = p.wait()
	if ret != 0:
		raise Exception('Call to "%s" returned %s' % ( cmd, ret ))

###########################
def getPercent(filesystem):
	fp = os.popen('df -h /%s' % filesystem, 'r')
	lines = fp.readlines()
	fp.close()
	for line in lines:
		m = re.search(r'\b(\d+)%', line)
		if m: return(int(m.group(1)))
	return(None)

#######################
zpoolName = sys.argv[1]

zfsName = '%s/zfsstress-%s' % ( zpoolName, randName() )
call('zfs', 'create', zfsName)
call('zfs', 'set', 'dedup=verify', zfsName)
if getPercent(zfsName) == None:
	sys.stderr.write('Unable to get percentage used via "df -h /%s"\n' % zfsName)
	sys.exit(1)

try:
	fpIn = open('/dev/frandom', 'r')
	randomFileName = '/dev/frandom'
except:
	fpIn = open('/dev/urandom', 'r')
	randomFileName = '/dev/urandom'

snapList = []
fileList = []
startTime = time.time()
while True:
	print '#  Elapsed run-time in seconds: %s' % ( time.time() - startTime )

	cmd = random.choice(['newsnap', 'delsnap', 'newfile', 'newfile', 'delfile',
			'readfile', 'readfile', 'readfile', 'readfile' ])

	if cmd in ['newfile', 'newsnap'] and getPercent(zfsName) > 95:
		print '#  DEBUG: Skipping "%s" because of disc fullness' % cmd
		continue

	if cmd == 'newsnap':
		snapName = '%s@%s' % ( zfsName, randName() )
		print '#  CreateSnapshot "%s"' % ( snapName, ); sys.stdout.flush()
		call('zfs', 'snapshot', snapName)
		snapList.append(snapName)

	if cmd == 'delsnap':
		if not snapList: continue
		snapName = random.choice(snapList)
		print '#  DestroySnapshot "%s"' % ( snapName, ); sys.stdout.flush()
		call('zfs', 'destroy', snapName)
		snapList.remove(snapName)

	if cmd == 'newfile':
		fileName = '/%s/%s' % ( zfsName, randName(random.randint(10, 30)) )
		fpOut = open(fileName, 'w')
		size = random.randint(10, 100000000)
		blockSize = random.randint(10, 102400)
		count = int(size / blockSize)
		print '#  Writing "%s" of size "%s"' % ( fileName, count * blockSize )
		call('dd', 'if=%s' % randomFileName, 'of="%s"' % fileName,
				'bs=%s' % blockSize, 'count=%s' % count,
				'2>&1 | sed "s/^/# dd Output: /"')
		fileList.append(fileName)

	if cmd == 'readfile':
		if not fileList:
			print ('#  DEBUG: Skipping read because not fileList: len=%s'
					% len(fileList))
			continue
		fileName = random.choice(fileList)
		print '#  Reading "%s"' % ( fileName, ); sys.stdout.flush()
		call('dd', 'if="%s"' % fileName, 'of=/dev/null', 'bs=10240',
				'2>&1 | sed "s/^/# dd Output: /"')

	if cmd == 'delfile':
		if not fileList:
			print ('#  DEBUG: Skipping delete because not fileList: len=%s'
					% len(fileList))
			continue
		fileName = random.choice(fileList)
		print '#  Deleting "%s"' % ( fileName, ); sys.stdout.flush()
		print 'rm -f "%s"' % ( fileName, ); sys.stdout.flush()
		os.remove(fileName)
		fileList.remove(fileName)
