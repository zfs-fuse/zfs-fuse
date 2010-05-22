#!/usr/bin/env python
# -*- coding: utf-8 -*-
#
# WAF build script - this file is part of ZFS-Fuse, a port of the Solaris ZFS to Linux
#
#  Sandeep S Srinivasa <sandys(at)gmail(dot)com>
#
# This program is free software; you can redistribute it and/or modify
# it under the terms of the GNU General Public License as published by
# the Free Software Foundation; either version 2 of the License, or
# (at your option) any later version.
#
# This program is distributed in the hope that it will be useful,
# but WITHOUT ANY WARRANTY; without even the implied warranty of
# MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
# GNU General Public License for more details.
#
# $Id$

"""
This is a WAF build script (http://code.google.com/p/waf/).
It can be used as an alternative build system to autotools
for zfs-fuse. 
"""


import Build, Configure, Options, Runner, Task, Utils
import sys, os, subprocess, shutil
from distutils import version
from Logs import error, debug, warn



APPNAME = 'zfs-fuse'
VERSION = '0.6.9_beta3'

srcdir = '.'
blddir = '__build'

subdirs = """
            src/lib/libsolcompat/
            src/lib/libumem/
            src/lib/libavl/
            src/lib/libsolkerncompat/
            src/lib/libnvpair/
            src/lib/libuutil/
            src/lib/libzpool/
            src/lib/libzfs/
            src/lib/libzfscommon/
            src/zfs-fuse/
            src/cmd/zfs/
            src/cmd/zpool/
            src/cmd/zstreamdump/
            src/cmd/zdb/
            src/cmd/ztest/
          """.split()


#####
#Cmd Line Options
####
def set_options(opt):
    opt.add_option('--prefix', type='string',help='set install path prefix', dest='usr_prefix')


def init(ctx):
    import Configure
#    Configure.configure.define('_FILE_OFFSET_BITS', 64)
####
#Configuration
####
def configure(conf):
#    import Options # getting the user-provided options to the configuration section
#    if Options.options.usr_prefix
#        Options.prefix = Options.options.usr_prefix


    conf.check_tool('gcc glib2')


#    conf.env.CCFLAGS = ['-Wall']
    conf.env.CCFLAGS = ['-pipe', '-Wall', '-std=c99', '-Wno-switch', '-Wno-unused', '-Wno-missing-braces', '-Wno-parentheses', '-Wno-uninitialized', '-fno-strict-aliasing', '-D_GNU_SOURCE', '-DLINUX_AIO']
    conf.env.INCLUDEDIR = ['/usr/include/']
#    conf.env['INCLUDEDIR'] = '/usr/include'
#    conf.define('_FILE_OFFSET_BITS', 64) 
#    conf.write_config_header('config.h')

    conf.check(header_name="aio.h", uselib_store='aio_defines', mandatory=True)
    conf.check(lib='aio',  uselib_store='aio_lib', mandatory=True)
    conf.check(lib='ssl',  uselib_store='openssl', mandatory=True)
    conf.check(lib='crypto',  uselib_store='crypto', mandatory=True)
    conf.check(lib='pthread',  uselib_store='pthread_lib', mandatory=True)
    conf.check_cc(lib='fuse',  uselib_store='fuse_lib',  mandatory=True)
    conf.check_cc(lib='dl',  uselib_store='dl_lib',  mandatory=True)
    conf.check_cc(lib='z',  uselib_store='z_lib',  mandatory=True)
    conf.check_cc(lib='m',  uselib_store='m_lib',  mandatory=True)
    conf.check_cc(header_name='fuse/fuse_lowlevel.h', includes=['/usr/include/'], 
            ccflags='-D_FILE_OFFSET_BITS=64', uselib_store='fuse_defines', mandatory=True)
#    conf.check_cc(header_name='attr/xattr.h', includes=['/usr/include/'], mandatory=True) # FIXME not working properly
    conf.check_cc(lib='rt', uselib_store='rt_lib', mandatory=True)
    conf.check_tool('gas')
    #if not conf.env.AS: conf.env.AS = conf.env.CC
    conf.env.AS = conf.env.CC

#    try:
#		conf.check_cc(compile_filename='test.s', fragment='''
#.text
#.align 2
#
#val:
# .long 10
#
## Multiply input value by 10...
#.global mult10
#.type mult10, function
#mult10:
#  movl val,%eax
#  imul 4(%esp),%eax
#  ret
#	''', type='cstaticlib', mandatory=True, msg='Checking for assembler')
#    except:
#		conf.env.AS = None

    ###################### install configuration ################

    conf.check_tool('gnu_dirs')
    warn(" setting MANDIR = %s" % conf.env.MANDIR)
    conf.env.PREFIX = '/'
    conf.env.MANDIR = '/usr/share/man/man8'


####
#Build
####
def build(bld):
    bld.add_subdirs(subdirs)
    bld.includes = '/usr/include/'
    #man_list = bld.path.ant_glob('doc/*.gz')
    bld.install_files('${MANDIR}', 'doc/*.gz')
    
