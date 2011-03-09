# Release tag is supposed to be 0. for prerelease, X. for serial number in this version and alphatag XXXsvn.

Name:          zfs-fuse
Version:       0.7.0
Release:       1
Summary:       The last word in filesystems
License:       GPL
Group:         System Environment/Daemons
URL:           http://zfs-fuse.net/
Source0:       %{name}-%{version}.tar.bz2
BuildRoot:     %{_tmppath}/%{name}-%{version}-root
BuildRequires: fuse-devel libaio-devel zlib-devel scons
BuildRequires: openssl-devel libattr-devel libacl-devel

%description
ZFS (formerly the Zettabyte File System), is a filesystem invented by
Jeff Bonwick, Bill Moore and others at Sun Microsystems.  It is the most
reliable and tested filesystem ever invented, and it has a feature set
that sets it apart from anything that came before:

1. Provable integrity - it checksums all data (and meta-data), which makes it
possible to detect hardware errors (hard disk corruption, flaky IDE cables..).
ZFS helped to detect a faulty power supply after only two hours of usage,
which was previously silently corrupting data for almost a year.

2. Atomic, transactional updates - means that the on-disk state is consistent
at all times, there's no need to perform a lengthy filesystem check after
forced reboots/power failures. 

3. Instantaneous snapshots and clones - it makes it possible to have hourly,
daily and weekly backups efficiently, as well as experiment with new system
configurations without any risks.

4. Built-in (optional) compression 

6. Pooled storage model - creating filesystems is as easy as creating a new
directory. You can efficiently have thousands of filesystems, each with it's
own quotas and reservations, and different properties (compression algorithm,
checksum algorithm, etc..). 

5. Very high scalability.  You can have an almost infinite number of snapshots
and more files / bytes in your filesystems than it is even theoretically
possible to store with every atom in Earth.  Performance scales linearly
with the number of mirrors you add to your pool.

6. Built-in stripes (RAID-0), mirrors (RAID-1) and RAID-Z (it's like software
RAID-5, but without the requirement of uninterruptible power or battery-
backed power to prevent catastrophes due to sudden power outages.
It is more efficient in resyncing failed arrays due to ZFS's copy-on-write
transactional model. 

...and many others (variable sector sizes, adaptive endianness, incremental
backups over the network...)

This project is a port of the ZFS filesystem to FUSE/Linux, done as part of the
Google Summer of Code 2006 initiative.



%prep
%setup -q 

%build
cd src
scons debug=0

%install
[ "$RPM_BUILD_ROOT" != "/" ] && [ -d $RPM_BUILD_ROOT ] && rm -rf $RPM_BUILD_ROOT;
mkdir -p $RPM_BUILD_ROOT%_sbindir
mkdir -p $RPM_BUILD_ROOT%{_initrddir} $RPM_BUILD_ROOT%{_sysconfdir}/sysconfig
install -m755 contrib/%{name}.initd.fedora $RPM_BUILD_ROOT%{_initrddir}/%{name}
install -m644 contrib/%{name}.sysconfig $RPM_BUILD_ROOT%{_sysconfdir}/sysconfig/%{name}
ln -s %{_sysconfdir}/init.d/%{name} $RPM_BUILD_ROOT%_sbindir/rc%{name}
mkdir -p $RPM_BUILD_ROOT%{_mandir}/man8
install -m 644 doc/*.8 $RPM_BUILD_ROOT%{_mandir}/man8
cd src
scons install install_dir=$RPM_BUILD_ROOT%_sbindir man_dir=$RPM_BUILD_ROOT%_mandir/man8/

%clean
[ "$RPM_BUILD_ROOT" != "/" ] && [ -d $RPM_BUILD_ROOT ] && rm -rf $RPM_BUILD_ROOT;

%files
%defattr(-,root,root)
%doc BUGS CHANGES HACKING INSTALL LICENSE README README.NFS STATUS TESTING TODO
%doc %{_mandir}/man8/*
%{_initrddir}/%{name}
%config(noreplace) %{_sysconfdir}/sysconfig/%{name}
%_sbindir/rc%{name}
%{_sbindir}/zdb
%{_sbindir}/zfs
%{_sbindir}/zpool
%{_sbindir}/ztest
%{_sbindir}/zfs-fuse
%{_sbindir}/zstreamdump

%changelog
* Wed Mar 09 2011 Seth Heeren <zfs-fuse@sehe.nl> 0.7.0-1
- Release 0.7.0

* Fri Oct 01 2010 Seth Heeren <zfs-fuse@sehe.nl> 0.7.0-0
- Release 0.7.0

* Tue Jun 01 2010 Seth Heeren <zfs-fuse@sehe.nl> 0.6.9-0
- Release 0.6.9 as is in preparation for 0.7.0

* Sun Dec 06 2009 Manuel Amador (Rudd-O) <rudd-o@rudd-o.com> 0.6.0-1
- Release 0.6.0 as is in preparation for 0.7.0

* Wed Sep 02 2009 Lenz Grimmer <lenz@grimmer.com> 0.6.0-0.0.433snapshot
- Added man pages to the package

* Sat Aug 15 2009 Manuel Amador (Rudd-O) <rudd-o@rudd-o.com> 0.6.0-0.0.433snapshot
- Bumped to 0.6.0

* Fri Aug 14 2009 Manuel Amador (Rudd-O) <rudd-o@rudd-o.com> 0.5.1-0.0.432snapshot
- Included /etc/sysconfig/zfs-fuse to provide command-line options for ZFS in a config file

* Fri Aug 14 2009 Manuel Amador (Rudd-O) <rudd-o@rudd-o.com> 0.5.1-0.0.431snapshot
- Thanks to Emmanuel Anne, we now conform to POSIX according to the NTFS-3G suite

* Fri Aug 14 2009 Manuel Amador (Rudd-O) <rudd-o@rudd-o.com> 0.5.1-0.0.414svn
- Renamed version / release to Fedora versioning policy (compatible with all RPM distros)
- Used Fedora init script (more reliable, performs more checks)

* Fri Aug 14 2009 Lenz Grimmer <lenz@grimmer.com>
- Updated to version 0.5.1r414 (hg snapshot taken from http://git.rudd-o.com/zfs/)
* Mon Dec 15 2008 Lenz Grimmer <lenz@grimmer.com>
- Updated to version 0.5.0r375 (hg snapshot)
- Removed build patch (now included upstream)
* Thu Sep 18 2008 Lenz Grimmer <lenz@grimmer.com>
- Updated to version 0.5.0
* Tue Aug 26 2008 Lenz Grimmer <lenz@grimmer.com>
- Added rczfs-fuse convenience symlink
* Sun Aug 24 2008 Lenz Grimmer <lenz@grimmer.com>
- Initial package, based on hg revision 346 of the trunk
