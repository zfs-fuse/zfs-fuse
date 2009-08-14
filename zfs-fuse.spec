# Release tag is supposed to be 0. for prerelease, X. for serial number in this version and alphatag XXXsvn.

Name:          zfs-fuse
Version:       0.5.1
Release:       0.0.414svn
Summary:       A port of ZFS to the FUSE framework for the Linux operating system
License:       GPL
Group:         System Environment/Daemons
Packager:      Lenz Grimmer <lenz@grimmer.com>
URL:           http://www.wizy.org/wiki/ZFS_on_FUSE
Source0:       %{name}-%{version}.tar.bz2
Patch:        %{name}.patch
BuildRoot:     %{_tmppath}/%{name}-%{version}-root
BuildRequires: fuse-devel libaio-devel zlib-devel scons

%description
This project is a port of the ZFS filesystem to FUSE/Linux, done as part of the
Google Summer of Code 2006 initiative.

ZFS has many features which can benefit all kinds of users - from the simple
end-user to the biggest enterprise systems. ZFS list of features: 

Provable integrity - it checksums all data (and meta-data), which makes it
possible to detect hardware errors (hard disk corruption, flaky IDE cables..).
Read how ZFS helped to detect a faulty power supply after only two hours of
usage, which was previously silently corrupting data for almost a year! 

Atomic updates - means that the on-disk state is consistent at all times,
there's no need to perform a lengthy filesystem check after forced
reboots/power failures. 

Instantaneous snapshots and clones - it makes it possible to have hourly, daily
and weekly backups efficiently, as well as experiment with new system
configurations without any risks. 

Built-in (optional) compression 

Highly scalable 

Pooled storage model - creating filesystems is as easy as creating a new
directory. You can efficiently have thousands of filesystems, each with it's
own quotas and reservations, and different properties (compression algorithm,
checksum algorithm, etc..). 

Built-in stripes (RAID-0), mirrors (RAID-1) and RAID-Z (it's like software
RAID-5, but more efficient due to ZFS's copy-on-write transactional model). 

Among others (variable sector sizes, adaptive endianness, ...)

%prep
%setup -q 
%patch -p1

%build
cd src
scons

%install
[ "$RPM_BUILD_ROOT" != "/" ] && [ -d $RPM_BUILD_ROOT ] && rm -rf $RPM_BUILD_ROOT;
mkdir -p $RPM_BUILD_ROOT%_sbindir
mkdir -p $RPM_BUILD_ROOT%{_sysconfdir}/init.d/
install -m755 contrib/%{name}.initd.fedora $RPM_BUILD_ROOT%{_sysconfdir}/init.d/%{name}
ln -s %{_sysconfdir}/init.d/%{name} $RPM_BUILD_ROOT%_sbindir/rc%{name}
cd src
scons install install_dir=$RPM_BUILD_ROOT%_sbindir

%clean
[ "$RPM_BUILD_ROOT" != "/" ] && [ -d $RPM_BUILD_ROOT ] && rm -rf $RPM_BUILD_ROOT;

%files
%defattr(-,root,root)
%doc BUGS CHANGES HACKING INSTALL LICENSE README README.NFS STATUS TESTING TODO
%{_sysconfdir}/init.d/%{name}
%_sbindir/rc%{name}
%{_sbindir}/zdb
%{_sbindir}/zfs
%{_sbindir}/zpool
%{_sbindir}/ztest
%{_sbindir}/zfs-fuse

%changelog
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
