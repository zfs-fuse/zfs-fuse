#!/usr/bin/perl

use strict;

# map is initialised with paths which can't be guessed easily
my %map = (
    "usr/src/lib/libzpool/common/taskq.c" => "src/lib/libzpool/taskq.c",
    "usr/src/uts/common/os/taskq.c" => "src/lib/libsolkerncompat/taskq.c",
);
# This map0 thing could probably be removed now, it worked.
my %map0 = (
    "usr/src/uts/common/fs/zfs/zfs_acl.c" => "src/zfs-fuse/zfs_acl.c",
    "usr/src/uts/common/os/policy.c" => "src/lib/libsolkerncompat/policy.c",
    "usr/src/uts/common/sys/policy.h" => "src/lib/libsolkerncompat/include/sys/policy.h",
    "usr/src/uts/common/fs/zfs/rrwlock.c" => "src/lib/libzpool/rrwlock.c",
    "usr/src/uts/common/fs/zfs/sys/zfs_acl.h" => "src/lib/libzfscommon/include/sys/zfs_acl.h",
    "usr/src/uts/common/fs/zfs/sys/zfs_znode.h" => "src/lib/libzfscommon/include/sys/zfs_znode.h",
    "usr/src/uts/common/fs/zfs/zfs_vnops.c" => "src/zfs-fuse/zfs_vnops.c",
    "usr/src/uts/common/fs/zfs/zfs_znode.c" => "src/lib/libzpool/zfs_znode.c",
    "usr/src/uts/common/fs/zfs/zfs_vfsops.c" => "src/zfs-fuse/zfs_vfsops.c",
    "usr/src/lib/libzfs/common/libzfs_pool.c" => "src/lib/libzfs/libzfs_pool.c",
    "usr/src/uts/common/fs/zfs/spa.c" => "src/lib/libzpool/spa.c",
    "usr/src/uts/common/fs/zfs/sys/spa.h" => "src/lib/libzfscommon/include/sys/spa.h",
    "usr/src/uts/common/fs/zfs/sys/spa_boot.h" => "./src/lib/libzfscommon/include/sys/spa_boot.h",
    "usr/src/uts/common/fs/zfs/sys/vdev_impl.h" => "./src/lib/libzfscommon/include/sys/vdev_impl.h",
    "usr/src/uts/common/fs/zfs/vdev.c" => "./src/lib/libzpool/vdev.c",
    "usr/src/uts/common/fs/zfs/zvol.c" => "./src/zfs-fuse/zvol.c",
    "usr/src/cmd/zpool/zpool_main.c" => "src/cmd/zpool/zpool_main.c",
    "usr/src/cmd/ztest/ztest.c" => "./src/cmd/ztest/ztest.c",
    "usr/src/common/zfs/zpool_prop.c" => "src/lib/libzfscommon/zpool_prop.c",
    "usr/src/lib/libzfs/common/libzfs.h" => "./src/lib/libzfs/include/libzfs.h",
    "usr/src/lib/libzfs/common/libzfs_pool.c" => "./src/lib/libzfs/libzfs_pool.c",
    "usr/src/lib/libzpool/common/sys/zfs_context.h" => "./src/lib/libzpool/include/sys/zfs_context.h",
    "usr/src/uts/common/fs/zfs/arc.c" => "src/lib/libzpool/arc.c",
    "usr/src/uts/common/fs/zfs/spa.c" => "src/lib/libzpool/spa.c",
    "usr/src/uts/common/fs/zfs/spa_config.c" => "src/lib/libzpool/spa_config.c",
    "usr/src/uts/common/fs/zfs/sys/arc.h" => "./src/lib/libzfscommon/include/sys/arc.h",
    "usr/src/uts/common/fs/zfs/sys/spa.h" => "./src/lib/libzfscommon/include/sys/spa.h",
    "usr/src/uts/common/fs/zfs/sys/spa_impl.h" => "src/lib/libzfscommon/include/sys/spa_impl.h",
    "usr/src/uts/common/fs/zfs/sys/vdev.h" => "./src/lib/libzfscommon/include/sys/vdev.h",
    "usr/src/uts/common/fs/zfs/sys/vdev_impl.h" => "./src/lib/libzfscommon/include/sys/vdev_impl.h",
    "usr/src/uts/common/fs/zfs/sys/zfs_context.h" => "./src/lib/libsolkerncompat/include/sys/zfs_context.h",
    "usr/src/uts/common/sys/fs/zfs.h" => "./src/lib/libzfscommon/include/sys/fs/zfs.h",
    "usr/src/uts/common/fs/zfs/spa_misc.c" => "./src/lib/libzpool/spa_misc.c",
    "usr/src/uts/common/fs/zfs/vdev_label.c" => "./src/lib/libzpool/vdev_label.c",
    "usr/src/uts/common/fs/zfs/vdev_mirror.c" => "./src/lib/libzpool/vdev_mirror.c",
    "usr/src/uts/common/fs/zfs/vdev_raidz.c" => "./src/lib/libzpool/vdev_raidz.c",
    "usr/src/uts/common/fs/zfs/vdev_root.c" => "./src/lib/libzpool/vdev_root.c",
    "usr/src/uts/common/fs/zfs/dsl_deleg.c" => "./src/lib/libzpool/dsl_deleg.c",
    "usr/src/uts/common/fs/zfs/dmu_tx.c" => "./src/lib/libzpool/dmu_tx.c",
    "usr/src/uts/common/fs/zfs/sys/zap.h" => "./src/lib/libzfscommon/include/sys/zap.h",
    "usr/src/uts/common/fs/zfs/zap_micro.c" => "./src/lib/libzpool/zap_micro.c",
    "usr/src/uts/common/fs/zfs/zil.c" => "src/lib/libzpool/zil.c",
    "usr/src/uts/common/fs/zfs/spa_history.c" => "./src/lib/libzpool/spa_history.c",
    "usr/src/uts/common/fs/zfs/dmu.c" => "./src/lib/libzpool/dmu.c",
    "usr/src/uts/common/fs/zfs/dnode.c" => "./src/lib/libzpool/dnode.c",
    "usr/src/uts/common/fs/zfs/dmu_objset.c" => "./src/lib/libzpool/dmu_objset.c",
    "usr/src/uts/common/fs/zfs/dsl_scrub.c" => "./src/lib/libzpool/dsl_scrub.c",
    "usr/src/uts/common/fs/zfs/dsl_dataset.c" => "./src/lib/libzpool/dsl_dataset.c",
    "usr/src/uts/common/fs/zfs/dsl_dir.c" => "./src/lib/libzpool/dsl_dir.c",
    "usr/src/cmd/zpool/zpool_vdev.c" => "./src/cmd/zpool/zpool_vdev.c",
    "usr/src/uts/common/fs/zfs/sys/zio.h" => "./src/lib/libzfscommon/include/sys/zio.h",
    "usr/src/uts/common/fs/zfs/vdev_queue.c" => "./src/lib/libzpool/vdev_queue.c",
    "usr/src/lib/libzfs/common/libzfs_status.c" => "./src/lib/libzfs/libzfs_status.c",
    "usr/src/lib/libzfs/common/libzfs_sendrecv.c" => "./src/lib/libzfs/libzfs_sendrecv.c",
    "usr/src/lib/libzfs/common/libzfs_changelist.c" => "./src/lib/libzfs/libzfs_changelist.c",
    "usr/src/lib/libzfs/common/libzfs_dataset.c" => "./src/lib/libzfs/libzfs_dataset.c",
    "usr/src/uts/common/fs/zfs/dmu_send.c" => "./src/lib/libzpool/dmu_send.c",
    "usr/src/uts/common/fs/zfs/sys/dmu.h" => "./src/lib/libzfscommon/include/sys/dmu.h",
    "usr/src/uts/common/fs/zfs/sys/dsl_dataset.h" => "./src/lib/libzfscommon/include/sys/dsl_dataset.h",
    "usr/src/uts/common/fs/zfs/sys/zfs_vfsops.h" => "./src/lib/libzfscommon/include/sys/zfs_vfsops.h",
    "usr/src/uts/common/fs/zfs/zfs_ioctl.c" => "./src/zfs-fuse/zfs_ioctl.c",
    "usr/src/cmd/zfs/zfs_main.c" => "./src/cmd/zfs/zfs_main.c",
    "usr/src/cmd/zdb/zdb.c" => "./src/cmd/zdb/zdb.c",
    "usr/src/cmd/zfs/zfs_iter.c" => "./src/cmd/zfs/zfs_iter.c",
    "usr/src/common/zfs/zfs_deleg.c" => "./src/lib/libzfscommon/zfs_deleg.c",
    "usr/src/common/zfs/zfs_deleg.h" => "./src/lib/libzfscommon/include/zfs_deleg.h",
    "usr/src/common/zfs/zfs_namecheck.c" => "./src/lib/libzfscommon/zfs_namecheck.c",
    "usr/src/common/zfs/zfs_prop.c" => "./src/lib/libzfscommon/zfs_prop.c",
    "usr/src/lib/libzfs/common/libzfs_util.c" => "./src/lib/libzfs/libzfs_util.c",
    "usr/src/uts/common/fs/zfs/dsl_prop.c" => "./src/lib/libzpool/dsl_prop.c",
    "usr/src/uts/common/fs/zfs/sys/dmu_impl.h" => "./src/lib/libzfscommon/include/sys/dmu_impl.h",
    "usr/src/uts/common/fs/zfs/sys/dmu_objset.h" => "./src/lib/libzfscommon/include/sys/dmu_objset.h",
    "usr/src/uts/common/fs/zfs/sys/dsl_deleg.h" => "./src/lib/libzfscommon/include/sys/dsl_deleg.h",
    "usr/src/uts/common/fs/zfs/sys/dsl_prop.h" => "./src/lib/libzfscommon/include/sys/dsl_prop.h",
    "usr/src/uts/common/fs/zfs/sys/zfs_ioctl.h" => "./src/lib/libzfscommon/include/sys/zfs_ioctl.h",
    "usr/src/uts/common/fs/zfs/zfs_ctldir.c" => "./src/zfs-fuse/zfs_ctldir.c",
    "usr/src/cmd/zpool/zpool_util.c" => "./src/cmd/zpool/zpool_util.c",
    "usr/src/cmd/zpool/zpool_util.h" => "./src/cmd/zpool/zpool_util.h",
    "usr/src/lib/libzpool/common/kernel.c" => "./src/lib/libzpool/kernel.c",
    "usr/src/uts/common/fs/zfs/dbuf.c" => "./src/lib/libzpool/dbuf.c",
    "usr/src/uts/common/fs/zfs/dmu_object.c" => "./src/lib/libzpool/dmu_object.c",
    "usr/src/uts/common/fs/zfs/dsl_pool.c" => "./src/lib/libzpool/dsl_pool.c",
    "usr/src/uts/common/fs/zfs/sys/dbuf.h" => "./src/lib/libzfscommon/include/sys/dbuf.h",
    "usr/src/uts/common/fs/zfs/sys/dnode.h" => "./src/lib/libzfscommon/include/sys/dnode.h",
    "usr/src/uts/common/fs/zfs/sys/zil.h" => "./src/lib/libzfscommon/include/sys/zil.h",
    "usr/src/uts/common/fs/zfs/sys/zil_impl.h" => "./src/lib/libzfscommon/include/sys/zil_impl.h",
    "usr/src/uts/common/fs/zfs/zfs_log.c" => "./src/zfs-fuse/zfs_log.c",
    "usr/src/uts/common/fs/zfs/zio.c" => "./src/lib/libzpool/zio.c",
    "usr/src/uts/common/fs/zfs/spa_errlog.c" => "./src/lib/libzpool/spa_errlog.c",
    "usr/src/uts/common/fs/zfs/sys/dsl_pool.h" => "./src/lib/libzfscommon/include/sys/dsl_pool.h",
    "usr/src/uts/common/fs/zfs/sys/dsl_dir.h" => "./src/lib/libzfscommon/include/sys/dsl_dir.h",
    "usr/src/uts/common/fs/zfs/zap.c" => "./src/lib/libzpool/zap.c",
    "usr/src/uts/common/fs/zfs/dmu_zfetch.c" => "./src/lib/libzpool/dmu_zfetch.c",
    "usr/src/uts/common/fs/zfs/sys/dmu_zfetch.h" => "./src/lib/libzfscommon/include/sys/dmu_zfetch.h",
    "usr/src/uts/common/fs/zfs/zfs_fm.c" => "src/lib/libzpool/zfs_fm.c",
    "usr/src/lib/libzfs/common/libzfs_impl.h" => "src/lib/libzfs/include/libzfs_impl.h",
    "usr/src/lib/libzfs/common/libzfs_mount.c" => "src/lib/libzfs/libzfs_mount.c",
    "usr/src/uts/common/fs/zfs/sys/zvol.h" => "src/lib/libzfscommon/include/sys/zvol.h",
    "usr/src/lib/libnvpair/libnvpair.c" => "src/lib/libnvpair/libnvpair.c",
    "usr/src/lib/libnvpair/libnvpair.h" => "src/lib/libnvpair/include/libnvpair.h",
    "usr/src/lib/libzfs/common/libzfs_import.c" => "src/lib/libzfs/libzfs_import.c",
    "usr/src/uts/common/fs/zfs/metaslab.c" => "src/lib/libzpool/metaslab.c",
    "usr/src/uts/common/fs/zfs/sys/metaslab.h" => "src/lib/libzfscommon/include/sys/metaslab.h",
    "usr/src/uts/common/fs/zfs/sys/metaslab_impl.h" => "src/lib/libzfscommon/include/sys/metaslab_impl.h",
    "usr/src/uts/common/fs/zfs/vdev_missing.c" => "src/lib/libzpool/vdev_missing.c",
    "usr/src/uts/common/fs/zfs/zio_inject.c" => "src/lib/libzpool/zio_inject.c",
    "usr/src/cmd/zstreamdump/zstreamdump.c" => "src/cmd/zstreamdump/zstreamdump.c",
    "usr/src/common/zfs/zfs_fletcher.h" => "./src/lib/libzfs/include/zfs_fletcher.h",
    "usr/src/lib/libzpool/common/taskq.c" => "src/lib/libzpool/taskq.c",
    "usr/src/uts/common/fs/zfs/sys/dmu_tx.h" => "./src/lib/libzfscommon/include/sys/dmu_tx.h",
    "usr/src/uts/common/fs/zfs/sys/txg.h" => "./src/lib/libzfscommon/include/sys/txg.h",
    "usr/src/uts/common/fs/zfs/sys/txg_impl.h" => "./src/lib/libzfscommon/include/sys/txg_impl.h",
    "usr/src/uts/common/fs/zfs/sys/zap_impl.h" => "./src/lib/libzfscommon/include/sys/zap_impl.h",
    "usr/src/uts/common/fs/zfs/txg.c" => "src/lib/libzpool/txg.c",
    "usr/src/uts/common/fs/zfs/sys/zio_checksum.h" => "src/lib/libzfscommon/include/sys/zio_checksum.h",
    "usr/src/uts/common/fs/zfs/zio_checksum.c" => "src/lib/libzpool/zio_checksum.c",
    "usr/src/uts/common/sys/fm/fs/zfs.h" => "src/lib/libzfscommon/include/sys/fm/fs/zfs.h",
    "usr/src/uts/common/fs/zfs/zfs_replay.c" => "./src/zfs-fuse/zfs_replay.c",
    "usr/src/cmd/zdb/zdb_il.c" => "src/cmd/zdb/zdb_il.c",
    "usr/src/lib/libzfs/common/libzfs_config.c" => "src/lib/libzfs/libzfs_config.c",
    "usr/src/lib/libzfs/common/libzfs_fru.c" => "src/lib/libzfs/libzfs_fru.c",
    "usr/src/uts/common/fs/zfs/vdev_file.c" => "src/lib/libzpool/vdev_file.c",
    "usr/src/uts/common/sys/vfs.h" => "src/lib/libsolkerncompat/include/sys/vfs.h",
    "usr/src/uts/common/sys/vnode.h" => "src/lib/libsolkerncompat/include/sys/vnode.h",

);

my $arg = $ARGV[0];
open(F,">header");
open(G,">diff");
$arg =~ /export-(\d+)/;
my $commit = $1;
print F "hg commit $commit:";
my $author;
while (<>) {
    if (/^# User (.+)/) {
	$author = $1;
	chomp $author;
    }
    next if (/^#/);
    last if (/^diff/);
    print F;
}
close(F);
my @files = ();
while (1) {
    / a\/(.+) /;  # /
    my $f1 = $1;
    if ($f1 =~ /(\.py$|grub|mapfile-vers$|cmd\/[a-y]|lib\/libc\/|\/fs\/[a-y]|\/vdev_disk.c$|libdiskmgt\/|dumpsubr.c$|zinject|Makefile\.(com|files|lint)$|pkgdefs\/|llib-lzfs$|fsreparse\/|\/xattr\/|libreparse\/|lib(secdb|topo)|zut\/|io\/|smbsrv|common\/syscall)|(llib-lzpool|spa_boot.c)$|zoneadmd\/|tsol\//) {
	print "skipping diff for $f1\n";
	while (<>) {
	    last if (/^diff/); # skip this diff
	}
    } else {
	if (!$map{$f1}) {
	    my $target = "src/";
	    if ($f1 =~ /(cmd\/z.+)/) {
		$target .= "$1";
		$map{$f1} = $target if (-f $target);
	    } elsif ($f1 =~ /(lib\/.+?\/)(.+)/) {
		$target .= $1;
		my $file = $2;
		die "lib $target\n" if (! -d $target);
		$file =~ s/^common\///;
		if ($file =~ /.h$/ && ! -f "$target$file") {
		    $file = "include/$file";
		}
		die "mapping lib $f1 -> $target $file\n" if (!-f "$target$file");
		$map{$f1} = "$target$file";
	    } else {
		# a file without any obvious directory
		my $file;
		if ($f1 =~ /(sys\/.+)/) {
		    $file = $1;
		} elsif ($f1 =~ /.+\/(.+?)$/) {
		    $file = $1;
		}
		my @list = glob("src/*/$file");
		@list = glob("src/*/*/$file") if (!@list);
		@list = glob("src/*/*/include/$file") if (!@list && $file =~ /h$/);
		if ($#list == 0) {
#		    print "new map ok $f1 -> @list\n";
		    $map{$f1} = $list[0];
		    $map0{$f1} =~ s/^\.\///;
		    if ($map0{$f1} ne $map{$f1} && $map0{$f1}) {
			die "no confirmation from map0 : $map0{$f1}\n";
		    }
		} else {
		    die "new map problem $f1 -> @list (using $file)\n";
		}
	    }
	} 
	die "map $f1\n" if (!$map{$f1});
	push @files,$map{$f1};
	s:$f1:$map{$f1}:g;
	print G;
	do {
	    $_ = <>;
	    die "renames must be handled manually (file $f1)\n" if (/^rename/);
	} while ($_ !~ /^--/);
	s:$f1:$map{$f1}:g;
	print G;
	$_ = <>;
	s:$f1:$map{$f1}:g;
	print G;
	while (<>) {
	    last if (/^diff/);
	    print G;
	}
    }
    next if (/^diff/);
    last;
}
close(G);
unlink "ok";
# system("patch -p1 < diff && echo ok && touch ok");
if ( -f "ok" ) {
    print "commiting...\n";
    system("git commit -F header --author \"$author\" @files && rm $arg");
} else {
    print "commit with : git commit -F header --author \"$author\" @files\n";
    print "or revert with git checkout @files\n";
}
