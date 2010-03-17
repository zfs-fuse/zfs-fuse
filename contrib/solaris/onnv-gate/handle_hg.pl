#!/usr/bin/perl

use strict;

# map is initialised with paths which can't be guessed easily
my %map = (
    "usr/src/lib/libzpool/common/taskq.c" => "src/lib/libzpool/taskq.c",
    "usr/src/uts/common/os/taskq.c" => "src/lib/libsolkerncompat/taskq.c",
    "usr/src/uts/common/sys/cred.h" => "src/lib/libsolcompat/include/sys/cred.h",
    "usr/src/uts/common/sys/proc.h" => "src/lib/libsolcompat/include/sys/proc.h",
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
    if ($f1 =~ /(\.py$|grub|mapfile-vers$|cmd\/[a-y]|lib\/libc\/|\/fs\/[a-y]|\/vdev_disk.c$|libdiskmgt\/|dumpsubr.c$|zinject|Makefile\.(com|files|lint)$|pkgdefs\/|llib-lzfs$|fsreparse\/|\/xattr\/|libreparse\/|lib(secdb|topo)|zut\/|io\/|smbsrv|common\/syscall)|(llib-lzpool|spa_boot.c)$|zoneadmd\/|tsol\/|src\/(head|Target)|uts\/common\/(disp|brand|os|sys\/class.h)|Makefile|sysdc.*h|startup.c|fth$/) {
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
		} elsif ($list[0] =~ /solkerncompat/) {
		    $map{$f1} = $list[0];
		    printf("choosing kerncompat option : $f1\n");
		} elsif ($list[1] =~ /solkerncompat/) {
		    $map{$f1} = $list[1];
		    printf("choosing kerncompat option : $f1\n");
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
system("patch -p1 < diff && echo ok && touch ok");
if ( -f "ok" ) {
    print "commiting...\n";
    system("git commit -F header --author \"$author\" @files && rm $arg");
} else {
    print "commit with : git commit -F header --author \"$author\" @files\n";
    print "or revert with git checkout @files\n";
}
