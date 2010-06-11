#!/usr/bin/perl

# Just fix the / comments in the S files and replace them by // (super easy)
# pass in argument the name of the file to update

while (my $file = shift @ARGV) {
    open(F,"<$file") || die "open $file\n";
    my @lines = <F>;
    close(F);
    for (my $i=0; $i<=$#lines; $i++) {
	$lines[$i] =~ s/\t\/ /\t\/\/ /;
    }
    open(F,">$file") || die "write $file\n";
    print F @lines;
    close(F);
}
