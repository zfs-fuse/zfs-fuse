PAGES=zfs zfs-fuse zdb zstreamdump zpool
XSLTPROC=$()

all: $(PAGES:=.8.gz)

%.8.gz: %.8
	cat "$<" | gzip > "$@"

%.8: %.man.xml
	@if [ -z "$(shell which xsltproc)" ]; then echo "Cannot find xsltproc"; fi
	xsltproc -o "$@" --nonet http://docbook.sourceforge.net/release/xsl/current/manpages/docbook.xsl "$<" || \
		echo "Cannot build manpage. Dependencies on debian: apt-get install xsltproc docbook-xsl docbook-xml"
