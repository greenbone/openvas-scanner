all: sha256sums

../../../target/release/scannerctl:
	cd ../../../ && cargo build --release

vt-metadata.json: ../../../target/release/scannerctl
	../../../target/release/scannerctl feed transform -p . > vt-metadata.json
	
sha256sums: vt-metadata.json
	find . -type f -regex ".*\.\(nasl\|inc\|json\)$$"  -exec sha256sum {} \; | tee sha256sums

rm:
	rm sha256sums
	rm vt-metadata.json

regenerate: rm sha256sums
