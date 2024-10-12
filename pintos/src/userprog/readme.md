[pipe-bad-write]
pintos -v -k -T 60 --qemu  --filesys-size=2 -p tests/userprog/pipe-bad-write -a pipe-bad-write -- -q  -f run pipe-bad-write < /dev/null 2> tests/userprog/pipe-bad-write.errors > tests/userprog/pipe-bad-write.output; perl -I../.. ../../tests/userprog/pipe-bad-write.ck tests/userprog/pipe-bad-write tests/userprog/pipe-bad-write.result

[pipe-bad-read]
pintos -v -k -T 60 --qemu  --filesys-size=2 -p tests/userprog/pipe-bad-read -a pipe-bad-read -- -q  -f run pipe-bad-read < /dev/null 2> tests/userprog/pipe-bad-read.errors > tests/userprog/pipe-bad-read.output; perl -I../.. ../../tests/userprog/pipe-bad-read.ck tests/userprog/pipe-bad-read tests/userprog/pipe-bad-read.result

[pipe-rw-close]
pintos -v -k -T 60 --qemu  --filesys-size=2 -p tests/userprog/pipe-rw-close -a pipe-rw-close -- -q  -f run pipe-rw-close < /dev/null 2> tests/userprog/pipe-rw-close.errors > tests/userprog/pipe-rw-close.output; perl -I../.. ../../tests/userprog/pipe-rw-close.ck tests/userprog/pipe-rw-close tests/userprog/pipe-rw-close.result

[pipe-wr-close]
pintos -v -k -T 60 --qemu  --filesys-size=2 -p tests/userprog/pipe-wr-close -a pipe-wr-close -- -q  -f run pipe-wr-close < /dev/null 2> tests/userprog/pipe-wr-close.errors > tests/userprog/pipe-wr-close.output; perl -I../.. ../../tests/userprog/pipe-wr-close.ck tests/userprog/pipe-wr-close tests/userprog/pipe-wr-close.result

[pipe-short]
pintos -v -k -T 60 --qemu  --filesys-size=2 -p tests/userprog/pipe-short -a pipe-short -p tests/userprog/child-short -a child-short -- -q  -f run pipe-short < /dev/null 2> tests/userprog/pipe-short.errors > tests/userprog/pit; perl -I../.. ../../tests/userprog/pipe-short.ck tests/userprog/pipe-short tests/userprog/pipe-short.result

[pipe-long]
pintos -v -k -T 60 --qemu  --filesys-size=2 -p tests/userprog/pipe-long -a pipe-long -p tests/userprog/child-long -a child-long -- -q  -f run pipe-long < /dev/null 2> tests/userprog/pipe-long.errors > tests/userprog/pipe-lont; perl -I../.. ../../tests/userprog/pipe-long.ck tests/userprog/pipe-long tests/userprog/pipe-long.result
