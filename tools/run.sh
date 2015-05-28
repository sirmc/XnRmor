#cp bzip2.orig.rewrite ./rewrite
#./elfinject -e ./rewrite -i ../profile/payload.bin -n inject -a 0x808000
./elfinject -e ./rewrite -i ../profile/payload.bin -n inject
#./generate_inject ./rewrite
