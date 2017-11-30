#!/bin/bash
ls $1/http* >filelist
while read file
do
	echo $file
	./compress_gmap "$file" a.out
	if [ $? -ne 0 ]; then
		echo "compress $file failed"
		break
	fi
done < filelist

rm filelist
