bin_PROGRAMS = ziproxylogtool quantize_png_color verify splitgmap compress_gmap

ziproxylogtool_SOURCES = ziproxylogtool.c
quantize_png_color_SOURCES = ../mmap_api.c ../mmap_api.h ../log.c ../log.h ../png_compressor.c ../png_compressor.h quantize_png_color.c 
quantize_png_color_CFLAGS=-DTEST -UHAVE_CONFIG_H
quantize_png_color_LDADD=-lcunit
quantize_png_color_DEFS=
verify_SOURCES = verify.c
splitgmap_SOURCES = splitgmap.c
compress_gmap_SOURCES = ../mmap_api.c ../mmap_api.h ../log.c ../log.h ../png_compressor.c ../png_compressor.h ../googlemap.c ../googlemap.h compress_gmap.c
compress_gmap_CFLAGS=-UHAVE_CONFIG_H

