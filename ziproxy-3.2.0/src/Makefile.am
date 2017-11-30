SUBDIRS = tools

bin_PROGRAMS = ziproxy runtest ziproxy_killtimeout savetomem
runtest_CFLAGS=-DTEST
runtest_LDADD=-lcunit
getcolor_CFLAGS=-DTEST

if COMPILE_JP2_SUPPORT
ziproxy_SOURCES = ziproxy.c http.c http.h log.c log.h text.c text.h image.c image.h cfgfile.c cfgfile.h config.h preemptdns.c preemptdns.h netd.c htmlopt.h htmlopt.c qparser.c qparser.h gzpipe.c gzpipe.h fstring.c fstring.h cdetect.c cdetect.h urltables.c urltables.h txtfiletools.c txtfiletools.h auth.c auth.h strtables.c strtables.h simplelist.c simplelist.h tosmarking.c tosmarking.h cttables.c cttables.h misc.c misc.h session.c session.h globaldefs.h jp2tools.c jp2tools.h global.h md5.h md5func.h md5c.c md5func.c mmap_api.c mmap_api.h logreduce.h logreduce.c generic_resp.c app_specific_resp.c png_compressor.c png_compressor.h googlemap.h googlemap.c applemap.c applemap.h user_settings.c user_settings.h usettings_process.h usettings_process.c 
runtest_SOURCES = runtest.c ziproxy.c http.c http.h log.c log.h text.c text.h image.c image.h cfgfile.c cfgfile.h config.h preemptdns.c preemptdns.h htmlopt.h htmlopt.c qparser.c qparser.h gzpipe.c gzpipe.h fstring.c fstring.h cdetect.c cdetect.h urltables.c urltables.h txtfiletools.c txtfiletools.h auth.c auth.h strtables.c strtables.h simplelist.c simplelist.h tosmarking.c tosmarking.h cttables.c cttables.h misc.c misc.h session.c session.h globaldefs.h jp2tools.c jp2tools.h global.h md5.h md5func.h md5c.c md5func.c mmap_api.c mmap_api.h logreduce.h logreduce.c generic_resp.c app_specific_resp.c png_compressor.c png_compressor.h googlemap.h googlemap.c applemap.c applemap.h user_settings.c user_settings.h usettings_process.h usettings_process.c 
else
ziproxy_SOURCES = ziproxy.c http.c http.h log.c log.h text.c text.h image.c image.h cfgfile.c cfgfile.h config.h preemptdns.c preemptdns.h netd.c htmlopt.h htmlopt.c qparser.c qparser.h gzpipe.c gzpipe.h fstring.c fstring.h cdetect.c cdetect.h urltables.c urltables.h txtfiletools.c txtfiletools.h auth.c auth.h strtables.c strtables.h simplelist.c simplelist.h tosmarking.c tosmarking.h cttables.c cttables.h misc.c misc.h session.c session.h globaldefs.h global.h md5.h md5func.h md5c.c md5func.c mmap_api.c mmap_api.h logreduce.h logreduce.c generic_resp.c app_specific_resp.c  png_compressor.c png_compressor.h googlemap.h googlemap.c applemap.c applemap.h user_settings.c user_settings.h usettings_process.h usettings_process.c 
runtest_SOURCES = runtest.c ziproxy.c http.c http.h log.c log.h text.c text.h image.c image.h cfgfile.c cfgfile.h config.h preemptdns.c preemptdns.h htmlopt.h htmlopt.c qparser.c qparser.h gzpipe.c gzpipe.h fstring.c fstring.h cdetect.c cdetect.h urltables.c urltables.h txtfiletools.c txtfiletools.h auth.c auth.h strtables.c strtables.h simplelist.c simplelist.h tosmarking.c tosmarking.h cttables.c cttables.h misc.c misc.h session.c session.h globaldefs.h global.h md5.h md5func.h md5c.c md5func.c mmap_api.c mmap_api.h logreduce.h logreduce.c generic_resp.c app_specific_resp.c png_compressor.c png_compressor.h googlemap.h googlemap.c applemap.c applemap.h user_settings.c user_settings.h usettings_process.h usettings_process.c 
endif

ziproxy_killtimeout_SOURCES = killtimeout.c

savetomem_SOURCES = savetomem.c global.h md5.h md5func.h md5c.c md5func.c

#ziproxyconfdir=$(sysconfdir)/ziproxy
#ziproxyconf_DATA=../etc/ziproxy/ziproxy.conf
