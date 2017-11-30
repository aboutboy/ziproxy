################################################################################
# Automatically-generated file. Do not edit!
################################################################################

# Add inputs and outputs from these tool invocations to the build variables 
O_SRCS += \
../src/app_specific_resp.o \
../src/auth.o \
../src/cdetect.o \
../src/cfgfile.o \
../src/cttables.o \
../src/fstring.o \
../src/generic_resp.o \
../src/getcolor-getcolor.o \
../src/getcolor-log.o \
../src/getcolor-png_compressor.o \
../src/getcolor.o \
../src/googlemap.o \
../src/gzpipe.o \
../src/htmlopt.o \
../src/http.o \
../src/image.o \
../src/jp2tools.o \
../src/log.o \
../src/logreduce.o \
../src/md5c.o \
../src/md5func.o \
../src/misc.o \
../src/mmap_api.o \
../src/netd.o \
../src/png_compressor.o \
../src/preemptdns.o \
../src/qparser.o \
../src/runtest-app_specific_resp.o \
../src/runtest-auth.o \
../src/runtest-cdetect.o \
../src/runtest-cfgfile.o \
../src/runtest-cttables.o \
../src/runtest-fstring.o \
../src/runtest-generic_resp.o \
../src/runtest-googlemap.o \
../src/runtest-gzpipe.o \
../src/runtest-htmlopt.o \
../src/runtest-http.o \
../src/runtest-image.o \
../src/runtest-jp2tools.o \
../src/runtest-log.o \
../src/runtest-logreduce.o \
../src/runtest-md5c.o \
../src/runtest-md5func.o \
../src/runtest-misc.o \
../src/runtest-mmap_api.o \
../src/runtest-png_compressor.o \
../src/runtest-preemptdns.o \
../src/runtest-qparser.o \
../src/runtest-runtest.o \
../src/runtest-session.o \
../src/runtest-simplelist.o \
../src/runtest-strtables.o \
../src/runtest-text.o \
../src/runtest-tosmarking.o \
../src/runtest-txtfiletools.o \
../src/runtest-urltables.o \
../src/runtest-ziproxy.o \
../src/session.o \
../src/simplelist.o \
../src/splitgmap.o \
../src/strtables.o \
../src/text.o \
../src/tosmarking.o \
../src/txtfiletools.o \
../src/urltables.o \
../src/verify.o \
../src/ziproxy.o 

C_SRCS += \
../src/app_specific_resp.c \
../src/auth.c \
../src/cdetect.c \
../src/cfgfile.c \
../src/cttables.c \
../src/fstring.c \
../src/gencvtables.c \
../src/genembbin.c \
../src/generic_resp.c \
../src/googlemap.c \
../src/gzpipe.c \
../src/htmlopt.c \
../src/http.c \
../src/image.c \
../src/jp2tools.c \
../src/log.c \
../src/logreduce.c \
../src/md5c.c \
../src/md5func.c \
../src/misc.c \
../src/mmap_api.c \
../src/netd.c \
../src/png_compressor.c \
../src/preemptdns.c \
../src/qparser.c \
../src/runtest.c \
../src/session.c \
../src/simplelist.c \
../src/strtables.c \
../src/testimage.c \
../src/text.c \
../src/tosmarking.c \
../src/txtfiletools.c \
../src/urltables.c \
../src/ziproxy.c 

OBJS += \
./src/app_specific_resp.o \
./src/auth.o \
./src/cdetect.o \
./src/cfgfile.o \
./src/cttables.o \
./src/fstring.o \
./src/gencvtables.o \
./src/genembbin.o \
./src/generic_resp.o \
./src/googlemap.o \
./src/gzpipe.o \
./src/htmlopt.o \
./src/http.o \
./src/image.o \
./src/jp2tools.o \
./src/log.o \
./src/logreduce.o \
./src/md5c.o \
./src/md5func.o \
./src/misc.o \
./src/mmap_api.o \
./src/netd.o \
./src/png_compressor.o \
./src/preemptdns.o \
./src/qparser.o \
./src/runtest.o \
./src/session.o \
./src/simplelist.o \
./src/strtables.o \
./src/testimage.o \
./src/text.o \
./src/tosmarking.o \
./src/txtfiletools.o \
./src/urltables.o \
./src/ziproxy.o 

C_DEPS += \
./src/app_specific_resp.d \
./src/auth.d \
./src/cdetect.d \
./src/cfgfile.d \
./src/cttables.d \
./src/fstring.d \
./src/gencvtables.d \
./src/genembbin.d \
./src/generic_resp.d \
./src/googlemap.d \
./src/gzpipe.d \
./src/htmlopt.d \
./src/http.d \
./src/image.d \
./src/jp2tools.d \
./src/log.d \
./src/logreduce.d \
./src/md5c.d \
./src/md5func.d \
./src/misc.d \
./src/mmap_api.d \
./src/netd.d \
./src/png_compressor.d \
./src/preemptdns.d \
./src/qparser.d \
./src/runtest.d \
./src/session.d \
./src/simplelist.d \
./src/strtables.d \
./src/testimage.d \
./src/text.d \
./src/tosmarking.d \
./src/txtfiletools.d \
./src/urltables.d \
./src/ziproxy.d 


# Each subdirectory must supply rules for building sources it contributes
src/%.o: ../src/%.c
	@echo 'Building file: $<'
	@echo 'Invoking: Cross GCC Compiler'
	gcc -O0 -g3 -Wall -c -fmessage-length=0 -MMD -MP -MF"$(@:%.o=%.d)" -MT"$(@:%.o=%.d)" -o "$@" "$<"
	@echo 'Finished building: $<'
	@echo ' '


