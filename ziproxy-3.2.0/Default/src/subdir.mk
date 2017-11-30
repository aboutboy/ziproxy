################################################################################
# Automatically-generated file. Do not edit!
################################################################################

# Add inputs and outputs from these tool invocations to the build variables 
C_SRCS += \
../src/app_specific_resp.c \
../src/applemap.c \
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
../src/killtimeout.c \
../src/local_user_settings.c \
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
../src/savetomem.c \
../src/session.c \
../src/simplelist.c \
../src/strtables.c \
../src/test.c \
../src/text.c \
../src/tosmarking.c \
../src/txtfiletools.c \
../src/urltables.c \
../src/user_settings.c \
../src/usettings_process.c \
../src/ziproxy.c 

OBJS += \
./src/app_specific_resp.o \
./src/applemap.o \
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
./src/killtimeout.o \
./src/local_user_settings.o \
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
./src/savetomem.o \
./src/session.o \
./src/simplelist.o \
./src/strtables.o \
./src/test.o \
./src/text.o \
./src/tosmarking.o \
./src/txtfiletools.o \
./src/urltables.o \
./src/user_settings.o \
./src/usettings_process.o \
./src/ziproxy.o 

C_DEPS += \
./src/app_specific_resp.d \
./src/applemap.d \
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
./src/killtimeout.d \
./src/local_user_settings.d \
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
./src/savetomem.d \
./src/session.d \
./src/simplelist.d \
./src/strtables.d \
./src/test.d \
./src/text.d \
./src/tosmarking.d \
./src/txtfiletools.d \
./src/urltables.d \
./src/user_settings.d \
./src/usettings_process.d \
./src/ziproxy.d 


# Each subdirectory must supply rules for building sources it contributes
src/%.o: ../src/%.c
	@echo 'Building file: $<'
	@echo 'Invoking: GCC C Compiler'
	gcc -O2 -g -Wall -c -fmessage-length=0 -MMD -MP -MF"$(@:%.o=%.d)" -MT"$(@:%.o=%.d)" -o "$@" "$<"
	@echo 'Finished building: $<'
	@echo ' '


