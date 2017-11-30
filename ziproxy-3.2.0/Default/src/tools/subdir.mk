################################################################################
# Automatically-generated file. Do not edit!
################################################################################

# Add inputs and outputs from these tool invocations to the build variables 
C_SRCS += \
../src/tools/compress_gmap.c \
../src/tools/quantize_png_color.c \
../src/tools/splitgmap.c \
../src/tools/verify.c \
../src/tools/ziproxylogtool.c 

OBJS += \
./src/tools/compress_gmap.o \
./src/tools/quantize_png_color.o \
./src/tools/splitgmap.o \
./src/tools/verify.o \
./src/tools/ziproxylogtool.o 

C_DEPS += \
./src/tools/compress_gmap.d \
./src/tools/quantize_png_color.d \
./src/tools/splitgmap.d \
./src/tools/verify.d \
./src/tools/ziproxylogtool.d 


# Each subdirectory must supply rules for building sources it contributes
src/tools/%.o: ../src/tools/%.c
	@echo 'Building file: $<'
	@echo 'Invoking: GCC C Compiler'
	gcc -O2 -g -Wall -c -fmessage-length=0 -MMD -MP -MF"$(@:%.o=%.d)" -MT"$(@:%.o=%.d)" -o "$@" "$<"
	@echo 'Finished building: $<'
	@echo ' '


