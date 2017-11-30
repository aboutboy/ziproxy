################################################################################
# Automatically-generated file. Do not edit!
################################################################################

# Add inputs and outputs from these tool invocations to the build variables 
O_SRCS += \
../src/tools/log.o \
../src/tools/png_compressor.o \
../src/tools/quantize_png_color-log.o \
../src/tools/quantize_png_color-png_compressor.o \
../src/tools/quantize_png_color-quantize_png_color.o \
../src/tools/quantize_png_color.o \
../src/tools/splitgmap.o \
../src/tools/verify.o \
../src/tools/ziproxylogtool.o 

C_SRCS += \
../src/tools/quantize_png_color.c \
../src/tools/splitgmap.c \
../src/tools/verify.c \
../src/tools/ziproxylogtool.c 

OBJS += \
./src/tools/quantize_png_color.o \
./src/tools/splitgmap.o \
./src/tools/verify.o \
./src/tools/ziproxylogtool.o 

C_DEPS += \
./src/tools/quantize_png_color.d \
./src/tools/splitgmap.d \
./src/tools/verify.d \
./src/tools/ziproxylogtool.d 


# Each subdirectory must supply rules for building sources it contributes
src/tools/%.o: ../src/tools/%.c
	@echo 'Building file: $<'
	@echo 'Invoking: Cross GCC Compiler'
	gcc -O0 -g3 -Wall -c -fmessage-length=0 -MMD -MP -MF"$(@:%.o=%.d)" -MT"$(@:%.o=%.d)" -o "$@" "$<"
	@echo 'Finished building: $<'
	@echo ' '


