################################################################################
# Automatically-generated file. Do not edit!
################################################################################

# Add inputs and outputs from these tool invocations to the build variables 
O_SRCS += \
../png/comppng.o 

C_SRCS += \
../png/comppng.c 

OBJS += \
./png/comppng.o 

C_DEPS += \
./png/comppng.d 


# Each subdirectory must supply rules for building sources it contributes
png/%.o: ../png/%.c
	@echo 'Building file: $<'
	@echo 'Invoking: GCC C Compiler'
	gcc -O2 -g -Wall -c -fmessage-length=0 -MMD -MP -MF"$(@:%.o=%.d)" -MT"$(@:%.o=%.d)" -o "$@" "$<"
	@echo 'Finished building: $<'
	@echo ' '


