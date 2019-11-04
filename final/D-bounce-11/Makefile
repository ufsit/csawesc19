all : full_exec.bin

full_exec.bin : full_exec.elf
	arm-none-eabi-objcopy -O binary $< $@

full_exec.elf : full_exec.S
	arm-none-eabi-as -mthumb -o $@ $<

.PHONY: all
