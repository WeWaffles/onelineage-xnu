obj-m := olxnu_jump_mod.o olxnu_ram_test.o olxnu_payload.o
olxnu_jump_mod-objs := olxnu_jump.o jump_stub.o

# KDIR must point to the prepared GKI tree with the device's config.gz applied
# and utsrelease.h patched to: 6.12.69-android16-6-pb4d3caf-abogkiS948USQS4BZIG-4k
KDIR ?= /lab/device-abi-linux

build:
	$(MAKE) -C $(KDIR) M=$(shell pwd) ARCH=arm64 LLVM=1 \
		NM=nm OBJCOPY=objcopy STRIP=strip OBJDUMP=objdump AR=ar modules

clean:
	$(MAKE) -C $(KDIR) M=$(shell pwd) ARCH=arm64 LLVM=1 clean
