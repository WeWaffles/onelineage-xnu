obj-m := olxnu_jump_mod.o olxnu_ram_test.o olxnu_payload.o olxnu_cmalist.o
olxnu_jump_mod-objs := olxnu_jump.o jump_stub.o

# Second instance under a distinct module name.  Android loads modules with
# MODULE_FLAG_PERMANENT, so an olxnu_jump_mod already resident cannot be
# rmmod'd and blocks reloading the rebuilt one; this name coexists with it and
# publishes its own proc directory (proc_name=...).
obj-m += olxnu_jump2_mod.o olxnu_payload2_mod.o
olxnu_jump2_mod-objs := olxnu_jump.o jump_stub.o
olxnu_payload2_mod-objs := olxnu_payload.o

# KDIR must point to the prepared GKI tree with the device's config.gz applied
# and utsrelease.h patched to: 6.12.69-android16-6-pb4d3caf-abogkigeneric-4k
KDIR ?= /lab/device-abi-linux

build:
	$(MAKE) -C $(KDIR) M=$(shell pwd) ARCH=arm64 LLVM=1 \
		NM=nm OBJCOPY=objcopy STRIP=strip OBJDUMP=objdump AR=ar modules

clean:
	$(MAKE) -C $(KDIR) M=$(shell pwd) ARCH=arm64 LLVM=1 clean
