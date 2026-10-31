/* One PT_LOAD at the guest base, nothing else for crosvm's loader to map. */
ENTRY(_start)
SECTIONS
{
	. = 0x80000000;
	.text : { *(.text) }
	.rodata : { *(.rodata) }
	/DISCARD/ : { *(.note*) *(.comment) *(.eh_frame*) *(.ARM*) }
}
