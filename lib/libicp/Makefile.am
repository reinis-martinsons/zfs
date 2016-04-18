include $(top_srcdir)/config/Rules.am

VPATH = \
	$(top_srcdir)/module/icp \
	$(top_srcdir)/module/icp/$(TARGET_ASM_DIR)

#VPATH = \
#	$(top_srcdir)/lib/libicp \
#	$(top_srcdir)/lib/libicp/$(TARGET_ASM_DIR)

AM_CFLAGS += $(DEBUG_STACKFLAGS) $(FRAME_LARGER_THAN)

#SUBDIRS = include #$(TARGET_ASM_DIR)
#DIST_SUBDIRS = include # asm-generic asm-i386 asm-x86_64

DEFAULT_INCLUDES += \
	-I$(top_srcdir)/include \
	-I$(top_srcdir)/module/icp/include \
	-I$(top_srcdir)/lib/libspl/include

AM_CCASFLAGS = \
	-I$(top_srcdir)/module/icp/include

noinst_LTLIBRARIES = libicp.la

#asm-x86_64_C = aes/aeskey.c
#asm-x86_64_ASM = aes/aes_amd64.S
#asm-i386_C =
#asm-i386_ASM =
#asm-generic_C =
#asm-generic_ASM =

USER_C =

USER_ASM =

KERNEL_C = \
	spi/kcf_spi.c \
	api/kcf_ctxops.c \
	api/kcf_digest.c \
	api/kcf_cipher.c \
	api/kcf_miscapi.c \
	api/kcf_mac.c \
	algs/aes/aes_impl.c \
	algs/modes/modes.c \
	algs/modes/cbc.c \
	algs/modes/gcm.c \
	algs/modes/ctr.c \
	algs/modes/ccm.c \
	algs/modes/ecb.c \
	algs/sha2/sha2.c \
	asm-x86_64/aes/aeskey.c \
	icp.mod.c \
	illumos-crypto.c \
	io/aes.c \
	io/sha2_mod.c \
	os/bitmap_arch.c \
	os/modhash.c \
	os/modconf.c \
	core/kcf_sched.c \
	core/kcf_prov_lib.c \
	core/kcf_callprov.c \
	core/kcf_mech_tabs.c \
	core/kcf_prov_tabs.c \
	aes/aeskey.c

#	$($(TARGET_ASM_DIR)_C)

KERNEL_ASM = \
	aes/aes_amd64.S
	
#
#	$($(TARGET_ASM_DIR)_ASM)

nodist_libicp_la_SOURCES = \
	$(USER_C) \
	$(USER_ASM) \
	$(KERNEL_C) \
	$(KERNEL_ASM)

libicp_la_LIBADD = -lrt

EXTRA_DIST = $(USER_C)

