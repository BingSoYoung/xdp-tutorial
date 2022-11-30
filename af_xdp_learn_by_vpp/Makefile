# SPDX-License-Identifier: (GPL-2.0 OR BSD-2-Clause)


XDP_TARGETS  := af_xdp_kern
USER_TARGETS := af_xdp

USER_C := af_xdp.c
USER_C += thpool.c

LIBBPF_DIR = ../libbpf/src/
COMMON_DIR = ../common/


include $(COMMON_DIR)/common.mk
LIBS += -lpthread -fPIC -lbpf -g -fno-omit-frame-pointer
