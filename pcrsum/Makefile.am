#################################################################################
#										#
# Makefile for libtpm/utils							#
#										#
# $Id: Makefile.am 4073 2010-04-30 14:44:14Z kgoldman $				#
#										#
# (c) Copyright IBM Corporation 2006, 2010.					#
# 										#
# All rights reserved.								#
# 										#
# Redistribution and use in source and binary forms, with or without		#
# modification, are permitted provided that the following conditions are	#
# met:										#
# 										#
# Redistributions of source code must retain the above copyright notice,	#
# this list of conditions and the following disclaimer.				#
# 										#
# Redistributions in binary form must reproduce the above copyright		#
# notice, this list of conditions and the following disclaimer in the		#
# documentation and/or other materials provided with the distribution.		#
# 										#
# Neither the names of the IBM Corporation nor the names of its			#
# contributors may be used to endorse or promote products derived from		#
# this software without specific prior written permission.			#
# 										#
# THIS SOFTWARE IS PROVIDED BY THE COPYRIGHT HOLDERS AND CONTRIBUTORS		#
# "AS IS" AND ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT		#
# LIMITED TO, THE IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS FOR		#
# A PARTICULAR PURPOSE ARE DISCLAIMED. IN NO EVENT SHALL THE COPYRIGHT		#
# HOLDER OR CONTRIBUTORS BE LIABLE FOR ANY DIRECT, INDIRECT, INCIDENTAL,	#
# SPECIAL, EXEMPLARY, OR CONSEQUENTIAL DAMAGES (INCLUDING, BUT NOT		#
# LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS OR SERVICES; LOSS OF USE,		#
# DATA, OR PROFITS; OR BUSINESS INTERRUPTION) HOWEVER CAUSED AND ON ANY		#
# THEORY OF LIABILITY, WHETHER IN CONTRACT, STRICT LIABILITY, OR TORT		#
# (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY OUT OF THE USE		#
# OF THIS SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF SUCH DAMAGE.		#
#										#
#################################################################################
SUBDIRS = .
if ARCH_AMD64
ARCH=x86_64
else
ARCH=ia32
endif
AM_CFLAGS = -I/usr/linux/include -I/usr/include/efi -I/usr/include/efi/$(ARCH) 

INCLUDES =  
#LDADD = lib/.libs/libtpm.a /usr/local/ssl/lib/libcrypto.a
LDADD = 

AM_CONDITIONAL = 
#AM_LDFLAGS = -all-static
AM_LDFLAGS = -lmd
LIBS=-lmd
bindir=/usr/sbin
bin_PROGRAMS = pcrsum pcrdecode

pcrsum_SOURCES = pcrsum.c
pcrdecode_SOURCES = pcrdecode.c

noinst_HEADERS = \
	include/Bluetooth.h \
	include/efistruct.h \
	include/PcAnsi.h \
	include/PeImage.h \
	include/Tpm12.h \
	include/UefiGpt.h \
	include/UefiTcgPlatform.h

