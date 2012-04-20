#
# Copyright (C) 2011 Free Software Foundation, Inc.
#
# Author: Nikos Mavrogiannopoulos
#
# This file is part of GnuTLS.
#
# The GnuTLS is free software; you can redistribute it and/or
# modify it under the terms of the GNU Lesser General Public License
# as published by the Free Software Foundation; either version 3 of
# the License, or (at your option) any later version.
#
# This library is distributed in the hope that it will be useful, but
# WITHOUT ANY WARRANTY; without even the implied warranty of
# MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the GNU
# Lesser General Public License for more details.
#
# You should have received a copy of the GNU Lesser General Public License
# along with this program.  If not, see <http://www.gnu.org/licenses/>.
#
.text	
.globl	gnutls_cpuid
.def	gnutls_cpuid;	.scl 2;	.type 32;	.endef
.p2align	4
gnutls_cpuid:
	pushq	%rbp
	movq	%rsp,%rbp
	pushq	%rbx
	movl	%edi,-12(%rbp)
	movq	%rsi,-24(%rbp)
	movq	%rdx,-32(%rbp)
	movq	%rcx,-40(%rbp)
	movq	%r8,-48(%rbp)
	movl	-12(%rbp),%eax
	movl	%eax,-60(%rbp)
	movl	-60(%rbp),%eax
	cpuid
	movl	%edx,-56(%rbp)
	movl	%ecx,%esi
	movl	%eax,-52(%rbp)
	movq	-24(%rbp),%rax
	movl	-52(%rbp),%edx
	movl	%edx,(%rax)
	movq	-32(%rbp),%rax
	movl	%ebx,(%rax)
	movq	-40(%rbp),%rax
	movl	%esi,(%rax)
	movq	-48(%rbp),%rax
	movl	-56(%rbp),%ecx
	movl	%ecx,(%rax)
	popq	%rbx
	leave
	.byte	0xf3,0xc3

