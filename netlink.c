/*
 * Copyright (c) 2016 Fabien Siron <fabien.siron@epita.fr>
 * Copyright (c) 2016 Dmitry V. Levin <ldv@altlinux.org>
 * All rights reserved.
 *
 * Redistribution and use in source and binary forms, with or without
 * modification, are permitted provided that the following conditions
 * are met:
 * 1. Redistributions of source code must retain the above copyright
 *    notice, this list of conditions and the following disclaimer.
 * 2. Redistributions in binary form must reproduce the above copyright
 *    notice, this list of conditions and the following disclaimer in the
 *    documentation and/or other materials provided with the distribution.
 * 3. The name of the author may not be used to endorse or promote products
 *    derived from this software without specific prior written permission.
 *
 * THIS SOFTWARE IS PROVIDED BY THE AUTHOR ``AS IS'' AND ANY EXPRESS OR
 * IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE IMPLIED WARRANTIES
 * OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE ARE DISCLAIMED.
 * IN NO EVENT SHALL THE AUTHOR BE LIABLE FOR ANY DIRECT, INDIRECT,
 * INCIDENTAL, SPECIAL, EXEMPLARY, OR CONSEQUENTIAL DAMAGES (INCLUDING, BUT
 * NOT LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS OR SERVICES; LOSS OF USE,
 * DATA, OR PROFITS; OR BUSINESS INTERRUPTION) HOWEVER CAUSED AND ON ANY
 * THEORY OF LIABILITY, WHETHER IN CONTRACT, STRICT LIABILITY, OR TORT
 * (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY OUT OF THE USE OF
 * THIS SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF SUCH DAMAGE.
 */

#include "defs.h"
#include <sys/socket.h>
#include <linux/netlink.h>
#include <linux/sock_diag.h>
#include <linux/inet_diag.h>
#include <linux/rtnetlink.h>
#include <linux/xfrm.h>
#include <linux/audit.h>
#include <linux/selinux_netlink.h>
#include <linux/netfilter/nfnetlink.h>
#include "xlat/netlink_flags.h"
#include "xlat/netlink_get_flags.h"
#include "xlat/netlink_new_flags.h"
#include "xlat/netlink_types.h"
#include "xlat/netlink_protocols.h"
#include "xlat/netlink_route_types.h"
#include "xlat/netlink_sock_diag_types.h"
#include "xlat/netlink_xfrm_types.h"
#include "xlat/netlink_selinux_types.h"
#include "xlat/netlink_audit_types.h"
#include "xlat/netlink_netfilter_ids.h"

/*
 * Fetch a struct nlmsghdr from the given address.
 */
static bool
fetch_nlmsghdr(struct tcb *const tcp, struct nlmsghdr *const nlmsghdr,
	       const kernel_ulong_t addr, const kernel_ulong_t len)
{
	if (len < sizeof(struct nlmsghdr)) {
		printstrn(tcp, addr, len);
		return false;
	}

	if (umove_or_printaddr(tcp, addr, nlmsghdr))
		return false;

	return true;
}

static unsigned long
nlmsg_data(unsigned long nlh) {
	return nlh + NLMSG_LENGTH(0);
}

static void
decode_netlink_type(int type, int proto) {
	if (type < NLMSG_MIN_TYPE) {
		printxval(netlink_types, type, "NLMSG_???");
		return;
	}

	switch (proto) {
	case NETLINK_ROUTE:
		printxval(netlink_route_types, type, "RTM_???");
		break;
	case NETLINK_SOCK_DIAG:
		printxval(netlink_sock_diag_types, type, "SOCK_DIAG_???");
		break;
	case NETLINK_XFRM:
		printxval(netlink_xfrm_types, type, "XFRM_MSG_???");
		break;
	case NETLINK_AUDIT:
		printxval(netlink_audit_types, type, "AUDIT_???");
		break;
	case NETLINK_SELINUX:
		printxval(netlink_selinux_types, type, "SELNL_???");
		break;
	case NETLINK_NETFILTER:
		tprints("{");
		printxval(netlink_netfilter_ids, NFNL_SUBSYS_ID(type),
			  "NFNL_SUBSYS_???");
		tprintf(", %d}", NFNL_MSG_TYPE(type));
		break;
	default:
		tprints("???");
	}
}

static void
decode_netlink_flags(int type, int proto, unsigned flags)
{
	const char *type_s = NULL;
	if (type < NLMSG_MIN_TYPE) {
		printflags(netlink_flags, flags, "NLM_F_???");
		return;
	}

	if (proto == NETLINK_ROUTE)
		type_s = xlookup(netlink_route_types, type);
	else if (proto == NETLINK_XFRM)
		type_s = xlookup(netlink_xfrm_types, type);
	else if (proto == NETLINK_SOCK_DIAG) {
		printflags(netlink_get_flags, flags, "NLM_F_???");
		return;
	}

	if (type_s != NULL) {
		if (strstr(type_s, "GET")) {
			printflags(netlink_get_flags, flags, "NLM_F_???");
			return;
		} else if (strstr(type_s, "NEW")) {
			printflags(netlink_new_flags, flags, "NLM_F_???");
			return;
		}
	}

	printflags(netlink_flags, flags, "NLM_F_???");
}

static void
print_nlmsghdr(struct tcb *tcp, const struct nlmsghdr *const nlmsghdr, int proto)
{
	/* print the whole structure regardless of its nlmsg_len */

	tprintf("{len=%u, type=", nlmsghdr->nlmsg_len);

	decode_netlink_type(nlmsghdr->nlmsg_type, proto);

	tprints(", flags=");
	decode_netlink_flags(nlmsghdr->nlmsg_type, proto, nlmsghdr->nlmsg_flags);

	tprintf(", seq=%u, pid=%u}", nlmsghdr->nlmsg_seq,
		nlmsghdr->nlmsg_pid);
}

static void
decode_netlink_error(struct tcb *tcp, unsigned long addr, unsigned long size,
		     int proto)
{
	struct nlmsgerr err;

	if (umove_or_printaddr(tcp, addr, &err) < 0)
		return;

	tprintf(", {error=\"%s\", msg=", strerror(-err.error));

	print_nlmsghdr(tcp, &err.msg, proto);
}

static int
decode_nlmsghdr_with_payload(struct tcb *const tcp, int fd,
			     const struct nlmsghdr *const nlmsghdr,
			     const kernel_ulong_t addr,
			     const kernel_ulong_t len)
{
	int proto;

	tprints("{");
	proto = getfdnlproto(tcp, fd, netlink_protocols);
	print_nlmsghdr(tcp, nlmsghdr, proto);

	unsigned int nlmsg_len =
		nlmsghdr->nlmsg_len > len ? len : nlmsghdr->nlmsg_len;
	if (nlmsg_len > sizeof(struct nlmsghdr)) {
		unsigned long data = nlmsg_data(addr);

		if (nlmsghdr->nlmsg_type < NLMSG_MIN_TYPE) {
			switch (nlmsghdr->nlmsg_type)
			{
			case NLMSG_ERROR:
				decode_netlink_error(tcp, data,
						     nlmsghdr->nlmsg_len -
						     sizeof(nlmsghdr),
						     proto);
			case NLMSG_DONE:
				tprints("}");
				return 0;
			default:
				tprints(", ");

				printstrn(tcp, addr + sizeof(struct nlmsghdr),
					 nlmsg_len - sizeof(struct nlmsghdr));
				tprints("}");
				return 1;
			}
		}

		switch (proto)
		{
		case NETLINK_SOCK_DIAG:
			decode_netlink_sock_diag(tcp, data,
						 nlmsghdr->nlmsg_len -
						 sizeof(struct nlmsghdr),
						 nlmsghdr->nlmsg_type,
						 nlmsghdr->nlmsg_flags &
						 NLM_F_REQUEST);
			break;
		default:
			tprints(", ");

			printstrn(tcp, addr + sizeof(struct nlmsghdr),
				 nlmsg_len - sizeof(struct nlmsghdr));
		}
	}

	tprints("}");

	return 1;
}

void
decode_netlink(struct tcb *const tcp, int fd, kernel_ulong_t addr, kernel_ulong_t len)
{
	struct nlmsghdr nlmsghdr;
	bool print_array = false;
	unsigned int elt;

	for (elt = 0; fetch_nlmsghdr(tcp, &nlmsghdr, addr, len); elt++) {
		if (abbrev(tcp) && elt == max_strlen) {
			tprints("...");
			break;
		}

		unsigned int nlmsg_len = NLMSG_ALIGN(nlmsghdr.nlmsg_len);
		kernel_ulong_t next_addr = 0;
		kernel_ulong_t next_len = 0;

		if (nlmsghdr.nlmsg_len >= sizeof(struct nlmsghdr)) {
			next_len = (len >= nlmsg_len) ? len - nlmsg_len : 0;

			if (next_len && addr + nlmsg_len > addr)
				next_addr = addr + nlmsg_len;
		}

		if (!print_array && next_addr) {
			tprints("[");
			print_array = true;
		}

		if (!decode_nlmsghdr_with_payload(tcp, fd, &nlmsghdr, addr, len))
			break;

		if (!next_addr)
			break;

		tprints(", ");
		addr = next_addr;
		len = next_len;
	}

	if (print_array) {
		tprints("]");
	}
}
