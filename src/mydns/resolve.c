/**************************************************************************************************
	$Id: resolve.c,v 1.59 2006/01/18 20:46:47 bboy Exp $

	Copyright (C) 2002-2005  Don Moore <bboy@bboy.net>

	This program is free software; you can redistribute it and/or modify
	it under the terms of the GNU General Public License as published by
	the Free Software Foundation; either version 2 of the License, or
	(at Your option) any later version.

	This program is distributed in the hope that it will be useful,
	but WITHOUT ANY WARRANTY; without even the implied warranty of
	MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
	GNU General Public License for more details.

	You should have received a copy of the GNU General Public License
	along with this program; if not, write to the Free Software
	Foundation, Inc., 59 Temple Place, Suite 330, Boston, MA  02111-1307  USA
**************************************************************************************************/

#include "named.h"

/* Make this nonzero to enable debugging for this source file */
#define	DEBUG_RESOLVE	1

#if DEBUG_ENABLED && DEBUG_RESOLVE
/* Strings describing the datasections */
char *resolve_datasection_str[] = { "QUESTION", "ANSWER", "AUTHORITY", "ADDITIONAL" };
#endif

#if STATUS_ENABLED
extern int remote_status(TASK *t);
#endif


/**************************************************************************************************
	RESOLVE_SOA
	Adds SOA record to the specified section.  If that section is ANSWER, assume this is a SOA
	query.  Returns number of records inserted, or -1 if an error occurred.
**************************************************************************************************/
static int
resolve_soa(TASK *t, datasection_t section, char *fqdn)
{
	MYDNS_SOA *soa = find_soa(t, fqdn, NULL);

	if (soa)
	{
		t->zone = soa->id;
		t->minimum_ttl = soa->minimum;

		/* Don't cache replies for SOA with a 0 second TTL */
		if (!soa->minimum && !soa->ttl)
			t->reply_cache_ok = 0;

		/* This is a SOA request - handle things a tiny bit differently */
		if (t->qtype == DNS_QTYPE_SOA && section == ANSWER)
		{
			/* If the fqdn does not exactly match, put the SOA in AUTHORITY instead of ANSWER */
			if (strcmp(fqdn, soa->origin))
			{
				rrlist_add(t, AUTHORITY, DNS_RRTYPE_SOA, (void *)soa, soa->origin);
				t->sort_level++;
			}
			else
			{
				/* SOA in ANSWER - also add authoritative nameservers */
				rrlist_add(t, section, DNS_RRTYPE_SOA, (void *)soa, soa->origin);
				t->sort_level++;
				(void)resolve(t, AUTHORITY, DNS_QTYPE_NS, soa->origin, 0);
			}
		}
		else
		{
			rrlist_add(t, section, DNS_RRTYPE_SOA, (void *)soa, soa->origin);
			t->sort_level++;
		}

		mydns_soa_free(soa);

		if (section == ANSWER)									/* We are authoritative; Set `aa' flag */
			t->hdr.aa = 1;
		return (1);
	}
	return (section == ANSWER ? dnserror(t, DNS_RCODE_REFUSED, ERR_ZONE_NOT_FOUND) : 0);
}
/*--- resolve_soa() -----------------------------------------------------------------------------*/


/**************************************************************************************************
	CNAME_RECURSE
	If task has a dominant matching CNAME record, recurse into it.
	Returns the number of records added.
**************************************************************************************************/
static int
cname_recurse(TASK *t, datasection_t section, dns_qtype_t qtype,
				  char *fqdn, MYDNS_SOA *soa, char *label, MYDNS_RR *cname, int level)
{
	register int n;

	if (level >= MAX_CNAME_LEVEL)
		return (1);

	/* Add the CNAME record to the answer section */
	if (section == ANSWER && level)
		rrlist_add(t, ADDITIONAL, DNS_RRTYPE_RR, (void *)cname, fqdn);
	else
		rrlist_add(t, section, DNS_RRTYPE_RR, (void *)cname, fqdn);
	t->sort_level++;

	/* If the request was for CNAME records, this is the answer; we are done. */
	if (t->qtype == DNS_QTYPE_CNAME)
		return (1);

	/* Check `Cnames' list; if we are looping, stop.  Otherwise add this to the array. */
	for (n = 0; n < level; n++)
		if (t->Cnames[n] == cname->id)
		{
			/* CNAME loop: Send what we have so far and consider the resolution complete */
			Verbose("%s: %s: %s %s %s (depth %d)", desctask(t), _("CNAME loop detected"),
					cname->name, mydns_qtype_str(cname->type), cname->data, level);
			return (1);
		}
	t->Cnames[level] = cname->id;

#if DEBUG_ENABLED && DEBUG_RESOLVE
	Debug("%s: CNAME -> `%s'", desctask(t), cname->data);
#endif

	/* Resolve with this new CNAME record as the FQDN */
	return resolve(t, section, qtype, cname->data, level+1);
}
/*--- cname_recurse() ---------------------------------------------------------------------------*/


/**************************************************************************************************
	PROCESS_RR
	Process the resource record list.  Returns number of records added.
**************************************************************************************************/
static int
process_rr(TASK *t, datasection_t section, dns_qtype_t qtype, char *fqdn,
			  MYDNS_SOA *soa, char *label, MYDNS_RR *rr, int level)
{
	register MYDNS_RR *r;
	register int rv = 0;
	register int add_ns = (section == ANSWER && !t->ns.size && qtype != DNS_QTYPE_NS && qtype != DNS_QTYPE_ANY);

	t->name_ok = 1;

#if DEBUG_ENABLED && DEBUG_RESOLVE
	Debug("%s: process_rr(%s, %s, \"%s\", (%s), \"%s\", %d)",
			desctask(t), resolve_datasection_str[section], mydns_qtype_str(qtype), fqdn,
			soa->origin, label, level);
	Debug("%s: matched `%s%s%s'", desctask(t), label, *label ? "." : "", soa->origin);
#endif

	/* If the data section calls for a FQDN, and we just get a hostname, append the origin */
	for (r = rr; r; r = r->next)
		if (r->type == DNS_QTYPE_NS || r->type == DNS_QTYPE_CNAME || r->type == DNS_QTYPE_MX)
		{
			register int len = strlen(r->data);

			if (r->data[len-1] == '.')
				continue;
#if DEBUG_ENABLED && DEBUG_RESOLVE
			Debug("Appending origin (%s) to data section (%s)", soa->origin, r->data);
#endif
			if (len + strlen(soa->origin) + 1 <= DNS_MAXNAMELEN)
			{
				r->data[len] = '.';
				strcpy(r->data + len + 1, soa->origin);
			}
		}

	/* If the RR list returned contains a CNAME record, follow the CNAME. */
	for (r = rr; r; r = r->next)
		if (r->type == DNS_QTYPE_CNAME)
			return cname_recurse(t, section, qtype, fqdn, soa, label, r, level);

	/* Find RRs matching QTYPE */
	for (r = rr; r; r = r->next)
		if (r->type == qtype || qtype == DNS_QTYPE_ANY)
		{
#if ALIAS_ENABLED
			/* If the RR is an ALIAS then follow it, otherwise just add it. */
			if (r->alias)
				rv += alias_recurse(t, section, fqdn, soa, label, r);
			else
			{
				rrlist_add(t, section, DNS_RRTYPE_RR, (void *)r, fqdn);
				rv++;
			}
#else
			rrlist_add(t, section, DNS_RRTYPE_RR, (void *)r, fqdn);
			rv++;
#endif
		}
	t->sort_level++;

	/* If we found no matching RR's but there are NS records, and the name isn't empty
		or '*' (which I think is probably wrong, but...) treat as delegation -- set 'rv'
		to make the caller return, then set 'add_ns' to fill the AUTHORITY */
	if (!rv && *label && *label != '*')
		for (r = rr; !rv && r; r = r->next)
			if (r->type == DNS_QTYPE_NS)
				rv = add_ns = 1;

	/* If we found some results, go ahead and put nameserver records into AUTHORITY */
	for (r = rr; rv && r; r = r->next)
		if (r->type == DNS_QTYPE_NS && add_ns)
		{
			char ns[DNS_MAXNAMELEN+1];

			/* If the rr is for something like "*.bboy.net.", show the labelized name */
			if (r->name[0] == '*' && r->name[1] == '.' && r->name[2])
				snprintf(ns, sizeof(ns), "%s.%s", r->name+2, soa->origin);
			else if (r->name[0] && r->name[0] != '*')
				snprintf(ns, sizeof(ns), "%s.%s", r->name, soa->origin);
			else
				strncpy(ns, soa->origin, sizeof(ns)-1);

#if DEBUG_ENABLED && DEBUG_RESOLVE
			Debug("%s: Adding AUTHORITY for NS \"%s\"", desctask(t), ns);
#endif
			rrlist_add(t, AUTHORITY, DNS_RRTYPE_RR, (void *)r, ns);

			/* If the NS data is a FQDN, look in THIS zone for an A record.  That way glue
				records can be stored out of bailiwick a la BIND */
			if (LASTCHAR(r->data) == '.')
			{
				MYDNS_RR *A = find_rr(t, soa, DNS_QTYPE_A, r->data);

				if (A)
				{
					register MYDNS_RR *a;

					for (a = A; a; a = a->next)
						rrlist_add(t, ADDITIONAL, DNS_RRTYPE_RR, (void *)a, r->data);
					mydns_rr_free(A);
				}
			}
			rv++;
		}
	t->sort_level++;

	/* We DID find matches for this label; thus, reply success but with no records in the
		ANSWER section. */
	if (!rv && section == ANSWER)
	{
#if DEBUG_ENABLED && DEBUG_RESOLVE
		Debug("%s: no RRs match", desctask(t));
#endif
		if (!t->ns.size)
			rrlist_add(t, AUTHORITY, DNS_RRTYPE_SOA, (void *)soa, soa->origin);
		rv++;
		t->sort_level++;
	}

	return (rv);
}
/*--- process_rr() ------------------------------------------------------------------------------*/


/**************************************************************************************************
	ADD_AUTHORITY_NS
	Adds AUTHORITY records for any NS records that match the request.
**************************************************************************************************/
static inline void
add_authority_ns(TASK *t, datasection_t section, MYDNS_SOA *soa, char *match_label)
{
	if (!t->ns.size && section == ANSWER)
	{
		register MYDNS_RR *rr = NULL, *r = NULL;
		register char *label = NULL;

#if DEBUG_ENABLED && DEBUG_RESOLVE
		Debug("%s: add_authority_ns(%s, (%s), \"%s\")",
				desctask(t), resolve_datasection_str[section], soa->origin, match_label);
#endif
		/* Match down label by label in `label' -- include first matching NS record(s) */
		for (label = match_label; *label; label++)
		{
			if (label == match_label || *label == '.')
			{
				if (label[0] == '.' && label[1]) label++;		/* Advance past leading dot */

				/* Ignore NS records on wildcard (is that correct behavior?) */
				if (*label != '*')
				{
#if DEBUG_ENABLED && DEBUG_RESOLVE
					Debug("%s: Checking for NS (AUTHORITY) for label \"%s\" (would be glue)",
							desctask(t), label);
#endif
					if ((rr = find_rr(t, soa, DNS_QTYPE_NS, label)))
					{
						for (r = rr; r; r = r->next)
						{
							char name[DNS_MAXNAMELEN+1];

							snprintf(name, sizeof(name), "%s.%s", label, soa->origin);
							rrlist_add(t, AUTHORITY, DNS_RRTYPE_RR, (void *)r, name);
						}
						t->sort_level++;
						mydns_rr_free(rr);
#if DEBUG_ENABLED && DEBUG_RESOLVE
						Debug("%s: FOUND GLUE", desctask(t));
#endif
						return;
					}
				}
			}
		}

		/* Nothing added - try empty label */
#if DEBUG_ENABLED && DEBUG_RESOLVE
		Debug("%s: Checking for NS (AUTHORITY) for empty label", desctask(t));
#endif
		if ((rr = find_rr(t, soa, DNS_QTYPE_NS, label)))
		{
			for (r = rr; r; r = r->next)
				rrlist_add(t, AUTHORITY, DNS_RRTYPE_RR, (void *)r, soa->origin);
			t->sort_level++;
			mydns_rr_free(rr);
		}
	}
}
/*--- add_authority_ns() ------------------------------------------------------------------------*/


/**************************************************************************************************
	RESOLVE_LABEL
	Examine `label' (or a wildcard).  Add any relevant records.
	Returns nonzero if resolution is complete (because matches were found), else 0.
**************************************************************************************************/
static int
resolve_label(TASK *t, datasection_t section, dns_qtype_t qtype,
				  char *fqdn, MYDNS_SOA *soa, char *label, int full_match, int level)
{
	register MYDNS_RR *rr = NULL;
	register int rv = 0;

#if DEBUG_ENABLED && DEBUG_RESOLVE
	Debug("%s: resolve_label(%s, %s, \"%s\", (%s), \"%s\", %d, %d)",
			desctask(t), resolve_datasection_str[section], mydns_qtype_str(qtype), fqdn,
			soa->origin, label, full_match, level);
#endif

	/* Do any records match this label exactly? */
	/* Only check this if the label is the first in the list */
	if (full_match)
	{
		if ((rr = find_rr(t, soa, DNS_QTYPE_ANY, label)))
		{
			rv = process_rr(t, section, qtype, fqdn, soa, label, rr, level);
			mydns_rr_free(rr);
			add_authority_ns(t, section, soa, label);
			return (rv);
		}
	}

	/* No exact match.  If `label' isn't empty, replace the first part of the label with `*' and
		check for wildcard matches. */
	if (*label && !rv)
	{
		char wclabel[DNS_MAXNAMELEN+1], *c;

		/* Generate wildcarded label, i.e. `*.example' or maybe just `*'. */
		if (!(c = strchr(label, '.')))
			wclabel[0] = '*', wclabel[1] = '\0';
		else
			wclabel[0] = '*', strncpy(wclabel+1, c, sizeof(wclabel)-2);

		if ((rr = find_rr(t, soa, DNS_QTYPE_ANY, wclabel)))
		{
			rv = process_rr(t, section, qtype, fqdn, soa, wclabel, rr, level);
			mydns_rr_free(rr);
			add_authority_ns(t, section, soa, wclabel);
			return (rv);
		}
	}

	/* STILL no match - check for NS records for child delegation */
	if (*label && !rv && (rr = find_rr(t, soa, DNS_QTYPE_NS, label)))
	{
		rv = process_rr(t, section, qtype, fqdn, soa, label, rr, level);
		mydns_rr_free(rr);
		add_authority_ns(t, section, soa, label);
		return (rv);
	}

	return (rv);
}
/*--- resolve_label() ---------------------------------------------------------------------------*/


/**************************************************************************************************
	RESOLVE
	Resolves the specified name, storing all data found in the specified section.
	If `section' is ANSWER, this function will set an error if we lack an authoritative answer.
	Returns number of records inserted, or -1 if an error occurred.
**************************************************************************************************/
int
resolve(TASK *t, datasection_t section, dns_qtype_t qtype, char *fqdn, int level)
{
	char name[DNS_MAXNAMELEN+1];
	register MYDNS_SOA *soa;
	register int rv = 0;
	register char *label;

#if DEBUG_ENABLED && DEBUG_RESOLVE
	Debug("%s: resolve(%s, %s, \"%s\", %d)",
			desctask(t), resolve_datasection_str[section], mydns_qtype_str(qtype), fqdn, level);
#endif

#if STATUS_ENABLED
	if (t->qclass == DNS_CLASS_CHAOS)
		return remote_status(t);
#endif

	if (!axfr_enabled && t->qtype == DNS_QTYPE_AXFR)
		return dnserror(t, DNS_RCODE_REFUSED, ERR_NO_AXFR);

	/* Is the request for a SOA record only? */
	if (t->qtype == DNS_QTYPE_SOA && section == ANSWER)
		return resolve_soa(t, section, fqdn);

	/* Load SOA record for this name - if section is ANSWER and no SOA is found, we're not
		authoritative */
#if DEBUG_ENABLED && DEBUG_RESOLVE
	Debug("%s: Look up soa record for this zone", desctask(t));
#endif
	memset(name, 0, sizeof(name));
	if (!(soa = find_soa(t, fqdn, name)))
	{
		if ((section == ANSWER) && !level)
		{
			if (forward_recursive && t->hdr.rd)
				return recursive_fwd(t);
			else
				return dnserror(t, DNS_RCODE_REFUSED, ERR_ZONE_NOT_FOUND);
		}
		return 0;
	}
	t->zone = soa->id;
	t->minimum_ttl = soa->minimum;

	/* We are authoritative; Set `aa' flag */
	if (section == ANSWER)
	{
#if DEBUG_ENABLED && DEBUG_RESOLVE
		Debug("%s: We are authoritative, zone_id is %u", desctask(t), soa->id);
#endif
		t->hdr.aa = 1;
	}

	/* If the request is ANY, and `fqdn' exactly matches the origin, include SOA */
	if ((qtype == DNS_QTYPE_ANY) && (section == ANSWER) && !strcasecmp(fqdn, soa->origin))
	{
		rrlist_add(t, section, DNS_RRTYPE_SOA, (void *)soa, soa->origin);
		t->sort_level++;
	}

	/* Examine each label in the name, one at a time; look for relevant records */
#if DEBUG_ENABLED && DEBUG_RESOLVE
	Debug("%s: Examining \"%s\", label by label", desctask(t), name);
#endif
	for (label = name; ; label++)
	{
		if (label == name || *label == '.')
		{
			if (label[0] == '.' && label[1]) label++;		/* Advance past leading dot */

			/* Resolve the label; if we find records, we're done. */
			if ((rv = resolve_label(t, section, qtype, fqdn, soa, label, label == name, level)) != 0)
				break;
		}
		if (!*label)
			break;
	}
#if DEBUG_ENABLED && DEBUG_RESOLVE
	Debug("%s: Done examining \"%s\", label by label", desctask(t), name);
#endif

	/* If we got this far and there are NO records, set result and send the SOA */
	if (!level && !t->an.size && !t->ns.size && !t->ar.size)
	{
#if DEBUG_ENABLED && DEBUG_RESOLVE
		Debug("- We are authoritative, but no RRs matched; sending %s with SOA in AUTHORITY section",
				t->name_ok == 1 ? "NOERROR" : "NXDOMAIN");
#endif
		if (t->name_ok)
		{
			t->hdr.rcode = DNS_RCODE_NOERROR;
			t->reason = ERR_NONE;
		}
		else
		{
			t->hdr.rcode = DNS_RCODE_NXDOMAIN;
			t->reason = ERR_NO_MATCHING_RECORDS;
		}
		rrlist_add(t, AUTHORITY, DNS_RRTYPE_SOA, (void *)soa, soa->origin);
		t->sort_level++;
	}

	mydns_soa_free(soa);

	return (rv);
}	
/*--- resolve() ---------------------------------------------------------------------------------*/

/* vi:set ts=3: */
/* NEED_PO */
