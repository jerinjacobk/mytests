#include <stdio.h>
#include <stdint.h>
#include <string.h>
#include <errno.h>
#include <stdbool.h>
#include <inttypes.h>

#include "common.h"
#include "otx2_test.h"

#define FIELDS_PER_ALG  5

static inline void
print_feilds(uint64_t *field)
{
	int i;

	for (i = 0; i < FIELDS_PER_ALG; i++)
		printf("field=%"PRIx64"\n", field[i]);
}

static inline int
get_nr_feilds(struct nix_rx_flowkey_alg *alg)
{
	int i = 0, fields = 0;

	for (i = 0;  i < FIELDS_PER_ALG; i++) {
		struct nix_rx_flowkey_alg *field = &alg[i];
		if (field->ena)
			fields++;
	}

	return fields;
}

static inline int
get_last_key_offset(struct nix_rx_flowkey_alg *alg)
{
	int i = 0, key_off = 0;

	for (i = 0;  i < FIELDS_PER_ALG; i++) {
		struct nix_rx_flowkey_alg *field = &alg[i];

		if (field->ena == 0)
			continue;

		if (field->ena)
			key_off = field->key_offset;
	}

	return key_off;
}

static inline int
find_empty_feilds_in_between(struct nix_rx_flowkey_alg *alg)
{
	int rc = 0, i = 0, got_first_enabled_field = 0, got_disabled_field = 0;

	for (i = 0;  i < FIELDS_PER_ALG; i++) {
		struct nix_rx_flowkey_alg *field = &alg[i];
		if (got_first_enabled_field == 0 && field->ena)
			got_first_enabled_field = true;

		if ((got_first_enabled_field == true) && !field->ena)
			got_disabled_field = true;

		/* Got you !!! */
		if (got_first_enabled_field == true && got_disabled_field == true && field->ena)
			rc = 1;
	}

	return rc;
}

static int
result_checker(uint32_t flowkey_cfg, int expect_error,
		int expected_fields, int expected_last_key_off)
{
	int rc;
	uint64_t field[FIELDS_PER_ALG];

	rc = set_flowkey_fields((struct nix_rx_flowkey_alg *)field, flowkey_cfg);
	if (expect_error && rc == 0)
		return -EDQUOT;

	if (expect_error == 0 && rc < 0)
		return rc;

	rc = find_empty_feilds_in_between((struct nix_rx_flowkey_alg *)field);
	if (expect_error == 0 && rc)
		return rc;

	rc = get_nr_feilds((struct nix_rx_flowkey_alg *)field);
	if (expect_error == 0 && rc != expected_fields)
		return -ERANGE;

	rc = get_last_key_offset((struct nix_rx_flowkey_alg *)field);
	if (expect_error == 0 && rc != expected_last_key_off)
		return -EINVAL;

	return 0;
}

static int
PORT(void)
{
	return result_checker(FLOW_KEY_TYPE_PORT, 0, 1, 0);
}

static int
IPV4_IPV6(void)
{
	return result_checker(FLOW_KEY_TYPE_IPV4 | FLOW_KEY_TYPE_IPV6, 0, 2, 0);
}

static int
IPV4_IPV6_TCP(void)
{
	return result_checker(FLOW_KEY_TYPE_IPV4 | FLOW_KEY_TYPE_IPV6 | FLOW_KEY_TYPE_TCP, 0, 3, 32);
}

static int
IPV4_IPV6_UDP(void)
{
	return result_checker(FLOW_KEY_TYPE_IPV4 | FLOW_KEY_TYPE_IPV6 | FLOW_KEY_TYPE_UDP, 0, 3, 32);
}

static int
IPV4_IPV6_SCTP(void)
{
	return result_checker(FLOW_KEY_TYPE_IPV4 | FLOW_KEY_TYPE_IPV6 | FLOW_KEY_TYPE_SCTP, 0, 3, 32);
}

static int
IPV4_IPV6_TCP_UDP(void)
{
	return result_checker(FLOW_KEY_TYPE_IPV4 | FLOW_KEY_TYPE_IPV6 | FLOW_KEY_TYPE_TCP | FLOW_KEY_TYPE_UDP, 0, 3, 32);
}

static int
IPV4_IPV6_TCP_SCTP(void)
{
	return result_checker(FLOW_KEY_TYPE_IPV4 | FLOW_KEY_TYPE_IPV6 | FLOW_KEY_TYPE_TCP | FLOW_KEY_TYPE_SCTP, 0, 3, 32);
}

static int
IPV4_IPV6_UDP_SCTP(void)
{
	return result_checker(FLOW_KEY_TYPE_IPV4 | FLOW_KEY_TYPE_IPV6 | FLOW_KEY_TYPE_UDP | FLOW_KEY_TYPE_SCTP, 0, 3, 32);
}

static int
IPV4_IPV6_TCP_UDP_SCTP(void)
{
	return result_checker(FLOW_KEY_TYPE_IPV4 | FLOW_KEY_TYPE_IPV6 | FLOW_KEY_TYPE_TCP | FLOW_KEY_TYPE_UDP | FLOW_KEY_TYPE_SCTP, 0, 3, 32);
}

static int
IPV4_IPV6_TCP_UDP_NVGRE(void)
{
	return result_checker(FLOW_KEY_TYPE_IPV4 | FLOW_KEY_TYPE_IPV6 | FLOW_KEY_TYPE_TCP | FLOW_KEY_TYPE_UDP | FLOW_KEY_TYPE_NVGRE, 0, 4, 36);
}

static int
PORT_IPV4_IPV6_TCP_UDP_NVGRE(void)
{
	return result_checker( FLOW_KEY_TYPE_PORT | FLOW_KEY_TYPE_IPV4 | FLOW_KEY_TYPE_IPV6 | FLOW_KEY_TYPE_TCP | FLOW_KEY_TYPE_UDP | FLOW_KEY_TYPE_NVGRE, 1, 5, 42);
}

static int
NVGRE_VXLAN_GENEVE(void)
{
	return result_checker(FLOW_KEY_TYPE_NVGRE | FLOW_KEY_TYPE_VXLAN | FLOW_KEY_TYPE_GENEVE, 0, 3, 6);
}

static int
PORT_NVGRE_VXLAN_GENEVE(void)
{
	return result_checker(FLOW_KEY_TYPE_PORT | FLOW_KEY_TYPE_NVGRE | FLOW_KEY_TYPE_VXLAN | FLOW_KEY_TYPE_GENEVE, 0, 4, 8);
}

static int
PORT_IPV4_IPV6_TCP_UDP_SCTP_NVGRE_VXLAN_GENEVE(void)
{
	return result_checker(FLOW_KEY_TYPE_PORT|
			      FLOW_KEY_TYPE_IPV4|FLOW_KEY_TYPE_IPV6|
			      FLOW_KEY_TYPE_TCP|FLOW_KEY_TYPE_UDP|
			      FLOW_KEY_TYPE_SCTP|FLOW_KEY_TYPE_NVGRE|
			      FLOW_KEY_TYPE_VXLAN|FLOW_KEY_TYPE_GENEVE,
			      1, 7, 44); //[1ff], fail
}

static int
IPV4_IPV6_TCP_UDP_SCTP_NVGRE_VXLAN_GENEVE(void)
{
	return result_checker(FLOW_KEY_TYPE_IPV4|
			      FLOW_KEY_TYPE_IPV6|FLOW_KEY_TYPE_TCP|
			      FLOW_KEY_TYPE_UDP|FLOW_KEY_TYPE_SCTP|
			      FLOW_KEY_TYPE_NVGRE|FLOW_KEY_TYPE_VXLAN|
			      FLOW_KEY_TYPE_GENEVE,
			      1, 6, 42); //[1fe], fail
}

static int
PORT_IPV6_TCP_UDP_SCTP_NVGRE_VXLAN_GENEVE(void)
{
	return result_checker(FLOW_KEY_TYPE_PORT|
			      FLOW_KEY_TYPE_IPV6|FLOW_KEY_TYPE_TCP|
			      FLOW_KEY_TYPE_UDP|FLOW_KEY_TYPE_SCTP|
			      FLOW_KEY_TYPE_NVGRE|FLOW_KEY_TYPE_VXLAN|
			      FLOW_KEY_TYPE_GENEVE,
			      1, 5, 42); //[1fd], fail
}

static int
IPV6_TCP_UDP_SCTP_NVGRE_VXLAN_GENEVE(void)
{
	return result_checker(FLOW_KEY_TYPE_IPV6|
			      FLOW_KEY_TYPE_TCP|FLOW_KEY_TYPE_UDP|
			      FLOW_KEY_TYPE_SCTP|FLOW_KEY_TYPE_NVGRE|
			      FLOW_KEY_TYPE_VXLAN|FLOW_KEY_TYPE_GENEVE,
			      1, 5, 42); //[1fc], fail
}

static int
PORT_IPV4_TCP_UDP_SCTP_NVGRE_VXLAN_GENEVE(void)
{
	return result_checker(FLOW_KEY_TYPE_PORT|
			      FLOW_KEY_TYPE_IPV4|FLOW_KEY_TYPE_TCP|
			      FLOW_KEY_TYPE_UDP|FLOW_KEY_TYPE_SCTP|
			      FLOW_KEY_TYPE_NVGRE|FLOW_KEY_TYPE_VXLAN|
			      FLOW_KEY_TYPE_GENEVE,
			      1, 5, 42); //[1fb], fail
}

static int
IPV4_TCP_UDP_SCTP_NVGRE_VXLAN_GENEVE(void)
{
	return result_checker(FLOW_KEY_TYPE_IPV4|
			      FLOW_KEY_TYPE_TCP|FLOW_KEY_TYPE_UDP|
			      FLOW_KEY_TYPE_SCTP|FLOW_KEY_TYPE_NVGRE|
			      FLOW_KEY_TYPE_VXLAN|FLOW_KEY_TYPE_GENEVE,
			      0, 5, 18); //[1fa], would pass!!
}

static int
PORT_TCP_UDP_SCTP_NVGRE_VXLAN_GENEVE(void)
{
	return result_checker(FLOW_KEY_TYPE_PORT|
			      FLOW_KEY_TYPE_TCP|FLOW_KEY_TYPE_UDP|
			      FLOW_KEY_TYPE_SCTP|FLOW_KEY_TYPE_NVGRE|
			      FLOW_KEY_TYPE_VXLAN|FLOW_KEY_TYPE_GENEVE,
			      0, 5, 12); //[1f9], would pass!!
}

static int
TCP_UDP_SCTP_NVGRE_VXLAN_GENEVE(void)
{
	return result_checker(FLOW_KEY_TYPE_TCP|
			      FLOW_KEY_TYPE_UDP|FLOW_KEY_TYPE_SCTP|
			      FLOW_KEY_TYPE_NVGRE|FLOW_KEY_TYPE_VXLAN|
			      FLOW_KEY_TYPE_GENEVE,
			      0, 4, 10); //[1f8], would pass!!
}

static int
PORT_IPV4_IPV6_UDP_SCTP_NVGRE_VXLAN_GENEVE(void)
{
	return result_checker(FLOW_KEY_TYPE_PORT|
			      FLOW_KEY_TYPE_IPV4|FLOW_KEY_TYPE_IPV6|
			      FLOW_KEY_TYPE_UDP|FLOW_KEY_TYPE_SCTP|
			      FLOW_KEY_TYPE_NVGRE|FLOW_KEY_TYPE_VXLAN|
			      FLOW_KEY_TYPE_GENEVE,
			      1, 7, 44); //[1f7], fail
}

static int
IPV4_IPV6_UDP_SCTP_NVGRE_VXLAN_GENEVE(void)
{
	return result_checker(FLOW_KEY_TYPE_IPV4|
			      FLOW_KEY_TYPE_IPV6|FLOW_KEY_TYPE_UDP|
			      FLOW_KEY_TYPE_SCTP|FLOW_KEY_TYPE_NVGRE|
			      FLOW_KEY_TYPE_VXLAN|FLOW_KEY_TYPE_GENEVE,
			      1, 6, 42); //[1f6], fail
}

static int
PORT_IPV6_UDP_SCTP_NVGRE_VXLAN_GENEVE(void)
{
	return result_checker(FLOW_KEY_TYPE_PORT|
			      FLOW_KEY_TYPE_IPV6|FLOW_KEY_TYPE_UDP|
			      FLOW_KEY_TYPE_SCTP|FLOW_KEY_TYPE_NVGRE|
			      FLOW_KEY_TYPE_VXLAN|FLOW_KEY_TYPE_GENEVE,
			      1, 6, 44); //[1f5], fail
}

static int
IPV6_UDP_SCTP_NVGRE_VXLAN_GENEVE(void)
{
	return result_checker(FLOW_KEY_TYPE_IPV6|
			      FLOW_KEY_TYPE_UDP|FLOW_KEY_TYPE_SCTP|
			      FLOW_KEY_TYPE_NVGRE|FLOW_KEY_TYPE_VXLAN|
			      FLOW_KEY_TYPE_GENEVE,
			      1, 5, 42); //[1f4], fail
}

static int
PORT_IPV4_UDP_SCTP_NVGRE_VXLAN_GENEVE(void)
{
	return result_checker(FLOW_KEY_TYPE_PORT|
			      FLOW_KEY_TYPE_IPV4|FLOW_KEY_TYPE_UDP|
			      FLOW_KEY_TYPE_SCTP|FLOW_KEY_TYPE_NVGRE|
			      FLOW_KEY_TYPE_VXLAN|FLOW_KEY_TYPE_GENEVE,
			      1, 6, 20); //[1f3], fail
}

static int
IPV4_UDP_SCTP_NVGRE_VXLAN_GENEVE(void)
{
	return result_checker(FLOW_KEY_TYPE_IPV4|
			      FLOW_KEY_TYPE_UDP|FLOW_KEY_TYPE_SCTP|
			      FLOW_KEY_TYPE_NVGRE|FLOW_KEY_TYPE_VXLAN|
			      FLOW_KEY_TYPE_GENEVE,
			      0, 5, 18); //[1f2], would pass!!
}

static int
PORT_UDP_SCTP_NVGRE_VXLAN_GENEVE(void)
{
	return result_checker(FLOW_KEY_TYPE_PORT|
			      FLOW_KEY_TYPE_UDP|FLOW_KEY_TYPE_SCTP|
			      FLOW_KEY_TYPE_NVGRE|FLOW_KEY_TYPE_VXLAN|
			      FLOW_KEY_TYPE_GENEVE,
			      0, 5, 12); //[1f1], would pass!!
}

static int
UDP_SCTP_NVGRE_VXLAN_GENEVE(void)
{
	return result_checker(FLOW_KEY_TYPE_UDP|
			      FLOW_KEY_TYPE_SCTP|FLOW_KEY_TYPE_NVGRE|
			      FLOW_KEY_TYPE_VXLAN|FLOW_KEY_TYPE_GENEVE,
			      0, 4, 10); //[1f0], would pass!!
}

static int
PORT_IPV4_IPV6_TCP_SCTP_NVGRE_VXLAN_GENEVE(void)
{
	return result_checker(FLOW_KEY_TYPE_PORT|
			      FLOW_KEY_TYPE_IPV4|FLOW_KEY_TYPE_IPV6|
			      FLOW_KEY_TYPE_TCP|FLOW_KEY_TYPE_SCTP|
			      FLOW_KEY_TYPE_NVGRE|FLOW_KEY_TYPE_VXLAN|
			      FLOW_KEY_TYPE_GENEVE,
			      1, 7, 44); //[1ef], fail
}

static int
IPV4_IPV6_TCP_SCTP_NVGRE_VXLAN_GENEVE(void)
{
	return result_checker(FLOW_KEY_TYPE_IPV4|
			      FLOW_KEY_TYPE_IPV6|FLOW_KEY_TYPE_TCP|
			      FLOW_KEY_TYPE_SCTP|FLOW_KEY_TYPE_NVGRE|
			      FLOW_KEY_TYPE_VXLAN|FLOW_KEY_TYPE_GENEVE,
			      1, 6, 42); //[1ee], fail
}

static int
PORT_IPV6_TCP_SCTP_NVGRE_VXLAN_GENEVE(void)
{
	return result_checker(FLOW_KEY_TYPE_PORT|
			      FLOW_KEY_TYPE_IPV6|FLOW_KEY_TYPE_TCP|
			      FLOW_KEY_TYPE_SCTP|FLOW_KEY_TYPE_NVGRE|
			      FLOW_KEY_TYPE_VXLAN|FLOW_KEY_TYPE_GENEVE,
			      1, 6, 44); //[1ed], fail
}

static int
IPV6_TCP_SCTP_NVGRE_VXLAN_GENEVE(void)
{
	return result_checker(FLOW_KEY_TYPE_IPV6|
			      FLOW_KEY_TYPE_TCP|FLOW_KEY_TYPE_SCTP|
			      FLOW_KEY_TYPE_NVGRE|FLOW_KEY_TYPE_VXLAN|
			      FLOW_KEY_TYPE_GENEVE,
			      1, 5, 42); //[1ec], fail
}

static int
PORT_IPV4_TCP_SCTP_NVGRE_VXLAN_GENEVE(void)
{
	return result_checker(FLOW_KEY_TYPE_PORT|
			      FLOW_KEY_TYPE_IPV4|FLOW_KEY_TYPE_TCP|
			      FLOW_KEY_TYPE_SCTP|FLOW_KEY_TYPE_NVGRE|
			      FLOW_KEY_TYPE_VXLAN|FLOW_KEY_TYPE_GENEVE,
			      1, 6, 20); //[1eb], fail
}

static int
IPV4_TCP_SCTP_NVGRE_VXLAN_GENEVE(void)
{
	return result_checker(FLOW_KEY_TYPE_IPV4|
			      FLOW_KEY_TYPE_TCP|FLOW_KEY_TYPE_SCTP|
			      FLOW_KEY_TYPE_NVGRE|FLOW_KEY_TYPE_VXLAN|
			      FLOW_KEY_TYPE_GENEVE,
			      0, 5, 18); //[1ea], would pass!!
}

static int
PORT_TCP_SCTP_NVGRE_VXLAN_GENEVE(void)
{
	return result_checker(FLOW_KEY_TYPE_PORT|
			      FLOW_KEY_TYPE_TCP|FLOW_KEY_TYPE_SCTP|
			      FLOW_KEY_TYPE_NVGRE|FLOW_KEY_TYPE_VXLAN|
			      FLOW_KEY_TYPE_GENEVE,
			      0, 5, 12); //[1e9], would pass!!
}

static int
TCP_SCTP_NVGRE_VXLAN_GENEVE(void)
{
	return result_checker(FLOW_KEY_TYPE_TCP|
			      FLOW_KEY_TYPE_SCTP|FLOW_KEY_TYPE_NVGRE|
			      FLOW_KEY_TYPE_VXLAN|FLOW_KEY_TYPE_GENEVE,
			      0, 4, 10); //[1e8], would pass!!
}

static int
PORT_IPV4_IPV6_SCTP_NVGRE_VXLAN_GENEVE(void)
{
	return result_checker(FLOW_KEY_TYPE_PORT|
			      FLOW_KEY_TYPE_IPV4|FLOW_KEY_TYPE_IPV6|
			      FLOW_KEY_TYPE_SCTP|FLOW_KEY_TYPE_NVGRE|
			      FLOW_KEY_TYPE_VXLAN|FLOW_KEY_TYPE_GENEVE,
			      1, 7, 44); //[1e7], fail
}

static int
IPV4_IPV6_SCTP_NVGRE_VXLAN_GENEVE(void)
{
	return result_checker(FLOW_KEY_TYPE_IPV4|
			      FLOW_KEY_TYPE_IPV6|FLOW_KEY_TYPE_SCTP|
			      FLOW_KEY_TYPE_NVGRE|FLOW_KEY_TYPE_VXLAN|
			      FLOW_KEY_TYPE_GENEVE,
			      1, 6, 42); //[1e6], fail
}

static int
PORT_IPV6_SCTP_NVGRE_VXLAN_GENEVE(void)
{
	return result_checker(FLOW_KEY_TYPE_PORT|
			      FLOW_KEY_TYPE_IPV6|FLOW_KEY_TYPE_SCTP|
			      FLOW_KEY_TYPE_NVGRE|FLOW_KEY_TYPE_VXLAN|
			      FLOW_KEY_TYPE_GENEVE,
			      1, 6, 44); //[1e5], fail
}

static int
IPV6_SCTP_NVGRE_VXLAN_GENEVE(void)
{
	return result_checker(FLOW_KEY_TYPE_IPV6|
			      FLOW_KEY_TYPE_SCTP|FLOW_KEY_TYPE_NVGRE|
			      FLOW_KEY_TYPE_VXLAN|FLOW_KEY_TYPE_GENEVE,
			      1, 5, 42); //[1e4], fail
}

static int
PORT_IPV4_SCTP_NVGRE_VXLAN_GENEVE(void)
{
	return result_checker(FLOW_KEY_TYPE_PORT|
			      FLOW_KEY_TYPE_IPV4|FLOW_KEY_TYPE_SCTP|
			      FLOW_KEY_TYPE_NVGRE|FLOW_KEY_TYPE_VXLAN|
			      FLOW_KEY_TYPE_GENEVE,
			      1, 6, 20); //[1e3], fail
}

static int
IPV4_SCTP_NVGRE_VXLAN_GENEVE(void)
{
	return result_checker(FLOW_KEY_TYPE_IPV4|
			      FLOW_KEY_TYPE_SCTP|FLOW_KEY_TYPE_NVGRE|
			      FLOW_KEY_TYPE_VXLAN|FLOW_KEY_TYPE_GENEVE,
			      0, 5, 18); //[1e2], would pass!!
}

static int
PORT_SCTP_NVGRE_VXLAN_GENEVE(void)
{
	return result_checker(FLOW_KEY_TYPE_PORT|
			      FLOW_KEY_TYPE_SCTP|FLOW_KEY_TYPE_NVGRE|
			      FLOW_KEY_TYPE_VXLAN|FLOW_KEY_TYPE_GENEVE,
			      0, 5, 12); //[1e1], would pass!!
}

static int
SCTP_NVGRE_VXLAN_GENEVE(void)
{
	return result_checker(FLOW_KEY_TYPE_SCTP|
			      FLOW_KEY_TYPE_NVGRE|FLOW_KEY_TYPE_VXLAN|
			      FLOW_KEY_TYPE_GENEVE,
			      0, 4, 10); //[1e0], would pass!!
}

static int
PORT_IPV4_IPV6_TCP_UDP_NVGRE_VXLAN_GENEVE(void)
{
	return result_checker(FLOW_KEY_TYPE_PORT|
			      FLOW_KEY_TYPE_IPV4|FLOW_KEY_TYPE_IPV6|
			      FLOW_KEY_TYPE_TCP|FLOW_KEY_TYPE_UDP|
			      FLOW_KEY_TYPE_NVGRE|FLOW_KEY_TYPE_VXLAN|
			      FLOW_KEY_TYPE_GENEVE,
			      1, 7, 44); //[1df], fail
}

static int
IPV4_IPV6_TCP_UDP_NVGRE_VXLAN_GENEVE(void)
{
	return result_checker(FLOW_KEY_TYPE_IPV4|
			      FLOW_KEY_TYPE_IPV6|FLOW_KEY_TYPE_TCP|
			      FLOW_KEY_TYPE_UDP|FLOW_KEY_TYPE_NVGRE|
			      FLOW_KEY_TYPE_VXLAN|FLOW_KEY_TYPE_GENEVE,
			      1, 6, 42); //[1de], fail
}

static int
PORT_IPV6_TCP_UDP_NVGRE_VXLAN_GENEVE(void)
{
	return result_checker(FLOW_KEY_TYPE_PORT|
			      FLOW_KEY_TYPE_IPV6|FLOW_KEY_TYPE_TCP|
			      FLOW_KEY_TYPE_UDP|FLOW_KEY_TYPE_NVGRE|
			      FLOW_KEY_TYPE_VXLAN|FLOW_KEY_TYPE_GENEVE,
			      1, 6, 44); //[1dd], fail
}

static int
IPV6_TCP_UDP_NVGRE_VXLAN_GENEVE(void)
{
	return result_checker(FLOW_KEY_TYPE_IPV6|
			      FLOW_KEY_TYPE_TCP|FLOW_KEY_TYPE_UDP|
			      FLOW_KEY_TYPE_NVGRE|FLOW_KEY_TYPE_VXLAN|
			      FLOW_KEY_TYPE_GENEVE,
			      1, 5, 42); //[1dc], fail
}

static int
PORT_IPV4_TCP_UDP_NVGRE_VXLAN_GENEVE(void)
{
	return result_checker(FLOW_KEY_TYPE_PORT|
			      FLOW_KEY_TYPE_IPV4|FLOW_KEY_TYPE_TCP|
			      FLOW_KEY_TYPE_UDP|FLOW_KEY_TYPE_NVGRE|
			      FLOW_KEY_TYPE_VXLAN|FLOW_KEY_TYPE_GENEVE,
			      1, 6, 20); //[1db], fail
}

static int
IPV4_TCP_UDP_NVGRE_VXLAN_GENEVE(void)
{
	return result_checker(FLOW_KEY_TYPE_IPV4|
			      FLOW_KEY_TYPE_TCP|FLOW_KEY_TYPE_UDP|
			      FLOW_KEY_TYPE_NVGRE|FLOW_KEY_TYPE_VXLAN|
			      FLOW_KEY_TYPE_GENEVE,
			      0, 5, 18); //[1da], would pass!!
}

static int
PORT_TCP_UDP_NVGRE_VXLAN_GENEVE(void)
{
	return result_checker(FLOW_KEY_TYPE_PORT|
			      FLOW_KEY_TYPE_TCP|FLOW_KEY_TYPE_UDP|
			      FLOW_KEY_TYPE_NVGRE|FLOW_KEY_TYPE_VXLAN|
			      FLOW_KEY_TYPE_GENEVE,
			      0, 5, 12); //[1d9], would pass!!
}

static int
TCP_UDP_NVGRE_VXLAN_GENEVE(void)
{
	return result_checker(FLOW_KEY_TYPE_TCP|
			      FLOW_KEY_TYPE_UDP|FLOW_KEY_TYPE_NVGRE|
			      FLOW_KEY_TYPE_VXLAN|FLOW_KEY_TYPE_GENEVE,
			      0, 4, 10); //[1d8], would pass!!
}

static int
PORT_IPV4_IPV6_UDP_NVGRE_VXLAN_GENEVE(void)
{
	return result_checker(FLOW_KEY_TYPE_PORT|
			      FLOW_KEY_TYPE_IPV4|FLOW_KEY_TYPE_IPV6|
			      FLOW_KEY_TYPE_UDP|FLOW_KEY_TYPE_NVGRE|
			      FLOW_KEY_TYPE_VXLAN|FLOW_KEY_TYPE_GENEVE,
			      1, 7, 44); //[1d7], fail
}

static int
IPV4_IPV6_UDP_NVGRE_VXLAN_GENEVE(void)
{
	return result_checker(FLOW_KEY_TYPE_IPV4|
			      FLOW_KEY_TYPE_IPV6|FLOW_KEY_TYPE_UDP|
			      FLOW_KEY_TYPE_NVGRE|FLOW_KEY_TYPE_VXLAN|
			      FLOW_KEY_TYPE_GENEVE,
			      1, 6, 42); //[1d6], fail
}

static int
PORT_IPV6_UDP_NVGRE_VXLAN_GENEVE(void)
{
	return result_checker(FLOW_KEY_TYPE_PORT|
			      FLOW_KEY_TYPE_IPV6|FLOW_KEY_TYPE_UDP|
			      FLOW_KEY_TYPE_NVGRE|FLOW_KEY_TYPE_VXLAN|
			      FLOW_KEY_TYPE_GENEVE,
			      1, 6, 44); //[1d5], fail
}

static int
IPV6_UDP_NVGRE_VXLAN_GENEVE(void)
{
	return result_checker(FLOW_KEY_TYPE_IPV6|
			      FLOW_KEY_TYPE_UDP|FLOW_KEY_TYPE_NVGRE|
			      FLOW_KEY_TYPE_VXLAN|FLOW_KEY_TYPE_GENEVE,
			      1, 6, 42); //[1d4], fail
}

static int
PORT_IPV4_UDP_NVGRE_VXLAN_GENEVE(void)
{
	return result_checker(FLOW_KEY_TYPE_PORT|
			      FLOW_KEY_TYPE_IPV4|FLOW_KEY_TYPE_UDP|
			      FLOW_KEY_TYPE_NVGRE|FLOW_KEY_TYPE_VXLAN|
			      FLOW_KEY_TYPE_GENEVE,
			      1, 6, 20); //[1d3], fail
}

static int
IPV4_UDP_NVGRE_VXLAN_GENEVE(void)
{
	return result_checker(FLOW_KEY_TYPE_IPV4|
			      FLOW_KEY_TYPE_UDP|FLOW_KEY_TYPE_NVGRE|
			      FLOW_KEY_TYPE_VXLAN|FLOW_KEY_TYPE_GENEVE,
			      0, 5, 18); //[1d2], would pass!!
}

static int
PORT_UDP_NVGRE_VXLAN_GENEVE(void)
{
	return result_checker(FLOW_KEY_TYPE_PORT|
			      FLOW_KEY_TYPE_UDP|FLOW_KEY_TYPE_NVGRE|
			      FLOW_KEY_TYPE_VXLAN|FLOW_KEY_TYPE_GENEVE,
			      0, 5, 12); //[1d1], would pass!!
}

static int
UDP_NVGRE_VXLAN_GENEVE(void)
{
	return result_checker(FLOW_KEY_TYPE_UDP|
			      FLOW_KEY_TYPE_NVGRE|FLOW_KEY_TYPE_VXLAN|
			      FLOW_KEY_TYPE_GENEVE,
			      0, 4, 10); //[1d0], would pass!!
}

static int
PORT_IPV4_IPV6_TCP_NVGRE_VXLAN_GENEVE(void)
{
	return result_checker(FLOW_KEY_TYPE_PORT|
			      FLOW_KEY_TYPE_IPV4|FLOW_KEY_TYPE_IPV6|
			      FLOW_KEY_TYPE_TCP|FLOW_KEY_TYPE_NVGRE|
			      FLOW_KEY_TYPE_VXLAN|FLOW_KEY_TYPE_GENEVE,
			      1, 7, 44); //[1cf], fail
}

static int
IPV4_IPV6_TCP_NVGRE_VXLAN_GENEVE(void)
{
	return result_checker(FLOW_KEY_TYPE_IPV4|
			      FLOW_KEY_TYPE_IPV6|FLOW_KEY_TYPE_TCP|
			      FLOW_KEY_TYPE_NVGRE|FLOW_KEY_TYPE_VXLAN|
			      FLOW_KEY_TYPE_GENEVE,
			      1, 6, 42); //[1ce], fail
}

static int
PORT_IPV6_TCP_NVGRE_VXLAN_GENEVE(void)
{
	return result_checker(FLOW_KEY_TYPE_PORT|
			      FLOW_KEY_TYPE_IPV6|FLOW_KEY_TYPE_TCP|
			      FLOW_KEY_TYPE_NVGRE|FLOW_KEY_TYPE_VXLAN|
			      FLOW_KEY_TYPE_GENEVE,
			      1, 6, 44); //[1cd], fail
}

static int
IPV6_TCP_NVGRE_VXLAN_GENEVE(void)
{
	return result_checker(FLOW_KEY_TYPE_IPV6|
			      FLOW_KEY_TYPE_TCP|FLOW_KEY_TYPE_NVGRE|
			      FLOW_KEY_TYPE_VXLAN|FLOW_KEY_TYPE_GENEVE,
			      1, 5, 42); //[1cc], fail
}

static int
PORT_IPV4_TCP_NVGRE_VXLAN_GENEVE(void)
{
	return result_checker(FLOW_KEY_TYPE_PORT|
			      FLOW_KEY_TYPE_IPV4|FLOW_KEY_TYPE_TCP|
			      FLOW_KEY_TYPE_NVGRE|FLOW_KEY_TYPE_VXLAN|
			      FLOW_KEY_TYPE_GENEVE,
			      1, 6, 20); //[1cb], fail
}

static int
IPV4_TCP_NVGRE_VXLAN_GENEVE(void)
{
	return result_checker(FLOW_KEY_TYPE_IPV4|
			      FLOW_KEY_TYPE_TCP|FLOW_KEY_TYPE_NVGRE|
			      FLOW_KEY_TYPE_VXLAN|FLOW_KEY_TYPE_GENEVE,
			      0, 5, 18); //[1ca], would pass!!
}

static int
PORT_TCP_NVGRE_VXLAN_GENEVE(void)
{
	return result_checker(FLOW_KEY_TYPE_PORT|
			      FLOW_KEY_TYPE_TCP|FLOW_KEY_TYPE_NVGRE|
			      FLOW_KEY_TYPE_VXLAN|FLOW_KEY_TYPE_GENEVE,
			      0, 5, 12); //[1c9], would pass!!
}

static int
TCP_NVGRE_VXLAN_GENEVE(void)
{
	return result_checker(FLOW_KEY_TYPE_TCP|
			      FLOW_KEY_TYPE_NVGRE|FLOW_KEY_TYPE_VXLAN|
			      FLOW_KEY_TYPE_GENEVE,
			      0, 4, 10); //[1c8], would pass!!
}

static int
PORT_IPV4_IPV6_NVGRE_VXLAN_GENEVE(void)
{
	return result_checker(FLOW_KEY_TYPE_PORT|
			      FLOW_KEY_TYPE_IPV4|FLOW_KEY_TYPE_IPV6|
			      FLOW_KEY_TYPE_NVGRE|FLOW_KEY_TYPE_VXLAN|
			      FLOW_KEY_TYPE_GENEVE,
			      1, 6, 40); //[1c7], fail
}

static int
IPV4_IPV6_NVGRE_VXLAN_GENEVE(void)
{
	return result_checker(FLOW_KEY_TYPE_IPV4|
			      FLOW_KEY_TYPE_IPV6|FLOW_KEY_TYPE_NVGRE|
			      FLOW_KEY_TYPE_VXLAN|FLOW_KEY_TYPE_GENEVE,
			      1, 5, 38); //[1c6], fail
}

static int
PORT_IPV6_NVGRE_VXLAN_GENEVE(void)
{
	return result_checker(FLOW_KEY_TYPE_PORT|
			      FLOW_KEY_TYPE_IPV6|FLOW_KEY_TYPE_NVGRE|
			      FLOW_KEY_TYPE_VXLAN|FLOW_KEY_TYPE_GENEVE,
			      1, 5, 40); //[1c5], fail
}

static int
IPV6_NVGRE_VXLAN_GENEVE(void)
{
	return result_checker(FLOW_KEY_TYPE_IPV6|
			      FLOW_KEY_TYPE_NVGRE|FLOW_KEY_TYPE_VXLAN|
			      FLOW_KEY_TYPE_GENEVE,
			      1, 5, 38); //[1c4], fail
}

static int
PORT_IPV4_NVGRE_VXLAN_GENEVE(void)
{
	return result_checker(FLOW_KEY_TYPE_PORT|
			      FLOW_KEY_TYPE_IPV4|FLOW_KEY_TYPE_NVGRE|
			      FLOW_KEY_TYPE_VXLAN|FLOW_KEY_TYPE_GENEVE,
			      0, 5, 16); //[1c3], would pass!!
}

static int
IPV4_NVGRE_VXLAN_GENEVE(void)
{
	return result_checker(FLOW_KEY_TYPE_IPV4|
			      FLOW_KEY_TYPE_NVGRE|FLOW_KEY_TYPE_VXLAN|
			      FLOW_KEY_TYPE_GENEVE,
			      0, 4, 14); //[1c2], would pass!!
}

static int
PORT_IPV4_IPV6_TCP_UDP_SCTP_VXLAN_GENEVE(void)
{
	return result_checker(FLOW_KEY_TYPE_PORT|
			      FLOW_KEY_TYPE_IPV4|FLOW_KEY_TYPE_IPV6|
			      FLOW_KEY_TYPE_TCP|FLOW_KEY_TYPE_UDP|
			      FLOW_KEY_TYPE_SCTP|FLOW_KEY_TYPE_VXLAN|
			      FLOW_KEY_TYPE_GENEVE,
			      1, 6, 41); //[1bf], fail
}

static int
IPV4_IPV6_TCP_UDP_SCTP_VXLAN_GENEVE(void)
{
	return result_checker(FLOW_KEY_TYPE_IPV4|
			      FLOW_KEY_TYPE_IPV6|FLOW_KEY_TYPE_TCP|
			      FLOW_KEY_TYPE_UDP|FLOW_KEY_TYPE_SCTP|
			      FLOW_KEY_TYPE_VXLAN|FLOW_KEY_TYPE_GENEVE,
			      1, 5, 39); //[1be], fail
}

static int
PORT_IPV6_TCP_UDP_SCTP_VXLAN_GENEVE(void)
{
	return result_checker(FLOW_KEY_TYPE_PORT|
			      FLOW_KEY_TYPE_IPV6|FLOW_KEY_TYPE_TCP|
			      FLOW_KEY_TYPE_UDP|FLOW_KEY_TYPE_SCTP|
			      FLOW_KEY_TYPE_VXLAN|FLOW_KEY_TYPE_GENEVE,
			      1, 5, 41); //[1bd], fail
}

static int
IPV6_TCP_UDP_SCTP_VXLAN_GENEVE(void)
{
	return result_checker(FLOW_KEY_TYPE_IPV6|
			      FLOW_KEY_TYPE_TCP|FLOW_KEY_TYPE_UDP|
			      FLOW_KEY_TYPE_SCTP|FLOW_KEY_TYPE_VXLAN|
			      FLOW_KEY_TYPE_GENEVE,
			      1, 4, 39); //[1bc], fail
}

static int
PORT_IPV4_TCP_UDP_SCTP_VXLAN_GENEVE(void)
{
	return result_checker(FLOW_KEY_TYPE_PORT|
			      FLOW_KEY_TYPE_IPV4|FLOW_KEY_TYPE_TCP|
			      FLOW_KEY_TYPE_UDP|FLOW_KEY_TYPE_SCTP|
			      FLOW_KEY_TYPE_VXLAN|FLOW_KEY_TYPE_GENEVE,
			      0, 5, 17); //[1bb], would pass!!
}

static int
IPV4_TCP_UDP_SCTP_VXLAN_GENEVE(void)
{
	return result_checker(FLOW_KEY_TYPE_IPV4|
			      FLOW_KEY_TYPE_TCP|FLOW_KEY_TYPE_UDP|
			      FLOW_KEY_TYPE_SCTP|FLOW_KEY_TYPE_VXLAN|
			      FLOW_KEY_TYPE_GENEVE,
			      0, 4, 15); //[1ba], would pass!!
}

static int
PORT_TCP_UDP_SCTP_VXLAN_GENEVE(void)
{
	return result_checker(FLOW_KEY_TYPE_PORT|
			      FLOW_KEY_TYPE_TCP|FLOW_KEY_TYPE_UDP|
			      FLOW_KEY_TYPE_SCTP|FLOW_KEY_TYPE_VXLAN|
			      FLOW_KEY_TYPE_GENEVE,
			      0, 4, 9); //[1b9], would pass!!
}

static int
TCP_UDP_SCTP_VXLAN_GENEVE(void)
{
	return result_checker(FLOW_KEY_TYPE_TCP|
			      FLOW_KEY_TYPE_UDP|FLOW_KEY_TYPE_SCTP|
			      FLOW_KEY_TYPE_VXLAN|FLOW_KEY_TYPE_GENEVE,
			      0, 3, 7); //[1b8], would pass!!
}

static int
PORT_IPV4_IPV6_UDP_SCTP_VXLAN_GENEVE(void)
{
	return result_checker(FLOW_KEY_TYPE_PORT|
			      FLOW_KEY_TYPE_IPV4|FLOW_KEY_TYPE_IPV6|
			      FLOW_KEY_TYPE_UDP|FLOW_KEY_TYPE_SCTP|
			      FLOW_KEY_TYPE_VXLAN|FLOW_KEY_TYPE_GENEVE,
			      1, 6, 41); //[1b7], fail
}

static int
IPV4_IPV6_UDP_SCTP_VXLAN_GENEVE(void)
{
	return result_checker(FLOW_KEY_TYPE_IPV4|
			      FLOW_KEY_TYPE_IPV6|FLOW_KEY_TYPE_UDP|
			      FLOW_KEY_TYPE_SCTP|FLOW_KEY_TYPE_VXLAN|
			      FLOW_KEY_TYPE_GENEVE,
			      1, 5, 39); //[1b6], fail
}

static int
PORT_IPV6_UDP_SCTP_VXLAN_GENEVE(void)
{
	return result_checker(FLOW_KEY_TYPE_PORT|
			      FLOW_KEY_TYPE_IPV6|FLOW_KEY_TYPE_UDP|
			      FLOW_KEY_TYPE_SCTP|FLOW_KEY_TYPE_VXLAN|
			      FLOW_KEY_TYPE_GENEVE,
			      1, 5, 41); //[1b5], fail
}

static int
IPV6_UDP_SCTP_VXLAN_GENEVE(void)
{
	return result_checker(FLOW_KEY_TYPE_IPV6|
			      FLOW_KEY_TYPE_UDP|FLOW_KEY_TYPE_SCTP|
			      FLOW_KEY_TYPE_VXLAN|FLOW_KEY_TYPE_GENEVE,
			      1, 4, 39); //[1b4], fail
}

static int
PORT_IPV4_UDP_SCTP_VXLAN_GENEVE(void)
{
	return result_checker(FLOW_KEY_TYPE_PORT|
			      FLOW_KEY_TYPE_IPV4|FLOW_KEY_TYPE_UDP|
			      FLOW_KEY_TYPE_SCTP|FLOW_KEY_TYPE_VXLAN|
			      FLOW_KEY_TYPE_GENEVE,
			      0, 5, 17); //[1b3], would pass!!
}

static int
IPV4_UDP_SCTP_VXLAN_GENEVE(void)
{
	return result_checker(FLOW_KEY_TYPE_IPV4|
			      FLOW_KEY_TYPE_UDP|FLOW_KEY_TYPE_SCTP|
			      FLOW_KEY_TYPE_VXLAN|FLOW_KEY_TYPE_GENEVE,
			      0, 4, 15); //[1b2], would pass!!
}

static int
PORT_UDP_SCTP_VXLAN_GENEVE(void)
{
	return result_checker(FLOW_KEY_TYPE_PORT|
			      FLOW_KEY_TYPE_UDP|FLOW_KEY_TYPE_SCTP|
			      FLOW_KEY_TYPE_VXLAN|FLOW_KEY_TYPE_GENEVE,
			      0, 4, 9); //[1b1], would pass!!
}

static int
UDP_SCTP_VXLAN_GENEVE(void)
{
	return result_checker(FLOW_KEY_TYPE_UDP|
			      FLOW_KEY_TYPE_SCTP|FLOW_KEY_TYPE_VXLAN|
			      FLOW_KEY_TYPE_GENEVE,
			      0, 3, 7); //[1b0], would pass!!
}

static int
PORT_IPV4_IPV6_TCP_SCTP_VXLAN_GENEVE(void)
{
	return result_checker(FLOW_KEY_TYPE_PORT|
			      FLOW_KEY_TYPE_IPV4|FLOW_KEY_TYPE_IPV6|
			      FLOW_KEY_TYPE_TCP|FLOW_KEY_TYPE_SCTP|
			      FLOW_KEY_TYPE_VXLAN|FLOW_KEY_TYPE_GENEVE,
			      1, 6, 41); //[1af], fail
}

static int
IPV4_IPV6_TCP_SCTP_VXLAN_GENEVE(void)
{
	return result_checker(FLOW_KEY_TYPE_IPV4|
			      FLOW_KEY_TYPE_IPV6|FLOW_KEY_TYPE_TCP|
			      FLOW_KEY_TYPE_SCTP|FLOW_KEY_TYPE_VXLAN|
			      FLOW_KEY_TYPE_GENEVE,
			      1, 5, 39); //[1ae], fail
}

static int
PORT_IPV6_TCP_SCTP_VXLAN_GENEVE(void)
{
	return result_checker(FLOW_KEY_TYPE_PORT|
			      FLOW_KEY_TYPE_IPV6|FLOW_KEY_TYPE_TCP|
			      FLOW_KEY_TYPE_SCTP|FLOW_KEY_TYPE_VXLAN|
			      FLOW_KEY_TYPE_GENEVE,
			      1, 5, 41); //[1ad], fail
}

static int
IPV6_TCP_SCTP_VXLAN_GENEVE(void)
{
	return result_checker(FLOW_KEY_TYPE_IPV6|
			      FLOW_KEY_TYPE_TCP|FLOW_KEY_TYPE_SCTP|
			      FLOW_KEY_TYPE_VXLAN|FLOW_KEY_TYPE_GENEVE,
			      1, 4, 39); //[1ac], fail
}

static int
PORT_IPV4_TCP_SCTP_VXLAN_GENEVE(void)
{
	return result_checker(FLOW_KEY_TYPE_PORT|
			      FLOW_KEY_TYPE_IPV4|FLOW_KEY_TYPE_TCP|
			      FLOW_KEY_TYPE_SCTP|FLOW_KEY_TYPE_VXLAN|
			      FLOW_KEY_TYPE_GENEVE,
			      0, 5, 17); //[1ab], would pass!!
}

static int
IPV4_TCP_SCTP_VXLAN_GENEVE(void)
{
	return result_checker(FLOW_KEY_TYPE_IPV4|
			      FLOW_KEY_TYPE_TCP|FLOW_KEY_TYPE_SCTP|
			      FLOW_KEY_TYPE_VXLAN|FLOW_KEY_TYPE_GENEVE,
			      0, 4, 15); //[1aa], would pass!!
}

static int
PORT_TCP_SCTP_VXLAN_GENEVE(void)
{
	return result_checker(FLOW_KEY_TYPE_PORT|
			      FLOW_KEY_TYPE_TCP|FLOW_KEY_TYPE_SCTP|
			      FLOW_KEY_TYPE_VXLAN|FLOW_KEY_TYPE_GENEVE,
			      0, 4, 9); //[1a9], would pass!!
}

static int
TCP_SCTP_VXLAN_GENEVE(void)
{
	return result_checker(FLOW_KEY_TYPE_TCP|
			      FLOW_KEY_TYPE_SCTP|FLOW_KEY_TYPE_VXLAN|
			      FLOW_KEY_TYPE_GENEVE,
			      0, 3, 7); //[1a8], would pass!!
}

static int
PORT_IPV4_IPV6_SCTP_VXLAN_GENEVE(void)
{
	return result_checker(FLOW_KEY_TYPE_PORT|
			      FLOW_KEY_TYPE_IPV4|FLOW_KEY_TYPE_IPV6|
			      FLOW_KEY_TYPE_SCTP|FLOW_KEY_TYPE_VXLAN|
			      FLOW_KEY_TYPE_GENEVE,
			      1, 6, 41); //[1a7], fail
}

static int
IPV4_IPV6_SCTP_VXLAN_GENEVE(void)
{
	return result_checker(FLOW_KEY_TYPE_IPV4|
			      FLOW_KEY_TYPE_IPV6|FLOW_KEY_TYPE_SCTP|
			      FLOW_KEY_TYPE_VXLAN|FLOW_KEY_TYPE_GENEVE,
			      1, 5, 39); //[1a6], fail
}

static int
PORT_IPV6_SCTP_VXLAN_GENEVE(void)
{
	return result_checker(FLOW_KEY_TYPE_PORT|
			      FLOW_KEY_TYPE_IPV6|FLOW_KEY_TYPE_SCTP|
			      FLOW_KEY_TYPE_VXLAN|FLOW_KEY_TYPE_GENEVE,
			      1, 5, 41); //[1a5], fail
}

static int
IPV6_SCTP_VXLAN_GENEVE(void)
{
	return result_checker(FLOW_KEY_TYPE_IPV6|
			      FLOW_KEY_TYPE_SCTP|FLOW_KEY_TYPE_VXLAN|
			      FLOW_KEY_TYPE_GENEVE,
			      1, 4, 39); //[1a4], fail
}

static int
PORT_IPV4_SCTP_VXLAN_GENEVE(void)
{
	return result_checker(FLOW_KEY_TYPE_PORT|
			      FLOW_KEY_TYPE_IPV4|FLOW_KEY_TYPE_SCTP|
			      FLOW_KEY_TYPE_VXLAN|FLOW_KEY_TYPE_GENEVE,
			      0, 5, 17); //[1a3], would pass!!
}

static int
IPV4_SCTP_VXLAN_GENEVE(void)
{
	return result_checker(FLOW_KEY_TYPE_IPV4|
			      FLOW_KEY_TYPE_SCTP|FLOW_KEY_TYPE_VXLAN|
			      FLOW_KEY_TYPE_GENEVE,
			      0, 4, 15); //[1a2], would pass!!
}

static int
PORT_SCTP_VXLAN_GENEVE(void)
{
	return result_checker(FLOW_KEY_TYPE_PORT|
			      FLOW_KEY_TYPE_SCTP|FLOW_KEY_TYPE_VXLAN|
			      FLOW_KEY_TYPE_GENEVE,
			      0, 4, 9); //[1a1], would pass!!
}

static int
SCTP_VXLAN_GENEVE(void)
{
	return result_checker(FLOW_KEY_TYPE_SCTP|
			      FLOW_KEY_TYPE_VXLAN|FLOW_KEY_TYPE_GENEVE,
			      0, 3, 7); //[1a0], would pass!!
}

static int
PORT_IPV4_IPV6_TCP_UDP_VXLAN_GENEVE(void)
{
	return result_checker(FLOW_KEY_TYPE_PORT|
			      FLOW_KEY_TYPE_IPV4|FLOW_KEY_TYPE_IPV6|
			      FLOW_KEY_TYPE_TCP|FLOW_KEY_TYPE_UDP|
			      FLOW_KEY_TYPE_VXLAN|FLOW_KEY_TYPE_GENEVE,
			      1, 6, 41); //[19f], fail
}

static int
IPV4_IPV6_TCP_UDP_VXLAN_GENEVE(void)
{
	return result_checker(FLOW_KEY_TYPE_IPV4|
			      FLOW_KEY_TYPE_IPV6|FLOW_KEY_TYPE_TCP|
			      FLOW_KEY_TYPE_UDP|FLOW_KEY_TYPE_VXLAN|
			      FLOW_KEY_TYPE_GENEVE,
			      1, 5, 39); //[19e], fail
}

static int
PORT_IPV6_TCP_UDP_VXLAN_GENEVE(void)
{
	return result_checker(FLOW_KEY_TYPE_PORT|
			      FLOW_KEY_TYPE_IPV6|FLOW_KEY_TYPE_TCP|
			      FLOW_KEY_TYPE_UDP|FLOW_KEY_TYPE_VXLAN|
			      FLOW_KEY_TYPE_GENEVE,
			      1, 5, 41); //[19d], fail
}

static int
IPV6_TCP_UDP_VXLAN_GENEVE(void)
{
	return result_checker(FLOW_KEY_TYPE_IPV6|
			      FLOW_KEY_TYPE_TCP|FLOW_KEY_TYPE_UDP|
			      FLOW_KEY_TYPE_VXLAN|FLOW_KEY_TYPE_GENEVE,
			      1, 4, 39); //[19c], fail
}

static int
PORT_IPV4_TCP_UDP_VXLAN_GENEVE(void)
{
	return result_checker(FLOW_KEY_TYPE_PORT|
			      FLOW_KEY_TYPE_IPV4|FLOW_KEY_TYPE_TCP|
			      FLOW_KEY_TYPE_UDP|FLOW_KEY_TYPE_VXLAN|
			      FLOW_KEY_TYPE_GENEVE,
			      0, 5, 17); //[19b], would pass!!
}

static int
IPV4_TCP_UDP_VXLAN_GENEVE(void)
{
	return result_checker(FLOW_KEY_TYPE_IPV4|
			      FLOW_KEY_TYPE_TCP|FLOW_KEY_TYPE_UDP|
			      FLOW_KEY_TYPE_VXLAN|FLOW_KEY_TYPE_GENEVE,
			      0, 4, 15); //[19a], would pass!!
}

static int
PORT_TCP_UDP_VXLAN_GENEVE(void)
{
	return result_checker(FLOW_KEY_TYPE_PORT|
			      FLOW_KEY_TYPE_TCP|FLOW_KEY_TYPE_UDP|
			      FLOW_KEY_TYPE_VXLAN|FLOW_KEY_TYPE_GENEVE,
			      0, 4, 9); //[199], would pass!!
}

static int
TCP_UDP_VXLAN_GENEVE(void)
{
	return result_checker(FLOW_KEY_TYPE_TCP|
			      FLOW_KEY_TYPE_UDP|FLOW_KEY_TYPE_VXLAN|
			      FLOW_KEY_TYPE_GENEVE,
			      0, 3, 7); //[198], would pass!!
}

static int
PORT_IPV4_IPV6_UDP_VXLAN_GENEVE(void)
{
	return result_checker(FLOW_KEY_TYPE_PORT|
			      FLOW_KEY_TYPE_IPV4|FLOW_KEY_TYPE_IPV6|
			      FLOW_KEY_TYPE_UDP|FLOW_KEY_TYPE_VXLAN|
			      FLOW_KEY_TYPE_GENEVE,
			      1, 6, 41); //[197], fail
}

static int
IPV4_IPV6_UDP_VXLAN_GENEVE(void)
{
	return result_checker(FLOW_KEY_TYPE_IPV4|
			      FLOW_KEY_TYPE_IPV6|FLOW_KEY_TYPE_UDP|
			      FLOW_KEY_TYPE_VXLAN|FLOW_KEY_TYPE_GENEVE,
			      1, 5, 39); //[196], fail
}

static int
PORT_IPV6_UDP_VXLAN_GENEVE(void)
{
	return result_checker(FLOW_KEY_TYPE_PORT|
			      FLOW_KEY_TYPE_IPV6|FLOW_KEY_TYPE_UDP|
			      FLOW_KEY_TYPE_VXLAN|FLOW_KEY_TYPE_GENEVE,
			      1, 5, 41); //[195], fail
}

static int
IPV6_UDP_VXLAN_GENEVE(void)
{
	return result_checker(FLOW_KEY_TYPE_IPV6|
			      FLOW_KEY_TYPE_UDP|FLOW_KEY_TYPE_VXLAN|
			      FLOW_KEY_TYPE_GENEVE,
			      1, 4, 39); //[194], fail
}

static int
PORT_IPV4_UDP_VXLAN_GENEVE(void)
{
	return result_checker(FLOW_KEY_TYPE_PORT|
			      FLOW_KEY_TYPE_IPV4|FLOW_KEY_TYPE_UDP|
			      FLOW_KEY_TYPE_VXLAN|FLOW_KEY_TYPE_GENEVE,
			      0, 5, 17); //[193], would pass!!
}

static int
IPV4_UDP_VXLAN_GENEVE(void)
{
	return result_checker(FLOW_KEY_TYPE_IPV4|
			      FLOW_KEY_TYPE_UDP|FLOW_KEY_TYPE_VXLAN|
			      FLOW_KEY_TYPE_GENEVE,
			      0, 4, 15); //[192], would pass!!
}

static int
PORT_UDP_VXLAN_GENEVE(void)
{
	return result_checker(FLOW_KEY_TYPE_PORT|
			      FLOW_KEY_TYPE_UDP|FLOW_KEY_TYPE_VXLAN|
			      FLOW_KEY_TYPE_GENEVE,
			      0, 4, 9); //[191], would pass!!
}

static int
UDP_VXLAN_GENEVE(void)
{
	return result_checker(FLOW_KEY_TYPE_UDP|
			      FLOW_KEY_TYPE_VXLAN|FLOW_KEY_TYPE_GENEVE,
			      0, 3, 7); //[190], would pass!!
}

static int
PORT_IPV4_IPV6_TCP_VXLAN_GENEVE(void)
{
	return result_checker(FLOW_KEY_TYPE_PORT|
			      FLOW_KEY_TYPE_IPV4|FLOW_KEY_TYPE_IPV6|
			      FLOW_KEY_TYPE_TCP|FLOW_KEY_TYPE_VXLAN|
			      FLOW_KEY_TYPE_GENEVE,
			      1, 6, 41); //[18f], fail
}

static int
IPV4_IPV6_TCP_VXLAN_GENEVE(void)
{
	return result_checker(FLOW_KEY_TYPE_IPV4|
			      FLOW_KEY_TYPE_IPV6|FLOW_KEY_TYPE_TCP|
			      FLOW_KEY_TYPE_VXLAN|FLOW_KEY_TYPE_GENEVE,
			      1, 5, 39); //[18e], fail
}

static int
PORT_IPV6_TCP_VXLAN_GENEVE(void)
{
	return result_checker(FLOW_KEY_TYPE_PORT|
			      FLOW_KEY_TYPE_IPV6|FLOW_KEY_TYPE_TCP|
			      FLOW_KEY_TYPE_VXLAN|FLOW_KEY_TYPE_GENEVE,
			      1, 5, 41); //[18d], fail
}

static int
IPV6_TCP_VXLAN_GENEVE(void)
{
	return result_checker(FLOW_KEY_TYPE_IPV6|
			      FLOW_KEY_TYPE_TCP|FLOW_KEY_TYPE_VXLAN|
			      FLOW_KEY_TYPE_GENEVE,
			      1, 4, 39); //[18c], fail
}

static int
PORT_IPV4_TCP_VXLAN_GENEVE(void)
{
	return result_checker(FLOW_KEY_TYPE_PORT|
			      FLOW_KEY_TYPE_IPV4|FLOW_KEY_TYPE_TCP|
			      FLOW_KEY_TYPE_VXLAN|FLOW_KEY_TYPE_GENEVE,
			      0, 5, 17); //[18b], would pass!!
}

static int
IPV4_TCP_VXLAN_GENEVE(void)
{
	return result_checker(FLOW_KEY_TYPE_IPV4|
			      FLOW_KEY_TYPE_TCP|FLOW_KEY_TYPE_VXLAN|
			      FLOW_KEY_TYPE_GENEVE,
			      0, 4, 15); //[18a], would pass!!
}

static int
PORT_TCP_VXLAN_GENEVE(void)
{
	return result_checker(FLOW_KEY_TYPE_PORT|
			      FLOW_KEY_TYPE_TCP|FLOW_KEY_TYPE_VXLAN|
			      FLOW_KEY_TYPE_GENEVE,
			      0, 4, 9); //[189], would pass!!
}

static int
TCP_VXLAN_GENEVE(void)
{
	return result_checker(FLOW_KEY_TYPE_TCP|
			      FLOW_KEY_TYPE_VXLAN|FLOW_KEY_TYPE_GENEVE,
			      0, 3, 7); //[188], would pass!!
}

static int
PORT_IPV4_IPV6_VXLAN_GENEVE(void)
{
	return result_checker(FLOW_KEY_TYPE_PORT|
			      FLOW_KEY_TYPE_IPV4|FLOW_KEY_TYPE_IPV6|
			      FLOW_KEY_TYPE_VXLAN|FLOW_KEY_TYPE_GENEVE,
			      0, 5, 37); //[187], would pass!!
}

static int
IPV4_IPV6_VXLAN_GENEVE(void)
{
	return result_checker(FLOW_KEY_TYPE_IPV4|
			      FLOW_KEY_TYPE_IPV6|FLOW_KEY_TYPE_VXLAN|
			      FLOW_KEY_TYPE_GENEVE,
			      0, 4, 35); //[186], would pass!!
}

static int
PORT_IPV6_VXLAN_GENEVE(void)
{
	return result_checker(FLOW_KEY_TYPE_PORT|
			      FLOW_KEY_TYPE_IPV6|FLOW_KEY_TYPE_VXLAN|
			      FLOW_KEY_TYPE_GENEVE,
			      0, 4, 37); //[185], would pass!!
}

static int
IPV6_VXLAN_GENEVE(void)
{
	return result_checker(FLOW_KEY_TYPE_IPV6|
			      FLOW_KEY_TYPE_VXLAN|FLOW_KEY_TYPE_GENEVE,
			      0, 3, 35); //[184], would pass!!
}

static int
PORT_IPV4_VXLAN_GENEVE(void)
{
	return result_checker(FLOW_KEY_TYPE_PORT|
			      FLOW_KEY_TYPE_IPV4|FLOW_KEY_TYPE_VXLAN|
			      FLOW_KEY_TYPE_GENEVE,
			      0, 4, 13); //[183], would pass!!
}

static int
IPV4_VXLAN_GENEVE(void)
{
	return result_checker(FLOW_KEY_TYPE_IPV4|
			      FLOW_KEY_TYPE_VXLAN|FLOW_KEY_TYPE_GENEVE,
			      0, 3, 11); //[182], would pass!!
}

static int
PORT_VXLAN_GENEVE(void)
{
	return result_checker(FLOW_KEY_TYPE_PORT|
			      FLOW_KEY_TYPE_VXLAN|FLOW_KEY_TYPE_GENEVE,
			      0, 3, 5); //[181], would pass!!
}

static int
VXLAN_GENEVE(void)
{
	return result_checker(FLOW_KEY_TYPE_VXLAN|
			      FLOW_KEY_TYPE_GENEVE,
			      0, 2, 3); //[180], would pass!!
}

static int
PORT_IPV4_IPV6_TCP_UDP_SCTP_NVGRE_GENEVE(void)
{
	return result_checker(FLOW_KEY_TYPE_PORT|
			      FLOW_KEY_TYPE_IPV4|FLOW_KEY_TYPE_IPV6|
			      FLOW_KEY_TYPE_TCP|FLOW_KEY_TYPE_UDP|
			      FLOW_KEY_TYPE_SCTP|FLOW_KEY_TYPE_NVGRE|
			      FLOW_KEY_TYPE_GENEVE,
			      1, 6, 41); //[17f], fail
}

static int
IPV4_IPV6_TCP_UDP_SCTP_NVGRE_GENEVE(void)
{
	return result_checker(FLOW_KEY_TYPE_IPV4|
			      FLOW_KEY_TYPE_IPV6|FLOW_KEY_TYPE_TCP|
			      FLOW_KEY_TYPE_UDP|FLOW_KEY_TYPE_SCTP|
			      FLOW_KEY_TYPE_NVGRE|FLOW_KEY_TYPE_GENEVE,
			      1, 5, 39); //[17e], fail
}

static int
PORT_IPV6_TCP_UDP_SCTP_NVGRE_GENEVE(void)
{
	return result_checker(FLOW_KEY_TYPE_PORT|
			      FLOW_KEY_TYPE_IPV6|FLOW_KEY_TYPE_TCP|
			      FLOW_KEY_TYPE_UDP|FLOW_KEY_TYPE_SCTP|
			      FLOW_KEY_TYPE_NVGRE|FLOW_KEY_TYPE_GENEVE,
			      1, 5, 41); //[17d], fail
}

static int
IPV6_TCP_UDP_SCTP_NVGRE_GENEVE(void)
{
	return result_checker(FLOW_KEY_TYPE_IPV6|
			      FLOW_KEY_TYPE_TCP|FLOW_KEY_TYPE_UDP|
			      FLOW_KEY_TYPE_SCTP|FLOW_KEY_TYPE_NVGRE|
			      FLOW_KEY_TYPE_GENEVE,
			      1, 4, 39); //[17c], fail
}

static int
PORT_IPV4_TCP_UDP_SCTP_NVGRE_GENEVE(void)
{
	return result_checker(FLOW_KEY_TYPE_PORT|
			      FLOW_KEY_TYPE_IPV4|FLOW_KEY_TYPE_TCP|
			      FLOW_KEY_TYPE_UDP|FLOW_KEY_TYPE_SCTP|
			      FLOW_KEY_TYPE_NVGRE|FLOW_KEY_TYPE_GENEVE,
			      0, 5, 17); //[17b], would pass!!
}

static int
IPV4_TCP_UDP_SCTP_NVGRE_GENEVE(void)
{
	return result_checker(FLOW_KEY_TYPE_IPV4|
			      FLOW_KEY_TYPE_TCP|FLOW_KEY_TYPE_UDP|
			      FLOW_KEY_TYPE_SCTP|FLOW_KEY_TYPE_NVGRE|
			      FLOW_KEY_TYPE_GENEVE,
			      0, 4, 15); //[17a], would pass!!
}

static int
PORT_TCP_UDP_SCTP_NVGRE_GENEVE(void)
{
	return result_checker(FLOW_KEY_TYPE_PORT|
			      FLOW_KEY_TYPE_TCP|FLOW_KEY_TYPE_UDP|
			      FLOW_KEY_TYPE_SCTP|FLOW_KEY_TYPE_NVGRE|
			      FLOW_KEY_TYPE_GENEVE,
			      0, 4, 9); //[179], would pass!!
}

static int
TCP_UDP_SCTP_NVGRE_GENEVE(void)
{
	return result_checker(FLOW_KEY_TYPE_TCP|
			      FLOW_KEY_TYPE_UDP|FLOW_KEY_TYPE_SCTP|
			      FLOW_KEY_TYPE_NVGRE|FLOW_KEY_TYPE_GENEVE,
			      0, 3, 7); //[178], would pass!!
}

static int
PORT_IPV4_IPV6_UDP_SCTP_NVGRE_GENEVE(void)
{
	return result_checker(FLOW_KEY_TYPE_PORT|
			      FLOW_KEY_TYPE_IPV4|FLOW_KEY_TYPE_IPV6|
			      FLOW_KEY_TYPE_UDP|FLOW_KEY_TYPE_SCTP|
			      FLOW_KEY_TYPE_NVGRE|FLOW_KEY_TYPE_GENEVE,
			      1, 5, 42); //[177], fail
}

static int
IPV4_IPV6_UDP_SCTP_NVGRE_GENEVE(void)
{
	return result_checker(FLOW_KEY_TYPE_IPV4|
			      FLOW_KEY_TYPE_IPV6|FLOW_KEY_TYPE_UDP|
			      FLOW_KEY_TYPE_SCTP|FLOW_KEY_TYPE_NVGRE|
			      FLOW_KEY_TYPE_GENEVE,
			      1, 5, 42); //[176], fail
}

static int
PORT_IPV6_UDP_SCTP_NVGRE_GENEVE(void)
{
	return result_checker(FLOW_KEY_TYPE_PORT|
			      FLOW_KEY_TYPE_IPV6|FLOW_KEY_TYPE_UDP|
			      FLOW_KEY_TYPE_SCTP|FLOW_KEY_TYPE_NVGRE|
			      FLOW_KEY_TYPE_GENEVE,
			      1, 5, 42); //[175], fail
}

static int
IPV6_UDP_SCTP_NVGRE_GENEVE(void)
{
	return result_checker(FLOW_KEY_TYPE_IPV6|
			      FLOW_KEY_TYPE_UDP|FLOW_KEY_TYPE_SCTP|
			      FLOW_KEY_TYPE_NVGRE|FLOW_KEY_TYPE_GENEVE,
			      1, 5, 42); //[174], fail
}

static int
PORT_IPV4_UDP_SCTP_NVGRE_GENEVE(void)
{
	return result_checker(FLOW_KEY_TYPE_PORT|
			      FLOW_KEY_TYPE_IPV4|FLOW_KEY_TYPE_UDP|
			      FLOW_KEY_TYPE_SCTP|FLOW_KEY_TYPE_NVGRE|
			      FLOW_KEY_TYPE_GENEVE,
			      0, 5, 17); //[173], would pass!!
}

static int
IPV4_UDP_SCTP_NVGRE_GENEVE(void)
{
	return result_checker(FLOW_KEY_TYPE_IPV4|
			      FLOW_KEY_TYPE_UDP|FLOW_KEY_TYPE_SCTP|
			      FLOW_KEY_TYPE_NVGRE|FLOW_KEY_TYPE_GENEVE,
			      0, 4, 15); //[172], would pass!!
}

static int
PORT_UDP_SCTP_NVGRE_GENEVE(void)
{
	return result_checker(FLOW_KEY_TYPE_PORT|
			      FLOW_KEY_TYPE_UDP|FLOW_KEY_TYPE_SCTP|
			      FLOW_KEY_TYPE_NVGRE|FLOW_KEY_TYPE_GENEVE,
			      0, 4, 9); //[171], would pass!!
}

static int
UDP_SCTP_NVGRE_GENEVE(void)
{
	return result_checker(FLOW_KEY_TYPE_UDP|
			      FLOW_KEY_TYPE_SCTP|FLOW_KEY_TYPE_NVGRE|
			      FLOW_KEY_TYPE_GENEVE,
			      0, 3, 7); //[170], would pass!!
}

static int
PORT_IPV4_IPV6_TCP_SCTP_NVGRE_GENEVE(void)
{
	return result_checker(FLOW_KEY_TYPE_PORT|
			      FLOW_KEY_TYPE_IPV4|FLOW_KEY_TYPE_IPV6|
			      FLOW_KEY_TYPE_TCP|FLOW_KEY_TYPE_SCTP|
			      FLOW_KEY_TYPE_NVGRE|FLOW_KEY_TYPE_GENEVE,
			      1, 5, 42); //[16f], fail
}

static int
IPV4_IPV6_TCP_SCTP_NVGRE_GENEVE(void)
{
	return result_checker(FLOW_KEY_TYPE_IPV4|
			      FLOW_KEY_TYPE_IPV6|FLOW_KEY_TYPE_TCP|
			      FLOW_KEY_TYPE_SCTP|FLOW_KEY_TYPE_NVGRE|
			      FLOW_KEY_TYPE_GENEVE,
			      1, 5, 42); //[16e], fail
}

static int
PORT_IPV6_TCP_SCTP_NVGRE_GENEVE(void)
{
	return result_checker(FLOW_KEY_TYPE_PORT|
			      FLOW_KEY_TYPE_IPV6|FLOW_KEY_TYPE_TCP|
			      FLOW_KEY_TYPE_SCTP|FLOW_KEY_TYPE_NVGRE|
			      FLOW_KEY_TYPE_GENEVE,
			      1, 5, 42); //[16d], fail
}

static int
IPV6_TCP_SCTP_NVGRE_GENEVE(void)
{
	return result_checker(FLOW_KEY_TYPE_IPV6|
			      FLOW_KEY_TYPE_TCP|FLOW_KEY_TYPE_SCTP|
			      FLOW_KEY_TYPE_NVGRE|FLOW_KEY_TYPE_GENEVE,
			      1, 5, 42); //[16c], fail
}

static int
PORT_IPV4_TCP_SCTP_NVGRE_GENEVE(void)
{
	return result_checker(FLOW_KEY_TYPE_PORT|
			      FLOW_KEY_TYPE_IPV4|FLOW_KEY_TYPE_TCP|
			      FLOW_KEY_TYPE_SCTP|FLOW_KEY_TYPE_NVGRE|
			      FLOW_KEY_TYPE_GENEVE,
			      0, 5, 17); //[16b], would pass!!
}

static int
IPV4_TCP_SCTP_NVGRE_GENEVE(void)
{
	return result_checker(FLOW_KEY_TYPE_IPV4|
			      FLOW_KEY_TYPE_TCP|FLOW_KEY_TYPE_SCTP|
			      FLOW_KEY_TYPE_NVGRE|FLOW_KEY_TYPE_GENEVE,
			      0, 4, 15); //[16a], would pass!!
}

static int
PORT_TCP_SCTP_NVGRE_GENEVE(void)
{
	return result_checker(FLOW_KEY_TYPE_PORT|
			      FLOW_KEY_TYPE_TCP|FLOW_KEY_TYPE_SCTP|
			      FLOW_KEY_TYPE_NVGRE|FLOW_KEY_TYPE_GENEVE,
			      0, 4, 9); //[169], would pass!!
}

static int
TCP_SCTP_NVGRE_GENEVE(void)
{
	return result_checker(FLOW_KEY_TYPE_TCP|
			      FLOW_KEY_TYPE_SCTP|FLOW_KEY_TYPE_NVGRE|
			      FLOW_KEY_TYPE_GENEVE,
			      0, 3, 7); //[168], would pass!!
}

static int
PORT_IPV4_IPV6_SCTP_NVGRE_GENEVE(void)
{
	return result_checker(FLOW_KEY_TYPE_PORT|
			      FLOW_KEY_TYPE_IPV4|FLOW_KEY_TYPE_IPV6|
			      FLOW_KEY_TYPE_SCTP|FLOW_KEY_TYPE_NVGRE|
			      FLOW_KEY_TYPE_GENEVE,
			      1, 5, 42); //[167], fail
}

static int
IPV4_IPV6_SCTP_NVGRE_GENEVE(void)
{
	return result_checker(FLOW_KEY_TYPE_IPV4|
			      FLOW_KEY_TYPE_IPV6|FLOW_KEY_TYPE_SCTP|
			      FLOW_KEY_TYPE_NVGRE|FLOW_KEY_TYPE_GENEVE,
			      1, 5, 42); //[166], fail
}

static int
PORT_IPV6_SCTP_NVGRE_GENEVE(void)
{
	return result_checker(FLOW_KEY_TYPE_PORT|
			      FLOW_KEY_TYPE_IPV6|FLOW_KEY_TYPE_SCTP|
			      FLOW_KEY_TYPE_NVGRE|FLOW_KEY_TYPE_GENEVE,
			      1, 5, 42); //[165], fail
}

static int
IPV6_SCTP_NVGRE_GENEVE(void)
{
	return result_checker(FLOW_KEY_TYPE_IPV6|
			      FLOW_KEY_TYPE_SCTP|FLOW_KEY_TYPE_NVGRE|
			      FLOW_KEY_TYPE_GENEVE,
			      1, 5, 42); //[164], fail
}

static int
PORT_IPV4_SCTP_NVGRE_GENEVE(void)
{
	return result_checker(FLOW_KEY_TYPE_PORT|
			      FLOW_KEY_TYPE_IPV4|FLOW_KEY_TYPE_SCTP|
			      FLOW_KEY_TYPE_NVGRE|FLOW_KEY_TYPE_GENEVE,
			      0, 5, 17); //[163], would pass!!
}

static int
IPV4_SCTP_NVGRE_GENEVE(void)
{
	return result_checker(FLOW_KEY_TYPE_IPV4|
			      FLOW_KEY_TYPE_SCTP|FLOW_KEY_TYPE_NVGRE|
			      FLOW_KEY_TYPE_GENEVE,
			      0, 4, 15); //[162], would pass!!
}

static int
PORT_SCTP_NVGRE_GENEVE(void)
{
	return result_checker(FLOW_KEY_TYPE_PORT|
			      FLOW_KEY_TYPE_SCTP|FLOW_KEY_TYPE_NVGRE|
			      FLOW_KEY_TYPE_GENEVE,
			      0, 4, 9); //[161], would pass!!
}

static int
SCTP_NVGRE_GENEVE(void)
{
	return result_checker(FLOW_KEY_TYPE_SCTP|
			      FLOW_KEY_TYPE_NVGRE|FLOW_KEY_TYPE_GENEVE,
			      0, 3, 7); //[160], would pass!!
}

static int
PORT_IPV4_IPV6_TCP_UDP_NVGRE_GENEVE(void)
{
	return result_checker(FLOW_KEY_TYPE_PORT|
			      FLOW_KEY_TYPE_IPV4|FLOW_KEY_TYPE_IPV6|
			      FLOW_KEY_TYPE_TCP|FLOW_KEY_TYPE_UDP|
			      FLOW_KEY_TYPE_NVGRE|FLOW_KEY_TYPE_GENEVE,
			      1, 5, 42); //[15f], fail
}

static int
IPV4_IPV6_TCP_UDP_NVGRE_GENEVE(void)
{
	return result_checker(FLOW_KEY_TYPE_IPV4|
			      FLOW_KEY_TYPE_IPV6|FLOW_KEY_TYPE_TCP|
			      FLOW_KEY_TYPE_UDP|FLOW_KEY_TYPE_NVGRE|
			      FLOW_KEY_TYPE_GENEVE,
			      1, 5, 42); //[15e], fail
}

static int
PORT_IPV6_TCP_UDP_NVGRE_GENEVE(void)
{
	return result_checker(FLOW_KEY_TYPE_PORT|
			      FLOW_KEY_TYPE_IPV6|FLOW_KEY_TYPE_TCP|
			      FLOW_KEY_TYPE_UDP|FLOW_KEY_TYPE_NVGRE|
			      FLOW_KEY_TYPE_GENEVE,
			      1, 5, 42); //[15d], fail
}

static int
IPV6_TCP_UDP_NVGRE_GENEVE(void)
{
	return result_checker(FLOW_KEY_TYPE_IPV6|
			      FLOW_KEY_TYPE_TCP|FLOW_KEY_TYPE_UDP|
			      FLOW_KEY_TYPE_NVGRE|FLOW_KEY_TYPE_GENEVE,
			      1, 5, 42); //[15c], fail
}

static int
PORT_IPV4_TCP_UDP_NVGRE_GENEVE(void)
{
	return result_checker(FLOW_KEY_TYPE_PORT|
			      FLOW_KEY_TYPE_IPV4|FLOW_KEY_TYPE_TCP|
			      FLOW_KEY_TYPE_UDP|FLOW_KEY_TYPE_NVGRE|
			      FLOW_KEY_TYPE_GENEVE,
			      0, 5, 17); //[15b], would pass!!
}

static int
IPV4_TCP_UDP_NVGRE_GENEVE(void)
{
	return result_checker(FLOW_KEY_TYPE_IPV4|
			      FLOW_KEY_TYPE_TCP|FLOW_KEY_TYPE_UDP|
			      FLOW_KEY_TYPE_NVGRE|FLOW_KEY_TYPE_GENEVE,
			      0, 4, 15); //[15a], would pass!!
}

static int
PORT_TCP_UDP_NVGRE_GENEVE(void)
{
	return result_checker(FLOW_KEY_TYPE_PORT|
			      FLOW_KEY_TYPE_TCP|FLOW_KEY_TYPE_UDP|
			      FLOW_KEY_TYPE_NVGRE|FLOW_KEY_TYPE_GENEVE,
			      0, 4, 9); //[159], would pass!!
}

static int
TCP_UDP_NVGRE_GENEVE(void)
{
	return result_checker(FLOW_KEY_TYPE_TCP|
			      FLOW_KEY_TYPE_UDP|FLOW_KEY_TYPE_NVGRE|
			      FLOW_KEY_TYPE_GENEVE,
			      0, 3, 7); //[158], would pass!!
}

static int
PORT_IPV4_IPV6_UDP_NVGRE_GENEVE(void)
{
	return result_checker(FLOW_KEY_TYPE_PORT|
			      FLOW_KEY_TYPE_IPV4|FLOW_KEY_TYPE_IPV6|
			      FLOW_KEY_TYPE_UDP|FLOW_KEY_TYPE_NVGRE|
			      FLOW_KEY_TYPE_GENEVE,
			      1, 5, 42); //[157], fail
}

static int
IPV4_IPV6_UDP_NVGRE_GENEVE(void)
{
	return result_checker(FLOW_KEY_TYPE_IPV4|
			      FLOW_KEY_TYPE_IPV6|FLOW_KEY_TYPE_UDP|
			      FLOW_KEY_TYPE_NVGRE|FLOW_KEY_TYPE_GENEVE,
			      1, 5, 42); //[156], fail
}

static int
PORT_IPV6_UDP_NVGRE_GENEVE(void)
{
	return result_checker(FLOW_KEY_TYPE_PORT|
			      FLOW_KEY_TYPE_IPV6|FLOW_KEY_TYPE_UDP|
			      FLOW_KEY_TYPE_NVGRE|FLOW_KEY_TYPE_GENEVE,
			      1, 5, 42); //[155], fail
}

static int
IPV6_UDP_NVGRE_GENEVE(void)
{
	return result_checker(FLOW_KEY_TYPE_IPV6|
			      FLOW_KEY_TYPE_UDP|FLOW_KEY_TYPE_NVGRE|
			      FLOW_KEY_TYPE_GENEVE,
			      1, 5, 42); //[154], fail
}

static int
PORT_IPV4_UDP_NVGRE_GENEVE(void)
{
	return result_checker(FLOW_KEY_TYPE_PORT|
			      FLOW_KEY_TYPE_IPV4|FLOW_KEY_TYPE_UDP|
			      FLOW_KEY_TYPE_NVGRE|FLOW_KEY_TYPE_GENEVE,
			      0, 5, 17); //[153], would pass!!
}

static int
IPV4_UDP_NVGRE_GENEVE(void)
{
	return result_checker(FLOW_KEY_TYPE_IPV4|
			      FLOW_KEY_TYPE_UDP|FLOW_KEY_TYPE_NVGRE|
			      FLOW_KEY_TYPE_GENEVE,
			      0, 4, 15); //[152], would pass!!
}

static int
PORT_UDP_NVGRE_GENEVE(void)
{
	return result_checker(FLOW_KEY_TYPE_PORT|
			      FLOW_KEY_TYPE_UDP|FLOW_KEY_TYPE_NVGRE|
			      FLOW_KEY_TYPE_GENEVE,
			      0, 4, 9); //[151], would pass!!
}

static int
UDP_NVGRE_GENEVE(void)
{
	return result_checker(FLOW_KEY_TYPE_UDP|
			      FLOW_KEY_TYPE_NVGRE|FLOW_KEY_TYPE_GENEVE,
			      0, 3, 7); //[150], would pass!!
}

static int
PORT_IPV4_IPV6_TCP_NVGRE_GENEVE(void)
{
	return result_checker(FLOW_KEY_TYPE_PORT|
			      FLOW_KEY_TYPE_IPV4|FLOW_KEY_TYPE_IPV6|
			      FLOW_KEY_TYPE_TCP|FLOW_KEY_TYPE_NVGRE|
			      FLOW_KEY_TYPE_GENEVE,
			      1, 5, 42); //[14f], fail
}

static int
IPV4_IPV6_TCP_NVGRE_GENEVE(void)
{
	return result_checker(FLOW_KEY_TYPE_IPV4|
			      FLOW_KEY_TYPE_IPV6|FLOW_KEY_TYPE_TCP|
			      FLOW_KEY_TYPE_NVGRE|FLOW_KEY_TYPE_GENEVE,
			      1, 5, 42); //[14e], fail
}

static int
PORT_IPV6_TCP_NVGRE_GENEVE(void)
{
	return result_checker(FLOW_KEY_TYPE_PORT|
			      FLOW_KEY_TYPE_IPV6|FLOW_KEY_TYPE_TCP|
			      FLOW_KEY_TYPE_NVGRE|FLOW_KEY_TYPE_GENEVE,
			      1, 5, 42); //[14d], fail
}

static int
IPV6_TCP_NVGRE_GENEVE(void)
{
	return result_checker(FLOW_KEY_TYPE_IPV6|
			      FLOW_KEY_TYPE_TCP|FLOW_KEY_TYPE_NVGRE|
			      FLOW_KEY_TYPE_GENEVE,
			      1, 5, 42); //[14c], fail
}

static int
PORT_IPV4_TCP_NVGRE_GENEVE(void)
{
	return result_checker(FLOW_KEY_TYPE_PORT|
			      FLOW_KEY_TYPE_IPV4|FLOW_KEY_TYPE_TCP|
			      FLOW_KEY_TYPE_NVGRE|FLOW_KEY_TYPE_GENEVE,
			      0, 5, 17); //[14b], would pass!!
}

static int
IPV4_TCP_NVGRE_GENEVE(void)
{
	return result_checker(FLOW_KEY_TYPE_IPV4|
			      FLOW_KEY_TYPE_TCP|FLOW_KEY_TYPE_NVGRE|
			      FLOW_KEY_TYPE_GENEVE,
			      0, 4, 15); //[14a], would pass!!
}

static int
PORT_TCP_NVGRE_GENEVE(void)
{
	return result_checker(FLOW_KEY_TYPE_PORT|
			      FLOW_KEY_TYPE_TCP|FLOW_KEY_TYPE_NVGRE|
			      FLOW_KEY_TYPE_GENEVE,
			      0, 4, 9); //[149], would pass!!
}

static int
TCP_NVGRE_GENEVE(void)
{
	return result_checker(FLOW_KEY_TYPE_TCP|
			      FLOW_KEY_TYPE_NVGRE|FLOW_KEY_TYPE_GENEVE,
			      0, 3, 7); //[148], would pass!!
}

static int
PORT_IPV4_IPV6_NVGRE_GENEVE(void)
{
	return result_checker(FLOW_KEY_TYPE_PORT|
			      FLOW_KEY_TYPE_IPV4|FLOW_KEY_TYPE_IPV6|
			      FLOW_KEY_TYPE_NVGRE|FLOW_KEY_TYPE_GENEVE,
			      0, 5, 37); //[147], would pass!!
}

static int
IPV4_IPV6_NVGRE_GENEVE(void)
{
	return result_checker(FLOW_KEY_TYPE_IPV4|
			      FLOW_KEY_TYPE_IPV6|FLOW_KEY_TYPE_NVGRE|
			      FLOW_KEY_TYPE_GENEVE,
			      0, 4, 35); //[146], would pass!!
}

static int
PORT_IPV6_NVGRE_GENEVE(void)
{
	return result_checker(FLOW_KEY_TYPE_PORT|
			      FLOW_KEY_TYPE_IPV6|FLOW_KEY_TYPE_NVGRE|
			      FLOW_KEY_TYPE_GENEVE,
			      0, 4, 37); //[145], would pass!!
}

static int
IPV6_NVGRE_GENEVE(void)
{
	return result_checker(FLOW_KEY_TYPE_IPV6|
			      FLOW_KEY_TYPE_NVGRE|FLOW_KEY_TYPE_GENEVE,
			      0, 3, 35); //[144], would pass!!
}

static int
PORT_IPV4_NVGRE_GENEVE(void)
{
	return result_checker(FLOW_KEY_TYPE_PORT|
			      FLOW_KEY_TYPE_IPV4|FLOW_KEY_TYPE_NVGRE|
			      FLOW_KEY_TYPE_GENEVE,
			      0, 4, 13); //[143], would pass!!
}

static int
IPV4_NVGRE_GENEVE(void)
{
	return result_checker(FLOW_KEY_TYPE_IPV4|
			      FLOW_KEY_TYPE_NVGRE|FLOW_KEY_TYPE_GENEVE,
			      0, 3, 11); //[142], would pass!!
}

static int
PORT_NVGRE_GENEVE(void)
{
	return result_checker(FLOW_KEY_TYPE_PORT|
			      FLOW_KEY_TYPE_NVGRE|FLOW_KEY_TYPE_GENEVE,
			      0, 3, 5); //[141], would pass!!
}

static int
NVGRE_GENEVE(void)
{
	return result_checker(FLOW_KEY_TYPE_NVGRE|
			      FLOW_KEY_TYPE_GENEVE,
			      0, 2, 3); //[140], would pass!!
}

static int
PORT_IPV4_IPV6_TCP_UDP_SCTP_GENEVE(void)
{
	return result_checker(FLOW_KEY_TYPE_PORT|
			      FLOW_KEY_TYPE_IPV4|FLOW_KEY_TYPE_IPV6|
			      FLOW_KEY_TYPE_TCP|FLOW_KEY_TYPE_UDP|
			      FLOW_KEY_TYPE_SCTP|FLOW_KEY_TYPE_GENEVE,
			      1, 5, 42); //[13f], fail
}

static int
IPV4_IPV6_TCP_UDP_SCTP_GENEVE(void)
{
	return result_checker(FLOW_KEY_TYPE_IPV4|
			      FLOW_KEY_TYPE_IPV6|FLOW_KEY_TYPE_TCP|
			      FLOW_KEY_TYPE_UDP|FLOW_KEY_TYPE_SCTP|
			      FLOW_KEY_TYPE_GENEVE,
			      0, 4, 36); //[13e], would pass!!
}

static int
PORT_IPV6_TCP_UDP_SCTP_GENEVE(void)
{
	return result_checker(FLOW_KEY_TYPE_PORT|
			      FLOW_KEY_TYPE_IPV6|FLOW_KEY_TYPE_TCP|
			      FLOW_KEY_TYPE_UDP|FLOW_KEY_TYPE_SCTP|
			      FLOW_KEY_TYPE_GENEVE,
			      1, 5, 42); //[13d], fail
}

static int
IPV6_TCP_UDP_SCTP_GENEVE(void)
{
	return result_checker(FLOW_KEY_TYPE_IPV6|
			      FLOW_KEY_TYPE_TCP|FLOW_KEY_TYPE_UDP|
			      FLOW_KEY_TYPE_SCTP|FLOW_KEY_TYPE_GENEVE,
			      0, 3, 36); //[13c], would pass!!
}

static int
PORT_IPV4_TCP_UDP_SCTP_GENEVE(void)
{
	return result_checker(FLOW_KEY_TYPE_PORT|
			      FLOW_KEY_TYPE_IPV4|FLOW_KEY_TYPE_TCP|
			      FLOW_KEY_TYPE_UDP|FLOW_KEY_TYPE_SCTP|
			      FLOW_KEY_TYPE_GENEVE,
			      0, 4, 14); //[13b], would pass!!
}

static int
IPV4_TCP_UDP_SCTP_GENEVE(void)
{
	return result_checker(FLOW_KEY_TYPE_IPV4|
			      FLOW_KEY_TYPE_TCP|FLOW_KEY_TYPE_UDP|
			      FLOW_KEY_TYPE_SCTP|FLOW_KEY_TYPE_GENEVE,
			      0, 3, 12); //[13a], would pass!!
}

static int
PORT_TCP_UDP_SCTP_GENEVE(void)
{
	return result_checker(FLOW_KEY_TYPE_PORT|
			      FLOW_KEY_TYPE_TCP|FLOW_KEY_TYPE_UDP|
			      FLOW_KEY_TYPE_SCTP|FLOW_KEY_TYPE_GENEVE,
			      0, 3, 6); //[139], would pass!!
}

static int
TCP_UDP_SCTP_GENEVE(void)
{
	return result_checker(FLOW_KEY_TYPE_TCP|
			      FLOW_KEY_TYPE_UDP|FLOW_KEY_TYPE_SCTP|
			      FLOW_KEY_TYPE_GENEVE,
			      0, 2, 4); //[138], would pass!!
}

static int
PORT_IPV4_IPV6_UDP_SCTP_GENEVE(void)
{
	return result_checker(FLOW_KEY_TYPE_PORT|
			      FLOW_KEY_TYPE_IPV4|FLOW_KEY_TYPE_IPV6|
			      FLOW_KEY_TYPE_UDP|FLOW_KEY_TYPE_SCTP|
			      FLOW_KEY_TYPE_GENEVE,
			      1, 5, 42); //[137], fail
}

static int
IPV4_IPV6_UDP_SCTP_GENEVE(void)
{
	return result_checker(FLOW_KEY_TYPE_IPV4|
			      FLOW_KEY_TYPE_IPV6|FLOW_KEY_TYPE_UDP|
			      FLOW_KEY_TYPE_SCTP|FLOW_KEY_TYPE_GENEVE,
			      0, 4, 36); //[136], would pass!!
}

static int
PORT_IPV6_UDP_SCTP_GENEVE(void)
{
	return result_checker(FLOW_KEY_TYPE_PORT|
			      FLOW_KEY_TYPE_IPV6|FLOW_KEY_TYPE_UDP|
			      FLOW_KEY_TYPE_SCTP|FLOW_KEY_TYPE_GENEVE,
			      1, 5, 42); //[135], fail
}

static int
IPV6_UDP_SCTP_GENEVE(void)
{
	return result_checker(FLOW_KEY_TYPE_IPV6|
			      FLOW_KEY_TYPE_UDP|FLOW_KEY_TYPE_SCTP|
			      FLOW_KEY_TYPE_GENEVE,
			      0, 3, 36); //[134], would pass!!
}

static int
PORT_IPV4_UDP_SCTP_GENEVE(void)
{
	return result_checker(FLOW_KEY_TYPE_PORT|
			      FLOW_KEY_TYPE_IPV4|FLOW_KEY_TYPE_UDP|
			      FLOW_KEY_TYPE_SCTP|FLOW_KEY_TYPE_GENEVE,
			      0, 4, 14); //[133], would pass!!
}

static int
IPV4_UDP_SCTP_GENEVE(void)
{
	return result_checker(FLOW_KEY_TYPE_IPV4|
			      FLOW_KEY_TYPE_UDP|FLOW_KEY_TYPE_SCTP|
			      FLOW_KEY_TYPE_GENEVE,
			      0, 3, 12); //[132], would pass!!
}

static int
PORT_UDP_SCTP_GENEVE(void)
{
	return result_checker(FLOW_KEY_TYPE_PORT|
			      FLOW_KEY_TYPE_UDP|FLOW_KEY_TYPE_SCTP|
			      FLOW_KEY_TYPE_GENEVE,
			      0, 3, 6); //[131], would pass!!
}

static int
UDP_SCTP_GENEVE(void)
{
	return result_checker(FLOW_KEY_TYPE_UDP|
			      FLOW_KEY_TYPE_SCTP|FLOW_KEY_TYPE_GENEVE,
			      0, 2, 4); //[130], would pass!!
}

static int
PORT_IPV4_IPV6_TCP_SCTP_GENEVE(void)
{
	return result_checker(FLOW_KEY_TYPE_PORT|
			      FLOW_KEY_TYPE_IPV4|FLOW_KEY_TYPE_IPV6|
			      FLOW_KEY_TYPE_TCP|FLOW_KEY_TYPE_SCTP|
			      FLOW_KEY_TYPE_GENEVE,
			      1, 5, 42); //[12f], fail
}

static int
IPV4_IPV6_TCP_SCTP_GENEVE(void)
{
	return result_checker(FLOW_KEY_TYPE_IPV4|
			      FLOW_KEY_TYPE_IPV6|FLOW_KEY_TYPE_TCP|
			      FLOW_KEY_TYPE_SCTP|FLOW_KEY_TYPE_GENEVE,
			      0, 4, 36); //[12e], would pass!!
}

static int
PORT_IPV6_TCP_SCTP_GENEVE(void)
{
	return result_checker(FLOW_KEY_TYPE_PORT|
			      FLOW_KEY_TYPE_IPV6|FLOW_KEY_TYPE_TCP|
			      FLOW_KEY_TYPE_SCTP|FLOW_KEY_TYPE_GENEVE,
			      1, 5, 42); //[12d], fail
}

static int
IPV6_TCP_SCTP_GENEVE(void)
{
	return result_checker(FLOW_KEY_TYPE_IPV6|
			      FLOW_KEY_TYPE_TCP|FLOW_KEY_TYPE_SCTP|
			      FLOW_KEY_TYPE_GENEVE,
			      0, 3, 36); //[12c], would pass!!
}

static int
PORT_IPV4_TCP_SCTP_GENEVE(void)
{
	return result_checker(FLOW_KEY_TYPE_PORT|
			      FLOW_KEY_TYPE_IPV4|FLOW_KEY_TYPE_TCP|
			      FLOW_KEY_TYPE_SCTP|FLOW_KEY_TYPE_GENEVE,
			      0, 4, 14); //[12b], would pass!!
}

static int
IPV4_TCP_SCTP_GENEVE(void)
{
	return result_checker(FLOW_KEY_TYPE_IPV4|
			      FLOW_KEY_TYPE_TCP|FLOW_KEY_TYPE_SCTP|
			      FLOW_KEY_TYPE_GENEVE,
			      0, 3, 12); //[12a], would pass!!
}

static int
PORT_TCP_SCTP_GENEVE(void)
{
	return result_checker(FLOW_KEY_TYPE_PORT|
			      FLOW_KEY_TYPE_TCP|FLOW_KEY_TYPE_SCTP|
			      FLOW_KEY_TYPE_GENEVE,
			      0, 3, 6); //[129], would pass!!
}

static int
TCP_SCTP_GENEVE(void)
{
	return result_checker(FLOW_KEY_TYPE_TCP|
			      FLOW_KEY_TYPE_SCTP|FLOW_KEY_TYPE_GENEVE,
			      0, 2, 4); //[128], would pass!!
}

static int
PORT_IPV4_IPV6_SCTP_GENEVE(void)
{
	return result_checker(FLOW_KEY_TYPE_PORT|
			      FLOW_KEY_TYPE_IPV4|FLOW_KEY_TYPE_IPV6|
			      FLOW_KEY_TYPE_SCTP|FLOW_KEY_TYPE_GENEVE,
			      1, 5, 42); //[127], fail
}

static int
IPV4_IPV6_SCTP_GENEVE(void)
{
	return result_checker(FLOW_KEY_TYPE_IPV4|
			      FLOW_KEY_TYPE_IPV6|FLOW_KEY_TYPE_SCTP|
			      FLOW_KEY_TYPE_GENEVE,
			      0, 4, 36); //[126], would pass!!
}

static int
PORT_IPV6_SCTP_GENEVE(void)
{
	return result_checker(FLOW_KEY_TYPE_PORT|
			      FLOW_KEY_TYPE_IPV6|FLOW_KEY_TYPE_SCTP|
			      FLOW_KEY_TYPE_GENEVE,
			      1, 5, 42); //[125], fail
}

static int
IPV6_SCTP_GENEVE(void)
{
	return result_checker(FLOW_KEY_TYPE_IPV6|
			      FLOW_KEY_TYPE_SCTP|FLOW_KEY_TYPE_GENEVE,
			      0, 3, 36); //[124], would pass!!
}

static int
PORT_IPV4_SCTP_GENEVE(void)
{
	return result_checker(FLOW_KEY_TYPE_PORT|
			      FLOW_KEY_TYPE_IPV4|FLOW_KEY_TYPE_SCTP|
			      FLOW_KEY_TYPE_GENEVE,
			      0, 4, 14); //[123], would pass!!
}

static int
IPV4_SCTP_GENEVE(void)
{
	return result_checker(FLOW_KEY_TYPE_IPV4|
			      FLOW_KEY_TYPE_SCTP|FLOW_KEY_TYPE_GENEVE,
			      0, 3, 12); //[122], would pass!!
}

static int
PORT_SCTP_GENEVE(void)
{
	return result_checker(FLOW_KEY_TYPE_PORT|
			      FLOW_KEY_TYPE_SCTP|FLOW_KEY_TYPE_GENEVE,
			      0, 3, 6); //[121], would pass!!
}

static int
SCTP_GENEVE(void)
{
	return result_checker(FLOW_KEY_TYPE_SCTP|
			      FLOW_KEY_TYPE_GENEVE,
			      0, 2, 4); //[120], would pass!!
}

static int
PORT_IPV4_IPV6_TCP_UDP_GENEVE(void)
{
	return result_checker(FLOW_KEY_TYPE_PORT|
			      FLOW_KEY_TYPE_IPV4|FLOW_KEY_TYPE_IPV6|
			      FLOW_KEY_TYPE_TCP|FLOW_KEY_TYPE_UDP|
			      FLOW_KEY_TYPE_GENEVE,
			      1, 5, 42); //[11f], fail
}

static int
IPV4_IPV6_TCP_UDP_GENEVE(void)
{
	return result_checker(FLOW_KEY_TYPE_IPV4|
			      FLOW_KEY_TYPE_IPV6|FLOW_KEY_TYPE_TCP|
			      FLOW_KEY_TYPE_UDP|FLOW_KEY_TYPE_GENEVE,
			      0, 4, 36); //[11e], would pass!!
}

static int
PORT_IPV6_TCP_UDP_GENEVE(void)
{
	return result_checker(FLOW_KEY_TYPE_PORT|
			      FLOW_KEY_TYPE_IPV6|FLOW_KEY_TYPE_TCP|
			      FLOW_KEY_TYPE_UDP|FLOW_KEY_TYPE_GENEVE,
			      1, 5, 42); //[11d], fail
}

static int
IPV6_TCP_UDP_GENEVE(void)
{
	return result_checker(FLOW_KEY_TYPE_IPV6|
			      FLOW_KEY_TYPE_TCP|FLOW_KEY_TYPE_UDP|
			      FLOW_KEY_TYPE_GENEVE,
			      0, 3, 36); //[11c], would pass!!
}

static int
PORT_IPV4_TCP_UDP_GENEVE(void)
{
	return result_checker(FLOW_KEY_TYPE_PORT|
			      FLOW_KEY_TYPE_IPV4|FLOW_KEY_TYPE_TCP|
			      FLOW_KEY_TYPE_UDP|FLOW_KEY_TYPE_GENEVE,
			      0, 4, 14); //[11b], would pass!!
}

static int
IPV4_TCP_UDP_GENEVE(void)
{
	return result_checker(FLOW_KEY_TYPE_IPV4|
			      FLOW_KEY_TYPE_TCP|FLOW_KEY_TYPE_UDP|
			      FLOW_KEY_TYPE_GENEVE,
			      0, 3, 12); //[11a], would pass!!
}

static int
PORT_TCP_UDP_GENEVE(void)
{
	return result_checker(FLOW_KEY_TYPE_PORT|
			      FLOW_KEY_TYPE_TCP|FLOW_KEY_TYPE_UDP|
			      FLOW_KEY_TYPE_GENEVE,
			      0, 3, 6); //[119], would pass!!
}

static int
TCP_UDP_GENEVE(void)
{
	return result_checker(FLOW_KEY_TYPE_TCP|
			      FLOW_KEY_TYPE_UDP|FLOW_KEY_TYPE_GENEVE,
			      0, 2, 4); //[118], would pass!!
}

static int
PORT_IPV4_IPV6_UDP_GENEVE(void)
{
	return result_checker(FLOW_KEY_TYPE_PORT|
			      FLOW_KEY_TYPE_IPV4|FLOW_KEY_TYPE_IPV6|
			      FLOW_KEY_TYPE_UDP|FLOW_KEY_TYPE_GENEVE,
			      1, 5, 42); //[117], fail
}

static int
IPV4_IPV6_UDP_GENEVE(void)
{
	return result_checker(FLOW_KEY_TYPE_IPV4|
			      FLOW_KEY_TYPE_IPV6|FLOW_KEY_TYPE_UDP|
			      FLOW_KEY_TYPE_GENEVE,
			      0, 4, 36); //[116], would pass!!
}

static int
PORT_IPV6_UDP_GENEVE(void)
{
	return result_checker(FLOW_KEY_TYPE_PORT|
			      FLOW_KEY_TYPE_IPV6|FLOW_KEY_TYPE_UDP|
			      FLOW_KEY_TYPE_GENEVE,
			      1, 5, 42); //[115], fail
}

static int
IPV6_UDP_GENEVE(void)
{
	return result_checker(FLOW_KEY_TYPE_IPV6|
			      FLOW_KEY_TYPE_UDP|FLOW_KEY_TYPE_GENEVE,
			      0, 3, 36); //[114], would pass!!
}

static int
PORT_IPV4_UDP_GENEVE(void)
{
	return result_checker(FLOW_KEY_TYPE_PORT|
			      FLOW_KEY_TYPE_IPV4|FLOW_KEY_TYPE_UDP|
			      FLOW_KEY_TYPE_GENEVE,
			      0, 4, 14); //[113], would pass!!
}

static int
IPV4_UDP_GENEVE(void)
{
	return result_checker(FLOW_KEY_TYPE_IPV4|
			      FLOW_KEY_TYPE_UDP|FLOW_KEY_TYPE_GENEVE,
			      0, 3, 12); //[112], would pass!!
}

static int
PORT_UDP_GENEVE(void)
{
	return result_checker(FLOW_KEY_TYPE_PORT|
			      FLOW_KEY_TYPE_UDP|FLOW_KEY_TYPE_GENEVE,
			      0, 3, 6); //[111], would pass!!
}

static int
UDP_GENEVE(void)
{
	return result_checker(FLOW_KEY_TYPE_UDP|
			      FLOW_KEY_TYPE_GENEVE,
			      0, 2, 4); //[110], would pass!!
}

static int
PORT_IPV4_IPV6_TCP_GENEVE(void)
{
	return result_checker(FLOW_KEY_TYPE_PORT|
			      FLOW_KEY_TYPE_IPV4|FLOW_KEY_TYPE_IPV6|
			      FLOW_KEY_TYPE_TCP|FLOW_KEY_TYPE_GENEVE,
			      1, 5, 42); //[10f], fail
}

static int
IPV4_IPV6_TCP_GENEVE(void)
{
	return result_checker(FLOW_KEY_TYPE_IPV4|
			      FLOW_KEY_TYPE_IPV6|FLOW_KEY_TYPE_TCP|
			      FLOW_KEY_TYPE_GENEVE,
			      0, 4, 36); //[10e], would pass!!
}

static int
PORT_IPV6_TCP_GENEVE(void)
{
	return result_checker(FLOW_KEY_TYPE_PORT|
			      FLOW_KEY_TYPE_IPV6|FLOW_KEY_TYPE_TCP|
			      FLOW_KEY_TYPE_GENEVE,
			      1, 5, 42); //[10d], fail
}

static int
IPV6_TCP_GENEVE(void)
{
	return result_checker(FLOW_KEY_TYPE_IPV6|
			      FLOW_KEY_TYPE_TCP|FLOW_KEY_TYPE_GENEVE,
			      0, 3, 36); //[10c], would pass!!
}

static int
PORT_IPV4_TCP_GENEVE(void)
{
	return result_checker(FLOW_KEY_TYPE_PORT|
			      FLOW_KEY_TYPE_IPV4|FLOW_KEY_TYPE_TCP|
			      FLOW_KEY_TYPE_GENEVE,
			      0, 4, 14); //[10b], would pass!!
}

static int
IPV4_TCP_GENEVE(void)
{
	return result_checker(FLOW_KEY_TYPE_IPV4|
			      FLOW_KEY_TYPE_TCP|FLOW_KEY_TYPE_GENEVE,
			      0, 3, 12); //[10a], would pass!!
}

static int
PORT_TCP_GENEVE(void)
{
	return result_checker(FLOW_KEY_TYPE_PORT|
			      FLOW_KEY_TYPE_TCP|FLOW_KEY_TYPE_GENEVE,
			      0, 3, 6); //[109], would pass!!
}

static int
TCP_GENEVE(void)
{
	return result_checker(FLOW_KEY_TYPE_TCP|
			      FLOW_KEY_TYPE_GENEVE,
			      0, 2, 4); //[108], would pass!!
}

static int
PORT_IPV4_IPV6_GENEVE(void)
{
	return result_checker(FLOW_KEY_TYPE_PORT|
			      FLOW_KEY_TYPE_IPV4|FLOW_KEY_TYPE_IPV6|
			      FLOW_KEY_TYPE_GENEVE,
			      0, 4, 34); //[107], would pass!!
}

static int
IPV4_IPV6_GENEVE(void)
{
	return result_checker(FLOW_KEY_TYPE_IPV4|
			      FLOW_KEY_TYPE_IPV6|FLOW_KEY_TYPE_GENEVE,
			      0, 3, 32); //[106], would pass!!
}

static int
PORT_IPV6_GENEVE(void)
{
	return result_checker(FLOW_KEY_TYPE_PORT|
			      FLOW_KEY_TYPE_IPV6|FLOW_KEY_TYPE_GENEVE,
			      0, 3, 34); //[105], would pass!!
}

static int
IPV6_GENEVE(void)
{
	return result_checker(FLOW_KEY_TYPE_IPV6|
			      FLOW_KEY_TYPE_GENEVE,
			      0, 2, 32); //[104], would pass!!
}

static int
PORT_IPV4_GENEVE(void)
{
	return result_checker(FLOW_KEY_TYPE_PORT|
			      FLOW_KEY_TYPE_IPV4|FLOW_KEY_TYPE_GENEVE,
			      0, 3, 10); //[103], would pass!!
}

static int
IPV4_GENEVE(void)
{
	return result_checker(FLOW_KEY_TYPE_IPV4|
			      FLOW_KEY_TYPE_GENEVE,
			      0, 2, 8); //[102], would pass!!
}

static int
PORT_GENEVE(void)
{
	return result_checker(FLOW_KEY_TYPE_PORT|
			      FLOW_KEY_TYPE_GENEVE,
			      0, 2, 2); //[101], would pass!!
}

static int
GENEVE(void)
{
	return result_checker(FLOW_KEY_TYPE_GENEVE,
			      0, 1, 0); //[100], would pass!!
}

static int
PORT_IPV4_IPV6_TCP_UDP_SCTP_NVGRE_VXLAN(void)
{
	return result_checker(FLOW_KEY_TYPE_PORT|
			      FLOW_KEY_TYPE_IPV4|FLOW_KEY_TYPE_IPV6|
			      FLOW_KEY_TYPE_TCP|FLOW_KEY_TYPE_UDP|
			      FLOW_KEY_TYPE_SCTP|FLOW_KEY_TYPE_NVGRE|
			      FLOW_KEY_TYPE_VXLAN,
			      1, 5, 42); //[ff], fail
}

static int
IPV4_IPV6_TCP_UDP_SCTP_NVGRE_VXLAN(void)
{
	return result_checker(FLOW_KEY_TYPE_IPV4|
			      FLOW_KEY_TYPE_IPV6|FLOW_KEY_TYPE_TCP|
			      FLOW_KEY_TYPE_UDP|FLOW_KEY_TYPE_SCTP|
			      FLOW_KEY_TYPE_NVGRE|FLOW_KEY_TYPE_VXLAN,
			      1, 5, 42); //[fe], fail
}

static int
PORT_IPV6_TCP_UDP_SCTP_NVGRE_VXLAN(void)
{
	return result_checker(FLOW_KEY_TYPE_PORT|
			      FLOW_KEY_TYPE_IPV6|FLOW_KEY_TYPE_TCP|
			      FLOW_KEY_TYPE_UDP|FLOW_KEY_TYPE_SCTP|
			      FLOW_KEY_TYPE_NVGRE|FLOW_KEY_TYPE_VXLAN,
			      1, 5, 42); //[fd], fail
}

static int
IPV6_TCP_UDP_SCTP_NVGRE_VXLAN(void)
{
	return result_checker(FLOW_KEY_TYPE_IPV6|
			      FLOW_KEY_TYPE_TCP|FLOW_KEY_TYPE_UDP|
			      FLOW_KEY_TYPE_SCTP|FLOW_KEY_TYPE_NVGRE|
			      FLOW_KEY_TYPE_VXLAN,
			      1, 5, 42); //[fc], fail
}

static int
PORT_IPV4_TCP_UDP_SCTP_NVGRE_VXLAN(void)
{
	return result_checker(FLOW_KEY_TYPE_PORT|
			      FLOW_KEY_TYPE_IPV4|FLOW_KEY_TYPE_TCP|
			      FLOW_KEY_TYPE_UDP|FLOW_KEY_TYPE_SCTP|
			      FLOW_KEY_TYPE_NVGRE|FLOW_KEY_TYPE_VXLAN,
			      0, 5, 17); //[fb], would pass!!
}

static int
IPV4_TCP_UDP_SCTP_NVGRE_VXLAN(void)
{
	return result_checker(FLOW_KEY_TYPE_IPV4|
			      FLOW_KEY_TYPE_TCP|FLOW_KEY_TYPE_UDP|
			      FLOW_KEY_TYPE_SCTP|FLOW_KEY_TYPE_NVGRE|
			      FLOW_KEY_TYPE_VXLAN,
			      0, 4, 15); //[fa], would pass!!
}

static int
PORT_TCP_UDP_SCTP_NVGRE_VXLAN(void)
{
	return result_checker(FLOW_KEY_TYPE_PORT|
			      FLOW_KEY_TYPE_TCP|FLOW_KEY_TYPE_UDP|
			      FLOW_KEY_TYPE_SCTP|FLOW_KEY_TYPE_NVGRE|
			      FLOW_KEY_TYPE_VXLAN,
			      0, 4, 9); //[f9], would pass!!
}

static int
TCP_UDP_SCTP_NVGRE_VXLAN(void)
{
	return result_checker(FLOW_KEY_TYPE_TCP|
			      FLOW_KEY_TYPE_UDP|FLOW_KEY_TYPE_SCTP|
			      FLOW_KEY_TYPE_NVGRE|FLOW_KEY_TYPE_VXLAN,
			      0, 3, 7); //[f8], would pass!!
}

static int
PORT_IPV4_IPV6_UDP_SCTP_NVGRE_VXLAN(void)
{
	return result_checker(FLOW_KEY_TYPE_PORT|
			      FLOW_KEY_TYPE_IPV4|FLOW_KEY_TYPE_IPV6|
			      FLOW_KEY_TYPE_UDP|FLOW_KEY_TYPE_SCTP|
			      FLOW_KEY_TYPE_NVGRE|FLOW_KEY_TYPE_VXLAN,
			      1, 5, 42); //[f7], fail
}

static int
IPV4_IPV6_UDP_SCTP_NVGRE_VXLAN(void)
{
	return result_checker(FLOW_KEY_TYPE_IPV4|
			      FLOW_KEY_TYPE_IPV6|FLOW_KEY_TYPE_UDP|
			      FLOW_KEY_TYPE_SCTP|FLOW_KEY_TYPE_NVGRE|
			      FLOW_KEY_TYPE_VXLAN,
			      1, 5, 42); //[f6], fail
}

static int
PORT_IPV6_UDP_SCTP_NVGRE_VXLAN(void)
{
	return result_checker(FLOW_KEY_TYPE_PORT|
			      FLOW_KEY_TYPE_IPV6|FLOW_KEY_TYPE_UDP|
			      FLOW_KEY_TYPE_SCTP|FLOW_KEY_TYPE_NVGRE|
			      FLOW_KEY_TYPE_VXLAN,
			      1, 5, 42); //[f5], fail
}

static int
IPV6_UDP_SCTP_NVGRE_VXLAN(void)
{
	return result_checker(FLOW_KEY_TYPE_IPV6|
			      FLOW_KEY_TYPE_UDP|FLOW_KEY_TYPE_SCTP|
			      FLOW_KEY_TYPE_NVGRE|FLOW_KEY_TYPE_VXLAN,
			      1, 5, 42); //[f4], fail
}

static int
PORT_IPV4_UDP_SCTP_NVGRE_VXLAN(void)
{
	return result_checker(FLOW_KEY_TYPE_PORT|
			      FLOW_KEY_TYPE_IPV4|FLOW_KEY_TYPE_UDP|
			      FLOW_KEY_TYPE_SCTP|FLOW_KEY_TYPE_NVGRE|
			      FLOW_KEY_TYPE_VXLAN,
			      0, 5, 17); //[f3], would pass!!
}

static int
IPV4_UDP_SCTP_NVGRE_VXLAN(void)
{
	return result_checker(FLOW_KEY_TYPE_IPV4|
			      FLOW_KEY_TYPE_UDP|FLOW_KEY_TYPE_SCTP|
			      FLOW_KEY_TYPE_NVGRE|FLOW_KEY_TYPE_VXLAN,
			      0, 4, 15); //[f2], would pass!!
}

static int
PORT_UDP_SCTP_NVGRE_VXLAN(void)
{
	return result_checker(FLOW_KEY_TYPE_PORT|
			      FLOW_KEY_TYPE_UDP|FLOW_KEY_TYPE_SCTP|
			      FLOW_KEY_TYPE_NVGRE|FLOW_KEY_TYPE_VXLAN,
			      0, 4, 9); //[f1], would pass!!
}

static int
UDP_SCTP_NVGRE_VXLAN(void)
{
	return result_checker(FLOW_KEY_TYPE_UDP|
			      FLOW_KEY_TYPE_SCTP|FLOW_KEY_TYPE_NVGRE|
			      FLOW_KEY_TYPE_VXLAN,
			      0, 3, 7); //[f0], would pass!!
}

static int
PORT_IPV4_IPV6_TCP_SCTP_NVGRE_VXLAN(void)
{
	return result_checker(FLOW_KEY_TYPE_PORT|
			      FLOW_KEY_TYPE_IPV4|FLOW_KEY_TYPE_IPV6|
			      FLOW_KEY_TYPE_TCP|FLOW_KEY_TYPE_SCTP|
			      FLOW_KEY_TYPE_NVGRE|FLOW_KEY_TYPE_VXLAN,
			      1, 5, 42); //[ef], fail
}

static int
IPV4_IPV6_TCP_SCTP_NVGRE_VXLAN(void)
{
	return result_checker(FLOW_KEY_TYPE_IPV4|
			      FLOW_KEY_TYPE_IPV6|FLOW_KEY_TYPE_TCP|
			      FLOW_KEY_TYPE_SCTP|FLOW_KEY_TYPE_NVGRE|
			      FLOW_KEY_TYPE_VXLAN,
			      1, 5, 42); //[ee], fail
}

static int
PORT_IPV6_TCP_SCTP_NVGRE_VXLAN(void)
{
	return result_checker(FLOW_KEY_TYPE_PORT|
			      FLOW_KEY_TYPE_IPV6|FLOW_KEY_TYPE_TCP|
			      FLOW_KEY_TYPE_SCTP|FLOW_KEY_TYPE_NVGRE|
			      FLOW_KEY_TYPE_VXLAN,
			      1, 5, 42); //[ed], fail
}

static int
IPV6_TCP_SCTP_NVGRE_VXLAN(void)
{
	return result_checker(FLOW_KEY_TYPE_IPV6|
			      FLOW_KEY_TYPE_TCP|FLOW_KEY_TYPE_SCTP|
			      FLOW_KEY_TYPE_NVGRE|FLOW_KEY_TYPE_VXLAN,
			      1, 5, 42); //[ec], fail
}

static int
PORT_IPV4_TCP_SCTP_NVGRE_VXLAN(void)
{
	return result_checker(FLOW_KEY_TYPE_PORT|
			      FLOW_KEY_TYPE_IPV4|FLOW_KEY_TYPE_TCP|
			      FLOW_KEY_TYPE_SCTP|FLOW_KEY_TYPE_NVGRE|
			      FLOW_KEY_TYPE_VXLAN,
			      0, 5, 17); //[eb], would pass!!
}

static int
IPV4_TCP_SCTP_NVGRE_VXLAN(void)
{
	return result_checker(FLOW_KEY_TYPE_IPV4|
			      FLOW_KEY_TYPE_TCP|FLOW_KEY_TYPE_SCTP|
			      FLOW_KEY_TYPE_NVGRE|FLOW_KEY_TYPE_VXLAN,
			      0, 4, 15); //[ea], would pass!!
}

static int
PORT_TCP_SCTP_NVGRE_VXLAN(void)
{
	return result_checker(FLOW_KEY_TYPE_PORT|
			      FLOW_KEY_TYPE_TCP|FLOW_KEY_TYPE_SCTP|
			      FLOW_KEY_TYPE_NVGRE|FLOW_KEY_TYPE_VXLAN,
			      0, 4, 9); //[e9], would pass!!
}

static int
TCP_SCTP_NVGRE_VXLAN(void)
{
	return result_checker(FLOW_KEY_TYPE_TCP|
			      FLOW_KEY_TYPE_SCTP|FLOW_KEY_TYPE_NVGRE|
			      FLOW_KEY_TYPE_VXLAN,
			      0, 3, 7); //[e8], would pass!!
}

static int
PORT_IPV4_IPV6_SCTP_NVGRE_VXLAN(void)
{
	return result_checker(FLOW_KEY_TYPE_PORT|
			      FLOW_KEY_TYPE_IPV4|FLOW_KEY_TYPE_IPV6|
			      FLOW_KEY_TYPE_SCTP|FLOW_KEY_TYPE_NVGRE|
			      FLOW_KEY_TYPE_VXLAN,
			      1, 5, 42); //[e7], fail
}

static int
IPV4_IPV6_SCTP_NVGRE_VXLAN(void)
{
	return result_checker(FLOW_KEY_TYPE_IPV4|
			      FLOW_KEY_TYPE_IPV6|FLOW_KEY_TYPE_SCTP|
			      FLOW_KEY_TYPE_NVGRE|FLOW_KEY_TYPE_VXLAN,
			      1, 5, 42); //[e6], fail
}

static int
PORT_IPV6_SCTP_NVGRE_VXLAN(void)
{
	return result_checker(FLOW_KEY_TYPE_PORT|
			      FLOW_KEY_TYPE_IPV6|FLOW_KEY_TYPE_SCTP|
			      FLOW_KEY_TYPE_NVGRE|FLOW_KEY_TYPE_VXLAN,
			      1, 5, 42); //[e5], fail
}

static int
IPV6_SCTP_NVGRE_VXLAN(void)
{
	return result_checker(FLOW_KEY_TYPE_IPV6|
			      FLOW_KEY_TYPE_SCTP|FLOW_KEY_TYPE_NVGRE|
			      FLOW_KEY_TYPE_VXLAN,
			      1, 5, 42); //[e4], fail
}

static int
PORT_IPV4_SCTP_NVGRE_VXLAN(void)
{
	return result_checker(FLOW_KEY_TYPE_PORT|
			      FLOW_KEY_TYPE_IPV4|FLOW_KEY_TYPE_SCTP|
			      FLOW_KEY_TYPE_NVGRE|FLOW_KEY_TYPE_VXLAN,
			      0, 5, 17); //[e3], would pass!!
}

static int
IPV4_SCTP_NVGRE_VXLAN(void)
{
	return result_checker(FLOW_KEY_TYPE_IPV4|
			      FLOW_KEY_TYPE_SCTP|FLOW_KEY_TYPE_NVGRE|
			      FLOW_KEY_TYPE_VXLAN,
			      0, 4, 15); //[e2], would pass!!
}

static int
PORT_SCTP_NVGRE_VXLAN(void)
{
	return result_checker(FLOW_KEY_TYPE_PORT|
			      FLOW_KEY_TYPE_SCTP|FLOW_KEY_TYPE_NVGRE|
			      FLOW_KEY_TYPE_VXLAN,
			      0, 4, 9); //[e1], would pass!!
}

static int
SCTP_NVGRE_VXLAN(void)
{
	return result_checker(FLOW_KEY_TYPE_SCTP|
			      FLOW_KEY_TYPE_NVGRE|FLOW_KEY_TYPE_VXLAN,
			      0, 3, 7); //[e0], would pass!!
}

static int
PORT_IPV4_IPV6_TCP_UDP_NVGRE_VXLAN(void)
{
	return result_checker(FLOW_KEY_TYPE_PORT|
			      FLOW_KEY_TYPE_IPV4|FLOW_KEY_TYPE_IPV6|
			      FLOW_KEY_TYPE_TCP|FLOW_KEY_TYPE_UDP|
			      FLOW_KEY_TYPE_NVGRE|FLOW_KEY_TYPE_VXLAN,
			      1, 5, 42); //[df], fail
}

static int
IPV4_IPV6_TCP_UDP_NVGRE_VXLAN(void)
{
	return result_checker(FLOW_KEY_TYPE_IPV4|
			      FLOW_KEY_TYPE_IPV6|FLOW_KEY_TYPE_TCP|
			      FLOW_KEY_TYPE_UDP|FLOW_KEY_TYPE_NVGRE|
			      FLOW_KEY_TYPE_VXLAN,
			      1, 5, 42); //[de], fail
}

static int
PORT_IPV6_TCP_UDP_NVGRE_VXLAN(void)
{
	return result_checker(FLOW_KEY_TYPE_PORT|
			      FLOW_KEY_TYPE_IPV6|FLOW_KEY_TYPE_TCP|
			      FLOW_KEY_TYPE_UDP|FLOW_KEY_TYPE_NVGRE|
			      FLOW_KEY_TYPE_VXLAN,
			      1, 5, 42); //[dd], fail
}

static int
IPV6_TCP_UDP_NVGRE_VXLAN(void)
{
	return result_checker(FLOW_KEY_TYPE_IPV6|
			      FLOW_KEY_TYPE_TCP|FLOW_KEY_TYPE_UDP|
			      FLOW_KEY_TYPE_NVGRE|FLOW_KEY_TYPE_VXLAN,
			      1, 5, 42); //[dc], fail
}

static int
PORT_IPV4_TCP_UDP_NVGRE_VXLAN(void)
{
	return result_checker(FLOW_KEY_TYPE_PORT|
			      FLOW_KEY_TYPE_IPV4|FLOW_KEY_TYPE_TCP|
			      FLOW_KEY_TYPE_UDP|FLOW_KEY_TYPE_NVGRE|
			      FLOW_KEY_TYPE_VXLAN,
			      0, 5, 17); //[db], would pass!!
}

static int
IPV4_TCP_UDP_NVGRE_VXLAN(void)
{
	return result_checker(FLOW_KEY_TYPE_IPV4|
			      FLOW_KEY_TYPE_TCP|FLOW_KEY_TYPE_UDP|
			      FLOW_KEY_TYPE_NVGRE|FLOW_KEY_TYPE_VXLAN,
			      0, 4, 15); //[da], would pass!!
}

static int
PORT_TCP_UDP_NVGRE_VXLAN(void)
{
	return result_checker(FLOW_KEY_TYPE_PORT|
			      FLOW_KEY_TYPE_TCP|FLOW_KEY_TYPE_UDP|
			      FLOW_KEY_TYPE_NVGRE|FLOW_KEY_TYPE_VXLAN,
			      0, 4, 9); //[d9], would pass!!
}

static int
TCP_UDP_NVGRE_VXLAN(void)
{
	return result_checker(FLOW_KEY_TYPE_TCP|
			      FLOW_KEY_TYPE_UDP|FLOW_KEY_TYPE_NVGRE|
			      FLOW_KEY_TYPE_VXLAN,
			      0, 3, 7); //[d8], would pass!!
}

static int
PORT_IPV4_IPV6_UDP_NVGRE_VXLAN(void)
{
	return result_checker(FLOW_KEY_TYPE_PORT|
			      FLOW_KEY_TYPE_IPV4|FLOW_KEY_TYPE_IPV6|
			      FLOW_KEY_TYPE_UDP|FLOW_KEY_TYPE_NVGRE|
			      FLOW_KEY_TYPE_VXLAN,
			      1, 5, 42); //[d7], fail
}

static int
IPV4_IPV6_UDP_NVGRE_VXLAN(void)
{
	return result_checker(FLOW_KEY_TYPE_IPV4|
			      FLOW_KEY_TYPE_IPV6|FLOW_KEY_TYPE_UDP|
			      FLOW_KEY_TYPE_NVGRE|FLOW_KEY_TYPE_VXLAN,
			      1, 5, 42); //[d6], fail
}

static int
PORT_IPV6_UDP_NVGRE_VXLAN(void)
{
	return result_checker(FLOW_KEY_TYPE_PORT|
			      FLOW_KEY_TYPE_IPV6|FLOW_KEY_TYPE_UDP|
			      FLOW_KEY_TYPE_NVGRE|FLOW_KEY_TYPE_VXLAN,
			      1, 5, 42); //[d5], fail
}

static int
IPV6_UDP_NVGRE_VXLAN(void)
{
	return result_checker(FLOW_KEY_TYPE_IPV6|
			      FLOW_KEY_TYPE_UDP|FLOW_KEY_TYPE_NVGRE|
			      FLOW_KEY_TYPE_VXLAN,
			      1, 5, 42); //[d4], fail
}

static int
PORT_IPV4_UDP_NVGRE_VXLAN(void)
{
	return result_checker(FLOW_KEY_TYPE_PORT|
			      FLOW_KEY_TYPE_IPV4|FLOW_KEY_TYPE_UDP|
			      FLOW_KEY_TYPE_NVGRE|FLOW_KEY_TYPE_VXLAN,
			      0, 5, 17); //[d3], would pass!!
}

static int
IPV4_UDP_NVGRE_VXLAN(void)
{
	return result_checker(FLOW_KEY_TYPE_IPV4|
			      FLOW_KEY_TYPE_UDP|FLOW_KEY_TYPE_NVGRE|
			      FLOW_KEY_TYPE_VXLAN,
			      0, 4, 15); //[d2], would pass!!
}

static int
PORT_UDP_NVGRE_VXLAN(void)
{
	return result_checker(FLOW_KEY_TYPE_PORT|
			      FLOW_KEY_TYPE_UDP|FLOW_KEY_TYPE_NVGRE|
			      FLOW_KEY_TYPE_VXLAN,
			      0, 4, 9); //[d1], would pass!!
}

static int
UDP_NVGRE_VXLAN(void)
{
	return result_checker(FLOW_KEY_TYPE_UDP|
			      FLOW_KEY_TYPE_NVGRE|FLOW_KEY_TYPE_VXLAN,
			      0, 3, 7); //[d0], would pass!!
}

static int
PORT_IPV4_IPV6_TCP_NVGRE_VXLAN(void)
{
	return result_checker(FLOW_KEY_TYPE_PORT|
			      FLOW_KEY_TYPE_IPV4|FLOW_KEY_TYPE_IPV6|
			      FLOW_KEY_TYPE_TCP|FLOW_KEY_TYPE_NVGRE|
			      FLOW_KEY_TYPE_VXLAN,
			      1, 5, 42); //[cf], fail
}

static int
IPV4_IPV6_TCP_NVGRE_VXLAN(void)
{
	return result_checker(FLOW_KEY_TYPE_IPV4|
			      FLOW_KEY_TYPE_IPV6|FLOW_KEY_TYPE_TCP|
			      FLOW_KEY_TYPE_NVGRE|FLOW_KEY_TYPE_VXLAN,
			      1, 5, 42); //[ce], fail
}

static int
PORT_IPV6_TCP_NVGRE_VXLAN(void)
{
	return result_checker(FLOW_KEY_TYPE_PORT|
			      FLOW_KEY_TYPE_IPV6|FLOW_KEY_TYPE_TCP|
			      FLOW_KEY_TYPE_NVGRE|FLOW_KEY_TYPE_VXLAN,
			      1, 5, 42); //[cd], fail
}

static int
IPV6_TCP_NVGRE_VXLAN(void)
{
	return result_checker(FLOW_KEY_TYPE_IPV6|
			      FLOW_KEY_TYPE_TCP|FLOW_KEY_TYPE_NVGRE|
			      FLOW_KEY_TYPE_VXLAN,
			      1, 5, 42); //[cc], fail
}

static int
PORT_IPV4_TCP_NVGRE_VXLAN(void)
{
	return result_checker(FLOW_KEY_TYPE_PORT|
			      FLOW_KEY_TYPE_IPV4|FLOW_KEY_TYPE_TCP|
			      FLOW_KEY_TYPE_NVGRE|FLOW_KEY_TYPE_VXLAN,
			      0, 5, 17); //[cb], would pass!!
}

static int
IPV4_TCP_NVGRE_VXLAN(void)
{
	return result_checker(FLOW_KEY_TYPE_IPV4|
			      FLOW_KEY_TYPE_TCP|FLOW_KEY_TYPE_NVGRE|
			      FLOW_KEY_TYPE_VXLAN,
			      0, 4, 15); //[ca], would pass!!
}

static int
PORT_TCP_NVGRE_VXLAN(void)
{
	return result_checker(FLOW_KEY_TYPE_PORT|
			      FLOW_KEY_TYPE_TCP|FLOW_KEY_TYPE_NVGRE|
			      FLOW_KEY_TYPE_VXLAN,
			      0, 4, 9); //[c9], would pass!!
}

static int
TCP_NVGRE_VXLAN(void)
{
	return result_checker(FLOW_KEY_TYPE_TCP|
			      FLOW_KEY_TYPE_NVGRE|FLOW_KEY_TYPE_VXLAN,
			      0, 3, 7); //[c8], would pass!!
}

static int
PORT_IPV4_IPV6_NVGRE_VXLAN(void)
{
	return result_checker(FLOW_KEY_TYPE_PORT|
			      FLOW_KEY_TYPE_IPV4|FLOW_KEY_TYPE_IPV6|
			      FLOW_KEY_TYPE_NVGRE|FLOW_KEY_TYPE_VXLAN,
			      0, 5, 37); //[c7], would pass!!
}

static int
IPV4_IPV6_NVGRE_VXLAN(void)
{
	return result_checker(FLOW_KEY_TYPE_IPV4|
			      FLOW_KEY_TYPE_IPV6|FLOW_KEY_TYPE_NVGRE|
			      FLOW_KEY_TYPE_VXLAN,
			      0, 4, 35); //[c6], would pass!!
}

static int
PORT_IPV6_NVGRE_VXLAN(void)
{
	return result_checker(FLOW_KEY_TYPE_PORT|
			      FLOW_KEY_TYPE_IPV6|FLOW_KEY_TYPE_NVGRE|
			      FLOW_KEY_TYPE_VXLAN,
			      0, 4, 37); //[c5], would pass!!
}

static int
IPV6_NVGRE_VXLAN(void)
{
	return result_checker(FLOW_KEY_TYPE_IPV6|
			      FLOW_KEY_TYPE_NVGRE|FLOW_KEY_TYPE_VXLAN,
			      0, 3, 35); //[c4], would pass!!
}

static int
PORT_IPV4_NVGRE_VXLAN(void)
{
	return result_checker(FLOW_KEY_TYPE_PORT|
			      FLOW_KEY_TYPE_IPV4|FLOW_KEY_TYPE_NVGRE|
			      FLOW_KEY_TYPE_VXLAN,
			      0, 4, 13); //[c3], would pass!!
}

static int
IPV4_NVGRE_VXLAN(void)
{
	return result_checker(FLOW_KEY_TYPE_IPV4|
			      FLOW_KEY_TYPE_NVGRE|FLOW_KEY_TYPE_VXLAN,
			      0, 3, 11); //[c2], would pass!!
}

static int
PORT_NVGRE_VXLAN(void)
{
	return result_checker(FLOW_KEY_TYPE_PORT|
			      FLOW_KEY_TYPE_NVGRE|FLOW_KEY_TYPE_VXLAN,
			      0, 3, 5); //[c1], would pass!!
}

static int
NVGRE_VXLAN(void)
{
	return result_checker(FLOW_KEY_TYPE_NVGRE|
			      FLOW_KEY_TYPE_VXLAN,
			      0, 2, 3); //[c0], would pass!!
}

static int
PORT_IPV4_IPV6_TCP_UDP_SCTP_VXLAN(void)
{
	return result_checker(FLOW_KEY_TYPE_PORT|
			      FLOW_KEY_TYPE_IPV4|FLOW_KEY_TYPE_IPV6|
			      FLOW_KEY_TYPE_TCP|FLOW_KEY_TYPE_UDP|
			      FLOW_KEY_TYPE_SCTP|FLOW_KEY_TYPE_VXLAN,
			      1, 5, 42); //[bf], fail
}

static int
IPV4_IPV6_TCP_UDP_SCTP_VXLAN(void)
{
	return result_checker(FLOW_KEY_TYPE_IPV4|
			      FLOW_KEY_TYPE_IPV6|FLOW_KEY_TYPE_TCP|
			      FLOW_KEY_TYPE_UDP|FLOW_KEY_TYPE_SCTP|
			      FLOW_KEY_TYPE_VXLAN,
			      0, 4, 36); //[be], would pass!!
}

static int
PORT_IPV6_TCP_UDP_SCTP_VXLAN(void)
{
	return result_checker(FLOW_KEY_TYPE_PORT|
			      FLOW_KEY_TYPE_IPV6|FLOW_KEY_TYPE_TCP|
			      FLOW_KEY_TYPE_UDP|FLOW_KEY_TYPE_SCTP|
			      FLOW_KEY_TYPE_VXLAN,
			      1, 5, 42); //[bd], fail
}

static int
IPV6_TCP_UDP_SCTP_VXLAN(void)
{
	return result_checker(FLOW_KEY_TYPE_IPV6|
			      FLOW_KEY_TYPE_TCP|FLOW_KEY_TYPE_UDP|
			      FLOW_KEY_TYPE_SCTP|FLOW_KEY_TYPE_VXLAN,
			      0, 3, 36); //[bc], would pass!!
}

static int
PORT_IPV4_TCP_UDP_SCTP_VXLAN(void)
{
	return result_checker(FLOW_KEY_TYPE_PORT|
			      FLOW_KEY_TYPE_IPV4|FLOW_KEY_TYPE_TCP|
			      FLOW_KEY_TYPE_UDP|FLOW_KEY_TYPE_SCTP|
			      FLOW_KEY_TYPE_VXLAN,
			      0, 4, 14); //[bb], would pass!!
}

static int
IPV4_TCP_UDP_SCTP_VXLAN(void)
{
	return result_checker(FLOW_KEY_TYPE_IPV4|
			      FLOW_KEY_TYPE_TCP|FLOW_KEY_TYPE_UDP|
			      FLOW_KEY_TYPE_SCTP|FLOW_KEY_TYPE_VXLAN,
			      0, 3, 12); //[ba], would pass!!
}

static int
PORT_TCP_UDP_SCTP_VXLAN(void)
{
	return result_checker(FLOW_KEY_TYPE_PORT|
			      FLOW_KEY_TYPE_TCP|FLOW_KEY_TYPE_UDP|
			      FLOW_KEY_TYPE_SCTP|FLOW_KEY_TYPE_VXLAN,
			      0, 3, 6); //[b9], would pass!!
}

static int
TCP_UDP_SCTP_VXLAN(void)
{
	return result_checker(FLOW_KEY_TYPE_TCP|
			      FLOW_KEY_TYPE_UDP|FLOW_KEY_TYPE_SCTP|
			      FLOW_KEY_TYPE_VXLAN,
			      0, 2, 4); //[b8], would pass!!
}

static int
PORT_IPV4_IPV6_UDP_SCTP_VXLAN(void)
{
	return result_checker(FLOW_KEY_TYPE_PORT|
			      FLOW_KEY_TYPE_IPV4|FLOW_KEY_TYPE_IPV6|
			      FLOW_KEY_TYPE_UDP|FLOW_KEY_TYPE_SCTP|
			      FLOW_KEY_TYPE_VXLAN,
			      1, 5, 42); //[b7], fail
}

static int
IPV4_IPV6_UDP_SCTP_VXLAN(void)
{
	return result_checker(FLOW_KEY_TYPE_IPV4|
			      FLOW_KEY_TYPE_IPV6|FLOW_KEY_TYPE_UDP|
			      FLOW_KEY_TYPE_SCTP|FLOW_KEY_TYPE_VXLAN,
			      0, 4, 36); //[b6], would pass!!
}

static int
PORT_IPV6_UDP_SCTP_VXLAN(void)
{
	return result_checker(FLOW_KEY_TYPE_PORT|
			      FLOW_KEY_TYPE_IPV6|FLOW_KEY_TYPE_UDP|
			      FLOW_KEY_TYPE_SCTP|FLOW_KEY_TYPE_VXLAN,
			      1, 5, 42); //[b5], fail
}

static int
IPV6_UDP_SCTP_VXLAN(void)
{
	return result_checker(FLOW_KEY_TYPE_IPV6|
			      FLOW_KEY_TYPE_UDP|FLOW_KEY_TYPE_SCTP|
			      FLOW_KEY_TYPE_VXLAN,
			      0, 3, 36); //[b4], would pass!!
}

static int
PORT_IPV4_UDP_SCTP_VXLAN(void)
{
	return result_checker(FLOW_KEY_TYPE_PORT|
			      FLOW_KEY_TYPE_IPV4|FLOW_KEY_TYPE_UDP|
			      FLOW_KEY_TYPE_SCTP|FLOW_KEY_TYPE_VXLAN,
			      0, 4, 14); //[b3], would pass!!
}

static int
IPV4_UDP_SCTP_VXLAN(void)
{
	return result_checker(FLOW_KEY_TYPE_IPV4|
			      FLOW_KEY_TYPE_UDP|FLOW_KEY_TYPE_SCTP|
			      FLOW_KEY_TYPE_VXLAN,
			      0, 3, 12); //[b2], would pass!!
}

static int
PORT_UDP_SCTP_VXLAN(void)
{
	return result_checker(FLOW_KEY_TYPE_PORT|
			      FLOW_KEY_TYPE_UDP|FLOW_KEY_TYPE_SCTP|
			      FLOW_KEY_TYPE_VXLAN,
			      0, 3, 6); //[b1], would pass!!
}

static int
UDP_SCTP_VXLAN(void)
{
	return result_checker(FLOW_KEY_TYPE_UDP|
			      FLOW_KEY_TYPE_SCTP|FLOW_KEY_TYPE_VXLAN,
			      0, 2, 4); //[b0], would pass!!
}

static int
PORT_IPV4_IPV6_TCP_SCTP_VXLAN(void)
{
	return result_checker(FLOW_KEY_TYPE_PORT|
			      FLOW_KEY_TYPE_IPV4|FLOW_KEY_TYPE_IPV6|
			      FLOW_KEY_TYPE_TCP|FLOW_KEY_TYPE_SCTP|
			      FLOW_KEY_TYPE_VXLAN,
			      1, 5, 42); //[af], fail
}

static int
IPV4_IPV6_TCP_SCTP_VXLAN(void)
{
	return result_checker(FLOW_KEY_TYPE_IPV4|
			      FLOW_KEY_TYPE_IPV6|FLOW_KEY_TYPE_TCP|
			      FLOW_KEY_TYPE_SCTP|FLOW_KEY_TYPE_VXLAN,
			      0, 4, 36); //[ae], would pass!!
}

static int
PORT_IPV6_TCP_SCTP_VXLAN(void)
{
	return result_checker(FLOW_KEY_TYPE_PORT|
			      FLOW_KEY_TYPE_IPV6|FLOW_KEY_TYPE_TCP|
			      FLOW_KEY_TYPE_SCTP|FLOW_KEY_TYPE_VXLAN,
			      1, 5, 42); //[ad], fail
}

static int
IPV6_TCP_SCTP_VXLAN(void)
{
	return result_checker(FLOW_KEY_TYPE_IPV6|
			      FLOW_KEY_TYPE_TCP|FLOW_KEY_TYPE_SCTP|
			      FLOW_KEY_TYPE_VXLAN,
			      0, 3, 36); //[ac], would pass!!
}

static int
PORT_IPV4_TCP_SCTP_VXLAN(void)
{
	return result_checker(FLOW_KEY_TYPE_PORT|
			      FLOW_KEY_TYPE_IPV4|FLOW_KEY_TYPE_TCP|
			      FLOW_KEY_TYPE_SCTP|FLOW_KEY_TYPE_VXLAN,
			      0, 4, 14); //[ab], would pass!!
}

static int
IPV4_TCP_SCTP_VXLAN(void)
{
	return result_checker(FLOW_KEY_TYPE_IPV4|
			      FLOW_KEY_TYPE_TCP|FLOW_KEY_TYPE_SCTP|
			      FLOW_KEY_TYPE_VXLAN,
			      0, 3, 12); //[aa], would pass!!
}

static int
PORT_TCP_SCTP_VXLAN(void)
{
	return result_checker(FLOW_KEY_TYPE_PORT|
			      FLOW_KEY_TYPE_TCP|FLOW_KEY_TYPE_SCTP|
			      FLOW_KEY_TYPE_VXLAN,
			      0, 3, 6); //[a9], would pass!!
}

static int
TCP_SCTP_VXLAN(void)
{
	return result_checker(FLOW_KEY_TYPE_TCP|
			      FLOW_KEY_TYPE_SCTP|FLOW_KEY_TYPE_VXLAN,
			      0, 2, 4); //[a8], would pass!!
}

static int
PORT_IPV4_IPV6_SCTP_VXLAN(void)
{
	return result_checker(FLOW_KEY_TYPE_PORT|
			      FLOW_KEY_TYPE_IPV4|FLOW_KEY_TYPE_IPV6|
			      FLOW_KEY_TYPE_SCTP|FLOW_KEY_TYPE_VXLAN,
			      1, 5, 42); //[a7], fail
}

static int
IPV4_IPV6_SCTP_VXLAN(void)
{
	return result_checker(FLOW_KEY_TYPE_IPV4|
			      FLOW_KEY_TYPE_IPV6|FLOW_KEY_TYPE_SCTP|
			      FLOW_KEY_TYPE_VXLAN,
			      0, 4, 36); //[a6], would pass!!
}

static int
PORT_IPV6_SCTP_VXLAN(void)
{
	return result_checker(FLOW_KEY_TYPE_PORT|
			      FLOW_KEY_TYPE_IPV6|FLOW_KEY_TYPE_SCTP|
			      FLOW_KEY_TYPE_VXLAN,
			      1, 5, 42); //[a5], fail
}

static int
IPV6_SCTP_VXLAN(void)
{
	return result_checker(FLOW_KEY_TYPE_IPV6|
			      FLOW_KEY_TYPE_SCTP|FLOW_KEY_TYPE_VXLAN,
			      0, 3, 36); //[a4], would pass!!
}

static int
PORT_IPV4_SCTP_VXLAN(void)
{
	return result_checker(FLOW_KEY_TYPE_PORT|
			      FLOW_KEY_TYPE_IPV4|FLOW_KEY_TYPE_SCTP|
			      FLOW_KEY_TYPE_VXLAN,
			      0, 4, 14); //[a3], would pass!!
}

static int
IPV4_SCTP_VXLAN(void)
{
	return result_checker(FLOW_KEY_TYPE_IPV4|
			      FLOW_KEY_TYPE_SCTP|FLOW_KEY_TYPE_VXLAN,
			      0, 3, 12); //[a2], would pass!!
}

static int
PORT_SCTP_VXLAN(void)
{
	return result_checker(FLOW_KEY_TYPE_PORT|
			      FLOW_KEY_TYPE_SCTP|FLOW_KEY_TYPE_VXLAN,
			      0, 3, 6); //[a1], would pass!!
}

static int
SCTP_VXLAN(void)
{
	return result_checker(FLOW_KEY_TYPE_SCTP|
			      FLOW_KEY_TYPE_VXLAN,
			      0, 2, 4); //[a0], would pass!!
}

static int
PORT_IPV4_IPV6_TCP_UDP_VXLAN(void)
{
	return result_checker(FLOW_KEY_TYPE_PORT|
			      FLOW_KEY_TYPE_IPV4|FLOW_KEY_TYPE_IPV6|
			      FLOW_KEY_TYPE_TCP|FLOW_KEY_TYPE_UDP|
			      FLOW_KEY_TYPE_VXLAN,
			      1, 5, 42); //[9f], fail
}

static int
IPV4_IPV6_TCP_UDP_VXLAN(void)
{
	return result_checker(FLOW_KEY_TYPE_IPV4|
			      FLOW_KEY_TYPE_IPV6|FLOW_KEY_TYPE_TCP|
			      FLOW_KEY_TYPE_UDP|FLOW_KEY_TYPE_VXLAN,
			      0, 4, 36); //[9e], would pass!!
}

static int
PORT_IPV6_TCP_UDP_VXLAN(void)
{
	return result_checker(FLOW_KEY_TYPE_PORT|
			      FLOW_KEY_TYPE_IPV6|FLOW_KEY_TYPE_TCP|
			      FLOW_KEY_TYPE_UDP|FLOW_KEY_TYPE_VXLAN,
			      1, 5, 42); //[9d], fail
}

static int
IPV6_TCP_UDP_VXLAN(void)
{
	return result_checker(FLOW_KEY_TYPE_IPV6|
			      FLOW_KEY_TYPE_TCP|FLOW_KEY_TYPE_UDP|
			      FLOW_KEY_TYPE_VXLAN,
			      0, 3, 36); //[9c], would pass!!
}

static int
PORT_IPV4_TCP_UDP_VXLAN(void)
{
	return result_checker(FLOW_KEY_TYPE_PORT|
			      FLOW_KEY_TYPE_IPV4|FLOW_KEY_TYPE_TCP|
			      FLOW_KEY_TYPE_UDP|FLOW_KEY_TYPE_VXLAN,
			      0, 4, 14); //[9b], would pass!!
}

static int
IPV4_TCP_UDP_VXLAN(void)
{
	return result_checker(FLOW_KEY_TYPE_IPV4|
			      FLOW_KEY_TYPE_TCP|FLOW_KEY_TYPE_UDP|
			      FLOW_KEY_TYPE_VXLAN,
			      0, 3, 12); //[9a], would pass!!
}

static int
PORT_TCP_UDP_VXLAN(void)
{
	return result_checker(FLOW_KEY_TYPE_PORT|
			      FLOW_KEY_TYPE_TCP|FLOW_KEY_TYPE_UDP|
			      FLOW_KEY_TYPE_VXLAN,
			      0, 3, 6); //[99], would pass!!
}

static int
TCP_UDP_VXLAN(void)
{
	return result_checker(FLOW_KEY_TYPE_TCP|
			      FLOW_KEY_TYPE_UDP|FLOW_KEY_TYPE_VXLAN,
			      0, 2, 4); //[98], would pass!!
}

static int
PORT_IPV4_IPV6_UDP_VXLAN(void)
{
	return result_checker(FLOW_KEY_TYPE_PORT|
			      FLOW_KEY_TYPE_IPV4|FLOW_KEY_TYPE_IPV6|
			      FLOW_KEY_TYPE_UDP|FLOW_KEY_TYPE_VXLAN,
			      1, 5, 42); //[97], fail
}

static int
IPV4_IPV6_UDP_VXLAN(void)
{
	return result_checker(FLOW_KEY_TYPE_IPV4|
			      FLOW_KEY_TYPE_IPV6|FLOW_KEY_TYPE_UDP|
			      FLOW_KEY_TYPE_VXLAN,
			      0, 4, 36); //[96], would pass!!
}

static int
PORT_IPV6_UDP_VXLAN(void)
{
	return result_checker(FLOW_KEY_TYPE_PORT|
			      FLOW_KEY_TYPE_IPV6|FLOW_KEY_TYPE_UDP|
			      FLOW_KEY_TYPE_VXLAN,
			      1, 5, 42); //[95], fail
}

static int
IPV6_UDP_VXLAN(void)
{
	return result_checker(FLOW_KEY_TYPE_IPV6|
			      FLOW_KEY_TYPE_UDP|FLOW_KEY_TYPE_VXLAN,
			      0, 3, 36); //[94], would pass!!
}

static int
PORT_IPV4_UDP_VXLAN(void)
{
	return result_checker(FLOW_KEY_TYPE_PORT|
			      FLOW_KEY_TYPE_IPV4|FLOW_KEY_TYPE_UDP|
			      FLOW_KEY_TYPE_VXLAN,
			      0, 4, 14); //[93], would pass!!
}

static int
IPV4_UDP_VXLAN(void)
{
	return result_checker(FLOW_KEY_TYPE_IPV4|
			      FLOW_KEY_TYPE_UDP|FLOW_KEY_TYPE_VXLAN,
			      0, 3, 12); //[92], would pass!!
}

static int
PORT_UDP_VXLAN(void)
{
	return result_checker(FLOW_KEY_TYPE_PORT|
			      FLOW_KEY_TYPE_UDP|FLOW_KEY_TYPE_VXLAN,
			      0, 3, 6); //[91], would pass!!
}

static int
UDP_VXLAN(void)
{
	return result_checker(FLOW_KEY_TYPE_UDP|
			      FLOW_KEY_TYPE_VXLAN,
			      0, 2, 4); //[90], would pass!!
}

static int
PORT_IPV4_IPV6_TCP_VXLAN(void)
{
	return result_checker(FLOW_KEY_TYPE_PORT|
			      FLOW_KEY_TYPE_IPV4|FLOW_KEY_TYPE_IPV6|
			      FLOW_KEY_TYPE_TCP|FLOW_KEY_TYPE_VXLAN,
			      1, 5, 42); //[8f], fail
}

static int
IPV4_IPV6_TCP_VXLAN(void)
{
	return result_checker(FLOW_KEY_TYPE_IPV4|
			      FLOW_KEY_TYPE_IPV6|FLOW_KEY_TYPE_TCP|
			      FLOW_KEY_TYPE_VXLAN,
			      0, 4, 36); //[8e], would pass!!
}

static int
PORT_IPV6_TCP_VXLAN(void)
{
	return result_checker(FLOW_KEY_TYPE_PORT|
			      FLOW_KEY_TYPE_IPV6|FLOW_KEY_TYPE_TCP|
			      FLOW_KEY_TYPE_VXLAN,
			      1, 5, 42); //[8d], fail
}

static int
IPV6_TCP_VXLAN(void)
{
	return result_checker(FLOW_KEY_TYPE_IPV6|
			      FLOW_KEY_TYPE_TCP|FLOW_KEY_TYPE_VXLAN,
			      0, 3, 36); //[8c], would pass!!
}

static int
PORT_IPV4_TCP_VXLAN(void)
{
	return result_checker(FLOW_KEY_TYPE_PORT|
			      FLOW_KEY_TYPE_IPV4|FLOW_KEY_TYPE_TCP|
			      FLOW_KEY_TYPE_VXLAN,
			      0, 4, 14); //[8b], would pass!!
}

static int
IPV4_TCP_VXLAN(void)
{
	return result_checker(FLOW_KEY_TYPE_IPV4|
			      FLOW_KEY_TYPE_TCP|FLOW_KEY_TYPE_VXLAN,
			      0, 3, 12); //[8a], would pass!!
}

static int
PORT_TCP_VXLAN(void)
{
	return result_checker(FLOW_KEY_TYPE_PORT|
			      FLOW_KEY_TYPE_TCP|FLOW_KEY_TYPE_VXLAN,
			      0, 3, 6); //[89], would pass!!
}

static int
TCP_VXLAN(void)
{
	return result_checker(FLOW_KEY_TYPE_TCP|
			      FLOW_KEY_TYPE_VXLAN,
			      0, 2, 4); //[88], would pass!!
}

static int
PORT_IPV4_IPV6_VXLAN(void)
{
	return result_checker(FLOW_KEY_TYPE_PORT|
			      FLOW_KEY_TYPE_IPV4|FLOW_KEY_TYPE_IPV6|
			      FLOW_KEY_TYPE_VXLAN,
			      0, 4, 34); //[87], would pass!!
}

static int
IPV4_IPV6_VXLAN(void)
{
	return result_checker(FLOW_KEY_TYPE_IPV4|
			      FLOW_KEY_TYPE_IPV6|FLOW_KEY_TYPE_VXLAN,
			      0, 3, 32); //[86], would pass!!
}

static int
PORT_IPV6_VXLAN(void)
{
	return result_checker(FLOW_KEY_TYPE_PORT|
			      FLOW_KEY_TYPE_IPV6|FLOW_KEY_TYPE_VXLAN,
			      0, 3, 34); //[85], would pass!!
}

static int
IPV6_VXLAN(void)
{
	return result_checker(FLOW_KEY_TYPE_IPV6|
			      FLOW_KEY_TYPE_VXLAN,
			      0, 2, 32); //[84], would pass!!
}

static int
PORT_IPV4_VXLAN(void)
{
	return result_checker(FLOW_KEY_TYPE_PORT|
			      FLOW_KEY_TYPE_IPV4|FLOW_KEY_TYPE_VXLAN,
			      0, 3, 10); //[83], would pass!!
}

static int
IPV4_VXLAN(void)
{
	return result_checker(FLOW_KEY_TYPE_IPV4|
			      FLOW_KEY_TYPE_VXLAN,
			      0, 2, 8); //[82], would pass!!
}

static int
PORT_VXLAN(void)
{
	return result_checker(FLOW_KEY_TYPE_PORT|
			      FLOW_KEY_TYPE_VXLAN,
			      0, 2, 2); //[81], would pass!!
}

static int
VXLAN(void)
{
	return result_checker(FLOW_KEY_TYPE_VXLAN,
			      0, 1, 0); //[80], would pass!!
}

static int
PORT_IPV4_IPV6_TCP_UDP_SCTP_NVGRE(void)
{
	return result_checker(FLOW_KEY_TYPE_PORT|
			      FLOW_KEY_TYPE_IPV4|FLOW_KEY_TYPE_IPV6|
			      FLOW_KEY_TYPE_TCP|FLOW_KEY_TYPE_UDP|
			      FLOW_KEY_TYPE_SCTP|FLOW_KEY_TYPE_NVGRE,
			      1, 5, 42); //[7f], fail
}

static int
IPV4_IPV6_TCP_UDP_SCTP_NVGRE(void)
{
	return result_checker(FLOW_KEY_TYPE_IPV4|
			      FLOW_KEY_TYPE_IPV6|FLOW_KEY_TYPE_TCP|
			      FLOW_KEY_TYPE_UDP|FLOW_KEY_TYPE_SCTP|
			      FLOW_KEY_TYPE_NVGRE,
			      0, 4, 36); //[7e], would pass!!
}

static int
PORT_IPV6_TCP_UDP_SCTP_NVGRE(void)
{
	return result_checker(FLOW_KEY_TYPE_PORT|
			      FLOW_KEY_TYPE_IPV6|FLOW_KEY_TYPE_TCP|
			      FLOW_KEY_TYPE_UDP|FLOW_KEY_TYPE_SCTP|
			      FLOW_KEY_TYPE_NVGRE,
			      1, 5, 42); //[7d], fail
}

static int
IPV6_TCP_UDP_SCTP_NVGRE(void)
{
	return result_checker(FLOW_KEY_TYPE_IPV6|
			      FLOW_KEY_TYPE_TCP|FLOW_KEY_TYPE_UDP|
			      FLOW_KEY_TYPE_SCTP|FLOW_KEY_TYPE_NVGRE,
			      0, 3, 36); //[7c], would pass!!
}

static int
PORT_IPV4_TCP_UDP_SCTP_NVGRE(void)
{
	return result_checker(FLOW_KEY_TYPE_PORT|
			      FLOW_KEY_TYPE_IPV4|FLOW_KEY_TYPE_TCP|
			      FLOW_KEY_TYPE_UDP|FLOW_KEY_TYPE_SCTP|
			      FLOW_KEY_TYPE_NVGRE,
			      0, 4, 14); //[7b], would pass!!
}

static int
IPV4_TCP_UDP_SCTP_NVGRE(void)
{
	return result_checker(FLOW_KEY_TYPE_IPV4|
			      FLOW_KEY_TYPE_TCP|FLOW_KEY_TYPE_UDP|
			      FLOW_KEY_TYPE_SCTP|FLOW_KEY_TYPE_NVGRE,
			      0, 3, 12); //[7a], would pass!!
}

static int
PORT_TCP_UDP_SCTP_NVGRE(void)
{
	return result_checker(FLOW_KEY_TYPE_PORT|
			      FLOW_KEY_TYPE_TCP|FLOW_KEY_TYPE_UDP|
			      FLOW_KEY_TYPE_SCTP|FLOW_KEY_TYPE_NVGRE,
			      0, 3, 6); //[79], would pass!!
}

static int
TCP_UDP_SCTP_NVGRE(void)
{
	return result_checker(FLOW_KEY_TYPE_TCP|
			      FLOW_KEY_TYPE_UDP|FLOW_KEY_TYPE_SCTP|
			      FLOW_KEY_TYPE_NVGRE,
			      0, 2, 4); //[78], would pass!!
}

static int
PORT_IPV4_IPV6_UDP_SCTP_NVGRE(void)
{
	return result_checker(FLOW_KEY_TYPE_PORT|
			      FLOW_KEY_TYPE_IPV4|FLOW_KEY_TYPE_IPV6|
			      FLOW_KEY_TYPE_UDP|FLOW_KEY_TYPE_SCTP|
			      FLOW_KEY_TYPE_NVGRE,
			      1, 5, 42); //[77], fail
}

static int
IPV4_IPV6_UDP_SCTP_NVGRE(void)
{
	return result_checker(FLOW_KEY_TYPE_IPV4|
			      FLOW_KEY_TYPE_IPV6|FLOW_KEY_TYPE_UDP|
			      FLOW_KEY_TYPE_SCTP|FLOW_KEY_TYPE_NVGRE,
			      0, 4, 36); //[76], would pass!!
}

static int
PORT_IPV6_UDP_SCTP_NVGRE(void)
{
	return result_checker(FLOW_KEY_TYPE_PORT|
			      FLOW_KEY_TYPE_IPV6|FLOW_KEY_TYPE_UDP|
			      FLOW_KEY_TYPE_SCTP|FLOW_KEY_TYPE_NVGRE,
			      1, 5, 42); //[75], fail
}

static int
IPV6_UDP_SCTP_NVGRE(void)
{
	return result_checker(FLOW_KEY_TYPE_IPV6|
			      FLOW_KEY_TYPE_UDP|FLOW_KEY_TYPE_SCTP|
			      FLOW_KEY_TYPE_NVGRE,
			      0, 3, 36); //[74], would pass!!
}

static int
PORT_IPV4_UDP_SCTP_NVGRE(void)
{
	return result_checker(FLOW_KEY_TYPE_PORT|
			      FLOW_KEY_TYPE_IPV4|FLOW_KEY_TYPE_UDP|
			      FLOW_KEY_TYPE_SCTP|FLOW_KEY_TYPE_NVGRE,
			      0, 4, 14); //[73], would pass!!
}

static int
IPV4_UDP_SCTP_NVGRE(void)
{
	return result_checker(FLOW_KEY_TYPE_IPV4|
			      FLOW_KEY_TYPE_UDP|FLOW_KEY_TYPE_SCTP|
			      FLOW_KEY_TYPE_NVGRE,
			      0, 3, 12); //[72], would pass!!
}

static int
PORT_UDP_SCTP_NVGRE(void)
{
	return result_checker(FLOW_KEY_TYPE_PORT|
			      FLOW_KEY_TYPE_UDP|FLOW_KEY_TYPE_SCTP|
			      FLOW_KEY_TYPE_NVGRE,
			      0, 3, 6); //[71], would pass!!
}

static int
UDP_SCTP_NVGRE(void)
{
	return result_checker(FLOW_KEY_TYPE_UDP|
			      FLOW_KEY_TYPE_SCTP|FLOW_KEY_TYPE_NVGRE,
			      0, 2, 4); //[70], would pass!!
}

static int
PORT_IPV4_IPV6_TCP_SCTP_NVGRE(void)
{
	return result_checker(FLOW_KEY_TYPE_PORT|
			      FLOW_KEY_TYPE_IPV4|FLOW_KEY_TYPE_IPV6|
			      FLOW_KEY_TYPE_TCP|FLOW_KEY_TYPE_SCTP|
			      FLOW_KEY_TYPE_NVGRE,
			      1, 5, 42); //[6f], fail
}

static int
IPV4_IPV6_TCP_SCTP_NVGRE(void)
{
	return result_checker(FLOW_KEY_TYPE_IPV4|
			      FLOW_KEY_TYPE_IPV6|FLOW_KEY_TYPE_TCP|
			      FLOW_KEY_TYPE_SCTP|FLOW_KEY_TYPE_NVGRE,
			      0, 4, 36); //[6e], would pass!!
}

static int
PORT_IPV6_TCP_SCTP_NVGRE(void)
{
	return result_checker(FLOW_KEY_TYPE_PORT|
			      FLOW_KEY_TYPE_IPV6|FLOW_KEY_TYPE_TCP|
			      FLOW_KEY_TYPE_SCTP|FLOW_KEY_TYPE_NVGRE,
			      1, 5, 42); //[6d], fail
}

static int
IPV6_TCP_SCTP_NVGRE(void)
{
	return result_checker(FLOW_KEY_TYPE_IPV6|
			      FLOW_KEY_TYPE_TCP|FLOW_KEY_TYPE_SCTP|
			      FLOW_KEY_TYPE_NVGRE,
			      0, 3, 36); //[6c], would pass!!
}

static int
PORT_IPV4_TCP_SCTP_NVGRE(void)
{
	return result_checker(FLOW_KEY_TYPE_PORT|
			      FLOW_KEY_TYPE_IPV4|FLOW_KEY_TYPE_TCP|
			      FLOW_KEY_TYPE_SCTP|FLOW_KEY_TYPE_NVGRE,
			      0, 4, 14); //[6b], would pass!!
}

static int
IPV4_TCP_SCTP_NVGRE(void)
{
	return result_checker(FLOW_KEY_TYPE_IPV4|
			      FLOW_KEY_TYPE_TCP|FLOW_KEY_TYPE_SCTP|
			      FLOW_KEY_TYPE_NVGRE,
			      0, 3, 12); //[6a], would pass!!
}

static int
PORT_TCP_SCTP_NVGRE(void)
{
	return result_checker(FLOW_KEY_TYPE_PORT|
			      FLOW_KEY_TYPE_TCP|FLOW_KEY_TYPE_SCTP|
			      FLOW_KEY_TYPE_NVGRE,
			      0, 3, 6); //[69], would pass!!
}

static int
TCP_SCTP_NVGRE(void)
{
	return result_checker(FLOW_KEY_TYPE_TCP|
			      FLOW_KEY_TYPE_SCTP|FLOW_KEY_TYPE_NVGRE,
			      0, 2, 4); //[68], would pass!!
}

static int
PORT_IPV4_IPV6_SCTP_NVGRE(void)
{
	return result_checker(FLOW_KEY_TYPE_PORT|
			      FLOW_KEY_TYPE_IPV4|FLOW_KEY_TYPE_IPV6|
			      FLOW_KEY_TYPE_SCTP|FLOW_KEY_TYPE_NVGRE,
			      1, 5, 42); //[67], fail
}

static int
IPV4_IPV6_SCTP_NVGRE(void)
{
	return result_checker(FLOW_KEY_TYPE_IPV4|
			      FLOW_KEY_TYPE_IPV6|FLOW_KEY_TYPE_SCTP|
			      FLOW_KEY_TYPE_NVGRE,
			      0, 4, 36); //[66], would pass!!
}

static int
PORT_IPV6_SCTP_NVGRE(void)
{
	return result_checker(FLOW_KEY_TYPE_PORT|
			      FLOW_KEY_TYPE_IPV6|FLOW_KEY_TYPE_SCTP|
			      FLOW_KEY_TYPE_NVGRE,
			      1, 5, 42); //[65], fail
}

static int
IPV6_SCTP_NVGRE(void)
{
	return result_checker(FLOW_KEY_TYPE_IPV6|
			      FLOW_KEY_TYPE_SCTP|FLOW_KEY_TYPE_NVGRE,
			      0, 3, 36); //[64], would pass!!
}

static int
PORT_IPV4_SCTP_NVGRE(void)
{
	return result_checker(FLOW_KEY_TYPE_PORT|
			      FLOW_KEY_TYPE_IPV4|FLOW_KEY_TYPE_SCTP|
			      FLOW_KEY_TYPE_NVGRE,
			      0, 4, 14); //[63], would pass!!
}

static int
IPV4_SCTP_NVGRE(void)
{
	return result_checker(FLOW_KEY_TYPE_IPV4|
			      FLOW_KEY_TYPE_SCTP|FLOW_KEY_TYPE_NVGRE,
			      0, 3, 12); //[62], would pass!!
}

static int
PORT_SCTP_NVGRE(void)
{
	return result_checker(FLOW_KEY_TYPE_PORT|
			      FLOW_KEY_TYPE_SCTP|FLOW_KEY_TYPE_NVGRE,
			      0, 3, 6); //[61], would pass!!
}

static int
SCTP_NVGRE(void)
{
	return result_checker(FLOW_KEY_TYPE_SCTP|
			      FLOW_KEY_TYPE_NVGRE,
			      0, 2, 4); //[60], would pass!!
}

static int
PORT_IPV6_TCP_UDP_NVGRE(void)
{
	return result_checker(FLOW_KEY_TYPE_PORT|
			      FLOW_KEY_TYPE_IPV6|FLOW_KEY_TYPE_TCP|
			      FLOW_KEY_TYPE_UDP|FLOW_KEY_TYPE_NVGRE,
			      1, 5, 42); //[5d], fail
}

static int
IPV6_TCP_UDP_NVGRE(void)
{
	return result_checker(FLOW_KEY_TYPE_IPV6|
			      FLOW_KEY_TYPE_TCP|FLOW_KEY_TYPE_UDP|
			      FLOW_KEY_TYPE_NVGRE,
			      0, 3, 36); //[5c], would pass!!
}

static int
PORT_IPV4_TCP_UDP_NVGRE(void)
{
	return result_checker(FLOW_KEY_TYPE_PORT|
			      FLOW_KEY_TYPE_IPV4|FLOW_KEY_TYPE_TCP|
			      FLOW_KEY_TYPE_UDP|FLOW_KEY_TYPE_NVGRE,
			      0, 4, 14); //[5b], would pass!!
}

static int
IPV4_TCP_UDP_NVGRE(void)
{
	return result_checker(FLOW_KEY_TYPE_IPV4|
			      FLOW_KEY_TYPE_TCP|FLOW_KEY_TYPE_UDP|
			      FLOW_KEY_TYPE_NVGRE,
			      0, 3, 12); //[5a], would pass!!
}

static int
PORT_TCP_UDP_NVGRE(void)
{
	return result_checker(FLOW_KEY_TYPE_PORT|
			      FLOW_KEY_TYPE_TCP|FLOW_KEY_TYPE_UDP|
			      FLOW_KEY_TYPE_NVGRE,
			      0, 3, 6); //[59], would pass!!
}

static int
TCP_UDP_NVGRE(void)
{
	return result_checker(FLOW_KEY_TYPE_TCP|
			      FLOW_KEY_TYPE_UDP|FLOW_KEY_TYPE_NVGRE,
			      0, 2, 4); //[58], would pass!!
}

static int
PORT_IPV4_IPV6_UDP_NVGRE(void)
{
	return result_checker(FLOW_KEY_TYPE_PORT|
			      FLOW_KEY_TYPE_IPV4|FLOW_KEY_TYPE_IPV6|
			      FLOW_KEY_TYPE_UDP|FLOW_KEY_TYPE_NVGRE,
			      1, 5, 42); //[57], fail
}

static int
IPV4_IPV6_UDP_NVGRE(void)
{
	return result_checker(FLOW_KEY_TYPE_IPV4|
			      FLOW_KEY_TYPE_IPV6|FLOW_KEY_TYPE_UDP|
			      FLOW_KEY_TYPE_NVGRE,
			      0, 4, 36); //[56], would pass!!
}

static int
PORT_IPV6_UDP_NVGRE(void)
{
	return result_checker(FLOW_KEY_TYPE_PORT|
			      FLOW_KEY_TYPE_IPV6|FLOW_KEY_TYPE_UDP|
			      FLOW_KEY_TYPE_NVGRE,
			      1, 5, 42); //[55], fail
}

static int
IPV6_UDP_NVGRE(void)
{
	return result_checker(FLOW_KEY_TYPE_IPV6|
			      FLOW_KEY_TYPE_UDP|FLOW_KEY_TYPE_NVGRE,
			      0, 3, 36); //[54], would pass!!
}

static int
PORT_IPV4_UDP_NVGRE(void)
{
	return result_checker(FLOW_KEY_TYPE_PORT|
			      FLOW_KEY_TYPE_IPV4|FLOW_KEY_TYPE_UDP|
			      FLOW_KEY_TYPE_NVGRE,
			      0, 4, 14); //[53], would pass!!
}

static int
IPV4_UDP_NVGRE(void)
{
	return result_checker(FLOW_KEY_TYPE_IPV4|
			      FLOW_KEY_TYPE_UDP|FLOW_KEY_TYPE_NVGRE,
			      0, 3, 12); //[52], would pass!!
}

static int
PORT_UDP_NVGRE(void)
{
	return result_checker(FLOW_KEY_TYPE_PORT|
			      FLOW_KEY_TYPE_UDP|FLOW_KEY_TYPE_NVGRE,
			      0, 3, 6); //[51], would pass!!
}

static int
UDP_NVGRE(void)
{
	return result_checker(FLOW_KEY_TYPE_UDP|
			      FLOW_KEY_TYPE_NVGRE,
			      0, 2, 4); //[50], would pass!!
}

static int
PORT_IPV4_IPV6_TCP_NVGRE(void)
{
	return result_checker(FLOW_KEY_TYPE_PORT|
			      FLOW_KEY_TYPE_IPV4|FLOW_KEY_TYPE_IPV6|
			      FLOW_KEY_TYPE_TCP|FLOW_KEY_TYPE_NVGRE,
			      1, 5, 42); //[4f], fail
}

static int
IPV4_IPV6_TCP_NVGRE(void)
{
	return result_checker(FLOW_KEY_TYPE_IPV4|
			      FLOW_KEY_TYPE_IPV6|FLOW_KEY_TYPE_TCP|
			      FLOW_KEY_TYPE_NVGRE,
			      0, 4, 36); //[4e], would pass!!
}

static int
PORT_IPV6_TCP_NVGRE(void)
{
	return result_checker(FLOW_KEY_TYPE_PORT|
			      FLOW_KEY_TYPE_IPV6|FLOW_KEY_TYPE_TCP|
			      FLOW_KEY_TYPE_NVGRE,
			      1, 5, 42); //[4d], fail
}

static int
IPV6_TCP_NVGRE(void)
{
	return result_checker(FLOW_KEY_TYPE_IPV6|
			      FLOW_KEY_TYPE_TCP|FLOW_KEY_TYPE_NVGRE,
			      0, 3, 36); //[4c], would pass!!
}

static int
PORT_IPV4_TCP_NVGRE(void)
{
	return result_checker(FLOW_KEY_TYPE_PORT|
			      FLOW_KEY_TYPE_IPV4|FLOW_KEY_TYPE_TCP|
			      FLOW_KEY_TYPE_NVGRE,
			      0, 4, 14); //[4b], would pass!!
}

static int
IPV4_TCP_NVGRE(void)
{
	return result_checker(FLOW_KEY_TYPE_IPV4|
			      FLOW_KEY_TYPE_TCP|FLOW_KEY_TYPE_NVGRE,
			      0, 3, 12); //[4a], would pass!!
}

static int
PORT_TCP_NVGRE(void)
{
	return result_checker(FLOW_KEY_TYPE_PORT|
			      FLOW_KEY_TYPE_TCP|FLOW_KEY_TYPE_NVGRE,
			      0, 3, 6); //[49], would pass!!
}

static int
TCP_NVGRE(void)
{
	return result_checker(FLOW_KEY_TYPE_TCP|
			      FLOW_KEY_TYPE_NVGRE,
			      0, 2, 4); //[48], would pass!!
}

static int
PORT_IPV4_IPV6_NVGRE(void)
{
	return result_checker(FLOW_KEY_TYPE_PORT|
			      FLOW_KEY_TYPE_IPV4|FLOW_KEY_TYPE_IPV6|
			      FLOW_KEY_TYPE_NVGRE,
			      0, 4, 34); //[47], would pass!!
}

static int
IPV4_IPV6_NVGRE(void)
{
	return result_checker(FLOW_KEY_TYPE_IPV4|
			      FLOW_KEY_TYPE_IPV6|FLOW_KEY_TYPE_NVGRE,
			      0, 3, 32); //[46], would pass!!
}

static int
PORT_IPV6_NVGRE(void)
{
	return result_checker(FLOW_KEY_TYPE_PORT|
			      FLOW_KEY_TYPE_IPV6|FLOW_KEY_TYPE_NVGRE,
			      0, 3, 34); //[45], would pass!!
}

static int
IPV6_NVGRE(void)
{
	return result_checker(FLOW_KEY_TYPE_IPV6|
			      FLOW_KEY_TYPE_NVGRE,
			      0, 2, 32); //[44], would pass!!
}

static int
PORT_IPV4_NVGRE(void)
{
	return result_checker(FLOW_KEY_TYPE_PORT|
			      FLOW_KEY_TYPE_IPV4|FLOW_KEY_TYPE_NVGRE,
			      0, 3, 10); //[43], would pass!!
}

static int
IPV4_NVGRE(void)
{
	return result_checker(FLOW_KEY_TYPE_IPV4|
			      FLOW_KEY_TYPE_NVGRE,
			      0, 2, 8); //[42], would pass!!
}

static int
PORT_NVGRE(void)
{
	return result_checker(FLOW_KEY_TYPE_PORT|
			      FLOW_KEY_TYPE_NVGRE,
			      0, 2, 2); //[41], would pass!!
}

static int
NVGRE(void)
{
	return result_checker(FLOW_KEY_TYPE_NVGRE,
			      0, 1, 0); //[40], would pass!!
}

static int
PORT_IPV4_IPV6_TCP_UDP_SCTP(void)
{
	return result_checker(FLOW_KEY_TYPE_PORT|
			      FLOW_KEY_TYPE_IPV4|FLOW_KEY_TYPE_IPV6|
			      FLOW_KEY_TYPE_TCP|FLOW_KEY_TYPE_UDP|
			      FLOW_KEY_TYPE_SCTP,
			      0, 4, 34); //[3f], would pass!!
}

static int
PORT_IPV6_TCP_UDP_SCTP(void)
{
	return result_checker(FLOW_KEY_TYPE_PORT|
			      FLOW_KEY_TYPE_IPV6|FLOW_KEY_TYPE_TCP|
			      FLOW_KEY_TYPE_UDP|FLOW_KEY_TYPE_SCTP,
			      0, 3, 34); //[3d], would pass!!
}

static int
IPV6_TCP_UDP_SCTP(void)
{
	return result_checker(FLOW_KEY_TYPE_IPV6|
			      FLOW_KEY_TYPE_TCP|FLOW_KEY_TYPE_UDP|
			      FLOW_KEY_TYPE_SCTP,
			      0, 2, 32); //[3c], would pass!!
}

static int
PORT_IPV4_TCP_UDP_SCTP(void)
{
	return result_checker(FLOW_KEY_TYPE_PORT|
			      FLOW_KEY_TYPE_IPV4|FLOW_KEY_TYPE_TCP|
			      FLOW_KEY_TYPE_UDP|FLOW_KEY_TYPE_SCTP,
			      0, 3, 10); //[3b], would pass!!
}

static int
IPV4_TCP_UDP_SCTP(void)
{
	return result_checker(FLOW_KEY_TYPE_IPV4|
			      FLOW_KEY_TYPE_TCP|FLOW_KEY_TYPE_UDP|
			      FLOW_KEY_TYPE_SCTP,
			      0, 2, 8); //[3a], would pass!!
}

static int
PORT_TCP_UDP_SCTP(void)
{
	return result_checker(FLOW_KEY_TYPE_PORT|
			      FLOW_KEY_TYPE_TCP|FLOW_KEY_TYPE_UDP|
			      FLOW_KEY_TYPE_SCTP,
			      0, 2, 2); //[39], would pass!!
}

static int
TCP_UDP_SCTP(void)
{
	return result_checker(FLOW_KEY_TYPE_TCP|
			      FLOW_KEY_TYPE_UDP|FLOW_KEY_TYPE_SCTP,
			      0, 1, 0); //[38], would pass!!
}

static int
PORT_IPV4_IPV6_UDP_SCTP(void)
{
	return result_checker(FLOW_KEY_TYPE_PORT|
			      FLOW_KEY_TYPE_IPV4|FLOW_KEY_TYPE_IPV6|
			      FLOW_KEY_TYPE_UDP|FLOW_KEY_TYPE_SCTP,
			      0, 4, 34); //[37], would pass!!
}

static int
PORT_IPV6_UDP_SCTP(void)
{
	return result_checker(FLOW_KEY_TYPE_PORT|
			      FLOW_KEY_TYPE_IPV6|FLOW_KEY_TYPE_UDP|
			      FLOW_KEY_TYPE_SCTP,
			      0, 3, 34); //[35], would pass!!
}

static int
IPV6_UDP_SCTP(void)
{
	return result_checker(FLOW_KEY_TYPE_IPV6|
			      FLOW_KEY_TYPE_UDP|FLOW_KEY_TYPE_SCTP,
			      0, 2, 32); //[34], would pass!!
}

static int
PORT_IPV4_UDP_SCTP(void)
{
	return result_checker(FLOW_KEY_TYPE_PORT|
			      FLOW_KEY_TYPE_IPV4|FLOW_KEY_TYPE_UDP|
			      FLOW_KEY_TYPE_SCTP,
			      0, 3, 10); //[33], would pass!!
}

static int
IPV4_UDP_SCTP(void)
{
	return result_checker(FLOW_KEY_TYPE_IPV4|
			      FLOW_KEY_TYPE_UDP|FLOW_KEY_TYPE_SCTP,
			      0, 2, 8); //[32], would pass!!
}

static int
PORT_UDP_SCTP(void)
{
	return result_checker(FLOW_KEY_TYPE_PORT|
			      FLOW_KEY_TYPE_UDP|FLOW_KEY_TYPE_SCTP,
			      0, 2, 2); //[31], would pass!!
}

static int
UDP_SCTP(void)
{
	return result_checker(FLOW_KEY_TYPE_UDP|
			      FLOW_KEY_TYPE_SCTP,
			      0, 1, 0); //[30], would pass!!
}

static int
PORT_IPV4_IPV6_TCP_SCTP(void)
{
	return result_checker(FLOW_KEY_TYPE_PORT|
			      FLOW_KEY_TYPE_IPV4|FLOW_KEY_TYPE_IPV6|
			      FLOW_KEY_TYPE_TCP|FLOW_KEY_TYPE_SCTP,
			      0, 4, 34); //[2f], would pass!!
}

static int
PORT_IPV6_TCP_SCTP(void)
{
	return result_checker(FLOW_KEY_TYPE_PORT|
			      FLOW_KEY_TYPE_IPV6|FLOW_KEY_TYPE_TCP|
			      FLOW_KEY_TYPE_SCTP,
			      0, 3, 34); //[2d], would pass!!
}

static int
IPV6_TCP_SCTP(void)
{
	return result_checker(FLOW_KEY_TYPE_IPV6|
			      FLOW_KEY_TYPE_TCP|FLOW_KEY_TYPE_SCTP,
			      0, 2, 32); //[2c], would pass!!
}

static int
PORT_IPV4_TCP_SCTP(void)
{
	return result_checker(FLOW_KEY_TYPE_PORT|
			      FLOW_KEY_TYPE_IPV4|FLOW_KEY_TYPE_TCP|
			      FLOW_KEY_TYPE_SCTP,
			      0, 3, 10); //[2b], would pass!!
}

static int
IPV4_TCP_SCTP(void)
{
	return result_checker(FLOW_KEY_TYPE_IPV4|
			      FLOW_KEY_TYPE_TCP|FLOW_KEY_TYPE_SCTP,
			      0, 2, 8); //[2a], would pass!!
}

static int
PORT_TCP_SCTP(void)
{
	return result_checker(FLOW_KEY_TYPE_PORT|
			      FLOW_KEY_TYPE_TCP|FLOW_KEY_TYPE_SCTP,
			      0, 2, 2); //[29], would pass!!
}

static int
TCP_SCTP(void)
{
	return result_checker(FLOW_KEY_TYPE_TCP|
			      FLOW_KEY_TYPE_SCTP,
			      0, 1, 0); //[28], would pass!!
}

static int
PORT_IPV4_IPV6_SCTP(void)
{
	return result_checker(FLOW_KEY_TYPE_PORT|
			      FLOW_KEY_TYPE_IPV4|FLOW_KEY_TYPE_IPV6|
			      FLOW_KEY_TYPE_SCTP,
			      0, 4, 34); //[27], would pass!!
}

static int
PORT_IPV6_SCTP(void)
{
	return result_checker(FLOW_KEY_TYPE_PORT|
			      FLOW_KEY_TYPE_IPV6|FLOW_KEY_TYPE_SCTP,
			      0, 3, 34); //[25], would pass!!
}

static int
IPV6_SCTP(void)
{
	return result_checker(FLOW_KEY_TYPE_IPV6|
			      FLOW_KEY_TYPE_SCTP,
			      0, 2, 32); //[24], would pass!!
}

static int
PORT_IPV4_SCTP(void)
{
	return result_checker(FLOW_KEY_TYPE_PORT|
			      FLOW_KEY_TYPE_IPV4|FLOW_KEY_TYPE_SCTP,
			      0, 3, 10); //[23], would pass!!
}

static int
IPV4_SCTP(void)
{
	return result_checker(FLOW_KEY_TYPE_IPV4|
			      FLOW_KEY_TYPE_SCTP,
			      0, 2, 8); //[22], would pass!!
}

static int
PORT_SCTP(void)
{
	return result_checker(FLOW_KEY_TYPE_PORT|
			      FLOW_KEY_TYPE_SCTP,
			      0, 2, 2); //[21], would pass!!
}

static int
SCTP(void)
{
	return result_checker(FLOW_KEY_TYPE_SCTP,
			      0, 1, 0); //[20], would pass!!
}

static int
PORT_IPV4_IPV6_TCP_UDP(void)
{
	return result_checker(FLOW_KEY_TYPE_PORT|
			      FLOW_KEY_TYPE_IPV4|FLOW_KEY_TYPE_IPV6|
			      FLOW_KEY_TYPE_TCP|FLOW_KEY_TYPE_UDP,
			      0, 4, 34); //[1f], would pass!!
}

static int
PORT_IPV6_TCP_UDP(void)
{
	return result_checker(FLOW_KEY_TYPE_PORT|
			      FLOW_KEY_TYPE_IPV6|FLOW_KEY_TYPE_TCP|
			      FLOW_KEY_TYPE_UDP,
			      0, 3, 34); //[1d], would pass!!
}

static int
IPV6_TCP_UDP(void)
{
	return result_checker(FLOW_KEY_TYPE_IPV6|
			      FLOW_KEY_TYPE_TCP|FLOW_KEY_TYPE_UDP,
			      0, 2, 32); //[1c], would pass!!
}

static int
PORT_IPV4_TCP_UDP(void)
{
	return result_checker(FLOW_KEY_TYPE_PORT|
			      FLOW_KEY_TYPE_IPV4|FLOW_KEY_TYPE_TCP|
			      FLOW_KEY_TYPE_UDP,
			      0, 3, 10); //[1b], would pass!!
}

static int
IPV4_TCP_UDP(void)
{
	return result_checker(FLOW_KEY_TYPE_IPV4|
			      FLOW_KEY_TYPE_TCP|FLOW_KEY_TYPE_UDP,
			      0, 2, 8); //[1a], would pass!!
}

static int
PORT_TCP_UDP(void)
{
	return result_checker(FLOW_KEY_TYPE_PORT|
			      FLOW_KEY_TYPE_TCP|FLOW_KEY_TYPE_UDP,
			      0, 2, 2); //[19], would pass!!
}

static int
TCP_UDP(void)
{
	return result_checker(FLOW_KEY_TYPE_TCP|
			      FLOW_KEY_TYPE_UDP,
			      0, 1, 0); //[18], would pass!!
}

static int
PORT_IPV4_IPV6_UDP(void)
{
	return result_checker(FLOW_KEY_TYPE_PORT|
			      FLOW_KEY_TYPE_IPV4|FLOW_KEY_TYPE_IPV6|
			      FLOW_KEY_TYPE_UDP,
			      0, 4, 34); //[17], would pass!!
}

static int
PORT_IPV6_UDP(void)
{
	return result_checker(FLOW_KEY_TYPE_PORT|
			      FLOW_KEY_TYPE_IPV6|FLOW_KEY_TYPE_UDP,
			      0, 3, 34); //[15], would pass!!
}

static int
IPV6_UDP(void)
{
	return result_checker(FLOW_KEY_TYPE_IPV6|
			      FLOW_KEY_TYPE_UDP,
			      0, 2, 32); //[14], would pass!!
}

static int
PORT_IPV4_UDP(void)
{
	return result_checker(FLOW_KEY_TYPE_PORT|
			      FLOW_KEY_TYPE_IPV4|FLOW_KEY_TYPE_UDP,
			      0, 3, 10); //[13], would pass!!
}

static int
IPV4_UDP(void)
{
	return result_checker(FLOW_KEY_TYPE_IPV4|
			      FLOW_KEY_TYPE_UDP,
			      0, 2, 8); //[12], would pass!!
}

static int
PORT_UDP(void)
{
	return result_checker(FLOW_KEY_TYPE_PORT|
			      FLOW_KEY_TYPE_UDP,
			      0, 2, 2); //[11], would pass!!
}

static int
UDP(void)
{
	return result_checker(FLOW_KEY_TYPE_UDP,
			      0, 1, 0); //[10], would pass!!
}

static int
PORT_IPV4_IPV6_TCP(void)
{
	return result_checker(FLOW_KEY_TYPE_PORT|
			      FLOW_KEY_TYPE_IPV4|FLOW_KEY_TYPE_IPV6|
			      FLOW_KEY_TYPE_TCP,
			      0, 4, 34); //[f], would pass!!
}

static int
PORT_IPV6_TCP(void)
{
	return result_checker(FLOW_KEY_TYPE_PORT|
			      FLOW_KEY_TYPE_IPV6|FLOW_KEY_TYPE_TCP,
			      0, 3, 34); //[d], would pass!!
}

static int
IPV6_TCP(void)
{
	return result_checker(FLOW_KEY_TYPE_IPV6|
			      FLOW_KEY_TYPE_TCP,
			      0, 2, 32); //[c], would pass!!
}

static int
PORT_IPV4_TCP(void)
{
	return result_checker(FLOW_KEY_TYPE_PORT|
			      FLOW_KEY_TYPE_IPV4|FLOW_KEY_TYPE_TCP,
			      0, 3, 10); //[b], would pass!!
}

static int
IPV4_TCP(void)
{
	return result_checker(FLOW_KEY_TYPE_IPV4|
			      FLOW_KEY_TYPE_TCP,
			      0, 2, 8); //[a], would pass!!
}

static int
PORT_TCP(void)
{
	return result_checker(FLOW_KEY_TYPE_PORT|
			      FLOW_KEY_TYPE_TCP,
			      0, 2, 2); //[9], would pass!!
}

static int
TCP(void)
{
	return result_checker(FLOW_KEY_TYPE_TCP,
			      0, 1, 0); //[8], would pass!!
}

static int
PORT_IPV4_IPV6(void)
{
	return result_checker(FLOW_KEY_TYPE_PORT|
			      FLOW_KEY_TYPE_IPV4|FLOW_KEY_TYPE_IPV6,
			      0, 3, 2); //[7], would pass!!
}

static int
PORT_IPV6(void)
{
	return result_checker(FLOW_KEY_TYPE_PORT|
			      FLOW_KEY_TYPE_IPV6,
			      0, 2, 2); //[5], would pass!!
}

static int
IPV6(void)
{
	return result_checker(FLOW_KEY_TYPE_IPV6,
			      0, 1, 0); //[4], would pass!!
}

static int
PORT_IPV4(void)
{
	return result_checker(FLOW_KEY_TYPE_PORT|
			      FLOW_KEY_TYPE_IPV4,
			      0, 2, 2); //[3], would pass!!
}

static int
IPV4(void)
{
	return result_checker(FLOW_KEY_TYPE_IPV4,
			      0, 1, 0); //[2], would pass!!
}

struct otx2_test unit_tests[] = {
	OTX2_TEST(PORT                                            ),
	OTX2_TEST(IPV4                                            ),
	OTX2_TEST(PORT_IPV4                                       ),
	OTX2_TEST(IPV6                                            ),
	OTX2_TEST(PORT_IPV6                                       ),
	OTX2_TEST(IPV4_IPV6                                       ),
	OTX2_TEST(PORT_IPV4_IPV6                                  ),
	OTX2_TEST(TCP                                             ),
	OTX2_TEST(PORT_TCP                                        ),
	OTX2_TEST(IPV4_TCP                                        ),
	OTX2_TEST(PORT_IPV4_TCP                                   ),
	OTX2_TEST(IPV6_TCP                                        ),
	OTX2_TEST(PORT_IPV6_TCP                                   ),
	OTX2_TEST(IPV4_IPV6_TCP                                   ),
	OTX2_TEST(PORT_IPV4_IPV6_TCP                              ),
	OTX2_TEST(UDP                                             ),
	OTX2_TEST(PORT_UDP                                        ),
	OTX2_TEST(IPV4_UDP                                        ),
	OTX2_TEST(PORT_IPV4_UDP                                   ),
	OTX2_TEST(IPV6_UDP                                        ),
	OTX2_TEST(PORT_IPV6_UDP                                   ),
	OTX2_TEST(IPV4_IPV6_UDP                                   ),
	OTX2_TEST(PORT_IPV4_IPV6_UDP                              ),
	OTX2_TEST(TCP_UDP                                         ),
	OTX2_TEST(PORT_TCP_UDP                                    ),
	OTX2_TEST(IPV4_TCP_UDP                                    ),
	OTX2_TEST(PORT_IPV4_TCP_UDP                               ),
	OTX2_TEST(IPV6_TCP_UDP                                    ),
	OTX2_TEST(PORT_IPV6_TCP_UDP                               ),
	OTX2_TEST(IPV4_IPV6_TCP_UDP                               ),
	OTX2_TEST(PORT_IPV4_IPV6_TCP_UDP                          ),
	OTX2_TEST(SCTP                                            ),
	OTX2_TEST(PORT_SCTP                                       ),
	OTX2_TEST(IPV4_SCTP                                       ),
	OTX2_TEST(PORT_IPV4_SCTP                                  ),
	OTX2_TEST(IPV6_SCTP                                       ),
	OTX2_TEST(PORT_IPV6_SCTP                                  ),
	OTX2_TEST(IPV4_IPV6_SCTP                                  ),
	OTX2_TEST(PORT_IPV4_IPV6_SCTP                             ),
	OTX2_TEST(TCP_SCTP                                        ),
	OTX2_TEST(PORT_TCP_SCTP                                   ),
	OTX2_TEST(IPV4_TCP_SCTP                                   ),
	OTX2_TEST(PORT_IPV4_TCP_SCTP                              ),
	OTX2_TEST(IPV6_TCP_SCTP                                   ),
	OTX2_TEST(PORT_IPV6_TCP_SCTP                              ),
	OTX2_TEST(IPV4_IPV6_TCP_SCTP                              ),
	OTX2_TEST(PORT_IPV4_IPV6_TCP_SCTP                         ),
	OTX2_TEST(UDP_SCTP                                        ),
	OTX2_TEST(PORT_UDP_SCTP                                   ),
	OTX2_TEST(IPV4_UDP_SCTP                                   ),
	OTX2_TEST(PORT_IPV4_UDP_SCTP                              ),
	OTX2_TEST(IPV6_UDP_SCTP                                   ),
	OTX2_TEST(PORT_IPV6_UDP_SCTP                              ),
	OTX2_TEST(IPV4_IPV6_UDP_SCTP                              ),
	OTX2_TEST(PORT_IPV4_IPV6_UDP_SCTP                         ),
	OTX2_TEST(TCP_UDP_SCTP                                    ),
	OTX2_TEST(PORT_TCP_UDP_SCTP                               ),
	OTX2_TEST(IPV4_TCP_UDP_SCTP                               ),
	OTX2_TEST(PORT_IPV4_TCP_UDP_SCTP                          ),
	OTX2_TEST(IPV6_TCP_UDP_SCTP                               ),
	OTX2_TEST(PORT_IPV6_TCP_UDP_SCTP                          ),
	OTX2_TEST(IPV4_IPV6_TCP_UDP_SCTP                          ),
	OTX2_TEST(PORT_IPV4_IPV6_TCP_UDP_SCTP                     ),
	OTX2_TEST(NVGRE                                           ),
	OTX2_TEST(PORT_NVGRE                                      ),
	OTX2_TEST(IPV4_NVGRE                                      ),
	OTX2_TEST(PORT_IPV4_NVGRE                                 ),
	OTX2_TEST(IPV6_NVGRE                                      ),
	OTX2_TEST(PORT_IPV6_NVGRE                                 ),
	OTX2_TEST(IPV4_IPV6_NVGRE                                 ),
	OTX2_TEST(PORT_IPV4_IPV6_NVGRE                            ),
	OTX2_TEST(TCP_NVGRE                                       ),
	OTX2_TEST(PORT_TCP_NVGRE                                  ),
	OTX2_TEST(IPV4_TCP_NVGRE                                  ),
	OTX2_TEST(PORT_IPV4_TCP_NVGRE                             ),
	OTX2_TEST(IPV6_TCP_NVGRE                                  ),
	OTX2_TEST(PORT_IPV6_TCP_NVGRE                             ),
	OTX2_TEST(IPV4_IPV6_TCP_NVGRE                             ),
	OTX2_TEST(PORT_IPV4_IPV6_TCP_NVGRE                        ),
	OTX2_TEST(UDP_NVGRE                                       ),
	OTX2_TEST(PORT_UDP_NVGRE                                  ),
	OTX2_TEST(IPV4_UDP_NVGRE                                  ),
	OTX2_TEST(PORT_IPV4_UDP_NVGRE                             ),
	OTX2_TEST(IPV6_UDP_NVGRE                                  ),
	OTX2_TEST(PORT_IPV6_UDP_NVGRE                             ),
	OTX2_TEST(IPV4_IPV6_UDP_NVGRE                             ),
	OTX2_TEST(PORT_IPV4_IPV6_UDP_NVGRE                        ),
	OTX2_TEST(TCP_UDP_NVGRE                                   ),
	OTX2_TEST(PORT_TCP_UDP_NVGRE                              ),
	OTX2_TEST(IPV4_TCP_UDP_NVGRE                              ),
	OTX2_TEST(PORT_IPV4_TCP_UDP_NVGRE                         ),
	OTX2_TEST(IPV6_TCP_UDP_NVGRE                              ),
	OTX2_TEST(PORT_IPV6_TCP_UDP_NVGRE                         ),
	OTX2_TEST(IPV4_IPV6_TCP_UDP_NVGRE                         ),
	OTX2_TEST(PORT_IPV4_IPV6_TCP_UDP_NVGRE                    ),
	OTX2_TEST(SCTP_NVGRE                                      ),
	OTX2_TEST(PORT_SCTP_NVGRE                                 ),
	OTX2_TEST(IPV4_SCTP_NVGRE                                 ),
	OTX2_TEST(PORT_IPV4_SCTP_NVGRE                            ),
	OTX2_TEST(IPV6_SCTP_NVGRE                                 ),
	OTX2_TEST(PORT_IPV6_SCTP_NVGRE                            ),
	OTX2_TEST(IPV4_IPV6_SCTP_NVGRE                            ),
	OTX2_TEST(PORT_IPV4_IPV6_SCTP_NVGRE                       ),
	OTX2_TEST(TCP_SCTP_NVGRE                                  ),
	OTX2_TEST(PORT_TCP_SCTP_NVGRE                             ),
	OTX2_TEST(IPV4_TCP_SCTP_NVGRE                             ),
	OTX2_TEST(PORT_IPV4_TCP_SCTP_NVGRE                        ),
	OTX2_TEST(IPV6_TCP_SCTP_NVGRE                             ),
	OTX2_TEST(PORT_IPV6_TCP_SCTP_NVGRE                        ),
	OTX2_TEST(IPV4_IPV6_TCP_SCTP_NVGRE                        ),
	OTX2_TEST(PORT_IPV4_IPV6_TCP_SCTP_NVGRE                   ),
	OTX2_TEST(UDP_SCTP_NVGRE                                  ),
	OTX2_TEST(PORT_UDP_SCTP_NVGRE                             ),
	OTX2_TEST(IPV4_UDP_SCTP_NVGRE                             ),
	OTX2_TEST(PORT_IPV4_UDP_SCTP_NVGRE                        ),
	OTX2_TEST(IPV6_UDP_SCTP_NVGRE                             ),
	OTX2_TEST(PORT_IPV6_UDP_SCTP_NVGRE                        ),
	OTX2_TEST(IPV4_IPV6_UDP_SCTP_NVGRE                        ),
	OTX2_TEST(PORT_IPV4_IPV6_UDP_SCTP_NVGRE                   ),
	OTX2_TEST(TCP_UDP_SCTP_NVGRE                              ),
	OTX2_TEST(PORT_TCP_UDP_SCTP_NVGRE                         ),
	OTX2_TEST(IPV4_TCP_UDP_SCTP_NVGRE                         ),
	OTX2_TEST(PORT_IPV4_TCP_UDP_SCTP_NVGRE                    ),
	OTX2_TEST(IPV6_TCP_UDP_SCTP_NVGRE                         ),
	OTX2_TEST(PORT_IPV6_TCP_UDP_SCTP_NVGRE                    ),
	OTX2_TEST(IPV4_IPV6_TCP_UDP_SCTP_NVGRE                    ),
	OTX2_TEST(PORT_IPV4_IPV6_TCP_UDP_SCTP_NVGRE               ),
	OTX2_TEST(VXLAN                                           ),
	OTX2_TEST(PORT_VXLAN                                      ),
	OTX2_TEST(IPV4_VXLAN                                      ),
	OTX2_TEST(PORT_IPV4_VXLAN                                 ),
	OTX2_TEST(IPV6_VXLAN                                      ),
	OTX2_TEST(PORT_IPV6_VXLAN                                 ),
	OTX2_TEST(IPV4_IPV6_VXLAN                                 ),
	OTX2_TEST(PORT_IPV4_IPV6_VXLAN                            ),
	OTX2_TEST(TCP_VXLAN                                       ),
	OTX2_TEST(PORT_TCP_VXLAN                                  ),
	OTX2_TEST(IPV4_TCP_VXLAN                                  ),
	OTX2_TEST(PORT_IPV4_TCP_VXLAN                             ),
	OTX2_TEST(IPV6_TCP_VXLAN                                  ),
	OTX2_TEST(PORT_IPV6_TCP_VXLAN                             ),
	OTX2_TEST(IPV4_IPV6_TCP_VXLAN                             ),
	OTX2_TEST(PORT_IPV4_IPV6_TCP_VXLAN                        ),
	OTX2_TEST(UDP_VXLAN                                       ),
	OTX2_TEST(PORT_UDP_VXLAN                                  ),
	OTX2_TEST(IPV4_UDP_VXLAN                                  ),
	OTX2_TEST(PORT_IPV4_UDP_VXLAN                             ),
	OTX2_TEST(IPV6_UDP_VXLAN                                  ),
	OTX2_TEST(PORT_IPV6_UDP_VXLAN                             ),
	OTX2_TEST(IPV4_IPV6_UDP_VXLAN                             ),
	OTX2_TEST(PORT_IPV4_IPV6_UDP_VXLAN                        ),
	OTX2_TEST(TCP_UDP_VXLAN                                   ),
	OTX2_TEST(PORT_TCP_UDP_VXLAN                              ),
	OTX2_TEST(IPV4_TCP_UDP_VXLAN                              ),
	OTX2_TEST(PORT_IPV4_TCP_UDP_VXLAN                         ),
	OTX2_TEST(IPV6_TCP_UDP_VXLAN                              ),
	OTX2_TEST(PORT_IPV6_TCP_UDP_VXLAN                         ),
	OTX2_TEST(IPV4_IPV6_TCP_UDP_VXLAN                         ),
	OTX2_TEST(PORT_IPV4_IPV6_TCP_UDP_VXLAN                    ),
	OTX2_TEST(SCTP_VXLAN                                      ),
	OTX2_TEST(PORT_SCTP_VXLAN                                 ),
	OTX2_TEST(IPV4_SCTP_VXLAN                                 ),
	OTX2_TEST(PORT_IPV4_SCTP_VXLAN                            ),
	OTX2_TEST(IPV6_SCTP_VXLAN                                 ),
	OTX2_TEST(PORT_IPV6_SCTP_VXLAN                            ),
	OTX2_TEST(IPV4_IPV6_SCTP_VXLAN                            ),
	OTX2_TEST(PORT_IPV4_IPV6_SCTP_VXLAN                       ),
	OTX2_TEST(TCP_SCTP_VXLAN                                  ),
	OTX2_TEST(PORT_TCP_SCTP_VXLAN                             ),
	OTX2_TEST(IPV4_TCP_SCTP_VXLAN                             ),
	OTX2_TEST(PORT_IPV4_TCP_SCTP_VXLAN                        ),
	OTX2_TEST(IPV6_TCP_SCTP_VXLAN                             ),
	OTX2_TEST(PORT_IPV6_TCP_SCTP_VXLAN                        ),
	OTX2_TEST(IPV4_IPV6_TCP_SCTP_VXLAN                        ),
	OTX2_TEST(PORT_IPV4_IPV6_TCP_SCTP_VXLAN                   ),
	OTX2_TEST(UDP_SCTP_VXLAN                                  ),
	OTX2_TEST(PORT_UDP_SCTP_VXLAN                             ),
	OTX2_TEST(IPV4_UDP_SCTP_VXLAN                             ),
	OTX2_TEST(PORT_IPV4_UDP_SCTP_VXLAN                        ),
	OTX2_TEST(IPV6_UDP_SCTP_VXLAN                             ),
	OTX2_TEST(PORT_IPV6_UDP_SCTP_VXLAN                        ),
	OTX2_TEST(IPV4_IPV6_UDP_SCTP_VXLAN                        ),
	OTX2_TEST(PORT_IPV4_IPV6_UDP_SCTP_VXLAN                   ),
	OTX2_TEST(TCP_UDP_SCTP_VXLAN                              ),
	OTX2_TEST(PORT_TCP_UDP_SCTP_VXLAN                         ),
	OTX2_TEST(IPV4_TCP_UDP_SCTP_VXLAN                         ),
	OTX2_TEST(PORT_IPV4_TCP_UDP_SCTP_VXLAN                    ),
	OTX2_TEST(IPV6_TCP_UDP_SCTP_VXLAN                         ),
	OTX2_TEST(PORT_IPV6_TCP_UDP_SCTP_VXLAN                    ),
	OTX2_TEST(IPV4_IPV6_TCP_UDP_SCTP_VXLAN                    ),
	OTX2_TEST(PORT_IPV4_IPV6_TCP_UDP_SCTP_VXLAN               ),
	OTX2_TEST(NVGRE_VXLAN                                     ),
	OTX2_TEST(PORT_NVGRE_VXLAN                                ),
	OTX2_TEST(IPV4_NVGRE_VXLAN                                ),
	OTX2_TEST(PORT_IPV4_NVGRE_VXLAN                           ),
	OTX2_TEST(IPV6_NVGRE_VXLAN                                ),
	OTX2_TEST(PORT_IPV6_NVGRE_VXLAN                           ),
	OTX2_TEST(IPV4_IPV6_NVGRE_VXLAN                           ),
	OTX2_TEST(PORT_IPV4_IPV6_NVGRE_VXLAN                      ),
	OTX2_TEST(TCP_NVGRE_VXLAN                                 ),
	OTX2_TEST(PORT_TCP_NVGRE_VXLAN                            ),
	OTX2_TEST(IPV4_TCP_NVGRE_VXLAN                            ),
	OTX2_TEST(PORT_IPV4_TCP_NVGRE_VXLAN                       ),
	OTX2_TEST(IPV6_TCP_NVGRE_VXLAN                            ),
	OTX2_TEST(PORT_IPV6_TCP_NVGRE_VXLAN                       ),
	OTX2_TEST(IPV4_IPV6_TCP_NVGRE_VXLAN                       ),
	OTX2_TEST(PORT_IPV4_IPV6_TCP_NVGRE_VXLAN                  ),
	OTX2_TEST(UDP_NVGRE_VXLAN                                 ),
	OTX2_TEST(PORT_UDP_NVGRE_VXLAN                            ),
	OTX2_TEST(IPV4_UDP_NVGRE_VXLAN                            ),
	OTX2_TEST(PORT_IPV4_UDP_NVGRE_VXLAN                       ),
	OTX2_TEST(IPV6_UDP_NVGRE_VXLAN                            ),
	OTX2_TEST(PORT_IPV6_UDP_NVGRE_VXLAN                       ),
	OTX2_TEST(IPV4_IPV6_UDP_NVGRE_VXLAN                       ),
	OTX2_TEST(PORT_IPV4_IPV6_UDP_NVGRE_VXLAN                  ),
	OTX2_TEST(TCP_UDP_NVGRE_VXLAN                             ),
	OTX2_TEST(PORT_TCP_UDP_NVGRE_VXLAN                        ),
	OTX2_TEST(IPV4_TCP_UDP_NVGRE_VXLAN                        ),
	OTX2_TEST(PORT_IPV4_TCP_UDP_NVGRE_VXLAN                   ),
	OTX2_TEST(IPV6_TCP_UDP_NVGRE_VXLAN                        ),
	OTX2_TEST(PORT_IPV6_TCP_UDP_NVGRE_VXLAN                   ),
	OTX2_TEST(IPV4_IPV6_TCP_UDP_NVGRE_VXLAN                   ),
	OTX2_TEST(PORT_IPV4_IPV6_TCP_UDP_NVGRE_VXLAN              ),
	OTX2_TEST(SCTP_NVGRE_VXLAN                                ),
	OTX2_TEST(PORT_SCTP_NVGRE_VXLAN                           ),
	OTX2_TEST(IPV4_SCTP_NVGRE_VXLAN                           ),
	OTX2_TEST(PORT_IPV4_SCTP_NVGRE_VXLAN                      ),
	OTX2_TEST(IPV6_SCTP_NVGRE_VXLAN                           ),
	OTX2_TEST(PORT_IPV6_SCTP_NVGRE_VXLAN                      ),
	OTX2_TEST(IPV4_IPV6_SCTP_NVGRE_VXLAN                      ),
	OTX2_TEST(PORT_IPV4_IPV6_SCTP_NVGRE_VXLAN                 ),
	OTX2_TEST(TCP_SCTP_NVGRE_VXLAN                            ),
	OTX2_TEST(PORT_TCP_SCTP_NVGRE_VXLAN                       ),
	OTX2_TEST(IPV4_TCP_SCTP_NVGRE_VXLAN                       ),
	OTX2_TEST(PORT_IPV4_TCP_SCTP_NVGRE_VXLAN                  ),
	OTX2_TEST(IPV6_TCP_SCTP_NVGRE_VXLAN                       ),
	OTX2_TEST(PORT_IPV6_TCP_SCTP_NVGRE_VXLAN                  ),
	OTX2_TEST(IPV4_IPV6_TCP_SCTP_NVGRE_VXLAN                  ),
	OTX2_TEST(PORT_IPV4_IPV6_TCP_SCTP_NVGRE_VXLAN             ),
	OTX2_TEST(UDP_SCTP_NVGRE_VXLAN                            ),
	OTX2_TEST(PORT_UDP_SCTP_NVGRE_VXLAN                       ),
	OTX2_TEST(IPV4_UDP_SCTP_NVGRE_VXLAN                       ),
	OTX2_TEST(PORT_IPV4_UDP_SCTP_NVGRE_VXLAN                  ),
	OTX2_TEST(IPV6_UDP_SCTP_NVGRE_VXLAN                       ),
	OTX2_TEST(PORT_IPV6_UDP_SCTP_NVGRE_VXLAN                  ),
	OTX2_TEST(IPV4_IPV6_UDP_SCTP_NVGRE_VXLAN                  ),
	OTX2_TEST(PORT_IPV4_IPV6_UDP_SCTP_NVGRE_VXLAN             ),
	OTX2_TEST(TCP_UDP_SCTP_NVGRE_VXLAN                        ),
	OTX2_TEST(PORT_TCP_UDP_SCTP_NVGRE_VXLAN                   ),
	OTX2_TEST(IPV4_TCP_UDP_SCTP_NVGRE_VXLAN                   ),
	OTX2_TEST(PORT_IPV4_TCP_UDP_SCTP_NVGRE_VXLAN              ),
	OTX2_TEST(IPV6_TCP_UDP_SCTP_NVGRE_VXLAN                   ),
	OTX2_TEST(PORT_IPV6_TCP_UDP_SCTP_NVGRE_VXLAN              ),
	OTX2_TEST(IPV4_IPV6_TCP_UDP_SCTP_NVGRE_VXLAN              ),
	OTX2_TEST(PORT_IPV4_IPV6_TCP_UDP_SCTP_NVGRE_VXLAN         ),
	OTX2_TEST(GENEVE                                          ),
	OTX2_TEST(PORT_GENEVE                                     ),
	OTX2_TEST(IPV4_GENEVE                                     ),
	OTX2_TEST(PORT_IPV4_GENEVE                                ),
	OTX2_TEST(IPV6_GENEVE                                     ),
	OTX2_TEST(PORT_IPV6_GENEVE                                ),
	OTX2_TEST(IPV4_IPV6_GENEVE                                ),
	OTX2_TEST(PORT_IPV4_IPV6_GENEVE                           ),
	OTX2_TEST(TCP_GENEVE                                      ),
	OTX2_TEST(PORT_TCP_GENEVE                                 ),
	OTX2_TEST(IPV4_TCP_GENEVE                                 ),
	OTX2_TEST(PORT_IPV4_TCP_GENEVE                            ),
	OTX2_TEST(IPV6_TCP_GENEVE                                 ),
	OTX2_TEST(PORT_IPV6_TCP_GENEVE                            ),
	OTX2_TEST(IPV4_IPV6_TCP_GENEVE                            ),
	OTX2_TEST(PORT_IPV4_IPV6_TCP_GENEVE                       ),
	OTX2_TEST(UDP_GENEVE                                      ),
	OTX2_TEST(PORT_UDP_GENEVE                                 ),
	OTX2_TEST(IPV4_UDP_GENEVE                                 ),
	OTX2_TEST(PORT_IPV4_UDP_GENEVE                            ),
	OTX2_TEST(IPV6_UDP_GENEVE                                 ),
	OTX2_TEST(PORT_IPV6_UDP_GENEVE                            ),
	OTX2_TEST(IPV4_IPV6_UDP_GENEVE                            ),
	OTX2_TEST(PORT_IPV4_IPV6_UDP_GENEVE                       ),
	OTX2_TEST(TCP_UDP_GENEVE                                  ),
	OTX2_TEST(PORT_TCP_UDP_GENEVE                             ),
	OTX2_TEST(IPV4_TCP_UDP_GENEVE                             ),
	OTX2_TEST(PORT_IPV4_TCP_UDP_GENEVE                        ),
	OTX2_TEST(IPV6_TCP_UDP_GENEVE                             ),
	OTX2_TEST(PORT_IPV6_TCP_UDP_GENEVE                        ),
	OTX2_TEST(IPV4_IPV6_TCP_UDP_GENEVE                        ),
	OTX2_TEST(PORT_IPV4_IPV6_TCP_UDP_GENEVE                   ),
	OTX2_TEST(SCTP_GENEVE                                     ),
	OTX2_TEST(PORT_SCTP_GENEVE                                ),
	OTX2_TEST(IPV4_SCTP_GENEVE                                ),
	OTX2_TEST(PORT_IPV4_SCTP_GENEVE                           ),
	OTX2_TEST(IPV6_SCTP_GENEVE                                ),
	OTX2_TEST(PORT_IPV6_SCTP_GENEVE                           ),
	OTX2_TEST(IPV4_IPV6_SCTP_GENEVE                           ),
	OTX2_TEST(PORT_IPV4_IPV6_SCTP_GENEVE                      ),
	OTX2_TEST(TCP_SCTP_GENEVE                                 ),
	OTX2_TEST(PORT_TCP_SCTP_GENEVE                            ),
	OTX2_TEST(IPV4_TCP_SCTP_GENEVE                            ),
	OTX2_TEST(PORT_IPV4_TCP_SCTP_GENEVE                       ),
	OTX2_TEST(IPV6_TCP_SCTP_GENEVE                            ),
	OTX2_TEST(PORT_IPV6_TCP_SCTP_GENEVE                       ),
	OTX2_TEST(IPV4_IPV6_TCP_SCTP_GENEVE                       ),
	OTX2_TEST(PORT_IPV4_IPV6_TCP_SCTP_GENEVE                  ),
	OTX2_TEST(UDP_SCTP_GENEVE                                 ),
	OTX2_TEST(PORT_UDP_SCTP_GENEVE                            ),
	OTX2_TEST(IPV4_UDP_SCTP_GENEVE                            ),
	OTX2_TEST(PORT_IPV4_UDP_SCTP_GENEVE                       ),
	OTX2_TEST(IPV6_UDP_SCTP_GENEVE                            ),
	OTX2_TEST(PORT_IPV6_UDP_SCTP_GENEVE                       ),
	OTX2_TEST(IPV4_IPV6_UDP_SCTP_GENEVE                       ),
	OTX2_TEST(PORT_IPV4_IPV6_UDP_SCTP_GENEVE                  ),
	OTX2_TEST(TCP_UDP_SCTP_GENEVE                             ),
	OTX2_TEST(PORT_TCP_UDP_SCTP_GENEVE                        ),
	OTX2_TEST(IPV4_TCP_UDP_SCTP_GENEVE                        ),
	OTX2_TEST(PORT_IPV4_TCP_UDP_SCTP_GENEVE                   ),
	OTX2_TEST(IPV6_TCP_UDP_SCTP_GENEVE                        ),
	OTX2_TEST(PORT_IPV6_TCP_UDP_SCTP_GENEVE                   ),
	OTX2_TEST(IPV4_IPV6_TCP_UDP_SCTP_GENEVE                   ),
	OTX2_TEST(PORT_IPV4_IPV6_TCP_UDP_SCTP_GENEVE              ),
	OTX2_TEST(NVGRE_GENEVE                                    ),
	OTX2_TEST(PORT_NVGRE_GENEVE                               ),
	OTX2_TEST(IPV4_NVGRE_GENEVE                               ),
	OTX2_TEST(PORT_IPV4_NVGRE_GENEVE                          ),
	OTX2_TEST(IPV6_NVGRE_GENEVE                               ),
	OTX2_TEST(PORT_IPV6_NVGRE_GENEVE                          ),
	OTX2_TEST(IPV4_IPV6_NVGRE_GENEVE                          ),
	OTX2_TEST(PORT_IPV4_IPV6_NVGRE_GENEVE                     ),
	OTX2_TEST(TCP_NVGRE_GENEVE                                ),
	OTX2_TEST(PORT_TCP_NVGRE_GENEVE                           ),
	OTX2_TEST(IPV4_TCP_NVGRE_GENEVE                           ),
	OTX2_TEST(PORT_IPV4_TCP_NVGRE_GENEVE                      ),
	OTX2_TEST(IPV6_TCP_NVGRE_GENEVE                           ),
	OTX2_TEST(PORT_IPV6_TCP_NVGRE_GENEVE                      ),
	OTX2_TEST(IPV4_IPV6_TCP_NVGRE_GENEVE                      ),
	OTX2_TEST(PORT_IPV4_IPV6_TCP_NVGRE_GENEVE                 ),
	OTX2_TEST(UDP_NVGRE_GENEVE                                ),
	OTX2_TEST(PORT_UDP_NVGRE_GENEVE                           ),
	OTX2_TEST(IPV4_UDP_NVGRE_GENEVE                           ),
	OTX2_TEST(PORT_IPV4_UDP_NVGRE_GENEVE                      ),
	OTX2_TEST(IPV6_UDP_NVGRE_GENEVE                           ),
	OTX2_TEST(PORT_IPV6_UDP_NVGRE_GENEVE                      ),
	OTX2_TEST(IPV4_IPV6_UDP_NVGRE_GENEVE                      ),
	OTX2_TEST(PORT_IPV4_IPV6_UDP_NVGRE_GENEVE                 ),
	OTX2_TEST(TCP_UDP_NVGRE_GENEVE                            ),
	OTX2_TEST(PORT_TCP_UDP_NVGRE_GENEVE                       ),
	OTX2_TEST(IPV4_TCP_UDP_NVGRE_GENEVE                       ),
	OTX2_TEST(PORT_IPV4_TCP_UDP_NVGRE_GENEVE                  ),
	OTX2_TEST(IPV6_TCP_UDP_NVGRE_GENEVE                       ),
	OTX2_TEST(PORT_IPV6_TCP_UDP_NVGRE_GENEVE                  ),
	OTX2_TEST(IPV4_IPV6_TCP_UDP_NVGRE_GENEVE                  ),
	OTX2_TEST(PORT_IPV4_IPV6_TCP_UDP_NVGRE_GENEVE             ),
	OTX2_TEST(SCTP_NVGRE_GENEVE                               ),
	OTX2_TEST(PORT_SCTP_NVGRE_GENEVE                          ),
	OTX2_TEST(IPV4_SCTP_NVGRE_GENEVE                          ),
	OTX2_TEST(PORT_IPV4_SCTP_NVGRE_GENEVE                     ),
	OTX2_TEST(IPV6_SCTP_NVGRE_GENEVE                          ),
	OTX2_TEST(PORT_IPV6_SCTP_NVGRE_GENEVE                     ),
	OTX2_TEST(IPV4_IPV6_SCTP_NVGRE_GENEVE                     ),
	OTX2_TEST(PORT_IPV4_IPV6_SCTP_NVGRE_GENEVE                ),
	OTX2_TEST(TCP_SCTP_NVGRE_GENEVE                           ),
	OTX2_TEST(PORT_TCP_SCTP_NVGRE_GENEVE                      ),
	OTX2_TEST(IPV4_TCP_SCTP_NVGRE_GENEVE                      ),
	OTX2_TEST(PORT_IPV4_TCP_SCTP_NVGRE_GENEVE                 ),
	OTX2_TEST(IPV6_TCP_SCTP_NVGRE_GENEVE                      ),
	OTX2_TEST(PORT_IPV6_TCP_SCTP_NVGRE_GENEVE                 ),
	OTX2_TEST(IPV4_IPV6_TCP_SCTP_NVGRE_GENEVE                 ),
	OTX2_TEST(PORT_IPV4_IPV6_TCP_SCTP_NVGRE_GENEVE            ),
	OTX2_TEST(UDP_SCTP_NVGRE_GENEVE                           ),
	OTX2_TEST(PORT_UDP_SCTP_NVGRE_GENEVE                      ),
	OTX2_TEST(IPV4_UDP_SCTP_NVGRE_GENEVE                      ),
	OTX2_TEST(PORT_IPV4_UDP_SCTP_NVGRE_GENEVE                 ),
	OTX2_TEST(IPV6_UDP_SCTP_NVGRE_GENEVE                      ),
	OTX2_TEST(PORT_IPV6_UDP_SCTP_NVGRE_GENEVE                 ),
	OTX2_TEST(IPV4_IPV6_UDP_SCTP_NVGRE_GENEVE                 ),
	OTX2_TEST(PORT_IPV4_IPV6_UDP_SCTP_NVGRE_GENEVE            ),
	OTX2_TEST(TCP_UDP_SCTP_NVGRE_GENEVE                       ),
	OTX2_TEST(PORT_TCP_UDP_SCTP_NVGRE_GENEVE                  ),
	OTX2_TEST(IPV4_TCP_UDP_SCTP_NVGRE_GENEVE                  ),
	OTX2_TEST(PORT_IPV4_TCP_UDP_SCTP_NVGRE_GENEVE             ),
	OTX2_TEST(IPV6_TCP_UDP_SCTP_NVGRE_GENEVE                  ),
	OTX2_TEST(PORT_IPV6_TCP_UDP_SCTP_NVGRE_GENEVE             ),
	OTX2_TEST(IPV4_IPV6_TCP_UDP_SCTP_NVGRE_GENEVE             ),
	OTX2_TEST(PORT_IPV4_IPV6_TCP_UDP_SCTP_NVGRE_GENEVE        ),
	OTX2_TEST(VXLAN_GENEVE                                    ),
	OTX2_TEST(PORT_VXLAN_GENEVE                               ),
	OTX2_TEST(IPV4_VXLAN_GENEVE                               ),
	OTX2_TEST(PORT_IPV4_VXLAN_GENEVE                          ),
	OTX2_TEST(IPV6_VXLAN_GENEVE                               ),
	OTX2_TEST(PORT_IPV6_VXLAN_GENEVE                          ),
	OTX2_TEST(IPV4_IPV6_VXLAN_GENEVE                          ),
	OTX2_TEST(PORT_IPV4_IPV6_VXLAN_GENEVE                     ),
	OTX2_TEST(TCP_VXLAN_GENEVE                                ),
	OTX2_TEST(PORT_TCP_VXLAN_GENEVE                           ),
	OTX2_TEST(IPV4_TCP_VXLAN_GENEVE                           ),
	OTX2_TEST(PORT_IPV4_TCP_VXLAN_GENEVE                      ),
	OTX2_TEST(IPV6_TCP_VXLAN_GENEVE                           ),
	OTX2_TEST(PORT_IPV6_TCP_VXLAN_GENEVE                      ),
	OTX2_TEST(IPV4_IPV6_TCP_VXLAN_GENEVE                      ),
	OTX2_TEST(PORT_IPV4_IPV6_TCP_VXLAN_GENEVE                 ),
	OTX2_TEST(UDP_VXLAN_GENEVE                                ),
	OTX2_TEST(PORT_UDP_VXLAN_GENEVE                           ),
	OTX2_TEST(IPV4_UDP_VXLAN_GENEVE                           ),
	OTX2_TEST(PORT_IPV4_UDP_VXLAN_GENEVE                      ),
	OTX2_TEST(IPV6_UDP_VXLAN_GENEVE                           ),
	OTX2_TEST(PORT_IPV6_UDP_VXLAN_GENEVE                      ),
	OTX2_TEST(IPV4_IPV6_UDP_VXLAN_GENEVE                      ),
	OTX2_TEST(PORT_IPV4_IPV6_UDP_VXLAN_GENEVE                 ),
	OTX2_TEST(TCP_UDP_VXLAN_GENEVE                            ),
	OTX2_TEST(PORT_TCP_UDP_VXLAN_GENEVE                       ),
	OTX2_TEST(IPV4_TCP_UDP_VXLAN_GENEVE                       ),
	OTX2_TEST(PORT_IPV4_TCP_UDP_VXLAN_GENEVE                  ),
	OTX2_TEST(IPV6_TCP_UDP_VXLAN_GENEVE                       ),
	OTX2_TEST(PORT_IPV6_TCP_UDP_VXLAN_GENEVE                  ),
	OTX2_TEST(IPV4_IPV6_TCP_UDP_VXLAN_GENEVE                  ),
	OTX2_TEST(PORT_IPV4_IPV6_TCP_UDP_VXLAN_GENEVE             ),
	OTX2_TEST(SCTP_VXLAN_GENEVE                               ),
	OTX2_TEST(PORT_SCTP_VXLAN_GENEVE                          ),
	OTX2_TEST(IPV4_SCTP_VXLAN_GENEVE                          ),
	OTX2_TEST(PORT_IPV4_SCTP_VXLAN_GENEVE                     ),
	OTX2_TEST(IPV6_SCTP_VXLAN_GENEVE                          ),
	OTX2_TEST(PORT_IPV6_SCTP_VXLAN_GENEVE                     ),
	OTX2_TEST(IPV4_IPV6_SCTP_VXLAN_GENEVE                     ),
	OTX2_TEST(PORT_IPV4_IPV6_SCTP_VXLAN_GENEVE                ),
	OTX2_TEST(TCP_SCTP_VXLAN_GENEVE                           ),
	OTX2_TEST(PORT_TCP_SCTP_VXLAN_GENEVE                      ),
	OTX2_TEST(IPV4_TCP_SCTP_VXLAN_GENEVE                      ),
	OTX2_TEST(PORT_IPV4_TCP_SCTP_VXLAN_GENEVE                 ),
	OTX2_TEST(IPV6_TCP_SCTP_VXLAN_GENEVE                      ),
	OTX2_TEST(PORT_IPV6_TCP_SCTP_VXLAN_GENEVE                 ),
	OTX2_TEST(IPV4_IPV6_TCP_SCTP_VXLAN_GENEVE                 ),
	OTX2_TEST(PORT_IPV4_IPV6_TCP_SCTP_VXLAN_GENEVE            ),
	OTX2_TEST(UDP_SCTP_VXLAN_GENEVE                           ),
	OTX2_TEST(PORT_UDP_SCTP_VXLAN_GENEVE                      ),
	OTX2_TEST(IPV4_UDP_SCTP_VXLAN_GENEVE                      ),
	OTX2_TEST(PORT_IPV4_UDP_SCTP_VXLAN_GENEVE                 ),
	OTX2_TEST(IPV6_UDP_SCTP_VXLAN_GENEVE                      ),
	OTX2_TEST(PORT_IPV6_UDP_SCTP_VXLAN_GENEVE                 ),
	OTX2_TEST(IPV4_IPV6_UDP_SCTP_VXLAN_GENEVE                 ),
	OTX2_TEST(PORT_IPV4_IPV6_UDP_SCTP_VXLAN_GENEVE            ),
	OTX2_TEST(TCP_UDP_SCTP_VXLAN_GENEVE                       ),
	OTX2_TEST(PORT_TCP_UDP_SCTP_VXLAN_GENEVE                  ),
	OTX2_TEST(IPV4_TCP_UDP_SCTP_VXLAN_GENEVE                  ),
	OTX2_TEST(PORT_IPV4_TCP_UDP_SCTP_VXLAN_GENEVE             ),
	OTX2_TEST(IPV6_TCP_UDP_SCTP_VXLAN_GENEVE                  ),
	OTX2_TEST(PORT_IPV6_TCP_UDP_SCTP_VXLAN_GENEVE             ),
	OTX2_TEST(IPV4_IPV6_TCP_UDP_SCTP_VXLAN_GENEVE             ),
	OTX2_TEST(PORT_IPV4_IPV6_TCP_UDP_SCTP_VXLAN_GENEVE        ),
	OTX2_TEST(NVGRE_VXLAN_GENEVE                              ),
	OTX2_TEST(PORT_NVGRE_VXLAN_GENEVE                         ),
	OTX2_TEST(IPV4_NVGRE_VXLAN_GENEVE                         ),
	OTX2_TEST(PORT_IPV4_NVGRE_VXLAN_GENEVE                    ),
	OTX2_TEST(IPV6_NVGRE_VXLAN_GENEVE                         ),
	OTX2_TEST(PORT_IPV6_NVGRE_VXLAN_GENEVE                    ),
	OTX2_TEST(IPV4_IPV6_NVGRE_VXLAN_GENEVE                    ),
	OTX2_TEST(PORT_IPV4_IPV6_NVGRE_VXLAN_GENEVE               ),
	OTX2_TEST(TCP_NVGRE_VXLAN_GENEVE                          ),
	OTX2_TEST(PORT_TCP_NVGRE_VXLAN_GENEVE                     ),
	OTX2_TEST(IPV4_TCP_NVGRE_VXLAN_GENEVE                     ),
	OTX2_TEST(PORT_IPV4_TCP_NVGRE_VXLAN_GENEVE                ),
	OTX2_TEST(IPV6_TCP_NVGRE_VXLAN_GENEVE                     ),
	OTX2_TEST(PORT_IPV6_TCP_NVGRE_VXLAN_GENEVE                ),
	OTX2_TEST(IPV4_IPV6_TCP_NVGRE_VXLAN_GENEVE                ),
	OTX2_TEST(PORT_IPV4_IPV6_TCP_NVGRE_VXLAN_GENEVE           ),
	OTX2_TEST(UDP_NVGRE_VXLAN_GENEVE                          ),
	OTX2_TEST(PORT_UDP_NVGRE_VXLAN_GENEVE                     ),
	OTX2_TEST(IPV4_UDP_NVGRE_VXLAN_GENEVE                     ),
	OTX2_TEST(PORT_IPV4_UDP_NVGRE_VXLAN_GENEVE                ),
	OTX2_TEST(IPV6_UDP_NVGRE_VXLAN_GENEVE                     ),
	OTX2_TEST(PORT_IPV6_UDP_NVGRE_VXLAN_GENEVE                ),
	OTX2_TEST(IPV4_IPV6_UDP_NVGRE_VXLAN_GENEVE                ),
	OTX2_TEST(PORT_IPV4_IPV6_UDP_NVGRE_VXLAN_GENEVE           ),
	OTX2_TEST(TCP_UDP_NVGRE_VXLAN_GENEVE                      ),
	OTX2_TEST(PORT_TCP_UDP_NVGRE_VXLAN_GENEVE                 ),
	OTX2_TEST(IPV4_TCP_UDP_NVGRE_VXLAN_GENEVE                 ),
	OTX2_TEST(PORT_IPV4_TCP_UDP_NVGRE_VXLAN_GENEVE            ),
	OTX2_TEST(IPV6_TCP_UDP_NVGRE_VXLAN_GENEVE                 ),
	OTX2_TEST(PORT_IPV6_TCP_UDP_NVGRE_VXLAN_GENEVE            ),
	OTX2_TEST(IPV4_IPV6_TCP_UDP_NVGRE_VXLAN_GENEVE            ),
	OTX2_TEST(PORT_IPV4_IPV6_TCP_UDP_NVGRE_VXLAN_GENEVE       ),
	OTX2_TEST(SCTP_NVGRE_VXLAN_GENEVE                         ),
	OTX2_TEST(PORT_SCTP_NVGRE_VXLAN_GENEVE                    ),
	OTX2_TEST(IPV4_SCTP_NVGRE_VXLAN_GENEVE                    ),
	OTX2_TEST(PORT_IPV4_SCTP_NVGRE_VXLAN_GENEVE               ),
	OTX2_TEST(IPV6_SCTP_NVGRE_VXLAN_GENEVE                    ),
	OTX2_TEST(PORT_IPV6_SCTP_NVGRE_VXLAN_GENEVE               ),
	OTX2_TEST(IPV4_IPV6_SCTP_NVGRE_VXLAN_GENEVE               ),
	OTX2_TEST(PORT_IPV4_IPV6_SCTP_NVGRE_VXLAN_GENEVE          ),
	OTX2_TEST(TCP_SCTP_NVGRE_VXLAN_GENEVE                     ),
	OTX2_TEST(PORT_TCP_SCTP_NVGRE_VXLAN_GENEVE                ),
	OTX2_TEST(IPV4_TCP_SCTP_NVGRE_VXLAN_GENEVE                ),
	OTX2_TEST(PORT_IPV4_TCP_SCTP_NVGRE_VXLAN_GENEVE           ),
	OTX2_TEST(IPV6_TCP_SCTP_NVGRE_VXLAN_GENEVE                ),
	OTX2_TEST(PORT_IPV6_TCP_SCTP_NVGRE_VXLAN_GENEVE           ),
	OTX2_TEST(IPV4_IPV6_TCP_SCTP_NVGRE_VXLAN_GENEVE           ),
	OTX2_TEST(PORT_IPV4_IPV6_TCP_SCTP_NVGRE_VXLAN_GENEVE      ),
	OTX2_TEST(UDP_SCTP_NVGRE_VXLAN_GENEVE                     ),
	OTX2_TEST(PORT_UDP_SCTP_NVGRE_VXLAN_GENEVE                ),
	OTX2_TEST(IPV4_UDP_SCTP_NVGRE_VXLAN_GENEVE                ),
	OTX2_TEST(PORT_IPV4_UDP_SCTP_NVGRE_VXLAN_GENEVE           ),
	OTX2_TEST(IPV6_UDP_SCTP_NVGRE_VXLAN_GENEVE                ),
	OTX2_TEST(PORT_IPV6_UDP_SCTP_NVGRE_VXLAN_GENEVE           ),
	OTX2_TEST(IPV4_IPV6_UDP_SCTP_NVGRE_VXLAN_GENEVE           ),
	OTX2_TEST(PORT_IPV4_IPV6_UDP_SCTP_NVGRE_VXLAN_GENEVE      ),
	OTX2_TEST(TCP_UDP_SCTP_NVGRE_VXLAN_GENEVE                 ),
	OTX2_TEST(PORT_TCP_UDP_SCTP_NVGRE_VXLAN_GENEVE            ),
	OTX2_TEST(IPV4_TCP_UDP_SCTP_NVGRE_VXLAN_GENEVE            ),
	OTX2_TEST(PORT_IPV4_TCP_UDP_SCTP_NVGRE_VXLAN_GENEVE       ),
	OTX2_TEST(IPV6_TCP_UDP_SCTP_NVGRE_VXLAN_GENEVE            ),
	OTX2_TEST(PORT_IPV6_TCP_UDP_SCTP_NVGRE_VXLAN_GENEVE       ),
	OTX2_TEST(IPV4_IPV6_TCP_UDP_SCTP_NVGRE_VXLAN_GENEVE       ),
	OTX2_TEST(PORT_IPV4_IPV6_TCP_UDP_SCTP_NVGRE_VXLAN_GENEVE  ),
 };
int main(void)
{
	return OTX2_RUN_TESTS(unit_tests);
}
