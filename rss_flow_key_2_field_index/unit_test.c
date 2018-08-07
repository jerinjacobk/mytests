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
	if (rc)
		return rc;

	rc = get_nr_feilds((struct nix_rx_flowkey_alg *)field);
	if (rc != expected_fields)
		return -ERANGE;

	rc = get_last_key_offset((struct nix_rx_flowkey_alg *)field);
	if (rc != expected_last_key_off)
		return -EINVAL;

	return 0;
}

static int
IPV4__IPV6(void)
{
	return result_checker(FLOW_KEY_TYPE_IPV4 | FLOW_KEY_TYPE_IPV6, 0, 2, 0);
}

static int
IPV4__IPV6__TCP(void)
{
	return result_checker(FLOW_KEY_TYPE_IPV4 | FLOW_KEY_TYPE_IPV6 | FLOW_KEY_TYPE_TCP, 0, 3, 32);
}

static int
IPV4__IPV6__UDP(void)
{
	return result_checker(FLOW_KEY_TYPE_IPV4 | FLOW_KEY_TYPE_IPV6 | FLOW_KEY_TYPE_UDP, 0, 3, 32);
}

static int
IPV4__IPV6__SCTP(void)
{
	return result_checker(FLOW_KEY_TYPE_IPV4 | FLOW_KEY_TYPE_IPV6 | FLOW_KEY_TYPE_SCTP, 0, 3, 32);
}

static int
IPV4__IPV6__TCP__UDP(void)
{
	return result_checker(FLOW_KEY_TYPE_IPV4 | FLOW_KEY_TYPE_IPV6 | FLOW_KEY_TYPE_TCP | FLOW_KEY_TYPE_UDP, 0, 3, 32);
}

static int
IPV4__IPV6__TCP__SCTP(void)
{
	return result_checker(FLOW_KEY_TYPE_IPV4 | FLOW_KEY_TYPE_IPV6 | FLOW_KEY_TYPE_TCP | FLOW_KEY_TYPE_SCTP, 0, 3, 32);
}

static int
IPV4__IPV6__UDP__SCTP(void)
{
	return result_checker(FLOW_KEY_TYPE_IPV4 | FLOW_KEY_TYPE_IPV6 | FLOW_KEY_TYPE_UDP | FLOW_KEY_TYPE_SCTP, 0, 3, 32);
}

static int
IPV4__IPV6__TCP__UDP__SCTP(void)
{
	return result_checker(FLOW_KEY_TYPE_IPV4 | FLOW_KEY_TYPE_IPV6 | FLOW_KEY_TYPE_TCP | FLOW_KEY_TYPE_UDP | FLOW_KEY_TYPE_SCTP, 0, 3, 32);
}

static int
IPV4__IPV6__TCP__UDP__NVGRE(void)
{
	return result_checker(FLOW_KEY_TYPE_IPV4 | FLOW_KEY_TYPE_IPV6 | FLOW_KEY_TYPE_TCP | FLOW_KEY_TYPE_UDP | FLOW_KEY_TYPE_NVGRE, 0, 4, 36);
}

struct otx2_test unit_tests[] = {
	OTX2_TEST(IPV4__IPV6),
	OTX2_TEST(IPV4__IPV6__TCP),
	OTX2_TEST(IPV4__IPV6__UDP),
	OTX2_TEST(IPV4__IPV6__SCTP),
	OTX2_TEST(IPV4__IPV6__TCP__UDP),
	OTX2_TEST(IPV4__IPV6__TCP__SCTP),
	OTX2_TEST(IPV4__IPV6__UDP__SCTP),
	OTX2_TEST(IPV4__IPV6__TCP__UDP__SCTP),
	OTX2_TEST(IPV4__IPV6__TCP__UDP__NVGRE),
};


int main(void)
{
	return OTX2_RUN_TESTS(unit_tests);
}
