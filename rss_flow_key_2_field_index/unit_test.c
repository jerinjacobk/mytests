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
		int expected_fields, int expected_last_key_off,
		int *ret_fields, int *ret_last_key_off)
{
	int rc, fields, last_key_off;
	uint64_t field[FIELDS_PER_ALG];

	rc = set_flowkey_fields((struct nix_rx_flowkey_alg *)field, flowkey_cfg);
	if (expect_error && rc == 0)
		return -EDQUOT;

	if (expect_error == 0 && rc < 0)
		return rc;

	rc = find_empty_feilds_in_between((struct nix_rx_flowkey_alg *)field);
	if (expect_error == 0 && rc)
		return rc;

	fields = get_nr_feilds((struct nix_rx_flowkey_alg *)field);
	last_key_off = get_last_key_offset((struct nix_rx_flowkey_alg *)field);

	if (ret_fields)
		*ret_fields = fields;
	if (ret_last_key_off)
		*ret_last_key_off = last_key_off;

	if (expect_error == 0 &&
	    (fields != expected_fields ||
	     last_key_off != expected_last_key_off))
		return ERANGE;

	return 0;
}

static int
PORT(void)
{
	return result_checker(FLOW_KEY_TYPE_PORT, 0, 1, 0, NULL, NULL);
}

static int
IPV4__IPV6(void)
{
	return result_checker(FLOW_KEY_TYPE_IPV4 | FLOW_KEY_TYPE_IPV6, 0, 2, 0,
			      NULL, NULL);
}

static int
IPV4__IPV6__TCP(void)
{
	return result_checker(FLOW_KEY_TYPE_IPV4 | FLOW_KEY_TYPE_IPV6 |
			      FLOW_KEY_TYPE_TCP, 0, 3, 32, NULL, NULL);
}

static int
IPV4__IPV6__UDP(void)
{
	return result_checker(FLOW_KEY_TYPE_IPV4 | FLOW_KEY_TYPE_IPV6 |
			      FLOW_KEY_TYPE_UDP, 0, 3, 32, NULL, NULL);
}

static int
IPV4__IPV6__SCTP(void)
{
	return result_checker(FLOW_KEY_TYPE_IPV4 | FLOW_KEY_TYPE_IPV6 |
			      FLOW_KEY_TYPE_SCTP, 0, 3, 32, NULL, NULL);
}

static int
IPV4__IPV6__TCP__UDP(void)
{
	return result_checker(FLOW_KEY_TYPE_IPV4 | FLOW_KEY_TYPE_IPV6 |
			      FLOW_KEY_TYPE_TCP | FLOW_KEY_TYPE_UDP, 0, 3, 32,
			      NULL, NULL);
}

static int
IPV4__IPV6__TCP__SCTP(void)
{
	return result_checker(FLOW_KEY_TYPE_IPV4 | FLOW_KEY_TYPE_IPV6 |
			      FLOW_KEY_TYPE_TCP | FLOW_KEY_TYPE_SCTP, 0, 3, 32,
			      NULL, NULL);
}

static int
IPV4__IPV6__UDP__SCTP(void)
{
	return result_checker(FLOW_KEY_TYPE_IPV4 | FLOW_KEY_TYPE_IPV6 |
			      FLOW_KEY_TYPE_UDP | FLOW_KEY_TYPE_SCTP, 0, 3, 32,
			      NULL, NULL);
}

static int
IPV4__IPV6__TCP__UDP__SCTP(void)
{
	return result_checker(FLOW_KEY_TYPE_IPV4 | FLOW_KEY_TYPE_IPV6 |
			      FLOW_KEY_TYPE_TCP | FLOW_KEY_TYPE_UDP |
			      FLOW_KEY_TYPE_SCTP, 0, 3, 32, NULL, NULL);
}

static int
IPV4__IPV6__TCP__UDP__NVGRE(void)
{
	return result_checker(FLOW_KEY_TYPE_IPV4 | FLOW_KEY_TYPE_IPV6 |
			      FLOW_KEY_TYPE_TCP | FLOW_KEY_TYPE_UDP |
			      FLOW_KEY_TYPE_NVGRE, 0, 4, 36, NULL, NULL);
}

static int
PORT_IPV4__IPV6__TCP__UDP__NVGRE(void)
{
	return result_checker( FLOW_KEY_TYPE_PORT | FLOW_KEY_TYPE_IPV4 |
			       FLOW_KEY_TYPE_IPV6 | FLOW_KEY_TYPE_TCP |
			       FLOW_KEY_TYPE_UDP | FLOW_KEY_TYPE_NVGRE, 1, 5,
			       42, NULL, NULL);
}

static int
NVGRE_VXLAN_GENEVE(void)
{
	return result_checker(FLOW_KEY_TYPE_NVGRE | FLOW_KEY_TYPE_VXLAN |
			      FLOW_KEY_TYPE_GENEVE, 0, 3, 6, NULL, NULL);
}

static int
PORT_NVGRE_VXLAN_GENEVE(void)
{
	return result_checker(FLOW_KEY_TYPE_PORT | FLOW_KEY_TYPE_NVGRE |
			      FLOW_KEY_TYPE_VXLAN | FLOW_KEY_TYPE_GENEVE, 0, 4,
			      8, NULL, NULL);
}

struct otx2_test unit_tests[] = {
	OTX2_TEST(PORT),
	OTX2_TEST(IPV4__IPV6),
	OTX2_TEST(IPV4__IPV6__TCP),
	OTX2_TEST(IPV4__IPV6__UDP),
	OTX2_TEST(IPV4__IPV6__SCTP),
	OTX2_TEST(IPV4__IPV6__TCP__UDP),
	OTX2_TEST(IPV4__IPV6__TCP__SCTP),
	OTX2_TEST(IPV4__IPV6__UDP__SCTP),
	OTX2_TEST(IPV4__IPV6__TCP__UDP__SCTP),
	OTX2_TEST(IPV4__IPV6__TCP__UDP__NVGRE),
	OTX2_TEST(PORT_IPV4__IPV6__TCP__UDP__NVGRE),
	OTX2_TEST(NVGRE_VXLAN_GENEVE),
	OTX2_TEST(PORT_NVGRE_VXLAN_GENEVE),
};

#define MAX_BIT 8
char proto_strings[][2][30] = {
	[PORT_VAL] = {"PORT", "FLOW_KEY_TYPE_PORT"},
	[IPV4] = {"IPV4", "FLOW_KEY_TYPE_IPV4"},
	[IPV6] = {"IPV6", "FLOW_KEY_TYPE_IPV6"},
	[TCP] = {"TCP", "FLOW_KEY_TYPE_TCP"},
	[UDP] = {"UDP", "FLOW_KEY_TYPE_UDP"},
	[SCTP] = {"SCTP", "FLOW_KEY_TYPE_SCTP"},
	[NVGRE] = {"NVGRE", "FLOW_KEY_TYPE_NVGRE"},
	[VXLAN] = {"VXLAN", "FLOW_KEY_TYPE_VXLAN"},
	[GENEVE] = {"GENEVE", "FLOW_KEY_TYPE_GENEVE"}
};

struct testcase {
	char name[128];
	uint32_t flowkey_cfg;
	int expect_err;
	int expected_fields;
	int expected_last_key_off;
};

struct testcase tclist[] = {
#ifndef GENERATE_TESTCASE
#include "gen.h"
#endif
};
struct otx2_test tests[sizeof(tclist)/sizeof(struct testcase)];

static int
GENERATED_TC_FUNC(void *arg)
{
	uint32_t idx = (uint64_t)arg;
	return result_checker(tclist[idx].flowkey_cfg, tclist[idx].expect_err,
			      tclist[idx].expected_fields,
			      tclist[idx].expected_last_key_off, NULL, NULL);
}

int main(void)
{
	OTX2_RUN_TESTS(unit_tests);

#ifndef GENERATE_TESTCASE
	uint64_t i;

	for (i = 0; i < sizeof(tests)/sizeof(tests[0]); i++) {
		strncpy(tests[i].name, tclist[i].name, sizeof(tests[i].name));
		tests[i].fn_args = GENERATED_TC_FUNC;
		tests[i].args = (void *)i;
	}

	printf("\n\nGenerated testcases:\n");
	OTX2_RUN_TESTS(tests);
#else
	uint32_t mask, i, cidx, cidx2, bit;
	int result, rc;
	char str[400], str2[100];
	for (mask = (1 << (MAX_BIT + 1)) - 1; mask > 0; mask--) {
		int fields, last_key_off;

		i = mask;
		cidx = 0;
		str2[0] = '"';
		cidx2 = 1;
		while (i) {
			bit = ffs(i) - 1;
			i = i & ~BIT_ULL(bit);
			rc = snprintf(&str[cidx], sizeof(str) - cidx,
				      "%s%s", proto_strings[bit][1], i ? "|" : ",");
			if (rc > 0)
				cidx += rc;
			rc = snprintf(&str2[cidx2], sizeof(str2) - cidx2,
				      "%s%s", proto_strings[bit][0], i ? "_" :
				      "\",");
			if (rc > 0)
				cidx2 += rc;
		}
		result = result_checker(mask, 0, 5, 42, &fields, &last_key_off);
		if (result < 0)
			fprintf(stderr, "{%-47s %-170s 1, 5, 42,}, //[%x], fail\n",
			       str2, str, mask);
		else if (result > 0)
			fprintf(stderr, "{%-47s %-170s 0, %d, %d,}, //[%x], would pass!!\n",
			       str2, str, fields, last_key_off, mask);
		else
			fprintf(stderr, "{%-47s %-170s 0, 5, 42,}, //[%x] passed!!\n",
			       str2, str, mask);
	}
#endif

	return 0;
}
