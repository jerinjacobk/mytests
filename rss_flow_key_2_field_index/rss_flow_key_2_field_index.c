#include <stdio.h>
#include <stdint.h>
#include <string.h>
#include <errno.h>
#include <stdbool.h>
#include <inttypes.h> 

#define RTE_MAX(a, b) \
	__extension__ ({ \
		typeof (a) _a = (a); \
		typeof (b) _b = (b); \
		_a > _b ? _a : _b; \
	})

#define NIX_AF_ERR_RSS_NOSPC_FIELD  -415

#ifndef BIT_ULL
#define BIT_ULL(nr) (1ULL << (nr))
#endif
#ifndef BIT
#define BIT(nr)     (1UL << (nr))
#endif

#define FLOW_KEY_TYPE_PORT     BIT(0)
#define FLOW_KEY_TYPE_IPV4     BIT(1)
#define FLOW_KEY_TYPE_IPV6     BIT(2)
#define FLOW_KEY_TYPE_TCP      BIT(3)
#define FLOW_KEY_TYPE_UDP      BIT(4)
#define FLOW_KEY_TYPE_SCTP     BIT(5)
#define FLOW_KEY_TYPE_NVGRE    BIT(6)

enum npc_lid_e {
	NPC_LID_LA = 0,
	NPC_LID_LB,
	NPC_LID_LC,
	NPC_LID_LD,
	NPC_LID_LE,
	NPC_LID_LF,
	NPC_LID_LG,
	NPC_LID_LH,
};
enum npc_kpu_lc_ltype {
	NPC_LT_LC_IP = 1,
	NPC_LT_LC_IP6,
	NPC_LT_LC_ARP,
	NPC_LT_LC_RARP,
	NPC_LT_LC_MPLS,
	NPC_LT_LC_NSH,
	NPC_LT_LC_PTP,
	NPC_LT_LC_FCOE,
};
enum npc_kpu_ld_ltype {
	NPC_LT_LD_TCP = 1,
	NPC_LT_LD_UDP,
	NPC_LT_LD_SCTP,
	NPC_LT_LD_ICMP,
	NPC_LT_LD_IGMP,
	NPC_LT_LD_ICMP6,
	NPC_LT_LD_ESP,
	NPC_LT_LD_AH,
	NPC_LT_LD_GRE,
	NPC_LT_LD_GRE_MPLS,
	NPC_LT_LD_GRE_NSH,
	NPC_LT_LD_TU_MPLS,
	NPC_LT_LD_NVGRE,
};

struct nix_rx_flowkey_alg {
#if defined(__BIG_ENDIAN_BITFIELD)
	uint64_t reserved_35_63  :29;
	uint64_t ltype_match     :4;
	uint64_t ltype_mask      :4;
	uint64_t sel_chan        :1;
	uint64_t ena         :1;
	uint64_t reserved_24_24  :1;
	uint64_t lid         :3;
	uint64_t bytesm1     :5;
	uint64_t hdr_offset      :8;
	uint64_t fn_mask     :1;
	uint64_t ln_mask     :1;
	uint64_t key_offset      :6;
#else
	uint64_t key_offset      :6;
	uint64_t ln_mask     :1;
	uint64_t fn_mask     :1;
	uint64_t hdr_offset      :8;
	uint64_t bytesm1     :5;
	uint64_t lid         :3;
	uint64_t reserved_24_24  :1;
	uint64_t ena         :1;
	uint64_t sel_chan        :1;
	uint64_t ltype_mask      :4;
	uint64_t ltype_match     :4;
	uint64_t reserved_35_63  :29;
#endif
};

static inline int fls(uint32_t x)
{
	int b;

	for (b = 31; b >= 0; --b) {
		if (x & (1u << b))
			return b + 1;
	}

	return 0;
}

static int
set_flowkey_fields(struct nix_rx_flowkey_alg *alg, uint32_t flow_cfg)
{
	int idx, nr_field, key_off, field_marker, keyoff_marker;
	struct nix_rx_flowkey_alg *field;
	struct nix_rx_flowkey_alg tmp;
	int max_key_off, max_bit_pos;
	uint32_t key_type, valid_key;

#define FIELDS_PER_ALG  5
#define MAX_KEY_OFF	40

	if (!alg)
		return -EINVAL;

	/* Clear all fields */
	memset(alg, 0, sizeof(uint64_t) * FIELDS_PER_ALG);

	/*
	 * Each of the 32 possible flow key algorithm definitions should
	 * fall into above incremental config (except ALG0). Otherwise a
	 * single NPC MCAM entry is not sufficient for supporting RSS.
	 *
	 * If a different definition or combination needed then NPC MCAM
	 * has to be programmed to filter such pkts and it's action should
	 * point to this definition to calculate flowtag or hash.
	 */

	nr_field = 0; key_off = 0; field_marker = 1; keyoff_marker = 0;
	max_key_off = 0; field = &tmp; max_bit_pos = fls(flow_cfg);
	for (idx = 0; idx < max_bit_pos && nr_field < FIELDS_PER_ALG &&
			key_off < MAX_KEY_OFF; idx++) {

		key_type = BIT(idx);
		valid_key = flow_cfg & key_type;
		/* Found a field marker, reset the field values */
		if (field_marker)
			memset(&tmp, 0, sizeof(tmp));

		switch (key_type) {
		case FLOW_KEY_TYPE_PORT:
			field->sel_chan = true;
			/* This should be set to 1, when SEL_CHAN is set */
			field->bytesm1 = 1;
			field_marker = true;
			keyoff_marker = true;
			break;
		case FLOW_KEY_TYPE_IPV4:
			field->lid = NPC_LID_LC;
			field->ltype_match = NPC_LT_LC_IP;
			field->hdr_offset = 12; /* SIP offset */
			field->bytesm1 = 7; /* SIP + DIP, 8 bytes */
			field->ltype_mask = 0xF; /* Match only IPv4 */
			field_marker = true;
			keyoff_marker = false;
			break;
		case FLOW_KEY_TYPE_IPV6:
			field->lid = NPC_LID_LC;
			field->ltype_match = NPC_LT_LC_IP6;
			field->hdr_offset = 8; /* SIP offset */
			field->bytesm1 = 31; /* SIP + DIP, 32 bytes */
			field->ltype_mask = 0xF; /* Match only IPv6 */
			field_marker = true;
			keyoff_marker = true;
			break;
		case FLOW_KEY_TYPE_TCP:
		case FLOW_KEY_TYPE_UDP:
		case FLOW_KEY_TYPE_SCTP:
			field->lid = NPC_LID_LD;
			field->bytesm1 = 3; /* Sport + Dport, 4 bytes */
			if (key_type == FLOW_KEY_TYPE_TCP && valid_key)
				field->ltype_match |= NPC_LT_LD_TCP;
			else if (key_type == FLOW_KEY_TYPE_UDP && valid_key)
				field->ltype_match |= NPC_LT_LD_UDP;
			else if (key_type == FLOW_KEY_TYPE_SCTP && valid_key)
				field->ltype_match |= NPC_LT_LD_SCTP;
			field->ltype_mask = ~field->ltype_match;
			if (key_type == FLOW_KEY_TYPE_SCTP) {
				field_marker = true;
				keyoff_marker = true;
			} else {
				field_marker = false;
				keyoff_marker = false;
			}
			break;
		case FLOW_KEY_TYPE_NVGRE:
			field->lid = NPC_LID_LD;
			field->ltype_match = NPC_LT_LD_NVGRE;
			field->hdr_offset = 4; /* VSID offset */
			field->bytesm1 = 3; /* VSID + FlowID, 4 bytes */
			field->ltype_mask = 0xF; /* Match only NVGRE */
			field_marker = true;
			keyoff_marker = true;
			break;
		}
		field->ena = 1;

		/* Found a valid flow key type */
		if (valid_key) {
			field->key_offset = key_off;
			memcpy(&alg[nr_field], field, sizeof(*field));
			max_key_off = RTE_MAX(max_key_off, field->bytesm1 + 1);

			/* Found a field marker, get the next field */
			if (field_marker)
				nr_field++;
		}

		/* Found a keyoff marker, update the new key_off */
		if (keyoff_marker) {
			key_off += max_key_off;
			max_key_off = 0;
		}
	}

	if (idx == max_bit_pos) /* Processed all the flow key types */
		return 0;
	else
		return NIX_AF_ERR_RSS_NOSPC_FIELD;
}

static void print_feilds(uint64_t *field)
{
	int i;

	for (i = 0; i < FIELDS_PER_ALG; i++)
		printf("field=%"PRIx64"\n", field[i]);


}

int main(void)
{
	int rc;
	uint64_t field[FIELDS_PER_ALG];

	uint32_t flowkey_cfg, minkey_cfg;

	/* IPv4/IPv6 SIP/DIPs */
	flowkey_cfg = FLOW_KEY_TYPE_IPV4 | FLOW_KEY_TYPE_IPV6;
	rc = set_flowkey_fields((struct nix_rx_flowkey_alg *)field, flowkey_cfg);
	if (rc < 0)
		return rc;

	print_feilds(field);

	/* TCPv4/v6 4-tuple, SIP, DIP, Sport, Dport */
	minkey_cfg = flowkey_cfg;
	flowkey_cfg = minkey_cfg | FLOW_KEY_TYPE_TCP;
	rc = set_flowkey_fields((struct nix_rx_flowkey_alg *)field, flowkey_cfg);
	if (rc < 0)
		return rc;

	print_feilds(field);
	/* UDPv4/v6 4-tuple, SIP, DIP, Sport, Dport */
	flowkey_cfg = minkey_cfg | FLOW_KEY_TYPE_UDP;
	rc = set_flowkey_fields((struct nix_rx_flowkey_alg *)field, flowkey_cfg);
	if (rc < 0)
		return rc;

	print_feilds(field);
	/* SCTPv4/v6 4-tuple, SIP, DIP, Sport, Dport */
	flowkey_cfg = minkey_cfg | FLOW_KEY_TYPE_SCTP;
	rc = set_flowkey_fields((struct nix_rx_flowkey_alg *)field, flowkey_cfg);
	if (rc < 0)
		return rc;

	print_feilds(field);
	/* TCP/UDP v4/v6 4-tuple, rest IP pkts 2-tuple */
	flowkey_cfg = minkey_cfg | FLOW_KEY_TYPE_TCP | FLOW_KEY_TYPE_UDP;
	rc = set_flowkey_fields((struct nix_rx_flowkey_alg *)field, flowkey_cfg);
	if (rc < 0)
		return rc;

	print_feilds(field);
	/* TCP/SCTP v4/v6 4-tuple, rest IP pkts 2-tuple */
	flowkey_cfg = minkey_cfg | FLOW_KEY_TYPE_TCP | FLOW_KEY_TYPE_SCTP;
	rc = set_flowkey_fields((struct nix_rx_flowkey_alg *)field, flowkey_cfg);
	if (rc < 0)
		return rc;

	print_feilds(field);
	/* UDP/SCTP v4/v6 4-tuple, rest IP pkts 2-tuple */
	flowkey_cfg = minkey_cfg | FLOW_KEY_TYPE_UDP | FLOW_KEY_TYPE_SCTP;
	rc = set_flowkey_fields((struct nix_rx_flowkey_alg *)field, flowkey_cfg);
	if (rc < 0)
		return rc;

	print_feilds(field);
	/* TCP/UDP/SCTP v4/v6 4-tuple, rest IP pkts 2-tuple */
	flowkey_cfg = minkey_cfg | FLOW_KEY_TYPE_TCP |
					FLOW_KEY_TYPE_UDP | FLOW_KEY_TYPE_SCTP;
	rc = set_flowkey_fields((struct nix_rx_flowkey_alg *)field, flowkey_cfg);
	if (rc < 0)
		return rc;
	print_feilds(field);

	/* TCP/UDP/SCTP/NVGRE v4/v6 4-tuple, rest IP pkts 2-tuple */
	flowkey_cfg = minkey_cfg | FLOW_KEY_TYPE_TCP |
					FLOW_KEY_TYPE_UDP | FLOW_KEY_TYPE_SCTP | FLOW_KEY_TYPE_NVGRE;
	rc = set_flowkey_fields((struct nix_rx_flowkey_alg *)field, flowkey_cfg);
	if (rc < 0)
		return rc;

	print_feilds(field);
	return 0;
}
