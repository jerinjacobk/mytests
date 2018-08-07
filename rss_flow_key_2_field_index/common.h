#ifndef _COMMON_H_
#define _COMMON_H_

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
#define FLOW_KEY_TYPE_VXLAN    BIT(7)
#define FLOW_KEY_TYPE_GENEVE   BIT(8)

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

int
set_flowkey_fields(struct nix_rx_flowkey_alg *alg, uint32_t flow_cfg);

#endif /* _COMMON_H_ */
