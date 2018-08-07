static int
PORT_IPV4_IPV6_TCP_UDP_SCTP_NVGRE_VXLAN_GENEVE(void)
{
	return result_checker(FLOW_KEY_TYPE_PORT|
			      FLOW_KEY_TYPE_IPV4|FLOW_KEY_TYPE_IPV6|
			      FLOW_KEY_TYPE_TCP|FLOW_KEY_TYPE_UDP|
			      FLOW_KEY_TYPE_SCTP|FLOW_KEY_TYPE_NVGRE|
			      FLOW_KEY_TYPE_VXLAN|FLOW_KEY_TYPE_GENEVE,
			      1, 5, 42, NULL, NULL); //[1ff], fail
}

static int
IPV4_IPV6_TCP_UDP_SCTP_NVGRE_VXLAN_GENEVE(void)
{
	return result_checker(FLOW_KEY_TYPE_IPV4|
			      FLOW_KEY_TYPE_IPV6|FLOW_KEY_TYPE_TCP|
			      FLOW_KEY_TYPE_UDP|FLOW_KEY_TYPE_SCTP|
			      FLOW_KEY_TYPE_NVGRE|FLOW_KEY_TYPE_VXLAN|
			      FLOW_KEY_TYPE_GENEVE,
			      1, 5, 42, NULL, NULL); //[1fe], fail
}

static int
PORT_IPV6_TCP_UDP_SCTP_NVGRE_VXLAN_GENEVE(void)
{
	return result_checker(FLOW_KEY_TYPE_PORT|
			      FLOW_KEY_TYPE_IPV6|FLOW_KEY_TYPE_TCP|
			      FLOW_KEY_TYPE_UDP|FLOW_KEY_TYPE_SCTP|
			      FLOW_KEY_TYPE_NVGRE|FLOW_KEY_TYPE_VXLAN|
			      FLOW_KEY_TYPE_GENEVE,
			      1, 5, 42, NULL, NULL); //[1fd], fail
}

static int
IPV6_TCP_UDP_SCTP_NVGRE_VXLAN_GENEVE(void)
{
	return result_checker(FLOW_KEY_TYPE_IPV6|
			      FLOW_KEY_TYPE_TCP|FLOW_KEY_TYPE_UDP|
			      FLOW_KEY_TYPE_SCTP|FLOW_KEY_TYPE_NVGRE|
			      FLOW_KEY_TYPE_VXLAN|FLOW_KEY_TYPE_GENEVE,
			      1, 5, 42, NULL, NULL); //[1fc], fail
}

static int
PORT_IPV4_TCP_UDP_SCTP_NVGRE_VXLAN_GENEVE(void)
{
	return result_checker(FLOW_KEY_TYPE_PORT|
			      FLOW_KEY_TYPE_IPV4|FLOW_KEY_TYPE_TCP|
			      FLOW_KEY_TYPE_UDP|FLOW_KEY_TYPE_SCTP|
			      FLOW_KEY_TYPE_NVGRE|FLOW_KEY_TYPE_VXLAN|
			      FLOW_KEY_TYPE_GENEVE,
			      1, 5, 42, NULL, NULL); //[1fb], fail
}

static int
IPV4_TCP_UDP_SCTP_NVGRE_VXLAN_GENEVE(void)
{
	return result_checker(FLOW_KEY_TYPE_IPV4|
			      FLOW_KEY_TYPE_TCP|FLOW_KEY_TYPE_UDP|
			      FLOW_KEY_TYPE_SCTP|FLOW_KEY_TYPE_NVGRE|
			      FLOW_KEY_TYPE_VXLAN|FLOW_KEY_TYPE_GENEVE,
			      0, 5, 18, NULL, NULL); //[1fa], would pass!!
}

static int
PORT_TCP_UDP_SCTP_NVGRE_VXLAN_GENEVE(void)
{
	return result_checker(FLOW_KEY_TYPE_PORT|
			      FLOW_KEY_TYPE_TCP|FLOW_KEY_TYPE_UDP|
			      FLOW_KEY_TYPE_SCTP|FLOW_KEY_TYPE_NVGRE|
			      FLOW_KEY_TYPE_VXLAN|FLOW_KEY_TYPE_GENEVE,
			      0, 5, 12, NULL, NULL); //[1f9], would pass!!
}

static int
TCP_UDP_SCTP_NVGRE_VXLAN_GENEVE(void)
{
	return result_checker(FLOW_KEY_TYPE_TCP|
			      FLOW_KEY_TYPE_UDP|FLOW_KEY_TYPE_SCTP|
			      FLOW_KEY_TYPE_NVGRE|FLOW_KEY_TYPE_VXLAN|
			      FLOW_KEY_TYPE_GENEVE,
			      0, 4, 10, NULL, NULL); //[1f8], would pass!!
}

static int
PORT_IPV4_IPV6_UDP_SCTP_NVGRE_VXLAN_GENEVE(void)
{
	return result_checker(FLOW_KEY_TYPE_PORT|
			      FLOW_KEY_TYPE_IPV4|FLOW_KEY_TYPE_IPV6|
			      FLOW_KEY_TYPE_UDP|FLOW_KEY_TYPE_SCTP|
			      FLOW_KEY_TYPE_NVGRE|FLOW_KEY_TYPE_VXLAN|
			      FLOW_KEY_TYPE_GENEVE,
			      1, 5, 42, NULL, NULL); //[1f7], fail
}

static int
IPV4_IPV6_UDP_SCTP_NVGRE_VXLAN_GENEVE(void)
{
	return result_checker(FLOW_KEY_TYPE_IPV4|
			      FLOW_KEY_TYPE_IPV6|FLOW_KEY_TYPE_UDP|
			      FLOW_KEY_TYPE_SCTP|FLOW_KEY_TYPE_NVGRE|
			      FLOW_KEY_TYPE_VXLAN|FLOW_KEY_TYPE_GENEVE,
			      1, 5, 42, NULL, NULL); //[1f6], fail
}

static int
PORT_IPV6_UDP_SCTP_NVGRE_VXLAN_GENEVE(void)
{
	return result_checker(FLOW_KEY_TYPE_PORT|
			      FLOW_KEY_TYPE_IPV6|FLOW_KEY_TYPE_UDP|
			      FLOW_KEY_TYPE_SCTP|FLOW_KEY_TYPE_NVGRE|
			      FLOW_KEY_TYPE_VXLAN|FLOW_KEY_TYPE_GENEVE,
			      1, 5, 42, NULL, NULL); //[1f5], fail
}

static int
IPV6_UDP_SCTP_NVGRE_VXLAN_GENEVE(void)
{
	return result_checker(FLOW_KEY_TYPE_IPV6|
			      FLOW_KEY_TYPE_UDP|FLOW_KEY_TYPE_SCTP|
			      FLOW_KEY_TYPE_NVGRE|FLOW_KEY_TYPE_VXLAN|
			      FLOW_KEY_TYPE_GENEVE,
			      1, 5, 42, NULL, NULL); //[1f4], fail
}

static int
PORT_IPV4_UDP_SCTP_NVGRE_VXLAN_GENEVE(void)
{
	return result_checker(FLOW_KEY_TYPE_PORT|
			      FLOW_KEY_TYPE_IPV4|FLOW_KEY_TYPE_UDP|
			      FLOW_KEY_TYPE_SCTP|FLOW_KEY_TYPE_NVGRE|
			      FLOW_KEY_TYPE_VXLAN|FLOW_KEY_TYPE_GENEVE,
			      1, 5, 42, NULL, NULL); //[1f3], fail
}

static int
IPV4_UDP_SCTP_NVGRE_VXLAN_GENEVE(void)
{
	return result_checker(FLOW_KEY_TYPE_IPV4|
			      FLOW_KEY_TYPE_UDP|FLOW_KEY_TYPE_SCTP|
			      FLOW_KEY_TYPE_NVGRE|FLOW_KEY_TYPE_VXLAN|
			      FLOW_KEY_TYPE_GENEVE,
			      0, 5, 18, NULL, NULL); //[1f2], would pass!!
}

static int
PORT_UDP_SCTP_NVGRE_VXLAN_GENEVE(void)
{
	return result_checker(FLOW_KEY_TYPE_PORT|
			      FLOW_KEY_TYPE_UDP|FLOW_KEY_TYPE_SCTP|
			      FLOW_KEY_TYPE_NVGRE|FLOW_KEY_TYPE_VXLAN|
			      FLOW_KEY_TYPE_GENEVE,
			      0, 5, 12, NULL, NULL); //[1f1], would pass!!
}

static int
UDP_SCTP_NVGRE_VXLAN_GENEVE(void)
{
	return result_checker(FLOW_KEY_TYPE_UDP|
			      FLOW_KEY_TYPE_SCTP|FLOW_KEY_TYPE_NVGRE|
			      FLOW_KEY_TYPE_VXLAN|FLOW_KEY_TYPE_GENEVE,
			      0, 4, 10, NULL, NULL); //[1f0], would pass!!
}

static int
PORT_IPV4_IPV6_TCP_SCTP_NVGRE_VXLAN_GENEVE(void)
{
	return result_checker(FLOW_KEY_TYPE_PORT|
			      FLOW_KEY_TYPE_IPV4|FLOW_KEY_TYPE_IPV6|
			      FLOW_KEY_TYPE_TCP|FLOW_KEY_TYPE_SCTP|
			      FLOW_KEY_TYPE_NVGRE|FLOW_KEY_TYPE_VXLAN|
			      FLOW_KEY_TYPE_GENEVE,
			      1, 5, 42, NULL, NULL); //[1ef], fail
}

static int
IPV4_IPV6_TCP_SCTP_NVGRE_VXLAN_GENEVE(void)
{
	return result_checker(FLOW_KEY_TYPE_IPV4|
			      FLOW_KEY_TYPE_IPV6|FLOW_KEY_TYPE_TCP|
			      FLOW_KEY_TYPE_SCTP|FLOW_KEY_TYPE_NVGRE|
			      FLOW_KEY_TYPE_VXLAN|FLOW_KEY_TYPE_GENEVE,
			      1, 5, 42, NULL, NULL); //[1ee], fail
}

static int
PORT_IPV6_TCP_SCTP_NVGRE_VXLAN_GENEVE(void)
{
	return result_checker(FLOW_KEY_TYPE_PORT|
			      FLOW_KEY_TYPE_IPV6|FLOW_KEY_TYPE_TCP|
			      FLOW_KEY_TYPE_SCTP|FLOW_KEY_TYPE_NVGRE|
			      FLOW_KEY_TYPE_VXLAN|FLOW_KEY_TYPE_GENEVE,
			      1, 5, 42, NULL, NULL); //[1ed], fail
}

static int
IPV6_TCP_SCTP_NVGRE_VXLAN_GENEVE(void)
{
	return result_checker(FLOW_KEY_TYPE_IPV6|
			      FLOW_KEY_TYPE_TCP|FLOW_KEY_TYPE_SCTP|
			      FLOW_KEY_TYPE_NVGRE|FLOW_KEY_TYPE_VXLAN|
			      FLOW_KEY_TYPE_GENEVE,
			      1, 5, 42, NULL, NULL); //[1ec], fail
}

static int
PORT_IPV4_TCP_SCTP_NVGRE_VXLAN_GENEVE(void)
{
	return result_checker(FLOW_KEY_TYPE_PORT|
			      FLOW_KEY_TYPE_IPV4|FLOW_KEY_TYPE_TCP|
			      FLOW_KEY_TYPE_SCTP|FLOW_KEY_TYPE_NVGRE|
			      FLOW_KEY_TYPE_VXLAN|FLOW_KEY_TYPE_GENEVE,
			      1, 5, 42, NULL, NULL); //[1eb], fail
}

static int
IPV4_TCP_SCTP_NVGRE_VXLAN_GENEVE(void)
{
	return result_checker(FLOW_KEY_TYPE_IPV4|
			      FLOW_KEY_TYPE_TCP|FLOW_KEY_TYPE_SCTP|
			      FLOW_KEY_TYPE_NVGRE|FLOW_KEY_TYPE_VXLAN|
			      FLOW_KEY_TYPE_GENEVE,
			      0, 5, 18, NULL, NULL); //[1ea], would pass!!
}

static int
PORT_TCP_SCTP_NVGRE_VXLAN_GENEVE(void)
{
	return result_checker(FLOW_KEY_TYPE_PORT|
			      FLOW_KEY_TYPE_TCP|FLOW_KEY_TYPE_SCTP|
			      FLOW_KEY_TYPE_NVGRE|FLOW_KEY_TYPE_VXLAN|
			      FLOW_KEY_TYPE_GENEVE,
			      0, 5, 12, NULL, NULL); //[1e9], would pass!!
}

static int
TCP_SCTP_NVGRE_VXLAN_GENEVE(void)
{
	return result_checker(FLOW_KEY_TYPE_TCP|
			      FLOW_KEY_TYPE_SCTP|FLOW_KEY_TYPE_NVGRE|
			      FLOW_KEY_TYPE_VXLAN|FLOW_KEY_TYPE_GENEVE,
			      0, 4, 10, NULL, NULL); //[1e8], would pass!!
}

static int
PORT_IPV4_IPV6_SCTP_NVGRE_VXLAN_GENEVE(void)
{
	return result_checker(FLOW_KEY_TYPE_PORT|
			      FLOW_KEY_TYPE_IPV4|FLOW_KEY_TYPE_IPV6|
			      FLOW_KEY_TYPE_SCTP|FLOW_KEY_TYPE_NVGRE|
			      FLOW_KEY_TYPE_VXLAN|FLOW_KEY_TYPE_GENEVE,
			      1, 5, 42, NULL, NULL); //[1e7], fail
}

static int
IPV4_IPV6_SCTP_NVGRE_VXLAN_GENEVE(void)
{
	return result_checker(FLOW_KEY_TYPE_IPV4|
			      FLOW_KEY_TYPE_IPV6|FLOW_KEY_TYPE_SCTP|
			      FLOW_KEY_TYPE_NVGRE|FLOW_KEY_TYPE_VXLAN|
			      FLOW_KEY_TYPE_GENEVE,
			      1, 5, 42, NULL, NULL); //[1e6], fail
}

static int
PORT_IPV6_SCTP_NVGRE_VXLAN_GENEVE(void)
{
	return result_checker(FLOW_KEY_TYPE_PORT|
			      FLOW_KEY_TYPE_IPV6|FLOW_KEY_TYPE_SCTP|
			      FLOW_KEY_TYPE_NVGRE|FLOW_KEY_TYPE_VXLAN|
			      FLOW_KEY_TYPE_GENEVE,
			      1, 5, 42, NULL, NULL); //[1e5], fail
}

static int
IPV6_SCTP_NVGRE_VXLAN_GENEVE(void)
{
	return result_checker(FLOW_KEY_TYPE_IPV6|
			      FLOW_KEY_TYPE_SCTP|FLOW_KEY_TYPE_NVGRE|
			      FLOW_KEY_TYPE_VXLAN|FLOW_KEY_TYPE_GENEVE,
			      1, 5, 42, NULL, NULL); //[1e4], fail
}

static int
PORT_IPV4_SCTP_NVGRE_VXLAN_GENEVE(void)
{
	return result_checker(FLOW_KEY_TYPE_PORT|
			      FLOW_KEY_TYPE_IPV4|FLOW_KEY_TYPE_SCTP|
			      FLOW_KEY_TYPE_NVGRE|FLOW_KEY_TYPE_VXLAN|
			      FLOW_KEY_TYPE_GENEVE,
			      1, 5, 42, NULL, NULL); //[1e3], fail
}

static int
IPV4_SCTP_NVGRE_VXLAN_GENEVE(void)
{
	return result_checker(FLOW_KEY_TYPE_IPV4|
			      FLOW_KEY_TYPE_SCTP|FLOW_KEY_TYPE_NVGRE|
			      FLOW_KEY_TYPE_VXLAN|FLOW_KEY_TYPE_GENEVE,
			      0, 5, 18, NULL, NULL); //[1e2], would pass!!
}

static int
PORT_SCTP_NVGRE_VXLAN_GENEVE(void)
{
	return result_checker(FLOW_KEY_TYPE_PORT|
			      FLOW_KEY_TYPE_SCTP|FLOW_KEY_TYPE_NVGRE|
			      FLOW_KEY_TYPE_VXLAN|FLOW_KEY_TYPE_GENEVE,
			      0, 5, 12, NULL, NULL); //[1e1], would pass!!
}

static int
SCTP_NVGRE_VXLAN_GENEVE(void)
{
	return result_checker(FLOW_KEY_TYPE_SCTP|
			      FLOW_KEY_TYPE_NVGRE|FLOW_KEY_TYPE_VXLAN|
			      FLOW_KEY_TYPE_GENEVE,
			      0, 4, 10, NULL, NULL); //[1e0], would pass!!
}

static int
PORT_IPV4_IPV6_TCP_UDP_NVGRE_VXLAN_GENEVE(void)
{
	return result_checker(FLOW_KEY_TYPE_PORT|
			      FLOW_KEY_TYPE_IPV4|FLOW_KEY_TYPE_IPV6|
			      FLOW_KEY_TYPE_TCP|FLOW_KEY_TYPE_UDP|
			      FLOW_KEY_TYPE_NVGRE|FLOW_KEY_TYPE_VXLAN|
			      FLOW_KEY_TYPE_GENEVE,
			      1, 5, 42, NULL, NULL); //[1df], fail
}

static int
IPV4_IPV6_TCP_UDP_NVGRE_VXLAN_GENEVE(void)
{
	return result_checker(FLOW_KEY_TYPE_IPV4|
			      FLOW_KEY_TYPE_IPV6|FLOW_KEY_TYPE_TCP|
			      FLOW_KEY_TYPE_UDP|FLOW_KEY_TYPE_NVGRE|
			      FLOW_KEY_TYPE_VXLAN|FLOW_KEY_TYPE_GENEVE,
			      1, 5, 42, NULL, NULL); //[1de], fail
}

static int
PORT_IPV6_TCP_UDP_NVGRE_VXLAN_GENEVE(void)
{
	return result_checker(FLOW_KEY_TYPE_PORT|
			      FLOW_KEY_TYPE_IPV6|FLOW_KEY_TYPE_TCP|
			      FLOW_KEY_TYPE_UDP|FLOW_KEY_TYPE_NVGRE|
			      FLOW_KEY_TYPE_VXLAN|FLOW_KEY_TYPE_GENEVE,
			      1, 5, 42, NULL, NULL); //[1dd], fail
}

static int
IPV6_TCP_UDP_NVGRE_VXLAN_GENEVE(void)
{
	return result_checker(FLOW_KEY_TYPE_IPV6|
			      FLOW_KEY_TYPE_TCP|FLOW_KEY_TYPE_UDP|
			      FLOW_KEY_TYPE_NVGRE|FLOW_KEY_TYPE_VXLAN|
			      FLOW_KEY_TYPE_GENEVE,
			      1, 5, 42, NULL, NULL); //[1dc], fail
}

static int
PORT_IPV4_TCP_UDP_NVGRE_VXLAN_GENEVE(void)
{
	return result_checker(FLOW_KEY_TYPE_PORT|
			      FLOW_KEY_TYPE_IPV4|FLOW_KEY_TYPE_TCP|
			      FLOW_KEY_TYPE_UDP|FLOW_KEY_TYPE_NVGRE|
			      FLOW_KEY_TYPE_VXLAN|FLOW_KEY_TYPE_GENEVE,
			      1, 5, 42, NULL, NULL); //[1db], fail
}

static int
IPV4_TCP_UDP_NVGRE_VXLAN_GENEVE(void)
{
	return result_checker(FLOW_KEY_TYPE_IPV4|
			      FLOW_KEY_TYPE_TCP|FLOW_KEY_TYPE_UDP|
			      FLOW_KEY_TYPE_NVGRE|FLOW_KEY_TYPE_VXLAN|
			      FLOW_KEY_TYPE_GENEVE,
			      0, 5, 18, NULL, NULL); //[1da], would pass!!
}

static int
PORT_TCP_UDP_NVGRE_VXLAN_GENEVE(void)
{
	return result_checker(FLOW_KEY_TYPE_PORT|
			      FLOW_KEY_TYPE_TCP|FLOW_KEY_TYPE_UDP|
			      FLOW_KEY_TYPE_NVGRE|FLOW_KEY_TYPE_VXLAN|
			      FLOW_KEY_TYPE_GENEVE,
			      0, 5, 12, NULL, NULL); //[1d9], would pass!!
}

static int
TCP_UDP_NVGRE_VXLAN_GENEVE(void)
{
	return result_checker(FLOW_KEY_TYPE_TCP|
			      FLOW_KEY_TYPE_UDP|FLOW_KEY_TYPE_NVGRE|
			      FLOW_KEY_TYPE_VXLAN|FLOW_KEY_TYPE_GENEVE,
			      0, 4, 10, NULL, NULL); //[1d8], would pass!!
}

static int
PORT_IPV4_IPV6_UDP_NVGRE_VXLAN_GENEVE(void)
{
	return result_checker(FLOW_KEY_TYPE_PORT|
			      FLOW_KEY_TYPE_IPV4|FLOW_KEY_TYPE_IPV6|
			      FLOW_KEY_TYPE_UDP|FLOW_KEY_TYPE_NVGRE|
			      FLOW_KEY_TYPE_VXLAN|FLOW_KEY_TYPE_GENEVE,
			      1, 5, 42, NULL, NULL); //[1d7], fail
}

static int
IPV4_IPV6_UDP_NVGRE_VXLAN_GENEVE(void)
{
	return result_checker(FLOW_KEY_TYPE_IPV4|
			      FLOW_KEY_TYPE_IPV6|FLOW_KEY_TYPE_UDP|
			      FLOW_KEY_TYPE_NVGRE|FLOW_KEY_TYPE_VXLAN|
			      FLOW_KEY_TYPE_GENEVE,
			      1, 5, 42, NULL, NULL); //[1d6], fail
}

static int
PORT_IPV6_UDP_NVGRE_VXLAN_GENEVE(void)
{
	return result_checker(FLOW_KEY_TYPE_PORT|
			      FLOW_KEY_TYPE_IPV6|FLOW_KEY_TYPE_UDP|
			      FLOW_KEY_TYPE_NVGRE|FLOW_KEY_TYPE_VXLAN|
			      FLOW_KEY_TYPE_GENEVE,
			      1, 5, 42, NULL, NULL); //[1d5], fail
}

static int
IPV6_UDP_NVGRE_VXLAN_GENEVE(void)
{
	return result_checker(FLOW_KEY_TYPE_IPV6|
			      FLOW_KEY_TYPE_UDP|FLOW_KEY_TYPE_NVGRE|
			      FLOW_KEY_TYPE_VXLAN|FLOW_KEY_TYPE_GENEVE,
			      1, 5, 42, NULL, NULL); //[1d4], fail
}

static int
PORT_IPV4_UDP_NVGRE_VXLAN_GENEVE(void)
{
	return result_checker(FLOW_KEY_TYPE_PORT|
			      FLOW_KEY_TYPE_IPV4|FLOW_KEY_TYPE_UDP|
			      FLOW_KEY_TYPE_NVGRE|FLOW_KEY_TYPE_VXLAN|
			      FLOW_KEY_TYPE_GENEVE,
			      1, 5, 42, NULL, NULL); //[1d3], fail
}

static int
IPV4_UDP_NVGRE_VXLAN_GENEVE(void)
{
	return result_checker(FLOW_KEY_TYPE_IPV4|
			      FLOW_KEY_TYPE_UDP|FLOW_KEY_TYPE_NVGRE|
			      FLOW_KEY_TYPE_VXLAN|FLOW_KEY_TYPE_GENEVE,
			      0, 5, 18, NULL, NULL); //[1d2], would pass!!
}

static int
PORT_UDP_NVGRE_VXLAN_GENEVE(void)
{
	return result_checker(FLOW_KEY_TYPE_PORT|
			      FLOW_KEY_TYPE_UDP|FLOW_KEY_TYPE_NVGRE|
			      FLOW_KEY_TYPE_VXLAN|FLOW_KEY_TYPE_GENEVE,
			      0, 5, 12, NULL, NULL); //[1d1], would pass!!
}

static int
UDP_NVGRE_VXLAN_GENEVE(void)
{
	return result_checker(FLOW_KEY_TYPE_UDP|
			      FLOW_KEY_TYPE_NVGRE|FLOW_KEY_TYPE_VXLAN|
			      FLOW_KEY_TYPE_GENEVE,
			      0, 4, 10, NULL, NULL); //[1d0], would pass!!
}

static int
PORT_IPV4_IPV6_TCP_NVGRE_VXLAN_GENEVE(void)
{
	return result_checker(FLOW_KEY_TYPE_PORT|
			      FLOW_KEY_TYPE_IPV4|FLOW_KEY_TYPE_IPV6|
			      FLOW_KEY_TYPE_TCP|FLOW_KEY_TYPE_NVGRE|
			      FLOW_KEY_TYPE_VXLAN|FLOW_KEY_TYPE_GENEVE,
			      1, 5, 42, NULL, NULL); //[1cf], fail
}

static int
IPV4_IPV6_TCP_NVGRE_VXLAN_GENEVE(void)
{
	return result_checker(FLOW_KEY_TYPE_IPV4|
			      FLOW_KEY_TYPE_IPV6|FLOW_KEY_TYPE_TCP|
			      FLOW_KEY_TYPE_NVGRE|FLOW_KEY_TYPE_VXLAN|
			      FLOW_KEY_TYPE_GENEVE,
			      1, 5, 42, NULL, NULL); //[1ce], fail
}

static int
PORT_IPV6_TCP_NVGRE_VXLAN_GENEVE(void)
{
	return result_checker(FLOW_KEY_TYPE_PORT|
			      FLOW_KEY_TYPE_IPV6|FLOW_KEY_TYPE_TCP|
			      FLOW_KEY_TYPE_NVGRE|FLOW_KEY_TYPE_VXLAN|
			      FLOW_KEY_TYPE_GENEVE,
			      1, 5, 42, NULL, NULL); //[1cd], fail
}

static int
IPV6_TCP_NVGRE_VXLAN_GENEVE(void)
{
	return result_checker(FLOW_KEY_TYPE_IPV6|
			      FLOW_KEY_TYPE_TCP|FLOW_KEY_TYPE_NVGRE|
			      FLOW_KEY_TYPE_VXLAN|FLOW_KEY_TYPE_GENEVE,
			      1, 5, 42, NULL, NULL); //[1cc], fail
}

static int
PORT_IPV4_TCP_NVGRE_VXLAN_GENEVE(void)
{
	return result_checker(FLOW_KEY_TYPE_PORT|
			      FLOW_KEY_TYPE_IPV4|FLOW_KEY_TYPE_TCP|
			      FLOW_KEY_TYPE_NVGRE|FLOW_KEY_TYPE_VXLAN|
			      FLOW_KEY_TYPE_GENEVE,
			      1, 5, 42, NULL, NULL); //[1cb], fail
}

static int
IPV4_TCP_NVGRE_VXLAN_GENEVE(void)
{
	return result_checker(FLOW_KEY_TYPE_IPV4|
			      FLOW_KEY_TYPE_TCP|FLOW_KEY_TYPE_NVGRE|
			      FLOW_KEY_TYPE_VXLAN|FLOW_KEY_TYPE_GENEVE,
			      0, 5, 18, NULL, NULL); //[1ca], would pass!!
}

static int
PORT_TCP_NVGRE_VXLAN_GENEVE(void)
{
	return result_checker(FLOW_KEY_TYPE_PORT|
			      FLOW_KEY_TYPE_TCP|FLOW_KEY_TYPE_NVGRE|
			      FLOW_KEY_TYPE_VXLAN|FLOW_KEY_TYPE_GENEVE,
			      0, 5, 12, NULL, NULL); //[1c9], would pass!!
}

static int
TCP_NVGRE_VXLAN_GENEVE(void)
{
	return result_checker(FLOW_KEY_TYPE_TCP|
			      FLOW_KEY_TYPE_NVGRE|FLOW_KEY_TYPE_VXLAN|
			      FLOW_KEY_TYPE_GENEVE,
			      0, 4, 10, NULL, NULL); //[1c8], would pass!!
}

static int
PORT_IPV4_IPV6_NVGRE_VXLAN_GENEVE(void)
{
	return result_checker(FLOW_KEY_TYPE_PORT|
			      FLOW_KEY_TYPE_IPV4|FLOW_KEY_TYPE_IPV6|
			      FLOW_KEY_TYPE_NVGRE|FLOW_KEY_TYPE_VXLAN|
			      FLOW_KEY_TYPE_GENEVE,
			      1, 5, 42, NULL, NULL); //[1c7], fail
}

static int
IPV4_IPV6_NVGRE_VXLAN_GENEVE(void)
{
	return result_checker(FLOW_KEY_TYPE_IPV4|
			      FLOW_KEY_TYPE_IPV6|FLOW_KEY_TYPE_NVGRE|
			      FLOW_KEY_TYPE_VXLAN|FLOW_KEY_TYPE_GENEVE,
			      1, 5, 42, NULL, NULL); //[1c6], fail
}

static int
PORT_IPV6_NVGRE_VXLAN_GENEVE(void)
{
	return result_checker(FLOW_KEY_TYPE_PORT|
			      FLOW_KEY_TYPE_IPV6|FLOW_KEY_TYPE_NVGRE|
			      FLOW_KEY_TYPE_VXLAN|FLOW_KEY_TYPE_GENEVE,
			      1, 5, 42, NULL, NULL); //[1c5], fail
}

static int
IPV6_NVGRE_VXLAN_GENEVE(void)
{
	return result_checker(FLOW_KEY_TYPE_IPV6|
			      FLOW_KEY_TYPE_NVGRE|FLOW_KEY_TYPE_VXLAN|
			      FLOW_KEY_TYPE_GENEVE,
			      1, 5, 42, NULL, NULL); //[1c4], fail
}

static int
PORT_IPV4_NVGRE_VXLAN_GENEVE(void)
{
	return result_checker(FLOW_KEY_TYPE_PORT|
			      FLOW_KEY_TYPE_IPV4|FLOW_KEY_TYPE_NVGRE|
			      FLOW_KEY_TYPE_VXLAN|FLOW_KEY_TYPE_GENEVE,
			      0, 5, 16, NULL, NULL); //[1c3], would pass!!
}

static int
IPV4_NVGRE_VXLAN_GENEVE(void)
{
	return result_checker(FLOW_KEY_TYPE_IPV4|
			      FLOW_KEY_TYPE_NVGRE|FLOW_KEY_TYPE_VXLAN|
			      FLOW_KEY_TYPE_GENEVE,
			      0, 4, 14, NULL, NULL); //[1c2], would pass!!
}

static int
PORT_NVGRE_VXLAN_GENEVE(void)
{
	return result_checker(FLOW_KEY_TYPE_PORT|
			      FLOW_KEY_TYPE_NVGRE|FLOW_KEY_TYPE_VXLAN|
			      FLOW_KEY_TYPE_GENEVE,
			      0, 4, 8, NULL, NULL); //[1c1], would pass!!
}

static int
NVGRE_VXLAN_GENEVE(void)
{
	return result_checker(FLOW_KEY_TYPE_NVGRE|
			      FLOW_KEY_TYPE_VXLAN|FLOW_KEY_TYPE_GENEVE,
			      0, 3, 6, NULL, NULL); //[1c0], would pass!!
}

static int
PORT_IPV4_IPV6_TCP_UDP_SCTP_VXLAN_GENEVE(void)
{
	return result_checker(FLOW_KEY_TYPE_PORT|
			      FLOW_KEY_TYPE_IPV4|FLOW_KEY_TYPE_IPV6|
			      FLOW_KEY_TYPE_TCP|FLOW_KEY_TYPE_UDP|
			      FLOW_KEY_TYPE_SCTP|FLOW_KEY_TYPE_VXLAN|
			      FLOW_KEY_TYPE_GENEVE,
			      1, 5, 42, NULL, NULL); //[1bf], fail
}

static int
IPV4_IPV6_TCP_UDP_SCTP_VXLAN_GENEVE(void)
{
	return result_checker(FLOW_KEY_TYPE_IPV4|
			      FLOW_KEY_TYPE_IPV6|FLOW_KEY_TYPE_TCP|
			      FLOW_KEY_TYPE_UDP|FLOW_KEY_TYPE_SCTP|
			      FLOW_KEY_TYPE_VXLAN|FLOW_KEY_TYPE_GENEVE,
			      1, 5, 42, NULL, NULL); //[1be], fail
}

static int
PORT_IPV6_TCP_UDP_SCTP_VXLAN_GENEVE(void)
{
	return result_checker(FLOW_KEY_TYPE_PORT|
			      FLOW_KEY_TYPE_IPV6|FLOW_KEY_TYPE_TCP|
			      FLOW_KEY_TYPE_UDP|FLOW_KEY_TYPE_SCTP|
			      FLOW_KEY_TYPE_VXLAN|FLOW_KEY_TYPE_GENEVE,
			      1, 5, 42, NULL, NULL); //[1bd], fail
}

static int
IPV6_TCP_UDP_SCTP_VXLAN_GENEVE(void)
{
	return result_checker(FLOW_KEY_TYPE_IPV6|
			      FLOW_KEY_TYPE_TCP|FLOW_KEY_TYPE_UDP|
			      FLOW_KEY_TYPE_SCTP|FLOW_KEY_TYPE_VXLAN|
			      FLOW_KEY_TYPE_GENEVE,
			      1, 5, 42, NULL, NULL); //[1bc], fail
}

static int
PORT_IPV4_TCP_UDP_SCTP_VXLAN_GENEVE(void)
{
	return result_checker(FLOW_KEY_TYPE_PORT|
			      FLOW_KEY_TYPE_IPV4|FLOW_KEY_TYPE_TCP|
			      FLOW_KEY_TYPE_UDP|FLOW_KEY_TYPE_SCTP|
			      FLOW_KEY_TYPE_VXLAN|FLOW_KEY_TYPE_GENEVE,
			      0, 5, 17, NULL, NULL); //[1bb], would pass!!
}

static int
IPV4_TCP_UDP_SCTP_VXLAN_GENEVE(void)
{
	return result_checker(FLOW_KEY_TYPE_IPV4|
			      FLOW_KEY_TYPE_TCP|FLOW_KEY_TYPE_UDP|
			      FLOW_KEY_TYPE_SCTP|FLOW_KEY_TYPE_VXLAN|
			      FLOW_KEY_TYPE_GENEVE,
			      0, 4, 15, NULL, NULL); //[1ba], would pass!!
}

static int
PORT_TCP_UDP_SCTP_VXLAN_GENEVE(void)
{
	return result_checker(FLOW_KEY_TYPE_PORT|
			      FLOW_KEY_TYPE_TCP|FLOW_KEY_TYPE_UDP|
			      FLOW_KEY_TYPE_SCTP|FLOW_KEY_TYPE_VXLAN|
			      FLOW_KEY_TYPE_GENEVE,
			      0, 4, 9, NULL, NULL); //[1b9], would pass!!
}

static int
TCP_UDP_SCTP_VXLAN_GENEVE(void)
{
	return result_checker(FLOW_KEY_TYPE_TCP|
			      FLOW_KEY_TYPE_UDP|FLOW_KEY_TYPE_SCTP|
			      FLOW_KEY_TYPE_VXLAN|FLOW_KEY_TYPE_GENEVE,
			      0, 3, 7, NULL, NULL); //[1b8], would pass!!
}

static int
PORT_IPV4_IPV6_UDP_SCTP_VXLAN_GENEVE(void)
{
	return result_checker(FLOW_KEY_TYPE_PORT|
			      FLOW_KEY_TYPE_IPV4|FLOW_KEY_TYPE_IPV6|
			      FLOW_KEY_TYPE_UDP|FLOW_KEY_TYPE_SCTP|
			      FLOW_KEY_TYPE_VXLAN|FLOW_KEY_TYPE_GENEVE,
			      1, 5, 42, NULL, NULL); //[1b7], fail
}

static int
IPV4_IPV6_UDP_SCTP_VXLAN_GENEVE(void)
{
	return result_checker(FLOW_KEY_TYPE_IPV4|
			      FLOW_KEY_TYPE_IPV6|FLOW_KEY_TYPE_UDP|
			      FLOW_KEY_TYPE_SCTP|FLOW_KEY_TYPE_VXLAN|
			      FLOW_KEY_TYPE_GENEVE,
			      1, 5, 42, NULL, NULL); //[1b6], fail
}

static int
PORT_IPV6_UDP_SCTP_VXLAN_GENEVE(void)
{
	return result_checker(FLOW_KEY_TYPE_PORT|
			      FLOW_KEY_TYPE_IPV6|FLOW_KEY_TYPE_UDP|
			      FLOW_KEY_TYPE_SCTP|FLOW_KEY_TYPE_VXLAN|
			      FLOW_KEY_TYPE_GENEVE,
			      1, 5, 42, NULL, NULL); //[1b5], fail
}

static int
IPV6_UDP_SCTP_VXLAN_GENEVE(void)
{
	return result_checker(FLOW_KEY_TYPE_IPV6|
			      FLOW_KEY_TYPE_UDP|FLOW_KEY_TYPE_SCTP|
			      FLOW_KEY_TYPE_VXLAN|FLOW_KEY_TYPE_GENEVE,
			      1, 5, 42, NULL, NULL); //[1b4], fail
}

static int
PORT_IPV4_UDP_SCTP_VXLAN_GENEVE(void)
{
	return result_checker(FLOW_KEY_TYPE_PORT|
			      FLOW_KEY_TYPE_IPV4|FLOW_KEY_TYPE_UDP|
			      FLOW_KEY_TYPE_SCTP|FLOW_KEY_TYPE_VXLAN|
			      FLOW_KEY_TYPE_GENEVE,
			      0, 5, 17, NULL, NULL); //[1b3], would pass!!
}

static int
IPV4_UDP_SCTP_VXLAN_GENEVE(void)
{
	return result_checker(FLOW_KEY_TYPE_IPV4|
			      FLOW_KEY_TYPE_UDP|FLOW_KEY_TYPE_SCTP|
			      FLOW_KEY_TYPE_VXLAN|FLOW_KEY_TYPE_GENEVE,
			      0, 4, 15, NULL, NULL); //[1b2], would pass!!
}

static int
PORT_UDP_SCTP_VXLAN_GENEVE(void)
{
	return result_checker(FLOW_KEY_TYPE_PORT|
			      FLOW_KEY_TYPE_UDP|FLOW_KEY_TYPE_SCTP|
			      FLOW_KEY_TYPE_VXLAN|FLOW_KEY_TYPE_GENEVE,
			      0, 4, 9, NULL, NULL); //[1b1], would pass!!
}

static int
UDP_SCTP_VXLAN_GENEVE(void)
{
	return result_checker(FLOW_KEY_TYPE_UDP|
			      FLOW_KEY_TYPE_SCTP|FLOW_KEY_TYPE_VXLAN|
			      FLOW_KEY_TYPE_GENEVE,
			      0, 3, 7, NULL, NULL); //[1b0], would pass!!
}

static int
PORT_IPV4_IPV6_TCP_SCTP_VXLAN_GENEVE(void)
{
	return result_checker(FLOW_KEY_TYPE_PORT|
			      FLOW_KEY_TYPE_IPV4|FLOW_KEY_TYPE_IPV6|
			      FLOW_KEY_TYPE_TCP|FLOW_KEY_TYPE_SCTP|
			      FLOW_KEY_TYPE_VXLAN|FLOW_KEY_TYPE_GENEVE,
			      1, 5, 42, NULL, NULL); //[1af], fail
}

static int
IPV4_IPV6_TCP_SCTP_VXLAN_GENEVE(void)
{
	return result_checker(FLOW_KEY_TYPE_IPV4|
			      FLOW_KEY_TYPE_IPV6|FLOW_KEY_TYPE_TCP|
			      FLOW_KEY_TYPE_SCTP|FLOW_KEY_TYPE_VXLAN|
			      FLOW_KEY_TYPE_GENEVE,
			      1, 5, 42, NULL, NULL); //[1ae], fail
}

static int
PORT_IPV6_TCP_SCTP_VXLAN_GENEVE(void)
{
	return result_checker(FLOW_KEY_TYPE_PORT|
			      FLOW_KEY_TYPE_IPV6|FLOW_KEY_TYPE_TCP|
			      FLOW_KEY_TYPE_SCTP|FLOW_KEY_TYPE_VXLAN|
			      FLOW_KEY_TYPE_GENEVE,
			      1, 5, 42, NULL, NULL); //[1ad], fail
}

static int
IPV6_TCP_SCTP_VXLAN_GENEVE(void)
{
	return result_checker(FLOW_KEY_TYPE_IPV6|
			      FLOW_KEY_TYPE_TCP|FLOW_KEY_TYPE_SCTP|
			      FLOW_KEY_TYPE_VXLAN|FLOW_KEY_TYPE_GENEVE,
			      1, 5, 42, NULL, NULL); //[1ac], fail
}

static int
PORT_IPV4_TCP_SCTP_VXLAN_GENEVE(void)
{
	return result_checker(FLOW_KEY_TYPE_PORT|
			      FLOW_KEY_TYPE_IPV4|FLOW_KEY_TYPE_TCP|
			      FLOW_KEY_TYPE_SCTP|FLOW_KEY_TYPE_VXLAN|
			      FLOW_KEY_TYPE_GENEVE,
			      0, 5, 17, NULL, NULL); //[1ab], would pass!!
}

static int
IPV4_TCP_SCTP_VXLAN_GENEVE(void)
{
	return result_checker(FLOW_KEY_TYPE_IPV4|
			      FLOW_KEY_TYPE_TCP|FLOW_KEY_TYPE_SCTP|
			      FLOW_KEY_TYPE_VXLAN|FLOW_KEY_TYPE_GENEVE,
			      0, 4, 15, NULL, NULL); //[1aa], would pass!!
}

static int
PORT_TCP_SCTP_VXLAN_GENEVE(void)
{
	return result_checker(FLOW_KEY_TYPE_PORT|
			      FLOW_KEY_TYPE_TCP|FLOW_KEY_TYPE_SCTP|
			      FLOW_KEY_TYPE_VXLAN|FLOW_KEY_TYPE_GENEVE,
			      0, 4, 9, NULL, NULL); //[1a9], would pass!!
}

static int
TCP_SCTP_VXLAN_GENEVE(void)
{
	return result_checker(FLOW_KEY_TYPE_TCP|
			      FLOW_KEY_TYPE_SCTP|FLOW_KEY_TYPE_VXLAN|
			      FLOW_KEY_TYPE_GENEVE,
			      0, 3, 7, NULL, NULL); //[1a8], would pass!!
}

static int
PORT_IPV4_IPV6_SCTP_VXLAN_GENEVE(void)
{
	return result_checker(FLOW_KEY_TYPE_PORT|
			      FLOW_KEY_TYPE_IPV4|FLOW_KEY_TYPE_IPV6|
			      FLOW_KEY_TYPE_SCTP|FLOW_KEY_TYPE_VXLAN|
			      FLOW_KEY_TYPE_GENEVE,
			      1, 5, 42, NULL, NULL); //[1a7], fail
}

static int
IPV4_IPV6_SCTP_VXLAN_GENEVE(void)
{
	return result_checker(FLOW_KEY_TYPE_IPV4|
			      FLOW_KEY_TYPE_IPV6|FLOW_KEY_TYPE_SCTP|
			      FLOW_KEY_TYPE_VXLAN|FLOW_KEY_TYPE_GENEVE,
			      1, 5, 42, NULL, NULL); //[1a6], fail
}

static int
PORT_IPV6_SCTP_VXLAN_GENEVE(void)
{
	return result_checker(FLOW_KEY_TYPE_PORT|
			      FLOW_KEY_TYPE_IPV6|FLOW_KEY_TYPE_SCTP|
			      FLOW_KEY_TYPE_VXLAN|FLOW_KEY_TYPE_GENEVE,
			      1, 5, 42, NULL, NULL); //[1a5], fail
}

static int
IPV6_SCTP_VXLAN_GENEVE(void)
{
	return result_checker(FLOW_KEY_TYPE_IPV6|
			      FLOW_KEY_TYPE_SCTP|FLOW_KEY_TYPE_VXLAN|
			      FLOW_KEY_TYPE_GENEVE,
			      1, 5, 42, NULL, NULL); //[1a4], fail
}

static int
PORT_IPV4_SCTP_VXLAN_GENEVE(void)
{
	return result_checker(FLOW_KEY_TYPE_PORT|
			      FLOW_KEY_TYPE_IPV4|FLOW_KEY_TYPE_SCTP|
			      FLOW_KEY_TYPE_VXLAN|FLOW_KEY_TYPE_GENEVE,
			      0, 5, 17, NULL, NULL); //[1a3], would pass!!
}

static int
IPV4_SCTP_VXLAN_GENEVE(void)
{
	return result_checker(FLOW_KEY_TYPE_IPV4|
			      FLOW_KEY_TYPE_SCTP|FLOW_KEY_TYPE_VXLAN|
			      FLOW_KEY_TYPE_GENEVE,
			      0, 4, 15, NULL, NULL); //[1a2], would pass!!
}

static int
PORT_SCTP_VXLAN_GENEVE(void)
{
	return result_checker(FLOW_KEY_TYPE_PORT|
			      FLOW_KEY_TYPE_SCTP|FLOW_KEY_TYPE_VXLAN|
			      FLOW_KEY_TYPE_GENEVE,
			      0, 4, 9, NULL, NULL); //[1a1], would pass!!
}

static int
SCTP_VXLAN_GENEVE(void)
{
	return result_checker(FLOW_KEY_TYPE_SCTP|
			      FLOW_KEY_TYPE_VXLAN|FLOW_KEY_TYPE_GENEVE,
			      0, 3, 7, NULL, NULL); //[1a0], would pass!!
}

static int
PORT_IPV4_IPV6_TCP_UDP_VXLAN_GENEVE(void)
{
	return result_checker(FLOW_KEY_TYPE_PORT|
			      FLOW_KEY_TYPE_IPV4|FLOW_KEY_TYPE_IPV6|
			      FLOW_KEY_TYPE_TCP|FLOW_KEY_TYPE_UDP|
			      FLOW_KEY_TYPE_VXLAN|FLOW_KEY_TYPE_GENEVE,
			      1, 5, 42, NULL, NULL); //[19f], fail
}

static int
IPV4_IPV6_TCP_UDP_VXLAN_GENEVE(void)
{
	return result_checker(FLOW_KEY_TYPE_IPV4|
			      FLOW_KEY_TYPE_IPV6|FLOW_KEY_TYPE_TCP|
			      FLOW_KEY_TYPE_UDP|FLOW_KEY_TYPE_VXLAN|
			      FLOW_KEY_TYPE_GENEVE,
			      1, 5, 42, NULL, NULL); //[19e], fail
}

static int
PORT_IPV6_TCP_UDP_VXLAN_GENEVE(void)
{
	return result_checker(FLOW_KEY_TYPE_PORT|
			      FLOW_KEY_TYPE_IPV6|FLOW_KEY_TYPE_TCP|
			      FLOW_KEY_TYPE_UDP|FLOW_KEY_TYPE_VXLAN|
			      FLOW_KEY_TYPE_GENEVE,
			      1, 5, 42, NULL, NULL); //[19d], fail
}

static int
IPV6_TCP_UDP_VXLAN_GENEVE(void)
{
	return result_checker(FLOW_KEY_TYPE_IPV6|
			      FLOW_KEY_TYPE_TCP|FLOW_KEY_TYPE_UDP|
			      FLOW_KEY_TYPE_VXLAN|FLOW_KEY_TYPE_GENEVE,
			      1, 5, 42, NULL, NULL); //[19c], fail
}

static int
PORT_IPV4_TCP_UDP_VXLAN_GENEVE(void)
{
	return result_checker(FLOW_KEY_TYPE_PORT|
			      FLOW_KEY_TYPE_IPV4|FLOW_KEY_TYPE_TCP|
			      FLOW_KEY_TYPE_UDP|FLOW_KEY_TYPE_VXLAN|
			      FLOW_KEY_TYPE_GENEVE,
			      0, 5, 17, NULL, NULL); //[19b], would pass!!
}

static int
IPV4_TCP_UDP_VXLAN_GENEVE(void)
{
	return result_checker(FLOW_KEY_TYPE_IPV4|
			      FLOW_KEY_TYPE_TCP|FLOW_KEY_TYPE_UDP|
			      FLOW_KEY_TYPE_VXLAN|FLOW_KEY_TYPE_GENEVE,
			      0, 4, 15, NULL, NULL); //[19a], would pass!!
}

static int
PORT_TCP_UDP_VXLAN_GENEVE(void)
{
	return result_checker(FLOW_KEY_TYPE_PORT|
			      FLOW_KEY_TYPE_TCP|FLOW_KEY_TYPE_UDP|
			      FLOW_KEY_TYPE_VXLAN|FLOW_KEY_TYPE_GENEVE,
			      0, 4, 9, NULL, NULL); //[199], would pass!!
}

static int
TCP_UDP_VXLAN_GENEVE(void)
{
	return result_checker(FLOW_KEY_TYPE_TCP|
			      FLOW_KEY_TYPE_UDP|FLOW_KEY_TYPE_VXLAN|
			      FLOW_KEY_TYPE_GENEVE,
			      0, 3, 7, NULL, NULL); //[198], would pass!!
}

static int
PORT_IPV4_IPV6_UDP_VXLAN_GENEVE(void)
{
	return result_checker(FLOW_KEY_TYPE_PORT|
			      FLOW_KEY_TYPE_IPV4|FLOW_KEY_TYPE_IPV6|
			      FLOW_KEY_TYPE_UDP|FLOW_KEY_TYPE_VXLAN|
			      FLOW_KEY_TYPE_GENEVE,
			      1, 5, 42, NULL, NULL); //[197], fail
}

static int
IPV4_IPV6_UDP_VXLAN_GENEVE(void)
{
	return result_checker(FLOW_KEY_TYPE_IPV4|
			      FLOW_KEY_TYPE_IPV6|FLOW_KEY_TYPE_UDP|
			      FLOW_KEY_TYPE_VXLAN|FLOW_KEY_TYPE_GENEVE,
			      1, 5, 42, NULL, NULL); //[196], fail
}

static int
PORT_IPV6_UDP_VXLAN_GENEVE(void)
{
	return result_checker(FLOW_KEY_TYPE_PORT|
			      FLOW_KEY_TYPE_IPV6|FLOW_KEY_TYPE_UDP|
			      FLOW_KEY_TYPE_VXLAN|FLOW_KEY_TYPE_GENEVE,
			      1, 5, 42, NULL, NULL); //[195], fail
}

static int
IPV6_UDP_VXLAN_GENEVE(void)
{
	return result_checker(FLOW_KEY_TYPE_IPV6|
			      FLOW_KEY_TYPE_UDP|FLOW_KEY_TYPE_VXLAN|
			      FLOW_KEY_TYPE_GENEVE,
			      1, 5, 42, NULL, NULL); //[194], fail
}

static int
PORT_IPV4_UDP_VXLAN_GENEVE(void)
{
	return result_checker(FLOW_KEY_TYPE_PORT|
			      FLOW_KEY_TYPE_IPV4|FLOW_KEY_TYPE_UDP|
			      FLOW_KEY_TYPE_VXLAN|FLOW_KEY_TYPE_GENEVE,
			      0, 5, 17, NULL, NULL); //[193], would pass!!
}

static int
IPV4_UDP_VXLAN_GENEVE(void)
{
	return result_checker(FLOW_KEY_TYPE_IPV4|
			      FLOW_KEY_TYPE_UDP|FLOW_KEY_TYPE_VXLAN|
			      FLOW_KEY_TYPE_GENEVE,
			      0, 4, 15, NULL, NULL); //[192], would pass!!
}

static int
PORT_UDP_VXLAN_GENEVE(void)
{
	return result_checker(FLOW_KEY_TYPE_PORT|
			      FLOW_KEY_TYPE_UDP|FLOW_KEY_TYPE_VXLAN|
			      FLOW_KEY_TYPE_GENEVE,
			      0, 4, 9, NULL, NULL); //[191], would pass!!
}

static int
UDP_VXLAN_GENEVE(void)
{
	return result_checker(FLOW_KEY_TYPE_UDP|
			      FLOW_KEY_TYPE_VXLAN|FLOW_KEY_TYPE_GENEVE,
			      0, 3, 7, NULL, NULL); //[190], would pass!!
}

static int
PORT_IPV4_IPV6_TCP_VXLAN_GENEVE(void)
{
	return result_checker(FLOW_KEY_TYPE_PORT|
			      FLOW_KEY_TYPE_IPV4|FLOW_KEY_TYPE_IPV6|
			      FLOW_KEY_TYPE_TCP|FLOW_KEY_TYPE_VXLAN|
			      FLOW_KEY_TYPE_GENEVE,
			      1, 5, 42, NULL, NULL); //[18f], fail
}

static int
IPV4_IPV6_TCP_VXLAN_GENEVE(void)
{
	return result_checker(FLOW_KEY_TYPE_IPV4|
			      FLOW_KEY_TYPE_IPV6|FLOW_KEY_TYPE_TCP|
			      FLOW_KEY_TYPE_VXLAN|FLOW_KEY_TYPE_GENEVE,
			      1, 5, 42, NULL, NULL); //[18e], fail
}

static int
PORT_IPV6_TCP_VXLAN_GENEVE(void)
{
	return result_checker(FLOW_KEY_TYPE_PORT|
			      FLOW_KEY_TYPE_IPV6|FLOW_KEY_TYPE_TCP|
			      FLOW_KEY_TYPE_VXLAN|FLOW_KEY_TYPE_GENEVE,
			      1, 5, 42, NULL, NULL); //[18d], fail
}

static int
IPV6_TCP_VXLAN_GENEVE(void)
{
	return result_checker(FLOW_KEY_TYPE_IPV6|
			      FLOW_KEY_TYPE_TCP|FLOW_KEY_TYPE_VXLAN|
			      FLOW_KEY_TYPE_GENEVE,
			      1, 5, 42, NULL, NULL); //[18c], fail
}

static int
PORT_IPV4_TCP_VXLAN_GENEVE(void)
{
	return result_checker(FLOW_KEY_TYPE_PORT|
			      FLOW_KEY_TYPE_IPV4|FLOW_KEY_TYPE_TCP|
			      FLOW_KEY_TYPE_VXLAN|FLOW_KEY_TYPE_GENEVE,
			      0, 5, 17, NULL, NULL); //[18b], would pass!!
}

static int
IPV4_TCP_VXLAN_GENEVE(void)
{
	return result_checker(FLOW_KEY_TYPE_IPV4|
			      FLOW_KEY_TYPE_TCP|FLOW_KEY_TYPE_VXLAN|
			      FLOW_KEY_TYPE_GENEVE,
			      0, 4, 15, NULL, NULL); //[18a], would pass!!
}

static int
PORT_TCP_VXLAN_GENEVE(void)
{
	return result_checker(FLOW_KEY_TYPE_PORT|
			      FLOW_KEY_TYPE_TCP|FLOW_KEY_TYPE_VXLAN|
			      FLOW_KEY_TYPE_GENEVE,
			      0, 4, 9, NULL, NULL); //[189], would pass!!
}

static int
TCP_VXLAN_GENEVE(void)
{
	return result_checker(FLOW_KEY_TYPE_TCP|
			      FLOW_KEY_TYPE_VXLAN|FLOW_KEY_TYPE_GENEVE,
			      0, 3, 7, NULL, NULL); //[188], would pass!!
}

static int
PORT_IPV4_IPV6_VXLAN_GENEVE(void)
{
	return result_checker(FLOW_KEY_TYPE_PORT|
			      FLOW_KEY_TYPE_IPV4|FLOW_KEY_TYPE_IPV6|
			      FLOW_KEY_TYPE_VXLAN|FLOW_KEY_TYPE_GENEVE,
			      1, 5, 42, NULL, NULL); //[187], fail
}

static int
IPV4_IPV6_VXLAN_GENEVE(void)
{
	return result_checker(FLOW_KEY_TYPE_IPV4|
			      FLOW_KEY_TYPE_IPV6|FLOW_KEY_TYPE_VXLAN|
			      FLOW_KEY_TYPE_GENEVE,
			      0, 4, 35, NULL, NULL); //[186], would pass!!
}

static int
PORT_IPV6_VXLAN_GENEVE(void)
{
	return result_checker(FLOW_KEY_TYPE_PORT|
			      FLOW_KEY_TYPE_IPV6|FLOW_KEY_TYPE_VXLAN|
			      FLOW_KEY_TYPE_GENEVE,
			      1, 5, 42, NULL, NULL); //[185], fail
}

static int
IPV6_VXLAN_GENEVE(void)
{
	return result_checker(FLOW_KEY_TYPE_IPV6|
			      FLOW_KEY_TYPE_VXLAN|FLOW_KEY_TYPE_GENEVE,
			      0, 3, 35, NULL, NULL); //[184], would pass!!
}

static int
PORT_IPV4_VXLAN_GENEVE(void)
{
	return result_checker(FLOW_KEY_TYPE_PORT|
			      FLOW_KEY_TYPE_IPV4|FLOW_KEY_TYPE_VXLAN|
			      FLOW_KEY_TYPE_GENEVE,
			      0, 4, 13, NULL, NULL); //[183], would pass!!
}

static int
IPV4_VXLAN_GENEVE(void)
{
	return result_checker(FLOW_KEY_TYPE_IPV4|
			      FLOW_KEY_TYPE_VXLAN|FLOW_KEY_TYPE_GENEVE,
			      0, 3, 11, NULL, NULL); //[182], would pass!!
}

static int
PORT_VXLAN_GENEVE(void)
{
	return result_checker(FLOW_KEY_TYPE_PORT|
			      FLOW_KEY_TYPE_VXLAN|FLOW_KEY_TYPE_GENEVE,
			      0, 3, 5, NULL, NULL); //[181], would pass!!
}

static int
VXLAN_GENEVE(void)
{
	return result_checker(FLOW_KEY_TYPE_VXLAN|
			      FLOW_KEY_TYPE_GENEVE,
			      0, 2, 3, NULL, NULL); //[180], would pass!!
}

static int
PORT_IPV4_IPV6_TCP_UDP_SCTP_NVGRE_GENEVE(void)
{
	return result_checker(FLOW_KEY_TYPE_PORT|
			      FLOW_KEY_TYPE_IPV4|FLOW_KEY_TYPE_IPV6|
			      FLOW_KEY_TYPE_TCP|FLOW_KEY_TYPE_UDP|
			      FLOW_KEY_TYPE_SCTP|FLOW_KEY_TYPE_NVGRE|
			      FLOW_KEY_TYPE_GENEVE,
			      1, 5, 42, NULL, NULL); //[17f], fail
}

static int
IPV4_IPV6_TCP_UDP_SCTP_NVGRE_GENEVE(void)
{
	return result_checker(FLOW_KEY_TYPE_IPV4|
			      FLOW_KEY_TYPE_IPV6|FLOW_KEY_TYPE_TCP|
			      FLOW_KEY_TYPE_UDP|FLOW_KEY_TYPE_SCTP|
			      FLOW_KEY_TYPE_NVGRE|FLOW_KEY_TYPE_GENEVE,
			      1, 5, 42, NULL, NULL); //[17e], fail
}

static int
PORT_IPV6_TCP_UDP_SCTP_NVGRE_GENEVE(void)
{
	return result_checker(FLOW_KEY_TYPE_PORT|
			      FLOW_KEY_TYPE_IPV6|FLOW_KEY_TYPE_TCP|
			      FLOW_KEY_TYPE_UDP|FLOW_KEY_TYPE_SCTP|
			      FLOW_KEY_TYPE_NVGRE|FLOW_KEY_TYPE_GENEVE,
			      1, 5, 42, NULL, NULL); //[17d], fail
}

static int
IPV6_TCP_UDP_SCTP_NVGRE_GENEVE(void)
{
	return result_checker(FLOW_KEY_TYPE_IPV6|
			      FLOW_KEY_TYPE_TCP|FLOW_KEY_TYPE_UDP|
			      FLOW_KEY_TYPE_SCTP|FLOW_KEY_TYPE_NVGRE|
			      FLOW_KEY_TYPE_GENEVE,
			      1, 5, 42, NULL, NULL); //[17c], fail
}

static int
PORT_IPV4_TCP_UDP_SCTP_NVGRE_GENEVE(void)
{
	return result_checker(FLOW_KEY_TYPE_PORT|
			      FLOW_KEY_TYPE_IPV4|FLOW_KEY_TYPE_TCP|
			      FLOW_KEY_TYPE_UDP|FLOW_KEY_TYPE_SCTP|
			      FLOW_KEY_TYPE_NVGRE|FLOW_KEY_TYPE_GENEVE,
			      0, 5, 17, NULL, NULL); //[17b], would pass!!
}

static int
IPV4_TCP_UDP_SCTP_NVGRE_GENEVE(void)
{
	return result_checker(FLOW_KEY_TYPE_IPV4|
			      FLOW_KEY_TYPE_TCP|FLOW_KEY_TYPE_UDP|
			      FLOW_KEY_TYPE_SCTP|FLOW_KEY_TYPE_NVGRE|
			      FLOW_KEY_TYPE_GENEVE,
			      0, 4, 15, NULL, NULL); //[17a], would pass!!
}

static int
PORT_TCP_UDP_SCTP_NVGRE_GENEVE(void)
{
	return result_checker(FLOW_KEY_TYPE_PORT|
			      FLOW_KEY_TYPE_TCP|FLOW_KEY_TYPE_UDP|
			      FLOW_KEY_TYPE_SCTP|FLOW_KEY_TYPE_NVGRE|
			      FLOW_KEY_TYPE_GENEVE,
			      0, 4, 9, NULL, NULL); //[179], would pass!!
}

static int
TCP_UDP_SCTP_NVGRE_GENEVE(void)
{
	return result_checker(FLOW_KEY_TYPE_TCP|
			      FLOW_KEY_TYPE_UDP|FLOW_KEY_TYPE_SCTP|
			      FLOW_KEY_TYPE_NVGRE|FLOW_KEY_TYPE_GENEVE,
			      0, 3, 7, NULL, NULL); //[178], would pass!!
}

static int
PORT_IPV4_IPV6_UDP_SCTP_NVGRE_GENEVE(void)
{
	return result_checker(FLOW_KEY_TYPE_PORT|
			      FLOW_KEY_TYPE_IPV4|FLOW_KEY_TYPE_IPV6|
			      FLOW_KEY_TYPE_UDP|FLOW_KEY_TYPE_SCTP|
			      FLOW_KEY_TYPE_NVGRE|FLOW_KEY_TYPE_GENEVE,
			      1, 5, 42, NULL, NULL); //[177], fail
}

static int
IPV4_IPV6_UDP_SCTP_NVGRE_GENEVE(void)
{
	return result_checker(FLOW_KEY_TYPE_IPV4|
			      FLOW_KEY_TYPE_IPV6|FLOW_KEY_TYPE_UDP|
			      FLOW_KEY_TYPE_SCTP|FLOW_KEY_TYPE_NVGRE|
			      FLOW_KEY_TYPE_GENEVE,
			      1, 5, 42, NULL, NULL); //[176], fail
}

static int
PORT_IPV6_UDP_SCTP_NVGRE_GENEVE(void)
{
	return result_checker(FLOW_KEY_TYPE_PORT|
			      FLOW_KEY_TYPE_IPV6|FLOW_KEY_TYPE_UDP|
			      FLOW_KEY_TYPE_SCTP|FLOW_KEY_TYPE_NVGRE|
			      FLOW_KEY_TYPE_GENEVE,
			      1, 5, 42, NULL, NULL); //[175], fail
}

static int
IPV6_UDP_SCTP_NVGRE_GENEVE(void)
{
	return result_checker(FLOW_KEY_TYPE_IPV6|
			      FLOW_KEY_TYPE_UDP|FLOW_KEY_TYPE_SCTP|
			      FLOW_KEY_TYPE_NVGRE|FLOW_KEY_TYPE_GENEVE,
			      1, 5, 42, NULL, NULL); //[174], fail
}

static int
PORT_IPV4_UDP_SCTP_NVGRE_GENEVE(void)
{
	return result_checker(FLOW_KEY_TYPE_PORT|
			      FLOW_KEY_TYPE_IPV4|FLOW_KEY_TYPE_UDP|
			      FLOW_KEY_TYPE_SCTP|FLOW_KEY_TYPE_NVGRE|
			      FLOW_KEY_TYPE_GENEVE,
			      0, 5, 17, NULL, NULL); //[173], would pass!!
}

static int
IPV4_UDP_SCTP_NVGRE_GENEVE(void)
{
	return result_checker(FLOW_KEY_TYPE_IPV4|
			      FLOW_KEY_TYPE_UDP|FLOW_KEY_TYPE_SCTP|
			      FLOW_KEY_TYPE_NVGRE|FLOW_KEY_TYPE_GENEVE,
			      0, 4, 15, NULL, NULL); //[172], would pass!!
}

static int
PORT_UDP_SCTP_NVGRE_GENEVE(void)
{
	return result_checker(FLOW_KEY_TYPE_PORT|
			      FLOW_KEY_TYPE_UDP|FLOW_KEY_TYPE_SCTP|
			      FLOW_KEY_TYPE_NVGRE|FLOW_KEY_TYPE_GENEVE,
			      0, 4, 9, NULL, NULL); //[171], would pass!!
}

static int
UDP_SCTP_NVGRE_GENEVE(void)
{
	return result_checker(FLOW_KEY_TYPE_UDP|
			      FLOW_KEY_TYPE_SCTP|FLOW_KEY_TYPE_NVGRE|
			      FLOW_KEY_TYPE_GENEVE,
			      0, 3, 7, NULL, NULL); //[170], would pass!!
}

static int
PORT_IPV4_IPV6_TCP_SCTP_NVGRE_GENEVE(void)
{
	return result_checker(FLOW_KEY_TYPE_PORT|
			      FLOW_KEY_TYPE_IPV4|FLOW_KEY_TYPE_IPV6|
			      FLOW_KEY_TYPE_TCP|FLOW_KEY_TYPE_SCTP|
			      FLOW_KEY_TYPE_NVGRE|FLOW_KEY_TYPE_GENEVE,
			      1, 5, 42, NULL, NULL); //[16f], fail
}

static int
IPV4_IPV6_TCP_SCTP_NVGRE_GENEVE(void)
{
	return result_checker(FLOW_KEY_TYPE_IPV4|
			      FLOW_KEY_TYPE_IPV6|FLOW_KEY_TYPE_TCP|
			      FLOW_KEY_TYPE_SCTP|FLOW_KEY_TYPE_NVGRE|
			      FLOW_KEY_TYPE_GENEVE,
			      1, 5, 42, NULL, NULL); //[16e], fail
}

static int
PORT_IPV6_TCP_SCTP_NVGRE_GENEVE(void)
{
	return result_checker(FLOW_KEY_TYPE_PORT|
			      FLOW_KEY_TYPE_IPV6|FLOW_KEY_TYPE_TCP|
			      FLOW_KEY_TYPE_SCTP|FLOW_KEY_TYPE_NVGRE|
			      FLOW_KEY_TYPE_GENEVE,
			      1, 5, 42, NULL, NULL); //[16d], fail
}

static int
IPV6_TCP_SCTP_NVGRE_GENEVE(void)
{
	return result_checker(FLOW_KEY_TYPE_IPV6|
			      FLOW_KEY_TYPE_TCP|FLOW_KEY_TYPE_SCTP|
			      FLOW_KEY_TYPE_NVGRE|FLOW_KEY_TYPE_GENEVE,
			      1, 5, 42, NULL, NULL); //[16c], fail
}

static int
PORT_IPV4_TCP_SCTP_NVGRE_GENEVE(void)
{
	return result_checker(FLOW_KEY_TYPE_PORT|
			      FLOW_KEY_TYPE_IPV4|FLOW_KEY_TYPE_TCP|
			      FLOW_KEY_TYPE_SCTP|FLOW_KEY_TYPE_NVGRE|
			      FLOW_KEY_TYPE_GENEVE,
			      0, 5, 17, NULL, NULL); //[16b], would pass!!
}

static int
IPV4_TCP_SCTP_NVGRE_GENEVE(void)
{
	return result_checker(FLOW_KEY_TYPE_IPV4|
			      FLOW_KEY_TYPE_TCP|FLOW_KEY_TYPE_SCTP|
			      FLOW_KEY_TYPE_NVGRE|FLOW_KEY_TYPE_GENEVE,
			      0, 4, 15, NULL, NULL); //[16a], would pass!!
}

static int
PORT_TCP_SCTP_NVGRE_GENEVE(void)
{
	return result_checker(FLOW_KEY_TYPE_PORT|
			      FLOW_KEY_TYPE_TCP|FLOW_KEY_TYPE_SCTP|
			      FLOW_KEY_TYPE_NVGRE|FLOW_KEY_TYPE_GENEVE,
			      0, 4, 9, NULL, NULL); //[169], would pass!!
}

static int
TCP_SCTP_NVGRE_GENEVE(void)
{
	return result_checker(FLOW_KEY_TYPE_TCP|
			      FLOW_KEY_TYPE_SCTP|FLOW_KEY_TYPE_NVGRE|
			      FLOW_KEY_TYPE_GENEVE,
			      0, 3, 7, NULL, NULL); //[168], would pass!!
}

static int
PORT_IPV4_IPV6_SCTP_NVGRE_GENEVE(void)
{
	return result_checker(FLOW_KEY_TYPE_PORT|
			      FLOW_KEY_TYPE_IPV4|FLOW_KEY_TYPE_IPV6|
			      FLOW_KEY_TYPE_SCTP|FLOW_KEY_TYPE_NVGRE|
			      FLOW_KEY_TYPE_GENEVE,
			      1, 5, 42, NULL, NULL); //[167], fail
}

static int
IPV4_IPV6_SCTP_NVGRE_GENEVE(void)
{
	return result_checker(FLOW_KEY_TYPE_IPV4|
			      FLOW_KEY_TYPE_IPV6|FLOW_KEY_TYPE_SCTP|
			      FLOW_KEY_TYPE_NVGRE|FLOW_KEY_TYPE_GENEVE,
			      1, 5, 42, NULL, NULL); //[166], fail
}

static int
PORT_IPV6_SCTP_NVGRE_GENEVE(void)
{
	return result_checker(FLOW_KEY_TYPE_PORT|
			      FLOW_KEY_TYPE_IPV6|FLOW_KEY_TYPE_SCTP|
			      FLOW_KEY_TYPE_NVGRE|FLOW_KEY_TYPE_GENEVE,
			      1, 5, 42, NULL, NULL); //[165], fail
}

static int
IPV6_SCTP_NVGRE_GENEVE(void)
{
	return result_checker(FLOW_KEY_TYPE_IPV6|
			      FLOW_KEY_TYPE_SCTP|FLOW_KEY_TYPE_NVGRE|
			      FLOW_KEY_TYPE_GENEVE,
			      1, 5, 42, NULL, NULL); //[164], fail
}

static int
PORT_IPV4_SCTP_NVGRE_GENEVE(void)
{
	return result_checker(FLOW_KEY_TYPE_PORT|
			      FLOW_KEY_TYPE_IPV4|FLOW_KEY_TYPE_SCTP|
			      FLOW_KEY_TYPE_NVGRE|FLOW_KEY_TYPE_GENEVE,
			      0, 5, 17, NULL, NULL); //[163], would pass!!
}

static int
IPV4_SCTP_NVGRE_GENEVE(void)
{
	return result_checker(FLOW_KEY_TYPE_IPV4|
			      FLOW_KEY_TYPE_SCTP|FLOW_KEY_TYPE_NVGRE|
			      FLOW_KEY_TYPE_GENEVE,
			      0, 4, 15, NULL, NULL); //[162], would pass!!
}

static int
PORT_SCTP_NVGRE_GENEVE(void)
{
	return result_checker(FLOW_KEY_TYPE_PORT|
			      FLOW_KEY_TYPE_SCTP|FLOW_KEY_TYPE_NVGRE|
			      FLOW_KEY_TYPE_GENEVE,
			      0, 4, 9, NULL, NULL); //[161], would pass!!
}

static int
SCTP_NVGRE_GENEVE(void)
{
	return result_checker(FLOW_KEY_TYPE_SCTP|
			      FLOW_KEY_TYPE_NVGRE|FLOW_KEY_TYPE_GENEVE,
			      0, 3, 7, NULL, NULL); //[160], would pass!!
}

static int
PORT_IPV4_IPV6_TCP_UDP_NVGRE_GENEVE(void)
{
	return result_checker(FLOW_KEY_TYPE_PORT|
			      FLOW_KEY_TYPE_IPV4|FLOW_KEY_TYPE_IPV6|
			      FLOW_KEY_TYPE_TCP|FLOW_KEY_TYPE_UDP|
			      FLOW_KEY_TYPE_NVGRE|FLOW_KEY_TYPE_GENEVE,
			      1, 5, 42, NULL, NULL); //[15f], fail
}

static int
IPV4_IPV6_TCP_UDP_NVGRE_GENEVE(void)
{
	return result_checker(FLOW_KEY_TYPE_IPV4|
			      FLOW_KEY_TYPE_IPV6|FLOW_KEY_TYPE_TCP|
			      FLOW_KEY_TYPE_UDP|FLOW_KEY_TYPE_NVGRE|
			      FLOW_KEY_TYPE_GENEVE,
			      1, 5, 42, NULL, NULL); //[15e], fail
}

static int
PORT_IPV6_TCP_UDP_NVGRE_GENEVE(void)
{
	return result_checker(FLOW_KEY_TYPE_PORT|
			      FLOW_KEY_TYPE_IPV6|FLOW_KEY_TYPE_TCP|
			      FLOW_KEY_TYPE_UDP|FLOW_KEY_TYPE_NVGRE|
			      FLOW_KEY_TYPE_GENEVE,
			      1, 5, 42, NULL, NULL); //[15d], fail
}

static int
IPV6_TCP_UDP_NVGRE_GENEVE(void)
{
	return result_checker(FLOW_KEY_TYPE_IPV6|
			      FLOW_KEY_TYPE_TCP|FLOW_KEY_TYPE_UDP|
			      FLOW_KEY_TYPE_NVGRE|FLOW_KEY_TYPE_GENEVE,
			      1, 5, 42, NULL, NULL); //[15c], fail
}

static int
PORT_IPV4_TCP_UDP_NVGRE_GENEVE(void)
{
	return result_checker(FLOW_KEY_TYPE_PORT|
			      FLOW_KEY_TYPE_IPV4|FLOW_KEY_TYPE_TCP|
			      FLOW_KEY_TYPE_UDP|FLOW_KEY_TYPE_NVGRE|
			      FLOW_KEY_TYPE_GENEVE,
			      0, 5, 17, NULL, NULL); //[15b], would pass!!
}

static int
IPV4_TCP_UDP_NVGRE_GENEVE(void)
{
	return result_checker(FLOW_KEY_TYPE_IPV4|
			      FLOW_KEY_TYPE_TCP|FLOW_KEY_TYPE_UDP|
			      FLOW_KEY_TYPE_NVGRE|FLOW_KEY_TYPE_GENEVE,
			      0, 4, 15, NULL, NULL); //[15a], would pass!!
}

static int
PORT_TCP_UDP_NVGRE_GENEVE(void)
{
	return result_checker(FLOW_KEY_TYPE_PORT|
			      FLOW_KEY_TYPE_TCP|FLOW_KEY_TYPE_UDP|
			      FLOW_KEY_TYPE_NVGRE|FLOW_KEY_TYPE_GENEVE,
			      0, 4, 9, NULL, NULL); //[159], would pass!!
}

static int
TCP_UDP_NVGRE_GENEVE(void)
{
	return result_checker(FLOW_KEY_TYPE_TCP|
			      FLOW_KEY_TYPE_UDP|FLOW_KEY_TYPE_NVGRE|
			      FLOW_KEY_TYPE_GENEVE,
			      0, 3, 7, NULL, NULL); //[158], would pass!!
}

static int
PORT_IPV4_IPV6_UDP_NVGRE_GENEVE(void)
{
	return result_checker(FLOW_KEY_TYPE_PORT|
			      FLOW_KEY_TYPE_IPV4|FLOW_KEY_TYPE_IPV6|
			      FLOW_KEY_TYPE_UDP|FLOW_KEY_TYPE_NVGRE|
			      FLOW_KEY_TYPE_GENEVE,
			      1, 5, 42, NULL, NULL); //[157], fail
}

static int
IPV4_IPV6_UDP_NVGRE_GENEVE(void)
{
	return result_checker(FLOW_KEY_TYPE_IPV4|
			      FLOW_KEY_TYPE_IPV6|FLOW_KEY_TYPE_UDP|
			      FLOW_KEY_TYPE_NVGRE|FLOW_KEY_TYPE_GENEVE,
			      1, 5, 42, NULL, NULL); //[156], fail
}

static int
PORT_IPV6_UDP_NVGRE_GENEVE(void)
{
	return result_checker(FLOW_KEY_TYPE_PORT|
			      FLOW_KEY_TYPE_IPV6|FLOW_KEY_TYPE_UDP|
			      FLOW_KEY_TYPE_NVGRE|FLOW_KEY_TYPE_GENEVE,
			      1, 5, 42, NULL, NULL); //[155], fail
}

static int
IPV6_UDP_NVGRE_GENEVE(void)
{
	return result_checker(FLOW_KEY_TYPE_IPV6|
			      FLOW_KEY_TYPE_UDP|FLOW_KEY_TYPE_NVGRE|
			      FLOW_KEY_TYPE_GENEVE,
			      1, 5, 42, NULL, NULL); //[154], fail
}

static int
PORT_IPV4_UDP_NVGRE_GENEVE(void)
{
	return result_checker(FLOW_KEY_TYPE_PORT|
			      FLOW_KEY_TYPE_IPV4|FLOW_KEY_TYPE_UDP|
			      FLOW_KEY_TYPE_NVGRE|FLOW_KEY_TYPE_GENEVE,
			      0, 5, 17, NULL, NULL); //[153], would pass!!
}

static int
IPV4_UDP_NVGRE_GENEVE(void)
{
	return result_checker(FLOW_KEY_TYPE_IPV4|
			      FLOW_KEY_TYPE_UDP|FLOW_KEY_TYPE_NVGRE|
			      FLOW_KEY_TYPE_GENEVE,
			      0, 4, 15, NULL, NULL); //[152], would pass!!
}

static int
PORT_UDP_NVGRE_GENEVE(void)
{
	return result_checker(FLOW_KEY_TYPE_PORT|
			      FLOW_KEY_TYPE_UDP|FLOW_KEY_TYPE_NVGRE|
			      FLOW_KEY_TYPE_GENEVE,
			      0, 4, 9, NULL, NULL); //[151], would pass!!
}

static int
UDP_NVGRE_GENEVE(void)
{
	return result_checker(FLOW_KEY_TYPE_UDP|
			      FLOW_KEY_TYPE_NVGRE|FLOW_KEY_TYPE_GENEVE,
			      0, 3, 7, NULL, NULL); //[150], would pass!!
}

static int
PORT_IPV4_IPV6_TCP_NVGRE_GENEVE(void)
{
	return result_checker(FLOW_KEY_TYPE_PORT|
			      FLOW_KEY_TYPE_IPV4|FLOW_KEY_TYPE_IPV6|
			      FLOW_KEY_TYPE_TCP|FLOW_KEY_TYPE_NVGRE|
			      FLOW_KEY_TYPE_GENEVE,
			      1, 5, 42, NULL, NULL); //[14f], fail
}

static int
IPV4_IPV6_TCP_NVGRE_GENEVE(void)
{
	return result_checker(FLOW_KEY_TYPE_IPV4|
			      FLOW_KEY_TYPE_IPV6|FLOW_KEY_TYPE_TCP|
			      FLOW_KEY_TYPE_NVGRE|FLOW_KEY_TYPE_GENEVE,
			      1, 5, 42, NULL, NULL); //[14e], fail
}

static int
PORT_IPV6_TCP_NVGRE_GENEVE(void)
{
	return result_checker(FLOW_KEY_TYPE_PORT|
			      FLOW_KEY_TYPE_IPV6|FLOW_KEY_TYPE_TCP|
			      FLOW_KEY_TYPE_NVGRE|FLOW_KEY_TYPE_GENEVE,
			      1, 5, 42, NULL, NULL); //[14d], fail
}

static int
IPV6_TCP_NVGRE_GENEVE(void)
{
	return result_checker(FLOW_KEY_TYPE_IPV6|
			      FLOW_KEY_TYPE_TCP|FLOW_KEY_TYPE_NVGRE|
			      FLOW_KEY_TYPE_GENEVE,
			      1, 5, 42, NULL, NULL); //[14c], fail
}

static int
PORT_IPV4_TCP_NVGRE_GENEVE(void)
{
	return result_checker(FLOW_KEY_TYPE_PORT|
			      FLOW_KEY_TYPE_IPV4|FLOW_KEY_TYPE_TCP|
			      FLOW_KEY_TYPE_NVGRE|FLOW_KEY_TYPE_GENEVE,
			      0, 5, 17, NULL, NULL); //[14b], would pass!!
}

static int
IPV4_TCP_NVGRE_GENEVE(void)
{
	return result_checker(FLOW_KEY_TYPE_IPV4|
			      FLOW_KEY_TYPE_TCP|FLOW_KEY_TYPE_NVGRE|
			      FLOW_KEY_TYPE_GENEVE,
			      0, 4, 15, NULL, NULL); //[14a], would pass!!
}

static int
PORT_TCP_NVGRE_GENEVE(void)
{
	return result_checker(FLOW_KEY_TYPE_PORT|
			      FLOW_KEY_TYPE_TCP|FLOW_KEY_TYPE_NVGRE|
			      FLOW_KEY_TYPE_GENEVE,
			      0, 4, 9, NULL, NULL); //[149], would pass!!
}

static int
TCP_NVGRE_GENEVE(void)
{
	return result_checker(FLOW_KEY_TYPE_TCP|
			      FLOW_KEY_TYPE_NVGRE|FLOW_KEY_TYPE_GENEVE,
			      0, 3, 7, NULL, NULL); //[148], would pass!!
}

static int
PORT_IPV4_IPV6_NVGRE_GENEVE(void)
{
	return result_checker(FLOW_KEY_TYPE_PORT|
			      FLOW_KEY_TYPE_IPV4|FLOW_KEY_TYPE_IPV6|
			      FLOW_KEY_TYPE_NVGRE|FLOW_KEY_TYPE_GENEVE,
			      1, 5, 42, NULL, NULL); //[147], fail
}

static int
IPV4_IPV6_NVGRE_GENEVE(void)
{
	return result_checker(FLOW_KEY_TYPE_IPV4|
			      FLOW_KEY_TYPE_IPV6|FLOW_KEY_TYPE_NVGRE|
			      FLOW_KEY_TYPE_GENEVE,
			      0, 4, 35, NULL, NULL); //[146], would pass!!
}

static int
PORT_IPV6_NVGRE_GENEVE(void)
{
	return result_checker(FLOW_KEY_TYPE_PORT|
			      FLOW_KEY_TYPE_IPV6|FLOW_KEY_TYPE_NVGRE|
			      FLOW_KEY_TYPE_GENEVE,
			      1, 5, 42, NULL, NULL); //[145], fail
}

static int
IPV6_NVGRE_GENEVE(void)
{
	return result_checker(FLOW_KEY_TYPE_IPV6|
			      FLOW_KEY_TYPE_NVGRE|FLOW_KEY_TYPE_GENEVE,
			      0, 3, 35, NULL, NULL); //[144], would pass!!
}

static int
PORT_IPV4_NVGRE_GENEVE(void)
{
	return result_checker(FLOW_KEY_TYPE_PORT|
			      FLOW_KEY_TYPE_IPV4|FLOW_KEY_TYPE_NVGRE|
			      FLOW_KEY_TYPE_GENEVE,
			      0, 4, 13, NULL, NULL); //[143], would pass!!
}

static int
IPV4_NVGRE_GENEVE(void)
{
	return result_checker(FLOW_KEY_TYPE_IPV4|
			      FLOW_KEY_TYPE_NVGRE|FLOW_KEY_TYPE_GENEVE,
			      0, 3, 11, NULL, NULL); //[142], would pass!!
}

static int
PORT_NVGRE_GENEVE(void)
{
	return result_checker(FLOW_KEY_TYPE_PORT|
			      FLOW_KEY_TYPE_NVGRE|FLOW_KEY_TYPE_GENEVE,
			      0, 3, 5, NULL, NULL); //[141], would pass!!
}

static int
NVGRE_GENEVE(void)
{
	return result_checker(FLOW_KEY_TYPE_NVGRE|
			      FLOW_KEY_TYPE_GENEVE,
			      0, 2, 3, NULL, NULL); //[140], would pass!!
}

static int
PORT_IPV4_IPV6_TCP_UDP_SCTP_GENEVE(void)
{
	return result_checker(FLOW_KEY_TYPE_PORT|
			      FLOW_KEY_TYPE_IPV4|FLOW_KEY_TYPE_IPV6|
			      FLOW_KEY_TYPE_TCP|FLOW_KEY_TYPE_UDP|
			      FLOW_KEY_TYPE_SCTP|FLOW_KEY_TYPE_GENEVE,
			      1, 5, 42, NULL, NULL); //[13f], fail
}

static int
IPV4_IPV6_TCP_UDP_SCTP_GENEVE(void)
{
	return result_checker(FLOW_KEY_TYPE_IPV4|
			      FLOW_KEY_TYPE_IPV6|FLOW_KEY_TYPE_TCP|
			      FLOW_KEY_TYPE_UDP|FLOW_KEY_TYPE_SCTP|
			      FLOW_KEY_TYPE_GENEVE,
			      0, 4, 36, NULL, NULL); //[13e], would pass!!
}

static int
PORT_IPV6_TCP_UDP_SCTP_GENEVE(void)
{
	return result_checker(FLOW_KEY_TYPE_PORT|
			      FLOW_KEY_TYPE_IPV6|FLOW_KEY_TYPE_TCP|
			      FLOW_KEY_TYPE_UDP|FLOW_KEY_TYPE_SCTP|
			      FLOW_KEY_TYPE_GENEVE,
			      1, 5, 42, NULL, NULL); //[13d], fail
}

static int
IPV6_TCP_UDP_SCTP_GENEVE(void)
{
	return result_checker(FLOW_KEY_TYPE_IPV6|
			      FLOW_KEY_TYPE_TCP|FLOW_KEY_TYPE_UDP|
			      FLOW_KEY_TYPE_SCTP|FLOW_KEY_TYPE_GENEVE,
			      0, 3, 36, NULL, NULL); //[13c], would pass!!
}

static int
PORT_IPV4_TCP_UDP_SCTP_GENEVE(void)
{
	return result_checker(FLOW_KEY_TYPE_PORT|
			      FLOW_KEY_TYPE_IPV4|FLOW_KEY_TYPE_TCP|
			      FLOW_KEY_TYPE_UDP|FLOW_KEY_TYPE_SCTP|
			      FLOW_KEY_TYPE_GENEVE,
			      0, 4, 14, NULL, NULL); //[13b], would pass!!
}

static int
IPV4_TCP_UDP_SCTP_GENEVE(void)
{
	return result_checker(FLOW_KEY_TYPE_IPV4|
			      FLOW_KEY_TYPE_TCP|FLOW_KEY_TYPE_UDP|
			      FLOW_KEY_TYPE_SCTP|FLOW_KEY_TYPE_GENEVE,
			      0, 3, 12, NULL, NULL); //[13a], would pass!!
}

static int
PORT_TCP_UDP_SCTP_GENEVE(void)
{
	return result_checker(FLOW_KEY_TYPE_PORT|
			      FLOW_KEY_TYPE_TCP|FLOW_KEY_TYPE_UDP|
			      FLOW_KEY_TYPE_SCTP|FLOW_KEY_TYPE_GENEVE,
			      0, 3, 6, NULL, NULL); //[139], would pass!!
}

static int
TCP_UDP_SCTP_GENEVE(void)
{
	return result_checker(FLOW_KEY_TYPE_TCP|
			      FLOW_KEY_TYPE_UDP|FLOW_KEY_TYPE_SCTP|
			      FLOW_KEY_TYPE_GENEVE,
			      0, 2, 4, NULL, NULL); //[138], would pass!!
}

static int
PORT_IPV4_IPV6_UDP_SCTP_GENEVE(void)
{
	return result_checker(FLOW_KEY_TYPE_PORT|
			      FLOW_KEY_TYPE_IPV4|FLOW_KEY_TYPE_IPV6|
			      FLOW_KEY_TYPE_UDP|FLOW_KEY_TYPE_SCTP|
			      FLOW_KEY_TYPE_GENEVE,
			      1, 5, 42, NULL, NULL); //[137], fail
}

static int
IPV4_IPV6_UDP_SCTP_GENEVE(void)
{
	return result_checker(FLOW_KEY_TYPE_IPV4|
			      FLOW_KEY_TYPE_IPV6|FLOW_KEY_TYPE_UDP|
			      FLOW_KEY_TYPE_SCTP|FLOW_KEY_TYPE_GENEVE,
			      0, 4, 36, NULL, NULL); //[136], would pass!!
}

static int
PORT_IPV6_UDP_SCTP_GENEVE(void)
{
	return result_checker(FLOW_KEY_TYPE_PORT|
			      FLOW_KEY_TYPE_IPV6|FLOW_KEY_TYPE_UDP|
			      FLOW_KEY_TYPE_SCTP|FLOW_KEY_TYPE_GENEVE,
			      1, 5, 42, NULL, NULL); //[135], fail
}

static int
IPV6_UDP_SCTP_GENEVE(void)
{
	return result_checker(FLOW_KEY_TYPE_IPV6|
			      FLOW_KEY_TYPE_UDP|FLOW_KEY_TYPE_SCTP|
			      FLOW_KEY_TYPE_GENEVE,
			      0, 3, 36, NULL, NULL); //[134], would pass!!
}

static int
PORT_IPV4_UDP_SCTP_GENEVE(void)
{
	return result_checker(FLOW_KEY_TYPE_PORT|
			      FLOW_KEY_TYPE_IPV4|FLOW_KEY_TYPE_UDP|
			      FLOW_KEY_TYPE_SCTP|FLOW_KEY_TYPE_GENEVE,
			      0, 4, 14, NULL, NULL); //[133], would pass!!
}

static int
IPV4_UDP_SCTP_GENEVE(void)
{
	return result_checker(FLOW_KEY_TYPE_IPV4|
			      FLOW_KEY_TYPE_UDP|FLOW_KEY_TYPE_SCTP|
			      FLOW_KEY_TYPE_GENEVE,
			      0, 3, 12, NULL, NULL); //[132], would pass!!
}

static int
PORT_UDP_SCTP_GENEVE(void)
{
	return result_checker(FLOW_KEY_TYPE_PORT|
			      FLOW_KEY_TYPE_UDP|FLOW_KEY_TYPE_SCTP|
			      FLOW_KEY_TYPE_GENEVE,
			      0, 3, 6, NULL, NULL); //[131], would pass!!
}

static int
UDP_SCTP_GENEVE(void)
{
	return result_checker(FLOW_KEY_TYPE_UDP|
			      FLOW_KEY_TYPE_SCTP|FLOW_KEY_TYPE_GENEVE,
			      0, 2, 4, NULL, NULL); //[130], would pass!!
}

static int
PORT_IPV4_IPV6_TCP_SCTP_GENEVE(void)
{
	return result_checker(FLOW_KEY_TYPE_PORT|
			      FLOW_KEY_TYPE_IPV4|FLOW_KEY_TYPE_IPV6|
			      FLOW_KEY_TYPE_TCP|FLOW_KEY_TYPE_SCTP|
			      FLOW_KEY_TYPE_GENEVE,
			      1, 5, 42, NULL, NULL); //[12f], fail
}

static int
IPV4_IPV6_TCP_SCTP_GENEVE(void)
{
	return result_checker(FLOW_KEY_TYPE_IPV4|
			      FLOW_KEY_TYPE_IPV6|FLOW_KEY_TYPE_TCP|
			      FLOW_KEY_TYPE_SCTP|FLOW_KEY_TYPE_GENEVE,
			      0, 4, 36, NULL, NULL); //[12e], would pass!!
}

static int
PORT_IPV6_TCP_SCTP_GENEVE(void)
{
	return result_checker(FLOW_KEY_TYPE_PORT|
			      FLOW_KEY_TYPE_IPV6|FLOW_KEY_TYPE_TCP|
			      FLOW_KEY_TYPE_SCTP|FLOW_KEY_TYPE_GENEVE,
			      1, 5, 42, NULL, NULL); //[12d], fail
}

static int
IPV6_TCP_SCTP_GENEVE(void)
{
	return result_checker(FLOW_KEY_TYPE_IPV6|
			      FLOW_KEY_TYPE_TCP|FLOW_KEY_TYPE_SCTP|
			      FLOW_KEY_TYPE_GENEVE,
			      0, 3, 36, NULL, NULL); //[12c], would pass!!
}

static int
PORT_IPV4_TCP_SCTP_GENEVE(void)
{
	return result_checker(FLOW_KEY_TYPE_PORT|
			      FLOW_KEY_TYPE_IPV4|FLOW_KEY_TYPE_TCP|
			      FLOW_KEY_TYPE_SCTP|FLOW_KEY_TYPE_GENEVE,
			      0, 4, 14, NULL, NULL); //[12b], would pass!!
}

static int
IPV4_TCP_SCTP_GENEVE(void)
{
	return result_checker(FLOW_KEY_TYPE_IPV4|
			      FLOW_KEY_TYPE_TCP|FLOW_KEY_TYPE_SCTP|
			      FLOW_KEY_TYPE_GENEVE,
			      0, 3, 12, NULL, NULL); //[12a], would pass!!
}

static int
PORT_TCP_SCTP_GENEVE(void)
{
	return result_checker(FLOW_KEY_TYPE_PORT|
			      FLOW_KEY_TYPE_TCP|FLOW_KEY_TYPE_SCTP|
			      FLOW_KEY_TYPE_GENEVE,
			      0, 3, 6, NULL, NULL); //[129], would pass!!
}

static int
TCP_SCTP_GENEVE(void)
{
	return result_checker(FLOW_KEY_TYPE_TCP|
			      FLOW_KEY_TYPE_SCTP|FLOW_KEY_TYPE_GENEVE,
			      0, 2, 4, NULL, NULL); //[128], would pass!!
}

static int
PORT_IPV4_IPV6_SCTP_GENEVE(void)
{
	return result_checker(FLOW_KEY_TYPE_PORT|
			      FLOW_KEY_TYPE_IPV4|FLOW_KEY_TYPE_IPV6|
			      FLOW_KEY_TYPE_SCTP|FLOW_KEY_TYPE_GENEVE,
			      1, 5, 42, NULL, NULL); //[127], fail
}

static int
IPV4_IPV6_SCTP_GENEVE(void)
{
	return result_checker(FLOW_KEY_TYPE_IPV4|
			      FLOW_KEY_TYPE_IPV6|FLOW_KEY_TYPE_SCTP|
			      FLOW_KEY_TYPE_GENEVE,
			      0, 4, 36, NULL, NULL); //[126], would pass!!
}

static int
PORT_IPV6_SCTP_GENEVE(void)
{
	return result_checker(FLOW_KEY_TYPE_PORT|
			      FLOW_KEY_TYPE_IPV6|FLOW_KEY_TYPE_SCTP|
			      FLOW_KEY_TYPE_GENEVE,
			      1, 5, 42, NULL, NULL); //[125], fail
}

static int
IPV6_SCTP_GENEVE(void)
{
	return result_checker(FLOW_KEY_TYPE_IPV6|
			      FLOW_KEY_TYPE_SCTP|FLOW_KEY_TYPE_GENEVE,
			      0, 3, 36, NULL, NULL); //[124], would pass!!
}

static int
PORT_IPV4_SCTP_GENEVE(void)
{
	return result_checker(FLOW_KEY_TYPE_PORT|
			      FLOW_KEY_TYPE_IPV4|FLOW_KEY_TYPE_SCTP|
			      FLOW_KEY_TYPE_GENEVE,
			      0, 4, 14, NULL, NULL); //[123], would pass!!
}

static int
IPV4_SCTP_GENEVE(void)
{
	return result_checker(FLOW_KEY_TYPE_IPV4|
			      FLOW_KEY_TYPE_SCTP|FLOW_KEY_TYPE_GENEVE,
			      0, 3, 12, NULL, NULL); //[122], would pass!!
}

static int
PORT_SCTP_GENEVE(void)
{
	return result_checker(FLOW_KEY_TYPE_PORT|
			      FLOW_KEY_TYPE_SCTP|FLOW_KEY_TYPE_GENEVE,
			      0, 3, 6, NULL, NULL); //[121], would pass!!
}

static int
SCTP_GENEVE(void)
{
	return result_checker(FLOW_KEY_TYPE_SCTP|
			      FLOW_KEY_TYPE_GENEVE,
			      0, 2, 4, NULL, NULL); //[120], would pass!!
}

static int
PORT_IPV4_IPV6_TCP_UDP_GENEVE(void)
{
	return result_checker(FLOW_KEY_TYPE_PORT|
			      FLOW_KEY_TYPE_IPV4|FLOW_KEY_TYPE_IPV6|
			      FLOW_KEY_TYPE_TCP|FLOW_KEY_TYPE_UDP|
			      FLOW_KEY_TYPE_GENEVE,
			      1, 5, 42, NULL, NULL); //[11f], fail
}

static int
IPV4_IPV6_TCP_UDP_GENEVE(void)
{
	return result_checker(FLOW_KEY_TYPE_IPV4|
			      FLOW_KEY_TYPE_IPV6|FLOW_KEY_TYPE_TCP|
			      FLOW_KEY_TYPE_UDP|FLOW_KEY_TYPE_GENEVE,
			      0, 4, 36, NULL, NULL); //[11e], would pass!!
}

static int
PORT_IPV6_TCP_UDP_GENEVE(void)
{
	return result_checker(FLOW_KEY_TYPE_PORT|
			      FLOW_KEY_TYPE_IPV6|FLOW_KEY_TYPE_TCP|
			      FLOW_KEY_TYPE_UDP|FLOW_KEY_TYPE_GENEVE,
			      1, 5, 42, NULL, NULL); //[11d], fail
}

static int
IPV6_TCP_UDP_GENEVE(void)
{
	return result_checker(FLOW_KEY_TYPE_IPV6|
			      FLOW_KEY_TYPE_TCP|FLOW_KEY_TYPE_UDP|
			      FLOW_KEY_TYPE_GENEVE,
			      0, 3, 36, NULL, NULL); //[11c], would pass!!
}

static int
PORT_IPV4_TCP_UDP_GENEVE(void)
{
	return result_checker(FLOW_KEY_TYPE_PORT|
			      FLOW_KEY_TYPE_IPV4|FLOW_KEY_TYPE_TCP|
			      FLOW_KEY_TYPE_UDP|FLOW_KEY_TYPE_GENEVE,
			      0, 4, 14, NULL, NULL); //[11b], would pass!!
}

static int
IPV4_TCP_UDP_GENEVE(void)
{
	return result_checker(FLOW_KEY_TYPE_IPV4|
			      FLOW_KEY_TYPE_TCP|FLOW_KEY_TYPE_UDP|
			      FLOW_KEY_TYPE_GENEVE,
			      0, 3, 12, NULL, NULL); //[11a], would pass!!
}

static int
PORT_TCP_UDP_GENEVE(void)
{
	return result_checker(FLOW_KEY_TYPE_PORT|
			      FLOW_KEY_TYPE_TCP|FLOW_KEY_TYPE_UDP|
			      FLOW_KEY_TYPE_GENEVE,
			      0, 3, 6, NULL, NULL); //[119], would pass!!
}

static int
TCP_UDP_GENEVE(void)
{
	return result_checker(FLOW_KEY_TYPE_TCP|
			      FLOW_KEY_TYPE_UDP|FLOW_KEY_TYPE_GENEVE,
			      0, 2, 4, NULL, NULL); //[118], would pass!!
}

static int
PORT_IPV4_IPV6_UDP_GENEVE(void)
{
	return result_checker(FLOW_KEY_TYPE_PORT|
			      FLOW_KEY_TYPE_IPV4|FLOW_KEY_TYPE_IPV6|
			      FLOW_KEY_TYPE_UDP|FLOW_KEY_TYPE_GENEVE,
			      1, 5, 42, NULL, NULL); //[117], fail
}

static int
IPV4_IPV6_UDP_GENEVE(void)
{
	return result_checker(FLOW_KEY_TYPE_IPV4|
			      FLOW_KEY_TYPE_IPV6|FLOW_KEY_TYPE_UDP|
			      FLOW_KEY_TYPE_GENEVE,
			      0, 4, 36, NULL, NULL); //[116], would pass!!
}

static int
PORT_IPV6_UDP_GENEVE(void)
{
	return result_checker(FLOW_KEY_TYPE_PORT|
			      FLOW_KEY_TYPE_IPV6|FLOW_KEY_TYPE_UDP|
			      FLOW_KEY_TYPE_GENEVE,
			      1, 5, 42, NULL, NULL); //[115], fail
}

static int
IPV6_UDP_GENEVE(void)
{
	return result_checker(FLOW_KEY_TYPE_IPV6|
			      FLOW_KEY_TYPE_UDP|FLOW_KEY_TYPE_GENEVE,
			      0, 3, 36, NULL, NULL); //[114], would pass!!
}

static int
PORT_IPV4_UDP_GENEVE(void)
{
	return result_checker(FLOW_KEY_TYPE_PORT|
			      FLOW_KEY_TYPE_IPV4|FLOW_KEY_TYPE_UDP|
			      FLOW_KEY_TYPE_GENEVE,
			      0, 4, 14, NULL, NULL); //[113], would pass!!
}

static int
IPV4_UDP_GENEVE(void)
{
	return result_checker(FLOW_KEY_TYPE_IPV4|
			      FLOW_KEY_TYPE_UDP|FLOW_KEY_TYPE_GENEVE,
			      0, 3, 12, NULL, NULL); //[112], would pass!!
}

static int
PORT_UDP_GENEVE(void)
{
	return result_checker(FLOW_KEY_TYPE_PORT|
			      FLOW_KEY_TYPE_UDP|FLOW_KEY_TYPE_GENEVE,
			      0, 3, 6, NULL, NULL); //[111], would pass!!
}

static int
UDP_GENEVE(void)
{
	return result_checker(FLOW_KEY_TYPE_UDP|
			      FLOW_KEY_TYPE_GENEVE,
			      0, 2, 4, NULL, NULL); //[110], would pass!!
}

static int
PORT_IPV4_IPV6_TCP_GENEVE(void)
{
	return result_checker(FLOW_KEY_TYPE_PORT|
			      FLOW_KEY_TYPE_IPV4|FLOW_KEY_TYPE_IPV6|
			      FLOW_KEY_TYPE_TCP|FLOW_KEY_TYPE_GENEVE,
			      1, 5, 42, NULL, NULL); //[10f], fail
}

static int
IPV4_IPV6_TCP_GENEVE(void)
{
	return result_checker(FLOW_KEY_TYPE_IPV4|
			      FLOW_KEY_TYPE_IPV6|FLOW_KEY_TYPE_TCP|
			      FLOW_KEY_TYPE_GENEVE,
			      0, 4, 36, NULL, NULL); //[10e], would pass!!
}

static int
PORT_IPV6_TCP_GENEVE(void)
{
	return result_checker(FLOW_KEY_TYPE_PORT|
			      FLOW_KEY_TYPE_IPV6|FLOW_KEY_TYPE_TCP|
			      FLOW_KEY_TYPE_GENEVE,
			      1, 5, 42, NULL, NULL); //[10d], fail
}

static int
IPV6_TCP_GENEVE(void)
{
	return result_checker(FLOW_KEY_TYPE_IPV6|
			      FLOW_KEY_TYPE_TCP|FLOW_KEY_TYPE_GENEVE,
			      0, 3, 36, NULL, NULL); //[10c], would pass!!
}

static int
PORT_IPV4_TCP_GENEVE(void)
{
	return result_checker(FLOW_KEY_TYPE_PORT|
			      FLOW_KEY_TYPE_IPV4|FLOW_KEY_TYPE_TCP|
			      FLOW_KEY_TYPE_GENEVE,
			      0, 4, 14, NULL, NULL); //[10b], would pass!!
}

static int
IPV4_TCP_GENEVE(void)
{
	return result_checker(FLOW_KEY_TYPE_IPV4|
			      FLOW_KEY_TYPE_TCP|FLOW_KEY_TYPE_GENEVE,
			      0, 3, 12, NULL, NULL); //[10a], would pass!!
}

static int
PORT_TCP_GENEVE(void)
{
	return result_checker(FLOW_KEY_TYPE_PORT|
			      FLOW_KEY_TYPE_TCP|FLOW_KEY_TYPE_GENEVE,
			      0, 3, 6, NULL, NULL); //[109], would pass!!
}

static int
TCP_GENEVE(void)
{
	return result_checker(FLOW_KEY_TYPE_TCP|
			      FLOW_KEY_TYPE_GENEVE,
			      0, 2, 4, NULL, NULL); //[108], would pass!!
}

static int
PORT_IPV4_IPV6_GENEVE(void)
{
	return result_checker(FLOW_KEY_TYPE_PORT|
			      FLOW_KEY_TYPE_IPV4|FLOW_KEY_TYPE_IPV6|
			      FLOW_KEY_TYPE_GENEVE,
			      0, 4, 34, NULL, NULL); //[107], would pass!!
}

static int
IPV4_IPV6_GENEVE(void)
{
	return result_checker(FLOW_KEY_TYPE_IPV4|
			      FLOW_KEY_TYPE_IPV6|FLOW_KEY_TYPE_GENEVE,
			      0, 3, 32, NULL, NULL); //[106], would pass!!
}

static int
PORT_IPV6_GENEVE(void)
{
	return result_checker(FLOW_KEY_TYPE_PORT|
			      FLOW_KEY_TYPE_IPV6|FLOW_KEY_TYPE_GENEVE,
			      0, 3, 34, NULL, NULL); //[105], would pass!!
}

static int
IPV6_GENEVE(void)
{
	return result_checker(FLOW_KEY_TYPE_IPV6|
			      FLOW_KEY_TYPE_GENEVE,
			      0, 2, 32, NULL, NULL); //[104], would pass!!
}

static int
PORT_IPV4_GENEVE(void)
{
	return result_checker(FLOW_KEY_TYPE_PORT|
			      FLOW_KEY_TYPE_IPV4|FLOW_KEY_TYPE_GENEVE,
			      0, 3, 10, NULL, NULL); //[103], would pass!!
}

static int
IPV4_GENEVE(void)
{
	return result_checker(FLOW_KEY_TYPE_IPV4|
			      FLOW_KEY_TYPE_GENEVE,
			      0, 2, 8, NULL, NULL); //[102], would pass!!
}

static int
PORT_GENEVE(void)
{
	return result_checker(FLOW_KEY_TYPE_PORT|
			      FLOW_KEY_TYPE_GENEVE,
			      0, 2, 2, NULL, NULL); //[101], would pass!!
}

static int
GENEVE(void)
{
	return result_checker(FLOW_KEY_TYPE_GENEVE,
			      0, 1, 0, NULL, NULL); //[100], would pass!!
}

static int
PORT_IPV4_IPV6_TCP_UDP_SCTP_NVGRE_VXLAN(void)
{
	return result_checker(FLOW_KEY_TYPE_PORT|
			      FLOW_KEY_TYPE_IPV4|FLOW_KEY_TYPE_IPV6|
			      FLOW_KEY_TYPE_TCP|FLOW_KEY_TYPE_UDP|
			      FLOW_KEY_TYPE_SCTP|FLOW_KEY_TYPE_NVGRE|
			      FLOW_KEY_TYPE_VXLAN,
			      1, 5, 42, NULL, NULL); //[ff], fail
}

static int
IPV4_IPV6_TCP_UDP_SCTP_NVGRE_VXLAN(void)
{
	return result_checker(FLOW_KEY_TYPE_IPV4|
			      FLOW_KEY_TYPE_IPV6|FLOW_KEY_TYPE_TCP|
			      FLOW_KEY_TYPE_UDP|FLOW_KEY_TYPE_SCTP|
			      FLOW_KEY_TYPE_NVGRE|FLOW_KEY_TYPE_VXLAN,
			      1, 5, 42, NULL, NULL); //[fe], fail
}

static int
PORT_IPV6_TCP_UDP_SCTP_NVGRE_VXLAN(void)
{
	return result_checker(FLOW_KEY_TYPE_PORT|
			      FLOW_KEY_TYPE_IPV6|FLOW_KEY_TYPE_TCP|
			      FLOW_KEY_TYPE_UDP|FLOW_KEY_TYPE_SCTP|
			      FLOW_KEY_TYPE_NVGRE|FLOW_KEY_TYPE_VXLAN,
			      1, 5, 42, NULL, NULL); //[fd], fail
}

static int
IPV6_TCP_UDP_SCTP_NVGRE_VXLAN(void)
{
	return result_checker(FLOW_KEY_TYPE_IPV6|
			      FLOW_KEY_TYPE_TCP|FLOW_KEY_TYPE_UDP|
			      FLOW_KEY_TYPE_SCTP|FLOW_KEY_TYPE_NVGRE|
			      FLOW_KEY_TYPE_VXLAN,
			      1, 5, 42, NULL, NULL); //[fc], fail
}

static int
PORT_IPV4_TCP_UDP_SCTP_NVGRE_VXLAN(void)
{
	return result_checker(FLOW_KEY_TYPE_PORT|
			      FLOW_KEY_TYPE_IPV4|FLOW_KEY_TYPE_TCP|
			      FLOW_KEY_TYPE_UDP|FLOW_KEY_TYPE_SCTP|
			      FLOW_KEY_TYPE_NVGRE|FLOW_KEY_TYPE_VXLAN,
			      0, 5, 17, NULL, NULL); //[fb], would pass!!
}

static int
IPV4_TCP_UDP_SCTP_NVGRE_VXLAN(void)
{
	return result_checker(FLOW_KEY_TYPE_IPV4|
			      FLOW_KEY_TYPE_TCP|FLOW_KEY_TYPE_UDP|
			      FLOW_KEY_TYPE_SCTP|FLOW_KEY_TYPE_NVGRE|
			      FLOW_KEY_TYPE_VXLAN,
			      0, 4, 15, NULL, NULL); //[fa], would pass!!
}

static int
PORT_TCP_UDP_SCTP_NVGRE_VXLAN(void)
{
	return result_checker(FLOW_KEY_TYPE_PORT|
			      FLOW_KEY_TYPE_TCP|FLOW_KEY_TYPE_UDP|
			      FLOW_KEY_TYPE_SCTP|FLOW_KEY_TYPE_NVGRE|
			      FLOW_KEY_TYPE_VXLAN,
			      0, 4, 9, NULL, NULL); //[f9], would pass!!
}

static int
TCP_UDP_SCTP_NVGRE_VXLAN(void)
{
	return result_checker(FLOW_KEY_TYPE_TCP|
			      FLOW_KEY_TYPE_UDP|FLOW_KEY_TYPE_SCTP|
			      FLOW_KEY_TYPE_NVGRE|FLOW_KEY_TYPE_VXLAN,
			      0, 3, 7, NULL, NULL); //[f8], would pass!!
}

static int
PORT_IPV4_IPV6_UDP_SCTP_NVGRE_VXLAN(void)
{
	return result_checker(FLOW_KEY_TYPE_PORT|
			      FLOW_KEY_TYPE_IPV4|FLOW_KEY_TYPE_IPV6|
			      FLOW_KEY_TYPE_UDP|FLOW_KEY_TYPE_SCTP|
			      FLOW_KEY_TYPE_NVGRE|FLOW_KEY_TYPE_VXLAN,
			      1, 5, 42, NULL, NULL); //[f7], fail
}

static int
IPV4_IPV6_UDP_SCTP_NVGRE_VXLAN(void)
{
	return result_checker(FLOW_KEY_TYPE_IPV4|
			      FLOW_KEY_TYPE_IPV6|FLOW_KEY_TYPE_UDP|
			      FLOW_KEY_TYPE_SCTP|FLOW_KEY_TYPE_NVGRE|
			      FLOW_KEY_TYPE_VXLAN,
			      1, 5, 42, NULL, NULL); //[f6], fail
}

static int
PORT_IPV6_UDP_SCTP_NVGRE_VXLAN(void)
{
	return result_checker(FLOW_KEY_TYPE_PORT|
			      FLOW_KEY_TYPE_IPV6|FLOW_KEY_TYPE_UDP|
			      FLOW_KEY_TYPE_SCTP|FLOW_KEY_TYPE_NVGRE|
			      FLOW_KEY_TYPE_VXLAN,
			      1, 5, 42, NULL, NULL); //[f5], fail
}

static int
IPV6_UDP_SCTP_NVGRE_VXLAN(void)
{
	return result_checker(FLOW_KEY_TYPE_IPV6|
			      FLOW_KEY_TYPE_UDP|FLOW_KEY_TYPE_SCTP|
			      FLOW_KEY_TYPE_NVGRE|FLOW_KEY_TYPE_VXLAN,
			      1, 5, 42, NULL, NULL); //[f4], fail
}

static int
PORT_IPV4_UDP_SCTP_NVGRE_VXLAN(void)
{
	return result_checker(FLOW_KEY_TYPE_PORT|
			      FLOW_KEY_TYPE_IPV4|FLOW_KEY_TYPE_UDP|
			      FLOW_KEY_TYPE_SCTP|FLOW_KEY_TYPE_NVGRE|
			      FLOW_KEY_TYPE_VXLAN,
			      0, 5, 17, NULL, NULL); //[f3], would pass!!
}

static int
IPV4_UDP_SCTP_NVGRE_VXLAN(void)
{
	return result_checker(FLOW_KEY_TYPE_IPV4|
			      FLOW_KEY_TYPE_UDP|FLOW_KEY_TYPE_SCTP|
			      FLOW_KEY_TYPE_NVGRE|FLOW_KEY_TYPE_VXLAN,
			      0, 4, 15, NULL, NULL); //[f2], would pass!!
}

static int
PORT_UDP_SCTP_NVGRE_VXLAN(void)
{
	return result_checker(FLOW_KEY_TYPE_PORT|
			      FLOW_KEY_TYPE_UDP|FLOW_KEY_TYPE_SCTP|
			      FLOW_KEY_TYPE_NVGRE|FLOW_KEY_TYPE_VXLAN,
			      0, 4, 9, NULL, NULL); //[f1], would pass!!
}

static int
UDP_SCTP_NVGRE_VXLAN(void)
{
	return result_checker(FLOW_KEY_TYPE_UDP|
			      FLOW_KEY_TYPE_SCTP|FLOW_KEY_TYPE_NVGRE|
			      FLOW_KEY_TYPE_VXLAN,
			      0, 3, 7, NULL, NULL); //[f0], would pass!!
}

static int
PORT_IPV4_IPV6_TCP_SCTP_NVGRE_VXLAN(void)
{
	return result_checker(FLOW_KEY_TYPE_PORT|
			      FLOW_KEY_TYPE_IPV4|FLOW_KEY_TYPE_IPV6|
			      FLOW_KEY_TYPE_TCP|FLOW_KEY_TYPE_SCTP|
			      FLOW_KEY_TYPE_NVGRE|FLOW_KEY_TYPE_VXLAN,
			      1, 5, 42, NULL, NULL); //[ef], fail
}

static int
IPV4_IPV6_TCP_SCTP_NVGRE_VXLAN(void)
{
	return result_checker(FLOW_KEY_TYPE_IPV4|
			      FLOW_KEY_TYPE_IPV6|FLOW_KEY_TYPE_TCP|
			      FLOW_KEY_TYPE_SCTP|FLOW_KEY_TYPE_NVGRE|
			      FLOW_KEY_TYPE_VXLAN,
			      1, 5, 42, NULL, NULL); //[ee], fail
}

static int
PORT_IPV6_TCP_SCTP_NVGRE_VXLAN(void)
{
	return result_checker(FLOW_KEY_TYPE_PORT|
			      FLOW_KEY_TYPE_IPV6|FLOW_KEY_TYPE_TCP|
			      FLOW_KEY_TYPE_SCTP|FLOW_KEY_TYPE_NVGRE|
			      FLOW_KEY_TYPE_VXLAN,
			      1, 5, 42, NULL, NULL); //[ed], fail
}

static int
IPV6_TCP_SCTP_NVGRE_VXLAN(void)
{
	return result_checker(FLOW_KEY_TYPE_IPV6|
			      FLOW_KEY_TYPE_TCP|FLOW_KEY_TYPE_SCTP|
			      FLOW_KEY_TYPE_NVGRE|FLOW_KEY_TYPE_VXLAN,
			      1, 5, 42, NULL, NULL); //[ec], fail
}

static int
PORT_IPV4_TCP_SCTP_NVGRE_VXLAN(void)
{
	return result_checker(FLOW_KEY_TYPE_PORT|
			      FLOW_KEY_TYPE_IPV4|FLOW_KEY_TYPE_TCP|
			      FLOW_KEY_TYPE_SCTP|FLOW_KEY_TYPE_NVGRE|
			      FLOW_KEY_TYPE_VXLAN,
			      0, 5, 17, NULL, NULL); //[eb], would pass!!
}

static int
IPV4_TCP_SCTP_NVGRE_VXLAN(void)
{
	return result_checker(FLOW_KEY_TYPE_IPV4|
			      FLOW_KEY_TYPE_TCP|FLOW_KEY_TYPE_SCTP|
			      FLOW_KEY_TYPE_NVGRE|FLOW_KEY_TYPE_VXLAN,
			      0, 4, 15, NULL, NULL); //[ea], would pass!!
}

static int
PORT_TCP_SCTP_NVGRE_VXLAN(void)
{
	return result_checker(FLOW_KEY_TYPE_PORT|
			      FLOW_KEY_TYPE_TCP|FLOW_KEY_TYPE_SCTP|
			      FLOW_KEY_TYPE_NVGRE|FLOW_KEY_TYPE_VXLAN,
			      0, 4, 9, NULL, NULL); //[e9], would pass!!
}

static int
TCP_SCTP_NVGRE_VXLAN(void)
{
	return result_checker(FLOW_KEY_TYPE_TCP|
			      FLOW_KEY_TYPE_SCTP|FLOW_KEY_TYPE_NVGRE|
			      FLOW_KEY_TYPE_VXLAN,
			      0, 3, 7, NULL, NULL); //[e8], would pass!!
}

static int
PORT_IPV4_IPV6_SCTP_NVGRE_VXLAN(void)
{
	return result_checker(FLOW_KEY_TYPE_PORT|
			      FLOW_KEY_TYPE_IPV4|FLOW_KEY_TYPE_IPV6|
			      FLOW_KEY_TYPE_SCTP|FLOW_KEY_TYPE_NVGRE|
			      FLOW_KEY_TYPE_VXLAN,
			      1, 5, 42, NULL, NULL); //[e7], fail
}

static int
IPV4_IPV6_SCTP_NVGRE_VXLAN(void)
{
	return result_checker(FLOW_KEY_TYPE_IPV4|
			      FLOW_KEY_TYPE_IPV6|FLOW_KEY_TYPE_SCTP|
			      FLOW_KEY_TYPE_NVGRE|FLOW_KEY_TYPE_VXLAN,
			      1, 5, 42, NULL, NULL); //[e6], fail
}

static int
PORT_IPV6_SCTP_NVGRE_VXLAN(void)
{
	return result_checker(FLOW_KEY_TYPE_PORT|
			      FLOW_KEY_TYPE_IPV6|FLOW_KEY_TYPE_SCTP|
			      FLOW_KEY_TYPE_NVGRE|FLOW_KEY_TYPE_VXLAN,
			      1, 5, 42, NULL, NULL); //[e5], fail
}

static int
IPV6_SCTP_NVGRE_VXLAN(void)
{
	return result_checker(FLOW_KEY_TYPE_IPV6|
			      FLOW_KEY_TYPE_SCTP|FLOW_KEY_TYPE_NVGRE|
			      FLOW_KEY_TYPE_VXLAN,
			      1, 5, 42, NULL, NULL); //[e4], fail
}

static int
PORT_IPV4_SCTP_NVGRE_VXLAN(void)
{
	return result_checker(FLOW_KEY_TYPE_PORT|
			      FLOW_KEY_TYPE_IPV4|FLOW_KEY_TYPE_SCTP|
			      FLOW_KEY_TYPE_NVGRE|FLOW_KEY_TYPE_VXLAN,
			      0, 5, 17, NULL, NULL); //[e3], would pass!!
}

static int
IPV4_SCTP_NVGRE_VXLAN(void)
{
	return result_checker(FLOW_KEY_TYPE_IPV4|
			      FLOW_KEY_TYPE_SCTP|FLOW_KEY_TYPE_NVGRE|
			      FLOW_KEY_TYPE_VXLAN,
			      0, 4, 15, NULL, NULL); //[e2], would pass!!
}

static int
PORT_SCTP_NVGRE_VXLAN(void)
{
	return result_checker(FLOW_KEY_TYPE_PORT|
			      FLOW_KEY_TYPE_SCTP|FLOW_KEY_TYPE_NVGRE|
			      FLOW_KEY_TYPE_VXLAN,
			      0, 4, 9, NULL, NULL); //[e1], would pass!!
}

static int
SCTP_NVGRE_VXLAN(void)
{
	return result_checker(FLOW_KEY_TYPE_SCTP|
			      FLOW_KEY_TYPE_NVGRE|FLOW_KEY_TYPE_VXLAN,
			      0, 3, 7, NULL, NULL); //[e0], would pass!!
}

static int
PORT_IPV4_IPV6_TCP_UDP_NVGRE_VXLAN(void)
{
	return result_checker(FLOW_KEY_TYPE_PORT|
			      FLOW_KEY_TYPE_IPV4|FLOW_KEY_TYPE_IPV6|
			      FLOW_KEY_TYPE_TCP|FLOW_KEY_TYPE_UDP|
			      FLOW_KEY_TYPE_NVGRE|FLOW_KEY_TYPE_VXLAN,
			      1, 5, 42, NULL, NULL); //[df], fail
}

static int
IPV4_IPV6_TCP_UDP_NVGRE_VXLAN(void)
{
	return result_checker(FLOW_KEY_TYPE_IPV4|
			      FLOW_KEY_TYPE_IPV6|FLOW_KEY_TYPE_TCP|
			      FLOW_KEY_TYPE_UDP|FLOW_KEY_TYPE_NVGRE|
			      FLOW_KEY_TYPE_VXLAN,
			      1, 5, 42, NULL, NULL); //[de], fail
}

static int
PORT_IPV6_TCP_UDP_NVGRE_VXLAN(void)
{
	return result_checker(FLOW_KEY_TYPE_PORT|
			      FLOW_KEY_TYPE_IPV6|FLOW_KEY_TYPE_TCP|
			      FLOW_KEY_TYPE_UDP|FLOW_KEY_TYPE_NVGRE|
			      FLOW_KEY_TYPE_VXLAN,
			      1, 5, 42, NULL, NULL); //[dd], fail
}

static int
IPV6_TCP_UDP_NVGRE_VXLAN(void)
{
	return result_checker(FLOW_KEY_TYPE_IPV6|
			      FLOW_KEY_TYPE_TCP|FLOW_KEY_TYPE_UDP|
			      FLOW_KEY_TYPE_NVGRE|FLOW_KEY_TYPE_VXLAN,
			      1, 5, 42, NULL, NULL); //[dc], fail
}

static int
PORT_IPV4_TCP_UDP_NVGRE_VXLAN(void)
{
	return result_checker(FLOW_KEY_TYPE_PORT|
			      FLOW_KEY_TYPE_IPV4|FLOW_KEY_TYPE_TCP|
			      FLOW_KEY_TYPE_UDP|FLOW_KEY_TYPE_NVGRE|
			      FLOW_KEY_TYPE_VXLAN,
			      0, 5, 17, NULL, NULL); //[db], would pass!!
}

static int
IPV4_TCP_UDP_NVGRE_VXLAN(void)
{
	return result_checker(FLOW_KEY_TYPE_IPV4|
			      FLOW_KEY_TYPE_TCP|FLOW_KEY_TYPE_UDP|
			      FLOW_KEY_TYPE_NVGRE|FLOW_KEY_TYPE_VXLAN,
			      0, 4, 15, NULL, NULL); //[da], would pass!!
}

static int
PORT_TCP_UDP_NVGRE_VXLAN(void)
{
	return result_checker(FLOW_KEY_TYPE_PORT|
			      FLOW_KEY_TYPE_TCP|FLOW_KEY_TYPE_UDP|
			      FLOW_KEY_TYPE_NVGRE|FLOW_KEY_TYPE_VXLAN,
			      0, 4, 9, NULL, NULL); //[d9], would pass!!
}

static int
TCP_UDP_NVGRE_VXLAN(void)
{
	return result_checker(FLOW_KEY_TYPE_TCP|
			      FLOW_KEY_TYPE_UDP|FLOW_KEY_TYPE_NVGRE|
			      FLOW_KEY_TYPE_VXLAN,
			      0, 3, 7, NULL, NULL); //[d8], would pass!!
}

static int
PORT_IPV4_IPV6_UDP_NVGRE_VXLAN(void)
{
	return result_checker(FLOW_KEY_TYPE_PORT|
			      FLOW_KEY_TYPE_IPV4|FLOW_KEY_TYPE_IPV6|
			      FLOW_KEY_TYPE_UDP|FLOW_KEY_TYPE_NVGRE|
			      FLOW_KEY_TYPE_VXLAN,
			      1, 5, 42, NULL, NULL); //[d7], fail
}

static int
IPV4_IPV6_UDP_NVGRE_VXLAN(void)
{
	return result_checker(FLOW_KEY_TYPE_IPV4|
			      FLOW_KEY_TYPE_IPV6|FLOW_KEY_TYPE_UDP|
			      FLOW_KEY_TYPE_NVGRE|FLOW_KEY_TYPE_VXLAN,
			      1, 5, 42, NULL, NULL); //[d6], fail
}

static int
PORT_IPV6_UDP_NVGRE_VXLAN(void)
{
	return result_checker(FLOW_KEY_TYPE_PORT|
			      FLOW_KEY_TYPE_IPV6|FLOW_KEY_TYPE_UDP|
			      FLOW_KEY_TYPE_NVGRE|FLOW_KEY_TYPE_VXLAN,
			      1, 5, 42, NULL, NULL); //[d5], fail
}

static int
IPV6_UDP_NVGRE_VXLAN(void)
{
	return result_checker(FLOW_KEY_TYPE_IPV6|
			      FLOW_KEY_TYPE_UDP|FLOW_KEY_TYPE_NVGRE|
			      FLOW_KEY_TYPE_VXLAN,
			      1, 5, 42, NULL, NULL); //[d4], fail
}

static int
PORT_IPV4_UDP_NVGRE_VXLAN(void)
{
	return result_checker(FLOW_KEY_TYPE_PORT|
			      FLOW_KEY_TYPE_IPV4|FLOW_KEY_TYPE_UDP|
			      FLOW_KEY_TYPE_NVGRE|FLOW_KEY_TYPE_VXLAN,
			      0, 5, 17, NULL, NULL); //[d3], would pass!!
}

static int
IPV4_UDP_NVGRE_VXLAN(void)
{
	return result_checker(FLOW_KEY_TYPE_IPV4|
			      FLOW_KEY_TYPE_UDP|FLOW_KEY_TYPE_NVGRE|
			      FLOW_KEY_TYPE_VXLAN,
			      0, 4, 15, NULL, NULL); //[d2], would pass!!
}

static int
PORT_UDP_NVGRE_VXLAN(void)
{
	return result_checker(FLOW_KEY_TYPE_PORT|
			      FLOW_KEY_TYPE_UDP|FLOW_KEY_TYPE_NVGRE|
			      FLOW_KEY_TYPE_VXLAN,
			      0, 4, 9, NULL, NULL); //[d1], would pass!!
}

static int
UDP_NVGRE_VXLAN(void)
{
	return result_checker(FLOW_KEY_TYPE_UDP|
			      FLOW_KEY_TYPE_NVGRE|FLOW_KEY_TYPE_VXLAN,
			      0, 3, 7, NULL, NULL); //[d0], would pass!!
}

static int
PORT_IPV4_IPV6_TCP_NVGRE_VXLAN(void)
{
	return result_checker(FLOW_KEY_TYPE_PORT|
			      FLOW_KEY_TYPE_IPV4|FLOW_KEY_TYPE_IPV6|
			      FLOW_KEY_TYPE_TCP|FLOW_KEY_TYPE_NVGRE|
			      FLOW_KEY_TYPE_VXLAN,
			      1, 5, 42, NULL, NULL); //[cf], fail
}

static int
IPV4_IPV6_TCP_NVGRE_VXLAN(void)
{
	return result_checker(FLOW_KEY_TYPE_IPV4|
			      FLOW_KEY_TYPE_IPV6|FLOW_KEY_TYPE_TCP|
			      FLOW_KEY_TYPE_NVGRE|FLOW_KEY_TYPE_VXLAN,
			      1, 5, 42, NULL, NULL); //[ce], fail
}

static int
PORT_IPV6_TCP_NVGRE_VXLAN(void)
{
	return result_checker(FLOW_KEY_TYPE_PORT|
			      FLOW_KEY_TYPE_IPV6|FLOW_KEY_TYPE_TCP|
			      FLOW_KEY_TYPE_NVGRE|FLOW_KEY_TYPE_VXLAN,
			      1, 5, 42, NULL, NULL); //[cd], fail
}

static int
IPV6_TCP_NVGRE_VXLAN(void)
{
	return result_checker(FLOW_KEY_TYPE_IPV6|
			      FLOW_KEY_TYPE_TCP|FLOW_KEY_TYPE_NVGRE|
			      FLOW_KEY_TYPE_VXLAN,
			      1, 5, 42, NULL, NULL); //[cc], fail
}

static int
PORT_IPV4_TCP_NVGRE_VXLAN(void)
{
	return result_checker(FLOW_KEY_TYPE_PORT|
			      FLOW_KEY_TYPE_IPV4|FLOW_KEY_TYPE_TCP|
			      FLOW_KEY_TYPE_NVGRE|FLOW_KEY_TYPE_VXLAN,
			      0, 5, 17, NULL, NULL); //[cb], would pass!!
}

static int
IPV4_TCP_NVGRE_VXLAN(void)
{
	return result_checker(FLOW_KEY_TYPE_IPV4|
			      FLOW_KEY_TYPE_TCP|FLOW_KEY_TYPE_NVGRE|
			      FLOW_KEY_TYPE_VXLAN,
			      0, 4, 15, NULL, NULL); //[ca], would pass!!
}

static int
PORT_TCP_NVGRE_VXLAN(void)
{
	return result_checker(FLOW_KEY_TYPE_PORT|
			      FLOW_KEY_TYPE_TCP|FLOW_KEY_TYPE_NVGRE|
			      FLOW_KEY_TYPE_VXLAN,
			      0, 4, 9, NULL, NULL); //[c9], would pass!!
}

static int
TCP_NVGRE_VXLAN(void)
{
	return result_checker(FLOW_KEY_TYPE_TCP|
			      FLOW_KEY_TYPE_NVGRE|FLOW_KEY_TYPE_VXLAN,
			      0, 3, 7, NULL, NULL); //[c8], would pass!!
}

static int
PORT_IPV4_IPV6_NVGRE_VXLAN(void)
{
	return result_checker(FLOW_KEY_TYPE_PORT|
			      FLOW_KEY_TYPE_IPV4|FLOW_KEY_TYPE_IPV6|
			      FLOW_KEY_TYPE_NVGRE|FLOW_KEY_TYPE_VXLAN,
			      1, 5, 42, NULL, NULL); //[c7], fail
}

static int
IPV4_IPV6_NVGRE_VXLAN(void)
{
	return result_checker(FLOW_KEY_TYPE_IPV4|
			      FLOW_KEY_TYPE_IPV6|FLOW_KEY_TYPE_NVGRE|
			      FLOW_KEY_TYPE_VXLAN,
			      0, 4, 35, NULL, NULL); //[c6], would pass!!
}

static int
PORT_IPV6_NVGRE_VXLAN(void)
{
	return result_checker(FLOW_KEY_TYPE_PORT|
			      FLOW_KEY_TYPE_IPV6|FLOW_KEY_TYPE_NVGRE|
			      FLOW_KEY_TYPE_VXLAN,
			      1, 5, 42, NULL, NULL); //[c5], fail
}

static int
IPV6_NVGRE_VXLAN(void)
{
	return result_checker(FLOW_KEY_TYPE_IPV6|
			      FLOW_KEY_TYPE_NVGRE|FLOW_KEY_TYPE_VXLAN,
			      0, 3, 35, NULL, NULL); //[c4], would pass!!
}

static int
PORT_IPV4_NVGRE_VXLAN(void)
{
	return result_checker(FLOW_KEY_TYPE_PORT|
			      FLOW_KEY_TYPE_IPV4|FLOW_KEY_TYPE_NVGRE|
			      FLOW_KEY_TYPE_VXLAN,
			      0, 4, 13, NULL, NULL); //[c3], would pass!!
}

static int
IPV4_NVGRE_VXLAN(void)
{
	return result_checker(FLOW_KEY_TYPE_IPV4|
			      FLOW_KEY_TYPE_NVGRE|FLOW_KEY_TYPE_VXLAN,
			      0, 3, 11, NULL, NULL); //[c2], would pass!!
}

static int
PORT_NVGRE_VXLAN(void)
{
	return result_checker(FLOW_KEY_TYPE_PORT|
			      FLOW_KEY_TYPE_NVGRE|FLOW_KEY_TYPE_VXLAN,
			      0, 3, 5, NULL, NULL); //[c1], would pass!!
}

static int
NVGRE_VXLAN(void)
{
	return result_checker(FLOW_KEY_TYPE_NVGRE|
			      FLOW_KEY_TYPE_VXLAN,
			      0, 2, 3, NULL, NULL); //[c0], would pass!!
}

static int
PORT_IPV4_IPV6_TCP_UDP_SCTP_VXLAN(void)
{
	return result_checker(FLOW_KEY_TYPE_PORT|
			      FLOW_KEY_TYPE_IPV4|FLOW_KEY_TYPE_IPV6|
			      FLOW_KEY_TYPE_TCP|FLOW_KEY_TYPE_UDP|
			      FLOW_KEY_TYPE_SCTP|FLOW_KEY_TYPE_VXLAN,
			      1, 5, 42, NULL, NULL); //[bf], fail
}

static int
IPV4_IPV6_TCP_UDP_SCTP_VXLAN(void)
{
	return result_checker(FLOW_KEY_TYPE_IPV4|
			      FLOW_KEY_TYPE_IPV6|FLOW_KEY_TYPE_TCP|
			      FLOW_KEY_TYPE_UDP|FLOW_KEY_TYPE_SCTP|
			      FLOW_KEY_TYPE_VXLAN,
			      0, 4, 36, NULL, NULL); //[be], would pass!!
}

static int
PORT_IPV6_TCP_UDP_SCTP_VXLAN(void)
{
	return result_checker(FLOW_KEY_TYPE_PORT|
			      FLOW_KEY_TYPE_IPV6|FLOW_KEY_TYPE_TCP|
			      FLOW_KEY_TYPE_UDP|FLOW_KEY_TYPE_SCTP|
			      FLOW_KEY_TYPE_VXLAN,
			      1, 5, 42, NULL, NULL); //[bd], fail
}

static int
IPV6_TCP_UDP_SCTP_VXLAN(void)
{
	return result_checker(FLOW_KEY_TYPE_IPV6|
			      FLOW_KEY_TYPE_TCP|FLOW_KEY_TYPE_UDP|
			      FLOW_KEY_TYPE_SCTP|FLOW_KEY_TYPE_VXLAN,
			      0, 3, 36, NULL, NULL); //[bc], would pass!!
}

static int
PORT_IPV4_TCP_UDP_SCTP_VXLAN(void)
{
	return result_checker(FLOW_KEY_TYPE_PORT|
			      FLOW_KEY_TYPE_IPV4|FLOW_KEY_TYPE_TCP|
			      FLOW_KEY_TYPE_UDP|FLOW_KEY_TYPE_SCTP|
			      FLOW_KEY_TYPE_VXLAN,
			      0, 4, 14, NULL, NULL); //[bb], would pass!!
}

static int
IPV4_TCP_UDP_SCTP_VXLAN(void)
{
	return result_checker(FLOW_KEY_TYPE_IPV4|
			      FLOW_KEY_TYPE_TCP|FLOW_KEY_TYPE_UDP|
			      FLOW_KEY_TYPE_SCTP|FLOW_KEY_TYPE_VXLAN,
			      0, 3, 12, NULL, NULL); //[ba], would pass!!
}

static int
PORT_TCP_UDP_SCTP_VXLAN(void)
{
	return result_checker(FLOW_KEY_TYPE_PORT|
			      FLOW_KEY_TYPE_TCP|FLOW_KEY_TYPE_UDP|
			      FLOW_KEY_TYPE_SCTP|FLOW_KEY_TYPE_VXLAN,
			      0, 3, 6, NULL, NULL); //[b9], would pass!!
}

static int
TCP_UDP_SCTP_VXLAN(void)
{
	return result_checker(FLOW_KEY_TYPE_TCP|
			      FLOW_KEY_TYPE_UDP|FLOW_KEY_TYPE_SCTP|
			      FLOW_KEY_TYPE_VXLAN,
			      0, 2, 4, NULL, NULL); //[b8], would pass!!
}

static int
PORT_IPV4_IPV6_UDP_SCTP_VXLAN(void)
{
	return result_checker(FLOW_KEY_TYPE_PORT|
			      FLOW_KEY_TYPE_IPV4|FLOW_KEY_TYPE_IPV6|
			      FLOW_KEY_TYPE_UDP|FLOW_KEY_TYPE_SCTP|
			      FLOW_KEY_TYPE_VXLAN,
			      1, 5, 42, NULL, NULL); //[b7], fail
}

static int
IPV4_IPV6_UDP_SCTP_VXLAN(void)
{
	return result_checker(FLOW_KEY_TYPE_IPV4|
			      FLOW_KEY_TYPE_IPV6|FLOW_KEY_TYPE_UDP|
			      FLOW_KEY_TYPE_SCTP|FLOW_KEY_TYPE_VXLAN,
			      0, 4, 36, NULL, NULL); //[b6], would pass!!
}

static int
PORT_IPV6_UDP_SCTP_VXLAN(void)
{
	return result_checker(FLOW_KEY_TYPE_PORT|
			      FLOW_KEY_TYPE_IPV6|FLOW_KEY_TYPE_UDP|
			      FLOW_KEY_TYPE_SCTP|FLOW_KEY_TYPE_VXLAN,
			      1, 5, 42, NULL, NULL); //[b5], fail
}

static int
IPV6_UDP_SCTP_VXLAN(void)
{
	return result_checker(FLOW_KEY_TYPE_IPV6|
			      FLOW_KEY_TYPE_UDP|FLOW_KEY_TYPE_SCTP|
			      FLOW_KEY_TYPE_VXLAN,
			      0, 3, 36, NULL, NULL); //[b4], would pass!!
}

static int
PORT_IPV4_UDP_SCTP_VXLAN(void)
{
	return result_checker(FLOW_KEY_TYPE_PORT|
			      FLOW_KEY_TYPE_IPV4|FLOW_KEY_TYPE_UDP|
			      FLOW_KEY_TYPE_SCTP|FLOW_KEY_TYPE_VXLAN,
			      0, 4, 14, NULL, NULL); //[b3], would pass!!
}

static int
IPV4_UDP_SCTP_VXLAN(void)
{
	return result_checker(FLOW_KEY_TYPE_IPV4|
			      FLOW_KEY_TYPE_UDP|FLOW_KEY_TYPE_SCTP|
			      FLOW_KEY_TYPE_VXLAN,
			      0, 3, 12, NULL, NULL); //[b2], would pass!!
}

static int
PORT_UDP_SCTP_VXLAN(void)
{
	return result_checker(FLOW_KEY_TYPE_PORT|
			      FLOW_KEY_TYPE_UDP|FLOW_KEY_TYPE_SCTP|
			      FLOW_KEY_TYPE_VXLAN,
			      0, 3, 6, NULL, NULL); //[b1], would pass!!
}

static int
UDP_SCTP_VXLAN(void)
{
	return result_checker(FLOW_KEY_TYPE_UDP|
			      FLOW_KEY_TYPE_SCTP|FLOW_KEY_TYPE_VXLAN,
			      0, 2, 4, NULL, NULL); //[b0], would pass!!
}

static int
PORT_IPV4_IPV6_TCP_SCTP_VXLAN(void)
{
	return result_checker(FLOW_KEY_TYPE_PORT|
			      FLOW_KEY_TYPE_IPV4|FLOW_KEY_TYPE_IPV6|
			      FLOW_KEY_TYPE_TCP|FLOW_KEY_TYPE_SCTP|
			      FLOW_KEY_TYPE_VXLAN,
			      1, 5, 42, NULL, NULL); //[af], fail
}

static int
IPV4_IPV6_TCP_SCTP_VXLAN(void)
{
	return result_checker(FLOW_KEY_TYPE_IPV4|
			      FLOW_KEY_TYPE_IPV6|FLOW_KEY_TYPE_TCP|
			      FLOW_KEY_TYPE_SCTP|FLOW_KEY_TYPE_VXLAN,
			      0, 4, 36, NULL, NULL); //[ae], would pass!!
}

static int
PORT_IPV6_TCP_SCTP_VXLAN(void)
{
	return result_checker(FLOW_KEY_TYPE_PORT|
			      FLOW_KEY_TYPE_IPV6|FLOW_KEY_TYPE_TCP|
			      FLOW_KEY_TYPE_SCTP|FLOW_KEY_TYPE_VXLAN,
			      1, 5, 42, NULL, NULL); //[ad], fail
}

static int
IPV6_TCP_SCTP_VXLAN(void)
{
	return result_checker(FLOW_KEY_TYPE_IPV6|
			      FLOW_KEY_TYPE_TCP|FLOW_KEY_TYPE_SCTP|
			      FLOW_KEY_TYPE_VXLAN,
			      0, 3, 36, NULL, NULL); //[ac], would pass!!
}

static int
PORT_IPV4_TCP_SCTP_VXLAN(void)
{
	return result_checker(FLOW_KEY_TYPE_PORT|
			      FLOW_KEY_TYPE_IPV4|FLOW_KEY_TYPE_TCP|
			      FLOW_KEY_TYPE_SCTP|FLOW_KEY_TYPE_VXLAN,
			      0, 4, 14, NULL, NULL); //[ab], would pass!!
}

static int
IPV4_TCP_SCTP_VXLAN(void)
{
	return result_checker(FLOW_KEY_TYPE_IPV4|
			      FLOW_KEY_TYPE_TCP|FLOW_KEY_TYPE_SCTP|
			      FLOW_KEY_TYPE_VXLAN,
			      0, 3, 12, NULL, NULL); //[aa], would pass!!
}

static int
PORT_TCP_SCTP_VXLAN(void)
{
	return result_checker(FLOW_KEY_TYPE_PORT|
			      FLOW_KEY_TYPE_TCP|FLOW_KEY_TYPE_SCTP|
			      FLOW_KEY_TYPE_VXLAN,
			      0, 3, 6, NULL, NULL); //[a9], would pass!!
}

static int
TCP_SCTP_VXLAN(void)
{
	return result_checker(FLOW_KEY_TYPE_TCP|
			      FLOW_KEY_TYPE_SCTP|FLOW_KEY_TYPE_VXLAN,
			      0, 2, 4, NULL, NULL); //[a8], would pass!!
}

static int
PORT_IPV4_IPV6_SCTP_VXLAN(void)
{
	return result_checker(FLOW_KEY_TYPE_PORT|
			      FLOW_KEY_TYPE_IPV4|FLOW_KEY_TYPE_IPV6|
			      FLOW_KEY_TYPE_SCTP|FLOW_KEY_TYPE_VXLAN,
			      1, 5, 42, NULL, NULL); //[a7], fail
}

static int
IPV4_IPV6_SCTP_VXLAN(void)
{
	return result_checker(FLOW_KEY_TYPE_IPV4|
			      FLOW_KEY_TYPE_IPV6|FLOW_KEY_TYPE_SCTP|
			      FLOW_KEY_TYPE_VXLAN,
			      0, 4, 36, NULL, NULL); //[a6], would pass!!
}

static int
PORT_IPV6_SCTP_VXLAN(void)
{
	return result_checker(FLOW_KEY_TYPE_PORT|
			      FLOW_KEY_TYPE_IPV6|FLOW_KEY_TYPE_SCTP|
			      FLOW_KEY_TYPE_VXLAN,
			      1, 5, 42, NULL, NULL); //[a5], fail
}

static int
IPV6_SCTP_VXLAN(void)
{
	return result_checker(FLOW_KEY_TYPE_IPV6|
			      FLOW_KEY_TYPE_SCTP|FLOW_KEY_TYPE_VXLAN,
			      0, 3, 36, NULL, NULL); //[a4], would pass!!
}

static int
PORT_IPV4_SCTP_VXLAN(void)
{
	return result_checker(FLOW_KEY_TYPE_PORT|
			      FLOW_KEY_TYPE_IPV4|FLOW_KEY_TYPE_SCTP|
			      FLOW_KEY_TYPE_VXLAN,
			      0, 4, 14, NULL, NULL); //[a3], would pass!!
}

static int
IPV4_SCTP_VXLAN(void)
{
	return result_checker(FLOW_KEY_TYPE_IPV4|
			      FLOW_KEY_TYPE_SCTP|FLOW_KEY_TYPE_VXLAN,
			      0, 3, 12, NULL, NULL); //[a2], would pass!!
}

static int
PORT_SCTP_VXLAN(void)
{
	return result_checker(FLOW_KEY_TYPE_PORT|
			      FLOW_KEY_TYPE_SCTP|FLOW_KEY_TYPE_VXLAN,
			      0, 3, 6, NULL, NULL); //[a1], would pass!!
}

static int
SCTP_VXLAN(void)
{
	return result_checker(FLOW_KEY_TYPE_SCTP|
			      FLOW_KEY_TYPE_VXLAN,
			      0, 2, 4, NULL, NULL); //[a0], would pass!!
}

static int
PORT_IPV4_IPV6_TCP_UDP_VXLAN(void)
{
	return result_checker(FLOW_KEY_TYPE_PORT|
			      FLOW_KEY_TYPE_IPV4|FLOW_KEY_TYPE_IPV6|
			      FLOW_KEY_TYPE_TCP|FLOW_KEY_TYPE_UDP|
			      FLOW_KEY_TYPE_VXLAN,
			      1, 5, 42, NULL, NULL); //[9f], fail
}

static int
IPV4_IPV6_TCP_UDP_VXLAN(void)
{
	return result_checker(FLOW_KEY_TYPE_IPV4|
			      FLOW_KEY_TYPE_IPV6|FLOW_KEY_TYPE_TCP|
			      FLOW_KEY_TYPE_UDP|FLOW_KEY_TYPE_VXLAN,
			      0, 4, 36, NULL, NULL); //[9e], would pass!!
}

static int
PORT_IPV6_TCP_UDP_VXLAN(void)
{
	return result_checker(FLOW_KEY_TYPE_PORT|
			      FLOW_KEY_TYPE_IPV6|FLOW_KEY_TYPE_TCP|
			      FLOW_KEY_TYPE_UDP|FLOW_KEY_TYPE_VXLAN,
			      1, 5, 42, NULL, NULL); //[9d], fail
}

static int
IPV6_TCP_UDP_VXLAN(void)
{
	return result_checker(FLOW_KEY_TYPE_IPV6|
			      FLOW_KEY_TYPE_TCP|FLOW_KEY_TYPE_UDP|
			      FLOW_KEY_TYPE_VXLAN,
			      0, 3, 36, NULL, NULL); //[9c], would pass!!
}

static int
PORT_IPV4_TCP_UDP_VXLAN(void)
{
	return result_checker(FLOW_KEY_TYPE_PORT|
			      FLOW_KEY_TYPE_IPV4|FLOW_KEY_TYPE_TCP|
			      FLOW_KEY_TYPE_UDP|FLOW_KEY_TYPE_VXLAN,
			      0, 4, 14, NULL, NULL); //[9b], would pass!!
}

static int
IPV4_TCP_UDP_VXLAN(void)
{
	return result_checker(FLOW_KEY_TYPE_IPV4|
			      FLOW_KEY_TYPE_TCP|FLOW_KEY_TYPE_UDP|
			      FLOW_KEY_TYPE_VXLAN,
			      0, 3, 12, NULL, NULL); //[9a], would pass!!
}

static int
PORT_TCP_UDP_VXLAN(void)
{
	return result_checker(FLOW_KEY_TYPE_PORT|
			      FLOW_KEY_TYPE_TCP|FLOW_KEY_TYPE_UDP|
			      FLOW_KEY_TYPE_VXLAN,
			      0, 3, 6, NULL, NULL); //[99], would pass!!
}

static int
TCP_UDP_VXLAN(void)
{
	return result_checker(FLOW_KEY_TYPE_TCP|
			      FLOW_KEY_TYPE_UDP|FLOW_KEY_TYPE_VXLAN,
			      0, 2, 4, NULL, NULL); //[98], would pass!!
}

static int
PORT_IPV4_IPV6_UDP_VXLAN(void)
{
	return result_checker(FLOW_KEY_TYPE_PORT|
			      FLOW_KEY_TYPE_IPV4|FLOW_KEY_TYPE_IPV6|
			      FLOW_KEY_TYPE_UDP|FLOW_KEY_TYPE_VXLAN,
			      1, 5, 42, NULL, NULL); //[97], fail
}

static int
IPV4_IPV6_UDP_VXLAN(void)
{
	return result_checker(FLOW_KEY_TYPE_IPV4|
			      FLOW_KEY_TYPE_IPV6|FLOW_KEY_TYPE_UDP|
			      FLOW_KEY_TYPE_VXLAN,
			      0, 4, 36, NULL, NULL); //[96], would pass!!
}

static int
PORT_IPV6_UDP_VXLAN(void)
{
	return result_checker(FLOW_KEY_TYPE_PORT|
			      FLOW_KEY_TYPE_IPV6|FLOW_KEY_TYPE_UDP|
			      FLOW_KEY_TYPE_VXLAN,
			      1, 5, 42, NULL, NULL); //[95], fail
}

static int
IPV6_UDP_VXLAN(void)
{
	return result_checker(FLOW_KEY_TYPE_IPV6|
			      FLOW_KEY_TYPE_UDP|FLOW_KEY_TYPE_VXLAN,
			      0, 3, 36, NULL, NULL); //[94], would pass!!
}

static int
PORT_IPV4_UDP_VXLAN(void)
{
	return result_checker(FLOW_KEY_TYPE_PORT|
			      FLOW_KEY_TYPE_IPV4|FLOW_KEY_TYPE_UDP|
			      FLOW_KEY_TYPE_VXLAN,
			      0, 4, 14, NULL, NULL); //[93], would pass!!
}

static int
IPV4_UDP_VXLAN(void)
{
	return result_checker(FLOW_KEY_TYPE_IPV4|
			      FLOW_KEY_TYPE_UDP|FLOW_KEY_TYPE_VXLAN,
			      0, 3, 12, NULL, NULL); //[92], would pass!!
}

static int
PORT_UDP_VXLAN(void)
{
	return result_checker(FLOW_KEY_TYPE_PORT|
			      FLOW_KEY_TYPE_UDP|FLOW_KEY_TYPE_VXLAN,
			      0, 3, 6, NULL, NULL); //[91], would pass!!
}

static int
UDP_VXLAN(void)
{
	return result_checker(FLOW_KEY_TYPE_UDP|
			      FLOW_KEY_TYPE_VXLAN,
			      0, 2, 4, NULL, NULL); //[90], would pass!!
}

static int
PORT_IPV4_IPV6_TCP_VXLAN(void)
{
	return result_checker(FLOW_KEY_TYPE_PORT|
			      FLOW_KEY_TYPE_IPV4|FLOW_KEY_TYPE_IPV6|
			      FLOW_KEY_TYPE_TCP|FLOW_KEY_TYPE_VXLAN,
			      1, 5, 42, NULL, NULL); //[8f], fail
}

static int
IPV4_IPV6_TCP_VXLAN(void)
{
	return result_checker(FLOW_KEY_TYPE_IPV4|
			      FLOW_KEY_TYPE_IPV6|FLOW_KEY_TYPE_TCP|
			      FLOW_KEY_TYPE_VXLAN,
			      0, 4, 36, NULL, NULL); //[8e], would pass!!
}

static int
PORT_IPV6_TCP_VXLAN(void)
{
	return result_checker(FLOW_KEY_TYPE_PORT|
			      FLOW_KEY_TYPE_IPV6|FLOW_KEY_TYPE_TCP|
			      FLOW_KEY_TYPE_VXLAN,
			      1, 5, 42, NULL, NULL); //[8d], fail
}

static int
IPV6_TCP_VXLAN(void)
{
	return result_checker(FLOW_KEY_TYPE_IPV6|
			      FLOW_KEY_TYPE_TCP|FLOW_KEY_TYPE_VXLAN,
			      0, 3, 36, NULL, NULL); //[8c], would pass!!
}

static int
PORT_IPV4_TCP_VXLAN(void)
{
	return result_checker(FLOW_KEY_TYPE_PORT|
			      FLOW_KEY_TYPE_IPV4|FLOW_KEY_TYPE_TCP|
			      FLOW_KEY_TYPE_VXLAN,
			      0, 4, 14, NULL, NULL); //[8b], would pass!!
}

static int
IPV4_TCP_VXLAN(void)
{
	return result_checker(FLOW_KEY_TYPE_IPV4|
			      FLOW_KEY_TYPE_TCP|FLOW_KEY_TYPE_VXLAN,
			      0, 3, 12, NULL, NULL); //[8a], would pass!!
}

static int
PORT_TCP_VXLAN(void)
{
	return result_checker(FLOW_KEY_TYPE_PORT|
			      FLOW_KEY_TYPE_TCP|FLOW_KEY_TYPE_VXLAN,
			      0, 3, 6, NULL, NULL); //[89], would pass!!
}

static int
TCP_VXLAN(void)
{
	return result_checker(FLOW_KEY_TYPE_TCP|
			      FLOW_KEY_TYPE_VXLAN,
			      0, 2, 4, NULL, NULL); //[88], would pass!!
}

static int
PORT_IPV4_IPV6_VXLAN(void)
{
	return result_checker(FLOW_KEY_TYPE_PORT|
			      FLOW_KEY_TYPE_IPV4|FLOW_KEY_TYPE_IPV6|
			      FLOW_KEY_TYPE_VXLAN,
			      0, 4, 34, NULL, NULL); //[87], would pass!!
}

static int
IPV4_IPV6_VXLAN(void)
{
	return result_checker(FLOW_KEY_TYPE_IPV4|
			      FLOW_KEY_TYPE_IPV6|FLOW_KEY_TYPE_VXLAN,
			      0, 3, 32, NULL, NULL); //[86], would pass!!
}

static int
PORT_IPV6_VXLAN(void)
{
	return result_checker(FLOW_KEY_TYPE_PORT|
			      FLOW_KEY_TYPE_IPV6|FLOW_KEY_TYPE_VXLAN,
			      0, 3, 34, NULL, NULL); //[85], would pass!!
}

static int
IPV6_VXLAN(void)
{
	return result_checker(FLOW_KEY_TYPE_IPV6|
			      FLOW_KEY_TYPE_VXLAN,
			      0, 2, 32, NULL, NULL); //[84], would pass!!
}

static int
PORT_IPV4_VXLAN(void)
{
	return result_checker(FLOW_KEY_TYPE_PORT|
			      FLOW_KEY_TYPE_IPV4|FLOW_KEY_TYPE_VXLAN,
			      0, 3, 10, NULL, NULL); //[83], would pass!!
}

static int
IPV4_VXLAN(void)
{
	return result_checker(FLOW_KEY_TYPE_IPV4|
			      FLOW_KEY_TYPE_VXLAN,
			      0, 2, 8, NULL, NULL); //[82], would pass!!
}

static int
PORT_VXLAN(void)
{
	return result_checker(FLOW_KEY_TYPE_PORT|
			      FLOW_KEY_TYPE_VXLAN,
			      0, 2, 2, NULL, NULL); //[81], would pass!!
}

static int
VXLAN(void)
{
	return result_checker(FLOW_KEY_TYPE_VXLAN,
			      0, 1, 0, NULL, NULL); //[80], would pass!!
}

static int
PORT_IPV4_IPV6_TCP_UDP_SCTP_NVGRE(void)
{
	return result_checker(FLOW_KEY_TYPE_PORT|
			      FLOW_KEY_TYPE_IPV4|FLOW_KEY_TYPE_IPV6|
			      FLOW_KEY_TYPE_TCP|FLOW_KEY_TYPE_UDP|
			      FLOW_KEY_TYPE_SCTP|FLOW_KEY_TYPE_NVGRE,
			      1, 5, 42, NULL, NULL); //[7f], fail
}

static int
IPV4_IPV6_TCP_UDP_SCTP_NVGRE(void)
{
	return result_checker(FLOW_KEY_TYPE_IPV4|
			      FLOW_KEY_TYPE_IPV6|FLOW_KEY_TYPE_TCP|
			      FLOW_KEY_TYPE_UDP|FLOW_KEY_TYPE_SCTP|
			      FLOW_KEY_TYPE_NVGRE,
			      0, 4, 36, NULL, NULL); //[7e], would pass!!
}

static int
PORT_IPV6_TCP_UDP_SCTP_NVGRE(void)
{
	return result_checker(FLOW_KEY_TYPE_PORT|
			      FLOW_KEY_TYPE_IPV6|FLOW_KEY_TYPE_TCP|
			      FLOW_KEY_TYPE_UDP|FLOW_KEY_TYPE_SCTP|
			      FLOW_KEY_TYPE_NVGRE,
			      1, 5, 42, NULL, NULL); //[7d], fail
}

static int
IPV6_TCP_UDP_SCTP_NVGRE(void)
{
	return result_checker(FLOW_KEY_TYPE_IPV6|
			      FLOW_KEY_TYPE_TCP|FLOW_KEY_TYPE_UDP|
			      FLOW_KEY_TYPE_SCTP|FLOW_KEY_TYPE_NVGRE,
			      0, 3, 36, NULL, NULL); //[7c], would pass!!
}

static int
PORT_IPV4_TCP_UDP_SCTP_NVGRE(void)
{
	return result_checker(FLOW_KEY_TYPE_PORT|
			      FLOW_KEY_TYPE_IPV4|FLOW_KEY_TYPE_TCP|
			      FLOW_KEY_TYPE_UDP|FLOW_KEY_TYPE_SCTP|
			      FLOW_KEY_TYPE_NVGRE,
			      0, 4, 14, NULL, NULL); //[7b], would pass!!
}

static int
IPV4_TCP_UDP_SCTP_NVGRE(void)
{
	return result_checker(FLOW_KEY_TYPE_IPV4|
			      FLOW_KEY_TYPE_TCP|FLOW_KEY_TYPE_UDP|
			      FLOW_KEY_TYPE_SCTP|FLOW_KEY_TYPE_NVGRE,
			      0, 3, 12, NULL, NULL); //[7a], would pass!!
}

static int
PORT_TCP_UDP_SCTP_NVGRE(void)
{
	return result_checker(FLOW_KEY_TYPE_PORT|
			      FLOW_KEY_TYPE_TCP|FLOW_KEY_TYPE_UDP|
			      FLOW_KEY_TYPE_SCTP|FLOW_KEY_TYPE_NVGRE,
			      0, 3, 6, NULL, NULL); //[79], would pass!!
}

static int
TCP_UDP_SCTP_NVGRE(void)
{
	return result_checker(FLOW_KEY_TYPE_TCP|
			      FLOW_KEY_TYPE_UDP|FLOW_KEY_TYPE_SCTP|
			      FLOW_KEY_TYPE_NVGRE,
			      0, 2, 4, NULL, NULL); //[78], would pass!!
}

static int
PORT_IPV4_IPV6_UDP_SCTP_NVGRE(void)
{
	return result_checker(FLOW_KEY_TYPE_PORT|
			      FLOW_KEY_TYPE_IPV4|FLOW_KEY_TYPE_IPV6|
			      FLOW_KEY_TYPE_UDP|FLOW_KEY_TYPE_SCTP|
			      FLOW_KEY_TYPE_NVGRE,
			      1, 5, 42, NULL, NULL); //[77], fail
}

static int
IPV4_IPV6_UDP_SCTP_NVGRE(void)
{
	return result_checker(FLOW_KEY_TYPE_IPV4|
			      FLOW_KEY_TYPE_IPV6|FLOW_KEY_TYPE_UDP|
			      FLOW_KEY_TYPE_SCTP|FLOW_KEY_TYPE_NVGRE,
			      0, 4, 36, NULL, NULL); //[76], would pass!!
}

static int
PORT_IPV6_UDP_SCTP_NVGRE(void)
{
	return result_checker(FLOW_KEY_TYPE_PORT|
			      FLOW_KEY_TYPE_IPV6|FLOW_KEY_TYPE_UDP|
			      FLOW_KEY_TYPE_SCTP|FLOW_KEY_TYPE_NVGRE,
			      1, 5, 42, NULL, NULL); //[75], fail
}

static int
IPV6_UDP_SCTP_NVGRE(void)
{
	return result_checker(FLOW_KEY_TYPE_IPV6|
			      FLOW_KEY_TYPE_UDP|FLOW_KEY_TYPE_SCTP|
			      FLOW_KEY_TYPE_NVGRE,
			      0, 3, 36, NULL, NULL); //[74], would pass!!
}

static int
PORT_IPV4_UDP_SCTP_NVGRE(void)
{
	return result_checker(FLOW_KEY_TYPE_PORT|
			      FLOW_KEY_TYPE_IPV4|FLOW_KEY_TYPE_UDP|
			      FLOW_KEY_TYPE_SCTP|FLOW_KEY_TYPE_NVGRE,
			      0, 4, 14, NULL, NULL); //[73], would pass!!
}

static int
IPV4_UDP_SCTP_NVGRE(void)
{
	return result_checker(FLOW_KEY_TYPE_IPV4|
			      FLOW_KEY_TYPE_UDP|FLOW_KEY_TYPE_SCTP|
			      FLOW_KEY_TYPE_NVGRE,
			      0, 3, 12, NULL, NULL); //[72], would pass!!
}

static int
PORT_UDP_SCTP_NVGRE(void)
{
	return result_checker(FLOW_KEY_TYPE_PORT|
			      FLOW_KEY_TYPE_UDP|FLOW_KEY_TYPE_SCTP|
			      FLOW_KEY_TYPE_NVGRE,
			      0, 3, 6, NULL, NULL); //[71], would pass!!
}

static int
UDP_SCTP_NVGRE(void)
{
	return result_checker(FLOW_KEY_TYPE_UDP|
			      FLOW_KEY_TYPE_SCTP|FLOW_KEY_TYPE_NVGRE,
			      0, 2, 4, NULL, NULL); //[70], would pass!!
}

static int
PORT_IPV4_IPV6_TCP_SCTP_NVGRE(void)
{
	return result_checker(FLOW_KEY_TYPE_PORT|
			      FLOW_KEY_TYPE_IPV4|FLOW_KEY_TYPE_IPV6|
			      FLOW_KEY_TYPE_TCP|FLOW_KEY_TYPE_SCTP|
			      FLOW_KEY_TYPE_NVGRE,
			      1, 5, 42, NULL, NULL); //[6f], fail
}

static int
IPV4_IPV6_TCP_SCTP_NVGRE(void)
{
	return result_checker(FLOW_KEY_TYPE_IPV4|
			      FLOW_KEY_TYPE_IPV6|FLOW_KEY_TYPE_TCP|
			      FLOW_KEY_TYPE_SCTP|FLOW_KEY_TYPE_NVGRE,
			      0, 4, 36, NULL, NULL); //[6e], would pass!!
}

static int
PORT_IPV6_TCP_SCTP_NVGRE(void)
{
	return result_checker(FLOW_KEY_TYPE_PORT|
			      FLOW_KEY_TYPE_IPV6|FLOW_KEY_TYPE_TCP|
			      FLOW_KEY_TYPE_SCTP|FLOW_KEY_TYPE_NVGRE,
			      1, 5, 42, NULL, NULL); //[6d], fail
}

static int
IPV6_TCP_SCTP_NVGRE(void)
{
	return result_checker(FLOW_KEY_TYPE_IPV6|
			      FLOW_KEY_TYPE_TCP|FLOW_KEY_TYPE_SCTP|
			      FLOW_KEY_TYPE_NVGRE,
			      0, 3, 36, NULL, NULL); //[6c], would pass!!
}

static int
PORT_IPV4_TCP_SCTP_NVGRE(void)
{
	return result_checker(FLOW_KEY_TYPE_PORT|
			      FLOW_KEY_TYPE_IPV4|FLOW_KEY_TYPE_TCP|
			      FLOW_KEY_TYPE_SCTP|FLOW_KEY_TYPE_NVGRE,
			      0, 4, 14, NULL, NULL); //[6b], would pass!!
}

static int
IPV4_TCP_SCTP_NVGRE(void)
{
	return result_checker(FLOW_KEY_TYPE_IPV4|
			      FLOW_KEY_TYPE_TCP|FLOW_KEY_TYPE_SCTP|
			      FLOW_KEY_TYPE_NVGRE,
			      0, 3, 12, NULL, NULL); //[6a], would pass!!
}

static int
PORT_TCP_SCTP_NVGRE(void)
{
	return result_checker(FLOW_KEY_TYPE_PORT|
			      FLOW_KEY_TYPE_TCP|FLOW_KEY_TYPE_SCTP|
			      FLOW_KEY_TYPE_NVGRE,
			      0, 3, 6, NULL, NULL); //[69], would pass!!
}

static int
TCP_SCTP_NVGRE(void)
{
	return result_checker(FLOW_KEY_TYPE_TCP|
			      FLOW_KEY_TYPE_SCTP|FLOW_KEY_TYPE_NVGRE,
			      0, 2, 4, NULL, NULL); //[68], would pass!!
}

static int
PORT_IPV4_IPV6_SCTP_NVGRE(void)
{
	return result_checker(FLOW_KEY_TYPE_PORT|
			      FLOW_KEY_TYPE_IPV4|FLOW_KEY_TYPE_IPV6|
			      FLOW_KEY_TYPE_SCTP|FLOW_KEY_TYPE_NVGRE,
			      1, 5, 42, NULL, NULL); //[67], fail
}

static int
IPV4_IPV6_SCTP_NVGRE(void)
{
	return result_checker(FLOW_KEY_TYPE_IPV4|
			      FLOW_KEY_TYPE_IPV6|FLOW_KEY_TYPE_SCTP|
			      FLOW_KEY_TYPE_NVGRE,
			      0, 4, 36, NULL, NULL); //[66], would pass!!
}

static int
PORT_IPV6_SCTP_NVGRE(void)
{
	return result_checker(FLOW_KEY_TYPE_PORT|
			      FLOW_KEY_TYPE_IPV6|FLOW_KEY_TYPE_SCTP|
			      FLOW_KEY_TYPE_NVGRE,
			      1, 5, 42, NULL, NULL); //[65], fail
}

static int
IPV6_SCTP_NVGRE(void)
{
	return result_checker(FLOW_KEY_TYPE_IPV6|
			      FLOW_KEY_TYPE_SCTP|FLOW_KEY_TYPE_NVGRE,
			      0, 3, 36, NULL, NULL); //[64], would pass!!
}

static int
PORT_IPV4_SCTP_NVGRE(void)
{
	return result_checker(FLOW_KEY_TYPE_PORT|
			      FLOW_KEY_TYPE_IPV4|FLOW_KEY_TYPE_SCTP|
			      FLOW_KEY_TYPE_NVGRE,
			      0, 4, 14, NULL, NULL); //[63], would pass!!
}

static int
IPV4_SCTP_NVGRE(void)
{
	return result_checker(FLOW_KEY_TYPE_IPV4|
			      FLOW_KEY_TYPE_SCTP|FLOW_KEY_TYPE_NVGRE,
			      0, 3, 12, NULL, NULL); //[62], would pass!!
}

static int
PORT_SCTP_NVGRE(void)
{
	return result_checker(FLOW_KEY_TYPE_PORT|
			      FLOW_KEY_TYPE_SCTP|FLOW_KEY_TYPE_NVGRE,
			      0, 3, 6, NULL, NULL); //[61], would pass!!
}

static int
SCTP_NVGRE(void)
{
	return result_checker(FLOW_KEY_TYPE_SCTP|
			      FLOW_KEY_TYPE_NVGRE,
			      0, 2, 4, NULL, NULL); //[60], would pass!!
}

static int
PORT_IPV4_IPV6_TCP_UDP_NVGRE(void)
{
	return result_checker(FLOW_KEY_TYPE_PORT|
			      FLOW_KEY_TYPE_IPV4|FLOW_KEY_TYPE_IPV6|
			      FLOW_KEY_TYPE_TCP|FLOW_KEY_TYPE_UDP|
			      FLOW_KEY_TYPE_NVGRE,
			      1, 5, 42, NULL, NULL); //[5f], fail
}

static int
IPV4_IPV6_TCP_UDP_NVGRE(void)
{
	return result_checker(FLOW_KEY_TYPE_IPV4|
			      FLOW_KEY_TYPE_IPV6|FLOW_KEY_TYPE_TCP|
			      FLOW_KEY_TYPE_UDP|FLOW_KEY_TYPE_NVGRE,
			      0, 4, 36, NULL, NULL); //[5e], would pass!!
}

static int
PORT_IPV6_TCP_UDP_NVGRE(void)
{
	return result_checker(FLOW_KEY_TYPE_PORT|
			      FLOW_KEY_TYPE_IPV6|FLOW_KEY_TYPE_TCP|
			      FLOW_KEY_TYPE_UDP|FLOW_KEY_TYPE_NVGRE,
			      1, 5, 42, NULL, NULL); //[5d], fail
}

static int
IPV6_TCP_UDP_NVGRE(void)
{
	return result_checker(FLOW_KEY_TYPE_IPV6|
			      FLOW_KEY_TYPE_TCP|FLOW_KEY_TYPE_UDP|
			      FLOW_KEY_TYPE_NVGRE,
			      0, 3, 36, NULL, NULL); //[5c], would pass!!
}

static int
PORT_IPV4_TCP_UDP_NVGRE(void)
{
	return result_checker(FLOW_KEY_TYPE_PORT|
			      FLOW_KEY_TYPE_IPV4|FLOW_KEY_TYPE_TCP|
			      FLOW_KEY_TYPE_UDP|FLOW_KEY_TYPE_NVGRE,
			      0, 4, 14, NULL, NULL); //[5b], would pass!!
}

static int
IPV4_TCP_UDP_NVGRE(void)
{
	return result_checker(FLOW_KEY_TYPE_IPV4|
			      FLOW_KEY_TYPE_TCP|FLOW_KEY_TYPE_UDP|
			      FLOW_KEY_TYPE_NVGRE,
			      0, 3, 12, NULL, NULL); //[5a], would pass!!
}

static int
PORT_TCP_UDP_NVGRE(void)
{
	return result_checker(FLOW_KEY_TYPE_PORT|
			      FLOW_KEY_TYPE_TCP|FLOW_KEY_TYPE_UDP|
			      FLOW_KEY_TYPE_NVGRE,
			      0, 3, 6, NULL, NULL); //[59], would pass!!
}

static int
TCP_UDP_NVGRE(void)
{
	return result_checker(FLOW_KEY_TYPE_TCP|
			      FLOW_KEY_TYPE_UDP|FLOW_KEY_TYPE_NVGRE,
			      0, 2, 4, NULL, NULL); //[58], would pass!!
}

static int
PORT_IPV4_IPV6_UDP_NVGRE(void)
{
	return result_checker(FLOW_KEY_TYPE_PORT|
			      FLOW_KEY_TYPE_IPV4|FLOW_KEY_TYPE_IPV6|
			      FLOW_KEY_TYPE_UDP|FLOW_KEY_TYPE_NVGRE,
			      1, 5, 42, NULL, NULL); //[57], fail
}

static int
IPV4_IPV6_UDP_NVGRE(void)
{
	return result_checker(FLOW_KEY_TYPE_IPV4|
			      FLOW_KEY_TYPE_IPV6|FLOW_KEY_TYPE_UDP|
			      FLOW_KEY_TYPE_NVGRE,
			      0, 4, 36, NULL, NULL); //[56], would pass!!
}

static int
PORT_IPV6_UDP_NVGRE(void)
{
	return result_checker(FLOW_KEY_TYPE_PORT|
			      FLOW_KEY_TYPE_IPV6|FLOW_KEY_TYPE_UDP|
			      FLOW_KEY_TYPE_NVGRE,
			      1, 5, 42, NULL, NULL); //[55], fail
}

static int
IPV6_UDP_NVGRE(void)
{
	return result_checker(FLOW_KEY_TYPE_IPV6|
			      FLOW_KEY_TYPE_UDP|FLOW_KEY_TYPE_NVGRE,
			      0, 3, 36, NULL, NULL); //[54], would pass!!
}

static int
PORT_IPV4_UDP_NVGRE(void)
{
	return result_checker(FLOW_KEY_TYPE_PORT|
			      FLOW_KEY_TYPE_IPV4|FLOW_KEY_TYPE_UDP|
			      FLOW_KEY_TYPE_NVGRE,
			      0, 4, 14, NULL, NULL); //[53], would pass!!
}

static int
IPV4_UDP_NVGRE(void)
{
	return result_checker(FLOW_KEY_TYPE_IPV4|
			      FLOW_KEY_TYPE_UDP|FLOW_KEY_TYPE_NVGRE,
			      0, 3, 12, NULL, NULL); //[52], would pass!!
}

static int
PORT_UDP_NVGRE(void)
{
	return result_checker(FLOW_KEY_TYPE_PORT|
			      FLOW_KEY_TYPE_UDP|FLOW_KEY_TYPE_NVGRE,
			      0, 3, 6, NULL, NULL); //[51], would pass!!
}

static int
UDP_NVGRE(void)
{
	return result_checker(FLOW_KEY_TYPE_UDP|
			      FLOW_KEY_TYPE_NVGRE,
			      0, 2, 4, NULL, NULL); //[50], would pass!!
}

static int
PORT_IPV4_IPV6_TCP_NVGRE(void)
{
	return result_checker(FLOW_KEY_TYPE_PORT|
			      FLOW_KEY_TYPE_IPV4|FLOW_KEY_TYPE_IPV6|
			      FLOW_KEY_TYPE_TCP|FLOW_KEY_TYPE_NVGRE,
			      1, 5, 42, NULL, NULL); //[4f], fail
}

static int
IPV4_IPV6_TCP_NVGRE(void)
{
	return result_checker(FLOW_KEY_TYPE_IPV4|
			      FLOW_KEY_TYPE_IPV6|FLOW_KEY_TYPE_TCP|
			      FLOW_KEY_TYPE_NVGRE,
			      0, 4, 36, NULL, NULL); //[4e], would pass!!
}

static int
PORT_IPV6_TCP_NVGRE(void)
{
	return result_checker(FLOW_KEY_TYPE_PORT|
			      FLOW_KEY_TYPE_IPV6|FLOW_KEY_TYPE_TCP|
			      FLOW_KEY_TYPE_NVGRE,
			      1, 5, 42, NULL, NULL); //[4d], fail
}

static int
IPV6_TCP_NVGRE(void)
{
	return result_checker(FLOW_KEY_TYPE_IPV6|
			      FLOW_KEY_TYPE_TCP|FLOW_KEY_TYPE_NVGRE,
			      0, 3, 36, NULL, NULL); //[4c], would pass!!
}

static int
PORT_IPV4_TCP_NVGRE(void)
{
	return result_checker(FLOW_KEY_TYPE_PORT|
			      FLOW_KEY_TYPE_IPV4|FLOW_KEY_TYPE_TCP|
			      FLOW_KEY_TYPE_NVGRE,
			      0, 4, 14, NULL, NULL); //[4b], would pass!!
}

static int
IPV4_TCP_NVGRE(void)
{
	return result_checker(FLOW_KEY_TYPE_IPV4|
			      FLOW_KEY_TYPE_TCP|FLOW_KEY_TYPE_NVGRE,
			      0, 3, 12, NULL, NULL); //[4a], would pass!!
}

static int
PORT_TCP_NVGRE(void)
{
	return result_checker(FLOW_KEY_TYPE_PORT|
			      FLOW_KEY_TYPE_TCP|FLOW_KEY_TYPE_NVGRE,
			      0, 3, 6, NULL, NULL); //[49], would pass!!
}

static int
TCP_NVGRE(void)
{
	return result_checker(FLOW_KEY_TYPE_TCP|
			      FLOW_KEY_TYPE_NVGRE,
			      0, 2, 4, NULL, NULL); //[48], would pass!!
}

static int
PORT_IPV4_IPV6_NVGRE(void)
{
	return result_checker(FLOW_KEY_TYPE_PORT|
			      FLOW_KEY_TYPE_IPV4|FLOW_KEY_TYPE_IPV6|
			      FLOW_KEY_TYPE_NVGRE,
			      0, 4, 34, NULL, NULL); //[47], would pass!!
}

static int
IPV4_IPV6_NVGRE(void)
{
	return result_checker(FLOW_KEY_TYPE_IPV4|
			      FLOW_KEY_TYPE_IPV6|FLOW_KEY_TYPE_NVGRE,
			      0, 3, 32, NULL, NULL); //[46], would pass!!
}

static int
PORT_IPV6_NVGRE(void)
{
	return result_checker(FLOW_KEY_TYPE_PORT|
			      FLOW_KEY_TYPE_IPV6|FLOW_KEY_TYPE_NVGRE,
			      0, 3, 34, NULL, NULL); //[45], would pass!!
}

static int
IPV6_NVGRE(void)
{
	return result_checker(FLOW_KEY_TYPE_IPV6|
			      FLOW_KEY_TYPE_NVGRE,
			      0, 2, 32, NULL, NULL); //[44], would pass!!
}

static int
PORT_IPV4_NVGRE(void)
{
	return result_checker(FLOW_KEY_TYPE_PORT|
			      FLOW_KEY_TYPE_IPV4|FLOW_KEY_TYPE_NVGRE,
			      0, 3, 10, NULL, NULL); //[43], would pass!!
}

static int
IPV4_NVGRE(void)
{
	return result_checker(FLOW_KEY_TYPE_IPV4|
			      FLOW_KEY_TYPE_NVGRE,
			      0, 2, 8, NULL, NULL); //[42], would pass!!
}

static int
PORT_NVGRE(void)
{
	return result_checker(FLOW_KEY_TYPE_PORT|
			      FLOW_KEY_TYPE_NVGRE,
			      0, 2, 2, NULL, NULL); //[41], would pass!!
}

static int
NVGRE(void)
{
	return result_checker(FLOW_KEY_TYPE_NVGRE,
			      0, 1, 0, NULL, NULL); //[40], would pass!!
}

static int
PORT_IPV4_IPV6_TCP_UDP_SCTP(void)
{
	return result_checker(FLOW_KEY_TYPE_PORT|
			      FLOW_KEY_TYPE_IPV4|FLOW_KEY_TYPE_IPV6|
			      FLOW_KEY_TYPE_TCP|FLOW_KEY_TYPE_UDP|
			      FLOW_KEY_TYPE_SCTP,
			      0, 4, 34, NULL, NULL); //[3f], would pass!!
}

static int
IPV4_IPV6_TCP_UDP_SCTP(void)
{
	return result_checker(FLOW_KEY_TYPE_IPV4|
			      FLOW_KEY_TYPE_IPV6|FLOW_KEY_TYPE_TCP|
			      FLOW_KEY_TYPE_UDP|FLOW_KEY_TYPE_SCTP,
			      0, 3, 32, NULL, NULL); //[3e], would pass!!
}

static int
PORT_IPV6_TCP_UDP_SCTP(void)
{
	return result_checker(FLOW_KEY_TYPE_PORT|
			      FLOW_KEY_TYPE_IPV6|FLOW_KEY_TYPE_TCP|
			      FLOW_KEY_TYPE_UDP|FLOW_KEY_TYPE_SCTP,
			      0, 3, 34, NULL, NULL); //[3d], would pass!!
}

static int
IPV6_TCP_UDP_SCTP(void)
{
	return result_checker(FLOW_KEY_TYPE_IPV6|
			      FLOW_KEY_TYPE_TCP|FLOW_KEY_TYPE_UDP|
			      FLOW_KEY_TYPE_SCTP,
			      0, 2, 32, NULL, NULL); //[3c], would pass!!
}

static int
PORT_IPV4_TCP_UDP_SCTP(void)
{
	return result_checker(FLOW_KEY_TYPE_PORT|
			      FLOW_KEY_TYPE_IPV4|FLOW_KEY_TYPE_TCP|
			      FLOW_KEY_TYPE_UDP|FLOW_KEY_TYPE_SCTP,
			      0, 3, 10, NULL, NULL); //[3b], would pass!!
}

static int
IPV4_TCP_UDP_SCTP(void)
{
	return result_checker(FLOW_KEY_TYPE_IPV4|
			      FLOW_KEY_TYPE_TCP|FLOW_KEY_TYPE_UDP|
			      FLOW_KEY_TYPE_SCTP,
			      0, 2, 8, NULL, NULL); //[3a], would pass!!
}

static int
PORT_TCP_UDP_SCTP(void)
{
	return result_checker(FLOW_KEY_TYPE_PORT|
			      FLOW_KEY_TYPE_TCP|FLOW_KEY_TYPE_UDP|
			      FLOW_KEY_TYPE_SCTP,
			      0, 2, 2, NULL, NULL); //[39], would pass!!
}

static int
TCP_UDP_SCTP(void)
{
	return result_checker(FLOW_KEY_TYPE_TCP|
			      FLOW_KEY_TYPE_UDP|FLOW_KEY_TYPE_SCTP,
			      0, 1, 0, NULL, NULL); //[38], would pass!!
}

static int
PORT_IPV4_IPV6_UDP_SCTP(void)
{
	return result_checker(FLOW_KEY_TYPE_PORT|
			      FLOW_KEY_TYPE_IPV4|FLOW_KEY_TYPE_IPV6|
			      FLOW_KEY_TYPE_UDP|FLOW_KEY_TYPE_SCTP,
			      0, 4, 34, NULL, NULL); //[37], would pass!!
}

static int
IPV4_IPV6_UDP_SCTP(void)
{
	return result_checker(FLOW_KEY_TYPE_IPV4|
			      FLOW_KEY_TYPE_IPV6|FLOW_KEY_TYPE_UDP|
			      FLOW_KEY_TYPE_SCTP,
			      0, 3, 32, NULL, NULL); //[36], would pass!!
}

static int
PORT_IPV6_UDP_SCTP(void)
{
	return result_checker(FLOW_KEY_TYPE_PORT|
			      FLOW_KEY_TYPE_IPV6|FLOW_KEY_TYPE_UDP|
			      FLOW_KEY_TYPE_SCTP,
			      0, 3, 34, NULL, NULL); //[35], would pass!!
}

static int
IPV6_UDP_SCTP(void)
{
	return result_checker(FLOW_KEY_TYPE_IPV6|
			      FLOW_KEY_TYPE_UDP|FLOW_KEY_TYPE_SCTP,
			      0, 2, 32, NULL, NULL); //[34], would pass!!
}

static int
PORT_IPV4_UDP_SCTP(void)
{
	return result_checker(FLOW_KEY_TYPE_PORT|
			      FLOW_KEY_TYPE_IPV4|FLOW_KEY_TYPE_UDP|
			      FLOW_KEY_TYPE_SCTP,
			      0, 3, 10, NULL, NULL); //[33], would pass!!
}

static int
IPV4_UDP_SCTP(void)
{
	return result_checker(FLOW_KEY_TYPE_IPV4|
			      FLOW_KEY_TYPE_UDP|FLOW_KEY_TYPE_SCTP,
			      0, 2, 8, NULL, NULL); //[32], would pass!!
}

static int
PORT_UDP_SCTP(void)
{
	return result_checker(FLOW_KEY_TYPE_PORT|
			      FLOW_KEY_TYPE_UDP|FLOW_KEY_TYPE_SCTP,
			      0, 2, 2, NULL, NULL); //[31], would pass!!
}

static int
UDP_SCTP(void)
{
	return result_checker(FLOW_KEY_TYPE_UDP|
			      FLOW_KEY_TYPE_SCTP,
			      0, 1, 0, NULL, NULL); //[30], would pass!!
}

static int
PORT_IPV4_IPV6_TCP_SCTP(void)
{
	return result_checker(FLOW_KEY_TYPE_PORT|
			      FLOW_KEY_TYPE_IPV4|FLOW_KEY_TYPE_IPV6|
			      FLOW_KEY_TYPE_TCP|FLOW_KEY_TYPE_SCTP,
			      0, 4, 34, NULL, NULL); //[2f], would pass!!
}

static int
IPV4_IPV6_TCP_SCTP(void)
{
	return result_checker(FLOW_KEY_TYPE_IPV4|
			      FLOW_KEY_TYPE_IPV6|FLOW_KEY_TYPE_TCP|
			      FLOW_KEY_TYPE_SCTP,
			      0, 3, 32, NULL, NULL); //[2e], would pass!!
}

static int
PORT_IPV6_TCP_SCTP(void)
{
	return result_checker(FLOW_KEY_TYPE_PORT|
			      FLOW_KEY_TYPE_IPV6|FLOW_KEY_TYPE_TCP|
			      FLOW_KEY_TYPE_SCTP,
			      0, 3, 34, NULL, NULL); //[2d], would pass!!
}

static int
IPV6_TCP_SCTP(void)
{
	return result_checker(FLOW_KEY_TYPE_IPV6|
			      FLOW_KEY_TYPE_TCP|FLOW_KEY_TYPE_SCTP,
			      0, 2, 32, NULL, NULL); //[2c], would pass!!
}

static int
PORT_IPV4_TCP_SCTP(void)
{
	return result_checker(FLOW_KEY_TYPE_PORT|
			      FLOW_KEY_TYPE_IPV4|FLOW_KEY_TYPE_TCP|
			      FLOW_KEY_TYPE_SCTP,
			      0, 3, 10, NULL, NULL); //[2b], would pass!!
}

static int
IPV4_TCP_SCTP(void)
{
	return result_checker(FLOW_KEY_TYPE_IPV4|
			      FLOW_KEY_TYPE_TCP|FLOW_KEY_TYPE_SCTP,
			      0, 2, 8, NULL, NULL); //[2a], would pass!!
}

static int
PORT_TCP_SCTP(void)
{
	return result_checker(FLOW_KEY_TYPE_PORT|
			      FLOW_KEY_TYPE_TCP|FLOW_KEY_TYPE_SCTP,
			      0, 2, 2, NULL, NULL); //[29], would pass!!
}

static int
TCP_SCTP(void)
{
	return result_checker(FLOW_KEY_TYPE_TCP|
			      FLOW_KEY_TYPE_SCTP,
			      0, 1, 0, NULL, NULL); //[28], would pass!!
}

static int
PORT_IPV4_IPV6_SCTP(void)
{
	return result_checker(FLOW_KEY_TYPE_PORT|
			      FLOW_KEY_TYPE_IPV4|FLOW_KEY_TYPE_IPV6|
			      FLOW_KEY_TYPE_SCTP,
			      0, 4, 34, NULL, NULL); //[27], would pass!!
}

static int
IPV4_IPV6_SCTP(void)
{
	return result_checker(FLOW_KEY_TYPE_IPV4|
			      FLOW_KEY_TYPE_IPV6|FLOW_KEY_TYPE_SCTP,
			      0, 3, 32, NULL, NULL); //[26], would pass!!
}

static int
PORT_IPV6_SCTP(void)
{
	return result_checker(FLOW_KEY_TYPE_PORT|
			      FLOW_KEY_TYPE_IPV6|FLOW_KEY_TYPE_SCTP,
			      0, 3, 34, NULL, NULL); //[25], would pass!!
}

static int
IPV6_SCTP(void)
{
	return result_checker(FLOW_KEY_TYPE_IPV6|
			      FLOW_KEY_TYPE_SCTP,
			      0, 2, 32, NULL, NULL); //[24], would pass!!
}

static int
PORT_IPV4_SCTP(void)
{
	return result_checker(FLOW_KEY_TYPE_PORT|
			      FLOW_KEY_TYPE_IPV4|FLOW_KEY_TYPE_SCTP,
			      0, 3, 10, NULL, NULL); //[23], would pass!!
}

static int
IPV4_SCTP(void)
{
	return result_checker(FLOW_KEY_TYPE_IPV4|
			      FLOW_KEY_TYPE_SCTP,
			      0, 2, 8, NULL, NULL); //[22], would pass!!
}

static int
PORT_SCTP(void)
{
	return result_checker(FLOW_KEY_TYPE_PORT|
			      FLOW_KEY_TYPE_SCTP,
			      0, 2, 2, NULL, NULL); //[21], would pass!!
}

static int
SCTP(void)
{
	return result_checker(FLOW_KEY_TYPE_SCTP,
			      0, 1, 0, NULL, NULL); //[20], would pass!!
}

static int
PORT_IPV4_IPV6_TCP_UDP(void)
{
	return result_checker(FLOW_KEY_TYPE_PORT|
			      FLOW_KEY_TYPE_IPV4|FLOW_KEY_TYPE_IPV6|
			      FLOW_KEY_TYPE_TCP|FLOW_KEY_TYPE_UDP,
			      0, 4, 34, NULL, NULL); //[1f], would pass!!
}

static int
IPV4_IPV6_TCP_UDP(void)
{
	return result_checker(FLOW_KEY_TYPE_IPV4|
			      FLOW_KEY_TYPE_IPV6|FLOW_KEY_TYPE_TCP|
			      FLOW_KEY_TYPE_UDP,
			      0, 3, 32, NULL, NULL); //[1e], would pass!!
}

static int
PORT_IPV6_TCP_UDP(void)
{
	return result_checker(FLOW_KEY_TYPE_PORT|
			      FLOW_KEY_TYPE_IPV6|FLOW_KEY_TYPE_TCP|
			      FLOW_KEY_TYPE_UDP,
			      0, 3, 34, NULL, NULL); //[1d], would pass!!
}

static int
IPV6_TCP_UDP(void)
{
	return result_checker(FLOW_KEY_TYPE_IPV6|
			      FLOW_KEY_TYPE_TCP|FLOW_KEY_TYPE_UDP,
			      0, 2, 32, NULL, NULL); //[1c], would pass!!
}

static int
PORT_IPV4_TCP_UDP(void)
{
	return result_checker(FLOW_KEY_TYPE_PORT|
			      FLOW_KEY_TYPE_IPV4|FLOW_KEY_TYPE_TCP|
			      FLOW_KEY_TYPE_UDP,
			      0, 3, 10, NULL, NULL); //[1b], would pass!!
}

static int
IPV4_TCP_UDP(void)
{
	return result_checker(FLOW_KEY_TYPE_IPV4|
			      FLOW_KEY_TYPE_TCP|FLOW_KEY_TYPE_UDP,
			      0, 2, 8, NULL, NULL); //[1a], would pass!!
}

static int
PORT_TCP_UDP(void)
{
	return result_checker(FLOW_KEY_TYPE_PORT|
			      FLOW_KEY_TYPE_TCP|FLOW_KEY_TYPE_UDP,
			      0, 2, 2, NULL, NULL); //[19], would pass!!
}

static int
TCP_UDP(void)
{
	return result_checker(FLOW_KEY_TYPE_TCP|
			      FLOW_KEY_TYPE_UDP,
			      0, 1, 0, NULL, NULL); //[18], would pass!!
}

static int
PORT_IPV4_IPV6_UDP(void)
{
	return result_checker(FLOW_KEY_TYPE_PORT|
			      FLOW_KEY_TYPE_IPV4|FLOW_KEY_TYPE_IPV6|
			      FLOW_KEY_TYPE_UDP,
			      0, 4, 34, NULL, NULL); //[17], would pass!!
}

static int
IPV4_IPV6_UDP(void)
{
	return result_checker(FLOW_KEY_TYPE_IPV4|
			      FLOW_KEY_TYPE_IPV6|FLOW_KEY_TYPE_UDP,
			      0, 3, 32, NULL, NULL); //[16], would pass!!
}

static int
PORT_IPV6_UDP(void)
{
	return result_checker(FLOW_KEY_TYPE_PORT|
			      FLOW_KEY_TYPE_IPV6|FLOW_KEY_TYPE_UDP,
			      0, 3, 34, NULL, NULL); //[15], would pass!!
}

static int
IPV6_UDP(void)
{
	return result_checker(FLOW_KEY_TYPE_IPV6|
			      FLOW_KEY_TYPE_UDP,
			      0, 2, 32, NULL, NULL); //[14], would pass!!
}

static int
PORT_IPV4_UDP(void)
{
	return result_checker(FLOW_KEY_TYPE_PORT|
			      FLOW_KEY_TYPE_IPV4|FLOW_KEY_TYPE_UDP,
			      0, 3, 10, NULL, NULL); //[13], would pass!!
}

static int
IPV4_UDP(void)
{
	return result_checker(FLOW_KEY_TYPE_IPV4|
			      FLOW_KEY_TYPE_UDP,
			      0, 2, 8, NULL, NULL); //[12], would pass!!
}

static int
PORT_UDP(void)
{
	return result_checker(FLOW_KEY_TYPE_PORT|
			      FLOW_KEY_TYPE_UDP,
			      0, 2, 2, NULL, NULL); //[11], would pass!!
}

static int
UDP(void)
{
	return result_checker(FLOW_KEY_TYPE_UDP,
			      0, 1, 0, NULL, NULL); //[10], would pass!!
}

static int
PORT_IPV4_IPV6_TCP(void)
{
	return result_checker(FLOW_KEY_TYPE_PORT|
			      FLOW_KEY_TYPE_IPV4|FLOW_KEY_TYPE_IPV6|
			      FLOW_KEY_TYPE_TCP,
			      0, 4, 34, NULL, NULL); //[f], would pass!!
}

static int
IPV4_IPV6_TCP(void)
{
	return result_checker(FLOW_KEY_TYPE_IPV4|
			      FLOW_KEY_TYPE_IPV6|FLOW_KEY_TYPE_TCP,
			      0, 3, 32, NULL, NULL); //[e], would pass!!
}

static int
PORT_IPV6_TCP(void)
{
	return result_checker(FLOW_KEY_TYPE_PORT|
			      FLOW_KEY_TYPE_IPV6|FLOW_KEY_TYPE_TCP,
			      0, 3, 34, NULL, NULL); //[d], would pass!!
}

static int
IPV6_TCP(void)
{
	return result_checker(FLOW_KEY_TYPE_IPV6|
			      FLOW_KEY_TYPE_TCP,
			      0, 2, 32, NULL, NULL); //[c], would pass!!
}

static int
PORT_IPV4_TCP(void)
{
	return result_checker(FLOW_KEY_TYPE_PORT|
			      FLOW_KEY_TYPE_IPV4|FLOW_KEY_TYPE_TCP,
			      0, 3, 10, NULL, NULL); //[b], would pass!!
}

static int
IPV4_TCP(void)
{
	return result_checker(FLOW_KEY_TYPE_IPV4|
			      FLOW_KEY_TYPE_TCP,
			      0, 2, 8, NULL, NULL); //[a], would pass!!
}

static int
PORT_TCP(void)
{
	return result_checker(FLOW_KEY_TYPE_PORT|
			      FLOW_KEY_TYPE_TCP,
			      0, 2, 2, NULL, NULL); //[9], would pass!!
}

static int
TCP(void)
{
	return result_checker(FLOW_KEY_TYPE_TCP,
			      0, 1, 0, NULL, NULL); //[8], would pass!!
}

static int
PORT_IPV4_IPV6(void)
{
	return result_checker(FLOW_KEY_TYPE_PORT|
			      FLOW_KEY_TYPE_IPV4|FLOW_KEY_TYPE_IPV6,
			      0, 3, 2, NULL, NULL); //[7], would pass!!
}

static int
IPV4_IPV6(void)
{
	return result_checker(FLOW_KEY_TYPE_IPV4|
			      FLOW_KEY_TYPE_IPV6,
			      0, 2, 0, NULL, NULL); //[6], would pass!!
}

static int
PORT_IPV6(void)
{
	return result_checker(FLOW_KEY_TYPE_PORT|
			      FLOW_KEY_TYPE_IPV6,
			      0, 2, 2, NULL, NULL); //[5], would pass!!
}

static int
IPV6(void)
{
	return result_checker(FLOW_KEY_TYPE_IPV6,
			      0, 1, 0, NULL, NULL); //[4], would pass!!
}

static int
PORT_IPV4(void)
{
	return result_checker(FLOW_KEY_TYPE_PORT|
			      FLOW_KEY_TYPE_IPV4,
			      0, 2, 2, NULL, NULL); //[3], would pass!!
}

static int
IPV4(void)
{
	return result_checker(FLOW_KEY_TYPE_IPV4,
			      0, 1, 0, NULL, NULL); //[2], would pass!!
}

static int
PORT(void)
{
	return result_checker(FLOW_KEY_TYPE_PORT,
			      0, 1, 0, NULL, NULL); //[1], would pass!!
}

