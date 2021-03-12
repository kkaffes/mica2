#pragma once
#ifndef MICA_NETWORK_AF_XDP_IMPL_H_
#define MICA_NETWORK_AF_XDP_IMPL_H_

#include <rte_mbuf_pool_ops.h>
#include <linux/if_xdp.h>
#include <net/if.h>
#include <sys/mman.h>
#include <sys/time.h>
#include <sys/resource.h>

#include <poll.h>

#include <cerrno>

#include "bpf/xsk.h"

#define ETHER_MAX_LEN RTE_ETHER_MAX_LEN

#define NUM_FRAMES (4 * 1024)

#define XDP_FLAGS_SKB_MODE         (1U << 1)
#define XDP_FLAGS_UPDATE_IF_NOEXIST        (1U << 0)

static int opt_xsk_frame_size = XSK_UMEM__DEFAULT_FRAME_SIZE;
static int opt_ifindex;
static uint32_t opt_umem_flags;
static uint32_t prog_id;

namespace mica {
namespace network {
template <class StaticConfig>
AFXDP<StaticConfig>::AFXDP(const ::mica::util::Config& config)
    : config_(config), rte_argc_(0), endpoint_count_(0), started_(false) {

  // Update rlimits to avoid BPF error.
  struct rlimit r = {RLIM_INFINITY, RLIM_INFINITY};
  if (setrlimit(RLIMIT_MEMLOCK, &r)) {
    std::cerr << "setrlimit(RLIMIT_MEMLOCK) failed" << std::endl;
    exit(-1);
  }

  // Initialize DPDK eal.
  uint64_t core_mask = 0;
  auto lcores_conf = config_.get("lcores");
  for (size_t i = 0; i < lcores_conf.size(); i++) {
    auto lcore_id = lcores_conf.get(i).get_uint64();
    core_mask |= uint64_t(1) << lcore_id;
  }
  init_eal(core_mask);

  // Initialize the endpoints.
  // Create one endpoint per core for now.
  assert(lcores_conf.size() <= StaticConfig::kMaxEndpointCount);
  for (size_t i = 0; i < lcores_conf.size(); i++) {
    auto lcore_id = lcores_conf.get(i).get_uint64();
    add_endpoint(lcore_id);
  }
  for (uint16_t socket_id = 0; socket_id < endpoint_count_; socket_id++)
    umems_[socket_id] = nullptr;

  // Initialize the UMEM areas.
  init_umems();

  // Setup the port.
  auto port_conf = config_.get("port");
  if (!port_conf.exists()) {
    std::cerr << "Port undefined" << std::endl;
    exit(-1);
  }
  port_.ifindex = if_nametoindex(port_conf.get("ifname").get_str().c_str());
  port_.valid = true;
  uint32_t ipv4_addr = NetworkAddress::parse_ipv4_addr(
    port_conf.get("ipv4_addr").get_str().c_str());
  port_.ipv4_addr = ipv4_addr;

  // TODO: Remove this.
  start();
  receive(1, nullptr, 1);
  printf("Before infinite loop\n");
  while(1);
  /*
  uint64_t core_mask = 0;
  auto lcores_conf = config_.get("lcores");
  for (size_t i = 0; i < lcores_conf.size(); i++) {
    auto lcore_id = lcores_conf.get(i).get_uint64();
    core_mask |= uint64_t(1) << lcore_id;
  }
  init_eal(core_mask);
  */
  /*
  {
    uint16_t num_ports = rte_eth_dev_count_avail();
    if (StaticConfig::kVerbose)
      printf("total %" PRIu16 " ports available\n", num_ports);

    ports_.resize(num_ports);
    for (uint16_t port_id = 0; port_id < num_ports; port_id++)
      ports_[port_id].valid = false;
  }*/

  /*
  auto port_conf = config_.get("port");
  // TODO Check for error.
  port_.ifindex = if_nametoindex(port_conf.get("ifname").get_str().c_str());
  port_.valid = true;
  uint32_t ipv4_addr = NetworkAddress::parse_ipv4_addr(
    port_conf.get("ipv4_addr").get_str().c_str());
  port_.ipv4_addr = ipv4_addr;
  */

  // Parse configurations.
  /*
  auto ports_conf = config_.get("ports");
  for (size_t i = 0; i < ports_conf.size(); i++) {
    auto port_conf = ports_conf.get(i);
    uint16_t port_id = ::mica::util::safe_cast<uint16_t>(
        port_conf.get("port_id").get_uint64());
    assert(port_id < ports_.size());

    uint32_t ipv4_addr = NetworkAddress::parse_ipv4_addr(
        port_conf.get("ipv4_addr").get_str().c_str());

    ether_addr mac_addr;
    if (port_conf.get("mac_addr").exists())
      mac_addr = NetworkAddress::parse_mac_addr(
          port_conf.get("mac_addr").get_str().c_str());
    else
      rte_eth_macaddr_get(static_cast<uint8_t>(port_id), &mac_addr);

    uint16_t numa_id = get_port_numa_id(port_id);
    assert(numa_id < StaticConfig::kMaxNUMACount);

    ports_[port_id].valid = true;
    ports_[port_id].mac_addr = mac_addr;
    ports_[port_id].ipv4_addr = ipv4_addr;
    ports_[port_id].numa_id = numa_id;
    ports_[port_id].next_available_queue_id = 0;
  }*/

  auto endpoints_conf = config_.get("endpoints");
  if (endpoints_conf.exists()) {
    assert(endpoints_conf.size() <= StaticConfig::kMaxEndpointCount);
    for (size_t i = 0; i < endpoints_conf.size(); i++) {
      uint16_t lcore_id = ::mica::util::safe_cast<uint16_t>(
          endpoints_conf.get(i).get(0).get_uint64());

      uint16_t port_id = ::mica::util::safe_cast<uint16_t>(
          endpoints_conf.get(i).get(1).get_uint64());
      assert(ports_[port_id].valid);

      //add_endpoint(lcore_id, port_id);
    }
  } else {
    uint16_t next_lcore_id[StaticConfig::kMaxNUMACount] = {
        0,
    };
    for (uint16_t port_id = 0; port_id < ports_.size(); port_id++) {
      if (!ports_[port_id].valid) continue;

      uint16_t endpoint_count = 0;

      struct rte_eth_link link;
      while (true) {
        if (StaticConfig::kVerbose)
          printf("querying port %" PRIu16 "...\n", port_id);

        rte_eth_link_get(static_cast<uint8_t>(port_id), &link);

        if (!link.link_status) {
          printf("warning: port %" PRIu16 ": link down; retrying...\n",
                 port_id);
          sleep(1);
          continue;
        }
        if (link.link_speed / 1000 < StaticConfig::kMinLinkSpeed) {
          printf("warning: port %" PRIu16 ": low speed (current: %" PRIu32
                 " Gbps, minimum: %" PRIu32 " Gbps); retrying...\n",
                 port_id, link.link_speed / 1000, StaticConfig::kMinLinkSpeed);
          sleep(1);
          continue;
        }
        break;
      }

      switch (link.link_speed) {
        case ETH_SPEED_NUM_10M:
        case ETH_SPEED_NUM_100M:
        case ETH_SPEED_NUM_1G:
        case ETH_SPEED_NUM_10G:
          endpoint_count = 2;
          break;
        case ETH_SPEED_NUM_20G:
          endpoint_count = 4;
          break;
        case ETH_SPEED_NUM_40G:
          endpoint_count = 8;
          break;
        default:
          if (StaticConfig::kVerbose)
            printf("unknown link speed for port %" PRIu16 ": %" PRIu32 "\n",
                   port_id, link.link_speed);
          endpoint_count = static_cast<uint16_t>(link.link_speed / 5000);
          break;
      }

      size_t numa_id = ports_[port_id].numa_id;

      for (uint16_t j = 0; j < endpoint_count; j++) {
        while (true) {
          next_lcore_id[numa_id] = static_cast<uint16_t>(
              next_lcore_id[numa_id] % ::mica::util::lcore.lcore_count());
          if (::mica::util::lcore.numa_id(next_lcore_id[numa_id]) != numa_id)
            next_lcore_id[numa_id]++;
          else
            break;
        }

        //add_endpoint(next_lcore_id[numa_id]++, port_id);
      }
    }
  }

  //init_mempool();
}

template <class StaticConfig>
AFXDP<StaticConfig>::~AFXDP() {
  if (started_) stop();

  for (int i = 0; i < rte_argc_; i++) free(rte_argv_[i]);
}

template <class StaticConfig>
uint16_t AFXDP<StaticConfig>::get_port_numa_id(uint16_t port_id) {
  int ret = rte_eth_dev_socket_id(static_cast<uint8_t>(port_id));
  assert(ret >= 0);
  return static_cast<uint16_t>(ret);
}

template <class StaticConfig>
void AFXDP<StaticConfig>::add_endpoint(uint16_t lcore_id) {
  uint16_t eid = endpoint_count_++;
  assert(eid < StaticConfig::kMaxEndpointCount);

  if (StaticConfig::kVerbose)
    printf("creating an endpoint %" PRIu16 " for lcore %" PRIu16 "\n",
           eid, lcore_id);

  auto& ei = endpoint_info_[eid];
  ei.owner_lcore_id = lcore_id;
  ei.rx_bursts = 0;
  ei.rx_packets = 0;
  ei.tx_bursts = 0;
  ei.tx_packets = 0;
  ei.tx_dropped = 0;

  ei.mac_addr = port_.mac_addr;
  ei.ipv4_addr = port_.ipv4_addr;
  ei.numa_id = port_.numa_id;

  ei.port_id = 0;
  assert(port_.next_available_queue_id != static_cast<uint16_t>(-1));
  ei.queue_id = port_.next_available_queue_id++;
  // XXX: We cannot use udp_port == 0 because fdir will never find a match?
  // ei.udp_port = static_cast<uint16_t>(1 + ei.queue_id);
  ei.udp_port = ei.queue_id;
}

template <class StaticConfig>
void AFXDP<StaticConfig>::init_eal(uint64_t core_mask) {
  rte_argc_ = 0;

  rte_argv_[rte_argc_++] = strdup("");

  char s_core_mask[1024];
  snprintf(s_core_mask, sizeof(core_mask), "%" PRIx64 "", core_mask);
  rte_argv_[rte_argc_++] = strdup("-c");
  rte_argv_[rte_argc_++] = strdup(s_core_mask);

  assert(static_cast<uint64_t>(rte_argc_) <=
         sizeof(rte_argv_) / sizeof(rte_argv_[0]));

  auto args = config_.get("dpdk_args");
  if (args.exists()) {
    assert(args.is_array());
    assert(static_cast<size_t>(rte_argc_) + args.size() <=
           sizeof(rte_argv_) / sizeof(rte_argv_[0]));
    for (size_t i = 0; i < args.size(); i++)
      rte_argv_[rte_argc_++] = strdup(args.get(i).get_str().c_str());
  }

  int ret = rte_eal_init(rte_argc_, rte_argv_);

  if (ret < 0) {
    fprintf(stderr, "error: failed to initialize DPDK EAL (err=%s)\n",
            rte_strerror(ret));
    assert(false);
    return;
  }
}

template <class StaticConfig>
struct xsk_umem_info *
AFXDP<StaticConfig>::xsk_configure_umem(void *buffer, uint64_t size)
{
  struct xsk_umem_info *umem;
  struct xsk_umem_config cfg = {
    .fill_size = XSK_RING_PROD__DEFAULT_NUM_DESCS,
    .comp_size = XSK_RING_CONS__DEFAULT_NUM_DESCS,
    .frame_size = opt_xsk_frame_size,
    .frame_headroom = XSK_UMEM__DEFAULT_FRAME_HEADROOM,
    .flags = opt_umem_flags
  };
  int ret;

  umem = (xsk_umem_info *)calloc(1, sizeof(*umem));
  if (!umem)
    exit(-1);

  ret = xsk_umem__create(&umem->umem, buffer, size, &umem->fq, &umem->cq,
             &cfg);
  if (ret)
    exit(-1);

  umem->buffer = buffer;
  return umem;
}

template <class StaticConfig>
void AFXDP<StaticConfig>::xsk_populate_fill_ring(struct xsk_umem_info *umem)
{
  int ret, i;
  uint32_t idx;

  ret = xsk_ring_prod__reserve(&umem->fq,
             XSK_RING_PROD__DEFAULT_NUM_DESCS, &idx);
  if (ret != XSK_RING_PROD__DEFAULT_NUM_DESCS)
    exit(-ret);
  for (i = 0; i < XSK_RING_PROD__DEFAULT_NUM_DESCS; i++)
    *xsk_ring_prod__fill_addr(&umem->fq, idx++) =
      i * opt_xsk_frame_size;
  xsk_ring_prod__submit(&umem->fq, XSK_RING_PROD__DEFAULT_NUM_DESCS);
}

template <class StaticConfig>
struct xsk_socket_info *
AFXDP<StaticConfig>::xsk_configure_socket(struct xsk_umem_info *umem,
                                          uint32_t queue_id, bool rx, bool tx)
{
  struct xsk_socket_config cfg;
  struct xsk_socket_info *xsk;
  struct xsk_ring_cons *rxr;
  struct xsk_ring_prod *txr;
  int ret;

  xsk = (struct xsk_socket_info *) calloc(1, sizeof(*xsk));
  if (!xsk)
    exit(-1);

  xsk->umem = umem;
  cfg.rx_size = XSK_RING_CONS__DEFAULT_NUM_DESCS;
  cfg.tx_size = XSK_RING_PROD__DEFAULT_NUM_DESCS;
  cfg.libbpf_flags = 0;
  // TODO: Add this flag when having multiple sockets per queue.
  //XSK_LIBBPF_FLAGS__INHIBIT_PROG_LOAD;
  cfg.xdp_flags = XDP_FLAGS_SKB_MODE | XDP_FLAGS_UPDATE_IF_NOEXIST;
  cfg.bind_flags = XDP_COPY;

  rxr = rx ? &xsk->rx : NULL;
  txr = tx ? &xsk->tx : NULL;
  ret = xsk_socket__create(
      &xsk->xsk, config_.get("port").get("ifname").get_str().c_str(),
      queue_id, umem->umem, rxr, txr, &cfg);
  if (ret) {
    std::cout << "xsk_socket__create: " << std::strerror(errno) << '\n';
    exit(-ret);
  }

  return xsk;
}

template <class StaticConfig>
void AFXDP<StaticConfig>::init_umems() {
  // Initialize UMEM mempool.
  for (uint16_t eid = 0; eid < endpoint_count_; eid++) {
    void *bufs = mmap(NULL, NUM_FRAMES * opt_xsk_frame_size,
                      PROT_READ | PROT_WRITE,
                      MAP_PRIVATE | MAP_ANONYMOUS, -1 ,0);
    if (bufs == MAP_FAILED) {
      std::cerr << "mmap failed" << std::endl;
      exit(-1);
    }

    struct xsk_umem_info *umem;
    umem = xsk_configure_umem(bufs, NUM_FRAMES * opt_xsk_frame_size);

    xsk_populate_fill_ring(umem);
    umems_[eid] = umem;
  }
}

template <class StaticConfig>
std::vector<typename AFXDP<StaticConfig>::EndpointId>
AFXDP<StaticConfig>::get_endpoints() const {
  std::vector<EndpointId> eids;
  eids.reserve(endpoint_count_);
  for (uint16_t eid = 0; eid < endpoint_count_; eid++) eids.push_back(eid);
  return eids;
}

template <class StaticConfig>
const typename AFXDP<StaticConfig>::EndpointInfo&
AFXDP<StaticConfig>::get_endpoint_info(EndpointId eid) const {
  assert(eid < endpoint_count_);
  return endpoint_info_[eid];
}

template <class StaticConfig>
void AFXDP<StaticConfig>::start() {
  assert(!started_);

  for (int eid = 0; eid < endpoint_count_; ++eid) {
    struct xsk_socket_info * xsk;
    // TODO Activate TX.
    endpoint_info_[eid].xsk = xsk_configure_socket(
        umems_[eid],endpoint_info_[eid].queue_id, true, false);
  }
  // TODO: Set up flow rules.
  started_ = true;
}

template <class StaticConfig>
void AFXDP<StaticConfig>::stop() {
  assert(started_);

  for (uint16_t port_id = 0; port_id < ports_.size(); port_id++) {
    if (!ports_[port_id].valid) continue;
    if (ports_[port_id].next_available_queue_id == 0) continue;

    if (StaticConfig::kVerbose)
      printf("stopping port %" PRIu16 "...\n", port_id);
    rte_eth_dev_stop(static_cast<uint8_t>(port_id));
  }

  for (uint16_t port_id = 0; port_id < ports_.size(); port_id++) {
    if (!ports_[port_id].valid) continue;

    if (StaticConfig::kVerbose)
      printf("closing port %" PRIu16 "...\n", port_id);
    rte_eth_dev_close(static_cast<uint8_t>(port_id));
  }

  started_ = false;
}

template <class StaticConfig>
typename AFXDP<StaticConfig>::PacketBuffer* AFXDP<StaticConfig>::allocate() {
  assert(false);
  return nullptr;
}

template <class StaticConfig>
typename AFXDP<StaticConfig>::PacketBuffer* AFXDP<StaticConfig>::clone(
    PacketBuffer* buf) {
  assert(false);
  return nullptr;
}

template <class StaticConfig>
void AFXDP<StaticConfig>::release(PacketBuffer* buf) {
  rte_pktmbuf_free(buf);
}

template <class StaticConfig>
uint16_t AFXDP<StaticConfig>::receive(EndpointId eid, PacketBuffer** bufs,
                                      uint16_t buf_count) {
  assert(eid < endpoint_count_);
  auto& ei = endpoint_info_[eid];

  assert(::mica::util::lcore.lcore_id() == ei.owner_lcore_id);

  auto port_id = ei.port_id;
  auto queue_id = ei.queue_id;


  uint32_t rcvd;
  uint32_t idx_rx = 0, idx_fq = 0;
  while (1) {
    auto xsk = ei.xsk;
    rcvd = xsk_ring_cons__peek(&xsk->rx, 1, &idx_rx);
    if (!rcvd) {
      if (xsk_ring_prod__needs_wakeup(&xsk->umem->fq)) {
        std::cout << "Needs wake-up\n";
        //poll(&poll_fd, 1, 1000000);
      }
      continue;
    }

    int ret = xsk_ring_prod__reserve(&xsk->umem->fq, rcvd, &idx_fq);
    while (ret != rcvd) {
      ret = xsk_ring_prod__reserve(&xsk->umem->fq, rcvd, &idx_fq);
    }

    for (int i = 0; i < rcvd; i++) {
     uint64_t addr = xsk_ring_cons__rx_desc(&xsk->rx, idx_rx)->addr;
     uint32_t len = xsk_ring_cons__rx_desc(&xsk->rx, idx_rx++)->len;
     uint64_t orig = xsk_umem__extract_addr(addr);

     addr = xsk_umem__add_offset_to_addr(addr);
     char *pkt = (char *) xsk_umem__get_data(xsk->umem->buffer, addr);

     std::cout << "Got " << rcvd << " packets" << std::endl;
     //hex_dump(pkt, len, addr);
     *xsk_ring_prod__fill_addr(&xsk->umem->fq, idx_fq++) = orig;
   }

   xsk_ring_prod__submit(&xsk->umem->fq, rcvd);
   xsk_ring_cons__release(&xsk->rx, rcvd);
  }

  /*
  uint16_t rx_packets =
      rte_eth_rx_burst(static_cast<uint8_t>(port_id), queue_id,
                       reinterpret_cast<rte_mbuf**>(bufs), buf_count);

  ei.rx_bursts++;
  ei.rx_packets += rx_packets;
  return rx_packets;*/
  return 1;
}

template <class StaticConfig>
uint16_t AFXDP<StaticConfig>::send(EndpointId eid, PacketBuffer** bufs,
                                  uint16_t buf_count) {
  assert(eid < endpoint_count_);
  auto& ei = endpoint_info_[eid];

  assert(::mica::util::lcore.lcore_id() == ei.owner_lcore_id);

  auto port_id = ei.port_id;
  auto queue_id = ei.queue_id;

  uint16_t tx_packets =
      rte_eth_tx_burst(static_cast<uint8_t>(port_id), queue_id,
                       reinterpret_cast<rte_mbuf**>(bufs), buf_count);

  ei.tx_bursts++;
  ei.tx_dropped +=
      static_cast<uint64_t>(buf_count) - static_cast<uint64_t>(tx_packets);
  ei.tx_packets += tx_packets;

  // TODO: Allow the user to resend packets?
  for (uint16_t i = tx_packets; i < buf_count; i++) release(bufs[i]);

  return tx_packets;
}
}
}

#endif
