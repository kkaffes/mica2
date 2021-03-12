#pragma once
#ifndef MICA_NETWORK_AF_XDP_H_
#define MICA_NETWORK_AF_XDP_H_

#include "mica/common.h"
#include "bpf/libbpf.h"
#include <algorithm>
#include <limits>
#include <numeric>
#include <vector>
#include <rte_common.h>
#include <rte_eal.h>
#include <rte_ethdev.h>
#include <rte_eth_ctrl.h>
#include <rte_log.h>
#include <rte_errno.h>
#include <unistd.h>
#include "mica/util/config.h"
#include "mica/util/lcore.h"
#include "mica/network/packet_io.h"
#include "mica/network/network_addr.h"

#include "bpf/xsk.h"

typedef rte_ether_addr ether_addr;

// Configuration file entries for DPDK:
//
//  * lcores (array): A list of lcore IDs to allow using with DPDK EAL.
//  * ports (array): A list of the port information dict:
//    * port_id (integer): The port ID.
//    * max_queue_count (integer): The maximum number of queues to use.
//    * ipv4_addr (string): The IP address to use.
//    * mac_addr (string): The MAC address to use.  Default = (the first
//      detected MAC address)
//  * endpoints (array): A list of [lcore_id, port_id] pairs. Default = (At most
//    1 lcore per 5 Gb/s).

namespace mica {
namespace network {
struct BasicAFXDPConfig {
  // The maximum number of NUMA domains to support.
  static constexpr uint16_t kMaxNUMACount = 8;

  // The maximum number of endpoints to support.
  static constexpr uint16_t kMaxEndpointCount = 256;

  // The number of packets to send or receive at once.
  // static constexpr uint16_t kMaxBurstSize = 32;

  // The number of RX/TX descriptors in each queue.
  static constexpr uint16_t kRXDescCount = 128;
  static constexpr uint16_t kTXDescCount = 512;

  // The number of spare packet buffer count per queue.
  static constexpr uint16_t kSpareMBufCount =
      4096 - kRXDescCount - kTXDescCount;

  // The minimum required link speed (Gbps).
  static constexpr uint32_t kMinLinkSpeed = 10;

  // Be verbose.
  static constexpr bool kVerbose = false;
};

struct xsk_umem_info {
  struct xsk_ring_prod fq;
  struct xsk_ring_cons cq;
  struct xsk_umem *umem;
  void *buffer;
};

struct xsk_socket_info {
  struct xsk_ring_cons rx;
  struct xsk_ring_prod tx;
  struct xsk_umem_info *umem;
  struct xsk_socket *xsk;
  uint32_t outstanding_tx;
};

template <class StaticConfig = BasicAFXDPConfig>
class AFXDP : public PacketIOInterface {
 public:
  struct PacketBuffer : public rte_mbuf {
   //uint16_t length;
   //uint64_t
   public:
    uint16_t get_length() const { return rte_pktmbuf_data_len(this); }
    uint16_t get_headroom() const { return rte_pktmbuf_headroom(this); }
    uint16_t get_tailroom() const { return rte_pktmbuf_tailroom(this); }

    char* get_data() { return rte_pktmbuf_mtod(this, char*); }
    const char* get_data() const { return rte_pktmbuf_mtod(this, const char*); }

    void set_length(uint16_t len) {
      // Assume a single segment packet (implied by ETH_TXQ_FLAGS_NOMULTSEGS).
      assert(rte_pktmbuf_is_contiguous(this));
      rte_pktmbuf_pkt_len(this) = rte_pktmbuf_data_len(this) = len;
      assert(rte_pktmbuf_is_contiguous(this));
    }
    char* prepend(uint16_t len) { return rte_pktmbuf_prepend(this, len); }
    char* append(uint16_t len) { return rte_pktmbuf_append(this, len); }
    char* adj(uint16_t len) { return rte_pktmbuf_adj(this, len); }
    char* trim(uint16_t len) { return rte_pktmbuf_trim(this, len); }

    PacketBuffer(const PacketBuffer& o) = delete;
    PacketBuffer& operator=(const PacketBuffer& o) = delete;
  };

  typedef uint32_t EndpointId;
  static constexpr EndpointId kInvalidEndpointId =
      std::numeric_limits<EndpointId>::max();

  static constexpr uint16_t kMaxEndpointCount = StaticConfig::kMaxEndpointCount;

  struct EndpointInfo {
    uint16_t owner_lcore_id;

    volatile uint64_t rx_bursts;
    volatile uint64_t rx_packets;

    volatile uint64_t tx_bursts;
    volatile uint64_t tx_packets;
    volatile uint64_t tx_dropped;

    // Specific to DPDK.
    // Values copied from Port.
    ether_addr mac_addr;
    uint32_t ipv4_addr;
    uint16_t numa_id;

    // UDP port for flow direction.
    uint16_t udp_port;

    // AF_XDP socket.
    struct xsk_socket_info * xsk;

   private:
    friend AFXDP<StaticConfig>;

    uint16_t port_id;
    uint16_t queue_id;
  } __attribute__((aligned(128)));

  // static constexpr uint16_t kMaxBurstSize = StaticConfig::kMaxBurstSize;

  AFXDP(const ::mica::util::Config& config);
  ~AFXDP();

  std::vector<EndpointId> get_endpoints() const;
  const EndpointInfo& get_endpoint_info(EndpointId eid) const;

  void start();
  void stop();

  PacketBuffer* allocate();
  PacketBuffer* clone(PacketBuffer* buf);
  void release(PacketBuffer* buf);

  uint16_t receive(EndpointId eid, PacketBuffer** bufs, uint16_t buf_count);
  uint16_t send(EndpointId eid, PacketBuffer** bufs, uint16_t buf_count);

 private:
  ::mica::util::Config config_;

  void init_eal(uint64_t core_mask);
  void init_umems();

  static struct xsk_umem_info *xsk_configure_umem(void *buffer, uint64_t size);
  static void xsk_populate_fill_ring(struct xsk_umem_info *umem);
  struct xsk_socket_info *xsk_configure_socket(
      struct xsk_umem_info *umem, uint32_t queue_id,bool rx, bool tx);
  static uint16_t get_port_numa_id(uint16_t port_id);

  void add_endpoint(uint16_t lcore_id);

  struct Port {
    uint8_t valid;

    ether_addr mac_addr;
    uint32_t ipv4_addr;
    uint32_t ifindex;
    uint16_t numa_id;

    uint16_t max_queue_count;
    uint16_t next_available_queue_id;
  };

  int rte_argc_;
  char* rte_argv_[100];

  rte_mempool* mempools_[StaticConfig::kMaxNUMACount];
  struct xsk_umem_info* umems_[StaticConfig::kMaxEndpointCount];
  std::vector<Port> ports_;
  Port port_;

  uint16_t endpoint_count_;
  EndpointInfo endpoint_info_[StaticConfig::kMaxEndpointCount];

  bool started_;
};
}
}

#include "mica/network/af_xdp_impl.h"

#endif
