#ifndef WRAPPER_H_
#define WRAPPER_H_

#include "traceroute.h"
#include <arpa/inet.h>
#include <array>
#include <chrono>
#include <cstdint>
#include <netdb.h>
#include <netinet/in.h>
#include <netinet/ip.h>
#include <netinet/ip_icmp.h>
#include <netinet/udp.h>
#include <poll.h>
#include <string_view>
#include <sys/socket.h>
#include <sys/types.h>
#include <unistd.h>

class UniqueFd {
public:
  UniqueFd() = default;
  explicit UniqueFd(int fd);
  UniqueFd(const UniqueFd &) = delete;
  UniqueFd &operator=(const UniqueFd &) = delete;
  UniqueFd(UniqueFd &&other) noexcept;
  UniqueFd &operator=(UniqueFd &&other) noexcept;

  ~UniqueFd();

  int get() const;
  explicit operator bool() const;

private:
  int _fd = -1;
};

struct IcmpMatchResult {
  bool matches = false;
  bool got_to_dest = false;
};

in_addr resolve_ipv4_target(std::string_view host);

template <typename Timer, typename Duration>
double time_between_ms(const std::chrono::time_point<Timer, Duration> &start,
                       const std::chrono::time_point<Timer, Duration> &end);

IcmpMatchResult
match_icmp_probe(const std::array<std::uint8_t, RECIEVE_BUFFER_SIZE> buf,
                 ssize_t len, std::size_t ttl, std::size_t probe,
                 std::size_t probes_per_hop, std::uint16_t base_dest_port,
                 in_addr dest_addr

) {
  IcmpMatchResult result{};
  if (len < static_cast<ssize_t>(sizeof(iphdr))) {
    return result;
  }

  auto *ip = reinterpret_cast<const iphdr *>(buf.data());

  const unsigned int iphdr_len = ip->ihl * 4;
  if (len < iphdr_len + static_cast<ssize_t>(sizeof(icmphdr))) {
    return result;
  }

  auto *icmp = reinterpret_cast<const icmphdr *>(buf.data() + iphdr_len);
  if (icmp->type != ICMP_TIME_EXCEEDED && icmp->type != ICMP_DEST_UNREACH) {
    return result;
  }

  const std::uint8_t *inner = buf.data() + iphdr_len + sizeof(icmphdr);
  const ssize_t inner_len =
      len - iphdr_len - static_cast<ssize_t>(sizeof(icmphdr));
  if (inner_len < static_cast<ssize_t>(sizeof(iphdr))) {
    return result;
  }

  auto *inner_ip = reinterpret_cast<const iphdr *>(inner);
  const unsigned int inner_iphdr_len = inner_ip->ihl * 4;
  if (inner_len < inner_iphdr_len + static_cast<ssize_t>(sizeof(udphdr))) {
    return result;
  }
  if (inner_ip->protocol != IPPROTO_UDP)
    return result;

  auto *inner_udp = reinterpret_cast<const udphdr *>(inner + inner_iphdr_len);
  const uint16_t dest_port = ntohs(inner_udp->dest);
  const uint16_t expected_port =
      static_cast<uint16_t>(base_dest_port + ttl * probes_per_hop);
  if (dest_port != expected_port || inner_ip->daddr != dest_addr.s_addr) {
    return result;
  }

  result.matches = true;
  result.got_to_dest = true;
  return result;
}
#endif
