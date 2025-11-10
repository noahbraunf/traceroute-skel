#include "utility.h"
#include <cstdint>
#include <netdb.h>
#include <netinet/in.h>
#include <netinet/ip_icmp.h>
#include <ratio>
#include <stdexcept>
#include <string>

// ****************************************************************************
// * Compute the Internet Checksum over an arbitrary buffer.
// * (written with the help of ChatGPT 3.5)
// ****************************************************************************
uint16_t checksum(unsigned short *buffer, int size) {
  unsigned long sum = 0;
  while (size > 1) {
    sum += *buffer++;
    size -= 2;
  }
  if (size == 1) {
    sum += *(unsigned char *)buffer;
  }
  sum = (sum >> 16) + (sum & 0xFFFF);
  sum += (sum >> 16);
  return (unsigned short)(~sum);
}

UniqueFd::UniqueFd(int fd) : _fd(fd) {
  if (_fd < 0) {
    throw std::runtime_error("Could not create file descriptor");
  }
}
UniqueFd::UniqueFd(UniqueFd &&other) noexcept : _fd(other._fd) {
  other._fd = -1;
}
UniqueFd &UniqueFd::operator=(UniqueFd &&other) noexcept {
  if (this != &other) {
    if (_fd >= 0)
      close(_fd);
    _fd = other._fd;
    other._fd = -1;
  }
  return *this;
}

UniqueFd::~UniqueFd() {
  if (_fd >= 0) {
    close(_fd);
  }
}

int UniqueFd::get() const { return _fd; }
UniqueFd::operator bool() const { return _fd >= 0; }

in_addr resolve_ipv4_target(std::string_view host) {
  addrinfo hints{};
  hints.ai_family = AF_INET; // ipv4
  hints.ai_socktype = SOCK_DGRAM;

  addrinfo *res = nullptr;
  const std::string host_s{host};
  int err = getaddrinfo(host_s.c_str(), nullptr, &hints, &res);
  if (err != 0) {
    throw std::runtime_error(std::string{"getaddrinfo: "} + gai_strerror(err));
  }
  in_addr addr = reinterpret_cast<sockaddr_in *>(res->ai_addr)->sin_addr;
  freeaddrinfo(res);
  return addr;
}

template <typename Timer, typename Duration>
double time_between_ms(const std::chrono::time_point<Timer, Duration> &start,
                       const std::chrono::time_point<Timer, Duration> &end) {
  return std::chrono::duration<double, std::milli>(end - start).count();
}
IcmpMatchResult
parse_icmp_response(const std::array<std::uint8_t, RECIEVE_BUFFER_SIZE> &packet,
                    ssize_t len, std::uint16_t our_id,
                    std::uint16_t expected_seq) {
  IcmpMatchResult result{};
  if (len < static_cast<ssize_t>(sizeof(iphdr))) {
    return result;
  }

  auto *ip = reinterpret_cast<const iphdr *>(packet.data());

  const unsigned int iphdr_len = ip->ihl * 4;
  if (len < iphdr_len + static_cast<ssize_t>(sizeof(icmphdr))) {
    return result;
  }

  auto *icmp = reinterpret_cast<const icmphdr *>(packet.data() + iphdr_len);
  std::uint16_t replyid = ntohs(icmp->un.echo.id);
  if (icmp->type == ICMP_ECHOREPLY) {
    std::uint16_t replyseq = ntohs(icmp->un.echo.sequence);

    if (replyid == our_id && replyseq == expected_seq) {
      result.matches = true;
      result.got_to_dest = true;
    }

    return result;
  }
  if (icmp->type == ICMP_TIME_EXCEEDED && icmp->code == ICMP_EXC_TTL) {
    const std::uint8_t *inner_packet =
        packet.data() + iphdr_len + sizeof(icmphdr);
    ssize_t inner_len = len - iphdr_len - static_cast<ssize_t>(sizeof(icmphdr));

    if (inner_len < static_cast<ssize_t>(sizeof(iphdr))) {
      return result;
    }

    auto *inner_ip = reinterpret_cast<const iphdr *>(inner_packet);
    std::size_t inner_iphdr_len = inner_ip->ihl * 4;

    if (inner_len < static_cast<ssize_t>(inner_iphdr_len + sizeof(icmphdr))) {
      return result;
    }

    auto *inner_icmp =
        reinterpret_cast<const icmphdr *>(inner_packet + inner_iphdr_len);

    if (inner_icmp->type == ICMP_ECHO) {
      std::uint16_t innerid = ntohs(inner_icmp->un.echo.id);
      std::uint16_t innerseq = ntohs(inner_icmp->un.echo.sequence);

      if (innerid == our_id && innerseq == expected_seq) {
        result.matches = true;
        result.got_to_dest = false;
      }
    }
  }
  return result;
}
void fill_ip_header(std::array<std::uint8_t, PACKET_SIZE> &packet,
                    const std::string_view dest_ip, int ttl) {
  iphdr *ip = reinterpret_cast<iphdr *>(packet.data());

  ip->version = 4;
  ip->ihl = 5; // Header length in 32-bit words (5 = 20 bytes)
  ip->tos = 0;
  ip->tot_len = htons(PACKET_SIZE); // Important: network byte order!
  // ip->id - kernel fills this with IPPROTO_RAW
  ip->frag_off = 0;
  ip->ttl = ttl; // This is what we'll increment!
  ip->protocol = IPPROTO_ICMP;
  // ip->check - kernel fills this
  const std::string dest_ip_s{dest_ip};
  ip->daddr = inet_addr(dest_ip_s.c_str());
}
void fill_icmp_header(std::array<std::uint8_t, PACKET_SIZE> &packet,
                      int sequence) {
  icmphdr *const icmp =
      reinterpret_cast<icmphdr *>(packet.data() + sizeof(iphdr));
  icmp->type = ICMP_ECHO;
  icmp->code = 0;
  icmp->un.echo.id = htons(getpid() & 0xFFFF);
  icmp->un.echo.sequence = htons(sequence);
  icmp->checksum = 0;
  icmp->checksum = checksum(reinterpret_cast<unsigned short *>(icmp),
                            PACKET_SIZE - sizeof(icmphdr));
}
