#ifndef WRAPPER_H_
#define WRAPPER_H_

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

constexpr std::size_t MAX_HOPS = 30;
constexpr std::size_t PACKET_SIZE = 64;
constexpr std::size_t PAYLOAD_SIZE = 36; // 64 - 20 for IP - 8 for ICMP
constexpr std::size_t STARTING_TTL = 2;
constexpr std::size_t RECIEVE_BUFFER_SIZE = 1000;
constexpr std::size_t TIMEOUT = 15; // seconds
uint16_t checksum(unsigned short *buffer, int size);
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

void fill_ip_header(std::array<std::uint8_t, PACKET_SIZE> &packet,
                    const std::string_view dest_ip, int ttl);

void fill_icmp_header(std::array<std::uint8_t, PACKET_SIZE> &packet,
                      int sequence);
IcmpMatchResult
parse_icmp_response(const std::array<std::uint8_t, RECIEVE_BUFFER_SIZE> &packet,
                    ssize_t len, std::uint16_t our_id,
                    std::uint16_t expected_seq);
#endif
