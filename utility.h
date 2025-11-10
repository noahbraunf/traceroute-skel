#ifndef WRAPPER_H_
#define WRAPPER_H_

#include <arpa/inet.h>
#include <array>
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
constexpr std::size_t PAYLOAD_SIZE = 36; // 64 - 20 for IP - 8 for ICMP = 36
constexpr std::size_t STARTING_TTL = 2;
constexpr std::size_t RECIEVE_BUFFER_SIZE = 1000;
constexpr std::size_t TIMEOUT = 15; // seconds
//
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

  /**
   * @brief Get the underlying file descriptor
   *
   * @return int fd
   */
  int get() const;
  /**
   * @brief Check if valid file descriptor
   */
  explicit operator bool() const;

private:
  int _fd = -1;
};

struct IcmpMatchResult {
  bool matches = false;
  bool got_to_dest = false;
};

/**
 * @brief fill the IP header within a packet
 *
 * @param packet The packet to fill
 * @param dest_ip The destination of the packet
 * @param ttl The time the request will live
 */
void fill_ip_header(std::array<std::uint8_t, PACKET_SIZE> &packet,
                    const std::string_view dest_ip, int ttl);

/**
 * @brief Fill the ICMP header within a packet
 *
 * @param packet The packet to fill
 * @param sequence the sequence number of the ICMP packet
 */
void fill_icmp_header(std::array<std::uint8_t, PACKET_SIZE> &packet,
                      int sequence);
/**
 * @brief check to see if response is for our request as well as if the response
 * reached its destination
 *
 * @param packet to analyze
 * @param len length of the packet
 * @param our_id the ID of the packet we expect
 * @param expected_seq the sequence number of the packet we expect
 * @return Whether or not the packet is one of ours as well as if it got to the
 * destination
 */
IcmpMatchResult
parse_icmp_response(const std::array<std::uint8_t, RECIEVE_BUFFER_SIZE> &packet,
                    ssize_t len, std::uint16_t our_id,
                    std::uint16_t expected_seq);
#endif
