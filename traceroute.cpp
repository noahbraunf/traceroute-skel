#include "traceroute.h"
#include "utility.h"
#include <algorithm>
#include <arpa/inet.h>
#include <array>
#include <chrono>
#include <iostream>
#include <netinet/in.h>
#include <sys/select.h>
#include <sys/socket.h>
#include <unistd.h>

int main(int argc, char *argv[]) {
  std::string destIP;

  // ********************************************************************
  // * Process the command line arguments
  // ********************************************************************
  int opt = 0;
  while ((opt = getopt(argc, argv, "t:d:")) != -1) {

    switch (opt) {
    case 't':
      destIP = optarg;
      break;
    case 'd':
      LOG_LEVEL = atoi(optarg);
      ;
      break;
    case ':':
    case '?':
    default:
      std::cout << "useage: " << argv[0] << " -t [target ip] -d [Debug Level]"
                << std::endl;
      exit(-1);
    }
  }

  if (destIP.empty()) {
    FATAL << "Error: -t is required" << ENDL;
    return -1;
  }

  // Socket which we send ICMP packets from
  UniqueFd send_fd(socket(AF_INET, SOCK_RAW, IPPROTO_RAW));
  if (!send_fd) {
    FATAL << "Could not open sending socket" << ENDL;
    return -1;
  }

  // Socket which we receive ICMP packets from
  UniqueFd recv_fd(socket(AF_INET, SOCK_RAW, IPPROTO_ICMP));
  if (!recv_fd) {
    FATAL << "Could not open receiving socket" << ENDL;
    return -1;
  }

  std::array<std::uint8_t, PACKET_SIZE> send_packet{};
  memset(send_packet.data() + sizeof(iphdr) + sizeof(icmphdr), 'S',
         PACKET_SIZE - sizeof(iphdr) -
             sizeof(icmphdr)); // important to set only payload part so kernel
                               // can set up headers

  sockaddr_in dest_addr;
  memset(&dest_addr, 0, sizeof(dest_addr));
  dest_addr.sin_family = AF_INET;
  dest_addr.sin_addr.s_addr = inet_addr(destIP.c_str());

  std::uint16_t our_id =
      static_cast<uint16_t>(getpid() & 0xFFFF); // specific to our application

  DEBUG << "traceroute to " << destIP << ", " << MAX_HOPS << " hops maximum"
        << ENDL;

  std::size_t current_ttl = STARTING_TTL;
  bool reached_dest = false;

  while (current_ttl <= (1 + MAX_HOPS) && !reached_dest) {
    fill_ip_header(send_packet, destIP, current_ttl);
    fill_icmp_header(send_packet, current_ttl);

    DEBUG << "Sending probe with TTL=" << current_ttl << ENDL;

    ssize_t sent = sendto(send_fd.get(), send_packet.data(), send_packet.size(),
                          0, reinterpret_cast<sockaddr *>(&dest_addr),
                          sizeof(dest_addr)); // send ICMP request
    if (sent < 0) {
      FATAL << "Failed sending packet through socket" << ENDL;
      return 1;
    }
    auto start_time = std::chrono::steady_clock::now();
    bool got_response = false;
    while (!got_response) {
      auto now = std::chrono::steady_clock::now();
      auto elapsed =
          std::chrono::duration_cast<std::chrono::seconds>(now - start_time)
              .count();

      if (elapsed >= static_cast<long>(TIMEOUT)) {
        std::cout << current_ttl << "\tNo response with TTL of " << current_ttl
                  << std::endl;
        break;
      }

      auto remaining = TIMEOUT - elapsed;

      // do receiving of data asynchronously
      fd_set read_fds;
      FD_ZERO(&read_fds);
      FD_SET(recv_fd.get(), &read_fds); // watch recv socket
      timeval timeout;
      timeout.tv_sec = std::min(5L, static_cast<long>(remaining));
      timeout.tv_usec = 0;

      int ready = select(recv_fd.get() + 1, &read_fds, nullptr, nullptr,
                         &timeout); // wait for recv_fd to finish reading

      if (ready < 0) { // error
        FATAL << "Select failed" << ENDL;
        return 1;
      } else if (ready == 0) { // timeout reached and no data, retry
        continue;
      } else if (FD_ISSET(recv_fd.get(),
                          &read_fds)) { // data is available to read (without
                                        // any blocking!)
        std::array<std::uint8_t, RECIEVE_BUFFER_SIZE> recv_buf;
        sockaddr_in recv_addr;
        socklen_t addr_len = sizeof(recv_addr);

        ssize_t len = // this won't block because the data is available (known
                      // from select)
            recvfrom(recv_fd.get(), recv_buf.data(), recv_buf.size(), 0,
                     reinterpret_cast<sockaddr *>(&recv_addr), &addr_len);

        if (len < 0) {
          FATAL << "failed to receive data from socket" << ENDL;
          return 1;
        }

        // extract important information
        auto result = parse_icmp_response(
            recv_buf, len, our_id, static_cast<std::uint16_t>(current_ttl));

        if (result.matches) { // we got an ICMP response
          std::array<char, INET_ADDRSTRLEN> responder_ip;
          inet_ntop(AF_INET, &recv_addr.sin_addr, responder_ip.data(),
                    responder_ip.size());

          std::cout << current_ttl << "\t" << responder_ip.data();

          if (result.got_to_dest) { // we have finished our traceroute
            reached_dest = true;
            std::cout << "\t(Destination Reached)" << std::endl;
          } else {
            std::cout << std::endl;
          }

          got_response = true;
        }
      }
    }
    current_ttl++; // increment TTL if there was a timeout
  }
  return 0;
}
