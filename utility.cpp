#include "utility.h"
#include <netdb.h>
#include <ratio>
#include <stdexcept>
#include <string>
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
