#ifndef HEADER_H
#define HEADER_H

#include <arpa/inet.h>
#include <array>
#include <chrono>
#include <csignal>
#include <cstddef>
#include <cstdio>
#include <cstring>
#include <iostream>
#include <netinet/in.h>
#include <netinet/ip.h>
#include <netinet/ip_icmp.h>
#include <string>
#include <sys/socket.h>
#include <unistd.h>

constexpr std::size_t MAX_HOPS = 30;
constexpr std::size_t PROBES_PER_HOP = 3;
constexpr std::uint16_t BASE_DEST_PORT = 33434;
constexpr std::size_t RECIEVE_BUFFER_SIZE = 1000;
constexpr std::size_t TIMEOUT = 100; // ms

inline int LOG_LEVEL = 0;
#define TRACE                                                                  \
  if (LOG_LEVEL > 5) {                                                         \
  std::cout << "TRACE: "
#define DEBUG                                                                  \
  if (LOG_LEVEL > 4) {                                                         \
  std::cout << "DEBUG: "
#define INFO                                                                   \
  if (LOG_LEVEL > 3) {                                                         \
  std::cout << "INFO: "
#define WARNING                                                                \
  if (LOG_LEVEL > 2) {                                                         \
  std::cout << "WARNING: "
#define ERROR                                                                  \
  if (LOG_LEVEL > 1) {                                                         \
  std::cout << "ERROR: "
#define FATAL                                                                  \
  if (LOG_LEVEL > 0) {                                                         \
  std::cout << "FATAL: "
#define ENDL                                                                   \
  " (" << __FILE__ << ":" << __LINE__ << ")" << std::endl;                     \
  }

uint16_t checksum(unsigned short *buffer, int size);

#endif
