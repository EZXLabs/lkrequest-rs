// Independent TLS peer: all TAI encoding and certificate selection is BoringSSL's.
#ifdef _WIN32
#define WIN32_LEAN_AND_MEAN
#define NOMINMAX
#include <winsock2.h>
#include <ws2tcpip.h>
using Socket = SOCKET;
#else
#include <arpa/inet.h>
#include <sys/select.h>
#include <sys/socket.h>
#include <unistd.h>
#include <signal.h>
using Socket = int;
#endif

#include <openssl/bytestring.h>
#include <openssl/err.h>
#include <openssl/evp.h>
#include <openssl/pool.h>
#include <openssl/ssl.h>
#include <openssl/x509.h>

#include <cstdio>
#include <cstdlib>
#include <fstream>
#include <iterator>
#include <string>
#include <vector>

static void Check(bool ok) {
  if (!ok) {
    ERR_print_errors_fp(stderr);
    std::exit(1);
  }
}

static std::vector<uint8_t> Read(const char *path) {
  std::ifstream file(path, std::ios::binary);
  Check(file.good());
  return std::vector<uint8_t>(std::istreambuf_iterator<char>(file), {});
}

static bssl::UniquePtr<EVP_PKEY> Key(const char *path) {
  auto bytes = Read(path);
  const uint8_t *cursor = bytes.data();
  bssl::UniquePtr<EVP_PKEY> key(d2i_AutoPrivateKey(nullptr, &cursor, bytes.size()));
  Check(key != nullptr && cursor == bytes.data() + bytes.size());
  return key;
}

static ssl_select_cert_result_t Observe(const SSL_CLIENT_HELLO *hello) {
  const uint8_t *data;
  size_t len;
  Check(SSL_early_callback_ctx_extension_get(hello, 0xca34, &data, &len) == 1);
  std::printf("HELLO ");
  for (size_t i = 0; i < len; i++) { std::printf("%02x", data[i]); }
  std::printf("\n");
  std::fflush(stdout);
  return ssl_select_cert_success;
}

static void Close(Socket socket) {
#ifdef _WIN32
  closesocket(socket);
#else
  close(socket);
#endif
}

int main(int argc, char **argv) {
  if (argc != 5) { return 2; }
#ifdef _WIN32
  WSADATA data;
  Check(WSAStartup(MAKEWORD(2, 2), &data) == 0);
#else
  signal(SIGPIPE, SIG_IGN);
#endif
  bssl::UniquePtr<SSL_CTX> ctx(SSL_CTX_new(TLS_method()));
  Check(ctx != nullptr);
  Check(SSL_CTX_set_min_proto_version(ctx.get(), TLS1_3_VERSION) == 1);
  Check(SSL_CTX_set_max_proto_version(ctx.get(), TLS1_3_VERSION) == 1);
  SSL_CTX_set_select_certificate_cb(ctx.get(), Observe);
  const uint8_t id[] = {0x81, 0xfd, 0x59, 1};
  const uint8_t available[] = {4, 0x81, 0xfd, 0x59, 1};
  auto der = Read(argv[1]);
  bssl::UniquePtr<CRYPTO_BUFFER> certificate(CRYPTO_BUFFER_new(der.data(), der.size(), nullptr));
  auto key = Key(argv[2]);
  bssl::UniquePtr<SSL_CREDENTIAL> credential(SSL_CREDENTIAL_new_x509());
  CRYPTO_BUFFER *chain[] = {certificate.get()};
  Check(SSL_CREDENTIAL_set1_cert_chain(credential.get(), chain, 1) == 1);
  Check(SSL_CREDENTIAL_set1_private_key(credential.get(), key.get()) == 1);
  Check(SSL_CREDENTIAL_set1_trust_anchor_id(credential.get(), id, sizeof(id)) == 1);
  SSL_CREDENTIAL_set_must_match_issuer(credential.get(), 1);
  Check(SSL_CTX_add1_credential(ctx.get(), credential.get()) == 1);
  Check(SSL_CTX_set1_available_trust_anchors(ctx.get(), available, sizeof(available)) == 1);
  auto fallback_der = Read(argv[3]);
  const uint8_t *cursor = fallback_der.data();
  bssl::UniquePtr<X509> fallback(d2i_X509(nullptr, &cursor, fallback_der.size()));
  auto fallback_key = Key(argv[4]);
  Check(SSL_CTX_use_certificate(ctx.get(), fallback.get()) == 1);
  Check(SSL_CTX_use_PrivateKey(ctx.get(), fallback_key.get()) == 1);
  Socket listener = socket(AF_INET, SOCK_STREAM, 0);
  sockaddr_in address{};
  address.sin_family = AF_INET;
  address.sin_addr.s_addr = htonl(INADDR_LOOPBACK);
  Check(bind(listener, reinterpret_cast<sockaddr *>(&address), sizeof(address)) == 0);
  Check(listen(listener, 2) == 0);
#ifdef _WIN32
  int address_len = sizeof(address);
#else
  socklen_t address_len = sizeof(address);
#endif
  Check(getsockname(listener, reinterpret_cast<sockaddr *>(&address), &address_len) == 0);
  std::printf("PORT %u\n", ntohs(address.sin_port));
  std::fflush(stdout);
  for (int attempt = 0; attempt < 2; attempt++) {
    fd_set readers;
    FD_ZERO(&readers);
    FD_SET(listener, &readers);
    timeval wait{10, 0};
    Check(select(static_cast<int>(listener) + 1, &readers, nullptr, nullptr, &wait) == 1);
    Socket peer = accept(listener, nullptr, nullptr);
#ifdef _WIN32
    DWORD timeout = 10000;
#else
    timeval timeout{10, 0};
#endif
    setsockopt(peer, SOL_SOCKET, SO_RCVTIMEO, reinterpret_cast<const char *>(&timeout), sizeof(timeout));
    bssl::UniquePtr<SSL> ssl(SSL_new(ctx.get()));
    Check(SSL_set_fd(ssl.get(), static_cast<int>(peer)) == 1);
    int result = SSL_accept(ssl.get());
    if (attempt == 0) {
      Check(result != 1);
      std::printf("REJECTED 0\n");
      ERR_clear_error();
    } else {
      Check(result == 1);
      std::string request;
      char byte;
      while (request.size() < 4096 && request.find("\r\n\r\n") == std::string::npos) {
        Check(SSL_read(ssl.get(), &byte, 1) == 1);
        request.push_back(byte);
      }
      Check(request.find("POST /test HTTP/1.1\r\n") == 0);
      Check(request.find("\r\n\r\n") != std::string::npos);
      std::string body;
      while (body.size() < 7) { Check(SSL_read(ssl.get(), &byte, 1) == 1); body.push_back(byte); }
      Check(body == "payload");
      const char reply[] = "HTTP/1.1 200 OK\r\nContent-Length: 2\r\nConnection: close\r\n\r\nok";
      Check(SSL_write(ssl.get(), reply, sizeof(reply) - 1) == sizeof(reply) - 1);
      std::printf("REQUESTS 1\n");
    }
    Close(peer);
  }
  Close(listener);
  std::fflush(stdout);
  return 0;
}
