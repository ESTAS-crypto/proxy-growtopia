#pragma once

#include <mbedtls/x509_crt.h>

#include <filesystem>
#include <string>
#include <vector>

namespace evan::cert {

inline constexpr const char* CA_COMMON_NAME = "EvanProxy Local CA";

struct CertPaths {
    std::filesystem::path ca_cert;
    std::filesystem::path ca_key;
    std::filesystem::path server_cert;
    std::filesystem::path server_key;
};

CertPaths get_cert_paths(const std::filesystem::path& cert_dir);

bool ensure_certs(
    const std::filesystem::path& cert_dir,
    const std::vector<std::string>& san_domains,
    CertPaths& out,
    std::string& err
);

bool is_ca_trusted_in_user_root();
bool install_ca_user_root(const std::filesystem::path& ca_pem, std::string& err);
bool uninstall_ca_user_root(std::string& err);

void load_windows_root_cas(mbedtls_x509_crt* chain);

} // namespace evan::cert
