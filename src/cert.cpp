#include "cert.hpp"

#include <winsock2.h>
#include <windows.h>
#include <wincrypt.h>

#include <mbedtls/ctr_drbg.h>
#include <mbedtls/ecp.h>
#include <mbedtls/entropy.h>
#include <mbedtls/error.h>
#include <mbedtls/oid.h>
#include <mbedtls/pk.h>
#include <mbedtls/x509.h>
#include <mbedtls/x509_crt.h>

#include <algorithm>
#include <cstdio>
#include <cstring>
#include <ctime>
#include <fstream>
#include <set>

namespace evan::cert {

namespace {

std::string mbedtls_err_str(int code) {
    char buf[256] = {};
    mbedtls_strerror(code, buf, sizeof(buf));
    return std::string(buf) + " (" + std::to_string(code) + ")";
}

bool write_string_file(const std::filesystem::path& p, const std::string& data, std::string& err) {
    std::ofstream out(p, std::ios::binary | std::ios::trunc);
    if (!out) {
        err = "Gagal membuat file sertifikat: " + p.string();
        return false;
    }
    out.write(data.data(), static_cast<std::streamsize>(data.size()));
    if (!out.good()) {
        err = "Gagal menulis file sertifikat: " + p.string();
        return false;
    }
    return true;
}

std::string format_x509_time(int year, int month, int day) {
    char buf[32] = {};
    std::snprintf(buf, sizeof(buf), "%04d%02d%02d000000", year, month, day);
    return std::string(buf);
}

int current_utc_year() {
    std::time_t now = std::time(nullptr);
    std::tm tm_utc{};
    gmtime_s(&tm_utc, &now);
    return tm_utc.tm_year + 1900;
}

bool gen_ec_p256_key(mbedtls_pk_context* pk, mbedtls_ctr_drbg_context* drbg, std::string& err) {
    int ret = mbedtls_pk_setup(pk, mbedtls_pk_info_from_type(MBEDTLS_PK_ECKEY));
    if (ret != 0) {
        err = "mbedtls_pk_setup gagal: " + mbedtls_err_str(ret);
        return false;
    }
    ret = mbedtls_ecp_gen_key(MBEDTLS_ECP_DP_SECP256R1, mbedtls_pk_ec(*pk), mbedtls_ctr_drbg_random, drbg);
    if (ret != 0) {
        err = "mbedtls_ecp_gen_key gagal: " + mbedtls_err_str(ret);
        return false;
    }
    return true;
}

bool set_random_positive_serial(mbedtls_x509write_cert* crt, mbedtls_ctr_drbg_context* drbg, std::string& err) {
    unsigned char serial[16] = {};
    int ret = mbedtls_ctr_drbg_random(drbg, serial, sizeof(serial));
    if (ret != 0) {
        err = "Gagal generate serial acak: " + mbedtls_err_str(ret);
        return false;
    }
    // Ensure positive ASN.1 INTEGER with non-zero leading byte
    serial[0] = static_cast<unsigned char>((serial[0] & 0x7F) | 0x01);
    ret = mbedtls_x509write_crt_set_serial_raw(crt, serial, sizeof(serial));
    if (ret != 0) {
        err = "mbedtls_x509write_crt_set_serial_raw gagal: " + mbedtls_err_str(ret);
        return false;
    }
    return true;
}

bool run_certutil(const std::string& args, std::string& err) {
    STARTUPINFOA si{};
    si.cb = sizeof(si);
    std::string cmd = "certutil.exe " + args;
    std::vector<char> cmd_buf(cmd.begin(), cmd.end());
    cmd_buf.push_back('\0');

    PROCESS_INFORMATION pi{};
    if (!CreateProcessA(nullptr, cmd_buf.data(), nullptr, nullptr, FALSE, 0, nullptr, nullptr, &si, &pi)) {
        err = "Gagal menjalankan certutil.exe (kode " + std::to_string(GetLastError()) + ")";
        return false;
    }
    WaitForSingleObject(pi.hProcess, INFINITE);
    DWORD exit_code = 1;
    GetExitCodeProcess(pi.hProcess, &exit_code);
    CloseHandle(pi.hProcess);
    CloseHandle(pi.hThread);
    if (exit_code != 0) {
        err = "certutil.exe keluar dengan kode " + std::to_string(exit_code);
        return false;
    }
    return true;
}

} // namespace

CertPaths get_cert_paths(const std::filesystem::path& cert_dir) {
    return CertPaths{
        cert_dir / "ca.pem",
        cert_dir / "ca.key.pem",
        cert_dir / "server.pem",
        cert_dir / "server.key.pem"
    };
}

bool ensure_certs(
    const std::filesystem::path& cert_dir,
    const std::vector<std::string>& san_domains,
    CertPaths& out,
    std::string& err
) {
    out = get_cert_paths(cert_dir);
    std::error_code ec;
    if (std::filesystem::exists(out.ca_cert, ec) &&
        std::filesystem::exists(out.server_cert, ec) &&
        std::filesystem::exists(out.server_key, ec)) {
        return true;
    }

    std::filesystem::create_directories(cert_dir, ec);
    if (ec) {
        err = "Gagal membuat folder certs: " + ec.message();
        return false;
    }

    mbedtls_entropy_context entropy;
    mbedtls_ctr_drbg_context drbg;
    mbedtls_pk_context ca_key;
    mbedtls_pk_context leaf_key;
    mbedtls_x509write_cert ca_crt;
    mbedtls_x509write_cert leaf_crt;

    mbedtls_entropy_init(&entropy);
    mbedtls_ctr_drbg_init(&drbg);
    mbedtls_pk_init(&ca_key);
    mbedtls_pk_init(&leaf_key);
    mbedtls_x509write_crt_init(&ca_crt);
    mbedtls_x509write_crt_init(&leaf_crt);

    auto cleanup = [&]() {
        mbedtls_x509write_crt_free(&leaf_crt);
        mbedtls_x509write_crt_free(&ca_crt);
        mbedtls_pk_free(&leaf_key);
        mbedtls_pk_free(&ca_key);
        mbedtls_ctr_drbg_free(&drbg);
        mbedtls_entropy_free(&entropy);
    };

    const char* pers = "EvanProxyCertGen";
    int ret = mbedtls_ctr_drbg_seed(&drbg, mbedtls_entropy_func, &entropy,
                                    reinterpret_cast<const unsigned char*>(pers), std::strlen(pers));
    if (ret != 0) {
        err = "mbedtls_ctr_drbg_seed gagal: " + mbedtls_err_str(ret);
        cleanup();
        return false;
    }

    if (!gen_ec_p256_key(&ca_key, &drbg, err) || !gen_ec_p256_key(&leaf_key, &drbg, err)) {
        cleanup();
        return false;
    }

    const int year = current_utc_year();
    const std::string not_before = format_x509_time(year - 1, 1, 1);
    const std::string ca_not_after = format_x509_time(year + 10, 1, 1);
    const std::string leaf_not_after = format_x509_time(year + 2, 1, 1);
    const std::string ca_subject = std::string("CN=") + CA_COMMON_NAME;

    // 1. Build self-signed Root CA
    mbedtls_x509write_crt_set_version(&ca_crt, MBEDTLS_X509_CRT_VERSION_3);
    mbedtls_x509write_crt_set_md_alg(&ca_crt, MBEDTLS_MD_SHA256);
    mbedtls_x509write_crt_set_subject_key(&ca_crt, &ca_key);
    mbedtls_x509write_crt_set_issuer_key(&ca_crt, &ca_key);

    if ((ret = mbedtls_x509write_crt_set_subject_name(&ca_crt, ca_subject.c_str())) != 0 ||
        (ret = mbedtls_x509write_crt_set_issuer_name(&ca_crt, ca_subject.c_str())) != 0 ||
        !set_random_positive_serial(&ca_crt, &drbg, err) ||
        (ret = mbedtls_x509write_crt_set_validity(&ca_crt, not_before.c_str(), ca_not_after.c_str())) != 0 ||
        (ret = mbedtls_x509write_crt_set_basic_constraints(&ca_crt, 1, 0)) != 0 ||
        (ret = mbedtls_x509write_crt_set_key_usage(&ca_crt,
            MBEDTLS_X509_KU_KEY_CERT_SIGN | MBEDTLS_X509_KU_CRL_SIGN | MBEDTLS_X509_KU_DIGITAL_SIGNATURE)) != 0 ||
        (ret = mbedtls_x509write_crt_set_subject_key_identifier(&ca_crt)) != 0) {
        if (err.empty()) err = "Gagal menyusun sertifikat CA: " + mbedtls_err_str(ret);
        cleanup();
        return false;
    }

    unsigned char ca_pem_buf[4096] = {};
    unsigned char ca_key_buf[4096] = {};
    if ((ret = mbedtls_x509write_crt_pem(&ca_crt, ca_pem_buf, sizeof(ca_pem_buf),
                                         mbedtls_ctr_drbg_random, &drbg)) != 0 ||
        (ret = mbedtls_pk_write_key_pem(&ca_key, ca_key_buf, sizeof(ca_key_buf))) != 0) {
        err = "Gagal menulis PEM CA: " + mbedtls_err_str(ret);
        cleanup();
        return false;
    }

    // 2. Build leaf server cert with SANs signed by CA
    mbedtls_x509write_crt_set_version(&leaf_crt, MBEDTLS_X509_CRT_VERSION_3);
    mbedtls_x509write_crt_set_md_alg(&leaf_crt, MBEDTLS_MD_SHA256);
    mbedtls_x509write_crt_set_subject_key(&leaf_crt, &leaf_key);
    mbedtls_x509write_crt_set_issuer_key(&leaf_crt, &ca_key);

    if ((ret = mbedtls_x509write_crt_set_subject_name(&leaf_crt, "CN=www.growtopia1.com")) != 0 ||
        (ret = mbedtls_x509write_crt_set_issuer_name(&leaf_crt, ca_subject.c_str())) != 0 ||
        !set_random_positive_serial(&leaf_crt, &drbg, err) ||
        (ret = mbedtls_x509write_crt_set_validity(&leaf_crt, not_before.c_str(), leaf_not_after.c_str())) != 0 ||
        (ret = mbedtls_x509write_crt_set_basic_constraints(&leaf_crt, 0, -1)) != 0 ||
        (ret = mbedtls_x509write_crt_set_key_usage(&leaf_crt,
            MBEDTLS_X509_KU_DIGITAL_SIGNATURE | MBEDTLS_X509_KU_KEY_ENCIPHERMENT)) != 0 ||
        (ret = mbedtls_x509write_crt_set_subject_key_identifier(&leaf_crt)) != 0 ||
        (ret = mbedtls_x509write_crt_set_authority_key_identifier(&leaf_crt)) != 0) {
        if (err.empty()) err = "Gagal menyusun sertifikat server: " + mbedtls_err_str(ret);
        cleanup();
        return false;
    }

    mbedtls_asn1_sequence eku_seq{};
    eku_seq.buf.tag = MBEDTLS_ASN1_OID;
    eku_seq.buf.p = reinterpret_cast<unsigned char*>(const_cast<char*>(MBEDTLS_OID_SERVER_AUTH));
    eku_seq.buf.len = MBEDTLS_OID_SIZE(MBEDTLS_OID_SERVER_AUTH);
    eku_seq.next = nullptr;
    if ((ret = mbedtls_x509write_crt_set_ext_key_usage(&leaf_crt, &eku_seq)) != 0) {
        err = "Gagal menyetel EKU serverAuth: " + mbedtls_err_str(ret);
        cleanup();
        return false;
    }

    std::set<std::string> unique_domains = {
        "www.growtopia1.com",
        "www.growtopia2.com",
        "growtopia1.com",
        "growtopia2.com",
        "localhost"
    };
    for (const auto& d : san_domains) {
        if (!d.empty()) unique_domains.insert(d);
    }

    std::vector<std::string> domain_storage(unique_domains.begin(), unique_domains.end());
    std::vector<mbedtls_x509_san_list> san_nodes(domain_storage.size());
    for (size_t i = 0; i < domain_storage.size(); ++i) {
        std::memset(&san_nodes[i], 0, sizeof(mbedtls_x509_san_list));
        san_nodes[i].node.type = MBEDTLS_X509_SAN_DNS_NAME;
        san_nodes[i].node.san.unstructured_name.tag = MBEDTLS_ASN1_IA5_STRING;
        san_nodes[i].node.san.unstructured_name.p =
            reinterpret_cast<unsigned char*>(const_cast<char*>(domain_storage[i].data()));
        san_nodes[i].node.san.unstructured_name.len = domain_storage[i].size();
        san_nodes[i].next = (i + 1 < san_nodes.size()) ? &san_nodes[i + 1] : nullptr;
    }

    if ((ret = mbedtls_x509write_crt_set_subject_alternative_name(&leaf_crt, &san_nodes[0])) != 0) {
        err = "Gagal menyetel SAN sertifikat server: " + mbedtls_err_str(ret);
        cleanup();
        return false;
    }

    unsigned char leaf_pem_buf[4096] = {};
    unsigned char leaf_key_buf[4096] = {};
    if ((ret = mbedtls_x509write_crt_pem(&leaf_crt, leaf_pem_buf, sizeof(leaf_pem_buf),
                                         mbedtls_ctr_drbg_random, &drbg)) != 0 ||
        (ret = mbedtls_pk_write_key_pem(&leaf_key, leaf_key_buf, sizeof(leaf_key_buf))) != 0) {
        err = "Gagal menulis PEM server: " + mbedtls_err_str(ret);
        cleanup();
        return false;
    }

    const std::string ca_pem_str(reinterpret_cast<const char*>(ca_pem_buf));
    const std::string ca_key_str(reinterpret_cast<const char*>(ca_key_buf));
    const std::string fullchain_str = std::string(reinterpret_cast<const char*>(leaf_pem_buf)) + ca_pem_str;
    const std::string leaf_key_str(reinterpret_cast<const char*>(leaf_key_buf));

    cleanup();

    return write_string_file(out.ca_cert, ca_pem_str, err) &&
           write_string_file(out.ca_key, ca_key_str, err) &&
           write_string_file(out.server_cert, fullchain_str, err) &&
           write_string_file(out.server_key, leaf_key_str, err);
}

bool is_ca_trusted_in_user_root() {
    HCERTSTORE store = CertOpenStore(
        CERT_STORE_PROV_SYSTEM_A,
        0,
        0,
        CERT_SYSTEM_STORE_CURRENT_USER | CERT_STORE_READONLY_FLAG,
        "ROOT"
    );
    if (!store) {
        return false;
    }

    bool found = false;
    PCCERT_CONTEXT ctx = nullptr;
    while ((ctx = CertEnumCertificatesInStore(store, ctx)) != nullptr) {
        char name_buf[256] = {};
        CertGetNameStringA(ctx, CERT_NAME_SIMPLE_DISPLAY_TYPE, 0, nullptr, name_buf, sizeof(name_buf));
        if (std::string(name_buf) == CA_COMMON_NAME) {
            found = true;
            CertFreeCertificateContext(ctx);
            break;
        }
    }
    CertCloseStore(store, 0);
    return found;
}

bool install_ca_user_root(const std::filesystem::path& ca_pem, std::string& err) {
    return run_certutil("-user -addstore Root \"" + ca_pem.string() + "\"", err);
}

bool uninstall_ca_user_root(std::string& err) {
    return run_certutil(std::string("-user -delstore Root \"") + CA_COMMON_NAME + "\"", err);
}

void load_windows_root_cas(mbedtls_x509_crt* chain) {
    if (!chain) return;
    HCERTSTORE store = CertOpenSystemStoreA(0, "ROOT");
    if (!store) return;

    PCCERT_CONTEXT ctx = nullptr;
    while ((ctx = CertEnumCertificatesInStore(store, ctx)) != nullptr) {
        mbedtls_x509_crt_parse_der(chain, ctx->pbCertEncoded, ctx->cbCertEncoded);
    }
    CertCloseStore(store, 0);
}

} // namespace evan::cert
