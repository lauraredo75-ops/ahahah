// config_crypto.hpp — Lecture de la memoire partagee (loader) et dechiffrement AES-256-GCM de la config/handshake.
// Module genere par RE (clustering graphe d'appels). Stubs -> adresses Ghidra.
#pragma once
namespace griffin { namespace config_crypto {
    void m_config_crypto_1800c0dc0();  // @ 1800c0dc0
    void m_config_crypto_1800c0e40();  // @ 1800c0e40  // BCrypt hash (derivation/verif)
    void m_config_crypto_1800c0f20();  // @ 1800c0f20  // BCrypt hash (derivation/verif)
    void m_config_crypto_1800c1010();  // @ 1800c1010
    void m_config_crypto_1800c1080();  // @ 1800c1080
    void m_config_crypto_1800c10e0();  // @ 1800c10e0
    void m_config_crypto_1800c1140();  // @ 1800c1140  // dechiffrement AES-256-GCM (BCrypt, ChainingModeGCM, cle 32o, label "VG_HANDSHAKE_V6")
    void m_config_crypto_1800c12d0();  // @ 1800c12d0
    void m_config_crypto_1800c1310();  // @ 1800c1310
    void m_config_crypto_1800c1360();  // @ 1800c1360
    void m_config_crypto_1800c1f70();  // @ 1800c1f70  // lit la memoire partagee du loader (OpenFileMappingW/MapViewOfFile) = licence/session/config
    void m_config_crypto_180286a20();  // @ 180286a20
}} // namespace
