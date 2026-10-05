// net_c2.hpp — Communications HTTP(S) propres au payload (telemetrie / relais emu).
// Module genere par RE (clustering graphe d'appels). Stubs -> adresses Ghidra.
#pragma once
namespace griffin { namespace net_c2 {
    void m_net_c2_18000c3c0();  // @ 18000c3c0
    void m_net_c2_18000c4a0();  // @ 18000c4a0
    void m_net_c2_18000c630();  // @ 18000c630
    void m_net_c2_180115260();  // @ 180115260  // HTTP GET (InternetOpenUrlA) vers C2/relais
    void m_net_c2_180131120();  // @ 180131120  // HTTP(S) request (WinHttpSendRequest) vers C2
    void m_net_c2_18013c2d0();  // @ 18013c2d0
    void m_net_c2_18015b870();  // @ 18015b870
    void m_net_c2_18015d1c0();  // @ 18015d1c0
    void m_net_c2_18016af10();  // @ 18016af10
    void m_net_c2_180188910();  // @ 180188910
}} // namespace
