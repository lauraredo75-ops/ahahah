// injection.hpp — Point d entree injecte dans Valorant (hook proc) + handshake Vanguard + CheatInit.
// Module genere par RE (clustering graphe d'appels). Stubs -> adresses Ghidra.
#pragma once
namespace griffin { namespace injection {
    void m_injection_1800c1410();  // @ 1800c1410
    void m_injection_1800c1430();  // @ 1800c1430
    void m_injection_1800c1f70();  // @ 1800c1f70  // lit la memoire partagee du loader (OpenFileMappingW/MapViewOfFile) = licence/session/config
    void m_injection_1800c2580();  // @ 1800c2580
    void m_injection_1800c25d0();  // @ 1800c25d0  // vg_handshake::hook_first_fire_verify() — handshake/anti-Vanguard, gate de CheatInit
    void m_injection_1800c2600();  // @ 1800c2600
    void m_injection_180131a80();  // @ 180131a80  // logger debug (wsprintfA -> immortal_dbg.log / OutputDebugString)
    void m_injection_1802b58e0();  // @ 1802b58e0
    void m_injection_180134a00();  // @ 180134a00  // EXPORT hook proc (charge dans Valorant via SetWinEventHook/SetWindowsHookEx) ; 1er fire -> vg_handshake puis CheatInit
}} // namespace
