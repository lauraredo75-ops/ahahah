// dllmain.cpp — flux reconstruit de griffin (payload injecte dans Valorant)
#include <windows.h>
#include "modules/injection.hpp"
#include "modules/config_crypto.hpp"
#include "modules/overlay_menu.hpp"
// Export reel observe : ngYm2pXk7rTv4wBc9qFj5hLs3aNe6uDi (hook proc). Ici: HookProc.
extern "C" __declspec(dllexport) LRESULT CALLBACK HookProc(int code, WPARAM w, LPARAM l) {
    // @180134a00 : au 1er fire -> vg_handshake::hook_first_fire_verify (@1800c25d0),
    // si OK -> CheatInit (lecture shmem @1800c1f70 + dechiffrement @1800c1140, puis overlay @180130c70).
    griffin::injection::m_injection_180134a00();
    return CallNextHookEx(nullptr, code, w, l);
}
BOOL APIENTRY DllMain(HMODULE, DWORD reason, LPVOID) {
    if (reason == DLL_PROCESS_ATTACH) { /* init differee via HookProc dans Valorant */ }
    return TRUE;
}
