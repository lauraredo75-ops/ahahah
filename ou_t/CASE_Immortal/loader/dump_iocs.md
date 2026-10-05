# IOC extraits du dump mÃ©moire (pe-sieve) â€” Emulator.vmp.exe

## Domaines / C2
- eOW.rU
- immortal-authentication.com
- vg.ac.pvp.net
- zE.co

## URLs (hors certificats Microsoft)

## Endpoints API
- /api/v4/binary-fetch
- /api/v4/challenge
- /api/v4/griffin-grant
- /api/v4/heartbeat
- /api/v4/login
- /api/v4/pak-key

## Auth / branding / injection
- restart Valorant, then press AUTH again.
- Valorant-
- Valorant
- "license_key":"
- .?AV?$_Func_base@XW4AuthState@v4@auth@immortal@@W4ErrorKind@234@@std@@
- .?AV?$_Func_impl_no_alloc@V<lambda_1>@?1??immortal_do_auth@immortal@@YA_NPEBDV?$function@$$A6AXXZ@std@@@Z@XW4AuthState@v4@auth@3@W4ErrorKind@783@@std@@
- .?AV?$_Func_impl_no_alloc@V<lambda_1>@?2??DoAuth@@YA_NAEBV?$basic_string@DU?$char_traits@D@std@@V?$allocator@D@2@@std@@@Z@X$$V@std@@
- .?AV?$_Func_impl_no_alloc@V<lambda_2_>@v4@auth@immortal@@_K$$V@std@@
- .?AV?$_Func_impl_no_alloc@V<lambda_2>@?1??immortal_do_auth@immortal@@YA_NPEBDV?$function@$$A6AXXZ@std@@@Z@_N$$V@std@@
- .?AV?$_Func_impl_no_alloc@V<lambda_3>@?1??immortal_do_auth@immortal@@YA_NPEBDV?$function@$$A6AXXZ@std@@@Z@X$$V@std@@
- .?AV<lambda_1>@?1??immortal_do_auth@immortal@@YA_NPEBDV?$function@$$A6AXXZ@std@@@Z@
- .?AV<lambda_1>@?2??DoAuth@@YA_NAEBV?$basic_string@DU?$char_traits@D@std@@V?$allocator@D@2@@std@@@Z@
- .?AV<lambda_2_>@v4@auth@immortal@@
- .?AV<lambda_2>@?1??immortal_do_auth@immortal@@YA_NPEBDV?$function@$$A6AXXZ@std@@@Z@
- .?AV<lambda_3>@?1??immortal_do_auth@immortal@@YA_NPEBDV?$function@$$A6AXXZ@std@@@Z@
- .?AVCanonicalError@v4@auth@immortal@@
- .?AVIDeviceKey@v4@auth@immortal@@
- .?AVLoaderDeviceKey@boot@v4@auth@immortal@@
- /api/v4/login
- : authorization denied.
- [guard] Valorant not running - skipping VerificationWorker
- [loader stage A.5] resolving ui_thread_id (val_pid=%lu)
- [loader stage A.6] ui_thread_id returned val_tid=%lu
- [loader stage A] launch_private entry: dll_bytes=%lu sess_hex_len=%d license_key_len=%d
- [loader stage C] seal_into_shmem: val_pid=%lu pak_present=1 sess_hex_ok=%d
- [loader stage D] SetWinEventHook val_pid=%lu val_tid=%lu (hook filter thread=0, any-thread) export=%.32s
- [loader stage E] Valorant HWND=%p val_tid=%lu
- [Login] /api/v4/login returned http=%ld body=%zu sig=%zu status=%.32s ec=%.32s
- [Login] posting /api/v4/login
- Authorization
- Authorization Denied
- Authorization: Basic
- Auto-inject armed - waiting for Valorant
- immortal_dbg.log
- immortal-authentication.com
- Immortal-Auth-v4
- immortal-auth-v4|
- immortal-auth-v4|pak-key-wrap|
- Immortal-Loader-v6
- Injecting into Valorant...

## Anti-analyse / anti-debug
- %s[2]%s  %sEmulator + Private%s  %s(auto-inject)%s
- [loader stage A.1] dll_bytes sha256=%.64s
- [loader stage A.5] resolving ui_thread_id (val_pid=%lu)
- [loader stage A.6] ui_thread_id returned val_tid=%lu
- [loader stage A] launch_private entry: dll_bytes=%lu sess_hex_len=%d license_key_len=%d
- [loader stage B.2] pak-key ok=%d http=%d diag=%.64s
- [loader stage C] seal_into_shmem: val_pid=%lu pak_present=1 sess_hex_ok=%d
- [loader stage D FAIL] SetWinEventHook err=%lu
- [loader stage D] SetWinEventHook val_pid=%lu val_tid=%lu (hook filter thread=0, any-thread) export=%.32s
- [loader stage E.1] SetForegroundWindow rv=%d err=%lu (fg=%p)
- [loader stage E] Valorant HWND=%p val_tid=%lu
- [loader stage F.2] DeleteFile after FreeLibrary rv=%d err=%lu -> dll_mapped_elsewhere=%d
- [tick] KILLING: dbg=%d hwbp=%d retools=%d frida=%d inject=%d wdbg=%d patch_auth=%d patch_cookie=%d cookie_miss=%d
- \\.\pipe\frida
- Auto-inject armed - waiting for Valorant
- frida
- frida_agent_main
- Friday
- Injecting into Valorant...
- Internal Already Injecting
- Internal Inject F2
- Internal Injected
- Internal Injecting
- valorantI
- VMProtectIsDebuggerPresent

## ClÃ©s cryptographiques embarquÃ©es
- **RSA PRIVATE KEY embarquÃ©e** dÃ©tectÃ©e (longueur bloc ~3186 chars) â†’ sauvegardÃ©e dans `embedded_private_key.pem` (local, non affichÃ©e ici).
  PremiÃ¨re ligne : `-----BEGIN RSA PRIVATE KEY-----`
