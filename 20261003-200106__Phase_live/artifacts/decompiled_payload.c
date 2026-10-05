/* Pseudo-C reconstruit par Ghidra (analyzeHeadless). NON source d'origine. */

/* ---- FUN_180001000 @ 180001000 ---- */

/* WARNING: Globals starting with '_' overlap smaller symbols at the same address */

void FUN_180001000(void)

{
  _DAT_18001c8e8 = GetTickCount();
  return;
}



/* ---- FUN_180001020 @ 180001020 ---- */

/* WARNING: Function: __security_check_cookie replaced with injection: security_check_cookie */

undefined8 FUN_180001020(LPCSTR param_1,LPWSTR param_2,DWORD param_3)

{
  DWORD DVar1;
  undefined1 (*pauVar2) [16];
  undefined4 extraout_var;
  undefined1 auStackY_a68 [32];
  WCHAR local_a38 [264];
  WCHAR local_828 [1024];
  ulonglong local_28;
  
  local_28 = DAT_18001c000 ^ (ulonglong)auStackY_a68;
  local_a38[0] = L'\0';
  GetModuleFileNameW((HMODULE)0x0,local_a38,0x104);
  pauVar2 = FUN_180002e10((undefined1 (*) [16])local_a38,0x5c);
  if (pauVar2 != (undefined1 (*) [16])0x0) {
    *(undefined2 *)(*pauVar2 + 2) = 0;
  }
  wcsncat_s(local_a38,0x104,L"VMProtectLicense.ini",0x104);
  FUN_180003320((undefined1 (*) [16])local_828,0,0x800);
  MultiByteToWideChar(0,0,param_1,-1,local_828,0x400);
  DVar1 = GetPrivateProfileStringW(L"TestLicense",local_828,L"",param_2,param_3,local_a38);
  return CONCAT71((int7)(CONCAT44(extraout_var,DVar1) >> 8),DVar1 != 0);
}



/* ---- FUN_180001130 @ 180001130 ---- */

undefined8 FUN_180001130(void)

{
  return 1;
}



/* ---- VMProtectActivateLicense @ 180001140 ---- */

/* WARNING: Function: _alloca_probe replaced with injection: alloca_probe */
/* WARNING: Function: __security_check_cookie replaced with injection: security_check_cookie */

undefined4 VMProtectActivateLicense(char *param_1,char *param_2,int param_3)

{
  char *pcVar1;
  char cVar2;
  char cVar3;
  undefined4 uVar4;
  undefined8 uVar5;
  longlong lVar6;
  undefined1 auStackY_1868 [32];
  CHAR local_1828;
  char acStack_1827 [2047];
  WCHAR local_1028 [2048];
  ulonglong local_28;
  undefined8 uStack_20;
  longlong lVar7;
  
                    /* 0x1140  1  VMProtectActivateLicense */
  uStack_20 = 0x18000114e;
  local_28 = DAT_18001c000 ^ (ulonglong)auStackY_1868;
  if (param_1 == (char *)0x0) {
    uVar4 = 6;
  }
  else {
    uVar5 = FUN_180001020("AcceptedActivationCode",local_1028,0x1000);
    if ((char)uVar5 == '\0') {
      local_1828 = '\0';
      strcpy_s(&local_1828,0x800,"activationcode");
    }
    else {
      WideCharToMultiByte(0,0,local_1028,-1,&local_1828,0x800,(LPCSTR)0x0,(LPBOOL)0x0);
    }
    lVar7 = -(longlong)param_1;
    do {
      cVar2 = *param_1;
      cVar3 = param_1[(longlong)(&local_1828 + lVar7)];
      if (cVar2 != cVar3) break;
      param_1 = param_1 + 1;
    } while (cVar3 != '\0');
    if (cVar2 == cVar3) {
      uVar5 = FUN_180001020("AcceptedSerialNumber",local_1028,0x1000);
      if ((char)uVar5 == '\0') {
        local_1828 = '\0';
        strcpy_s(&local_1828,0x800,"serialnumber");
      }
      else {
        WideCharToMultiByte(0,0,local_1028,-1,&local_1828,0x800,(LPCSTR)0x0,(LPBOOL)0x0);
      }
      lVar7 = -1;
      do {
        lVar6 = lVar7 + 1;
        pcVar1 = acStack_1827 + lVar7;
        lVar7 = lVar6;
      } while (*pcVar1 != '\0');
      if (param_3 + -1 < (int)lVar6) {
        uVar4 = 1;
      }
      else {
        strncpy_s(param_2,(longlong)param_3,&local_1828,0xffffffffffffffff);
        uVar4 = 0;
      }
    }
    else {
      uVar4 = 6;
    }
  }
  return uVar4;
}



/* ---- _guard_check_icall @ 1800012f0 ---- */

void _guard_check_icall(void)

{
                    /* 0x12f0  2  VMProtectBegin
                       0x12f0  3  VMProtectBeginMutation
                       0x12f0  4  VMProtectBeginUltra
                       0x12f0  5  VMProtectBeginUltraLockByKey
                       0x12f0  6  VMProtectBeginVirtualization
                       0x12f0  7  VMProtectBeginVirtualizationLockByKey
                       0x12f0  11  VMProtectEnd */
  return;
}



/* ---- VMProtectDeactivateLicense @ 180001300 ---- */

undefined8 VMProtectDeactivateLicense(void)

{
                    /* 0x1300  8  VMProtectDeactivateLicense
                       0x1300  14  VMProtectGetOfflineActivationString
                       0x1300  15  VMProtectGetOfflineDeactivationString */
  return 0;
}



/* ---- VMProtectDecryptStringA @ 180001310 ---- */

undefined8 VMProtectDecryptStringA(undefined8 param_1)

{
                    /* 0x1310  9  VMProtectDecryptStringA
                       0x1310  10  VMProtectDecryptStringW */
  return param_1;
}



/* ---- VMProtectGetCurrentHWID @ 180001320 ---- */

/* WARNING: Function: _alloca_probe replaced with injection: alloca_probe */
/* WARNING: Function: __security_check_cookie replaced with injection: security_check_cookie */

int VMProtectGetCurrentHWID(undefined8 *param_1,int param_2)

{
  char *pcVar1;
  int iVar2;
  undefined8 uVar3;
  ulonglong uVar4;
  ulonglong uVar5;
  uint uVar6;
  undefined1 auStackY_1458 [32];
  CHAR local_1418;
  char acStack_1417 [1023];
  WCHAR local_1018 [2048];
  ulonglong local_18;
  undefined8 uStack_10;
  
                    /* 0x1320  13  VMProtectGetCurrentHWID */
  uStack_10 = 0x180001330;
  local_18 = DAT_18001c000 ^ (ulonglong)auStackY_1458;
  if ((param_1 == (undefined8 *)0x0) || (param_2 != 0)) {
    uVar3 = FUN_180001020("MyHWID",local_1018,0x1000);
    uVar4 = 0xffffffffffffffff;
    if ((char)uVar3 == '\0') {
      local_1418 = '\0';
      strcpy_s(&local_1418,0x400,"myhwid");
    }
    else {
      WideCharToMultiByte(0,0,local_1018,-1,&local_1418,0x400,(LPCSTR)0x0,(LPBOOL)0x0);
    }
    do {
      uVar5 = uVar4 + 1;
      pcVar1 = acStack_1417 + uVar4;
      uVar4 = uVar5;
    } while (*pcVar1 != '\0');
    if (param_1 != (undefined8 *)0x0) {
      uVar6 = param_2 - 1U;
      if ((int)(uint)uVar5 <= (int)(param_2 - 1U)) {
        uVar6 = (uint)uVar5;
      }
      FUN_180002ed0(param_1,(undefined8 *)&local_1418,(longlong)(int)uVar6);
      *(undefined1 *)((longlong)(int)uVar6 + (longlong)param_1) = 0;
      uVar5 = (ulonglong)uVar6;
    }
    iVar2 = (int)uVar5 + 1;
  }
  else {
    iVar2 = 0;
  }
  return iVar2;
}



/* ---- VMProtectGetSerialNumberData @ 180001440 ---- */

/* WARNING: Function: _alloca_probe replaced with injection: alloca_probe */
/* WARNING: Function: __security_check_cookie replaced with injection: security_check_cookie */

ulonglong VMProtectGetSerialNumberData(undefined1 (*param_1) [16],int param_2)

{
  byte bVar1;
  char cVar2;
  uint uVar3;
  int iVar4;
  undefined4 extraout_var;
  undefined8 uVar5;
  undefined1 (*pauVar6) [16];
  ulonglong uVar7;
  ulonglong uVar8;
  ulonglong uVar9;
  undefined1 auStackY_1878 [32];
  undefined2 local_1838 [2];
  undefined1 local_1834 [4];
  undefined2 local_1830 [4];
  CHAR local_1828;
  char local_1827 [2047];
  WCHAR local_1028 [2048];
  ulonglong local_28;
  
                    /* 0x1440  16  VMProtectGetSerialNumberData */
  local_28 = DAT_18001c000 ^ (ulonglong)auStackY_1878;
  if (param_2 == 0x510) {
    FUN_180003320(param_1,0,0x510);
    uVar3 = VMProtectGetSerialNumberState();
    pauVar6 = (undefined1 (*) [16])CONCAT44(extraout_var,uVar3);
    *(uint *)*param_1 = uVar3;
    if ((uVar3 & 6) == 0) {
      FUN_180001020("UserName",(LPWSTR)(*param_1 + 4),0x100);
      FUN_180001020("EMail",(LPWSTR)(param_1[0x20] + 4),0x100);
      uVar5 = FUN_180001020("TimeLimit",local_1028,0x1000);
      uVar7 = 0;
      uVar9 = 0xffffffffffffffff;
      if ((char)uVar5 == '\0') {
        local_1828 = '\0';
      }
      else {
        WideCharToMultiByte(0,0,local_1028,-1,&local_1828,0x800,(LPCSTR)0x0,(LPBOOL)0x0);
        iVar4 = FID_conflict_atoi(&local_1828);
        if (iVar4 < 0) {
          *(undefined4 *)(param_1[0x40] + 0xc) = 0;
        }
        else {
          bVar1 = (byte)iVar4;
          if (0xff < iVar4) {
            bVar1 = 0xff;
          }
          *(uint *)(param_1[0x40] + 0xc) = (uint)bVar1;
        }
      }
      uVar5 = FUN_180001020("ExpDate",local_1028,0x1000);
      if ((char)uVar5 == '\0') {
        local_1828 = '\0';
      }
      else {
        WideCharToMultiByte(0,0,local_1028,-1,&local_1828,0x800,(LPCSTR)0x0,(LPBOOL)0x0);
        iVar4 = FUN_180001de0((longlong)&local_1828,0x180012320,local_1838,local_1834);
        if (iVar4 == 3) {
          *(undefined2 *)(param_1[0x40] + 4) = local_1838[0];
          param_1[0x40][6] = local_1834[0];
          param_1[0x40][7] = (undefined1)local_1830[0];
        }
      }
      uVar5 = FUN_180001020("MaxBuildDate",local_1028,0x1000);
      if ((char)uVar5 == '\0') {
        local_1828 = '\0';
      }
      else {
        WideCharToMultiByte(0,0,local_1028,-1,&local_1828,0x800,(LPCSTR)0x0,(LPBOOL)0x0);
        iVar4 = FUN_180001de0((longlong)&local_1828,0x180012320,local_1830,local_1834);
        if (iVar4 == 3) {
          *(undefined2 *)(param_1[0x40] + 8) = local_1830[0];
          param_1[0x40][10] = local_1834[0];
          param_1[0x40][0xb] = (undefined1)local_1838[0];
        }
      }
      pauVar6 = (undefined1 (*) [16])FUN_180001020("UserData",local_1028,0x1000);
      if ((char)pauVar6 != '\0') {
        WideCharToMultiByte(0,0,local_1028,-1,&local_1828,0x800,(LPCSTR)0x0,(LPBOOL)0x0);
        pauVar6 = (undefined1 (*) [16])&local_1828;
        do {
          uVar9 = uVar9 + 1;
        } while ((*pauVar6)[uVar9] != '\0');
        if ((((uVar9 != 0) && ((uVar9 & 1) == 0)) && (uVar9 < 0x1ff)) && (uVar8 = uVar7, uVar9 != 0)
           ) {
          do {
            cVar2 = (&local_1828)[uVar8];
            if ((byte)(cVar2 - 0x30U) < 10) {
              pauVar6 = (undefined1 (*) [16])(ulonglong)((int)cVar2 - 0x30);
            }
            else if ((byte)(cVar2 + 0x9fU) < 6) {
              pauVar6 = (undefined1 (*) [16])(ulonglong)((int)cVar2 - 0x57);
            }
            else {
              if (5 < (byte)(cVar2 + 0xbfU)) {
                param_1[0x41][0] = 0;
                pauVar6 = FUN_180003320((undefined1 (*) [16])(param_1[0x41] + 1),0,0xff);
                break;
              }
              pauVar6 = (undefined1 (*) [16])(ulonglong)((int)cVar2 - 0x37);
            }
            if ((uVar8 & 1) == 0) {
              cVar2 = (byte)pauVar6 << 4;
              pauVar6 = (undefined1 (*) [16])CONCAT71((int7)((ulonglong)pauVar6 >> 8),cVar2);
              param_1[0x41][uVar7 + 1] = cVar2;
            }
            else {
              param_1[0x41][uVar7 + 1] = param_1[0x41][uVar7 + 1] | (byte)pauVar6;
              uVar7 = uVar7 + 1;
              param_1[0x41][0] = (char)uVar7;
            }
            uVar8 = uVar8 + 1;
          } while (uVar8 < uVar9);
        }
      }
    }
    local_28 = CONCAT71((int7)((ulonglong)pauVar6 >> 8),1);
  }
  else {
    local_28 = local_28 & 0xffffffffffffff00;
  }
  return local_28;
}



/* ---- VMProtectGetSerialNumberState @ 1800017e0 ---- */

/* WARNING: Function: _alloca_probe replaced with injection: alloca_probe */
/* WARNING: Function: __security_check_cookie replaced with injection: security_check_cookie */
/* WARNING: Globals starting with '_' overlap smaller symbols at the same address */

uint VMProtectGetSerialNumberState(void)

{
  char cVar1;
  char cVar2;
  longlong lVar3;
  uint uVar4;
  DWORD DVar5;
  int iVar6;
  uint uVar7;
  undefined8 uVar8;
  char *pcVar9;
  uint uVar10;
  undefined1 auStackY_1278 [32];
  byte local_1238 [4];
  int local_1234;
  byte local_1230 [8];
  _SYSTEMTIME local_1228;
  CHAR local_1218 [256];
  CHAR local_1118 [256];
  WCHAR local_1018 [2048];
  ulonglong local_18;
  undefined8 uStack_10;
  
                    /* 0x17e0  17  VMProtectGetSerialNumberState */
  uStack_10 = 0x1800017f4;
  local_18 = DAT_18001c000 ^ (ulonglong)auStackY_1278;
  if (DAT_18001c8e4 == '\0') {
    uVar10 = 2;
  }
  else if (DAT_18001c8e5 == '\0') {
    uVar10 = 0;
    uVar8 = FUN_180001020("TimeLimit",local_1018,0x1000);
    if ((char)uVar8 == '\0') {
      local_1218[0] = '\0';
      uVar10 = 0;
    }
    else {
      WideCharToMultiByte(0,0,local_1018,-1,local_1218,0x100,(LPCSTR)0x0,(LPBOOL)0x0);
      uVar4 = FID_conflict_atoi(local_1218);
      if ((uVar4 < 0x100) &&
         (DVar5 = GetTickCount(), (int)uVar4 <= (int)((DVar5 - _DAT_18001c8e8) / 60000))) {
        uVar10 = 0x10;
      }
    }
    uVar8 = FUN_180001020("ExpDate",local_1018,0x1000);
    if ((char)uVar8 == '\0') {
      local_1218[0] = '\0';
    }
    else {
      WideCharToMultiByte(0,0,local_1018,-1,local_1218,0x100,(LPCSTR)0x0,(LPBOOL)0x0);
      iVar6 = FUN_180001de0((longlong)local_1218,0x180012320,&local_1234,local_1238);
      if ((iVar6 == 3) &&
         (iVar6 = local_1234 * 0x10000, uVar4 = (uint)local_1238[0], uVar7 = (uint)local_1230[0],
         GetLocalTime(&local_1228),
         uVar4 * 0x100 + iVar6 + uVar7 <
         (uint)(byte)local_1228.wMonth * 0x100 + (uint)local_1228.wYear * 0x10000 +
         (uint)(byte)local_1228.wDay)) {
        uVar10 = uVar10 | 8;
      }
    }
    uVar8 = FUN_180001020("MaxBuildDate",local_1018,0x1000);
    if ((char)uVar8 == '\0') {
      local_1218[0] = '\0';
    }
    else {
      WideCharToMultiByte(0,0,local_1018,-1,local_1218,0x100,(LPCSTR)0x0,(LPBOOL)0x0);
      iVar6 = FUN_180001de0((longlong)local_1218,0x180012320,&local_1234,local_1230);
      if ((iVar6 == 3) &&
         (GetLocalTime(&local_1228),
         (uint)local_1230[0] * 0x100 + local_1234 * 0x10000 + (uint)local_1238[0] <
         (uint)(byte)local_1228.wMonth * 0x100 + (uint)local_1228.wYear * 0x10000 +
         (uint)(byte)local_1228.wDay)) {
        uVar10 = uVar10 | 0x40;
      }
    }
    uVar8 = FUN_180001020("KeyHWID",local_1018,0x1000);
    if ((char)uVar8 != '\0') {
      WideCharToMultiByte(0,0,local_1018,-1,local_1218,0x100,(LPCSTR)0x0,(LPBOOL)0x0);
      uVar8 = FUN_180001020("MyHWID",local_1018,0x1000);
      if ((char)uVar8 == '\0') {
        local_1118[0] = '\0';
      }
      else {
        WideCharToMultiByte(0,0,local_1018,-1,local_1118,0x100,(LPCSTR)0x0,(LPBOOL)0x0);
      }
      pcVar9 = local_1218;
      lVar3 = -(longlong)pcVar9;
      do {
        cVar1 = *pcVar9;
        cVar2 = pcVar9[(longlong)(local_1118 + lVar3)];
        if (cVar1 != cVar2) break;
        pcVar9 = pcVar9 + 1;
      } while (cVar2 != '\0');
      if (cVar1 != cVar2) {
        uVar10 = uVar10 | 0x20;
      }
    }
  }
  else {
    uVar10 = 4;
  }
  return uVar10;
}



/* ---- VMProtectIsDebuggerPresent @ 180001b70 ---- */

bool VMProtectIsDebuggerPresent(void)

{
  BOOL BVar1;
  
                    /* 0x1b70  18  VMProtectIsDebuggerPresent */
  BVar1 = IsDebuggerPresent();
  return BVar1 != 0;
}



/* ---- VMProtectIsProtected @ 180001b90 ---- */

undefined1 VMProtectIsProtected(void)

{
                    /* 0x1b90  19  VMProtectIsProtected
                       0x1b90  21  VMProtectIsVirtualMachinePresent */
  return 0;
}



/* ---- VMProtectFreeString @ 180001ba0 ---- */

undefined1 VMProtectFreeString(void)

{
                    /* 0x1ba0  12  VMProtectFreeString
                       0x1ba0  20  VMProtectIsValidImageCRC */
  return 1;
}



/* ---- VMProtectSetSerialNumber @ 180001bb0 ---- */

/* WARNING: Function: _alloca_probe replaced with injection: alloca_probe */
/* WARNING: Function: __security_check_cookie replaced with injection: security_check_cookie */

uint VMProtectSetSerialNumber(char *param_1)

{
  char cVar1;
  longlong lVar2;
  uint uVar3;
  undefined8 uVar4;
  char cVar5;
  char *pcVar6;
  undefined1 auStackY_2058 [32];
  CHAR local_2018 [2048];
  char local_1818 [2048];
  WCHAR local_1018 [2048];
  ulonglong local_18;
  
                    /* 0x1bb0  22  VMProtectSetSerialNumber */
  local_18 = DAT_18001c000 ^ (ulonglong)auStackY_2058;
  DAT_18001c8e4 = 0;
  DAT_18001c8e5 = 0;
  if ((param_1 == (char *)0x0) || (cVar5 = *param_1, cVar5 == '\0')) {
    return 2;
  }
  pcVar6 = local_1818;
  do {
    if ((((byte)(cVar5 - 0x2bU) < 0x30) &&
        ((0xffffffc47ff1U >> ((longlong)(char)(cVar5 - 0x2bU) & 0x3fU) & 1) != 0)) ||
       ((byte)(cVar5 + 0x9fU) < 0x1a)) {
      *pcVar6 = cVar5;
      pcVar6 = pcVar6 + 1;
    }
    cVar5 = param_1[1];
    param_1 = param_1 + 1;
  } while (cVar5 != '\0');
  *pcVar6 = '\0';
  uVar4 = FUN_180001020("AcceptedSerialNumber",local_1018,0x1000);
  if ((char)uVar4 == '\0') {
    local_2018[0] = '\0';
    strcpy_s(local_2018,0x800,"serialnumber");
  }
  else {
    WideCharToMultiByte(0,0,local_1018,-1,local_2018,0x800,(LPCSTR)0x0,(LPBOOL)0x0);
  }
  pcVar6 = local_1818;
  lVar2 = -(longlong)pcVar6;
  do {
    cVar5 = *pcVar6;
    cVar1 = pcVar6[(longlong)(local_2018 + lVar2)];
    if (cVar5 != cVar1) break;
    pcVar6 = pcVar6 + 1;
  } while (cVar1 != '\0');
  DAT_18001c8e4 = cVar5 == cVar1;
  uVar4 = FUN_180001020("BlackListedSerialNumber",local_1018,0x1000);
  if ((char)uVar4 == '\0') {
    local_2018[0] = '\0';
    uVar3 = VMProtectGetSerialNumberState();
    return uVar3;
  }
  WideCharToMultiByte(0,0,local_1018,-1,local_2018,0x800,(LPCSTR)0x0,(LPBOOL)0x0);
  pcVar6 = local_1818;
  lVar2 = -(longlong)pcVar6;
  do {
    cVar5 = *pcVar6;
    cVar1 = pcVar6[(longlong)(local_2018 + lVar2)];
    if (cVar5 != cVar1) break;
    pcVar6 = pcVar6 + 1;
  } while (cVar1 != '\0');
  DAT_18001c8e5 = cVar5 == cVar1;
  uVar3 = VMProtectGetSerialNumberState();
  return uVar3;
}



/* ---- FUN_180001dd0 @ 180001dd0 ---- */

undefined * FUN_180001dd0(void)

{
  return &DAT_18001c8f0;
}



/* ---- FUN_180001de0 @ 180001de0 ---- */

void FUN_180001de0(longlong param_1,longlong param_2,undefined8 param_3,undefined8 param_4)

{
  ulonglong *puVar1;
  undefined8 local_res18;
  undefined8 local_res20;
  
  local_res18 = param_3;
  local_res20 = param_4;
  puVar1 = (ulonglong *)FUN_180001dd0();
  FUN_1800097b0(*puVar1 | 1,param_1,-1,param_2,(__crt_locale_pointers *)0x0,&local_res18);
  return;
}



/* ---- __GSHandlerCheck @ 180001e34 ---- */

/* Library Function - Single Match
    __GSHandlerCheck
   
   Library: Visual Studio 2015 Release */

undefined8
__GSHandlerCheck(undefined8 param_1,undefined8 param_2,undefined8 param_3,longlong param_4)

{
  __GSHandlerCheckCommon(param_2,param_4);
  return 1;
}



/* ---- __GSHandlerCheckCommon @ 180001e54 ---- */

/* WARNING: Function: __security_check_cookie replaced with injection: security_check_cookie */
/* Library Function - Single Match
    __GSHandlerCheckCommon
   
   Library: Visual Studio 2015 Release */

ulonglong __GSHandlerCheckCommon(undefined8 param_1,longlong param_2)

{
  ulonglong uVar1;
  longlong lVar2;
  
  uVar1 = *(ulonglong *)(param_2 + 0x10);
  lVar2 = (ulonglong)*(uint *)(uVar1 + 8) + *(longlong *)(param_2 + 8);
  if ((*(byte *)(lVar2 + 3) & 0xf) != 0) {
    uVar1 = (ulonglong)(*(byte *)(lVar2 + 3) & 0xfffffff0);
  }
  return uVar1;
}



/* ---- _alloca_probe @ 180001ec0 ---- */

/* WARNING: This is an inlined function */
/* Library Function - Single Match
    _alloca_probe
   
   Libraries: Visual Studio 2015, Visual Studio 2017, Visual Studio 2019 */

void _alloca_probe(void)

{
  undefined1 *in_RAX;
  undefined1 *puVar1;
  undefined1 *puVar2;
  undefined1 local_res8 [32];
  
  puVar1 = local_res8 + -(longlong)in_RAX;
  if (local_res8 < in_RAX) {
    puVar1 = (undefined1 *)0x0;
  }
  if (puVar1 < StackLimit) {
    puVar2 = StackLimit;
    do {
      puVar2 = puVar2 + -0x1000;
      *puVar2 = 0;
    } while ((undefined1 *)((ulonglong)puVar1 & 0xfffffffffffff000) != puVar2);
  }
  return;
}



/* ---- __security_check_cookie @ 180001f30 ---- */

/* WARNING: This is an inlined function */
/* Library Function - Single Match
    __security_check_cookie
   
   Libraries: Visual Studio 2015, Visual Studio 2017, Visual Studio 2019 */

void __cdecl __security_check_cookie(uintptr_t _StackCookie)

{
  if ((_StackCookie == DAT_18001c000) && ((short)(_StackCookie >> 0x30) == 0)) {
    return;
  }
                    /* WARNING: Subroutine does not return */
  __report_gsfailure(_StackCookie);
}



/* ---- FUN_180001f54 @ 180001f54 ---- */

ulonglong FUN_180001f54(undefined8 param_1,int param_2,longlong param_3)

{
  byte bVar1;
  bool bVar2;
  ulonglong uVar3;
  undefined7 extraout_var;
  
  if (param_2 == 0) {
    bVar2 = FUN_1800020d0(param_3 != 0);
    return CONCAT71(extraout_var,bVar2);
  }
  if (param_2 != 1) {
    if (param_2 == 2) {
      bVar1 = __scrt_dllmain_crt_thread_attach();
    }
    else {
      if (param_2 != 3) {
        return 1;
      }
      bVar1 = __scrt_dllmain_crt_thread_detach();
    }
    return (ulonglong)bVar1;
  }
  uVar3 = FUN_180001fa4(param_1,param_3);
  return uVar3;
}



/* ---- FUN_180001fa4 @ 180001fa4 ---- */

undefined8 FUN_180001fa4(undefined8 param_1,undefined8 param_2)

{
  code *pcVar1;
  bool bVar2;
  bool bVar3;
  undefined8 uVar4;
  undefined8 uVar5;
  longlong *plVar6;
  ulonglong uVar7;
  
  uVar4 = __scrt_initialize_crt(0);
  if ((char)uVar4 != '\0') {
    uVar4 = __scrt_acquire_startup_lock();
    bVar2 = true;
    if (DAT_18001ce70 != 0) {
      __scrt_fastfail(7);
    }
    DAT_18001ce70 = 1;
    bVar3 = FUN_1800025ec();
    if (bVar3) {
      FUN_180002b9c();
      atexit(FUN_180002be8);
      FUN_180002a04();
      atexit((_func_5014 *)&LAB_180002a14);
      FUN_180002a28();
      uVar5 = _initterm_e((undefined8 *)&DAT_180012260,(undefined8 *)&DAT_180012280);
      if (((int)uVar5 == 0) && (uVar5 = __scrt_dllmain_after_initialize_c(), (char)uVar5 != '\0')) {
        _initterm((undefined8 *)&DAT_180012248,(undefined8 *)&DAT_180012258);
        DAT_18001ce70 = 2;
        bVar2 = false;
      }
    }
    __scrt_release_startup_lock((char)uVar4);
    if (!bVar2) {
      plVar6 = (longlong *)FUN_180002a44();
      if ((*plVar6 != 0) &&
         (uVar7 = __scrt_is_nonwritable_in_current_image((longlong)plVar6), (char)uVar7 != '\0')) {
        pcVar1 = (code *)*plVar6;
        _guard_check_icall();
        (*pcVar1)(param_1,2,param_2);
      }
      DAT_18001c8f8 = DAT_18001c8f8 + 1;
      return 1;
    }
  }
  return 0;
}



/* ---- FUN_1800020d0 @ 1800020d0 ---- */

bool FUN_1800020d0(char param_1)

{
  undefined8 uVar1;
  bool bVar2;
  
  if (DAT_18001c8f8 < 1) {
    bVar2 = false;
  }
  else {
    DAT_18001c8f8 = DAT_18001c8f8 + -1;
    uVar1 = __scrt_acquire_startup_lock();
    if (DAT_18001ce70 != 2) {
      __scrt_fastfail(7);
    }
    __scrt_dllmain_uninitialize_c();
    DAT_18001ce70 = 0;
    FUN_1800026d8();
    __scrt_release_startup_lock((char)uVar1);
    uVar1 = __scrt_uninitialize_crt(param_1,'\0');
    bVar2 = (char)uVar1 != '\0';
  }
  return bVar2;
}



/* ---- dllmain_dispatch @ 180002154 ---- */

/* Library Function - Single Match
    int __cdecl dllmain_dispatch(struct HINSTANCE__ * __ptr64 const,unsigned long,void * __ptr64
   const)
   
   Library: Visual Studio 2015 Release */

int __cdecl dllmain_dispatch(HINSTANCE__ *param_1,ulong param_2,void *param_3)

{
  int iVar1;
  ulonglong uVar2;
  undefined8 uVar3;
  
  if ((param_2 == 0) && (DAT_18001c8f8 < 1)) {
    return 0;
  }
  if (param_2 - 1 < 2) {
    iVar1 = dllmain_raw(param_1,param_2,param_3);
    if (iVar1 == 0) {
      return 0;
    }
    uVar2 = FUN_180001f54(param_1,param_2,(longlong)param_3);
    if ((int)uVar2 == 0) {
      return 0;
    }
  }
  uVar3 = FUN_180001130();
  iVar1 = (int)uVar3;
  if ((param_2 == 1) && (iVar1 == 0)) {
    FUN_180001130();
    FUN_180001f54(param_1,0,(longlong)param_3);
    dllmain_raw(param_1,0,param_3);
  }
  if ((param_2 == 0) || (param_2 == 3)) {
    uVar2 = FUN_180001f54(param_1,param_2,(longlong)param_3);
    iVar1 = 0;
    if ((int)uVar2 != 0) {
      iVar1 = dllmain_raw(param_1,param_2,param_3);
    }
  }
  return iVar1;
}



/* ---- dllmain_raw @ 18000224c ---- */

/* Library Function - Single Match
    int __cdecl dllmain_raw(struct HINSTANCE__ * __ptr64 const,unsigned long,void * __ptr64 const)
   
   Library: Visual Studio 2015 Release */

int __cdecl dllmain_raw(HINSTANCE__ *param_1,ulong param_2,void *param_3)

{
  code *pcVar1;
  int iVar2;
  
  pcVar1 = DAT_1800123e8;
  if (DAT_1800123e8 == (code *)0x0) {
    iVar2 = 1;
  }
  else {
    _guard_check_icall();
    iVar2 = (*pcVar1)(param_1,param_2,param_3);
  }
  return iVar2;
}



/* ---- entry @ 1800022a0 ---- */

void entry(HINSTANCE__ *param_1,ulong param_2,void *param_3)

{
  if (param_2 == 1) {
    __security_init_cookie();
  }
  dllmain_dispatch(param_1,param_2,param_3);
  return;
}



/* ---- __raise_securityfailure @ 1800022e0 ---- */

/* Library Function - Single Match
    __raise_securityfailure
   
   Libraries: Visual Studio 2015 Release, Visual Studio 2017 Release, Visual Studio 2019 Release */

void __raise_securityfailure(_EXCEPTION_POINTERS *param_1)

{
  HANDLE hProcess;
  
  SetUnhandledExceptionFilter((LPTOP_LEVEL_EXCEPTION_FILTER)0x0);
  UnhandledExceptionFilter(param_1);
  hProcess = GetCurrentProcess();
                    /* WARNING: Could not recover jumptable at 0x00018000230d. Too many branches */
                    /* WARNING: Treating indirect jump as call */
  TerminateProcess(hProcess,0xc0000409);
  return;
}



/* ---- __report_gsfailure @ 180002314 ---- */

/* WARNING: Globals starting with '_' overlap smaller symbols at the same address */
/* Library Function - Single Match
    __report_gsfailure
   
   Libraries: Visual Studio 2015 Release, Visual Studio 2017 Release, Visual Studio 2019 Release */

void __cdecl __report_gsfailure(uintptr_t _StackCookie)

{
  code *pcVar1;
  BOOL BVar2;
  undefined1 *puVar3;
  undefined1 auStack_38 [8];
  undefined1 auStack_30 [48];
  
  puVar3 = auStack_38;
  BVar2 = IsProcessorFeaturePresent(0x17);
  if (BVar2 != 0) {
    pcVar1 = (code *)swi(0x29);
    (*pcVar1)(2);
    puVar3 = auStack_30;
  }
  *(undefined8 *)(puVar3 + -8) = 0x18000233e;
  capture_previous_context((PCONTEXT)&DAT_18001c9a0);
  _DAT_18001c910 = *(undefined8 *)(puVar3 + 0x38);
  _DAT_18001ca38 = puVar3 + 0x40;
  _DAT_18001ca20 = *(undefined8 *)(puVar3 + 0x40);
  _DAT_18001c900 = 0xc0000409;
  _DAT_18001c904 = 1;
  _DAT_18001c918 = 1;
  DAT_18001c920 = 2;
  *(undefined8 *)(puVar3 + 0x20) = DAT_18001c000;
  *(undefined8 *)(puVar3 + 0x28) = DAT_18001c008;
  *(undefined8 *)(puVar3 + -8) = 0x1800023e0;
  DAT_18001ca98 = _DAT_18001c910;
  __raise_securityfailure((_EXCEPTION_POINTERS *)&PTR_DAT_1800123f0);
  return;
}



/* ---- __report_rangecheckfailure @ 1800023e8 ---- */

/* Library Function - Single Match
    __report_rangecheckfailure
   
   Libraries: Visual Studio 2015 Release, Visual Studio 2017 Release, Visual Studio 2019 Release */

void __report_rangecheckfailure(void)

{
  __report_securityfailure(8);
  return;
}



/* ---- __report_securityfailure @ 1800023fc ---- */

/* WARNING: Globals starting with '_' overlap smaller symbols at the same address */
/* Library Function - Single Match
    __report_securityfailure
   
   Libraries: Visual Studio 2015 Release, Visual Studio 2017 Release, Visual Studio 2019 Release */

void __report_securityfailure(undefined4 param_1)

{
  code *pcVar1;
  BOOL BVar2;
  undefined1 *puVar3;
  undefined1 auStack_28 [8];
  undefined1 auStack_20 [32];
  
  puVar3 = auStack_28;
  BVar2 = IsProcessorFeaturePresent(0x17);
  if (BVar2 != 0) {
    pcVar1 = (code *)swi(0x29);
    (*pcVar1)(param_1);
    puVar3 = auStack_20;
  }
  *(undefined8 *)(puVar3 + -8) = 0x180002426;
  capture_current_context((PCONTEXT)&DAT_18001c9a0);
  _DAT_18001c910 = *(undefined8 *)(puVar3 + 0x28);
  _DAT_18001ca38 = puVar3 + 0x30;
  _DAT_18001c900 = 0xc0000409;
  _DAT_18001c904 = 1;
  _DAT_18001c918 = 1;
  DAT_18001c920 = (ulonglong)*(uint *)(puVar3 + 0x30);
  *(undefined8 *)(puVar3 + -8) = 0x180002492;
  DAT_18001ca98 = _DAT_18001c910;
  __raise_securityfailure((_EXCEPTION_POINTERS *)&PTR_DAT_1800123f0);
  return;
}



/* ---- capture_current_context @ 180002498 ---- */

/* Library Function - Single Match
    capture_current_context
   
   Libraries: Visual Studio 2015 Release, Visual Studio 2017 Release, Visual Studio 2019 Release */

void capture_current_context(PCONTEXT param_1)

{
  DWORD64 ControlPc;
  PRUNTIME_FUNCTION FunctionEntry;
  DWORD64 local_res8;
  ulonglong local_res10;
  PVOID local_res18;
  
  RtlCaptureContext();
  ControlPc = param_1->Rip;
  FunctionEntry = RtlLookupFunctionEntry(ControlPc,&local_res8,(PUNWIND_HISTORY_TABLE)0x0);
  if (FunctionEntry != (PRUNTIME_FUNCTION)0x0) {
    RtlVirtualUnwind(0,local_res8,ControlPc,FunctionEntry,param_1,&local_res18,&local_res10,
                     (PKNONVOLATILE_CONTEXT_POINTERS)0x0);
  }
  return;
}



/* ---- capture_previous_context @ 180002508 ---- */

/* Library Function - Single Match
    capture_previous_context
   
   Libraries: Visual Studio 2015 Release, Visual Studio 2017 Release, Visual Studio 2019 Release */

void capture_previous_context(PCONTEXT param_1)

{
  DWORD64 ControlPc;
  PRUNTIME_FUNCTION FunctionEntry;
  int iVar1;
  DWORD64 local_res8;
  ulonglong local_res10;
  PVOID local_res18 [2];
  
  RtlCaptureContext();
  ControlPc = param_1->Rip;
  iVar1 = 0;
  do {
    FunctionEntry = RtlLookupFunctionEntry(ControlPc,&local_res8,(PUNWIND_HISTORY_TABLE)0x0);
    if (FunctionEntry == (PRUNTIME_FUNCTION)0x0) {
      return;
    }
    RtlVirtualUnwind(0,local_res8,ControlPc,FunctionEntry,param_1,local_res18,&local_res10,
                     (PKNONVOLATILE_CONTEXT_POINTERS)0x0);
    iVar1 = iVar1 + 1;
  } while (iVar1 < 2);
  return;
}



/* ---- __scrt_acquire_startup_lock @ 18000257c ---- */

/* Library Function - Single Match
    __scrt_acquire_startup_lock
   
   Libraries: Visual Studio 2015 Release, Visual Studio 2017 Release, Visual Studio 2019 Release */

ulonglong __scrt_acquire_startup_lock(void)

{
  ulonglong uVar1;
  bool bVar2;
  undefined7 extraout_var;
  ulonglong uVar3;
  
  bVar2 = __scrt_is_ucrt_dll_in_use();
  uVar3 = CONCAT71(extraout_var,bVar2);
  if ((int)uVar3 == 0) {
LAB_1800025aa:
    uVar3 = uVar3 & 0xffffffffffffff00;
  }
  else {
    do {
      uVar3 = 0;
      LOCK();
      bVar2 = DAT_18001ce78 == 0;
      uVar1 = *(ulonglong *)((longlong)Self + 8);
      if (!bVar2) {
        uVar3 = DAT_18001ce78;
        uVar1 = DAT_18001ce78;
      }
      DAT_18001ce78 = uVar1;
      UNLOCK();
      if (bVar2) goto LAB_1800025aa;
    } while (*(ulonglong *)((longlong)Self + 8) != uVar3);
    uVar3 = CONCAT71((int7)(uVar3 >> 8),1);
  }
  return uVar3;
}



/* ---- __scrt_dllmain_after_initialize_c @ 1800025b8 ---- */

/* Library Function - Single Match
    __scrt_dllmain_after_initialize_c
   
   Library: Visual Studio 2015 Release */

undefined8 __scrt_dllmain_after_initialize_c(void)

{
  bool bVar1;
  int iVar2;
  undefined7 extraout_var;
  undefined8 uVar3;
  ulonglong uVar4;
  undefined4 extraout_var_00;
  
  bVar1 = __scrt_is_ucrt_dll_in_use();
  if ((int)CONCAT71(extraout_var,bVar1) == 0) {
    uVar3 = FUN_180001130();
    uVar4 = _configure_narrow_argv((int)uVar3);
    if ((int)uVar4 != 0) {
      return uVar4 & 0xffffffffffffff00;
    }
    iVar2 = common_initialize_environment_nolock<char>();
    uVar3 = CONCAT44(extraout_var_00,iVar2);
  }
  else {
    uVar3 = __isa_available_init();
  }
  return CONCAT71((int7)((ulonglong)uVar3 >> 8),1);
}



/* ---- FUN_1800025ec @ 1800025ec ---- */

bool FUN_1800025ec(void)

{
  bool bVar1;
  
  bVar1 = FUN_180002738(0);
  return bVar1;
}



/* ---- __scrt_dllmain_crt_thread_attach @ 180002604 ---- */

/* Library Function - Single Match
    __scrt_dllmain_crt_thread_attach
   
   Libraries: Visual Studio 2015 Release, Visual Studio 2017 Release, Visual Studio 2019 Release */

undefined1 __scrt_dllmain_crt_thread_attach(void)

{
  bool bVar1;
  
  bVar1 = __vcrt_thread_attach();
  if (bVar1) {
    bVar1 = __acrt_thread_attach();
    if (bVar1) {
      return 1;
    }
    __vcrt_thread_detach();
  }
  return 0;
}



/* ---- __scrt_dllmain_crt_thread_detach @ 18000262c ---- */

/* Library Function - Single Match
    __scrt_dllmain_crt_thread_detach
   
   Libraries: Visual Studio 2015, Visual Studio 2017, Visual Studio 2019 */

undefined1 __scrt_dllmain_crt_thread_detach(void)

{
  __acrt_thread_detach();
  __vcrt_thread_detach();
  return 1;
}



/* ---- __scrt_dllmain_exception_filter @ 180002644 ---- */

/* Library Function - Single Match
    __scrt_dllmain_exception_filter
   
   Library: Visual Studio 2015 Release */

void __scrt_dllmain_exception_filter
               (undefined8 param_1,int param_2,undefined8 param_3,undefined *param_4,int param_5,
               undefined8 param_6)

{
  bool bVar1;
  undefined3 extraout_var;
  
  bVar1 = __scrt_is_ucrt_dll_in_use();
  if ((CONCAT31(extraout_var,bVar1) == 0) && (param_2 == 1)) {
    _guard_check_icall();
    (*(code *)param_4)(param_1,0,param_3);
  }
  _seh_filter_dll(param_5,param_6);
  return;
}



/* ---- __scrt_dllmain_uninitialize_c @ 1800026a8 ---- */

/* Library Function - Single Match
    __scrt_dllmain_uninitialize_c
   
   Libraries: Visual Studio 2015 Release, Visual Studio 2017 Release, Visual Studio 2019 Release */

void __scrt_dllmain_uninitialize_c(void)

{
  bool bVar1;
  undefined3 extraout_var;
  int iVar2;
  
  bVar1 = __scrt_is_ucrt_dll_in_use();
  if (CONCAT31(extraout_var,bVar1) != 0) {
    _execute_onexit_table(&DAT_18001ce80);
    return;
  }
  iVar2 = FUN_18000a070();
  if (iVar2 == 0) {
    _cexit();
  }
  return;
}



/* ---- FUN_1800026d8 @ 1800026d8 ---- */

void FUN_1800026d8(void)

{
  FUN_18000ac40();
  FUN_180003738();
  return;
}



/* ---- __scrt_initialize_crt @ 1800026ec ---- */

/* Library Function - Single Match
    __scrt_initialize_crt
   
   Library: Visual Studio 2015 Release */

ulonglong __scrt_initialize_crt(int param_1)

{
  ulonglong uVar1;
  undefined8 uVar2;
  
  if (param_1 == 0) {
    DAT_18001ceb0 = 1;
  }
  __isa_available_init();
  uVar1 = __vcrt_initialize();
  if ((char)uVar1 != '\0') {
    uVar2 = FUN_18000abf4();
    if ((char)uVar2 != '\0') {
      return CONCAT71((int7)((ulonglong)uVar2 >> 8),1);
    }
    uVar1 = __vcrt_uninitialize('\0');
  }
  return uVar1 & 0xffffffffffffff00;
}



/* ---- FUN_180002738 @ 180002738 ---- */

/* WARNING: Globals starting with '_' overlap smaller symbols at the same address */

bool FUN_180002738(uint param_1)

{
  code *pcVar1;
  byte bVar2;
  bool bVar3;
  undefined1 uVar4;
  undefined7 extraout_var;
  undefined8 uVar5;
  
  if (param_1 < 2) {
    bVar3 = __scrt_is_ucrt_dll_in_use();
    if (((int)CONCAT71(extraout_var,bVar3) == 0) || (param_1 != 0)) {
      bVar3 = true;
      bVar2 = 0x40 - ((byte)DAT_18001c000 & 0x3f) & 0x3f;
      _DAT_18001ce80 = (0xffffffffffffffffU >> bVar2 | -1L << 0x40 - bVar2) ^ DAT_18001c000;
      uRam000000018001ce88 = _DAT_18001ce80;
      _DAT_18001ce90 = _DAT_18001ce80;
      _DAT_18001ce98 = _DAT_18001ce80;
      uRam000000018001cea0 = _DAT_18001ce80;
      _DAT_18001cea8 = _DAT_18001ce80;
    }
    else {
      uVar5 = _initialize_onexit_table((ulonglong *)&DAT_18001ce80);
      if ((int)uVar5 == 0) {
        uVar5 = _initialize_onexit_table((ulonglong *)&DAT_18001ce98);
        bVar3 = (int)uVar5 == 0;
      }
      else {
        bVar3 = false;
      }
    }
    return bVar3;
  }
  __scrt_fastfail(5);
  pcVar1 = (code *)swi(3);
  uVar4 = (*pcVar1)();
  return (bool)uVar4;
}



/* ---- __scrt_is_nonwritable_in_current_image @ 180002804 ---- */

/* Library Function - Single Match
    __scrt_is_nonwritable_in_current_image
   
   Libraries: Visual Studio 2015 Release, Visual Studio 2017 Release */

ulonglong __scrt_is_nonwritable_in_current_image(longlong param_1)

{
  longlong lVar1;
  ulonglong uVar2;
  ulonglong uVar3;
  uint7 uVar4;
  longlong lVar5;
  
  uVar3 = 0x5a4d;
  if (((IMAGE_DOS_HEADER_180000000.e_magic == (char  [2])0x5a4d) &&
      (uVar2 = (ulonglong)(int)IMAGE_DOS_HEADER_180000000.e_lfanew, uVar3 = uVar2,
      *(int *)(uVar2 + 0x180000000) == 0x4550)) &&
     (uVar3 = 0x20b,
     *(short *)((longlong)IMAGE_DOS_HEADER_180000000.e_res_4_ + (uVar2 - 4)) == 0x20b)) {
    lVar5 = uVar2 + 0x180000018 +
            (ulonglong)*(ushort *)((longlong)IMAGE_DOS_HEADER_180000000.e_res_4_ + (uVar2 - 8));
    uVar3 = (ulonglong)*(ushort *)(IMAGE_DOS_HEADER_180000000.e_magic + uVar2 + 6);
    lVar1 = lVar5 + uVar3 * 0x28;
    for (; lVar5 != lVar1; lVar5 = lVar5 + 0x28) {
      if (((ulonglong)*(uint *)(lVar5 + 0xc) <= param_1 - 0x180000000U) &&
         (uVar3 = (ulonglong)(*(int *)(lVar5 + 8) + *(uint *)(lVar5 + 0xc)),
         param_1 - 0x180000000U < uVar3)) goto LAB_18000287b;
    }
    lVar5 = 0;
LAB_18000287b:
    if (lVar5 == 0) {
      uVar3 = uVar3 & 0xffffffffffffff00;
    }
    else {
      uVar4 = (uint7)(uVar3 >> 8);
      if (*(int *)(lVar5 + 0x24) < 0) {
        uVar3 = (ulonglong)uVar4 << 8;
      }
      else {
        uVar3 = CONCAT71(uVar4,1);
      }
    }
  }
  else {
    uVar3 = uVar3 & 0xffffffffffffff00;
  }
  return uVar3;
}



/* ---- __scrt_release_startup_lock @ 1800028a0 ---- */

/* Library Function - Single Match
    __scrt_release_startup_lock
   
   Libraries: Visual Studio 2015 Release, Visual Studio 2017 Release, Visual Studio 2019 Release */

void __scrt_release_startup_lock(char param_1)

{
  bool bVar1;
  undefined3 extraout_var;
  
  bVar1 = __scrt_is_ucrt_dll_in_use();
  if ((CONCAT31(extraout_var,bVar1) != 0) && (param_1 == '\0')) {
    LOCK();
    DAT_18001ce78 = 0;
    UNLOCK();
  }
  return;
}



/* ---- __scrt_uninitialize_crt @ 1800028c4 ---- */

/* Library Function - Single Match
    __scrt_uninitialize_crt
   
   Libraries: Visual Studio 2015 Release, Visual Studio 2017 Release */

undefined8 __scrt_uninitialize_crt(char param_1,char param_2)

{
  undefined8 in_RAX;
  
  if ((DAT_18001ceb0 == '\0') || (param_2 == '\0')) {
    FUN_18000ac2c();
    in_RAX = __vcrt_uninitialize(param_1);
  }
  return CONCAT71((int7)((ulonglong)in_RAX >> 8),1);
}



/* ---- _onexit @ 1800028f0 ---- */

/* WARNING: Globals starting with '_' overlap smaller symbols at the same address */
/* Library Function - Single Match
    _onexit
   
   Libraries: Visual Studio 2015 Release, Visual Studio 2017 Release */

_onexit_t __cdecl _onexit(_onexit_t _Func)

{
  int iVar1;
  byte bVar2;
  _onexit_t p_Var3;
  
  bVar2 = (byte)DAT_18001c000 & 0x3f;
  if (((DAT_18001c000 ^ _DAT_18001ce80) >> bVar2 | (DAT_18001c000 ^ _DAT_18001ce80) << 0x40 - bVar2)
      == 0xffffffffffffffff) {
    iVar1 = FUN_18000a9ec(_Func);
  }
  else {
    iVar1 = _register_onexit_function(&DAT_18001ce80,_Func);
  }
  p_Var3 = (_onexit_t)0x0;
  if (iVar1 == 0) {
    p_Var3 = _Func;
  }
  return p_Var3;
}



/* ---- atexit @ 180002940 ---- */

/* Library Function - Single Match
    atexit
   
   Libraries: Visual Studio 2015 Release, Visual Studio 2017 Release */

int __cdecl atexit(_func_5014 *param_1)

{
  _onexit_t p_Var1;
  
  p_Var1 = _onexit((_onexit_t)param_1);
  return (p_Var1 != (_onexit_t)0x0) - 1;
}



/* ---- __security_init_cookie @ 180002958 ---- */

/* Library Function - Single Match
    __security_init_cookie
   
   Library: Visual Studio 2015 Release */

void __cdecl __security_init_cookie(void)

{
  DWORD DVar1;
  _FILETIME local_res8;
  _FILETIME local_res10;
  LARGE_INTEGER local_res18;
  
  local_res10.dwLowDateTime = 0;
  local_res10.dwHighDateTime = 0;
  if (DAT_18001c000 == 0x2b992ddfa232) {
    GetSystemTimeAsFileTime(&local_res10);
    local_res8 = local_res10;
    DVar1 = GetCurrentThreadId();
    local_res8 = (_FILETIME)((ulonglong)local_res8 ^ (ulonglong)DVar1);
    DVar1 = GetCurrentProcessId();
    local_res8 = (_FILETIME)((ulonglong)local_res8 ^ (ulonglong)DVar1);
    QueryPerformanceCounter(&local_res18);
    DAT_18001c000 =
         ((ulonglong)local_res18.s.LowPart << 0x20 ^
          CONCAT44(local_res18.s.HighPart,local_res18.s.LowPart) ^ (ulonglong)local_res8 ^
         (ulonglong)&local_res8) & 0xffffffffffff;
    if (DAT_18001c000 == 0x2b992ddfa232) {
      DAT_18001c000 = 0x2b992ddfa233;
    }
  }
  DAT_18001c008 = ~DAT_18001c000;
  return;
}



/* ---- FUN_180002a04 @ 180002a04 ---- */

void FUN_180002a04(void)

{
                    /* WARNING: Could not recover jumptable at 0x000180002a0b. Too many branches */
                    /* WARNING: Treating indirect jump as call */
  InitializeSListHead(&DAT_18001cec0);
  return;
}



/* ---- FUN_180002a20 @ 180002a20 ---- */

undefined * FUN_180002a20(void)

{
  return &DAT_18001ced0;
}



/* ---- FUN_180002a28 @ 180002a28 ---- */

void FUN_180002a28(void)

{
  ulonglong *puVar1;
  
  puVar1 = (ulonglong *)FUN_180002a20();
  *puVar1 = *puVar1 | 4;
  puVar1 = (ulonglong *)FUN_180001dd0();
  *puVar1 = *puVar1 | 2;
  return;
}



/* ---- FUN_180002a44 @ 180002a44 ---- */

undefined * FUN_180002a44(void)

{
  return &DAT_18001da90;
}



/* ---- FUN_180002a4c @ 180002a4c ---- */

/* WARNING: Globals starting with '_' overlap smaller symbols at the same address */

void FUN_180002a4c(void)

{
  _DAT_18001ced8 = 0;
  return;
}



/* ---- __scrt_fastfail @ 180002a54 ---- */

/* WARNING: Globals starting with '_' overlap smaller symbols at the same address */
/* Library Function - Single Match
    __scrt_fastfail
   
   Library: Visual Studio 2015 Release */

void __scrt_fastfail(undefined4 param_1)

{
  code *pcVar1;
  BOOL BVar2;
  LONG LVar3;
  PRUNTIME_FUNCTION FunctionEntry;
  undefined1 *puVar4;
  undefined8 unaff_retaddr;
  DWORD64 local_res10;
  undefined1 local_res18 [8];
  undefined1 local_res20 [8];
  undefined1 auStack_5c8 [8];
  undefined1 auStack_5c0 [232];
  undefined1 local_4d8 [152];
  undefined1 *local_440;
  DWORD64 local_3e0;
  
  puVar4 = auStack_5c8;
  BVar2 = IsProcessorFeaturePresent(0x17);
  if (BVar2 != 0) {
    pcVar1 = (code *)swi(0x29);
    (*pcVar1)(param_1);
    puVar4 = auStack_5c0;
  }
  _DAT_18001ced8 = 0;
  *(undefined8 *)(puVar4 + -8) = 0x180002a95;
  FUN_180003320((undefined1 (*) [16])local_4d8,0,0x4d0);
  *(undefined8 *)(puVar4 + -8) = 0x180002a9f;
  RtlCaptureContext(local_4d8);
  *(undefined8 *)(puVar4 + -8) = 0x180002ab9;
  FunctionEntry = RtlLookupFunctionEntry(local_3e0,&local_res10,(PUNWIND_HISTORY_TABLE)0x0);
  if (FunctionEntry != (PRUNTIME_FUNCTION)0x0) {
    *(undefined8 *)(puVar4 + 0x38) = 0;
    *(undefined1 **)(puVar4 + 0x30) = local_res18;
    *(undefined1 **)(puVar4 + 0x28) = local_res20;
    *(undefined1 **)(puVar4 + 0x20) = local_4d8;
    *(undefined8 *)(puVar4 + -8) = 0x180002afa;
    RtlVirtualUnwind(0,local_res10,local_3e0,FunctionEntry,*(PCONTEXT *)(puVar4 + 0x20),
                     *(PVOID **)(puVar4 + 0x28),*(PDWORD64 *)(puVar4 + 0x30),
                     *(PKNONVOLATILE_CONTEXT_POINTERS *)(puVar4 + 0x38));
  }
  local_440 = &stack0x00000008;
  *(undefined8 *)(puVar4 + -8) = 0x180002b2c;
  FUN_180003320((undefined1 (*) [16])(puVar4 + 0x50),0,0x98);
  *(undefined8 *)(puVar4 + 0x60) = unaff_retaddr;
  *(undefined4 *)(puVar4 + 0x50) = 0x40000015;
  *(undefined4 *)(puVar4 + 0x54) = 1;
  *(undefined8 *)(puVar4 + -8) = 0x180002b4e;
  BVar2 = IsDebuggerPresent();
  *(undefined1 **)(puVar4 + 0x40) = puVar4 + 0x50;
  *(undefined1 **)(puVar4 + 0x48) = local_4d8;
  *(undefined8 *)(puVar4 + -8) = 0x180002b6f;
  SetUnhandledExceptionFilter((LPTOP_LEVEL_EXCEPTION_FILTER)0x0);
  *(undefined8 *)(puVar4 + -8) = 0x180002b7a;
  LVar3 = UnhandledExceptionFilter((_EXCEPTION_POINTERS *)(puVar4 + 0x40));
  if (LVar3 == 0) {
    _DAT_18001ced8 = _DAT_18001ced8 & -(uint)(BVar2 == 1);
  }
  return;
}



/* ---- FUN_180002b9c @ 180002b9c ---- */

void FUN_180002b9c(void)

{
  code *pcVar1;
  undefined8 *puVar2;
  
  for (puVar2 = &DAT_180019f00; puVar2 < &DAT_180019f00; puVar2 = puVar2 + 1) {
    pcVar1 = (code *)*puVar2;
    if (pcVar1 != (code *)0x0) {
      _guard_check_icall();
      (*pcVar1)();
    }
  }
  return;
}



/* ---- FUN_180002be8 @ 180002be8 ---- */

void FUN_180002be8(void)

{
  code *pcVar1;
  undefined8 *puVar2;
  
  for (puVar2 = &DAT_180019f10; puVar2 < &DAT_180019f10; puVar2 = puVar2 + 1) {
    pcVar1 = (code *)*puVar2;
    if (pcVar1 != (code *)0x0) {
      _guard_check_icall();
      (*pcVar1)();
    }
  }
  return;
}



/* ---- _guard_check_icall @ 180002c34 ---- */

/* WARNING: Switch with 1 destination removed at 0x000180002c34 */

void _guard_check_icall(void)

{
  return;
}



/* ---- __isa_available_init @ 180002c3c ---- */

/* WARNING: Removing unreachable block (ram,0x000180002d59) */
/* WARNING: Removing unreachable block (ram,0x000180002cbe) */
/* WARNING: Removing unreachable block (ram,0x000180002c60) */
/* Library Function - Single Match
    __isa_available_init
   
   Library: Visual Studio 2015 Release */

undefined8 __isa_available_init(void)

{
  int *piVar1;
  uint *puVar2;
  longlong lVar3;
  uint uVar4;
  undefined8 uVar5;
  uint uVar6;
  uint uVar7;
  byte in_XCR0;
  uint local_20;
  
  local_20 = 0;
  DAT_18001c01c = 2;
  piVar1 = (int *)cpuid_basic_info(0);
  DAT_18001c018 = 1;
  puVar2 = (uint *)cpuid_Version_info(1);
  uVar4 = puVar2[3];
  uVar6 = DAT_18001cedc;
  if ((piVar1[2] == 0x49656e69 && piVar1[3] == 0x6c65746e) && piVar1[1] == 0x756e6547) {
    DAT_18001c020 = 0xffffffffffffffff;
    uVar7 = *puVar2 & 0xfff3ff0;
    if ((((uVar7 == 0x106c0) || (uVar7 == 0x20660)) || (uVar7 == 0x20670)) ||
       ((uVar6 = DAT_18001cedc | 4, uVar7 - 0x30650 < 0x21 &&
        ((0x100010001U >> ((ulonglong)(uVar7 - 0x30650) & 0x3f) & 1) != 0)))) {
      uVar6 = DAT_18001cedc | 5;
    }
  }
  DAT_18001cedc = uVar6;
  if (((piVar1[1] == 0x68747541 && piVar1[2] == 0x69746e65) && piVar1[3] == 0x444d4163) &&
     (0x600eff < (*puVar2 & 0xff00f00))) {
    DAT_18001cedc = DAT_18001cedc | 4;
  }
  if (6 < *piVar1) {
    lVar3 = cpuid_Extended_Feature_Enumeration_info(7);
    local_20 = *(uint *)(lVar3 + 4);
    if ((local_20 >> 9 & 1) != 0) {
      DAT_18001cedc = DAT_18001cedc | 2;
    }
  }
  if ((uVar4 >> 0x14 & 1) != 0) {
    DAT_18001c018 = 2;
    DAT_18001c01c = 6;
    if ((((uVar4 >> 0x1b & 1) != 0) && ((uVar4 >> 0x1c & 1) != 0)) &&
       (uVar5 = xinuse(0), (in_XCR0 & (byte)uVar5 & 6) == 6)) {
      DAT_18001c01c = 0xe;
      DAT_18001c018 = 3;
      if ((local_20 & 0x20) != 0) {
        DAT_18001c018 = 5;
        DAT_18001c01c = 0x2e;
      }
    }
  }
  return 0;
}



/* ---- __scrt_is_ucrt_dll_in_use @ 180002e04 ---- */

/* Library Function - Single Match
    __scrt_is_ucrt_dll_in_use
   
   Library: Visual Studio 2015 Release */

bool __scrt_is_ucrt_dll_in_use(void)

{
  return DAT_18001da88 != 0;
}



/* ---- FUN_180002e10 @ 180002e10 ---- */

undefined1 (*) [16] FUN_180002e10(undefined1 (*param_1) [16],ushort param_2)

{
  undefined1 *puVar1;
  int iVar2;
  undefined1 (*pauVar3) [16];
  undefined1 (*pauVar4) [16];
  bool bVar5;
  bool bVar6;
  
  pauVar3 = (undefined1 (*) [16])0x0;
  pauVar4 = param_1;
  if (1 < DAT_18001c018) {
    while( true ) {
      if (((int)param_1 + 1U & 0xe) == 0) {
        bVar5 = param_2 != 0;
        if (param_2 != 0) {
          bVar6 = false;
          while( true ) {
            iVar2 = pcmpistri(ZEXT216(param_2),*param_1,0x41);
            if (bVar5) {
              pauVar3 = (undefined1 (*) [16])(*param_1 + (longlong)iVar2 * 2);
            }
            if (bVar6) break;
            bVar5 = (undefined1 (*) [16])0xffffffffffffffef < param_1;
            param_1 = param_1 + 1;
            bVar6 = param_1 == (undefined1 (*) [16])0x0;
          }
          return pauVar3;
        }
        bVar5 = true;
        while (iVar2 = pcmpistri(ZEXT416(0xffff0001),*param_1,0x15), !bVar5) {
          param_1 = param_1 + 1;
          bVar5 = param_1 == (undefined1 (*) [16])0x0;
        }
        return (undefined1 (*) [16])(*param_1 + (longlong)iVar2 * 2);
      }
      if (*(ushort *)*param_1 == param_2) {
        pauVar3 = param_1;
      }
      if (*(short *)*param_1 == 0) break;
      param_1 = (undefined1 (*) [16])(*param_1 + 2);
    }
    return pauVar3;
  }
  do {
    puVar1 = *pauVar4;
    pauVar4 = (undefined1 (*) [16])(*pauVar4 + 2);
  } while (*(short *)puVar1 != 0);
  do {
    pauVar4 = (undefined1 (*) [16])(pauVar4[-1] + 0xe);
    if (pauVar4 == param_1) break;
  } while (*(ushort *)*pauVar4 != param_2);
  if (*(ushort *)*pauVar4 == param_2) {
    pauVar3 = pauVar4;
  }
  return pauVar3;
}



/* ---- FUN_180002ed0 @ 180002ed0 ---- */

undefined8 * FUN_180002ed0(undefined8 *param_1,undefined8 *param_2,ulonglong param_3)

{
  undefined4 *puVar1;
  undefined4 *puVar2;
  undefined8 *puVar3;
  undefined8 *puVar4;
  undefined1 uVar5;
  undefined2 uVar6;
  undefined4 uVar7;
  undefined4 uVar8;
  undefined4 uVar9;
  undefined8 *puVar10;
  undefined8 *puVar11;
  longlong lVar12;
  ulonglong uVar13;
  ulonglong uVar14;
  undefined8 uVar15;
  undefined8 uVar16;
  undefined8 uVar17;
  undefined8 uVar18;
  undefined4 uVar19;
  undefined4 uVar20;
  undefined4 uVar21;
  undefined4 uVar22;
  
  switch(param_3) {
  case 0:
    return param_1;
  case 1:
    *(undefined1 *)param_1 = *(undefined1 *)param_2;
    return param_1;
  case 2:
    *(undefined2 *)param_1 = *(undefined2 *)param_2;
    return param_1;
  case 3:
    uVar5 = *(undefined1 *)((longlong)param_2 + 2);
    *(undefined2 *)param_1 = *(undefined2 *)param_2;
    *(undefined1 *)((longlong)param_1 + 2) = uVar5;
    return param_1;
  case 4:
    *(undefined4 *)param_1 = *(undefined4 *)param_2;
    return param_1;
  case 5:
    uVar5 = *(undefined1 *)((longlong)param_2 + 4);
    *(undefined4 *)param_1 = *(undefined4 *)param_2;
    *(undefined1 *)((longlong)param_1 + 4) = uVar5;
    return param_1;
  case 6:
    uVar6 = *(undefined2 *)((longlong)param_2 + 4);
    *(undefined4 *)param_1 = *(undefined4 *)param_2;
    *(undefined2 *)((longlong)param_1 + 4) = uVar6;
    return param_1;
  case 7:
    uVar6 = *(undefined2 *)((longlong)param_2 + 4);
    uVar5 = *(undefined1 *)((longlong)param_2 + 6);
    *(undefined4 *)param_1 = *(undefined4 *)param_2;
    *(undefined2 *)((longlong)param_1 + 4) = uVar6;
    *(undefined1 *)((longlong)param_1 + 6) = uVar5;
    return param_1;
  case 8:
    *param_1 = *param_2;
    return param_1;
  case 9:
    uVar5 = *(undefined1 *)(param_2 + 1);
    *param_1 = *param_2;
    *(undefined1 *)(param_1 + 1) = uVar5;
    return param_1;
  case 10:
    uVar6 = *(undefined2 *)(param_2 + 1);
    *param_1 = *param_2;
    *(undefined2 *)(param_1 + 1) = uVar6;
    return param_1;
  case 0xb:
    uVar6 = *(undefined2 *)(param_2 + 1);
    uVar5 = *(undefined1 *)((longlong)param_2 + 10);
    *param_1 = *param_2;
    *(undefined2 *)(param_1 + 1) = uVar6;
    *(undefined1 *)((longlong)param_1 + 10) = uVar5;
    return param_1;
  case 0xc:
    uVar19 = *(undefined4 *)(param_2 + 1);
    *param_1 = *param_2;
    *(undefined4 *)(param_1 + 1) = uVar19;
    return param_1;
  case 0xd:
    uVar19 = *(undefined4 *)(param_2 + 1);
    uVar5 = *(undefined1 *)((longlong)param_2 + 0xc);
    *param_1 = *param_2;
    *(undefined4 *)(param_1 + 1) = uVar19;
    *(undefined1 *)((longlong)param_1 + 0xc) = uVar5;
    return param_1;
  case 0xe:
    uVar19 = *(undefined4 *)(param_2 + 1);
    uVar6 = *(undefined2 *)((longlong)param_2 + 0xc);
    *param_1 = *param_2;
    *(undefined4 *)(param_1 + 1) = uVar19;
    *(undefined2 *)((longlong)param_1 + 0xc) = uVar6;
    return param_1;
  case 0xf:
    uVar19 = *(undefined4 *)(param_2 + 1);
    uVar6 = *(undefined2 *)((longlong)param_2 + 0xc);
    uVar5 = *(undefined1 *)((longlong)param_2 + 0xe);
    *param_1 = *param_2;
    *(undefined4 *)(param_1 + 1) = uVar19;
    *(undefined2 *)((longlong)param_1 + 0xc) = uVar6;
    *(undefined1 *)((longlong)param_1 + 0xe) = uVar5;
    return param_1;
  case 0x10:
    uVar15 = param_2[1];
    *param_1 = *param_2;
    param_1[1] = uVar15;
    return param_1;
  }
  if (0x20 < param_3) {
    lVar12 = (longlong)param_2 - (longlong)param_1;
    if ((param_2 < param_1) && ((longlong)param_1 < (longlong)((longlong)param_2 + param_3))) {
      puVar11 = (undefined8 *)((longlong)param_1 + lVar12 + -0x10 + param_3);
      uVar15 = *puVar11;
      uVar17 = puVar11[1];
      puVar10 = (undefined8 *)((longlong)param_1 + (param_3 - 0x10));
      uVar13 = param_3 - 0x10;
      puVar11 = puVar10;
      uVar16 = uVar15;
      uVar18 = uVar17;
      if (((ulonglong)puVar10 & 0xf) != 0) {
        puVar11 = (undefined8 *)((ulonglong)puVar10 & 0xfffffffffffffff0);
        uVar16 = *(undefined8 *)(lVar12 + (longlong)puVar11);
        uVar18 = ((undefined8 *)(lVar12 + (longlong)puVar11))[1];
        *puVar10 = uVar15;
        *(undefined8 *)((longlong)param_1 + (param_3 - 8)) = uVar17;
        uVar13 = (longlong)puVar11 - (longlong)param_1;
      }
      uVar14 = uVar13 >> 7;
      if (uVar14 != 0) {
        *puVar11 = uVar16;
        puVar11[1] = uVar18;
        puVar10 = puVar11;
        while( true ) {
          puVar3 = (undefined8 *)(lVar12 + -0x10 + (longlong)puVar10);
          uVar15 = puVar3[1];
          puVar11 = (undefined8 *)(lVar12 + -0x20 + (longlong)puVar10);
          uVar17 = *puVar11;
          uVar16 = puVar11[1];
          puVar11 = puVar10 + -0x10;
          puVar10[-2] = *puVar3;
          puVar10[-1] = uVar15;
          puVar10[-4] = uVar17;
          puVar10[-3] = uVar16;
          puVar3 = (undefined8 *)(lVar12 + 0x50 + (longlong)puVar11);
          uVar15 = puVar3[1];
          puVar4 = (undefined8 *)(lVar12 + 0x40 + (longlong)puVar11);
          uVar17 = *puVar4;
          uVar16 = puVar4[1];
          uVar14 = uVar14 - 1;
          puVar10[-6] = *puVar3;
          puVar10[-5] = uVar15;
          puVar10[-8] = uVar17;
          puVar10[-7] = uVar16;
          puVar3 = (undefined8 *)(lVar12 + 0x30 + (longlong)puVar11);
          uVar15 = puVar3[1];
          puVar4 = (undefined8 *)(lVar12 + 0x20 + (longlong)puVar11);
          uVar17 = *puVar4;
          uVar16 = puVar4[1];
          puVar10[-10] = *puVar3;
          puVar10[-9] = uVar15;
          puVar10[-0xc] = uVar17;
          puVar10[-0xb] = uVar16;
          puVar3 = (undefined8 *)(lVar12 + 0x10 + (longlong)puVar11);
          uVar15 = *puVar3;
          uVar17 = puVar3[1];
          uVar16 = *(undefined8 *)(lVar12 + (longlong)puVar11);
          uVar18 = ((undefined8 *)(lVar12 + (longlong)puVar11))[1];
          if (uVar14 == 0) break;
          puVar10[-0xe] = uVar15;
          puVar10[-0xd] = uVar17;
          *puVar11 = uVar16;
          puVar10[-0xf] = uVar18;
          puVar10 = puVar11;
        }
        puVar10[-0xe] = uVar15;
        puVar10[-0xd] = uVar17;
        uVar13 = uVar13 & 0x7f;
      }
      for (uVar14 = uVar13 >> 4; uVar14 != 0; uVar14 = uVar14 - 1) {
        *puVar11 = uVar16;
        puVar11[1] = uVar18;
        puVar11 = puVar11 + -2;
        uVar16 = *(undefined8 *)(lVar12 + (longlong)puVar11);
        uVar18 = ((undefined8 *)(lVar12 + (longlong)puVar11))[1];
      }
      if ((uVar13 & 0xf) != 0) {
        uVar15 = param_2[1];
        *param_1 = *param_2;
        param_1[1] = uVar15;
      }
      *puVar11 = uVar16;
      puVar11[1] = uVar18;
      return param_1;
    }
    if (param_3 < 0x81) {
      puVar1 = (undefined4 *)(lVar12 + (longlong)param_1);
      uVar19 = *puVar1;
      uVar20 = puVar1[1];
      uVar21 = puVar1[2];
      uVar22 = puVar1[3];
      puVar11 = param_1 + 2;
      uVar13 = param_3 - 0x10;
    }
    else {
      if ((DAT_18001cedc >> 1 & 1) != 0) {
        puVar11 = param_1;
        for (; param_3 != 0; param_3 = param_3 - 1) {
          *(undefined1 *)puVar11 = *(undefined1 *)param_2;
          param_2 = (undefined8 *)((longlong)param_2 + 1);
          puVar11 = (undefined8 *)((longlong)puVar11 + 1);
        }
        return param_1;
      }
      puVar1 = (undefined4 *)(lVar12 + (longlong)param_1);
      uVar7 = puVar1[1];
      uVar8 = puVar1[2];
      uVar9 = puVar1[3];
      puVar10 = param_1 + 2;
      uVar19 = *puVar1;
      uVar20 = uVar7;
      uVar21 = uVar8;
      uVar22 = uVar9;
      if (((ulonglong)param_1 & 0xf) != 0) {
        puVar2 = (undefined4 *)(lVar12 + ((ulonglong)puVar10 & 0xfffffffffffffff0));
        uVar19 = *puVar2;
        uVar20 = puVar2[1];
        uVar21 = puVar2[2];
        uVar22 = puVar2[3];
        puVar10 = (undefined8 *)(((ulonglong)puVar10 & 0xfffffffffffffff0) + 0x10);
        *(undefined4 *)param_1 = *puVar1;
        *(undefined4 *)((longlong)param_1 + 4) = uVar7;
        *(undefined4 *)(param_1 + 1) = uVar8;
        *(undefined4 *)((longlong)param_1 + 0xc) = uVar9;
      }
      uVar13 = (longlong)param_1 + (param_3 - (longlong)puVar10);
      uVar14 = uVar13 >> 7;
      puVar11 = puVar10;
      if (uVar14 != 0) {
        *(undefined4 *)(puVar10 + -2) = uVar19;
        *(undefined4 *)((longlong)puVar10 + -0xc) = uVar20;
        *(undefined4 *)(puVar10 + -1) = uVar21;
        *(undefined4 *)((longlong)puVar10 + -4) = uVar22;
        if (DAT_18001c020 < uVar14) {
          while( true ) {
            uVar15 = ((undefined8 *)(lVar12 + (longlong)puVar10))[1];
            puVar11 = (undefined8 *)(lVar12 + 0x10 + (longlong)puVar10);
            uVar17 = *puVar11;
            uVar16 = puVar11[1];
            puVar11 = puVar10 + 0x10;
            *puVar10 = *(undefined8 *)(lVar12 + (longlong)puVar10);
            puVar10[1] = uVar15;
            puVar10[2] = uVar17;
            puVar10[3] = uVar16;
            puVar3 = (undefined8 *)(lVar12 + -0x60 + (longlong)puVar11);
            uVar15 = puVar3[1];
            puVar4 = (undefined8 *)(lVar12 + -0x50 + (longlong)puVar11);
            uVar17 = *puVar4;
            uVar16 = puVar4[1];
            uVar14 = uVar14 - 1;
            puVar10[4] = *puVar3;
            puVar10[5] = uVar15;
            puVar10[6] = uVar17;
            puVar10[7] = uVar16;
            puVar3 = (undefined8 *)(lVar12 + -0x40 + (longlong)puVar11);
            uVar15 = puVar3[1];
            puVar4 = (undefined8 *)(lVar12 + -0x30 + (longlong)puVar11);
            uVar17 = *puVar4;
            uVar16 = puVar4[1];
            puVar10[8] = *puVar3;
            puVar10[9] = uVar15;
            puVar10[10] = uVar17;
            puVar10[0xb] = uVar16;
            puVar3 = (undefined8 *)(lVar12 + -0x20 + (longlong)puVar11);
            uVar15 = *puVar3;
            uVar17 = puVar3[1];
            puVar1 = (undefined4 *)(lVar12 + -0x10 + (longlong)puVar11);
            uVar19 = *puVar1;
            uVar20 = puVar1[1];
            uVar21 = puVar1[2];
            uVar22 = puVar1[3];
            if (uVar14 == 0) break;
            puVar10[0xc] = uVar15;
            puVar10[0xd] = uVar17;
            *(undefined4 *)(puVar10 + 0xe) = uVar19;
            *(undefined4 *)((longlong)puVar10 + 0x74) = uVar20;
            *(undefined4 *)(puVar10 + 0xf) = uVar21;
            *(undefined4 *)((longlong)puVar10 + 0x7c) = uVar22;
            puVar10 = puVar11;
          }
        }
        else {
          while( true ) {
            uVar15 = ((undefined8 *)(lVar12 + (longlong)puVar10))[1];
            puVar11 = (undefined8 *)(lVar12 + 0x10 + (longlong)puVar10);
            uVar17 = *puVar11;
            uVar16 = puVar11[1];
            puVar11 = puVar10 + 0x10;
            *puVar10 = *(undefined8 *)(lVar12 + (longlong)puVar10);
            puVar10[1] = uVar15;
            puVar10[2] = uVar17;
            puVar10[3] = uVar16;
            puVar3 = (undefined8 *)(lVar12 + -0x60 + (longlong)puVar11);
            uVar15 = puVar3[1];
            puVar4 = (undefined8 *)(lVar12 + -0x50 + (longlong)puVar11);
            uVar17 = *puVar4;
            uVar16 = puVar4[1];
            uVar14 = uVar14 - 1;
            puVar10[4] = *puVar3;
            puVar10[5] = uVar15;
            puVar10[6] = uVar17;
            puVar10[7] = uVar16;
            puVar3 = (undefined8 *)(lVar12 + -0x40 + (longlong)puVar11);
            uVar15 = puVar3[1];
            puVar4 = (undefined8 *)(lVar12 + -0x30 + (longlong)puVar11);
            uVar17 = *puVar4;
            uVar16 = puVar4[1];
            puVar10[8] = *puVar3;
            puVar10[9] = uVar15;
            puVar10[10] = uVar17;
            puVar10[0xb] = uVar16;
            puVar3 = (undefined8 *)(lVar12 + -0x20 + (longlong)puVar11);
            uVar15 = *puVar3;
            uVar17 = puVar3[1];
            puVar1 = (undefined4 *)(lVar12 + -0x10 + (longlong)puVar11);
            uVar19 = *puVar1;
            uVar20 = puVar1[1];
            uVar21 = puVar1[2];
            uVar22 = puVar1[3];
            if (uVar14 == 0) break;
            puVar10[0xc] = uVar15;
            puVar10[0xd] = uVar17;
            *(undefined4 *)(puVar10 + 0xe) = uVar19;
            *(undefined4 *)((longlong)puVar10 + 0x74) = uVar20;
            *(undefined4 *)(puVar10 + 0xf) = uVar21;
            *(undefined4 *)((longlong)puVar10 + 0x7c) = uVar22;
            puVar10 = puVar11;
          }
        }
        puVar11[-4] = uVar15;
        puVar11[-3] = uVar17;
        uVar13 = uVar13 & 0x7f;
      }
    }
    for (uVar14 = uVar13 >> 4; uVar14 != 0; uVar14 = uVar14 - 1) {
      *(undefined4 *)(puVar11 + -2) = uVar19;
      *(undefined4 *)((longlong)puVar11 + -0xc) = uVar20;
      *(undefined4 *)(puVar11 + -1) = uVar21;
      *(undefined4 *)((longlong)puVar11 + -4) = uVar22;
      puVar1 = (undefined4 *)(lVar12 + (longlong)puVar11);
      uVar19 = *puVar1;
      uVar20 = puVar1[1];
      uVar21 = puVar1[2];
      uVar22 = puVar1[3];
      puVar11 = puVar11 + 2;
    }
    uVar13 = uVar13 & 0xf;
    if (uVar13 != 0) {
      puVar10 = (undefined8 *)((longlong)puVar11 + lVar12 + -0x10 + uVar13);
      uVar15 = puVar10[1];
      *(undefined8 *)((longlong)puVar11 + (uVar13 - 0x10)) = *puVar10;
      *(undefined8 *)((longlong)puVar11 + (uVar13 - 8)) = uVar15;
    }
    *(undefined4 *)(puVar11 + -2) = uVar19;
    *(undefined4 *)((longlong)puVar11 + -0xc) = uVar20;
    *(undefined4 *)(puVar11 + -1) = uVar21;
    *(undefined4 *)((longlong)puVar11 + -4) = uVar22;
    return param_1;
  }
  uVar15 = param_2[1];
  puVar11 = (undefined8 *)((param_3 - 0x10) + (longlong)param_2);
  uVar17 = *puVar11;
  uVar16 = puVar11[1];
  *param_1 = *param_2;
  param_1[1] = uVar15;
  puVar11 = (undefined8 *)((param_3 - 0x10) + (longlong)param_1);
  *puVar11 = uVar17;
  puVar11[1] = uVar16;
  return param_1;
}



/* ---- FUN_180003320 @ 180003320 ---- */

undefined1 (*) [16] FUN_180003320(undefined1 (*param_1) [16],byte param_2,ulonglong param_3)

{
  undefined1 (*pauVar1) [16];
  undefined1 (*pauVar2) [16];
  undefined1 uVar3;
  ulonglong uVar6;
  undefined1 auVar7 [16];
  undefined2 uVar4;
  undefined4 uVar5;
  undefined1 auVar8 [16];
  undefined1 auVar9 [16];
  undefined1 auVar10 [16];
  undefined1 auVar11 [16];
  undefined1 auVar12 [16];
  undefined1 auVar13 [16];
  undefined1 auVar14 [16];
  undefined1 auVar15 [16];
  undefined1 auVar16 [16];
  undefined1 uVar17;
  
  uVar6 = (ulonglong)param_2 * 0x101010101010101;
  uVar3 = (undefined1)uVar6;
  uVar4 = (undefined2)uVar6;
  uVar5 = (undefined4)uVar6;
  switch(param_3) {
  case 0:
    return param_1;
  case 8:
    *(ulonglong *)*param_1 = uVar6;
    return param_1;
  case 9:
    *(ulonglong *)(param_1[-1] + param_3 + 7) = uVar6;
    param_1[-1][param_3 + 0xf] = uVar3;
    return param_1;
  case 10:
    *(ulonglong *)*param_1 = uVar6;
    *(undefined2 *)(*param_1 + 8) = uVar4;
    return param_1;
  case 0xb:
    *(ulonglong *)*param_1 = uVar6;
    *(undefined2 *)(*param_1 + 8) = uVar4;
    (*param_1)[10] = uVar3;
    return param_1;
  case 0xc:
    *(ulonglong *)(param_1[-1] + param_3 + 4) = uVar6;
  case 4:
    *(undefined4 *)(param_1[-1] + param_3 + 0xc) = uVar5;
    return param_1;
  case 0xd:
    *(ulonglong *)(param_1[-1] + param_3 + 3) = uVar6;
  case 5:
    *(undefined4 *)(param_1[-1] + param_3 + 0xb) = uVar5;
    param_1[-1][param_3 + 0xf] = uVar3;
    return param_1;
  case 0xe:
    *(ulonglong *)(param_1[-1] + param_3 + 2) = uVar6;
  case 6:
    *(undefined4 *)(param_1[-1] + param_3 + 10) = uVar5;
  case 2:
    *(undefined2 *)(param_1[-1] + param_3 + 0xe) = uVar4;
    return param_1;
  case 0xf:
    *(ulonglong *)(param_1[-1] + param_3 + 1) = uVar6;
  case 7:
    *(undefined4 *)(param_1[-1] + param_3 + 9) = uVar5;
  case 3:
    *(undefined2 *)(param_1[-1] + param_3 + 0xd) = uVar4;
  case 1:
    param_1[-1][param_3 + 0xf] = uVar3;
    return param_1;
  case 0x10:
    *(ulonglong *)*param_1 = uVar6;
    *(ulonglong *)(*param_1 + 8) = uVar6;
    return param_1;
  }
  uVar17 = (undefined1)(uVar6 >> 0x38);
  auVar16._8_6_ = 0;
  auVar16._0_8_ = uVar6;
  auVar16[0xe] = uVar17;
  auVar16[0xf] = uVar17;
  uVar17 = (undefined1)(uVar6 >> 0x30);
  auVar15._14_2_ = auVar16._14_2_;
  auVar15._8_5_ = 0;
  auVar15._0_8_ = uVar6;
  auVar15[0xd] = uVar17;
  auVar14._13_3_ = auVar15._13_3_;
  auVar14._8_4_ = 0;
  auVar14._0_8_ = uVar6;
  auVar14[0xc] = uVar17;
  uVar17 = (undefined1)(uVar6 >> 0x28);
  auVar13._12_4_ = auVar14._12_4_;
  auVar13._8_3_ = 0;
  auVar13._0_8_ = uVar6;
  auVar13[0xb] = uVar17;
  auVar12._11_5_ = auVar13._11_5_;
  auVar12._8_2_ = 0;
  auVar12._0_8_ = uVar6;
  auVar12[10] = uVar17;
  uVar17 = (undefined1)(uVar6 >> 0x20);
  auVar11._10_6_ = auVar12._10_6_;
  auVar11[8] = 0;
  auVar11._0_8_ = uVar6;
  auVar11[9] = uVar17;
  auVar10._9_7_ = auVar11._9_7_;
  auVar10[8] = uVar17;
  auVar10._0_8_ = uVar6;
  uVar17 = (undefined1)(uVar6 >> 0x18);
  auVar9._8_8_ = auVar10._8_8_;
  auVar9[7] = uVar17;
  auVar9[6] = uVar17;
  uVar17 = (undefined1)(uVar6 >> 0x10);
  auVar9[5] = uVar17;
  auVar9[4] = uVar17;
  auVar9._0_4_ = uVar5;
  uVar17 = (undefined1)(uVar6 >> 8);
  auVar8._4_12_ = auVar9._4_12_;
  auVar8[3] = uVar17;
  auVar8[2] = uVar17;
  auVar8._0_2_ = uVar4;
  auVar7._2_14_ = auVar8._2_14_;
  auVar7[1] = uVar3;
  auVar7[0] = uVar3;
  pauVar2 = param_1;
  if (0x80 < param_3) {
    if ((DAT_18001cedc >> 1 & 1) != 0) {
      for (; param_3 != 0; param_3 = param_3 - 1) {
        (*pauVar2)[0] = param_2;
        pauVar2 = (undefined1 (*) [16])(*pauVar2 + 1);
      }
      return param_1;
    }
    *param_1 = auVar7;
    pauVar1 = (undefined1 (*) [16])((ulonglong)(param_1 + 1) & 0xfffffffffffffff0);
    param_3 = (longlong)param_1 + (param_3 - (longlong)pauVar1);
    uVar6 = param_3 >> 7;
    pauVar2 = pauVar1;
    if (uVar6 != 0) {
      do {
        *pauVar1 = auVar7;
        pauVar1[1] = auVar7;
        pauVar2 = pauVar1 + 8;
        pauVar1[2] = auVar7;
        pauVar1[3] = auVar7;
        uVar6 = uVar6 - 1;
        pauVar1[4] = auVar7;
        pauVar1[5] = auVar7;
        pauVar1[6] = auVar7;
        pauVar1[7] = auVar7;
        pauVar1 = pauVar2;
      } while (uVar6 != 0);
      param_3 = param_3 & 0x7f;
    }
  }
  for (uVar6 = param_3 >> 4; uVar6 != 0; uVar6 = uVar6 - 1) {
    *pauVar2 = auVar7;
    pauVar2 = pauVar2 + 1;
  }
  if ((param_3 & 0xf) != 0) {
    *(undefined1 (*) [16])(pauVar2[-1] + (param_3 & 0xf)) = auVar7;
  }
  return param_1;
}



/* ---- __C_specific_handler @ 1800034c0 ---- */

/* Library Function - Single Match
    __C_specific_handler
   
   Library: Visual Studio 2015 Release */

EXCEPTION_DISPOSITION
__C_specific_handler
          (_EXCEPTION_RECORD *ExceptionRecord,void *EstablisherFrame,_CONTEXT *ContextRecord,
          _DISPATCHER_CONTEXT *DispatcherContext)

{
  uint uVar1;
  longlong lVar2;
  uint *puVar3;
  int iVar4;
  BOOL BVar5;
  ulonglong uVar6;
  uint uVar7;
  ulonglong uVar8;
  uint uVar9;
  ulonglong uVar10;
  uint uVar11;
  ulonglong uVar12;
  _EXCEPTION_RECORD *local_38;
  _CONTEXT *local_30;
  
  lVar2 = *(longlong *)(DispatcherContext + 8);
  puVar3 = *(uint **)(DispatcherContext + 0x38);
  uVar12 = *(longlong *)DispatcherContext - lVar2;
  _guard_check_icall();
  if ((ExceptionRecord->ExceptionFlags & 0x66) == 0) {
    local_38 = ExceptionRecord;
    local_30 = ContextRecord;
    for (uVar7 = *(uint *)(DispatcherContext + 0x48); uVar7 < *puVar3; uVar7 = uVar7 + 1) {
      uVar8 = (ulonglong)uVar7;
      if (((puVar3[uVar8 * 4 + 1] <= uVar12) && (uVar12 < puVar3[uVar8 * 4 + 2])) &&
         (puVar3[uVar8 * 4 + 4] != 0)) {
        if (puVar3[uVar8 * 4 + 3] != 1) {
          iVar4 = (*(code *)((ulonglong)puVar3[uVar8 * 4 + 3] + lVar2))(&local_38,EstablisherFrame);
          if (iVar4 < 0) {
            return ExceptionContinueExecution;
          }
          if (iVar4 < 1) goto LAB_1800035da;
        }
        if (((ExceptionRecord->ExceptionCode == 0xe06d7363) && (DAT_18001da98 != (code *)0x0)) &&
           (BVar5 = _IsNonwritableInCurrentImage((PBYTE)&DAT_18001da98), BVar5 != 0)) {
          (*DAT_18001da98)(ExceptionRecord,1);
        }
        _NLG_Notify();
        RtlUnwindEx(EstablisherFrame,(PVOID)((ulonglong)puVar3[uVar8 * 4 + 4] + lVar2),
                    ExceptionRecord,(PVOID)(ulonglong)ExceptionRecord->ExceptionCode,
                    *(PCONTEXT *)(DispatcherContext + 0x28),
                    *(PUNWIND_HISTORY_TABLE *)(DispatcherContext + 0x40));
        FUN_1800037f0();
      }
LAB_1800035da:
    }
  }
  else {
    uVar8 = *(longlong *)(DispatcherContext + 0x20) - lVar2;
    for (uVar7 = *(uint *)(DispatcherContext + 0x48); uVar1 = *puVar3, uVar7 < uVar1;
        uVar7 = uVar7 + 1) {
      uVar6 = (ulonglong)uVar7;
      if ((puVar3[uVar6 * 4 + 1] <= uVar12) && (uVar12 < puVar3[uVar6 * 4 + 2])) {
        uVar11 = ExceptionRecord->ExceptionFlags & 0x20;
        if (uVar11 != 0) {
          uVar10 = 0;
          if (uVar1 != 0) {
            do {
              if ((((puVar3[uVar10 * 4 + 1] <= uVar8) && (uVar8 < puVar3[uVar10 * 4 + 2])) &&
                  (puVar3[uVar10 * 4 + 4] == puVar3[uVar6 * 4 + 4])) &&
                 (puVar3[uVar10 * 4 + 3] == puVar3[uVar6 * 4 + 3])) break;
              uVar9 = (int)uVar10 + 1;
              uVar10 = (ulonglong)uVar9;
            } while (uVar9 < uVar1);
          }
          if ((uint)uVar10 != uVar1) {
            return ExceptionContinueSearch;
          }
        }
        if (puVar3[uVar6 * 4 + 4] == 0) {
          *(uint *)(DispatcherContext + 0x48) = uVar7 + 1;
          (*(code *)((ulonglong)puVar3[uVar6 * 4 + 3] + lVar2))
                    (CONCAT71((int7)(uVar6 * 2 >> 8),1),EstablisherFrame);
        }
        else if ((uVar8 == puVar3[uVar6 * 4 + 4]) && (uVar11 != 0)) {
          return ExceptionContinueSearch;
        }
      }
    }
  }
  return ExceptionContinueSearch;
}



/* ---- __vcrt_initialize @ 1800036bc ---- */

/* Library Function - Single Match
    __vcrt_initialize
   
   Library: Visual Studio 2015 Release */

ulonglong __vcrt_initialize(void)

{
  undefined4 uVar1;
  ulonglong uVar2;
  undefined4 extraout_var;
  
  __vcrt_initialize_pure_virtual_call_handler();
  __vcrt_initialize_winapi_thunks();
  uVar2 = __vcrt_initialize_locks();
  if ((char)uVar2 != '\0') {
    uVar1 = __vcrt_initialize_ptd();
    if ((char)uVar1 != '\0') {
      return CONCAT71((int7)(CONCAT44(extraout_var,uVar1) >> 8),1);
    }
    uVar2 = __vcrt_uninitialize_locks();
  }
  return uVar2 & 0xffffffffffffff00;
}



/* ---- __vcrt_thread_attach @ 1800036f0 ---- */

/* Library Function - Single Match
    __vcrt_thread_attach
   
   Library: Visual Studio 2015 Release */

bool __vcrt_thread_attach(void)

{
  LPVOID pvVar1;
  
  pvVar1 = __vcrt_getptd_noexit();
  return pvVar1 != (LPVOID)0x0;
}



/* ---- __vcrt_thread_detach @ 180003704 ---- */

/* Library Function - Single Match
    __vcrt_thread_detach
   
   Libraries: Visual Studio 2015 Release, Visual Studio 2017 Release, Visual Studio 2019 Release */

undefined1 __vcrt_thread_detach(void)

{
  __vcrt_freeptd((undefined *)0x0);
  return 1;
}



/* ---- __vcrt_uninitialize @ 180003718 ---- */

/* Library Function - Single Match
    __vcrt_uninitialize
   
   Libraries: Visual Studio 2015 Release, Visual Studio 2017 Release */

undefined8 __vcrt_uninitialize(char param_1)

{
  undefined8 in_RAX;
  
  if (param_1 == '\0') {
    __vcrt_uninitialize_ptd();
    __vcrt_uninitialize_locks();
    in_RAX = __vcrt_uninitialize_winapi_thunks('\0');
  }
  return CONCAT71((int7)((ulonglong)in_RAX >> 8),1);
}



/* ---- FUN_180003738 @ 180003738 ---- */

undefined1 FUN_180003738(void)

{
  __vcrt_uninitialize_ptd();
  return 1;
}



/* ---- FUN_180003748 @ 180003748 ---- */

void FUN_180003748(PSLIST_HEADER param_1)

{
  PSLIST_ENTRY p_Var1;
  PSLIST_ENTRY_conflict p_Var2;
  
  p_Var2 = InterlockedFlushSList(param_1);
  while (p_Var2 != (PSLIST_ENTRY_conflict)0x0) {
    p_Var1 = p_Var2->Next;
    _free_base(p_Var2);
    p_Var2 = p_Var1;
  }
  return;
}



/* ---- FUN_180003790 @ 180003790 ---- */

void FUN_180003790(PVOID param_1,PVOID param_2)

{
  RtlUnwindEx(param_1,param_2,(PEXCEPTION_RECORD)0x0,(PVOID)0x0,(PCONTEXT)&stack0xfffffffffffffb28,
              (PUNWIND_HISTORY_TABLE)0x0);
  return;
}



/* ---- _NLG_Notify @ 1800037c0 ---- */

/* Library Function - Single Match
    _NLG_Notify
   
   Library: Visual Studio 2015 Release */

void _NLG_Notify(void)

{
  FUN_1800037e0();
  return;
}



/* ---- FUN_1800037e0 @ 1800037e0 ---- */

void FUN_1800037e0(void)

{
  return;
}



/* ---- FUN_1800037f0 @ 1800037f0 ---- */

void FUN_1800037f0(void)

{
  return;
}



/* ---- FUN_1800037f4 @ 1800037f4 ---- */

void FUN_1800037f4(undefined *param_1)

{
  if ((param_1 != (undefined *)0x0) && (param_1 != &DAT_18001cee0)) {
    _free_base(param_1);
  }
  return;
}



/* ---- __vcrt_freeptd @ 180003814 ---- */

/* Library Function - Single Match
    __vcrt_freeptd
   
   Library: Visual Studio 2015 Release */

void __vcrt_freeptd(undefined *param_1)

{
  if (DAT_18001c030 != 0xffffffff) {
    if (param_1 == (undefined *)0x0) {
      param_1 = (undefined *)__vcrt_FlsGetValue(DAT_18001c030);
    }
    __vcrt_FlsSetValue(DAT_18001c030,(LPVOID)0x0);
    if ((param_1 != (undefined *)0x0) && (param_1 != &DAT_18001cee0)) {
      _free_base(param_1);
    }
  }
  return;
}



/* ---- __vcrt_getptd_noexit @ 180003864 ---- */

/* Library Function - Single Match
    __vcrt_getptd_noexit
   
   Library: Visual Studio 2015 Release */

LPVOID __vcrt_getptd_noexit(void)

{
  DWORD dwErrCode;
  int iVar1;
  LPVOID pvVar2;
  LPVOID pvVar3;
  LPVOID pvVar4;
  
  if (DAT_18001c030 == 0xffffffff) {
    pvVar3 = (LPVOID)0x0;
  }
  else {
    dwErrCode = GetLastError();
    pvVar2 = (LPVOID)__vcrt_FlsGetValue(DAT_18001c030);
    pvVar4 = (LPVOID)0x0;
    pvVar3 = pvVar4;
    if (((pvVar2 != (LPVOID)0xffffffffffffffff) && (pvVar3 = pvVar2, pvVar2 == (LPVOID)0x0)) &&
       (iVar1 = __vcrt_FlsSetValue(DAT_18001c030,(LPVOID)0xffffffffffffffff), pvVar3 = pvVar4,
       iVar1 != 0)) {
      pvVar3 = _calloc_base(1,0x78);
      if ((pvVar3 == (LPVOID)0x0) ||
         (iVar1 = __vcrt_FlsSetValue(DAT_18001c030,pvVar3), pvVar2 = pvVar4, iVar1 == 0)) {
        __vcrt_FlsSetValue(DAT_18001c030,(LPVOID)0x0);
        pvVar2 = pvVar3;
        pvVar3 = pvVar4;
      }
      _free_base(pvVar2);
    }
    SetLastError(dwErrCode);
  }
  return pvVar3;
}



/* ---- __vcrt_initialize_ptd @ 18000391c ---- */

/* Library Function - Single Match
    __vcrt_initialize_ptd
   
   Library: Visual Studio 2015 Release */

uint __vcrt_initialize_ptd(void)

{
  uint uVar1;
  int iVar2;
  uint3 extraout_var;
  
  uVar1 = __vcrt_FlsAlloc(FUN_1800037f4);
  DAT_18001c030 = uVar1;
  if (uVar1 != 0xffffffff) {
    iVar2 = __vcrt_FlsSetValue(uVar1,&DAT_18001cee0);
    if (iVar2 != 0) {
      return CONCAT31((int3)((uint)iVar2 >> 8),1);
    }
    __vcrt_uninitialize_ptd();
    uVar1 = (uint)extraout_var << 8;
  }
  return uVar1 & 0xffffff00;
}



/* ---- __vcrt_uninitialize_ptd @ 18000395c ---- */

/* Library Function - Single Match
    __vcrt_uninitialize_ptd
   
   Library: Visual Studio 2015 Release */

undefined1 __vcrt_uninitialize_ptd(void)

{
  if (DAT_18001c030 != 0xffffffff) {
    __vcrt_FlsFree(DAT_18001c030);
    DAT_18001c030 = 0xffffffff;
  }
  return 1;
}



/* ---- __vcrt_initialize_locks @ 180003980 ---- */

/* Library Function - Single Match
    __vcrt_initialize_locks
   
   Library: Visual Studio 2015 Release */

undefined8 __vcrt_initialize_locks(void)

{
  undefined8 uVar1;
  ulonglong uVar2;
  uint uVar3;
  
  uVar2 = 0;
  do {
    uVar1 = __vcrt_InitializeCriticalSectionEx
                      ((LPCRITICAL_SECTION)(&DAT_18001cf58 + uVar2 * 0x28),4000,0);
    if ((int)uVar1 == 0) {
      uVar2 = __vcrt_uninitialize_locks();
      return uVar2 & 0xffffffffffffff00;
    }
    DAT_18001cf80 = DAT_18001cf80 + 1;
    uVar3 = (int)uVar2 + 1;
    uVar2 = (ulonglong)uVar3;
  } while (uVar3 == 0);
  return CONCAT71((int7)((ulonglong)uVar1 >> 8),1);
}



/* ---- __vcrt_uninitialize_locks @ 1800039c8 ---- */

/* Library Function - Single Match
    __vcrt_uninitialize_locks
   
   Libraries: Visual Studio 2015 Release, Visual Studio 2017 Release */

undefined8 __vcrt_uninitialize_locks(void)

{
  undefined8 in_RAX;
  undefined8 extraout_RAX;
  ulonglong uVar1;
  
  uVar1 = (ulonglong)DAT_18001cf80;
  while ((int)uVar1 != 0) {
    uVar1 = (ulonglong)((int)uVar1 - 1);
    DeleteCriticalSection((LPCRITICAL_SECTION)(&DAT_18001cf58 + uVar1 * 0x28));
    DAT_18001cf80 = DAT_18001cf80 - 1;
    in_RAX = extraout_RAX;
  }
  return CONCAT71((int7)((ulonglong)in_RAX >> 8),1);
}



/* ---- try_get_function @ 180003a00 ---- */

/* Library Function - Single Match
    void * __ptr64 __cdecl try_get_function(enum `anonymous namespace'::function_id,char const *
   __ptr64 const,enum A0x679b24ab::module_id const * __ptr64 const,enum A0x679b24ab::module_id const
   * __ptr64 const)
   
   Library: Visual Studio 2015 Release */

void * __cdecl
try_get_function(function_id param_1,char *param_2,module_id *param_3,module_id *param_4)

{
  longlong lVar1;
  module_id mVar2;
  LPCWSTR lpLibFileName;
  DWORD DVar3;
  ulonglong uVar4;
  HMODULE hLibModule;
  FARPROC pFVar5;
  byte bVar6;
  void *pvVar7;
  bool bVar8;
  
  LOCK();
  uVar4 = (&DAT_18001cfb0)[param_1];
  if (uVar4 == 0) {
    (&DAT_18001cfb0)[param_1] = 0;
    uVar4 = 0;
  }
  UNLOCK();
  bVar6 = (byte)DAT_18001c000 & 0x3f;
  pvVar7 = (void *)((DAT_18001c000 ^ uVar4) >> bVar6 | (DAT_18001c000 ^ uVar4) << 0x40 - bVar6);
  if (pvVar7 != (void *)0xffffffffffffffff) {
    if (pvVar7 != (void *)0x0) {
      return pvVar7;
    }
    for (; param_3 != param_4; param_3 = param_3 + 1) {
      mVar2 = *param_3;
      LOCK();
      hLibModule = (HMODULE)(&DAT_18001cf90)[mVar2];
      bVar8 = hLibModule == (HMODULE)0x0;
      if (bVar8) {
        (&DAT_18001cf90)[mVar2] = 0;
        hLibModule = (HMODULE)0x0;
      }
      UNLOCK();
      if (bVar8) {
        lpLibFileName = (LPCWSTR)(&PTR_u_advapi32_180012400)[mVar2];
        hLibModule = LoadLibraryExW(lpLibFileName,(HANDLE)0x0,0x800);
        if (hLibModule == (HMODULE)0x0) {
          DVar3 = GetLastError();
          if (DVar3 == 0x57) {
            hLibModule = LoadLibraryExW(lpLibFileName,(HANDLE)0x0,0);
          }
          else {
            hLibModule = (HMODULE)0x0;
          }
        }
        if (hLibModule != (HMODULE)0x0) {
          LOCK();
          lVar1 = (&DAT_18001cf90)[mVar2];
          (&DAT_18001cf90)[mVar2] = hLibModule;
          UNLOCK();
          if (lVar1 != 0) {
            FreeLibrary(hLibModule);
          }
          goto LAB_180003b1c;
        }
        LOCK();
        (&DAT_18001cf90)[mVar2] = 0xffffffffffffffff;
        UNLOCK();
      }
      else if (hLibModule != (HMODULE)0xffffffffffffffff) {
LAB_180003b1c:
        if (hLibModule != (HMODULE)0x0) goto LAB_180003b38;
      }
    }
    hLibModule = (HMODULE)0x0;
LAB_180003b38:
    if ((hLibModule != (HMODULE)0x0) &&
       (pFVar5 = GetProcAddress(hLibModule,param_2), pFVar5 != (FARPROC)0x0)) {
      bVar6 = 0x40 - ((byte)DAT_18001c000 & 0x3f) & 0x3f;
      LOCK();
      (&DAT_18001cfb0)[param_1] =
           ((ulonglong)pFVar5 >> bVar6 | (longlong)pFVar5 << 0x40 - bVar6) ^ DAT_18001c000;
      UNLOCK();
      return pFVar5;
    }
    bVar6 = 0x40 - ((byte)DAT_18001c000 & 0x3f) & 0x3f;
    LOCK();
    (&DAT_18001cfb0)[param_1] = (0xffffffffffffffffU >> bVar6 | -1L << 0x40 - bVar6) ^ DAT_18001c000
    ;
    UNLOCK();
  }
  return (void *)0x0;
}



/* ---- __vcrt_FlsAlloc @ 180003bc8 ---- */

/* Library Function - Single Match
    __vcrt_FlsAlloc
   
   Library: Visual Studio 2015 Release */

void __vcrt_FlsAlloc(undefined8 param_1)

{
  code *pcVar1;
  
  pcVar1 = try_get_function(4,"FlsAlloc",(module_id *)&DAT_1800124d0,(module_id *)"FlsAlloc");
  if (pcVar1 == (code *)0x0) {
    TlsAlloc();
  }
  else {
    _guard_check_icall();
    (*pcVar1)(param_1);
  }
  return;
}



/* ---- __vcrt_FlsFree @ 180003c1c ---- */

/* Library Function - Single Match
    __vcrt_FlsFree
   
   Library: Visual Studio 2015 Release */

void __vcrt_FlsFree(DWORD param_1)

{
  code *pcVar1;
  
  pcVar1 = try_get_function(5,"FlsFree",(module_id *)&DAT_1800124e8,(module_id *)"FlsFree");
  if (pcVar1 == (code *)0x0) {
    TlsFree(param_1);
  }
  else {
    _guard_check_icall();
    (*pcVar1)(param_1);
  }
  return;
}



/* ---- __vcrt_FlsGetValue @ 180003c70 ---- */

/* Library Function - Single Match
    __vcrt_FlsGetValue
   
   Library: Visual Studio 2015 Release */

void __vcrt_FlsGetValue(DWORD param_1)

{
  code *pcVar1;
  
  pcVar1 = try_get_function(6,"FlsGetValue",(module_id *)&DAT_1800124f8,(module_id *)"FlsGetValue");
  if (pcVar1 == (code *)0x0) {
    TlsGetValue(param_1);
  }
  else {
    _guard_check_icall();
    (*pcVar1)(param_1);
  }
  return;
}



/* ---- __vcrt_FlsSetValue @ 180003cc4 ---- */

/* Library Function - Single Match
    __vcrt_FlsSetValue
   
   Library: Visual Studio 2015 Release */

void __vcrt_FlsSetValue(DWORD param_1,LPVOID param_2)

{
  code *pcVar1;
  
  pcVar1 = try_get_function(7,"FlsSetValue",(module_id *)&DAT_180012510,(module_id *)"FlsSetValue");
  if (pcVar1 == (code *)0x0) {
    TlsSetValue(param_1,param_2);
  }
  else {
    _guard_check_icall();
    (*pcVar1)(param_1,param_2);
  }
  return;
}



/* ---- __vcrt_InitializeCriticalSectionEx @ 180003d2c ---- */

/* Library Function - Single Match
    __vcrt_InitializeCriticalSectionEx
   
   Library: Visual Studio 2015 Release */

void __vcrt_InitializeCriticalSectionEx(LPCRITICAL_SECTION param_1,DWORD param_2,undefined4 param_3)

{
  code *pcVar1;
  
  pcVar1 = try_get_function(8,"InitializeCriticalSectionEx",(module_id *)&DAT_180012528,
                            (module_id *)"InitializeCriticalSectionEx");
  if (pcVar1 == (code *)0x0) {
    InitializeCriticalSectionAndSpinCount(param_1,param_2);
  }
  else {
    _guard_check_icall();
    (*pcVar1)(param_1,param_2,param_3);
  }
  return;
}



/* ---- __vcrt_initialize_winapi_thunks @ 180003da4 ---- */

/* Library Function - Single Match
    __vcrt_initialize_winapi_thunks
   
   Library: Visual Studio 2015 Release */

void __vcrt_initialize_winapi_thunks(void)

{
  byte bVar1;
  ulonglong *puVar2;
  longlong lVar3;
  ulonglong uVar4;
  
  lVar3 = 0;
  puVar2 = &DAT_18001cfb0;
  bVar1 = 0x40 - ((byte)DAT_18001c000 & 0x3f) & 0x3f;
  uVar4 = (0UL >> bVar1 | 0L << 0x40 - bVar1) ^ DAT_18001c000;
  do {
    lVar3 = lVar3 + 1;
    *puVar2 = uVar4;
    puVar2 = puVar2 + 1;
  } while (lVar3 != 9);
  return;
}



/* ---- __vcrt_uninitialize_winapi_thunks @ 180003df0 ---- */

/* Library Function - Single Match
    __vcrt_uninitialize_winapi_thunks
   
   Libraries: Visual Studio 2015 Release, Visual Studio 2017 Release */

void __vcrt_uninitialize_winapi_thunks(char param_1)

{
  HMODULE hLibModule;
  undefined8 *puVar1;
  
  if (param_1 == '\0') {
    puVar1 = &DAT_18001cf90;
    do {
      hLibModule = (HMODULE)*puVar1;
      if (hLibModule != (HMODULE)0x0) {
        if (hLibModule != (HMODULE)0xffffffffffffffff) {
          FreeLibrary(hLibModule);
        }
        *puVar1 = 0;
      }
      puVar1 = puVar1 + 1;
    } while (puVar1 != &DAT_18001cfb0);
  }
  return;
}



/* ---- __vcrt_initialize_pure_virtual_call_handler @ 180003e30 ---- */

/* WARNING: Globals starting with '_' overlap smaller symbols at the same address */
/* Library Function - Single Match
    __vcrt_initialize_pure_virtual_call_handler
   
   Library: Visual Studio 2015 Release */

void __vcrt_initialize_pure_virtual_call_handler(void)

{
  byte bVar1;
  
  bVar1 = 0x40 - ((byte)DAT_18001c000 & 0x3f) & 0x3f;
  _DAT_18001cff8 = ((ulonglong)(0 >> bVar1) | 0L << 0x40 - bVar1) ^ DAT_18001c000;
  return;
}



/* ---- is_overflow_condition<unsigned_long> @ 180003e54 ---- */

/* Library Function - Single Match
    bool __cdecl __crt_strtox::is_overflow_condition<unsigned long>(unsigned int,unsigned long)
   
   Library: Visual Studio 2015 Release */

bool __cdecl __crt_strtox::is_overflow_condition<unsigned_long>(uint param_1,ulong param_2)

{
  if (((param_1 & 4) == 0) &&
     (((param_1 & 1) == 0 ||
      ((((param_1 & 2) == 0 || (param_2 < 0x80000001)) &&
       (((param_1 & 2) != 0 || (param_2 < 0x80000000)))))))) {
    return false;
  }
  return true;
}



/* ---- is_overflow_condition<unsigned___int64> @ 180003e80 ---- */

/* Library Function - Single Match
    bool __cdecl __crt_strtox::is_overflow_condition<unsigned __int64>(unsigned int,unsigned
   __int64)
   
   Library: Visual Studio 2015 Release */

bool __cdecl __crt_strtox::is_overflow_condition<unsigned___int64>(uint param_1,__uint64 param_2)

{
  if (((param_1 & 4) == 0) &&
     (((param_1 & 1) == 0 ||
      ((((param_1 & 2) == 0 || (param_2 < 0x8000000000000001)) &&
       (((param_1 & 2) != 0 || (param_2 < 0x8000000000000000)))))))) {
    return false;
  }
  return true;
}



/* ---- parse_integer<unsigned_long,__crt_strtox::c_string_character_source<char>_> @ 180003eb8 ---- */

/* Library Function - Single Match
    unsigned long __cdecl __crt_strtox::parse_integer<unsigned long,class
   __crt_strtox::c_string_character_source<char> >(struct __crt_locale_pointers * __ptr64
   const,class __crt_strtox::c_string_character_source<char>,int,bool)
   
   Library: Visual Studio 2015 Release */

ulong __cdecl
__crt_strtox::parse_integer<unsigned_long,__crt_strtox::c_string_character_source<char>_>
          (__crt_locale_pointers *param_1,longlong *param_2,uint param_3,char param_4)

{
  char cVar1;
  byte *pbVar2;
  byte *pbVar3;
  char *pcVar4;
  bool bVar5;
  uint uVar6;
  int iVar7;
  ulong *puVar8;
  uint uVar9;
  pthreadlocinfo ptVar10;
  uint uVar11;
  uint uVar12;
  byte bVar13;
  uint uVar14;
  uint uVar15;
  ulonglong uVar16;
  longlong local_48;
  localeinfo_struct local_40;
  char local_30;
  
  uVar16 = (ulonglong)param_3;
  if ((*param_2 == 0) || ((param_3 != 0 && (0x22 < param_3 - 2)))) {
    puVar8 = __doserrno();
    *puVar8 = 0x16;
    FUN_18000aff4();
    goto LAB_180003ef6;
  }
  _LocaleUpdate::_LocaleUpdate((_LocaleUpdate *)&local_48,param_1);
  pbVar2 = (byte *)*param_2;
  uVar11 = 0;
  bVar13 = *pbVar2;
  ptVar10 = local_40.locinfo;
  pbVar3 = pbVar2;
  while( true ) {
    *param_2 = (longlong)(pbVar3 + 1);
    if ((int)ptVar10->lc_collate_cp < 2) {
      uVar6 = *(ushort *)(*(longlong *)ptVar10 + (ulonglong)bVar13 * 2) & 8;
    }
    else {
      uVar6 = _isctype_l((uint)bVar13,8,&local_40);
      ptVar10 = local_40.locinfo;
    }
    if (uVar6 == 0) break;
    pbVar3 = (byte *)*param_2;
    bVar13 = *pbVar3;
  }
  uVar6 = (uint)(param_4 != '\0');
  if (bVar13 == 0x2d) {
    uVar6 = param_4 != '\0' | 2;
LAB_180003f98:
    bVar13 = *(byte *)*param_2;
    *param_2 = (longlong)((byte *)*param_2 + 1);
  }
  else if (bVar13 == 0x2b) goto LAB_180003f98;
  uVar12 = 0xffffffff;
  if ((param_3 & 0xffffffef) == 0) {
    if ((byte)(bVar13 - 0x30) < 10) {
      iVar7 = (char)bVar13 + -0x30;
    }
    else if ((byte)(bVar13 + 0x9f) < 0x1a) {
      iVar7 = (char)bVar13 + -0x57;
    }
    else if ((byte)(bVar13 + 0xbf) < 0x1a) {
      iVar7 = (char)bVar13 + -0x37;
    }
    else {
      iVar7 = -1;
    }
    if (iVar7 == 0) {
      pcVar4 = (char *)*param_2;
      cVar1 = *pcVar4;
      *param_2 = (longlong)(pcVar4 + 1);
      if ((cVar1 + 0xa8U & 0xdf) == 0) {
        bVar13 = pcVar4[1];
        if (param_3 == 0) {
          param_3 = 0x10;
        }
        uVar16 = (ulonglong)param_3;
        *param_2 = (longlong)(pcVar4 + 2);
      }
      else {
        if (param_3 == 0) {
          param_3 = 8;
        }
        uVar16 = (ulonglong)param_3;
        *param_2 = (longlong)pcVar4;
        if ((cVar1 != '\0') && (*pcVar4 != cVar1)) {
          puVar8 = __doserrno();
          *puVar8 = 0x16;
          FUN_18000aff4();
        }
      }
    }
    else if (param_3 == 0) {
      uVar16 = 10;
    }
  }
  while( true ) {
    if ((byte)(bVar13 - 0x30) < 10) {
      uVar9 = (int)(char)bVar13 - 0x30;
    }
    else if ((byte)(bVar13 + 0x9f) < 0x1a) {
      uVar9 = (int)(char)bVar13 - 0x57;
    }
    else if ((byte)(bVar13 + 0xbf) < 0x1a) {
      uVar9 = (int)(char)bVar13 - 0x37;
    }
    else {
      uVar9 = 0xffffffff;
    }
    if ((uVar9 == 0xffffffff) || ((uint)uVar16 <= uVar9)) break;
    uVar15 = uVar6 | 8;
    uVar14 = (uint)(0xffffffff / uVar16);
    if ((uVar11 < uVar14) || ((uVar11 == uVar14 && (uVar9 <= (uint)(0xffffffff % uVar16))))) {
      uVar11 = uVar11 * (uint)uVar16 + uVar9;
    }
    else {
      uVar15 = uVar6 | 0xc;
    }
    bVar13 = *(byte *)*param_2;
    *param_2 = (longlong)((byte *)*param_2 + 1);
    uVar6 = uVar15;
  }
  *param_2 = *param_2 + -1;
  if ((bVar13 != 0) && (*(byte *)*param_2 != bVar13)) {
    puVar8 = __doserrno();
    *puVar8 = 0x16;
    FUN_18000aff4();
  }
  if ((uVar6 & 8) != 0) {
    bVar5 = is_overflow_condition<unsigned_long>(uVar6,uVar11);
    if (bVar5) {
      puVar8 = __doserrno();
      *puVar8 = 0x22;
      if ((uVar6 & 1) != 0) {
        if ((uVar6 & 2) != 0) {
          if (local_30 != '\0') {
            *(uint *)(local_48 + 0x3a8) = *(uint *)(local_48 + 0x3a8) & 0xfffffffd;
          }
          if ((longlong *)param_2[1] != (longlong *)0x0) {
            *(longlong *)param_2[1] = *param_2;
          }
          return 0x80000000;
        }
        if (local_30 != '\0') {
          *(uint *)(local_48 + 0x3a8) = *(uint *)(local_48 + 0x3a8) & 0xfffffffd;
        }
        if ((longlong *)param_2[1] != (longlong *)0x0) {
          *(longlong *)param_2[1] = *param_2;
        }
        return 0x7fffffff;
      }
    }
    else {
      uVar12 = uVar11;
      if ((uVar6 & 2) != 0) {
        uVar12 = -uVar11;
      }
    }
    if (local_30 != '\0') {
      *(uint *)(local_48 + 0x3a8) = *(uint *)(local_48 + 0x3a8) & 0xfffffffd;
    }
    if ((longlong *)param_2[1] == (longlong *)0x0) {
      return uVar12;
    }
    *(longlong *)param_2[1] = *param_2;
    return uVar12;
  }
  *param_2 = (longlong)pbVar2;
  if (local_30 != '\0') {
    *(uint *)(local_48 + 0x3a8) = *(uint *)(local_48 + 0x3a8) & 0xfffffffd;
  }
LAB_180003ef6:
  if ((longlong *)param_2[1] != (longlong *)0x0) {
    *(longlong *)param_2[1] = *param_2;
  }
  return 0;
}



/* ---- parse_integer<unsigned___int64,__crt_strtox::c_string_character_source<char>_> @ 1800041cc ---- */

/* Library Function - Single Match
    unsigned __int64 __cdecl __crt_strtox::parse_integer<unsigned __int64,class
   __crt_strtox::c_string_character_source<char> >(struct __crt_locale_pointers * __ptr64
   const,class __crt_strtox::c_string_character_source<char>,int,bool)
   
   Library: Visual Studio 2015 Release */

__uint64 __cdecl
__crt_strtox::parse_integer<unsigned___int64,__crt_strtox::c_string_character_source<char>_>
          (__crt_locale_pointers *param_1,longlong *param_2,uint param_3,char param_4)

{
  char cVar1;
  byte *pbVar2;
  byte *pbVar3;
  char *pcVar4;
  undefined1 auVar5 [16];
  undefined1 auVar6 [16];
  bool bVar7;
  uint uVar8;
  int iVar9;
  ulong *puVar10;
  ulonglong uVar11;
  pthreadlocinfo ptVar12;
  uint uVar13;
  byte bVar14;
  ulonglong uVar15;
  ulonglong uVar16;
  longlong local_48;
  localeinfo_struct local_40;
  char local_30;
  
  if ((*param_2 == 0) || ((param_3 != 0 && (0x22 < param_3 - 2)))) {
    puVar10 = __doserrno();
    *puVar10 = 0x16;
    FUN_18000aff4();
    goto LAB_18000420a;
  }
  _LocaleUpdate::_LocaleUpdate((_LocaleUpdate *)&local_48,param_1);
  pbVar2 = (byte *)*param_2;
  uVar16 = 0;
  bVar14 = *pbVar2;
  ptVar12 = local_40.locinfo;
  pbVar3 = pbVar2;
  while( true ) {
    *param_2 = (longlong)(pbVar3 + 1);
    if ((int)ptVar12->lc_collate_cp < 2) {
      uVar8 = *(ushort *)(*(longlong *)ptVar12 + (ulonglong)bVar14 * 2) & 8;
    }
    else {
      uVar8 = _isctype_l((uint)bVar14,8,&local_40);
      ptVar12 = local_40.locinfo;
    }
    if (uVar8 == 0) break;
    pbVar3 = (byte *)*param_2;
    bVar14 = *pbVar3;
  }
  uVar8 = (uint)(param_4 != '\0');
  if (bVar14 == 0x2d) {
    uVar8 = param_4 != '\0' | 2;
LAB_1800042ab:
    bVar14 = *(byte *)*param_2;
    *param_2 = (longlong)((byte *)*param_2 + 1);
  }
  else if (bVar14 == 0x2b) goto LAB_1800042ab;
  if ((param_3 & 0xffffffef) == 0) {
    if ((byte)(bVar14 - 0x30) < 10) {
      iVar9 = (char)bVar14 + -0x30;
    }
    else if ((byte)(bVar14 + 0x9f) < 0x1a) {
      iVar9 = (char)bVar14 + -0x57;
    }
    else if ((byte)(bVar14 + 0xbf) < 0x1a) {
      iVar9 = (char)bVar14 + -0x37;
    }
    else {
      iVar9 = -1;
    }
    if (iVar9 == 0) {
      pcVar4 = (char *)*param_2;
      cVar1 = *pcVar4;
      *param_2 = (longlong)(pcVar4 + 1);
      if ((cVar1 + 0xa8U & 0xdf) == 0) {
        bVar14 = pcVar4[1];
        if (param_3 == 0) {
          param_3 = 0x10;
        }
        *param_2 = (longlong)(pcVar4 + 2);
      }
      else {
        if (param_3 == 0) {
          param_3 = 8;
        }
        *param_2 = (longlong)pcVar4;
        if ((cVar1 != '\0') && (*pcVar4 != cVar1)) {
          puVar10 = __doserrno();
          *puVar10 = 0x16;
          FUN_18000aff4();
        }
      }
    }
    else if (param_3 == 0) {
      param_3 = 10;
    }
  }
  auVar5._8_8_ = 0;
  auVar5._0_8_ = (longlong)(int)param_3;
  auVar6 = ZEXT816(0) << 0x40 | ZEXT816(0xffffffffffffffff);
  uVar11 = SUB168(auVar6 / auVar5,0);
  while( true ) {
    if ((byte)(bVar14 - 0x30) < 10) {
      uVar15 = (ulonglong)((int)(char)bVar14 - 0x30);
    }
    else if ((byte)(bVar14 + 0x9f) < 0x1a) {
      uVar15 = (ulonglong)((int)(char)bVar14 - 0x57);
    }
    else if ((byte)(bVar14 + 0xbf) < 0x1a) {
      uVar15 = (ulonglong)((int)(char)bVar14 - 0x37);
    }
    else {
      uVar15 = 0xffffffff;
    }
    if (((uint)uVar15 == 0xffffffff) || (param_3 <= (uint)uVar15)) break;
    uVar13 = uVar8 | 8;
    if ((uVar16 < uVar11) || ((uVar16 == uVar11 && (uVar15 <= SUB168(auVar6 % auVar5,0))))) {
      uVar16 = uVar15 + (longlong)(int)param_3 * uVar16;
    }
    else {
      uVar13 = uVar8 | 0xc;
    }
    bVar14 = *(byte *)*param_2;
    *param_2 = (longlong)((byte *)*param_2 + 1);
    uVar8 = uVar13;
  }
  *param_2 = *param_2 + -1;
  if ((bVar14 != 0) && (*(byte *)*param_2 != bVar14)) {
    puVar10 = __doserrno();
    *puVar10 = 0x16;
    FUN_18000aff4();
  }
  if ((uVar8 & 8) != 0) {
    bVar7 = is_overflow_condition<unsigned___int64>(uVar8,uVar16);
    if (bVar7) {
      puVar10 = __doserrno();
      *puVar10 = 0x22;
      if ((uVar8 & 1) != 0) {
        if ((uVar8 & 2) != 0) {
          if (local_30 != '\0') {
            *(uint *)(local_48 + 0x3a8) = *(uint *)(local_48 + 0x3a8) & 0xfffffffd;
          }
          if ((longlong *)param_2[1] != (longlong *)0x0) {
            *(longlong *)param_2[1] = *param_2;
          }
          return 0x8000000000000000;
        }
        if (local_30 != '\0') {
          *(uint *)(local_48 + 0x3a8) = *(uint *)(local_48 + 0x3a8) & 0xfffffffd;
        }
        if ((longlong *)param_2[1] != (longlong *)0x0) {
          *(longlong *)param_2[1] = *param_2;
        }
        return 0x7fffffffffffffff;
      }
      uVar16 = 0xffffffffffffffff;
    }
    else if ((uVar8 & 2) != 0) {
      uVar16 = -uVar16;
    }
    if (local_30 != '\0') {
      *(uint *)(local_48 + 0x3a8) = *(uint *)(local_48 + 0x3a8) & 0xfffffffd;
    }
    if ((longlong *)param_2[1] == (longlong *)0x0) {
      return uVar16;
    }
    *(longlong *)param_2[1] = *param_2;
    return uVar16;
  }
  *param_2 = (longlong)pbVar2;
  if (local_30 != '\0') {
    *(uint *)(local_48 + 0x3a8) = *(uint *)(local_48 + 0x3a8) & 0xfffffffd;
  }
LAB_18000420a:
  if ((longlong *)param_2[1] != (longlong *)0x0) {
    *(longlong *)param_2[1] = *param_2;
  }
  return 0;
}



/* ---- _LocaleUpdate @ 180004500 ---- */

/* Library Function - Single Match
    public: __cdecl _LocaleUpdate::_LocaleUpdate(struct __crt_locale_pointers * __ptr64 const)
   __ptr64
   
   Libraries: Visual Studio 2015 Debug, Visual Studio 2015 Release */

_LocaleUpdate * __thiscall
_LocaleUpdate::_LocaleUpdate(_LocaleUpdate *this,__crt_locale_pointers *param_1)

{
  uint uVar1;
  __acrt_ptd *p_Var2;
  undefined4 uVar3;
  undefined4 uVar4;
  undefined4 uVar5;
  undefined4 uVar6;
  
  this[0x18] = (_LocaleUpdate)0x0;
  if (param_1 == (__crt_locale_pointers *)0x0) {
    uVar3 = PTR_PTR_18001c1a8._0_4_;
    uVar4 = PTR_PTR_18001c1a8._4_4_;
    uVar5 = PTR_DAT_18001c1b0._0_4_;
    uVar6 = PTR_DAT_18001c1b0._4_4_;
    if (DAT_18001d1f0 != 0) {
      p_Var2 = FUN_18000b630();
      *(__acrt_ptd **)this = p_Var2;
      *(longlong *)(this + 8) = *(longlong *)(p_Var2 + 0x90);
      *(undefined8 *)(this + 0x10) = *(undefined8 *)(p_Var2 + 0x88);
      FUN_18000b7c4((longlong)p_Var2,(longlong *)(this + 8));
      FUN_18000b7f8(*(longlong *)this,(longlong *)(this + 0x10));
      uVar1 = *(uint *)(*(longlong *)this + 0x3a8);
      if ((uVar1 & 2) != 0) {
        return this;
      }
      *(uint *)(*(longlong *)this + 0x3a8) = uVar1 | 2;
      this[0x18] = (_LocaleUpdate)0x1;
      return this;
    }
  }
  else {
    uVar3 = *(undefined4 *)param_1;
    uVar4 = *(undefined4 *)(param_1 + 4);
    uVar5 = *(undefined4 *)(param_1 + 8);
    uVar6 = *(undefined4 *)(param_1 + 0xc);
  }
  *(undefined4 *)(this + 8) = uVar3;
  *(undefined4 *)(this + 0xc) = uVar4;
  *(undefined4 *)(this + 0x10) = uVar5;
  *(undefined4 *)(this + 0x14) = uVar6;
  return this;
}



/* ---- FID_conflict:atoi @ 180004590 ---- */

/* Library Function - Multiple Matches With Different Base Names
    atoi
    atol
   
   Library: Visual Studio 2015 Release */

int __cdecl FID_conflict_atoi(char *_Str)

{
  ulong uVar1;
  undefined8 *puVar2;
  undefined8 local_18 [3];
  
  puVar2 = make_c_string_character_source<>(local_18,_Str,(undefined8 *)0x0);
  uVar1 = __crt_strtox::parse_integer<unsigned_long,__crt_strtox::c_string_character_source<char>_>
                    (0,puVar2,10,1);
  return uVar1;
}



/* ---- make_input_adapter_character_source<__crt_stdio_input::string_input_adapter<char>_> @ 1800045bc ---- */

/* Library Function - Single Match
    class __crt_strtox::input_adapter_character_source<class
   __crt_stdio_input::string_input_adapter<char> > __cdecl
   __crt_strtox::make_input_adapter_character_source<class
   __crt_stdio_input::string_input_adapter<char> >(class
   __crt_stdio_input::string_input_adapter<char> * __ptr64 const,unsigned __int64,bool * __ptr64
   const)
   
   Library: Visual Studio 2015 Release */

string_input_adapter<char> * __cdecl
__crt_strtox::make_input_adapter_character_source<__crt_stdio_input::string_input_adapter<char>_>
          (string_input_adapter<char> *param_1,__uint64 param_2,bool *param_3)

{
  undefined1 *in_R9;
  
  *(undefined8 *)(param_1 + 0x10) = 0;
  *(__uint64 *)param_1 = param_2;
  *(bool **)(param_1 + 8) = param_3;
  *(undefined1 **)(param_1 + 0x18) = in_R9;
  if (in_R9 != (undefined1 *)0x0) {
    *in_R9 = 1;
  }
  return param_1;
}



/* ---- parse_floating_point<__crt_strtox::input_adapter_character_source<__crt_stdio_input::string_input_adapter<char>_>,float> @ 1800045dc ---- */

/* WARNING: Function: __security_check_cookie replaced with injection: security_check_cookie */
/* Library Function - Single Match
    enum SLD_STATUS __cdecl __crt_strtox::parse_floating_point<class
   __crt_strtox::input_adapter_character_source<class __crt_stdio_input::string_input_adapter<char>
   >,float>(struct __crt_locale_pointers * __ptr64 const,class
   __crt_strtox::input_adapter_character_source<class __crt_stdio_input::string_input_adapter<char>
   >,float * __ptr64 const)
   
   Library: Visual Studio 2015 Release */

SLD_STATUS __cdecl
__crt_strtox::
parse_floating_point<__crt_strtox::input_adapter_character_source<__crt_stdio_input::string_input_adapter<char>_>,float>
          (__crt_locale_pointers *param_1,
          input_adapter_character_source<__crt_stdio_input::string_input_adapter<char>_> *param_2,
          float *param_3)

{
  floating_point_parse_result fVar1;
  SLD_STATUS SVar2;
  ulong *puVar3;
  undefined1 auStack_348 [32];
  floating_point_string local_328 [784];
  ulonglong local_18;
  
  local_18 = DAT_18001c000 ^ (ulonglong)auStack_348;
  if ((param_3 == (float *)0x0) || (param_1 == (__crt_locale_pointers *)0x0)) {
    puVar3 = __doserrno();
    *puVar3 = 0x16;
    FUN_18000aff4();
    if ((*(undefined1 **)(param_2 + 0x18) != (undefined1 *)0x0) &&
       (*(longlong *)(param_2 + 0x10) == 0)) {
      **(undefined1 **)(param_2 + 0x18) = 0;
    }
    SVar2 = 1;
  }
  else {
    fVar1 = parse_floating_point_from_source<__crt_strtox::input_adapter_character_source<__crt_stdio_input::string_input_adapter<char>_>_>
                      (param_1,param_2,local_328);
    SVar2 = parse_floating_point_write_result<float>(fVar1,local_328,param_3);
    if ((*(undefined1 **)(param_2 + 0x18) != (undefined1 *)0x0) &&
       (*(longlong *)(param_2 + 0x10) == 0)) {
      **(undefined1 **)(param_2 + 0x18) = 0;
    }
  }
  return SVar2;
}



/* ---- parse_floating_point<__crt_strtox::input_adapter_character_source<__crt_stdio_input::string_input_adapter<char>_>,double> @ 180004684 ---- */

/* WARNING: Function: __security_check_cookie replaced with injection: security_check_cookie */
/* Library Function - Single Match
    enum SLD_STATUS __cdecl __crt_strtox::parse_floating_point<class
   __crt_strtox::input_adapter_character_source<class __crt_stdio_input::string_input_adapter<char>
   >,double>(struct __crt_locale_pointers * __ptr64 const,class
   __crt_strtox::input_adapter_character_source<class __crt_stdio_input::string_input_adapter<char>
   >,double * __ptr64 const)
   
   Library: Visual Studio 2015 Release */

SLD_STATUS __cdecl
__crt_strtox::
parse_floating_point<__crt_strtox::input_adapter_character_source<__crt_stdio_input::string_input_adapter<char>_>,double>
          (__crt_locale_pointers *param_1,
          input_adapter_character_source<__crt_stdio_input::string_input_adapter<char>_> *param_2,
          double *param_3)

{
  floating_point_parse_result fVar1;
  SLD_STATUS SVar2;
  ulong *puVar3;
  undefined1 auStack_348 [32];
  floating_point_string local_328 [784];
  ulonglong local_18;
  
  local_18 = DAT_18001c000 ^ (ulonglong)auStack_348;
  if ((param_3 == (double *)0x0) || (param_1 == (__crt_locale_pointers *)0x0)) {
    puVar3 = __doserrno();
    *puVar3 = 0x16;
    FUN_18000aff4();
    if ((*(undefined1 **)(param_2 + 0x18) != (undefined1 *)0x0) &&
       (*(longlong *)(param_2 + 0x10) == 0)) {
      **(undefined1 **)(param_2 + 0x18) = 0;
    }
    SVar2 = 1;
  }
  else {
    fVar1 = parse_floating_point_from_source<__crt_strtox::input_adapter_character_source<__crt_stdio_input::string_input_adapter<char>_>_>
                      (param_1,param_2,local_328);
    SVar2 = parse_floating_point_write_result<double>(fVar1,local_328,param_3);
    if ((*(undefined1 **)(param_2 + 0x18) != (undefined1 *)0x0) &&
       (*(longlong *)(param_2 + 0x10) == 0)) {
      **(undefined1 **)(param_2 + 0x18) = 0;
    }
  }
  return SVar2;
}



/* ---- parse_floating_point_from_source<__crt_strtox::input_adapter_character_source<__crt_stdio_input::string_input_adapter<char>_>_> @ 18000472c ---- */

/* Library Function - Single Match
    enum __crt_strtox::floating_point_parse_result __cdecl
   __crt_strtox::parse_floating_point_from_source<class
   __crt_strtox::input_adapter_character_source<class __crt_stdio_input::string_input_adapter<char>
   > >(struct __crt_locale_pointers * __ptr64 const,class
   __crt_strtox::input_adapter_character_source<class __crt_stdio_input::string_input_adapter<char>
   > & __ptr64,struct __crt_strtox::floating_point_string & __ptr64)
   
   Library: Visual Studio 2015 Release */

floating_point_parse_result __cdecl
__crt_strtox::
parse_floating_point_from_source<__crt_strtox::input_adapter_character_source<__crt_stdio_input::string_input_adapter<char>_>_>
          (__crt_locale_pointers *param_1,
          input_adapter_character_source<__crt_stdio_input::string_input_adapter<char>_> *param_2,
          floating_point_string *param_3)

{
  ulonglong uVar1;
  floating_point_string *pfVar2;
  floating_point_string *pfVar3;
  longlong lVar4;
  char *pcVar5;
  __uint64 _Var6;
  byte *pbVar7;
  longlong *plVar8;
  bool bVar9;
  bool bVar10;
  bool bVar11;
  uint uVar12;
  uint uVar13;
  floating_point_parse_result fVar14;
  ulong *puVar15;
  ushort *puVar16;
  char cVar17;
  ulonglong uVar18;
  int iVar19;
  int iVar20;
  int iVar21;
  floating_point_string *pfVar22;
  int iVar23;
  byte local_res10 [16];
  __uint64 local_res20;
  input_adapter_character_source<__crt_stdio_input::string_input_adapter<char>_> *local_58;
  byte *local_50;
  __uint64 *local_48;
  
  lVar4 = *(longlong *)param_2;
  iVar19 = 0;
  if ((lVar4 == 0) || (*(longlong *)(param_2 + 0x18) == 0)) {
    puVar15 = __doserrno();
    *puVar15 = 0x16;
    FUN_18000aff4();
    return 7;
  }
  local_res20 = *(__uint64 *)(param_2 + 0x10);
  *(__uint64 *)(param_2 + 0x10) = local_res20 + 1;
  if (((*(longlong *)(param_2 + 8) == 0) || (local_res20 + 1 <= *(ulonglong *)(param_2 + 8))) &&
     (pcVar5 = *(char **)(lVar4 + 0x10), pcVar5 != *(char **)(lVar4 + 8))) {
    cVar17 = *pcVar5;
    uVar18 = (ulonglong)(uint)(int)cVar17;
    *(char **)(lVar4 + 0x10) = pcVar5 + 1;
    if ((int)cVar17 == 0xffffffff) goto LAB_1800047aa;
  }
  else {
LAB_1800047aa:
    uVar18 = 0;
  }
  local_50 = local_res10;
  local_48 = &local_res20;
  local_58 = param_2;
LAB_1800047c1:
  local_res10[0] = (byte)uVar18;
  if (param_1 == (__crt_locale_pointers *)0x0) {
    puVar16 = __pctype_func();
    uVar12 = puVar16[uVar18 & 0xff] & 8;
LAB_180004804:
    uVar18 = (ulonglong)local_res10[0];
  }
  else {
    iVar21 = (int)(uVar18 & 0xff);
    if (1 < (int)(*(longlong **)param_1)[1]) {
      uVar12 = _isctype_l(iVar21,8,(_locale_t)param_1);
      goto LAB_180004804;
    }
    uVar12 = *(ushort *)(**(longlong **)param_1 + (longlong)iVar21 * 2) & 8;
  }
  if (uVar12 != 0) {
    *(longlong *)(param_2 + 0x10) = *(longlong *)(param_2 + 0x10) + 1;
    if ((*(longlong *)(param_2 + 8) != 0) &&
       (*(ulonglong *)(param_2 + 8) < *(ulonglong *)(param_2 + 0x10))) goto LAB_18000483b;
    lVar4 = *(longlong *)param_2;
    pcVar5 = *(char **)(lVar4 + 0x10);
    if (pcVar5 == *(char **)(lVar4 + 8)) goto LAB_18000483b;
    cVar17 = *pcVar5;
    uVar18 = (ulonglong)(uint)(int)cVar17;
    *(char **)(lVar4 + 0x10) = pcVar5 + 1;
    if ((int)cVar17 == 0xffffffff) {
LAB_18000483b:
      uVar18 = 0;
    }
    goto LAB_1800047c1;
  }
  pfVar3 = param_3 + 0x308;
  *pfVar3 = (floating_point_string)((char)uVar18 == '-');
  if (((int)uVar18 - 0x2bU & 0xfd) == 0) {
    *(longlong *)(param_2 + 0x10) = *(longlong *)(param_2 + 0x10) + 1;
    if ((*(longlong *)(param_2 + 8) == 0) ||
       (*(ulonglong *)(param_2 + 0x10) <= *(ulonglong *)(param_2 + 8))) {
      lVar4 = *(longlong *)param_2;
      pcVar5 = *(char **)(lVar4 + 0x10);
      if (pcVar5 == *(char **)(lVar4 + 8)) goto LAB_180004887;
      cVar17 = *pcVar5;
      uVar18 = (ulonglong)(uint)(int)cVar17;
      *(char **)(lVar4 + 0x10) = pcVar5 + 1;
      if ((int)cVar17 == 0xffffffff) goto LAB_180004887;
    }
    else {
LAB_180004887:
      uVar18 = 0;
    }
    local_res10[0] = (byte)uVar18;
  }
  cVar17 = (char)uVar18;
  if ((cVar17 + 0xb7U & 0xdf) == 0) {
    fVar14 = parse_floating_point_possible_infinity<char,__crt_strtox::input_adapter_character_source<__crt_stdio_input::string_input_adapter<char>_>,unsigned___int64>
                       ((char *)local_res10,param_2,local_res20);
    return fVar14;
  }
  if ((cVar17 + 0xb2U & 0xdf) == 0) {
    fVar14 = parse_floating_point_possible_nan<char,__crt_strtox::input_adapter_character_source<__crt_stdio_input::string_input_adapter<char>_>,unsigned___int64>
                       ((char *)local_res10,param_2,local_res20);
    return fVar14;
  }
  bVar9 = false;
  if (cVar17 == '0') {
    _Var6 = *(__uint64 *)(param_2 + 0x10);
    uVar1 = _Var6 + 1;
    *(ulonglong *)(param_2 + 0x10) = uVar1;
    if ((*(longlong *)(param_2 + 8) == 0) || (uVar1 <= *(ulonglong *)(param_2 + 8))) {
      lVar4 = *(longlong *)param_2;
      pcVar5 = *(char **)(lVar4 + 0x10);
      if (pcVar5 == *(char **)(lVar4 + 8)) goto LAB_180004937;
      cVar17 = *pcVar5;
      *(char **)(lVar4 + 0x10) = pcVar5 + 1;
      if (cVar17 == -1) {
        uVar18 = (ulonglong)local_res10[0];
        goto LAB_180004937;
      }
      if ((cVar17 + 0xa8U & 0xdf) == 0) {
        *(longlong *)(param_2 + 0x10) = *(longlong *)(param_2 + 0x10) + 1;
        bVar9 = true;
        if ((*(longlong *)(param_2 + 8) == 0) ||
           (*(ulonglong *)(param_2 + 0x10) <= *(ulonglong *)(param_2 + 8))) {
          lVar4 = *(longlong *)param_2;
          pcVar5 = *(char **)(lVar4 + 0x10);
          if (pcVar5 == *(char **)(lVar4 + 8)) goto LAB_180004923;
          cVar17 = *pcVar5;
          uVar18 = (ulonglong)(uint)(int)cVar17;
          *(char **)(lVar4 + 0x10) = pcVar5 + 1;
          if ((int)cVar17 == 0xffffffff) goto LAB_180004923;
        }
        else {
LAB_180004923:
          uVar18 = 0;
        }
        local_res10[0] = (byte)uVar18;
        local_res20 = _Var6;
        goto LAB_18000496b;
      }
      uVar18 = (ulonglong)local_res10[0];
    }
    else {
LAB_180004937:
      cVar17 = '\0';
    }
    *(longlong *)(param_2 + 0x10) = *(longlong *)(param_2 + 0x10) + -1;
    if (((*(longlong *)(param_2 + 8) == 0) ||
        (*(ulonglong *)(param_2 + 0x10) <= *(ulonglong *)(param_2 + 8))) &&
       (1 < (byte)(cVar17 + 1U))) {
      plVar8 = *(longlong **)param_2;
      if (plVar8[2] != *plVar8) {
        plVar8[2] = plVar8[2] + -1;
        uVar18 = (ulonglong)local_res10[0];
      }
    }
  }
LAB_18000496b:
  pfVar2 = param_3 + 8;
  iVar21 = 0;
  bVar11 = false;
  if ((char)uVar18 == '0') {
    bVar11 = true;
    do {
      *(longlong *)(param_2 + 0x10) = *(longlong *)(param_2 + 0x10) + 1;
      if ((*(longlong *)(param_2 + 8) != 0) &&
         (*(ulonglong *)(param_2 + 8) < *(ulonglong *)(param_2 + 0x10))) {
LAB_1800049bc:
        uVar18 = 0;
        local_res10[0] = 0;
        break;
      }
      lVar4 = *(longlong *)param_2;
      pbVar7 = *(byte **)(lVar4 + 0x10);
      if (pbVar7 == *(byte **)(lVar4 + 8)) goto LAB_1800049bc;
      local_res10[0] = *pbVar7;
      *(byte **)(lVar4 + 0x10) = pbVar7 + 1;
      if (local_res10[0] == 0xff) goto LAB_1800049bc;
      uVar18 = (ulonglong)local_res10[0];
    } while (local_res10[0] == 0x30);
  }
  uVar12 = (-(uint)bVar9 & 6) + 9;
  pfVar22 = pfVar2;
  iVar23 = iVar19;
  while( true ) {
    cVar17 = (char)uVar18;
    if ((byte)(cVar17 - 0x30U) < 10) {
      uVar13 = (int)cVar17 - 0x30;
    }
    else if ((byte)(cVar17 + 0x9fU) < 0x1a) {
      uVar13 = (int)cVar17 - 0x57;
    }
    else if ((byte)(cVar17 + 0xbfU) < 0x1a) {
      uVar13 = (int)cVar17 - 0x37;
    }
    else {
      uVar13 = 0xffffffff;
    }
    if (uVar12 < uVar13) break;
    bVar11 = true;
    if (pfVar22 != pfVar3) {
      *pfVar22 = SUB41(uVar13,0);
      pfVar22 = pfVar22 + 1;
    }
    *(longlong *)(param_2 + 0x10) = *(longlong *)(param_2 + 0x10) + 1;
    iVar23 = iVar23 + 1;
    if ((*(longlong *)(param_2 + 8) == 0) ||
       (*(ulonglong *)(param_2 + 0x10) <= *(ulonglong *)(param_2 + 8))) {
      lVar4 = *(longlong *)param_2;
      pcVar5 = *(char **)(lVar4 + 0x10);
      if (pcVar5 == *(char **)(lVar4 + 8)) goto LAB_180004a48;
      cVar17 = *pcVar5;
      uVar18 = (ulonglong)(uint)(int)cVar17;
      *(char **)(lVar4 + 0x10) = pcVar5 + 1;
      if ((int)cVar17 == 0xffffffff) goto LAB_180004a48;
    }
    else {
LAB_180004a48:
      uVar18 = 0;
    }
    local_res10[0] = (byte)uVar18;
  }
  if (cVar17 == *(char *)**(undefined8 **)(*(longlong *)param_1 + 0xf8)) {
    *(longlong *)(param_2 + 0x10) = *(longlong *)(param_2 + 0x10) + 1;
    if ((*(longlong *)(param_2 + 8) == 0) ||
       (*(ulonglong *)(param_2 + 0x10) <= *(ulonglong *)(param_2 + 8))) {
      lVar4 = *(longlong *)param_2;
      pbVar7 = *(byte **)(lVar4 + 0x10);
      if (pbVar7 == *(byte **)(lVar4 + 8)) goto LAB_180004a95;
      local_res10[0] = *pbVar7;
      *(byte **)(lVar4 + 0x10) = pbVar7 + 1;
      if (local_res10[0] == 0xff) goto LAB_180004a95;
    }
    else {
LAB_180004a95:
      local_res10[0] = 0;
    }
    uVar13 = (uint)local_res10[0];
    if ((pfVar22 == pfVar2) && (local_res10[0] == 0x30)) {
      bVar11 = true;
      do {
        *(longlong *)(param_2 + 0x10) = *(longlong *)(param_2 + 0x10) + 1;
        iVar23 = iVar23 + -1;
        if ((*(longlong *)(param_2 + 8) != 0) &&
           (*(ulonglong *)(param_2 + 8) < *(ulonglong *)(param_2 + 0x10))) goto LAB_180004ae9;
        lVar4 = *(longlong *)param_2;
        pbVar7 = *(byte **)(lVar4 + 0x10);
        if (pbVar7 == *(byte **)(lVar4 + 8)) goto LAB_180004ae9;
        local_res10[0] = *pbVar7;
        *(byte **)(lVar4 + 0x10) = pbVar7 + 1;
        if (local_res10[0] == 0xff) goto LAB_180004ae9;
        uVar13 = (uint)local_res10[0];
      } while (local_res10[0] == 0x30);
    }
    while( true ) {
      cVar17 = (char)uVar13;
      if ((byte)(cVar17 - 0x30U) < 10) {
        uVar13 = (int)cVar17 - 0x30;
      }
      else if ((byte)(cVar17 + 0x9fU) < 0x1a) {
        uVar13 = (int)cVar17 - 0x57;
      }
      else if ((byte)(cVar17 + 0xbfU) < 0x1a) {
        uVar13 = (int)cVar17 - 0x37;
      }
      else {
        uVar13 = 0xffffffff;
      }
      if (uVar12 < uVar13) break;
      if (pfVar22 != pfVar3) {
        *pfVar22 = SUB41(uVar13,0);
        pfVar22 = pfVar22 + 1;
      }
      *(longlong *)(param_2 + 0x10) = *(longlong *)(param_2 + 0x10) + 1;
      if ((*(longlong *)(param_2 + 8) == 0) ||
         (*(ulonglong *)(param_2 + 0x10) <= *(ulonglong *)(param_2 + 8))) {
        lVar4 = *(longlong *)param_2;
        pcVar5 = *(char **)(lVar4 + 0x10);
        if (pcVar5 == *(char **)(lVar4 + 8)) goto LAB_180004ae9;
        uVar13 = (uint)*pcVar5;
        *(char **)(lVar4 + 0x10) = pcVar5 + 1;
        if (uVar13 == 0xffffffff) goto LAB_180004ae9;
      }
      else {
LAB_180004ae9:
        uVar13 = 0;
      }
      bVar11 = true;
      local_res10[0] = (byte)uVar13;
    }
  }
  if (!bVar11) {
    bVar11 = <lambda_5b936a367a2157d8f8fe79b470b291e7>::operator()
                       ((<lambda_5b936a367a2157d8f8fe79b470b291e7> *)&local_58);
    if (!bVar11) {
      return 7;
    }
    return (-(uint)bVar9 & 0xfffffffb) + 7;
  }
  *(longlong *)(param_2 + 0x10) = *(longlong *)(param_2 + 0x10) + -1;
  if (((*(longlong *)(param_2 + 8) == 0) ||
      (*(ulonglong *)(param_2 + 0x10) <= *(ulonglong *)(param_2 + 8))) && (1 < (byte)(cVar17 + 1U)))
  {
    plVar8 = *(longlong **)param_2;
    if (plVar8[2] != *plVar8) {
      plVar8[2] = plVar8[2] + -1;
    }
  }
  local_res20 = *(__uint64 *)(param_2 + 0x10);
  *(__uint64 *)(param_2 + 0x10) = local_res20 + 1;
  if ((*(longlong *)(param_2 + 8) == 0) || (local_res20 + 1 <= *(ulonglong *)(param_2 + 8))) {
    lVar4 = *(longlong *)param_2;
    pcVar5 = *(char **)(lVar4 + 0x10);
    if (pcVar5 == *(char **)(lVar4 + 8)) goto LAB_180004bef;
    cVar17 = *pcVar5;
    *(char **)(lVar4 + 0x10) = pcVar5 + 1;
    if (cVar17 == -1) goto LAB_180004bef;
  }
  else {
LAB_180004bef:
    cVar17 = '\0';
  }
  if (cVar17 == 'E') {
LAB_180004c11:
    bVar11 = !bVar9;
  }
  else if (cVar17 == 'P') {
LAB_180004c0c:
    bVar11 = bVar9;
  }
  else {
    if (cVar17 == 'e') goto LAB_180004c11;
    bVar11 = false;
    if (cVar17 == 'p') goto LAB_180004c0c;
  }
  iVar20 = 0;
  if (!bVar11) {
LAB_180004e30:
    *(longlong *)(param_2 + 0x10) = *(longlong *)(param_2 + 0x10) + -1;
    if (((*(longlong *)(param_2 + 8) == 0) ||
        (*(ulonglong *)(param_2 + 0x10) <= *(ulonglong *)(param_2 + 8))) &&
       (1 < (byte)(cVar17 + 1U))) {
      plVar8 = *(longlong **)param_2;
      if (plVar8[2] != *plVar8) {
        plVar8[2] = plVar8[2] + -1;
      }
    }
    if (pfVar22 != pfVar2) {
      do {
        pfVar3 = pfVar22 + -1;
        if (*pfVar3 != (floating_point_string)0x0) break;
        pfVar22 = pfVar3;
      } while (pfVar3 != pfVar2);
      if (pfVar22 != pfVar2) {
        if (0x1450 < iVar21) {
          return 9;
        }
        if (-0x1451 < iVar21) {
          iVar21 = iVar21 + ((-(uint)bVar9 & 3) + 1) * iVar23;
          if (0x1450 < iVar21) {
            return 9;
          }
          if (-0x1451 < iVar21) {
            *(int *)param_3 = iVar21;
            *(int *)(param_3 + 4) = (int)pfVar22 - (int)pfVar2;
            return (uint)bVar9;
          }
        }
        return 8;
      }
    }
    return 2;
  }
  *(longlong *)(param_2 + 0x10) = *(longlong *)(param_2 + 0x10) + 1;
  if ((*(longlong *)(param_2 + 8) == 0) ||
     (*(ulonglong *)(param_2 + 0x10) <= *(ulonglong *)(param_2 + 8))) {
    lVar4 = *(longlong *)param_2;
    pcVar5 = *(char **)(lVar4 + 0x10);
    if (pcVar5 == *(char **)(lVar4 + 8)) goto LAB_180004c58;
    uVar12 = (uint)*pcVar5;
    *(char **)(lVar4 + 0x10) = pcVar5 + 1;
    if (uVar12 == 0xffffffff) goto LAB_180004c58;
  }
  else {
LAB_180004c58:
    uVar12 = 0;
  }
  local_res10[0] = (byte)uVar12;
  bVar11 = local_res10[0] == 0x2d;
  uVar12 = uVar12 & 0xff;
  if ((local_res10[0] - 0x2b & 0xfd) != 0) goto LAB_180004ca5;
  *(longlong *)(param_2 + 0x10) = *(longlong *)(param_2 + 0x10) + 1;
  if ((*(longlong *)(param_2 + 8) == 0) ||
     (*(ulonglong *)(param_2 + 0x10) <= *(ulonglong *)(param_2 + 8))) {
    lVar4 = *(longlong *)param_2;
    pcVar5 = *(char **)(lVar4 + 0x10);
    if (pcVar5 == *(char **)(lVar4 + 8)) goto LAB_180004c9f;
    uVar12 = (uint)*pcVar5;
    *(char **)(lVar4 + 0x10) = pcVar5 + 1;
    if (uVar12 == 0xffffffff) goto LAB_180004c9f;
  }
  else {
LAB_180004c9f:
    uVar12 = 0;
  }
  local_res10[0] = (byte)uVar12;
LAB_180004ca5:
  bVar10 = false;
  iVar21 = iVar19;
  if ((char)uVar12 == '0') {
    bVar10 = true;
    do {
      *(longlong *)(param_2 + 0x10) = *(longlong *)(param_2 + 0x10) + 1;
      if ((*(longlong *)(param_2 + 8) != 0) &&
         (iVar21 = iVar19, *(ulonglong *)(param_2 + 8) < *(ulonglong *)(param_2 + 0x10)))
      goto LAB_180004cec;
      lVar4 = *(longlong *)param_2;
      pbVar7 = *(byte **)(lVar4 + 0x10);
      iVar21 = iVar20;
      if (pbVar7 == *(byte **)(lVar4 + 8)) goto LAB_180004cec;
      local_res10[0] = *pbVar7;
      *(byte **)(lVar4 + 0x10) = pbVar7 + 1;
      if (local_res10[0] == 0xff) goto LAB_180004cec;
      uVar12 = (uint)local_res10[0];
    } while (local_res10[0] == 0x30);
  }
  while( true ) {
    cVar17 = (char)uVar12;
    if ((byte)(cVar17 - 0x30U) < 10) {
      uVar13 = (int)cVar17 - 0x30;
    }
    else if ((byte)(cVar17 + 0x9fU) < 0x1a) {
      uVar13 = (int)cVar17 - 0x57;
    }
    else if ((byte)(cVar17 + 0xbfU) < 0x1a) {
      uVar13 = (int)cVar17 - 0x37;
    }
    else {
      uVar13 = 0xffffffff;
    }
    if (9 < uVar13) goto LAB_180004d6f;
    bVar10 = true;
    iVar21 = uVar13 + iVar21 * 10;
    if (0x1450 < iVar21) break;
    *(longlong *)(param_2 + 0x10) = *(longlong *)(param_2 + 0x10) + 1;
    if ((*(longlong *)(param_2 + 8) == 0) ||
       (*(ulonglong *)(param_2 + 0x10) <= *(ulonglong *)(param_2 + 8))) {
      lVar4 = *(longlong *)param_2;
      pcVar5 = *(char **)(lVar4 + 0x10);
      if (pcVar5 == *(char **)(lVar4 + 8)) goto LAB_180004cec;
      uVar12 = (uint)*pcVar5;
      *(char **)(lVar4 + 0x10) = pcVar5 + 1;
      if (uVar12 == 0xffffffff) goto LAB_180004cec;
    }
    else {
LAB_180004cec:
      uVar12 = 0;
    }
    bVar10 = true;
    local_res10[0] = (byte)uVar12;
  }
  iVar21 = 0x1451;
LAB_180004d6f:
  do {
    cVar17 = (char)uVar12;
    if ((byte)(cVar17 - 0x30U) < 10) {
      uVar12 = (int)cVar17 - 0x30;
    }
    else if ((byte)(cVar17 + 0x9fU) < 0x1a) {
      uVar12 = (int)cVar17 - 0x57;
    }
    else if ((byte)(cVar17 + 0xbfU) < 0x1a) {
      uVar12 = (int)cVar17 - 0x37;
    }
    else {
      uVar12 = 0xffffffff;
    }
    if (9 < uVar12) break;
    *(longlong *)(param_2 + 0x10) = *(longlong *)(param_2 + 0x10) + 1;
    if ((*(longlong *)(param_2 + 8) == 0) ||
       (*(ulonglong *)(param_2 + 0x10) <= *(ulonglong *)(param_2 + 8))) {
      lVar4 = *(longlong *)param_2;
      pcVar5 = *(char **)(lVar4 + 0x10);
      if (pcVar5 == *(char **)(lVar4 + 8)) goto LAB_180004dd4;
      uVar12 = (uint)*pcVar5;
      *(char **)(lVar4 + 0x10) = pcVar5 + 1;
      if (uVar12 == 0xffffffff) goto LAB_180004dd4;
    }
    else {
LAB_180004dd4:
      uVar12 = 0;
    }
    local_res10[0] = (byte)uVar12;
  } while( true );
  if (bVar11) {
    iVar21 = -iVar21;
  }
  if (!bVar10) {
    bVar11 = <lambda_5b936a367a2157d8f8fe79b470b291e7>::operator()
                       ((<lambda_5b936a367a2157d8f8fe79b470b291e7> *)&local_58);
    if (!bVar11) {
      return 7;
    }
    *(longlong *)(param_2 + 0x10) = *(longlong *)(param_2 + 0x10) + 1;
    if ((*(longlong *)(param_2 + 8) == 0) ||
       (*(ulonglong *)(param_2 + 0x10) <= *(ulonglong *)(param_2 + 8))) {
      lVar4 = *(longlong *)param_2;
      pcVar5 = *(char **)(lVar4 + 0x10);
      if (pcVar5 != *(char **)(lVar4 + 8)) {
        cVar17 = *pcVar5;
        *(char **)(lVar4 + 0x10) = pcVar5 + 1;
        if (cVar17 != -1) goto LAB_180004e30;
      }
    }
    cVar17 = '\0';
  }
  goto LAB_180004e30;
}



/* ---- parse_floating_point_possible_infinity<char,__crt_strtox::input_adapter_character_source<__crt_stdio_input::string_input_adapter<char>_>,unsigned___int64> @ 180004f0c ---- */

/* Library Function - Single Match
    enum __crt_strtox::floating_point_parse_result __cdecl
   __crt_strtox::parse_floating_point_possible_infinity<char,class
   __crt_strtox::input_adapter_character_source<class __crt_stdio_input::string_input_adapter<char>
   >,unsigned __int64>(char & __ptr64,class __crt_strtox::input_adapter_character_source<class
   __crt_stdio_input::string_input_adapter<char> > & __ptr64,unsigned __int64)
   
   Library: Visual Studio 2015 Release */

floating_point_parse_result __cdecl
__crt_strtox::
parse_floating_point_possible_infinity<char,__crt_strtox::input_adapter_character_source<__crt_stdio_input::string_input_adapter<char>_>,unsigned___int64>
          (char *param_1,
          input_adapter_character_source<__crt_stdio_input::string_input_adapter<char>_> *param_2,
          __uint64 param_3)

{
  longlong lVar1;
  char *pcVar2;
  longlong *plVar3;
  bool bVar4;
  char cVar5;
  longlong lVar6;
  longlong lVar7;
  __uint64 local_res18 [2];
  input_adapter_character_source<__crt_stdio_input::string_input_adapter<char>_> *local_28;
  char *local_20;
  __uint64 *local_18;
  
  local_18 = local_res18;
  lVar7 = 0;
  lVar6 = lVar7;
  do {
    local_28 = param_2;
    local_20 = param_1;
    if ((*param_1 != (&DAT_180013a88)[lVar6]) && (*param_1 != (&DAT_180013a8c)[lVar6])) {
      local_res18[0] = param_3;
      <lambda_5b936a367a2157d8f8fe79b470b291e7>::operator()
                ((<lambda_5b936a367a2157d8f8fe79b470b291e7> *)&local_28);
      return 7;
    }
    *(longlong *)(param_2 + 0x10) = *(longlong *)(param_2 + 0x10) + 1;
    if ((*(longlong *)(param_2 + 8) == 0) ||
       (*(ulonglong *)(param_2 + 0x10) <= *(ulonglong *)(param_2 + 8))) {
      lVar1 = *(longlong *)param_2;
      pcVar2 = *(char **)(lVar1 + 0x10);
      if (pcVar2 == *(char **)(lVar1 + 8)) goto LAB_180004f83;
      cVar5 = *pcVar2;
      *(char **)(lVar1 + 0x10) = pcVar2 + 1;
      if (cVar5 == -1) goto LAB_180004f83;
    }
    else {
LAB_180004f83:
      cVar5 = '\0';
    }
    lVar6 = lVar6 + 1;
    *param_1 = cVar5;
  } while (lVar6 != 3);
  *(longlong *)(param_2 + 0x10) = *(longlong *)(param_2 + 0x10) + -1;
  if (((*(longlong *)(param_2 + 8) == 0) ||
      (*(ulonglong *)(param_2 + 0x10) <= *(ulonglong *)(param_2 + 8))) && (1 < (byte)(cVar5 + 1U)))
  {
    plVar3 = *(longlong **)param_2;
    if (plVar3[2] != *plVar3) {
      plVar3[2] = plVar3[2] + -1;
    }
  }
  local_res18[0] = *(__uint64 *)(param_2 + 0x10);
  *(__uint64 *)(param_2 + 0x10) = local_res18[0] + 1;
  if ((*(longlong *)(param_2 + 8) == 0) || (local_res18[0] + 1 <= *(ulonglong *)(param_2 + 8))) {
    lVar6 = *(longlong *)param_2;
    pcVar2 = *(char **)(lVar6 + 0x10);
    if (pcVar2 != *(char **)(lVar6 + 8)) {
      cVar5 = *pcVar2;
      *(char **)(lVar6 + 0x10) = pcVar2 + 1;
      if (cVar5 != -1) goto LAB_180004ffb;
    }
  }
  cVar5 = '\0';
LAB_180004ffb:
  *param_1 = cVar5;
  do {
    if ((*param_1 != "INITY"[lVar7]) && (*param_1 != "inity"[lVar7])) {
      bVar4 = <lambda_5b936a367a2157d8f8fe79b470b291e7>::operator()
                        ((<lambda_5b936a367a2157d8f8fe79b470b291e7> *)&local_28);
      return (-(uint)bVar4 & 0xfffffffc) + 7;
    }
    *(longlong *)(param_2 + 0x10) = *(longlong *)(param_2 + 0x10) + 1;
    if ((*(longlong *)(param_2 + 8) == 0) ||
       (*(ulonglong *)(param_2 + 0x10) <= *(ulonglong *)(param_2 + 8))) {
      lVar6 = *(longlong *)param_2;
      pcVar2 = *(char **)(lVar6 + 0x10);
      if (pcVar2 == *(char **)(lVar6 + 8)) goto LAB_18000504c;
      cVar5 = *pcVar2;
      *(char **)(lVar6 + 0x10) = pcVar2 + 1;
      if (cVar5 == -1) goto LAB_18000504c;
    }
    else {
LAB_18000504c:
      cVar5 = '\0';
    }
    lVar7 = lVar7 + 1;
    *param_1 = cVar5;
    if (lVar7 == 5) {
      *(longlong *)(param_2 + 0x10) = *(longlong *)(param_2 + 0x10) + -1;
      if (((*(longlong *)(param_2 + 8) == 0) ||
          (*(ulonglong *)(param_2 + 0x10) <= *(ulonglong *)(param_2 + 8))) &&
         (1 < (byte)(cVar5 + 1U))) {
        plVar3 = *(longlong **)param_2;
        if (plVar3[2] != *plVar3) {
          plVar3[2] = plVar3[2] + -1;
        }
      }
      return 3;
    }
  } while( true );
}



/* ---- parse_floating_point_possible_nan<char,__crt_strtox::input_adapter_character_source<__crt_stdio_input::string_input_adapter<char>_>,unsigned___int64> @ 1800050bc ---- */

/* Library Function - Single Match
    enum __crt_strtox::floating_point_parse_result __cdecl
   __crt_strtox::parse_floating_point_possible_nan<char,class
   __crt_strtox::input_adapter_character_source<class __crt_stdio_input::string_input_adapter<char>
   >,unsigned __int64>(char & __ptr64,class __crt_strtox::input_adapter_character_source<class
   __crt_stdio_input::string_input_adapter<char> > & __ptr64,unsigned __int64)
   
   Library: Visual Studio 2015 Release */

floating_point_parse_result __cdecl
__crt_strtox::
parse_floating_point_possible_nan<char,__crt_strtox::input_adapter_character_source<__crt_stdio_input::string_input_adapter<char>_>,unsigned___int64>
          (char *param_1,
          input_adapter_character_source<__crt_stdio_input::string_input_adapter<char>_> *param_2,
          __uint64 param_3)

{
  longlong lVar1;
  char *pcVar2;
  longlong *plVar3;
  bool bVar4;
  floating_point_parse_result fVar5;
  undefined8 uVar6;
  char cVar7;
  int iVar8;
  longlong lVar9;
  __uint64 local_res18 [2];
  input_adapter_character_source<__crt_stdio_input::string_input_adapter<char>_> *local_28;
  char *local_20;
  __uint64 *local_18;
  
  local_18 = local_res18;
  lVar9 = 0;
  do {
    local_28 = param_2;
    local_20 = param_1;
    if ((*param_1 != (&DAT_180013aa0)[lVar9]) && (*param_1 != (&DAT_180013aa4)[lVar9])) {
      local_res18[0] = param_3;
      <lambda_5b936a367a2157d8f8fe79b470b291e7>::operator()
                ((<lambda_5b936a367a2157d8f8fe79b470b291e7> *)&local_28);
      return 7;
    }
    *(longlong *)(param_2 + 0x10) = *(longlong *)(param_2 + 0x10) + 1;
    if ((*(longlong *)(param_2 + 8) == 0) ||
       (*(ulonglong *)(param_2 + 0x10) <= *(ulonglong *)(param_2 + 8))) {
      lVar1 = *(longlong *)param_2;
      pcVar2 = *(char **)(lVar1 + 0x10);
      if (pcVar2 == *(char **)(lVar1 + 8)) goto LAB_180005136;
      cVar7 = *pcVar2;
      *(char **)(lVar1 + 0x10) = pcVar2 + 1;
      if (cVar7 == -1) goto LAB_180005136;
    }
    else {
LAB_180005136:
      cVar7 = '\0';
    }
    lVar9 = lVar9 + 1;
    *param_1 = cVar7;
  } while (lVar9 != 3);
  *(longlong *)(param_2 + 0x10) = *(longlong *)(param_2 + 0x10) + -1;
  if (((*(longlong *)(param_2 + 8) == 0) ||
      (*(ulonglong *)(param_2 + 0x10) <= *(ulonglong *)(param_2 + 8))) && (1 < (byte)(cVar7 + 1U)))
  {
    plVar3 = *(longlong **)param_2;
    if (plVar3[2] != *plVar3) {
      plVar3[2] = plVar3[2] + -1;
    }
  }
  local_res18[0] = *(__uint64 *)(param_2 + 0x10);
  *(__uint64 *)(param_2 + 0x10) = local_res18[0] + 1;
  if ((*(longlong *)(param_2 + 8) == 0) || (local_res18[0] + 1 <= *(ulonglong *)(param_2 + 8))) {
    lVar9 = *(longlong *)param_2;
    pcVar2 = *(char **)(lVar9 + 0x10);
    if (pcVar2 == *(char **)(lVar9 + 8)) goto LAB_1800051ab;
    cVar7 = *pcVar2;
    *(char **)(lVar9 + 0x10) = pcVar2 + 1;
    if (cVar7 == -1) goto LAB_1800051ab;
  }
  else {
LAB_1800051ab:
    cVar7 = '\0';
  }
  *param_1 = cVar7;
  if (cVar7 == '(') {
    *(longlong *)(param_2 + 0x10) = *(longlong *)(param_2 + 0x10) + 1;
    if ((*(longlong *)(param_2 + 8) == 0) ||
       (*(ulonglong *)(param_2 + 0x10) <= *(ulonglong *)(param_2 + 8))) {
      lVar9 = *(longlong *)param_2;
      pcVar2 = *(char **)(lVar9 + 0x10);
      if (pcVar2 == *(char **)(lVar9 + 8)) goto LAB_180005212;
      cVar7 = *pcVar2;
      *(char **)(lVar9 + 0x10) = pcVar2 + 1;
      if (cVar7 == -1) goto LAB_180005212;
    }
    else {
LAB_180005212:
      cVar7 = '\0';
    }
    *param_1 = cVar7;
    uVar6 = FID_conflict_parse_floating_point_possible_nan_is_snan<char,__crt_strtox::input_adapter_character_source<__crt_stdio_input::string_input_adapter<char>_>_>
                      (param_1,(longlong *)param_2);
    if ((char)uVar6 != '\0') {
      cVar7 = *param_1;
      *(longlong *)(param_2 + 0x10) = *(longlong *)(param_2 + 0x10) + -1;
      if (((*(longlong *)(param_2 + 8) == 0) ||
          (*(ulonglong *)(param_2 + 0x10) <= *(ulonglong *)(param_2 + 8))) &&
         (1 < (byte)(cVar7 + 1U))) {
        plVar3 = *(longlong **)param_2;
        if (plVar3[2] != *plVar3) {
          plVar3[2] = plVar3[2] + -1;
        }
      }
      return 5;
    }
    uVar6 = FID_conflict_parse_floating_point_possible_nan_is_snan<char,__crt_strtox::input_adapter_character_source<__crt_stdio_input::string_input_adapter<char>_>_>
                      (param_1,(longlong *)param_2);
    if ((char)uVar6 != '\0') {
      cVar7 = *param_1;
      *(longlong *)(param_2 + 0x10) = *(longlong *)(param_2 + 0x10) + -1;
      if (((*(longlong *)(param_2 + 8) == 0) ||
          (*(ulonglong *)(param_2 + 0x10) <= *(ulonglong *)(param_2 + 8))) &&
         (1 < (byte)(cVar7 + 1U))) {
        plVar3 = *(longlong **)param_2;
        if (plVar3[2] != *plVar3) {
          plVar3[2] = plVar3[2] + -1;
        }
      }
      return 6;
    }
    if (*param_1 != ')') {
      do {
        if (*param_1 == '\0') break;
        iVar8 = (int)*param_1;
        if (((9 < iVar8 - 0x30U) && (0x19 < iVar8 - 0x61U)) &&
           ((0x19 < iVar8 - 0x41U && (iVar8 != 0x5f)))) goto LAB_1800051b4;
        *(longlong *)(param_2 + 0x10) = *(longlong *)(param_2 + 0x10) + 1;
        if ((*(longlong *)(param_2 + 8) == 0) ||
           (*(ulonglong *)(param_2 + 0x10) <= *(ulonglong *)(param_2 + 8))) {
          lVar9 = *(longlong *)param_2;
          pcVar2 = *(char **)(lVar9 + 0x10);
          if (pcVar2 == *(char **)(lVar9 + 8)) goto LAB_180005307;
          cVar7 = *pcVar2;
          *(char **)(lVar9 + 0x10) = pcVar2 + 1;
          if (cVar7 == -1) goto LAB_180005307;
        }
        else {
LAB_180005307:
          cVar7 = '\0';
        }
        *param_1 = cVar7;
      } while (cVar7 != ')');
      if (*param_1 != ')') goto LAB_1800051b4;
    }
    fVar5 = 4;
  }
  else {
LAB_1800051b4:
    bVar4 = <lambda_5b936a367a2157d8f8fe79b470b291e7>::operator()
                      ((<lambda_5b936a367a2157d8f8fe79b470b291e7> *)&local_28);
    fVar5 = (-(uint)bVar4 & 0xfffffffd) + 7;
  }
  return fVar5;
}



/* ---- FID_conflict:parse_floating_point_possible_nan_is_snan<char,__crt_strtox::input_adapter_character_source<__crt_stdio_input::string_input_adapter<char>_>_> @ 18000532c ---- */

/* Library Function - Multiple Matches With Different Base Names
    bool __cdecl __crt_strtox::parse_floating_point_possible_nan_is_ind<char,class
   __crt_strtox::input_adapter_character_source<class __crt_stdio_input::string_input_adapter<char>
   > >(char & __ptr64,class __crt_strtox::input_adapter_character_source<class
   __crt_stdio_input::string_input_adapter<char> > & __ptr64)
    bool __cdecl __crt_strtox::parse_floating_point_possible_nan_is_snan<char,class
   __crt_strtox::input_adapter_character_source<class __crt_stdio_input::string_input_adapter<char>
   > >(char & __ptr64,class __crt_strtox::input_adapter_character_source<class
   __crt_stdio_input::string_input_adapter<char> > & __ptr64)
   
   Library: Visual Studio 2015 Release */

undefined8
FID_conflict_parse_floating_point_possible_nan_is_snan<char,__crt_strtox::input_adapter_character_source<__crt_stdio_input::string_input_adapter<char>_>_>
          (char *param_1,longlong *param_2)

{
  longlong lVar1;
  char *in_RAX;
  char cVar2;
  longlong lVar3;
  longlong lVar4;
  
  lVar3 = 0;
  lVar4 = lVar3;
  do {
    cVar2 = *param_1;
    in_RAX = (char *)CONCAT71((int7)((ulonglong)in_RAX >> 8),cVar2);
    if ((cVar2 != (&DAT_180013ab8)[lVar4]) && (cVar2 != (&DAT_180013abc)[lVar4]))
    goto LAB_18000539a;
    param_2[2] = param_2[2] + 1;
    in_RAX = (char *)param_2[2];
    if ((param_2[1] == 0) || (in_RAX <= (char *)param_2[1])) {
      lVar1 = *param_2;
      in_RAX = *(char **)(lVar1 + 0x10);
      if (in_RAX == *(char **)(lVar1 + 8)) goto LAB_180005388;
      cVar2 = *in_RAX;
      in_RAX = in_RAX + 1;
      *(char **)(lVar1 + 0x10) = in_RAX;
      if (cVar2 == -1) goto LAB_180005388;
    }
    else {
LAB_180005388:
      cVar2 = '\0';
    }
    lVar4 = lVar4 + 1;
    *param_1 = cVar2;
  } while (lVar4 != 4);
  lVar3 = 1;
LAB_18000539a:
  return CONCAT71((int7)((ulonglong)in_RAX >> 8),(char)lVar3);
}



/* ---- FID_conflict:parse_floating_point_possible_nan_is_snan<char,__crt_strtox::input_adapter_character_source<__crt_stdio_input::string_input_adapter<char>_>_> @ 1800053a4 ---- */

/* Library Function - Multiple Matches With Different Base Names
    bool __cdecl __crt_strtox::parse_floating_point_possible_nan_is_ind<char,class
   __crt_strtox::input_adapter_character_source<class __crt_stdio_input::string_input_adapter<char>
   > >(char & __ptr64,class __crt_strtox::input_adapter_character_source<class
   __crt_stdio_input::string_input_adapter<char> > & __ptr64)
    bool __cdecl __crt_strtox::parse_floating_point_possible_nan_is_snan<char,class
   __crt_strtox::input_adapter_character_source<class __crt_stdio_input::string_input_adapter<char>
   > >(char & __ptr64,class __crt_strtox::input_adapter_character_source<class
   __crt_stdio_input::string_input_adapter<char> > & __ptr64)
   
   Library: Visual Studio 2015 Release */

undefined8
FID_conflict_parse_floating_point_possible_nan_is_snan<char,__crt_strtox::input_adapter_character_source<__crt_stdio_input::string_input_adapter<char>_>_>
          (char *param_1,longlong *param_2)

{
  longlong lVar1;
  char *in_RAX;
  char cVar2;
  longlong lVar3;
  longlong lVar4;
  
  lVar3 = 0;
  lVar4 = lVar3;
  do {
    cVar2 = *param_1;
    in_RAX = (char *)CONCAT71((int7)((ulonglong)in_RAX >> 8),cVar2);
    if ((cVar2 != (&DAT_180013aa8)[lVar4]) && (cVar2 != (&DAT_180013ab0)[lVar4]))
    goto LAB_180005412;
    param_2[2] = param_2[2] + 1;
    in_RAX = (char *)param_2[2];
    if ((param_2[1] == 0) || (in_RAX <= (char *)param_2[1])) {
      lVar1 = *param_2;
      in_RAX = *(char **)(lVar1 + 0x10);
      if (in_RAX == *(char **)(lVar1 + 8)) goto LAB_180005400;
      cVar2 = *in_RAX;
      in_RAX = in_RAX + 1;
      *(char **)(lVar1 + 0x10) = in_RAX;
      if (cVar2 == -1) goto LAB_180005400;
    }
    else {
LAB_180005400:
      cVar2 = '\0';
    }
    lVar4 = lVar4 + 1;
    *param_1 = cVar2;
  } while (lVar4 != 5);
  lVar3 = 1;
LAB_180005412:
  return CONCAT71((int7)((ulonglong)in_RAX >> 8),(char)lVar3);
}



/* ---- parse_floating_point_write_result<float> @ 18000541c ---- */

/* Library Function - Single Match
    enum SLD_STATUS __cdecl __crt_strtox::parse_floating_point_write_result<float>(enum
   __crt_strtox::floating_point_parse_result,struct __crt_strtox::floating_point_string const &
   __ptr64,float * __ptr64 const)
   
   Library: Visual Studio 2015 Release */

SLD_STATUS __cdecl
__crt_strtox::parse_floating_point_write_result<float>
          (floating_point_parse_result param_1,floating_point_string *param_2,float *param_3)

{
  float fVar1;
  SLD_STATUS SVar2;
  float *local_18;
  undefined1 local_10;
  
  if ((int)param_1 < 6) {
    if (param_1 == 5) {
      fVar1 = (float)((uint)(param_2[0x308] != (floating_point_string)0x0) << 0x1f | 0x7f800001);
    }
    else {
      local_18 = param_3;
      if (param_1 == 0) {
        local_10 = 0;
        SVar2 = convert_decimal_string_to_floating_type_common
                          (param_2,(floating_point_value *)&local_18);
        return SVar2;
      }
      if (param_1 == 1) {
        local_10 = 0;
        SVar2 = convert_hexadecimal_string_to_floating_type_common
                          (param_2,(floating_point_value *)&local_18);
        return SVar2;
      }
      if (param_1 == 2) {
        fVar1 = (float)((uint)(param_2[0x308] != (floating_point_string)0x0) << 0x1f);
      }
      else if (param_1 == 3) {
        fVar1 = (float)((uint)(param_2[0x308] != (floating_point_string)0x0) << 0x1f | 0x7f800000);
      }
      else {
        if (param_1 != 4) {
          return 1;
        }
        fVar1 = (float)((uint)(param_2[0x308] != (floating_point_string)0x0) << 0x1f | 0x7fffffff);
      }
    }
    *param_3 = fVar1;
  }
  else {
    if (param_1 != 6) {
      if (param_1 == 7) {
        *param_3 = 0.0;
      }
      else {
        if (param_1 == 8) {
          *param_3 = (float)((uint)(param_2[0x308] != (floating_point_string)0x0) << 0x1f);
          return 2;
        }
        if (param_1 == 9) {
          *param_3 = (float)((uint)(param_2[0x308] != (floating_point_string)0x0) << 0x1f |
                            0x7f800000);
          return 3;
        }
      }
      return 1;
    }
    *param_3 = -NAN;
  }
  return 0;
}



/* ---- parse_floating_point_write_result<double> @ 180005534 ---- */

/* Library Function - Single Match
    enum SLD_STATUS __cdecl __crt_strtox::parse_floating_point_write_result<double>(enum
   __crt_strtox::floating_point_parse_result,struct __crt_strtox::floating_point_string const &
   __ptr64,double * __ptr64 const)
   
   Library: Visual Studio 2015 Release */

SLD_STATUS __cdecl
__crt_strtox::parse_floating_point_write_result<double>
          (floating_point_parse_result param_1,floating_point_string *param_2,double *param_3)

{
  SLD_STATUS SVar1;
  double dVar2;
  ulonglong uVar3;
  double *local_18;
  undefined1 local_10;
  
  if ((int)param_1 < 6) {
    if (param_1 == 5) {
      uVar3 = 0x7ff0000000000001;
    }
    else {
      local_18 = param_3;
      if (param_1 == 0) {
        local_10 = 1;
        SVar1 = convert_decimal_string_to_floating_type_common
                          (param_2,(floating_point_value *)&local_18);
        return SVar1;
      }
      if (param_1 == 1) {
        local_10 = 1;
        SVar1 = convert_hexadecimal_string_to_floating_type_common
                          (param_2,(floating_point_value *)&local_18);
        return SVar1;
      }
      if (param_1 == 2) {
        dVar2 = (double)((ulonglong)(param_2[0x308] != (floating_point_string)0x0) << 0x3f);
        goto LAB_180005651;
      }
      if (param_1 == 3) {
        uVar3 = 0x7ff0000000000000;
      }
      else {
        if (param_1 != 4) {
          return 1;
        }
        uVar3 = 0x7fffffffffffffff;
      }
    }
    dVar2 = (double)((ulonglong)(param_2[0x308] != (floating_point_string)0x0) << 0x3f | uVar3);
  }
  else {
    if (param_1 != 6) {
      if (param_1 == 7) {
        *param_3 = 0.0;
      }
      else {
        if (param_1 == 8) {
          *param_3 = (double)((ulonglong)(param_2[0x308] != (floating_point_string)0x0) << 0x3f);
          return 2;
        }
        if (param_1 == 9) {
          *param_3 = (double)((ulonglong)(param_2[0x308] != (floating_point_string)0x0) << 0x3f |
                             0x7ff0000000000000);
          return 3;
        }
      }
      return 1;
    }
    dVar2 = -NAN;
  }
LAB_180005651:
  *param_3 = dVar2;
  return 0;
}



/* ---- parse_integer<unsigned___int64,__crt_strtox::input_adapter_character_source<__crt_stdio_input::string_input_adapter<char>_>_> @ 18000565c ---- */

/* Library Function - Single Match
    unsigned __int64 __cdecl __crt_strtox::parse_integer<unsigned __int64,class
   __crt_strtox::input_adapter_character_source<class __crt_stdio_input::string_input_adapter<char>
   > >(struct __crt_locale_pointers * __ptr64 const,class
   __crt_strtox::input_adapter_character_source<class __crt_stdio_input::string_input_adapter<char>
   >,int,bool)
   
   Library: Visual Studio 2015 Release */

__uint64 __cdecl
__crt_strtox::
parse_integer<unsigned___int64,__crt_strtox::input_adapter_character_source<__crt_stdio_input::string_input_adapter<char>_>_>
          (__crt_locale_pointers *param_1,longlong *param_2,uint param_3,char param_4)

{
  longlong lVar1;
  longlong lVar2;
  char *pcVar3;
  longlong *plVar4;
  undefined1 auVar5 [16];
  undefined1 auVar6 [16];
  bool bVar7;
  uint uVar8;
  int iVar9;
  ulong *puVar10;
  ulonglong uVar11;
  char cVar12;
  uint uVar13;
  ulonglong uVar14;
  ulonglong uVar15;
  longlong local_48;
  localeinfo_struct local_40;
  char local_30;
  
  uVar15 = 0;
  if (((*param_2 == 0) || (param_2[3] == 0)) || ((param_3 != 0 && (0x22 < param_3 - 2)))) {
    puVar10 = __doserrno();
    *puVar10 = 0x16;
    FUN_18000aff4();
    if ((undefined1 *)param_2[3] == (undefined1 *)0x0) {
      return 0;
    }
    if (param_2[2] != 0) {
      return 0;
    }
    *(undefined1 *)param_2[3] = 0;
    return 0;
  }
  _LocaleUpdate::_LocaleUpdate((_LocaleUpdate *)&local_48,param_1);
  lVar1 = param_2[2];
  uVar14 = lVar1 + 1;
  param_2[2] = uVar14;
  if ((param_2[1] == 0) || (uVar14 <= (ulonglong)param_2[1])) {
    lVar2 = *param_2;
    pcVar3 = *(char **)(lVar2 + 0x10);
    if (pcVar3 == *(char **)(lVar2 + 8)) goto LAB_18000570f;
    cVar12 = *pcVar3;
    uVar14 = (ulonglong)(uint)(int)cVar12;
    *(char **)(lVar2 + 0x10) = pcVar3 + 1;
    if ((int)cVar12 == 0xffffffff) goto LAB_18000570f;
  }
  else {
LAB_18000570f:
    uVar14 = 0;
  }
  while( true ) {
    if ((int)(local_40.locinfo)->lc_collate_cp < 2) {
      uVar8 = *(ushort *)(*(longlong *)local_40.locinfo + (uVar14 & 0xff) * 2) & 8;
    }
    else {
      uVar8 = _isctype_l((int)(uVar14 & 0xff),8,&local_40);
    }
    if (uVar8 == 0) break;
    param_2[2] = param_2[2] + 1;
    if ((param_2[1] != 0) && ((ulonglong)param_2[1] < (ulonglong)param_2[2])) goto LAB_18000575d;
    lVar2 = *param_2;
    pcVar3 = *(char **)(lVar2 + 0x10);
    if (pcVar3 == *(char **)(lVar2 + 8)) goto LAB_18000575d;
    cVar12 = *pcVar3;
    uVar14 = (ulonglong)(uint)(int)cVar12;
    *(char **)(lVar2 + 0x10) = pcVar3 + 1;
    if ((int)cVar12 == 0xffffffff) {
LAB_18000575d:
      uVar14 = 0;
    }
  }
  uVar8 = (uint)(param_4 != '\0');
  if ((char)uVar14 == '-') {
    uVar8 = param_4 != '\0' | 2;
LAB_180005798:
    param_2[2] = param_2[2] + 1;
    if ((param_2[1] == 0) || ((ulonglong)param_2[2] <= (ulonglong)param_2[1])) {
      lVar2 = *param_2;
      pcVar3 = *(char **)(lVar2 + 0x10);
      if (pcVar3 != *(char **)(lVar2 + 8)) {
        cVar12 = *pcVar3;
        uVar14 = (ulonglong)(uint)(int)cVar12;
        *(char **)(lVar2 + 0x10) = pcVar3 + 1;
        if ((int)cVar12 != 0xffffffff) goto LAB_1800057d5;
      }
    }
    uVar14 = 0;
  }
  else if ((char)uVar14 == '+') goto LAB_180005798;
LAB_1800057d5:
  if ((param_3 & 0xffffffef) != 0) goto LAB_1800058e7;
  cVar12 = (char)uVar14;
  if ((byte)(cVar12 - 0x30U) < 10) {
    iVar9 = cVar12 + -0x30;
  }
  else if ((byte)(cVar12 + 0x9fU) < 0x1a) {
    iVar9 = cVar12 + -0x57;
  }
  else if ((byte)(cVar12 + 0xbfU) < 0x1a) {
    iVar9 = cVar12 + -0x37;
  }
  else {
    iVar9 = -1;
  }
  if (iVar9 != 0) {
    if (param_3 == 0) {
      param_3 = 10;
    }
    goto LAB_1800058e7;
  }
  param_2[2] = param_2[2] + 1;
  if ((param_2[1] == 0) || ((ulonglong)param_2[2] <= (ulonglong)param_2[1])) {
    lVar2 = *param_2;
    pcVar3 = *(char **)(lVar2 + 0x10);
    if (pcVar3 == *(char **)(lVar2 + 8)) goto LAB_1800058ac;
    cVar12 = *pcVar3;
    *(char **)(lVar2 + 0x10) = pcVar3 + 1;
    if (cVar12 == -1) goto LAB_1800058ac;
    if (((int)cVar12 - 0x58U & 0xdf) == 0) {
      if (param_3 == 0) {
        param_3 = 0x10;
      }
      param_2[2] = param_2[2] + 1;
      if ((param_2[1] == 0) || ((ulonglong)param_2[2] <= (ulonglong)param_2[1])) {
        lVar2 = *param_2;
        pcVar3 = *(char **)(lVar2 + 0x10);
        if (pcVar3 != *(char **)(lVar2 + 8)) {
          cVar12 = *pcVar3;
          uVar14 = (ulonglong)(uint)(int)cVar12;
          *(char **)(lVar2 + 0x10) = pcVar3 + 1;
          if ((int)cVar12 != 0xffffffff) goto LAB_1800058e7;
        }
      }
      uVar14 = 0;
      goto LAB_1800058e7;
    }
  }
  else {
LAB_1800058ac:
    cVar12 = '\0';
  }
  if (param_3 == 0) {
    param_3 = 8;
  }
  param_2[2] = param_2[2] + -1;
  if (((param_2[1] == 0) || ((ulonglong)param_2[2] <= (ulonglong)param_2[1])) &&
     (1 < (byte)(cVar12 + 1U))) {
    plVar4 = (longlong *)*param_2;
    if (plVar4[2] != *plVar4) {
      plVar4[2] = plVar4[2] + -1;
    }
  }
LAB_1800058e7:
  auVar5._8_8_ = 0;
  auVar5._0_8_ = (longlong)(int)param_3;
  auVar6 = ZEXT816(0) << 0x40 | ZEXT816(0xffffffffffffffff);
  uVar11 = SUB168(auVar6 / auVar5,0);
  do {
    cVar12 = (char)uVar14;
    if ((byte)(cVar12 - 0x30U) < 10) {
      uVar14 = (ulonglong)((int)cVar12 - 0x30);
    }
    else if ((byte)(cVar12 + 0x9fU) < 0x1a) {
      uVar14 = (ulonglong)((int)cVar12 - 0x57);
    }
    else if ((byte)(cVar12 + 0xbfU) < 0x1a) {
      uVar14 = (ulonglong)((int)cVar12 - 0x37);
    }
    else {
      uVar14 = 0xffffffff;
    }
    if (((uint)uVar14 == 0xffffffff) || (param_3 <= (uint)uVar14)) {
      param_2[2] = param_2[2] + -1;
      if (((param_2[1] == 0) || ((ulonglong)param_2[2] <= (ulonglong)param_2[1])) &&
         (1 < (byte)(cVar12 + 1U))) {
        plVar4 = (longlong *)*param_2;
        if (plVar4[2] != *plVar4) {
          plVar4[2] = plVar4[2] + -1;
        }
      }
      if ((uVar8 & 8) == 0) {
        if (lVar1 != param_2[2]) {
          *(undefined1 *)param_2[3] = 0;
        }
        if (local_30 != '\0') {
          *(uint *)(local_48 + 0x3a8) = *(uint *)(local_48 + 0x3a8) & 0xfffffffd;
        }
        if (((undefined1 *)param_2[3] != (undefined1 *)0x0) && (param_2[2] == 0)) {
          *(undefined1 *)param_2[3] = 0;
        }
        return 0;
      }
      bVar7 = is_overflow_condition<unsigned___int64>(uVar8,uVar15);
      if (bVar7) {
        puVar10 = __doserrno();
        *puVar10 = 0x22;
        if ((uVar8 & 1) != 0) {
          if ((uVar8 & 2) == 0) {
            if (local_30 != '\0') {
              *(uint *)(local_48 + 0x3a8) = *(uint *)(local_48 + 0x3a8) & 0xfffffffd;
            }
            if (((undefined1 *)param_2[3] != (undefined1 *)0x0) && (param_2[2] == 0)) {
              *(undefined1 *)param_2[3] = 0;
            }
            return 0x7fffffffffffffff;
          }
          if (local_30 != '\0') {
            *(uint *)(local_48 + 0x3a8) = *(uint *)(local_48 + 0x3a8) & 0xfffffffd;
          }
          if (((undefined1 *)param_2[3] != (undefined1 *)0x0) && (param_2[2] == 0)) {
            *(undefined1 *)param_2[3] = 0;
          }
          return 0x8000000000000000;
        }
        uVar15 = 0xffffffffffffffff;
      }
      else if ((uVar8 & 2) != 0) {
        uVar15 = -uVar15;
      }
      if (local_30 != '\0') {
        *(uint *)(local_48 + 0x3a8) = *(uint *)(local_48 + 0x3a8) & 0xfffffffd;
      }
      if ((undefined1 *)param_2[3] != (undefined1 *)0x0) {
        if (param_2[2] == 0) {
          *(undefined1 *)param_2[3] = 0;
          return uVar15;
        }
        return uVar15;
      }
      return uVar15;
    }
    uVar13 = uVar8 | 8;
    if ((uVar15 < uVar11) || ((uVar15 == uVar11 && (uVar14 <= SUB168(auVar6 % auVar5,0))))) {
      uVar15 = uVar14 + (longlong)(int)param_3 * uVar15;
    }
    else {
      uVar13 = uVar8 | 0xc;
    }
    param_2[2] = param_2[2] + 1;
    uVar8 = uVar13;
    if ((param_2[1] != 0) && ((ulonglong)param_2[1] < (ulonglong)param_2[2])) goto LAB_180005973;
    lVar2 = *param_2;
    pcVar3 = *(char **)(lVar2 + 0x10);
    if (pcVar3 == *(char **)(lVar2 + 8)) goto LAB_180005973;
    cVar12 = *pcVar3;
    uVar14 = (ulonglong)(uint)(int)cVar12;
    *(char **)(lVar2 + 0x10) = pcVar3 + 1;
    if ((int)cVar12 == 0xffffffff) {
LAB_180005973:
      uVar14 = 0;
    }
  } while( true );
}



/* ---- process_floating_point_specifier_t<float> @ 180005af0 ---- */

/* WARNING: Removing unreachable block (ram,0x000180005b3a) */
/* WARNING: Removing unreachable block (ram,0x000180005b3f) */
/* WARNING: Removing unreachable block (ram,0x000180005b49) */
/* WARNING: Removing unreachable block (ram,0x000180005b73) */
/* WARNING: Removing unreachable block (ram,0x000180005b61) */
/* WARNING: Removing unreachable block (ram,0x000180005b83) */
/* WARNING: Removing unreachable block (ram,0x000180005b45) */
/* Library Function - Single Match
    private: bool __cdecl __crt_stdio_input::input_processor<char,class
   __crt_stdio_input::string_input_adapter<char> >::process_floating_point_specifier_t<float>(void)
   __ptr64
   
   Library: Visual Studio 2015 Release */

bool __thiscall
__crt_stdio_input::input_processor<char,__crt_stdio_input::string_input_adapter<char>_>::
process_floating_point_specifier_t<float>
          (input_processor<char,__crt_stdio_input::string_input_adapter<char>_> *this)

{
  undefined8 uVar1;
  undefined4 local_res10 [2];
  string_input_adapter<char> local_28 [32];
  
  local_res10[0] = 0;
  uVar1 = __crt_strtox::
          make_input_adapter_character_source<__crt_stdio_input::string_input_adapter<char>_>
                    (local_28,(__uint64)(this + 8),*(bool **)(this + 0x40));
  __crt_strtox::
  parse_floating_point<__crt_strtox::input_adapter_character_source<__crt_stdio_input::string_input_adapter<char>_>,float>
            (*(undefined8 *)(this + 0x78),uVar1,local_res10);
  return false;
}



/* ---- process_floating_point_specifier_t<double> @ 180005b98 ---- */

/* WARNING: Removing unreachable block (ram,0x000180005be2) */
/* WARNING: Removing unreachable block (ram,0x000180005be7) */
/* WARNING: Removing unreachable block (ram,0x000180005bf1) */
/* WARNING: Removing unreachable block (ram,0x000180005c1b) */
/* WARNING: Removing unreachable block (ram,0x000180005c09) */
/* WARNING: Removing unreachable block (ram,0x000180005c2d) */
/* WARNING: Removing unreachable block (ram,0x000180005bed) */
/* Library Function - Single Match
    private: bool __cdecl __crt_stdio_input::input_processor<char,class
   __crt_stdio_input::string_input_adapter<char> >::process_floating_point_specifier_t<double>(void)
   __ptr64
   
   Library: Visual Studio 2015 Release */

bool __thiscall
__crt_stdio_input::input_processor<char,__crt_stdio_input::string_input_adapter<char>_>::
process_floating_point_specifier_t<double>
          (input_processor<char,__crt_stdio_input::string_input_adapter<char>_> *this)

{
  undefined8 uVar1;
  undefined8 local_res10;
  string_input_adapter<char> local_28 [32];
  
  local_res10 = 0;
  uVar1 = __crt_strtox::
          make_input_adapter_character_source<__crt_stdio_input::string_input_adapter<char>_>
                    (local_28,(__uint64)(this + 8),*(bool **)(this + 0x40));
  __crt_strtox::
  parse_floating_point<__crt_strtox::input_adapter_character_source<__crt_stdio_input::string_input_adapter<char>_>,double>
            (*(undefined8 *)(this + 0x78),uVar1,&local_res10);
  return false;
}



/* ---- process_string_specifier_tchar<char> @ 180005c40 ---- */

/* WARNING: Removing unreachable block (ram,0x000180005d3e) */
/* Library Function - Single Match
    private: bool __cdecl __crt_stdio_input::input_processor<char,class
   __crt_stdio_input::string_input_adapter<char> >::process_string_specifier_tchar<char>(enum
   __crt_stdio_input::conversion_mode,char) __ptr64
   
   Library: Visual Studio 2015 Release */

bool __thiscall
__crt_stdio_input::input_processor<char,__crt_stdio_input::string_input_adapter<char>_>::
process_string_specifier_tchar<char>
          (input_processor<char,__crt_stdio_input::string_input_adapter<char>_> *this,
          conversion_mode param_1,char param_2)

{
  byte bVar1;
  uint *puVar2;
  longlong lVar3;
  byte *pbVar4;
  longlong lVar5;
  ulong *puVar6;
  longlong lVar7;
  ulonglong uVar8;
  ulonglong uVar9;
  int iVar10;
  byte *pbVar11;
  byte *pbVar12;
  bool bVar13;
  
  pbVar11 = (byte *)0x0;
  if (this[0x3a] == (input_processor<char,__crt_stdio_input::string_input_adapter<char>_>)0x0) {
    *(longlong *)(this + 0x80) = *(longlong *)(this + 0x80) + 8;
    puVar2 = *(uint **)(this + 0x80);
    pbVar11 = *(byte **)(puVar2 + -2);
    if (pbVar11 == (byte *)0x0) {
      puVar6 = __doserrno();
      *puVar6 = 0x16;
      FUN_18000aff4();
      return false;
    }
    if (((byte)*this & 1) != 0) {
      *(uint **)(this + 0x80) = puVar2 + 2;
      uVar9 = (ulonglong)*puVar2;
      goto LAB_180005cb0;
    }
  }
  uVar9 = 0xffffffffffffffff;
LAB_180005cb0:
  if (uVar9 == 0) {
    if (((byte)*this & 4) != 0) {
      if (*(longlong *)(this + 0x18) != *(longlong *)(this + 0x10)) {
        *(longlong *)(this + 0x18) = *(longlong *)(this + 0x18) + 1;
      }
LAB_180005ccb:
      *pbVar11 = 0;
    }
LAB_180005ccf:
    puVar6 = __doserrno();
    *puVar6 = 0xc;
  }
  else {
    lVar3 = *(longlong *)(this + 0x40);
    uVar8 = uVar9;
    if ((param_1 != 0) && (uVar9 != 0xffffffffffffffff)) {
      uVar8 = uVar9 - 1;
    }
    lVar7 = 0;
    pbVar12 = pbVar11;
    while( true ) {
      if ((lVar3 != 0) && (lVar7 == lVar3)) goto LAB_180005db9;
      pbVar4 = *(byte **)(this + 0x18);
      if (pbVar4 == *(byte **)(this + 0x10)) break;
      bVar1 = *pbVar4;
      iVar10 = (int)(char)bVar1;
      *(byte **)(this + 0x18) = pbVar4 + 1;
      if (iVar10 == -1) goto LAB_180005d9c;
      if (param_1 != 0) {
        if (param_1 == 1) {
          if (iVar10 - 9U < 5) goto LAB_180005d9c;
          bVar13 = iVar10 == 0x20;
        }
        else {
          if (param_1 != 8) goto LAB_180005d9c;
          bVar13 = ((byte)this[(ulonglong)(bVar1 >> 3) + 0x54] & (byte)(1 << (bVar1 & 7))) == 0;
        }
        if (bVar13) goto LAB_180005d9c;
      }
      if (this[0x3a] == (input_processor<char,__crt_stdio_input::string_input_adapter<char>_>)0x0) {
        if (uVar8 == 0) {
          if (uVar9 != 0xffffffffffffffff) goto LAB_180005ccb;
          goto LAB_180005ccf;
        }
        *pbVar12 = bVar1;
        pbVar12 = pbVar12 + 1;
        uVar8 = uVar8 - 1;
      }
      lVar7 = lVar7 + 1;
    }
    iVar10 = -1;
LAB_180005d9c:
    lVar5 = *(longlong *)(this + 0x18);
    if ((lVar5 != *(longlong *)(this + 8)) &&
       ((lVar5 != *(longlong *)(this + 0x10) || (iVar10 != -1)))) {
      *(longlong *)(this + 0x18) = lVar5 + -1;
    }
LAB_180005db9:
    if ((lVar7 != 0) && (((param_1 != 0 || (lVar7 == lVar3)) || (((byte)*this & 4) != 0)))) {
      if (this[0x3a] == (input_processor<char,__crt_stdio_input::string_input_adapter<char>_>)0x0) {
        if (param_1 != 0) {
          *pbVar12 = 0;
        }
        *(longlong *)(this + 0x88) = *(longlong *)(this + 0x88) + 1;
      }
      return true;
    }
  }
  return false;
}



/* ---- process_string_specifier_tchar<wchar_t> @ 180005e08 ---- */

/* WARNING: Removing unreachable block (ram,0x000180005f1d) */
/* Library Function - Single Match
    private: bool __cdecl __crt_stdio_input::input_processor<char,class
   __crt_stdio_input::string_input_adapter<char> >::process_string_specifier_tchar<wchar_t>(enum
   __crt_stdio_input::conversion_mode,wchar_t) __ptr64
   
   Library: Visual Studio 2015 Release */

bool __thiscall
__crt_stdio_input::input_processor<char,__crt_stdio_input::string_input_adapter<char>_>::
process_string_specifier_tchar<wchar_t>
          (input_processor<char,__crt_stdio_input::string_input_adapter<char>_> *this,
          conversion_mode param_1,wchar_t param_2)

{
  byte bVar1;
  uint *puVar2;
  wchar_t *pwVar3;
  byte *pbVar4;
  longlong lVar5;
  ulong *puVar6;
  wchar_t *pwVar7;
  wchar_t *pwVar8;
  __uint64 _Var9;
  uint uVar10;
  __uint64 _Var11;
  bool bVar12;
  __uint64 local_res8;
  wchar_t *local_res20;
  
  pwVar7 = (wchar_t *)0x0;
  pwVar8 = pwVar7;
  if (this[0x3a] == (input_processor<char,__crt_stdio_input::string_input_adapter<char>_>)0x0) {
    *(longlong *)(this + 0x80) = *(longlong *)(this + 0x80) + 8;
    puVar2 = *(uint **)(this + 0x80);
    pwVar8 = *(wchar_t **)(puVar2 + -2);
    if (pwVar8 == (wchar_t *)0x0) {
      puVar6 = __doserrno();
      *puVar6 = 0x16;
      FUN_18000aff4();
      return false;
    }
    if (((byte)*this & 1) != 0) {
      *(uint **)(this + 0x80) = puVar2 + 2;
      _Var9 = (__uint64)*puVar2;
      goto LAB_180005e78;
    }
  }
  _Var9 = 0xffffffffffffffff;
LAB_180005e78:
  if (_Var9 == 0) {
    if (((byte)*this & 4) != 0) {
      if (*(longlong *)(this + 0x18) != *(longlong *)(this + 0x10)) {
        *(longlong *)(this + 0x18) = *(longlong *)(this + 0x18) + 1;
      }
LAB_180005e93:
      *pwVar8 = L'\0';
    }
LAB_180005e97:
    puVar6 = __doserrno();
    *puVar6 = 0xc;
  }
  else {
    pwVar3 = *(wchar_t **)(this + 0x40);
    _Var11 = _Var9;
    local_res8 = _Var9;
    local_res20 = pwVar8;
    if ((param_1 != 0) && (_Var9 != 0xffffffffffffffff)) {
      _Var11 = _Var9 - 1;
      local_res8 = _Var11;
    }
    while( true ) {
      if ((pwVar3 != (wchar_t *)0x0) && (pwVar7 == pwVar3)) goto LAB_180005fb8;
      pbVar4 = *(byte **)(this + 0x18);
      if (pbVar4 == *(byte **)(this + 0x10)) break;
      bVar1 = *pbVar4;
      uVar10 = (uint)(char)bVar1;
      *(byte **)(this + 0x18) = pbVar4 + 1;
      if (uVar10 == 0xffffffff) goto LAB_180005f9b;
      if (param_1 != 0) {
        if (param_1 == 1) {
          if (4 < uVar10 - 9) {
            bVar12 = uVar10 == 0x20;
            goto LAB_180005f48;
          }
        }
        else if (param_1 == 8) {
          bVar12 = ((byte)this[(((ulonglong)uVar10 & 0xff) >> 3) + 0x54] & (byte)(1 << (bVar1 & 7)))
                   == 0;
LAB_180005f48:
          if (!bVar12) goto LAB_180005f4a;
        }
        goto LAB_180005f9b;
      }
LAB_180005f4a:
      if (this[0x3a] == (input_processor<char,__crt_stdio_input::string_input_adapter<char>_>)0x0) {
        if (_Var11 == 0) {
          if (_Var9 != 0xffffffffffffffff) goto LAB_180005e93;
          goto LAB_180005e97;
        }
        bVar12 = write_character(this,pwVar8,_Var9,&local_res20,&local_res8,bVar1);
        _Var11 = local_res8;
        if (!bVar12) goto LAB_180005fb8;
      }
      pwVar7 = (wchar_t *)((longlong)pwVar7 + 1);
    }
    uVar10 = 0xffffffff;
LAB_180005f9b:
    lVar5 = *(longlong *)(this + 0x18);
    if ((lVar5 != *(longlong *)(this + 8)) &&
       ((lVar5 != *(longlong *)(this + 0x10) || (uVar10 != 0xffffffff)))) {
      *(longlong *)(this + 0x18) = lVar5 + -1;
    }
LAB_180005fb8:
    if ((pwVar7 != (wchar_t *)0x0) &&
       (((param_1 != 0 || (pwVar7 == pwVar3)) || (((byte)*this & 4) != 0)))) {
      if (this[0x3a] == (input_processor<char,__crt_stdio_input::string_input_adapter<char>_>)0x0) {
        if (param_1 != 0) {
          *local_res20 = L'\0';
        }
        *(longlong *)(this + 0x88) = *(longlong *)(this + 0x88) + 1;
      }
      return true;
    }
  }
  return false;
}



/* ---- skip_whitespace<__crt_stdio_input::string_input_adapter,char> @ 180006008 ---- */

/* Library Function - Single Match
    int __cdecl __crt_stdio_input::skip_whitespace<class
   __crt_stdio_input::string_input_adapter,char>(class __crt_stdio_input::string_input_adapter<char>
   & __ptr64,struct __crt_locale_pointers * __ptr64 const)
   
   Library: Visual Studio 2015 Release */

int __cdecl
__crt_stdio_input::skip_whitespace<__crt_stdio_input::string_input_adapter,char>
          (string_input_adapter<char> *param_1,__crt_locale_pointers *param_2)

{
  byte bVar1;
  ushort uVar2;
  byte *pbVar3;
  uint uVar4;
  ushort *puVar5;
  
  do {
    pbVar3 = *(byte **)(param_1 + 0x10);
    if (pbVar3 == *(byte **)(param_1 + 8)) {
      return -1;
    }
    bVar1 = *pbVar3;
    *(byte **)(param_1 + 0x10) = pbVar3 + 1;
    if ((char)bVar1 == -1) {
      return -1;
    }
    if (param_2 == (__crt_locale_pointers *)0x0) {
      puVar5 = __pctype_func();
      uVar2 = puVar5[bVar1];
LAB_180006072:
      uVar4 = uVar2 & 8;
    }
    else {
      if ((int)(*(longlong **)param_2)[1] < 2) {
        uVar2 = *(ushort *)(**(longlong **)param_2 + (longlong)(int)(uint)bVar1 * 2);
        goto LAB_180006072;
      }
      uVar4 = _isctype_l((uint)bVar1,8,(_locale_t)param_2);
    }
    if (uVar4 == 0) {
      return (int)(char)bVar1;
    }
  } while( true );
}



/* ---- operator() @ 180006098 ---- */

/* Library Function - Single Match
    public: bool __cdecl <lambda_5b936a367a2157d8f8fe79b470b291e7>::operator()(void)const __ptr64
   
   Library: Visual Studio 2015 Release */

bool __thiscall
<lambda_5b936a367a2157d8f8fe79b470b291e7>::operator()
          (<lambda_5b936a367a2157d8f8fe79b470b291e7> *this)

{
  char cVar1;
  longlong *plVar2;
  bool bVar3;
  
  cVar1 = **(char **)(this + 8);
  plVar2 = *(longlong **)this;
  plVar2[2] = plVar2[2] + -1;
  if (((plVar2[1] == 0) || ((ulonglong)plVar2[2] <= (ulonglong)plVar2[1])) &&
     (1 < (byte)(cVar1 + 1U))) {
    plVar2 = (longlong *)*plVar2;
    if (plVar2[2] != *plVar2) {
      plVar2[2] = plVar2[2] + -1;
    }
  }
  **(undefined1 **)(this + 8) = 0;
  bVar3 = **(longlong **)(this + 0x10) == *(longlong *)(*(longlong *)this + 0x10);
  if (!bVar3) {
    **(undefined1 **)(*(longlong *)this + 0x18) = 0;
  }
  return bVar3;
}



/* ---- advance @ 1800060f8 ---- */

/* Library Function - Single Match
    public: bool __cdecl __crt_stdio_input::format_string_parser<char>::advance(void) __ptr64
   
   Library: Visual Studio 2015 Release */

bool __thiscall
__crt_stdio_input::format_string_parser<char>::advance(format_string_parser<char> *this)

{
  format_string_parser<char> *pfVar1;
  char cVar2;
  format_string_parser<char> fVar3;
  format_string_parser<char> *pfVar4;
  bool bVar5;
  int iVar6;
  ushort *puVar7;
  
  if (*(int *)(this + 0x10) != 0) {
    return false;
  }
  *(undefined4 *)(this + 0x14) = 0;
  *(undefined2 *)(this + 0x18) = 0;
  this[0x1a] = (format_string_parser<char>)0x0;
  *(undefined8 *)(this + 0x20) = 0;
  *(undefined4 *)(this + 0x28) = 0;
  this[0x2c] = (format_string_parser<char>)0x0;
  *(undefined4 *)(this + 0x30) = 0;
  if (**(byte **)(this + 8) == 0) {
    *(undefined4 *)(this + 0x14) = 1;
    return false;
  }
  iVar6 = isspace((uint)**(byte **)(this + 8));
  if (iVar6 != 0) {
    *(undefined4 *)(this + 0x14) = 2;
    iVar6 = isspace((uint)**(byte **)(this + 8));
    while (iVar6 != 0) {
      *(longlong *)(this + 8) = *(longlong *)(this + 8) + 1;
      iVar6 = isspace((uint)**(byte **)(this + 8));
    }
    return true;
  }
  pfVar4 = *(format_string_parser<char> **)(this + 8);
  if ((*pfVar4 != (format_string_parser<char>)0x25) ||
     (pfVar1 = pfVar4 + 1, *pfVar1 == (format_string_parser<char>)0x25)) {
    *(undefined4 *)(this + 0x14) = 3;
    this[0x18] = *pfVar4;
    *(format_string_parser<char> **)(this + 8) =
         pfVar4 + (ulonglong)(*pfVar4 == (format_string_parser<char>)0x25) + 1;
    puVar7 = __pctype_func();
    if ((puVar7[(byte)this[0x18]] & 0x8000) == 0) {
      return true;
    }
    fVar3 = **(format_string_parser<char> **)(this + 8);
    if (fVar3 != (format_string_parser<char>)0x0) {
      this[0x19] = fVar3;
      *(format_string_parser<char> **)(this + 8) = *(format_string_parser<char> **)(this + 8) + 1;
      return true;
    }
    *(undefined8 *)(this + 0x10) = 0x2a;
    *(undefined2 *)(this + 0x18) = 0;
    this[0x1a] = (format_string_parser<char>)0x0;
    *(undefined8 *)(this + 0x20) = 0;
    *(undefined4 *)(this + 0x28) = 0;
    this[0x2c] = (format_string_parser<char>)0x0;
    *(undefined4 *)(this + 0x30) = 0;
    return false;
  }
  *(undefined4 *)(this + 0x14) = 4;
  *(format_string_parser<char> **)(this + 8) = pfVar1;
  if (*pfVar1 == (format_string_parser<char>)0x2a) {
    this[0x1a] = (format_string_parser<char>)0x1;
    *(format_string_parser<char> **)(this + 8) = pfVar4 + 2;
  }
  bVar5 = scan_optional_field_width(this);
  if (!bVar5) {
    return false;
  }
  scan_optional_length_modifier(this);
  cVar2 = **(char **)(this + 8);
  if (cVar2 == 'w') {
    *(char **)(this + 8) = *(char **)(this + 8) + 1;
  }
  else if ((cVar2 + 0xbdU & 0xef) != 0) goto LAB_1800061f3;
  this[0x2c] = (format_string_parser<char>)0x1;
LAB_1800061f3:
  bVar5 = scan_conversion_specifier(this);
  if (bVar5) {
    if ((&DAT_180013a10)[(longlong)*(int *)(this + 0x28) + (longlong)*(int *)(this + 0x30) * 0xc] !=
        '\0') {
      return true;
    }
    *(undefined8 *)(this + 0x10) = 0x16;
    *(undefined2 *)(this + 0x18) = 0;
    this[0x1a] = (format_string_parser<char>)0x0;
    *(undefined8 *)(this + 0x20) = 0;
    *(undefined4 *)(this + 0x28) = 0;
    this[0x2c] = (format_string_parser<char>)0x0;
    *(undefined4 *)(this + 0x30) = 0;
  }
  return false;
}



/* ---- FUN_1800062c8 @ 1800062c8 ---- */

undefined8 FUN_1800062c8(undefined8 *param_1)

{
  if (*(char *)(param_1 + 1) != '\0') {
    return *param_1;
  }
                    /* WARNING: Subroutine does not return */
  _invoke_watson(L"_is_double",L"__crt_strtox::floating_point_value::as_double",
                 L"minkernel\\crts\\ucrt\\inc\\corecrt_internal_strtox.h",0x19f,0);
}



/* ---- FUN_180006304 @ 180006304 ---- */

undefined8 FUN_180006304(undefined8 *param_1)

{
  if (*(char *)(param_1 + 1) == '\0') {
    return *param_1;
  }
                    /* WARNING: Subroutine does not return */
  _invoke_watson(L"!_is_double",L"__crt_strtox::floating_point_value::as_float",
                 L"minkernel\\crts\\ucrt\\inc\\corecrt_internal_strtox.h",0x1a5,0);
}



/* ---- assemble_floating_point_value @ 180006340 ---- */

/* Library Function - Single Match
    enum SLD_STATUS __cdecl __crt_strtox::assemble_floating_point_value(unsigned
   __int64,int,bool,bool,class __crt_strtox::floating_point_value const & __ptr64)
   
   Library: Visual Studio 2015 Release */

SLD_STATUS __cdecl
__crt_strtox::assemble_floating_point_value
          (__uint64 param_1,int param_2,bool param_3,bool param_4,floating_point_value *param_5)

{
  uint uVar1;
  ulonglong uVar2;
  int iVar3;
  uint uVar4;
  floating_point_value fVar5;
  bool bVar6;
  int iVar7;
  int iVar8;
  int iVar9;
  bool bVar10;
  bool bVar11;
  
  uVar2 = 0;
  iVar3 = 0;
  if (param_1 < 0x100000000) {
    iVar7 = 0x1f;
    uVar4 = (uint)param_1;
    if (uVar4 != 0) {
      for (; uVar4 >> iVar7 == 0; iVar7 = iVar7 + -1) {
      }
    }
    if (uVar4 != 0) {
      iVar3 = iVar7 + 1;
    }
  }
  else {
    iVar7 = 0x1f;
    uVar4 = (uint)(param_1 >> 0x20);
    if (uVar4 != 0) {
      for (; uVar4 >> iVar7 == 0; iVar7 = iVar7 + -1) {
      }
    }
    if (uVar4 != 0) {
      iVar3 = iVar7 + 1;
    }
    iVar3 = iVar3 + 0x20;
  }
  fVar5 = param_5[8];
  iVar3 = ((-(uint)(fVar5 != (floating_point_value)0x0) & 0x1d) + 0x18) - iVar3;
  iVar7 = param_2 - iVar3;
  iVar8 = (-(uint)(fVar5 != (floating_point_value)0x0) & 0x380) + 0x7f;
  if (iVar8 < iVar7) goto LAB_1800063d1;
  bVar6 = false;
  if (iVar7 < (int)((-(uint)(fVar5 != (floating_point_value)0x0) & 0xfffffc80) - 0x7e)) {
    iVar9 = iVar8 + iVar7;
    iVar7 = -iVar8;
    iVar9 = iVar3 + -1 + iVar9;
    if (iVar9 < 0) {
      uVar4 = -iVar9;
      if (0x3f < uVar4) goto LAB_180006547;
      uVar2 = 1L << ((byte)uVar4 - 1 & 0x3f);
      bVar11 = (param_1 & uVar2) != 0;
      if ((!param_4) || (bVar10 = bVar6, (param_1 & uVar2 - 1) != 0)) {
        bVar10 = true;
      }
      if ((bVar11) || (bVar10 != false)) {
        uVar1 = fegetround();
        if (uVar1 == 0) {
          if ((!bVar11) ||
             ((bVar11 = true, bVar10 == false && ((param_1 >> ((ulonglong)uVar4 & 0x3f) & 1) == 0)))
             ) goto LAB_1800064fd;
        }
        else if (uVar1 == 0x100) {
          bVar11 = !param_3;
        }
        else {
          bVar11 = param_3;
          if (uVar1 != 0x200) goto LAB_1800064fd;
        }
      }
      else {
LAB_1800064fd:
        bVar11 = bVar6;
      }
      param_1 = (param_1 >> ((byte)uVar4 & 0x3f)) + (ulonglong)bVar11;
      if (param_1 == 0) {
LAB_180006547:
        if (param_5[8] == (floating_point_value)0x0) {
          *(uint *)*(longlong **)param_5 = (uint)param_3 << 0x1f;
        }
        else {
          **(longlong **)param_5 = (ulonglong)param_3 << 0x3f;
        }
        return 2;
      }
      fVar5 = param_5[8];
      if ((-(ulonglong)(fVar5 != (floating_point_value)0x0) & 0xfffffff800000) + 0x7fffff < param_1)
      {
        iVar7 = ((param_2 - iVar9) - iVar3) + -1;
      }
      goto LAB_18000666f;
    }
  }
  else {
    if (iVar3 < 0) {
      uVar4 = -iVar3;
      if (uVar4 < 0x40) {
        uVar2 = 1L << ((byte)uVar4 - 1 & 0x3f);
        bVar11 = (param_1 & uVar2) != 0;
        if ((!param_4) || ((param_1 & uVar2 - 1) != 0)) {
          bVar6 = true;
        }
        if ((bVar11) || (bVar6 != false)) {
          uVar1 = fegetround();
          if (uVar1 == 0) {
            if ((!bVar11) ||
               ((uVar2 = 1, bVar6 == false && ((param_1 >> ((ulonglong)uVar4 & 0x3f) & 1) == 0))))
            goto LAB_18000660c;
          }
          else if (uVar1 == 0x100) {
            uVar2 = (ulonglong)!param_3;
          }
          else {
            uVar2 = (ulonglong)param_3;
            if (uVar1 != 0x200) goto LAB_18000660c;
          }
        }
        else {
LAB_18000660c:
          uVar2 = 0;
        }
        uVar2 = (param_1 >> ((byte)uVar4 & 0x3f)) + uVar2;
      }
      fVar5 = param_5[8];
      param_1 = uVar2;
      if ((-(ulonglong)(fVar5 != (floating_point_value)0x0) & 0x1fffffff000000) + 0xffffff < uVar2)
      {
        param_1 = uVar2 >> 1;
        iVar7 = iVar7 + 1;
        if ((int)((-(uint)(fVar5 != (floating_point_value)0x0) & 0x380) + 0x7f) < iVar7) {
LAB_1800063d1:
          if (fVar5 == (floating_point_value)0x0) {
            *(uint *)*(ulonglong **)param_5 = (uint)param_3 << 0x1f | 0x7f800000;
          }
          else {
            **(ulonglong **)param_5 = (ulonglong)param_3 << 0x3f | 0x7ff0000000000000;
          }
          return 3;
        }
      }
      goto LAB_18000666f;
    }
    iVar9 = iVar3;
    if (iVar3 < 1) goto LAB_18000666f;
  }
  param_1 = param_1 << ((byte)iVar9 & 0x3f);
LAB_18000666f:
  uVar2 = param_1 & (-(ulonglong)(fVar5 != (floating_point_value)0x0) & 0xfffffff800000) + 0x7fffff;
  if (fVar5 == (floating_point_value)0x0) {
    *(uint *)*(ulonglong **)param_5 =
         (iVar7 + 0x7f) * 0x800000 & 0x7f800000U | (uint)param_3 << 0x1f | (uint)uVar2 & 0x7fffff;
  }
  else {
    **(ulonglong **)param_5 =
         ((ulonglong)(iVar7 + 0x3ffU & 0x7ff) | (ulonglong)param_3 << 0xb) << 0x34 | uVar2;
  }
  return 0;
}



/* ---- assemble_floating_point_value_from_big_integer @ 1800066f4 ---- */

/* Library Function - Single Match
    enum SLD_STATUS __cdecl __crt_strtox::assemble_floating_point_value_from_big_integer(struct
   __crt_strtox::big_integer const & __ptr64,unsigned int,bool,bool,class
   __crt_strtox::floating_point_value const & __ptr64)
   
   Library: Visual Studio 2015 Release */

SLD_STATUS __cdecl
__crt_strtox::assemble_floating_point_value_from_big_integer
          (big_integer *param_1,uint param_2,bool param_3,bool param_4,floating_point_value *param_5
          )

{
  longlong lVar1;
  sbyte sVar2;
  undefined4 uVar3;
  SLD_STATUS SVar4;
  __uint64 _Var5;
  int iVar6;
  uint uVar7;
  undefined4 uVar8;
  uint uVar9;
  uint uVar10;
  uint uVar11;
  ulonglong uVar12;
  bool bVar13;
  
  iVar6 = (-(uint)(param_5[8] != (floating_point_value)0x0) & 0x1d) + 0x17;
  if (param_2 < 0x41) {
    if (*(int *)param_1 == 0) {
      uVar8 = 0;
    }
    else {
      uVar8 = *(undefined4 *)(param_1 + 4);
    }
    if (*(uint *)param_1 < 2) {
      uVar3 = 0;
    }
    else {
      uVar3 = *(undefined4 *)(param_1 + 8);
    }
    bVar13 = !param_4;
    _Var5 = CONCAT44(uVar3,uVar8);
  }
  else {
    uVar11 = param_2 >> 5;
    uVar9 = uVar11 - 2;
    uVar10 = param_2 & 0x1f;
    if (uVar10 == 0) {
      iVar6 = uVar9 * 0x20 + iVar6;
      _Var5 = CONCAT44(*(undefined4 *)(param_1 + (ulonglong)(uVar11 - 1) * 4 + 4),
                       *(undefined4 *)(param_1 + (ulonglong)uVar9 * 4 + 4));
      bVar13 = !param_4;
      uVar12 = 0;
      if (uVar9 != 0) {
        do {
          lVar1 = uVar12 * 4;
          uVar10 = (int)uVar12 + 1;
          uVar12 = (ulonglong)uVar10;
          bVar13 = (bool)(bVar13 & *(int *)(param_1 + lVar1 + 4) == 0);
        } while (uVar10 != uVar9);
      }
    }
    else {
      sVar2 = (sbyte)uVar10;
      uVar7 = (1 << sVar2) - 1;
      iVar6 = uVar9 * 0x20 + uVar10 + iVar6;
      _Var5 = ((ulonglong)*(uint *)(param_1 + (ulonglong)(uVar11 - 1) * 4 + 4) <<
              (-sVar2 + 0x20U & 0x3f)) +
              ((ulonglong)(*(uint *)(param_1 + (ulonglong)uVar11 * 4 + 4) & uVar7) <<
              (-sVar2 + 0x40U & 0x3f)) +
              (ulonglong)((~uVar7 & *(uint *)(param_1 + (ulonglong)uVar9 * 4 + 4)) >> sVar2);
      if ((param_4) || ((uVar7 & *(uint *)(param_1 + (ulonglong)uVar9 * 4 + 4)) != 0)) {
        bVar13 = false;
      }
      else {
        bVar13 = true;
      }
      uVar12 = 0;
      if (uVar9 != 0) {
        do {
          lVar1 = uVar12 * 4;
          uVar10 = (int)uVar12 + 1;
          uVar12 = (ulonglong)uVar10;
          bVar13 = (bool)(bVar13 & *(int *)(param_1 + lVar1 + 4) == 0);
        } while (uVar10 != uVar9);
      }
    }
  }
  SVar4 = assemble_floating_point_value(_Var5,iVar6,param_3,bVar13,param_5);
  return SVar4;
}



/* ---- convert_decimal_string_to_floating_type_common @ 180006880 ---- */

/* WARNING: Function: __security_check_cookie replaced with injection: security_check_cookie */
/* Library Function - Single Match
    enum SLD_STATUS __cdecl __crt_strtox::convert_decimal_string_to_floating_type_common(struct
   __crt_strtox::floating_point_string const & __ptr64,class __crt_strtox::floating_point_value
   const & __ptr64)
   
   Library: Visual Studio 2015 Release */

SLD_STATUS __cdecl
__crt_strtox::convert_decimal_string_to_floating_type_common
          (floating_point_string *param_1,floating_point_value *param_2)

{
  floating_point_string fVar1;
  byte bVar2;
  int iVar3;
  bool bVar4;
  bool bVar5;
  uint uVar6;
  uint uVar7;
  uint uVar8;
  SLD_STATUS SVar9;
  floating_point_string *pfVar10;
  ulong *puVar11;
  longlong *plVar12;
  int *piVar13;
  __uint64 _Var14;
  byte bVar15;
  uint uVar16;
  uint uVar17;
  uint uVar18;
  uint uVar19;
  ulonglong uVar20;
  ulonglong uVar21;
  ulonglong uVar22;
  uint uVar23;
  uint *puVar24;
  longlong lVar25;
  uint uVar26;
  uint uVar27;
  uint *puVar28;
  uint uVar29;
  uint uVar30;
  floating_point_string *pfVar31;
  ulonglong uVar32;
  rsize_t rVar33;
  uint uVar34;
  floating_point_string *pfVar35;
  ulonglong uVar36;
  uint uVar37;
  ulonglong uVar38;
  ulonglong uVar39;
  int iVar40;
  uint uVar41;
  bool bVar42;
  bool bVar43;
  undefined1 auStackY_ba8 [32];
  uint local_b24 [115];
  uint local_958;
  uint local_954 [115];
  uint local_788;
  uint local_784 [115];
  uint local_5b8;
  undefined8 local_5b4;
  uint local_3e8;
  uint local_3e4 [115];
  uint local_218;
  uint local_214 [115];
  ulonglong local_48;
  
  local_48 = DAT_18001c000 ^ (ulonglong)auStackY_ba8;
  uVar16 = *(uint *)(param_1 + 4);
  uVar36 = 0;
  uVar26 = 0;
  uVar6 = (-(uint)(param_2[8] != (floating_point_value)0x0) & 0x1d) + 0x19;
  uVar19 = 0;
  local_958 = 0;
  uVar34 = *(uint *)param_1;
  if ((int)*(uint *)param_1 < 0) {
    uVar34 = uVar19;
  }
  uVar41 = 0;
  uVar39 = (ulonglong)uVar16;
  if (uVar34 < uVar16) {
    uVar39 = (ulonglong)uVar34;
  }
  uVar34 = uVar34 - (int)uVar39;
  pfVar31 = param_1 + uVar39 + 8;
  pfVar10 = param_1 + (ulonglong)uVar16 + 8;
  uVar16 = (int)pfVar10 - (int)pfVar31;
  pfVar35 = param_1 + 8;
  uVar38 = uVar36;
  uVar39 = uVar36;
  uVar22 = uVar36;
  if (pfVar35 != pfVar31) {
    do {
      uVar17 = (uint)uVar38;
      uVar29 = (uint)uVar39;
      uVar37 = uVar17;
      if ((uint)uVar39 == 9) {
        uVar39 = uVar36;
        uVar21 = uVar36;
        if ((uint)uVar22 != 0) {
          do {
            uVar29 = (int)uVar21 + 1;
            uVar20 = (ulonglong)local_954[uVar21] * 1000000000 + uVar39;
            local_954[uVar21] = (uint)uVar20;
            uVar39 = uVar20 >> 0x20;
            uVar21 = (ulonglong)uVar29;
          } while (uVar29 != (uint)uVar22);
          uVar29 = (uint)(uVar20 >> 0x20);
          if (uVar29 == 0) {
            uVar22 = (ulonglong)local_958;
          }
          else if (local_958 < 0x73) {
            local_954[local_958] = uVar29;
            local_958 = local_958 + 1;
            uVar22 = (ulonglong)local_958;
          }
          else {
            local_958 = 0;
            uVar22 = uVar36;
          }
        }
        uVar29 = uVar41;
        uVar37 = uVar19;
        if (uVar17 != 0) {
          uVar39 = uVar36;
          if ((int)uVar22 != 0) {
            do {
              uVar27 = (int)uVar39 + 1;
              uVar21 = local_954[uVar39] + uVar38;
              local_954[uVar39] = (uint)uVar21;
              uVar22 = (ulonglong)local_958;
              uVar38 = uVar21 >> 0x20;
              uVar17 = (uint)(uVar21 >> 0x20);
              uVar39 = (ulonglong)uVar27;
            } while (uVar27 != local_958);
          }
          if (uVar17 != 0) {
            if ((uint)uVar22 < 0x73) {
              local_954[uVar22] = uVar17;
              local_958 = local_958 + 1;
              uVar22 = (ulonglong)local_958;
            }
            else {
              local_958 = 0;
              uVar22 = uVar36;
            }
          }
        }
      }
      fVar1 = *pfVar35;
      uVar29 = uVar29 + 1;
      uVar39 = (ulonglong)uVar29;
      pfVar35 = pfVar35 + 1;
      uVar37 = (uint)(byte)fVar1 + uVar37 * 10;
      uVar38 = (ulonglong)uVar37;
    } while (pfVar35 != pfVar31);
    if (uVar29 != 0) {
      uVar39 = uVar39 / 10;
      uVar27 = (uint)uVar39;
      uVar17 = uVar27;
      while (uVar23 = (uint)uVar22, uVar17 != 0) {
        uVar18 = (uint)uVar39;
        if (0x26 < (uint)uVar39) {
          uVar18 = 0x26;
        }
        uVar7 = uVar18 - 1;
        bVar15 = (&DAT_1800137e2)[(ulonglong)uVar7 * 4];
        bVar2 = (&DAT_1800137e3)[(ulonglong)uVar7 * 4];
        local_3e8 = (uint)bVar2 + (uint)bVar15;
        FUN_180003320((undefined1 (*) [16])local_3e4,0,(ulonglong)bVar15 * 4);
        FUN_180002ed0((undefined8 *)(local_3e4 + bVar15),
                      (undefined8 *)
                      (&DAT_180012ed0 +
                      (ulonglong)*(ushort *)(&DAT_1800137e0 + (ulonglong)uVar7 * 4) * 4),
                      (ulonglong)bVar2 << 2);
        uVar7 = local_954[0];
        uVar39 = (ulonglong)local_3e8;
        if (local_3e8 < 2) {
          uVar39 = (ulonglong)local_3e4[0];
          if (local_3e4[0] == 0) {
LAB_180006b01:
            local_958 = 0;
            uVar22 = uVar36;
            goto LAB_180006e25;
          }
          if ((local_3e4[0] == 1) || (uVar21 = uVar36, uVar20 = uVar36, uVar23 == 0))
          goto LAB_180006e25;
          do {
            uVar8 = (int)uVar20 + 1;
            uVar21 = local_954[uVar20] * uVar39 + uVar21;
            local_954[uVar20] = (uint)uVar21;
            uVar7 = (uint)(uVar21 >> 0x20);
            uVar21 = uVar21 >> 0x20;
            uVar20 = (ulonglong)uVar8;
          } while (uVar8 != uVar23);
LAB_180006b55:
          if (uVar7 == 0) goto LAB_180006e1e;
          if (local_958 < 0x73) {
            local_954[local_958] = uVar7;
            local_958 = local_958 + 1;
            uVar22 = (ulonglong)local_958;
            goto LAB_180006e25;
          }
          local_958 = 0;
          bVar43 = false;
          uVar22 = uVar36;
        }
        else {
          if (uVar23 < 2) {
            uVar21 = (ulonglong)local_954[0];
            local_958 = local_3e8;
            uVar22 = uVar39;
            if (uVar39 != 0) {
              if (uVar39 << 2 < 0x1cd) {
                FUN_180002ed0((undefined8 *)local_954,(undefined8 *)local_3e4,uVar39 << 2);
              }
              else {
                FUN_180003320((undefined1 (*) [16])local_954,0,0x1cc);
                puVar11 = __doserrno();
                *puVar11 = 0x22;
                FUN_18000aff4();
              }
              uVar22 = (ulonglong)local_958;
            }
            if (uVar7 == 0) goto LAB_180006b01;
            if ((uVar7 != 1) && (uVar39 = uVar36, uVar20 = uVar36, (uint)uVar22 != 0)) {
              do {
                uVar23 = (int)uVar20 + 1;
                uVar39 = local_954[uVar20] * uVar21 + uVar39;
                local_954[uVar20] = (uint)uVar39;
                uVar7 = (uint)(uVar39 >> 0x20);
                uVar39 = uVar39 >> 0x20;
                uVar20 = (ulonglong)uVar23;
              } while (uVar23 != (uint)uVar22);
              goto LAB_180006b55;
            }
          }
          else {
            local_5b8 = 0;
            puVar28 = local_954;
            puVar24 = local_3e4;
            uVar7 = local_3e8;
            if (local_3e8 < uVar23) {
              uVar7 = uVar23;
              uVar22 = uVar39;
              puVar24 = local_954;
              puVar28 = local_3e4;
            }
            uVar21 = uVar36;
            uVar39 = uVar36;
            if ((uint)uVar22 != 0) {
              do {
                uVar8 = (uint)uVar21;
                uVar23 = puVar28[uVar21];
                if (uVar23 == 0) {
                  if (uVar8 == (uint)uVar39) {
                    uVar39 = (ulonglong)(uVar8 + 1);
                    *(undefined4 *)((longlong)&local_5b4 + uVar21 * 4) = 0;
                    local_5b8 = uVar8 + 1;
                  }
                }
                else {
                  uVar30 = uVar8;
                  if (uVar7 != 0) {
                    uVar20 = uVar36;
                    do {
                      iVar40 = (int)uVar21;
                      uVar32 = uVar21;
                      if (iVar40 == 0x73) break;
                      if (iVar40 == (int)uVar39) {
                        *(undefined4 *)((longlong)&local_5b4 + uVar21 * 4) = 0;
                        local_5b8 = iVar40 + 1;
                      }
                      uVar32 = (ulonglong)(iVar40 + 1U);
                      uVar20 = (ulonglong)puVar24[-uVar8 + iVar40] * (ulonglong)uVar23 + uVar20 +
                               (ulonglong)*(uint *)((longlong)&local_5b4 + uVar21 * 4);
                      *(int *)((longlong)&local_5b4 + uVar21 * 4) = (int)uVar20;
                      uVar39 = (ulonglong)local_5b8;
                      uVar20 = uVar20 >> 0x20;
                      uVar21 = uVar32;
                    } while (-uVar8 + iVar40 + 1U != uVar7);
                    uVar30 = (uint)uVar32;
                    uVar23 = (uint)uVar20;
                    while (uVar23 != 0) {
                      iVar40 = (int)uVar32;
                      if (iVar40 == 0x73) goto LAB_180006e6c;
                      if (iVar40 == (int)uVar39) {
                        *(undefined4 *)((longlong)&local_5b4 + uVar32 * 4) = 0;
                        local_5b8 = iVar40 + 1;
                      }
                      uVar30 = iVar40 + 1;
                      lVar25 = uVar20 + *(uint *)((longlong)&local_5b4 + uVar32 * 4);
                      *(int *)((longlong)&local_5b4 + uVar32 * 4) = (int)lVar25;
                      uVar39 = (ulonglong)local_5b8;
                      uVar23 = (uint)((ulonglong)lVar25 >> 0x20);
                      uVar20 = (ulonglong)uVar23;
                      uVar32 = (ulonglong)uVar30;
                    }
                  }
                  if (uVar30 == 0x73) goto LAB_180006e6c;
                }
                uVar21 = (ulonglong)(uVar8 + 1);
              } while (uVar8 + 1 != (uint)uVar22);
            }
            local_958 = (uint)uVar39;
            uVar22 = 0;
            if (uVar39 != 0) {
              if (uVar39 << 2 < 0x1cd) {
                FUN_180002ed0((undefined8 *)local_954,&local_5b4,uVar39 << 2);
              }
              else {
                FUN_180003320((undefined1 (*) [16])local_954,0,0x1cc);
                puVar11 = __doserrno();
                *puVar11 = 0x22;
                FUN_18000aff4();
              }
LAB_180006e1e:
              uVar22 = (ulonglong)local_958;
            }
          }
LAB_180006e25:
          bVar43 = true;
        }
        if (!bVar43) goto LAB_180006e6c;
        uVar17 = uVar17 - uVar18;
        uVar39 = (ulonglong)uVar17;
      }
      iVar40 = uVar29 + uVar27 * -10;
      if (iVar40 != 0) {
        uVar29 = *(uint *)(&DAT_180013878 + (ulonglong)(iVar40 - 1) * 4);
        if (uVar29 == 0) {
LAB_180006e6c:
          local_958 = 0;
          uVar22 = uVar36;
        }
        else if ((uVar29 != 1) && (uVar39 = uVar36, uVar21 = uVar36, uVar23 != 0)) {
          do {
            uVar17 = (int)uVar21 + 1;
            uVar22 = (ulonglong)local_954[uVar21] * (ulonglong)uVar29 + uVar39;
            local_954[uVar21] = (uint)uVar22;
            uVar39 = uVar22 >> 0x20;
            uVar21 = (ulonglong)uVar17;
          } while (uVar17 != uVar23);
          uVar29 = (uint)(uVar22 >> 0x20);
          if (uVar29 == 0) {
            uVar22 = (ulonglong)local_958;
          }
          else {
            if (0x72 < local_958) goto LAB_180006e6c;
            local_954[local_958] = uVar29;
            local_958 = local_958 + 1;
            uVar22 = (ulonglong)local_958;
          }
        }
      }
      if (uVar37 != 0) {
        uVar39 = uVar36;
        if ((int)uVar22 != 0) {
          do {
            uVar29 = (int)uVar39 + 1;
            uVar21 = local_954[uVar39] + uVar38;
            local_954[uVar39] = (uint)uVar21;
            uVar22 = (ulonglong)local_958;
            uVar38 = uVar21 >> 0x20;
            uVar37 = (uint)(uVar21 >> 0x20);
            uVar39 = (ulonglong)uVar29;
          } while (uVar29 != local_958);
        }
        if (uVar37 != 0) {
          if ((uint)uVar22 < 0x73) {
            local_954[uVar22] = uVar37;
            local_958 = local_958 + 1;
            uVar22 = (ulonglong)local_958;
          }
          else {
            uVar22 = 0;
            local_958 = 0;
          }
        }
      }
    }
  }
  uVar29 = (uint)uVar22;
  uVar37 = uVar41;
  if (uVar34 == 0) {
LAB_180007480:
    if (uVar29 != 0) {
      iVar40 = 0x1f;
      bVar43 = local_954[uVar29 - 1] != 0;
      if (bVar43) {
        for (; local_954[uVar29 - 1] >> iVar40 == 0; iVar40 = iVar40 + -1) {
        }
      }
      uVar34 = uVar41;
      if (bVar43) {
        uVar34 = iVar40 + 1;
      }
      uVar37 = (uVar29 - 1) * 0x20 + uVar34;
    }
  }
  else {
    uVar39 = (ulonglong)uVar34 / 10;
    uVar27 = (uint)uVar39;
    uVar17 = uVar27;
    while (uVar17 != 0) {
      uVar23 = (uint)uVar39;
      uVar18 = uVar23;
      if (0x26 < uVar23) {
        uVar18 = 0x26;
      }
      uVar29 = uVar18 - 1;
      bVar15 = (&DAT_1800137e2)[(ulonglong)uVar29 * 4];
      bVar2 = (&DAT_1800137e3)[(ulonglong)uVar29 * 4];
      local_3e8 = (uint)bVar2 + (uint)bVar15;
      FUN_180003320((undefined1 (*) [16])local_3e4,0,(ulonglong)bVar15 * 4);
      FUN_180002ed0((undefined8 *)(local_3e4 + bVar15),
                    (undefined8 *)
                    (&DAT_180012ed0 +
                    (ulonglong)*(ushort *)(&DAT_1800137e0 + (ulonglong)uVar29 * 4) * 4),
                    (ulonglong)bVar2 << 2);
      uVar7 = local_954[0];
      uVar29 = (uint)uVar22;
      if (local_3e8 < 2) {
        uVar39 = (ulonglong)local_3e4[0];
        if (local_3e4[0] == 0) {
LAB_180007036:
          local_958 = 0;
          uVar22 = uVar36;
          goto LAB_18000735c;
        }
        if ((local_3e4[0] == 1) || (uVar38 = uVar36, uVar21 = uVar36, uVar29 == 0))
        goto LAB_18000735c;
        do {
          uVar7 = (int)uVar21 + 1;
          uVar38 = local_954[uVar21] * uVar39 + uVar38;
          local_954[uVar21] = (uint)uVar38;
          uVar17 = (uint)(uVar38 >> 0x20);
          uVar38 = uVar38 >> 0x20;
          uVar21 = (ulonglong)uVar7;
        } while (uVar7 != uVar29);
LAB_18000708a:
        if (uVar17 == 0) {
          uVar22 = (ulonglong)local_958;
          goto LAB_18000735c;
        }
        if (local_958 < 0x73) {
          local_954[local_958] = uVar17;
          local_958 = local_958 + 1;
          uVar22 = (ulonglong)local_958;
          goto LAB_18000735c;
        }
        local_958 = 0;
        bVar43 = false;
        uVar22 = uVar36;
      }
      else {
        if (uVar29 < 2) {
          uVar39 = (ulonglong)local_954[0];
          uVar38 = (ulonglong)local_3e8 << 2;
          local_958 = local_3e8;
          uVar22 = 0;
          if ((ulonglong)local_3e8 != 0) {
            if (uVar38 < 0x1cd) {
              FUN_180002ed0((undefined8 *)local_954,(undefined8 *)local_3e4,uVar38);
            }
            else {
              FUN_180003320((undefined1 (*) [16])local_954,0,0x1cc);
              puVar11 = __doserrno();
              *puVar11 = 0x22;
              FUN_18000aff4();
            }
            uVar22 = (ulonglong)local_958;
          }
          if (uVar7 == 0) goto LAB_180007036;
          if ((uVar7 != 1) && (uVar38 = uVar36, uVar21 = uVar36, (uint)uVar22 != 0)) {
            do {
              uVar29 = (int)uVar21 + 1;
              uVar38 = local_954[uVar21] * uVar39 + uVar38;
              local_954[uVar21] = (uint)uVar38;
              uVar17 = (uint)(uVar38 >> 0x20);
              uVar38 = uVar38 >> 0x20;
              uVar21 = (ulonglong)uVar29;
            } while (uVar29 != (uint)uVar22);
            goto LAB_18000708a;
          }
        }
        else {
          local_5b8 = 0;
          puVar28 = local_954;
          puVar24 = local_3e4;
          uVar23 = local_3e8;
          if (local_3e8 < uVar29) {
            puVar24 = local_954;
            uVar23 = uVar29;
            uVar29 = local_3e8;
            puVar28 = local_3e4;
          }
          uVar38 = uVar36;
          uVar39 = uVar36;
          if (uVar29 != 0) {
            do {
              uVar8 = (uint)uVar38;
              uVar7 = puVar28[uVar38];
              if (uVar7 == 0) {
                if (uVar8 == (uint)uVar39) {
                  uVar39 = (ulonglong)(uVar8 + 1);
                  *(undefined4 *)((longlong)&local_5b4 + uVar38 * 4) = 0;
                  local_5b8 = uVar8 + 1;
                }
              }
              else {
                uVar30 = uVar8;
                if (uVar23 != 0) {
                  uVar22 = uVar36;
                  do {
                    iVar40 = (int)uVar38;
                    uVar21 = uVar38;
                    if (iVar40 == 0x73) break;
                    if (iVar40 == (int)uVar39) {
                      *(undefined4 *)((longlong)&local_5b4 + uVar38 * 4) = 0;
                      local_5b8 = iVar40 + 1;
                    }
                    uVar21 = (ulonglong)(iVar40 + 1U);
                    uVar22 = (ulonglong)puVar24[iVar40 + -uVar8] * (ulonglong)uVar7 + uVar22 +
                             (ulonglong)*(uint *)((longlong)&local_5b4 + uVar38 * 4);
                    *(int *)((longlong)&local_5b4 + uVar38 * 4) = (int)uVar22;
                    uVar39 = (ulonglong)local_5b8;
                    uVar22 = uVar22 >> 0x20;
                    uVar38 = uVar21;
                  } while (iVar40 + 1U + -uVar8 != uVar23);
                  uVar30 = (uint)uVar21;
                  uVar7 = (uint)uVar22;
                  while (uVar7 != 0) {
                    iVar40 = (int)uVar21;
                    if (iVar40 == 0x73) goto LAB_180007425;
                    if (iVar40 == (int)uVar39) {
                      *(undefined4 *)((longlong)&local_5b4 + uVar21 * 4) = 0;
                      local_5b8 = iVar40 + 1;
                    }
                    uVar30 = iVar40 + 1;
                    lVar25 = uVar22 + *(uint *)((longlong)&local_5b4 + uVar21 * 4);
                    *(int *)((longlong)&local_5b4 + uVar21 * 4) = (int)lVar25;
                    uVar39 = (ulonglong)local_5b8;
                    uVar7 = (uint)((ulonglong)lVar25 >> 0x20);
                    uVar22 = (ulonglong)uVar7;
                    uVar21 = (ulonglong)uVar30;
                  }
                }
                if (uVar30 == 0x73) goto LAB_180007425;
              }
              uVar38 = (ulonglong)(uVar8 + 1);
            } while (uVar8 + 1 != uVar29);
          }
          local_958 = (uint)uVar39;
          uVar22 = 0;
          uVar23 = uVar17;
          if (uVar39 != 0) {
            if (uVar39 << 2 < 0x1cd) {
              FUN_180002ed0((undefined8 *)local_954,&local_5b4,uVar39 << 2);
            }
            else {
              FUN_180003320((undefined1 (*) [16])local_954,0,0x1cc);
              puVar11 = __doserrno();
              *puVar11 = 0x22;
              FUN_18000aff4();
            }
            uVar22 = (ulonglong)local_958;
          }
        }
LAB_18000735c:
        bVar43 = true;
      }
      uVar29 = (uint)uVar22;
      if (!bVar43) goto LAB_180007425;
      uVar17 = uVar23 - uVar18;
      uVar39 = (ulonglong)uVar17;
    }
    iVar40 = uVar34 + uVar27 * -10;
    if (iVar40 == 0) goto LAB_180007480;
    uVar34 = *(uint *)(&DAT_180013878 + (ulonglong)(iVar40 - 1) * 4);
    if (uVar34 != 0) {
      if (uVar34 != 1) {
        uVar39 = uVar36;
        uVar38 = uVar36;
        if (uVar29 == 0) goto LAB_1800074a9;
        do {
          uVar17 = (int)uVar38 + 1;
          uVar22 = (ulonglong)local_954[uVar38] * (ulonglong)uVar34 + uVar39;
          local_954[uVar38] = (uint)uVar22;
          uVar39 = uVar22 >> 0x20;
          uVar38 = (ulonglong)uVar17;
        } while (uVar17 != uVar29);
        uVar34 = (uint)(uVar22 >> 0x20);
        uVar29 = local_958;
        if (uVar34 != 0) {
          if (0x72 < local_958) {
LAB_180007425:
            if (param_2[8] == (floating_point_value)0x0) {
              *(uint *)*(ulonglong **)param_2 =
                   (uint)(param_1[0x308] != (floating_point_string)0x0) << 0x1f | 0x7f800000;
            }
            else {
              **(ulonglong **)param_2 =
                   (ulonglong)(param_1[0x308] != (floating_point_string)0x0) << 0x3f |
                   0x7ff0000000000000;
            }
            return 3;
          }
          local_954[local_958] = uVar34;
          local_958 = local_958 + 1;
          uVar29 = local_958;
        }
      }
      goto LAB_180007480;
    }
    local_958 = 0;
    uVar29 = uVar26;
  }
LAB_1800074a9:
  if ((uVar37 < uVar6) && (uVar16 != 0)) {
    local_788 = 0;
    uVar22 = uVar36;
    uVar39 = uVar36;
    uVar38 = uVar36;
    if (pfVar31 != pfVar10) {
      do {
        uVar27 = (uint)uVar39;
        uVar34 = (uint)uVar22;
        uVar17 = uVar27;
        if ((uint)uVar22 == 9) {
          uVar22 = uVar36;
          uVar21 = uVar36;
          if ((uint)uVar38 != 0) {
            do {
              uVar34 = (int)uVar21 + 1;
              uVar20 = (ulonglong)local_784[uVar21] * 1000000000 + uVar22;
              local_784[uVar21] = (uint)uVar20;
              uVar22 = uVar20 >> 0x20;
              uVar21 = (ulonglong)uVar34;
            } while (uVar34 != (uint)uVar38);
            uVar34 = (uint)(uVar20 >> 0x20);
            if (uVar34 != 0) {
              if (local_788 < 0x73) {
                local_784[local_788] = uVar34;
                uVar38 = (ulonglong)(local_788 + 1);
                local_788 = local_788 + 1;
                goto LAB_18000758d;
              }
              local_218 = 0;
              local_788 = 0;
              memcpy_s(local_784,0x1cc,local_214,0);
            }
            uVar38 = (ulonglong)local_788;
          }
LAB_18000758d:
          uVar34 = uVar41;
          uVar17 = uVar19;
          if (uVar27 != 0) {
            uVar22 = uVar36;
            if ((int)uVar38 != 0) {
              do {
                uVar23 = (int)uVar22 + 1;
                uVar21 = uVar39 + local_784[uVar22];
                local_784[uVar22] = (uint)uVar21;
                uVar38 = (ulonglong)local_788;
                uVar39 = uVar21 >> 0x20;
                uVar27 = (uint)(uVar21 >> 0x20);
                uVar22 = (ulonglong)uVar23;
              } while (uVar23 != local_788);
            }
            if (uVar27 != 0) {
              if ((uint)uVar38 < 0x73) {
                local_784[uVar38] = uVar27;
                uVar38 = (ulonglong)(local_788 + 1);
                local_788 = local_788 + 1;
              }
              else {
                local_218 = 0;
                local_788 = 0;
                memcpy_s(local_784,0x1cc,local_214,0);
                uVar38 = (ulonglong)local_788;
              }
            }
          }
        }
        fVar1 = *pfVar31;
        uVar34 = uVar34 + 1;
        uVar22 = (ulonglong)uVar34;
        pfVar31 = pfVar31 + 1;
        uVar17 = (uint)(byte)fVar1 + uVar17 * 10;
        uVar39 = (ulonglong)uVar17;
      } while (pfVar31 != pfVar10);
      if (uVar34 != 0) {
        uVar22 = (ulonglong)uVar34 / 10;
        uVar27 = (uint)uVar22;
        uVar19 = uVar27;
        while (uVar23 = (uint)uVar38, uVar19 != 0) {
          uVar18 = (uint)uVar22;
          if (0x26 < uVar18) {
            uVar18 = 0x26;
          }
          uVar22 = (ulonglong)(uVar18 - 1);
          bVar15 = (&DAT_1800137e2)[uVar22 * 4];
          bVar2 = (&DAT_1800137e3)[uVar22 * 4];
          local_3e8 = (uint)bVar2 + (uint)bVar15;
          FUN_180003320((undefined1 (*) [16])local_3e4,0,(ulonglong)bVar15 * 4);
          FUN_180002ed0((undefined8 *)(local_3e4 + bVar15),
                        (undefined8 *)
                        (&DAT_180012ed0 + (ulonglong)*(ushort *)(&DAT_1800137e0 + uVar22 * 4) * 4),
                        (ulonglong)bVar2 << 2);
          uVar7 = local_784[0];
          if (local_3e8 < 2) {
            uVar22 = (ulonglong)local_3e4[0];
            if (local_3e4[0] == 0) {
LAB_180007700:
              local_218 = 0;
              puVar28 = local_214;
              local_788 = 0;
              rVar33 = 0;
              goto LAB_180007996;
            }
            if ((local_3e4[0] == 1) || (uVar21 = uVar36, uVar20 = uVar36, uVar23 == 0))
            goto LAB_1800079ae;
            do {
              uVar7 = (int)uVar20 + 1;
              uVar21 = local_784[uVar20] * uVar22 + uVar21;
              local_784[uVar20] = (uint)uVar21;
              uVar8 = (uint)(uVar21 >> 0x20);
              uVar21 = uVar21 >> 0x20;
              uVar20 = (ulonglong)uVar7;
            } while (uVar7 != uVar23);
LAB_180007762:
            if (uVar8 == 0) goto LAB_1800079a7;
            if (local_788 < 0x73) {
              local_784[local_788] = uVar8;
              uVar38 = (ulonglong)(local_788 + 1);
              local_788 = local_788 + 1;
              goto LAB_1800079ae;
            }
LAB_180007a73:
            local_218 = 0;
            local_788 = 0;
            memcpy_s(local_784,0x1cc,local_214,0);
            uVar38 = (ulonglong)local_788;
            bVar43 = false;
          }
          else {
            puVar28 = local_3e4;
            puVar24 = local_784;
            if (uVar23 < 2) {
              local_788 = local_3e8;
              memcpy_s(puVar24,0x1cc,puVar28,(ulonglong)local_3e8 << 2);
              if (uVar7 != 0) {
                uVar38 = (ulonglong)local_788;
                if ((uVar7 != 1) && (local_788 != 0)) {
                  uVar38 = uVar36;
                  uVar22 = uVar36;
                  do {
                    uVar23 = (int)uVar22 + 1;
                    uVar21 = (ulonglong)local_784[uVar22] * (ulonglong)uVar7 + uVar38;
                    local_784[uVar22] = (uint)uVar21;
                    uVar38 = uVar21 >> 0x20;
                    uVar8 = (uint)(uVar21 >> 0x20);
                    uVar22 = (ulonglong)uVar23;
                  } while (uVar23 != local_788);
                  goto LAB_180007762;
                }
                goto LAB_1800079ae;
              }
              goto LAB_180007700;
            }
            local_5b8 = 0;
            uVar7 = local_3e8;
            if (local_3e8 < uVar23) {
              uVar7 = uVar23;
              uVar38 = (ulonglong)local_3e8;
              puVar28 = local_784;
              puVar24 = local_3e4;
            }
            uVar22 = uVar36;
            uVar21 = uVar36;
            local_788 = uVar41;
            if ((uint)uVar38 != 0) {
              do {
                uVar8 = (uint)uVar21;
                uVar23 = puVar24[uVar21];
                if (uVar23 == 0) {
                  if (uVar8 == (uint)uVar22) {
                    uVar22 = (ulonglong)(uVar8 + 1);
                    *(undefined4 *)((longlong)&local_5b4 + uVar21 * 4) = 0;
                    local_5b8 = uVar8 + 1;
                  }
                }
                else {
                  uVar30 = uVar8;
                  if (uVar7 != 0) {
                    uVar20 = uVar36;
                    do {
                      iVar40 = (int)uVar21;
                      uVar32 = uVar21;
                      if (iVar40 == 0x73) break;
                      if (iVar40 == (int)uVar22) {
                        *(undefined4 *)((longlong)&local_5b4 + uVar21 * 4) = 0;
                        local_5b8 = iVar40 + 1;
                      }
                      uVar32 = (ulonglong)(iVar40 + 1U);
                      uVar20 = (ulonglong)puVar28[-uVar8 + iVar40] * (ulonglong)uVar23 +
                               (ulonglong)*(uint *)((longlong)&local_5b4 + uVar21 * 4) + uVar20;
                      *(int *)((longlong)&local_5b4 + uVar21 * 4) = (int)uVar20;
                      uVar20 = uVar20 >> 0x20;
                      uVar22 = (ulonglong)local_5b8;
                      uVar21 = uVar32;
                    } while (-uVar8 + iVar40 + 1U != uVar7);
                    uVar30 = (uint)uVar32;
                    uVar23 = (uint)uVar20;
                    while ((uVar23 != 0 && (uVar30 = (uint)uVar32, uVar30 != 0x73))) {
                      if (uVar30 == (uint)uVar22) {
                        *(undefined4 *)((longlong)&local_5b4 + uVar32 * 4) = 0;
                        local_5b8 = uVar30 + 1;
                      }
                      uVar30 = uVar30 + 1;
                      lVar25 = *(uint *)((longlong)&local_5b4 + uVar32 * 4) + uVar20;
                      *(int *)((longlong)&local_5b4 + uVar32 * 4) = (int)lVar25;
                      uVar22 = (ulonglong)local_5b8;
                      uVar23 = (uint)((ulonglong)lVar25 >> 0x20);
                      uVar20 = (ulonglong)uVar23;
                      uVar32 = (ulonglong)uVar30;
                    }
                  }
                  if (uVar30 == 0x73) goto LAB_180007a73;
                }
                local_788 = (uint)uVar22;
                uVar21 = (ulonglong)(uVar8 + 1);
              } while (uVar8 + 1 != (uint)uVar38);
            }
            puVar28 = (uint *)&local_5b4;
            rVar33 = (ulonglong)local_788 << 2;
LAB_180007996:
            memcpy_s(local_784,0x1cc,puVar28,rVar33);
LAB_1800079a7:
            uVar38 = (ulonglong)local_788;
LAB_1800079ae:
            bVar43 = true;
          }
          if (!bVar43) goto LAB_180007aab;
          uVar19 = uVar19 - uVar18;
          uVar22 = (ulonglong)uVar19;
        }
        iVar40 = uVar34 + uVar27 * -10;
        if (iVar40 != 0) {
          uVar34 = *(uint *)(&DAT_180013878 + (ulonglong)(iVar40 - 1) * 4);
          if (uVar34 == 0) {
LAB_180007aab:
            local_218 = 0;
            local_788 = 0;
            memcpy_s(local_784,0x1cc,local_214,0);
LAB_180007ad4:
            uVar38 = (ulonglong)local_788;
          }
          else if ((uVar34 != 1) && (uVar23 != 0)) {
            uVar38 = uVar36;
            uVar22 = uVar36;
            do {
              uVar19 = (int)uVar22 + 1;
              uVar21 = (ulonglong)local_784[uVar22] * (ulonglong)uVar34 + uVar38;
              local_784[uVar22] = (uint)uVar21;
              uVar38 = uVar21 >> 0x20;
              uVar22 = (ulonglong)uVar19;
            } while (uVar19 != uVar23);
            uVar34 = (uint)(uVar21 >> 0x20);
            if (uVar34 == 0) goto LAB_180007ad4;
            if (0x72 < local_788) goto LAB_180007aab;
            local_784[local_788] = uVar34;
            uVar38 = (ulonglong)(local_788 + 1);
            local_788 = local_788 + 1;
          }
        }
        if (uVar17 != 0) {
          uVar22 = uVar36;
          if ((int)uVar38 != 0) {
            do {
              uVar34 = (int)uVar22 + 1;
              uVar21 = local_784[uVar22] + uVar39;
              local_784[uVar22] = (uint)uVar21;
              uVar38 = (ulonglong)local_788;
              uVar39 = uVar21 >> 0x20;
              uVar17 = (uint)(uVar21 >> 0x20);
              uVar22 = (ulonglong)uVar34;
            } while (uVar34 != local_788);
          }
          if (uVar17 != 0) {
            if ((uint)uVar38 < 0x73) {
              local_784[uVar38] = uVar17;
              uVar38 = (ulonglong)(local_788 + 1);
              local_788 = local_788 + 1;
            }
            else {
              local_218 = 0;
              local_788 = 0;
              memcpy_s(local_784,0x1cc,local_214,0);
              uVar38 = (ulonglong)local_788;
            }
          }
        }
      }
    }
    if (*(int *)param_1 < 0) {
      uVar16 = uVar16 - *(int *)param_1;
    }
    uVar34 = 1;
    local_5b4 = 1;
    local_5b8 = 1;
    uVar39 = (ulonglong)uVar16 / 10;
    uVar19 = uVar16 / 10;
    bVar43 = false;
    bVar4 = false;
    while (uVar19 != 0) {
      uVar17 = (uint)uVar39;
      if (0x26 < uVar17) {
        uVar17 = 0x26;
      }
      uVar39 = (ulonglong)(uVar17 - 1);
      bVar15 = (&DAT_1800137e2)[uVar39 * 4];
      bVar2 = (&DAT_1800137e3)[uVar39 * 4];
      local_218 = (uint)bVar2 + (uint)bVar15;
      FUN_180003320((undefined1 (*) [16])local_214,0,(ulonglong)bVar15 * 4);
      FUN_180002ed0((undefined8 *)(local_214 + bVar15),
                    (undefined8 *)
                    (&DAT_180012ed0 + (ulonglong)*(ushort *)(&DAT_1800137e0 + uVar39 * 4) * 4),
                    (ulonglong)bVar2 << 2);
      if (local_218 < 2) {
        uVar39 = (ulonglong)local_214[0];
        if (local_214[0] == 0) {
          local_3e8 = 0;
          local_5b8 = 0;
          memcpy_s(&local_5b4,0x1cc,local_3e4,0);
          uVar34 = local_5b8;
        }
        else if ((local_214[0] != 1) && (uVar22 = uVar36, uVar21 = uVar36, uVar34 != 0)) {
          do {
            uVar27 = (int)uVar21 + 1;
            uVar20 = *(uint *)((longlong)&local_5b4 + uVar21 * 4) * uVar39 + uVar22;
            *(int *)((longlong)&local_5b4 + uVar21 * 4) = (int)uVar20;
            uVar22 = uVar20 >> 0x20;
            uVar21 = (ulonglong)uVar27;
          } while (uVar27 != uVar34);
          iVar40 = (int)(uVar20 >> 0x20);
          uVar34 = local_5b8;
          if (iVar40 == 0) goto LAB_180007c83;
          if (local_5b8 < 0x73) {
            *(int *)((longlong)&local_5b4 + (ulonglong)local_5b8 * 4) = iVar40;
            local_5b8 = local_5b8 + 1;
            uVar34 = local_5b8;
            goto LAB_180007c83;
          }
          local_218 = 0;
          local_5b8 = 0;
          memcpy_s(&local_5b4,0x1cc,local_214,0);
          uVar34 = local_5b8;
          bVar42 = bVar4;
          goto LAB_180007faf;
        }
LAB_180007c83:
        bVar42 = true;
      }
      else {
        puVar28 = local_214;
        puVar24 = (uint *)&local_5b4;
        if (uVar34 < 2) {
          uVar34 = (uint)local_5b4;
          uVar39 = local_5b4 & 0xffffffff;
          local_5b8 = local_218;
          memcpy_s(puVar24,0x1cc,puVar28,(ulonglong)local_218 << 2);
          if (uVar34 == 0) {
            local_218 = 0;
            puVar28 = local_214;
            local_5b8 = 0;
            rVar33 = 0;
            goto LAB_180007f97;
          }
          if ((uVar34 != 1) && (uVar22 = uVar36, uVar21 = uVar36, local_5b8 != 0)) {
            do {
              uVar34 = (int)uVar21 + 1;
              uVar20 = *(uint *)((longlong)&local_5b4 + uVar21 * 4) * uVar39 + uVar22;
              *(int *)((longlong)&local_5b4 + uVar21 * 4) = (int)uVar20;
              uVar22 = uVar20 >> 0x20;
              uVar21 = (ulonglong)uVar34;
            } while (uVar34 != local_5b8);
            iVar40 = (int)(uVar20 >> 0x20);
            if (iVar40 != 0) {
              if (0x72 < local_5b8) {
                local_218 = 0;
                puVar28 = local_214;
LAB_18000803a:
                local_5b8 = 0;
                memcpy_s(&local_5b4,0x1cc,puVar28,0);
                uVar34 = local_5b8;
                bVar42 = false;
                goto LAB_180007faf;
              }
              *(int *)((longlong)&local_5b4 + (ulonglong)local_5b8 * 4) = iVar40;
              local_5b8 = local_5b8 + 1;
            }
          }
        }
        else {
          local_3e8 = 0;
          uVar27 = local_218;
          if (local_218 < uVar34) {
            uVar27 = uVar34;
            uVar34 = local_218;
            puVar28 = (uint *)&local_5b4;
            puVar24 = local_214;
          }
          uVar39 = uVar36;
          uVar22 = uVar36;
          local_5b8 = uVar41;
          if (uVar34 != 0) {
            do {
              uVar18 = (uint)uVar22;
              uVar23 = puVar24[uVar22];
              if (uVar23 == 0) {
                if (uVar18 == (uint)uVar39) {
                  uVar39 = (ulonglong)(uVar18 + 1);
                  local_3e4[uVar22] = 0;
                  local_3e8 = uVar18 + 1;
                }
              }
              else {
                uVar7 = uVar18;
                if (uVar27 != 0) {
                  uVar21 = uVar36;
                  do {
                    iVar40 = (int)uVar22;
                    uVar20 = uVar22;
                    if (iVar40 == 0x73) break;
                    if (iVar40 == (int)uVar39) {
                      local_3e4[uVar22] = 0;
                      local_3e8 = iVar40 + 1;
                    }
                    uVar20 = (ulonglong)(iVar40 + 1U);
                    uVar21 = (ulonglong)puVar28[-uVar18 + iVar40] * (ulonglong)uVar23 + uVar21 +
                             (ulonglong)local_3e4[uVar22];
                    local_3e4[uVar22] = (uint)uVar21;
                    uVar21 = uVar21 >> 0x20;
                    uVar39 = (ulonglong)local_3e8;
                    uVar22 = uVar20;
                  } while (-uVar18 + iVar40 + 1U != uVar27);
                  uVar7 = (uint)uVar20;
                  uVar23 = (uint)uVar21;
                  while ((uVar23 != 0 && (uVar7 = (uint)uVar20, uVar7 != 0x73))) {
                    if (uVar7 == (uint)uVar39) {
                      local_3e4[uVar20] = 0;
                      local_3e8 = uVar7 + 1;
                    }
                    uVar7 = uVar7 + 1;
                    uVar23 = local_3e4[uVar20];
                    local_3e4[uVar20] = (uint)(uVar21 + uVar23);
                    uVar39 = (ulonglong)local_3e8;
                    uVar23 = (uint)(uVar21 + uVar23 >> 0x20);
                    uVar21 = (ulonglong)uVar23;
                    uVar20 = (ulonglong)uVar7;
                  }
                }
                if (uVar7 == 0x73) {
                  puVar28 = local_b24;
                  goto LAB_18000803a;
                }
              }
              local_5b8 = (uint)uVar39;
              uVar22 = (ulonglong)(uVar18 + 1);
            } while (uVar18 + 1 != uVar34);
          }
          puVar28 = local_3e4;
          rVar33 = (ulonglong)local_5b8 << 2;
LAB_180007f97:
          memcpy_s(&local_5b4,0x1cc,puVar28,rVar33);
        }
        uVar34 = local_5b8;
        bVar42 = true;
      }
LAB_180007faf:
      if (!bVar42) goto LAB_1800080df;
      uVar19 = uVar19 - uVar17;
      uVar39 = (ulonglong)uVar19;
    }
    if (uVar16 % 10 != 0) {
      uVar16 = *(uint *)(&DAT_180013878 + (ulonglong)(uVar16 % 10 - 1) * 4);
      if (uVar16 == 0) {
        local_5b8 = 0;
        memcpy_s(&local_5b4,0x1cc,local_b24,0);
        uVar34 = local_5b8;
      }
      else if ((uVar16 != 1) && (uVar39 = uVar36, uVar22 = uVar36, uVar34 != 0)) {
        do {
          uVar19 = (int)uVar22 + 1;
          uVar21 = (ulonglong)*(uint *)((longlong)&local_5b4 + uVar22 * 4) * (ulonglong)uVar16 +
                   uVar39;
          *(int *)((longlong)&local_5b4 + uVar22 * 4) = (int)uVar21;
          uVar39 = uVar21 >> 0x20;
          uVar22 = (ulonglong)uVar19;
        } while (uVar19 != uVar34);
        iVar40 = (int)(uVar21 >> 0x20);
        uVar34 = local_5b8;
        if (iVar40 != 0) {
          if (0x72 < local_5b8) {
LAB_1800080df:
            local_5b8 = 0;
            memcpy_s(&local_5b4,0x1cc,local_b24,0);
            fVar1 = param_1[0x308];
            if (param_2[8] == (floating_point_value)0x0) {
              piVar13 = (int *)FUN_180006304((undefined8 *)param_2);
              *piVar13 = (uint)(fVar1 != (floating_point_string)0x0) << 0x1f;
            }
            else {
              plVar12 = (longlong *)FUN_1800062c8((undefined8 *)param_2);
              *plVar12 = (ulonglong)(fVar1 != (floating_point_string)0x0) << 0x3f;
            }
            return 2;
          }
          *(int *)((longlong)&local_5b4 + (ulonglong)local_5b8 * 4) = iVar40;
          local_5b8 = local_5b8 + 1;
          uVar34 = local_5b8;
        }
      }
    }
    iVar40 = (int)uVar38;
    uVar16 = uVar41;
    if (iVar40 != 0) {
      iVar3 = 0x1f;
      bVar42 = local_784[iVar40 - 1U] != 0;
      if (bVar42) {
        for (; local_784[iVar40 - 1U] >> iVar3 == 0; iVar3 = iVar3 + -1) {
        }
      }
      if (bVar42) {
        uVar16 = iVar3 + 1;
      }
      uVar16 = (iVar40 - 1U) * 0x20 + uVar16;
    }
    if (uVar34 != 0) {
      puVar28 = (uint *)((longlong)&local_5b4 + (ulonglong)(uVar34 - 1) * 4);
      iVar3 = 0x1f;
      bVar42 = *puVar28 != 0;
      if (bVar42) {
        for (; *puVar28 >> iVar3 == 0; iVar3 = iVar3 + -1) {
        }
      }
      uVar26 = uVar41;
      if (bVar42) {
        uVar26 = iVar3 + 1;
      }
      uVar26 = (uVar34 - 1) * 0x20 + uVar26;
    }
    uVar16 = -(uint)(uVar16 < uVar26) & uVar26 - uVar16;
    if (uVar16 != 0) {
      uVar26 = uVar16 & 0x1f;
      uVar17 = uVar16 >> 5;
      bVar15 = 0x20 - (sbyte)uVar26;
      uVar19 = (1 << (bVar15 & 0x3f)) - 1;
      iVar3 = 0x1f;
      bVar42 = local_784[iVar40 - 1] != 0;
      if (bVar42) {
        for (; local_784[iVar40 - 1] >> iVar3 == 0; iVar3 = iVar3 + -1) {
        }
      }
      uVar27 = uVar41;
      if (bVar42) {
        uVar27 = iVar3 + 1;
      }
      uVar23 = uVar17 + iVar40;
      bVar42 = 0x20 - uVar27 < uVar26;
      if ((uVar23 != 0x73) || (bVar5 = true, !bVar42)) {
        bVar5 = bVar4;
      }
      if ((0x73 < uVar23) || (bVar5)) {
        local_788 = 0;
        memcpy_s(local_784,0x1cc,local_b24,0);
      }
      else {
        uVar27 = 0x72;
        if (uVar23 < 0x72) {
          uVar27 = uVar23;
        }
        if (uVar27 != 0xffffffff) {
          uVar23 = uVar27 - uVar17;
          while (uVar17 <= uVar23 + uVar17) {
            uVar18 = uVar41;
            if (uVar23 < (uint)uVar38) {
              uVar18 = local_784[uVar23];
            }
            uVar7 = uVar41;
            if (uVar23 - 1 < (uint)uVar38) {
              uVar7 = local_784[uVar23 - 1];
            }
            uVar8 = uVar23 + uVar17;
            uVar23 = uVar23 - 1;
            local_784[uVar8] =
                 (uVar7 & ~uVar19) >> (bVar15 & 0x1f) | (uVar18 & uVar19) << (sbyte)uVar26;
            if (uVar23 + uVar17 == -1) break;
            uVar38 = (ulonglong)local_788;
          }
        }
        uVar39 = uVar36;
        if (uVar17 != 0) {
          do {
            uVar26 = (int)uVar39 + 1;
            local_784[uVar39] = 0;
            uVar39 = (ulonglong)uVar26;
          } while (uVar26 != uVar17);
        }
        if (bVar42) {
          uVar27 = uVar27 + 1;
        }
        local_788 = uVar27;
      }
      uVar38 = (ulonglong)local_788;
    }
    uVar6 = uVar6 - uVar37;
    uVar26 = uVar6;
    if (uVar37 != 0) {
      if (uVar6 < uVar16) {
        bVar43 = true;
        goto LAB_1800085f6;
      }
      uVar26 = uVar6 - uVar16;
    }
    uVar19 = (uint)uVar38;
    if (uVar19 <= uVar34) {
      if (uVar19 < uVar34) {
        bVar43 = true;
      }
      else {
        uVar39 = (ulonglong)(uVar19 - 1);
        if (uVar19 - 1 != 0xffffffff) {
          do {
            if (local_784[uVar39] != *(uint *)((longlong)&local_5b4 + uVar39 * 4)) break;
            uVar34 = (int)uVar39 - 1;
            uVar39 = (ulonglong)uVar34;
          } while (uVar34 != 0xffffffff);
          if ((int)uVar39 != -1) {
            bVar43 = local_784[uVar39] <= *(uint *)((longlong)&local_5b4 + uVar39 * 4);
          }
        }
      }
    }
    if (bVar43) {
      uVar16 = uVar16 + 1;
    }
    uVar17 = uVar26 & 0x1f;
    uVar26 = uVar26 >> 5;
    bVar15 = 0x20 - (sbyte)uVar17;
    uVar34 = (int)(1L << (bVar15 & 0x3f)) - 1;
    iVar40 = 0x1f;
    bVar43 = local_784[uVar19 - 1] != 0;
    if (bVar43) {
      for (; local_784[uVar19 - 1] >> iVar40 == 0; iVar40 = iVar40 + -1) {
      }
    }
    uVar27 = uVar41;
    if (bVar43) {
      uVar27 = iVar40 + 1;
    }
    uVar19 = uVar26 + uVar19;
    bVar43 = 0x20 - uVar27 < uVar17;
    if ((uVar19 != 0x73) || (bVar42 = true, !bVar43)) {
      bVar42 = bVar4;
    }
    if ((0x73 < uVar19) || (bVar42)) {
      local_788 = 0;
      memcpy_s(local_784,0x1cc,local_b24,0);
    }
    else {
      uVar27 = 0x72;
      if (uVar19 < 0x72) {
        uVar27 = uVar19;
      }
      if (uVar27 != 0xffffffff) {
        uVar19 = uVar27 - uVar26;
        while( true ) {
          uVar23 = uVar19 + uVar26;
          if (uVar23 < uVar26) break;
          uVar18 = uVar41;
          if (uVar19 < (uint)uVar38) {
            uVar18 = local_784[uVar19];
          }
          uVar7 = uVar41;
          if (uVar19 - 1 < (uint)uVar38) {
            uVar7 = local_784[uVar19 - 1];
          }
          uVar19 = uVar19 - 1;
          local_784[uVar23] =
               (uVar7 & ~uVar34) >> (bVar15 & 0x1f) | (uVar18 & uVar34) << (sbyte)uVar17;
          if (uVar19 + uVar26 == -1) break;
          uVar38 = (ulonglong)local_788;
        }
      }
      uVar39 = uVar36;
      if (uVar26 != 0) {
        do {
          uVar34 = (int)uVar39 + 1;
          local_784[uVar39] = 0;
          uVar39 = (ulonglong)uVar34;
        } while (uVar34 != uVar26);
      }
      local_788 = uVar27;
      if (bVar43) {
        local_788 = uVar27 + 1;
      }
    }
    _Var14 = divide((big_integer *)&local_788,(big_integer *)&local_5b8);
    bVar43 = local_788 == 0;
    if (_Var14 < 0x100000000) {
      iVar40 = 0x1f;
      uVar34 = (uint)_Var14;
      if (uVar34 != 0) {
        for (; uVar34 >> iVar40 == 0; iVar40 = iVar40 + -1) {
        }
      }
      uVar26 = uVar41;
      if (uVar34 != 0) {
        uVar26 = iVar40 + 1;
      }
    }
    else {
      iVar40 = 0x1f;
      uVar34 = (uint)(_Var14 >> 0x20);
      if (uVar34 != 0) {
        for (; uVar34 >> iVar40 == 0; iVar40 = iVar40 + -1) {
        }
      }
      uVar26 = uVar41;
      if (uVar34 != 0) {
        uVar26 = iVar40 + 1;
      }
      uVar26 = uVar26 + 0x20;
    }
    if (uVar6 < uVar26) {
      bVar15 = (char)uVar26 - (byte)uVar6;
      if ((!bVar43) || (bVar43 = true, (_Var14 & (1L << (bVar15 & 0x3f)) - 1U) != 0)) {
        bVar43 = false;
      }
      _Var14 = _Var14 >> (bVar15 & 0x3f);
    }
    if (uVar29 != 0) {
      uVar36 = (ulonglong)local_954[0];
    }
    if (1 < uVar29) {
      uVar41 = local_954[1];
    }
    iVar40 = -1 - uVar16;
    if (uVar37 != 0) {
      iVar40 = uVar37 - 2;
    }
    SVar9 = assemble_floating_point_value
                      (_Var14 + (((ulonglong)uVar41 << 0x20) + uVar36 << ((byte)uVar6 & 0x3f)),
                       iVar40,(bool)param_1[0x308],bVar43,param_2);
  }
  else {
    bVar43 = uVar16 != 0;
LAB_1800085f6:
    SVar9 = assemble_floating_point_value_from_big_integer
                      ((big_integer *)&local_958,uVar37,(bool)param_1[0x308],bVar43,param_2);
  }
  return SVar9;
}



/* ---- convert_hexadecimal_string_to_floating_type_common @ 180008644 ---- */

/* Library Function - Single Match
    enum SLD_STATUS __cdecl __crt_strtox::convert_hexadecimal_string_to_floating_type_common(struct
   __crt_strtox::floating_point_string const & __ptr64,class __crt_strtox::floating_point_value
   const & __ptr64)
   
   Library: Visual Studio 2015 Release */

SLD_STATUS __cdecl
__crt_strtox::convert_hexadecimal_string_to_floating_type_common
          (floating_point_string *param_1,floating_point_value *param_2)

{
  floating_point_string fVar1;
  SLD_STATUS SVar2;
  __uint64 _Var3;
  floating_point_string *pfVar4;
  int iVar5;
  bool bVar6;
  floating_point_string *pfVar7;
  
  _Var3 = 0;
  pfVar4 = param_1 + 8;
  pfVar7 = param_1 + (ulonglong)*(uint *)(param_1 + 4) + 8;
  iVar5 = *(int *)param_1 + (-(uint)(param_2[8] != (floating_point_value)0x0) & 0x1d) + 0x17;
  if (pfVar4 != pfVar7) {
    do {
      if ((-(ulonglong)(param_2[8] != (floating_point_value)0x0) & 0x1fffffff000000) + 0xffffff <
          _Var3) break;
      fVar1 = *pfVar4;
      iVar5 = iVar5 + -4;
      pfVar4 = pfVar4 + 1;
      _Var3 = _Var3 * 0x10 + (ulonglong)(byte)fVar1;
    } while (pfVar4 != pfVar7);
  }
  do {
    bVar6 = true;
    while( true ) {
      if ((pfVar4 == pfVar7) || (bVar6 == false)) {
        SVar2 = assemble_floating_point_value(_Var3,iVar5,(bool)param_1[0x308],bVar6,param_2);
        return SVar2;
      }
      fVar1 = *pfVar4;
      pfVar4 = pfVar4 + 1;
      if (fVar1 == (floating_point_string)0x0) break;
      bVar6 = false;
    }
  } while( true );
}



/* ---- divide @ 180008700 ---- */

/* Library Function - Single Match
    unsigned __int64 __cdecl __crt_strtox::divide(struct __crt_strtox::big_integer & __ptr64,struct
   __crt_strtox::big_integer const & __ptr64)
   
   Library: Visual Studio 2015 Release */

__uint64 __cdecl __crt_strtox::divide(big_integer *param_1,big_integer *param_2)

{
  int iVar1;
  byte bVar2;
  uint uVar3;
  ulonglong uVar4;
  ulonglong uVar5;
  ulonglong uVar6;
  byte bVar7;
  uint uVar8;
  big_integer *pbVar9;
  __uint64 _Var10;
  int iVar11;
  uint uVar12;
  __uint64 _Var13;
  longlong lVar14;
  ulonglong uVar15;
  ulonglong uVar16;
  longlong lVar17;
  ulonglong uVar18;
  uint uVar19;
  int iVar20;
  uint uVar21;
  uint uVar22;
  uint local_res20;
  undefined8 local_230;
  undefined1 local_214 [468];
  
  if ((*(int *)param_1 == 0) || (uVar8 = *(uint *)param_2, uVar8 == 0)) {
    return 0;
  }
  uVar21 = *(int *)param_1 - 1;
  uVar18 = (ulonglong)uVar21;
  uVar3 = uVar8 - 1;
  if (uVar3 == 0) {
    uVar8 = *(uint *)(param_2 + 4);
    _Var13 = 0;
    if (uVar8 == 1) {
      uVar8 = *(uint *)(param_1 + 4);
      *(undefined4 *)param_1 = 0;
      memcpy_s(param_1 + 4,0x1cc,local_214,0);
      uVar5 = (ulonglong)uVar8;
    }
    else {
      uVar5 = _Var13;
      if (uVar21 == 0) {
        uVar21 = *(uint *)(param_1 + 4);
        *(undefined4 *)param_1 = 0;
        memcpy_s(param_1 + 4,0x1cc,local_214,0);
        uVar5 = (ulonglong)uVar21 / (ulonglong)uVar8;
        uVar21 = uVar21 % uVar8;
        *(uint *)(param_1 + 4) = uVar21;
        *(uint *)param_1 = (uint)(uVar21 != 0);
      }
      else {
        while (uVar21 != 0xffffffff) {
          lVar14 = uVar18 * 4;
          uVar21 = (int)uVar18 - 1;
          uVar18 = (ulonglong)uVar21;
          uVar4 = (ulonglong)*(uint *)(param_1 + lVar14 + 4) | _Var13 << 0x20;
          _Var13 = uVar4 % (ulonglong)uVar8;
          uVar5 = (uVar5 << 0x20) + (uVar4 / uVar8 & 0xffffffff);
        }
        *(undefined4 *)param_1 = 0;
        memcpy_s(param_1 + 4,0x1cc,local_214,0);
        *(int *)(param_1 + 4) = (int)_Var13;
        *(undefined4 *)(param_1 + 8) = 0;
        *(undefined4 *)param_1 = 1;
      }
    }
  }
  else if (uVar21 < uVar3) {
    uVar5 = 0;
  }
  else {
    lVar14 = (longlong)(int)uVar21;
    iVar20 = uVar21 - uVar3;
    lVar17 = (longlong)iVar20;
    if (lVar17 <= lVar14) {
      pbVar9 = param_1 + lVar14 * 4 + 4;
      uVar3 = uVar21;
      do {
        if (*(int *)(pbVar9 + (longlong)(param_2 + (lVar17 * -4 - (longlong)param_1))) !=
            *(int *)pbVar9) {
          if (*(uint *)(param_1 + (longlong)(int)uVar3 * 4 + 4) <=
              *(uint *)(param_2 + ((int)uVar3 - lVar17) * 4 + 4)) goto LAB_1800088cf;
          break;
        }
        uVar3 = uVar3 - 1;
        lVar14 = lVar14 + -1;
        pbVar9 = pbVar9 + -4;
      } while (lVar17 <= lVar14);
    }
    iVar20 = iVar20 + 1;
LAB_1800088cf:
    if (iVar20 == 0) {
      uVar5 = 0;
    }
    else {
      uVar3 = *(uint *)(param_2 + (ulonglong)(uVar8 - 1) * 4 + 4);
      local_res20 = *(uint *)(param_2 + (ulonglong)(uVar8 - 2) * 4 + 4);
      iVar1 = 0x1f;
      if (uVar3 != 0) {
        for (; uVar3 >> iVar1 == 0; iVar1 = iVar1 + -1) {
        }
      }
      iVar11 = 0x20;
      if (uVar3 != 0) {
        iVar11 = 0x1f - iVar1;
      }
      bVar2 = (byte)iVar11;
      bVar7 = 0x20 - bVar2;
      if (iVar11 != 0) {
        uVar12 = local_res20 >> (bVar7 & 0x1f);
        local_res20 = local_res20 << (bVar2 & 0x1f);
        uVar3 = uVar12 | uVar3 << (bVar2 & 0x1f);
        if (2 < uVar8) {
          local_res20 = local_res20 |
                        *(uint *)(param_2 + (ulonglong)(uVar8 - 3) * 4 + 4) >> (bVar7 & 0x1f);
        }
      }
      _Var13 = 0;
      uVar12 = iVar20 - 1;
      uVar5 = _Var13;
      if (-1 < (int)uVar12) {
        uVar19 = uVar12 + uVar8;
        uVar4 = (ulonglong)uVar3;
        do {
          uVar21 = 0;
          if (uVar19 <= (uint)uVar18) {
            uVar21 = *(uint *)(param_1 + (ulonglong)uVar19 * 4 + 4);
          }
          uVar3 = *(uint *)(param_1 + (ulonglong)(uVar19 - 2) * 4 + 4);
          local_230 = CONCAT44(uVar21,*(undefined4 *)(param_1 + (ulonglong)(uVar19 - 1) * 4 + 4));
          if (iVar11 != 0) {
            local_230 = (ulonglong)(uVar3 >> (bVar7 & 0x3f)) | local_230 << (bVar2 & 0x3f);
            uVar3 = uVar3 << (bVar2 & 0x1f);
            if (2 < uVar19) {
              uVar3 = uVar3 | *(uint *)(param_1 + (ulonglong)(uVar19 - 3) * 4 + 4) >> (bVar7 & 0x1f)
              ;
            }
          }
          uVar6 = local_230 / uVar4;
          local_230 = local_230 % uVar4;
          if (0xffffffff < uVar6) {
            lVar14 = uVar6 - 0xffffffff;
            uVar6 = 0xffffffff;
            local_230 = local_230 + lVar14 * uVar4;
          }
          if (local_230 < 0x100000000) {
            uVar16 = local_res20 * uVar6;
            do {
              if (uVar16 <= (local_230 << 0x20 | (ulonglong)uVar3)) break;
              uVar6 = uVar6 - 1;
              uVar16 = uVar16 - local_res20;
              local_230 = local_230 + uVar4;
            } while (local_230 < 0x100000000);
          }
          if (uVar6 != 0) {
            _Var10 = _Var13;
            if (uVar8 != 0) {
              uVar18 = (ulonglong)uVar8;
              pbVar9 = param_2;
              uVar3 = uVar12;
              do {
                uVar15 = (ulonglong)uVar3;
                pbVar9 = pbVar9 + 4;
                uVar16 = _Var10 + *(uint *)pbVar9 * uVar6;
                _Var10 = uVar16 >> 0x20;
                uVar22 = (uint)uVar16;
                if (*(uint *)(param_1 + uVar15 * 4 + 4) < uVar22) {
                  _Var10 = _Var10 + 1;
                }
                uVar3 = uVar3 + 1;
                *(uint *)(param_1 + uVar15 * 4 + 4) = *(uint *)(param_1 + uVar15 * 4 + 4) - uVar22;
                uVar18 = uVar18 - 1;
              } while (uVar18 != 0);
            }
            if (uVar21 < _Var10) {
              uVar18 = (ulonglong)uVar8;
              uVar16 = _Var13;
              uVar21 = uVar12;
              pbVar9 = param_2;
              if (uVar8 != 0) {
                do {
                  uVar16 = (ulonglong)*(uint *)(param_1 + (ulonglong)uVar21 * 4 + 4) +
                           (ulonglong)*(uint *)(pbVar9 + 4) + uVar16;
                  *(int *)(param_1 + (ulonglong)uVar21 * 4 + 4) = (int)uVar16;
                  uVar18 = uVar18 - 1;
                  uVar16 = uVar16 >> 0x20;
                  uVar21 = uVar21 + 1;
                  pbVar9 = pbVar9 + 4;
                } while (uVar18 != 0);
              }
              uVar6 = uVar6 - 1;
            }
            uVar18 = (ulonglong)(uVar19 - 1);
          }
          uVar21 = (uint)uVar18;
          uVar12 = uVar12 - 1;
          uVar19 = uVar19 - 1;
          uVar5 = (uVar5 << 0x20) + (uVar6 & 0xffffffff);
        } while (-1 < (int)uVar12);
      }
      uVar21 = uVar21 + 1;
      uVar8 = uVar21;
      if (uVar21 < *(uint *)param_1) {
        do {
          uVar18 = (ulonglong)uVar8;
          uVar8 = uVar8 + 1;
          *(undefined4 *)(param_1 + uVar18 * 4 + 4) = 0;
        } while (uVar8 < *(uint *)param_1);
      }
      *(uint *)param_1 = uVar21;
      while ((uVar21 != 0 &&
             (uVar21 = *(int *)param_1 - 1, *(int *)(param_1 + (ulonglong)uVar21 * 4 + 4) == 0))) {
        *(uint *)param_1 = uVar21;
      }
    }
  }
  return uVar5;
}



/* ---- length @ 180008bd0 ---- */

/* Library Function - Single Match
    public: unsigned __int64 __cdecl
   __crt_stdio_input::format_string_parser<char>::length(void)const __ptr64
   
   Library: Visual Studio 2015 Release */

__uint64 __thiscall
__crt_stdio_input::format_string_parser<char>::length(format_string_parser<char> *this)

{
  int iVar1;
  
  iVar1 = *(int *)(this + 0x30);
  if (iVar1 < 0) {
    return 0;
  }
  if (1 < iVar1) {
    if (6 < iVar1) {
      if (iVar1 == 7) {
        iVar1 = *(int *)(this + 0x28);
        if (iVar1 == 0) {
          return 4;
        }
        if (iVar1 != 3) {
          if (iVar1 != 8) {
            return 0;
          }
          return 8;
        }
        return 8;
      }
      if (iVar1 == 8) goto LAB_180008c5a;
      if (iVar1 != 9) {
        return 0;
      }
    }
    iVar1 = *(int *)(this + 0x28);
    if (iVar1 < 6) {
      if (iVar1 == 5) {
        return 8;
      }
      if (iVar1 == 0) {
        return 4;
      }
      if (iVar1 == 1) {
        return 1;
      }
      if (iVar1 == 2) {
        return 2;
      }
      iVar1 = iVar1 + -3;
    }
    else {
      if (iVar1 == 6) {
        return 8;
      }
      if (iVar1 == 7) {
        return 8;
      }
      iVar1 = iVar1 + -9;
    }
    if (iVar1 == 0) {
      return 4;
    }
    if (iVar1 != 1) {
      return 0;
    }
    return 8;
  }
LAB_180008c5a:
  return (ulonglong)(this[0x2c] != (format_string_parser<char>)0x0) + 1;
}



/* ---- process @ 180008c6c ---- */

/* Library Function - Single Match
    public: int __cdecl __crt_stdio_input::input_processor<char,class
   __crt_stdio_input::string_input_adapter<char> >::process(void) __ptr64
   
   Library: Visual Studio 2015 Release */

int __thiscall
__crt_stdio_input::input_processor<char,__crt_stdio_input::string_input_adapter<char>_>::process
          (input_processor<char,__crt_stdio_input::string_input_adapter<char>_> *this)

{
  ulong uVar1;
  char *pcVar2;
  longlong lVar3;
  bool bVar4;
  ulong *puVar5;
  char cVar6;
  int iVar7;
  
  if ((*(ulonglong *)(this + 0x18) == 0) ||
     (*(ulonglong *)(this + 0x10) < *(ulonglong *)(this + 0x18))) {
    puVar5 = __doserrno();
    *puVar5 = 0x16;
    FUN_18000aff4();
    return -1;
  }
  if (*(longlong *)(this + 0x28) == 0) {
    puVar5 = __doserrno();
    iVar7 = -1;
    *puVar5 = 0x16;
    goto LAB_180008d3f;
  }
  do {
    bVar4 = format_string_parser<char>::advance((format_string_parser<char> *)(this + 0x20));
    if (!bVar4) break;
    bVar4 = process_state(this);
  } while (bVar4);
  iVar7 = *(int *)(this + 0x88);
  if (*(longlong *)(this + 0x90) == 0) {
    pcVar2 = *(char **)(this + 0x18);
    if (pcVar2 == *(char **)(this + 0x10)) {
      cVar6 = -1;
LAB_180008d0d:
      iVar7 = -1;
    }
    else {
      cVar6 = *pcVar2;
      *(char **)(this + 0x18) = pcVar2 + 1;
      if (cVar6 == -1) goto LAB_180008d0d;
    }
    lVar3 = *(longlong *)(this + 0x18);
    if ((lVar3 != *(longlong *)(this + 8)) &&
       ((lVar3 != *(longlong *)(this + 0x10) || (cVar6 != -1)))) {
      *(longlong *)(this + 0x18) = lVar3 + -1;
    }
  }
  if (((byte)*this & 1) == 0) {
    return iVar7;
  }
  uVar1 = *(ulong *)(this + 0x30);
  if (uVar1 == 0) {
    return iVar7;
  }
  puVar5 = __doserrno();
  *puVar5 = uVar1;
LAB_180008d3f:
  FUN_18000aff4();
  return iVar7;
}



/* ---- process_conversion_specifier @ 180008d5c ---- */

/* Library Function - Single Match
    private: bool __cdecl __crt_stdio_input::input_processor<char,class
   __crt_stdio_input::string_input_adapter<char> >::process_conversion_specifier(void) __ptr64
   
   Library: Visual Studio 2015 Release */

bool __thiscall
__crt_stdio_input::input_processor<char,__crt_stdio_input::string_input_adapter<char>_>::
process_conversion_specifier
          (input_processor<char,__crt_stdio_input::string_input_adapter<char>_> *this)

{
  int iVar1;
  bool bVar2;
  __uint64 _Var3;
  uint uVar4;
  conversion_mode cVar5;
  
  iVar1 = *(int *)(this + 0x50);
  if (iVar1 < 6) {
    if (iVar1 != 5) {
      if (iVar1 == 0) {
        _Var3 = format_string_parser<char>::length((format_string_parser<char> *)(this + 0x20));
        if (_Var3 == 1) {
          cVar5 = 0;
          goto LAB_180008de5;
        }
        if (_Var3 != 2) {
          return false;
        }
        cVar5 = 0;
        goto LAB_180008dd6;
      }
      if (iVar1 == 1) {
        bVar2 = process_string_specifier(this,1);
        return bVar2;
      }
      if (iVar1 == 2) {
        uVar4 = 0;
      }
      else {
        if (iVar1 != 3) {
          if (iVar1 != 4) {
            return false;
          }
          uVar4 = 8;
          goto LAB_180008e6a;
        }
        uVar4 = 10;
      }
      bVar2 = true;
      goto LAB_180008e6d;
    }
    uVar4 = 10;
  }
  else {
    if (iVar1 != 6) {
      if (iVar1 == 7) {
        bVar2 = process_floating_point_specifier(this);
        return bVar2;
      }
      if (iVar1 != 8) {
        if (iVar1 != 9) {
          return false;
        }
        if (this[0x3a] == (input_processor<char,__crt_stdio_input::string_input_adapter<char>_>)0x0)
        {
          bVar2 = write_integer(this,*(longlong *)(this + 0x18) - *(longlong *)(this + 8),false);
          return bVar2;
        }
        return true;
      }
      _Var3 = format_string_parser<char>::length((format_string_parser<char> *)(this + 0x20));
      if (_Var3 == 1) {
        cVar5 = 8;
LAB_180008de5:
        bVar2 = process_string_specifier_tchar<char>(this,cVar5,'\0');
        return bVar2;
      }
      if (_Var3 != 2) {
        return false;
      }
      cVar5 = 8;
LAB_180008dd6:
      bVar2 = process_string_specifier_tchar<wchar_t>(this,cVar5,L'\0');
      return bVar2;
    }
    uVar4 = 0x10;
  }
LAB_180008e6a:
  bVar2 = false;
LAB_180008e6d:
  bVar2 = process_integer_specifier(this,uVar4,bVar2);
  return bVar2;
}



/* ---- process_floating_point_specifier @ 180008e80 ---- */

/* Library Function - Single Match
    private: bool __cdecl __crt_stdio_input::input_processor<char,class
   __crt_stdio_input::string_input_adapter<char> >::process_floating_point_specifier(void) __ptr64
   
   Library: Visual Studio 2015 Release */

bool __thiscall
__crt_stdio_input::input_processor<char,__crt_stdio_input::string_input_adapter<char>_>::
process_floating_point_specifier
          (input_processor<char,__crt_stdio_input::string_input_adapter<char>_> *this)

{
  longlong lVar1;
  bool bVar2;
  int iVar3;
  __uint64 _Var4;
  
  iVar3 = skip_whitespace<__crt_stdio_input::string_input_adapter,char>
                    ((string_input_adapter<char> *)(this + 8),
                     *(__crt_locale_pointers **)(this + 0x78));
  lVar1 = *(longlong *)(this + 0x18);
  if ((lVar1 != *(longlong *)(this + 8)) && ((lVar1 != *(longlong *)(this + 0x10) || (iVar3 != -1)))
     ) {
    *(longlong *)(this + 0x18) = lVar1 + -1;
  }
  _Var4 = format_string_parser<char>::length((format_string_parser<char> *)(this + 0x20));
  if (_Var4 == 4) {
    bVar2 = process_floating_point_specifier_t<float>(this);
  }
  else if (_Var4 == 8) {
    bVar2 = process_floating_point_specifier_t<double>(this);
  }
  else {
    bVar2 = false;
  }
  return bVar2;
}



/* ---- process_integer_specifier @ 180008ef0 ---- */

/* WARNING: Removing unreachable block (ram,0x000180008f71) */
/* WARNING: Removing unreachable block (ram,0x000180008f7b) */
/* WARNING: Removing unreachable block (ram,0x000180008f77) */
/* Library Function - Single Match
    private: bool __cdecl __crt_stdio_input::input_processor<char,class
   __crt_stdio_input::string_input_adapter<char> >::process_integer_specifier(unsigned int,bool)
   __ptr64
   
   Library: Visual Studio 2015 Release */

bool __thiscall
__crt_stdio_input::input_processor<char,__crt_stdio_input::string_input_adapter<char>_>::
process_integer_specifier
          (input_processor<char,__crt_stdio_input::string_input_adapter<char>_> *this,uint param_1,
          bool param_2)

{
  string_input_adapter<char> *psVar1;
  longlong lVar2;
  int iVar3;
  undefined8 uVar4;
  string_input_adapter<char> local_28 [32];
  
  psVar1 = (string_input_adapter<char> *)(this + 8);
  iVar3 = skip_whitespace<__crt_stdio_input::string_input_adapter,char>
                    (psVar1,*(__crt_locale_pointers **)(this + 0x78));
  lVar2 = *(longlong *)(this + 0x18);
  if ((lVar2 != *(longlong *)psVar1) && ((lVar2 != *(longlong *)(this + 0x10) || (iVar3 != -1)))) {
    *(longlong *)(this + 0x18) = lVar2 + -1;
  }
  uVar4 = __crt_strtox::
          make_input_adapter_character_source<__crt_stdio_input::string_input_adapter<char>_>
                    (local_28,(__uint64)psVar1,*(bool **)(this + 0x40));
  __crt_strtox::
  parse_integer<unsigned___int64,__crt_strtox::input_adapter_character_source<__crt_stdio_input::string_input_adapter<char>_>_>
            (*(undefined8 *)(this + 0x78),uVar4,param_1,param_2);
  return false;
}



/* ---- process_literal_character_tchar @ 180008fa0 ---- */

/* Library Function - Single Match
    private: bool __cdecl __crt_stdio_input::input_processor<char,class
   __crt_stdio_input::string_input_adapter<char> >::process_literal_character_tchar(char) __ptr64
   
   Library: Visual Studio 2015 Release */

bool __thiscall
__crt_stdio_input::input_processor<char,__crt_stdio_input::string_input_adapter<char>_>::
process_literal_character_tchar
          (input_processor<char,__crt_stdio_input::string_input_adapter<char>_> *this,char param_1)

{
  char *pcVar1;
  longlong lVar2;
  ushort *puVar3;
  uint uVar4;
  
  puVar3 = __pctype_func();
  if ((puVar3[(byte)param_1] & 0x8000) != 0) {
    pcVar1 = *(char **)(this + 0x18);
    if (pcVar1 == *(char **)(this + 0x10)) {
      uVar4 = 0xffffffff;
    }
    else {
      uVar4 = (uint)*pcVar1;
      *(char **)(this + 0x18) = pcVar1 + 1;
    }
    if (uVar4 != (byte)this[0x39]) {
      lVar2 = *(longlong *)(this + 0x18);
      if ((lVar2 != *(longlong *)(this + 8)) &&
         ((lVar2 != *(longlong *)(this + 0x10) || (uVar4 != 0xffffffff)))) {
        *(longlong *)(this + 0x18) = lVar2 + -1;
      }
      lVar2 = *(longlong *)(this + 0x18);
      if ((lVar2 != *(longlong *)(this + 8)) &&
         ((lVar2 != *(longlong *)(this + 0x10) || (param_1 != -1)))) {
        *(longlong *)(this + 0x18) = lVar2 + -1;
      }
      return false;
    }
  }
  return true;
}



/* ---- process_state @ 18000902c ---- */

/* Library Function - Single Match
    private: bool __cdecl __crt_stdio_input::input_processor<char,class
   __crt_stdio_input::string_input_adapter<char> >::process_state(void) __ptr64
   
   Library: Visual Studio 2015 Release */

bool __thiscall
__crt_stdio_input::input_processor<char,__crt_stdio_input::string_input_adapter<char>_>::
process_state(input_processor<char,__crt_stdio_input::string_input_adapter<char>_> *this)

{
  char cVar1;
  char *pcVar2;
  longlong lVar3;
  bool bVar4;
  int iVar5;
  
  iVar5 = *(int *)(this + 0x34);
  if (iVar5 == 2) {
    iVar5 = skip_whitespace<__crt_stdio_input::string_input_adapter,char>
                      ((string_input_adapter<char> *)(this + 8),
                       *(__crt_locale_pointers **)(this + 0x78));
    lVar3 = *(longlong *)(this + 0x18);
    if ((lVar3 != *(longlong *)(this + 8)) &&
       ((lVar3 != *(longlong *)(this + 0x10) || (iVar5 != -1)))) {
      *(longlong *)(this + 0x18) = lVar3 + -1;
    }
    bVar4 = true;
  }
  else {
    if (iVar5 == 3) {
      pcVar2 = *(char **)(this + 0x18);
      if (pcVar2 != *(char **)(this + 0x10)) {
        cVar1 = *pcVar2;
        *(char **)(this + 0x18) = pcVar2 + 1;
        if ((int)cVar1 != 0xffffffff) {
          if ((int)cVar1 == (uint)(byte)this[0x38]) {
            bVar4 = process_literal_character_tchar(this,cVar1);
            return bVar4;
          }
          if (*(longlong *)(this + 0x18) != *(longlong *)(this + 8)) {
            *(longlong *)(this + 0x18) = *(longlong *)(this + 0x18) + -1;
          }
        }
      }
    }
    else if (iVar5 == 4) {
      bVar4 = process_conversion_specifier(this);
      if (!bVar4) {
        return false;
      }
      *(longlong *)(this + 0x90) = *(longlong *)(this + 0x90) + 1;
      return true;
    }
    bVar4 = false;
  }
  return bVar4;
}



/* ---- process_string_specifier @ 1800090e0 ---- */

/* Library Function - Single Match
    private: bool __cdecl __crt_stdio_input::input_processor<char,class
   __crt_stdio_input::string_input_adapter<char> >::process_string_specifier(enum
   __crt_stdio_input::conversion_mode) __ptr64
   
   Library: Visual Studio 2015 Release */

bool __thiscall
__crt_stdio_input::input_processor<char,__crt_stdio_input::string_input_adapter<char>_>::
process_string_specifier
          (input_processor<char,__crt_stdio_input::string_input_adapter<char>_> *this,
          conversion_mode param_1)

{
  longlong lVar1;
  bool bVar2;
  int iVar3;
  __uint64 _Var4;
  
  if (param_1 == 1) {
    iVar3 = skip_whitespace<__crt_stdio_input::string_input_adapter,char>
                      ((string_input_adapter<char> *)(this + 8),
                       *(__crt_locale_pointers **)(this + 0x78));
    lVar1 = *(longlong *)(this + 0x18);
    if ((lVar1 != *(longlong *)(this + 8)) &&
       ((lVar1 != *(longlong *)(this + 0x10) || (iVar3 != -1)))) {
      *(longlong *)(this + 0x18) = lVar1 + -1;
    }
  }
  _Var4 = format_string_parser<char>::length((format_string_parser<char> *)(this + 0x20));
  if (_Var4 == 1) {
    bVar2 = process_string_specifier_tchar<char>(this,param_1,'\0');
  }
  else if (_Var4 == 2) {
    bVar2 = process_string_specifier_tchar<wchar_t>(this,param_1,L'\0');
  }
  else {
    bVar2 = false;
  }
  return bVar2;
}



/* ---- scan_conversion_specifier @ 18000916c ---- */

/* Library Function - Single Match
    private: bool __cdecl
   __crt_stdio_input::format_string_parser<char>::scan_conversion_specifier(void) __ptr64
   
   Libraries: Visual Studio 2015 Debug, Visual Studio 2015 Release */

bool __thiscall
__crt_stdio_input::format_string_parser<char>::scan_conversion_specifier
          (format_string_parser<char> *this)

{
  byte bVar1;
  int iVar2;
  byte *pbVar3;
  bool bVar4;
  
  pbVar3 = *(byte **)(this + 8);
  bVar1 = *pbVar3;
  if (bVar1 < 0x65) {
    if (bVar1 == 100) {
      *(undefined4 *)(this + 0x30) = 3;
      goto LAB_18000931d;
    }
    if (bVar1 < 0x54) {
      if (bVar1 == 0x53) {
LAB_1800092c1:
        iVar2 = *(int *)(this + 0x28);
        if (iVar2 == 2) {
          this[0x2c] = (format_string_parser<char>)0x0;
        }
        if (((iVar2 - 3U & 0xfffffffa) == 0) && (iVar2 != 7)) {
          this[0x2c] = (format_string_parser<char>)0x1;
        }
        *(undefined4 *)(this + 0x30) = 1;
        *(byte **)(this + 8) = pbVar3 + 1;
        return true;
      }
      if (bVar1 != 0x41) {
        if (bVar1 == 0x43) goto LAB_1800091f5;
        if (bVar1 < 0x45) {
LAB_1800091b6:
          *(undefined8 *)(this + 0x10) = 0x16;
          *(undefined2 *)(this + 0x18) = 0;
          this[0x1a] = (format_string_parser<char>)0x0;
          *(undefined8 *)(this + 0x20) = 0;
          *(undefined4 *)(this + 0x28) = 0;
          this[0x2c] = (format_string_parser<char>)0x0;
          *(undefined4 *)(this + 0x30) = 0;
          return false;
        }
        if (0x47 < bVar1) {
          if (bVar1 != 0x49) goto LAB_1800091b6;
          goto LAB_18000930d;
        }
      }
    }
    else {
      if (bVar1 == 0x58) goto LAB_1800092af;
      if (bVar1 == 0x5b) {
        iVar2 = *(int *)(this + 0x28);
        if (iVar2 == 2) {
          this[0x2c] = (format_string_parser<char>)0x0;
        }
        if (((iVar2 - 3U & 0xfffffffa) == 0) && (iVar2 != 7)) {
          this[0x2c] = (format_string_parser<char>)0x1;
        }
        *(undefined4 *)(this + 0x30) = 8;
        *(byte **)(this + 8) = pbVar3 + 1;
        bVar4 = scan_scanset_range(this);
        return bVar4;
      }
      if (bVar1 != 0x61) {
        if (bVar1 != 99) goto LAB_1800091b6;
LAB_1800091f5:
        if (*(longlong *)(this + 0x20) == 0) {
          *(undefined8 *)(this + 0x20) = 1;
        }
        iVar2 = *(int *)(this + 0x28);
        if (iVar2 == 2) {
          this[0x2c] = (format_string_parser<char>)0x0;
        }
        if (((iVar2 - 3U & 0xfffffffa) == 0) && (iVar2 != 7)) {
          this[0x2c] = (format_string_parser<char>)0x1;
        }
        *(undefined4 *)(this + 0x30) = 0;
        *(byte **)(this + 8) = pbVar3 + 1;
        return true;
      }
    }
  }
  else if (0x67 < bVar1) {
    if (bVar1 == 0x69) {
LAB_18000930d:
      *(undefined4 *)(this + 0x30) = 2;
      goto LAB_18000931d;
    }
    if (bVar1 == 0x6e) {
      *(undefined4 *)(this + 0x30) = 9;
      goto LAB_18000931d;
    }
    if (bVar1 == 0x6f) {
      *(undefined4 *)(this + 0x30) = 4;
      goto LAB_18000931d;
    }
    if (bVar1 == 0x70) {
      *(undefined4 *)(this + 0x28) = 10;
    }
    else {
      if (bVar1 == 0x73) goto LAB_1800092c1;
      if (bVar1 == 0x75) {
        *(undefined4 *)(this + 0x30) = 5;
        goto LAB_18000931d;
      }
      if (bVar1 != 0x78) goto LAB_1800091b6;
    }
LAB_1800092af:
    *(undefined4 *)(this + 0x30) = 6;
    goto LAB_18000931d;
  }
  *(undefined4 *)(this + 0x30) = 7;
LAB_18000931d:
  *(byte **)(this + 8) = pbVar3 + 1;
  return true;
}



/* ---- scan_optional_field_width @ 180009328 ---- */

/* Library Function - Single Match
    private: bool __cdecl
   __crt_stdio_input::format_string_parser<char>::scan_optional_field_width(void) __ptr64
   
   Library: Visual Studio 2015 Release */

bool __thiscall
__crt_stdio_input::format_string_parser<char>::scan_optional_field_width
          (format_string_parser<char> *this)

{
  char *pcVar1;
  uint uVar2;
  longlong lVar3;
  longlong local_res8 [4];
  
  pcVar1 = *(char **)(this + 8);
  if ((byte)(*pcVar1 - 0x30U) < 10) {
    uVar2 = (int)*pcVar1 - 0x30;
  }
  else if ((byte)(*pcVar1 + 0x9fU) < 0x1a) {
    uVar2 = (int)*pcVar1 - 0x57;
  }
  else if ((byte)(*pcVar1 + 0xbfU) < 0x1a) {
    uVar2 = (int)*pcVar1 - 0x37;
  }
  else {
    uVar2 = 0xffffffff;
  }
  if (uVar2 < 10) {
    local_res8[0] = 0;
    lVar3 = strtoull(pcVar1,local_res8,10);
    if ((lVar3 == 0) || (local_res8[0] == *(longlong *)(this + 8))) {
      *(undefined4 *)(this + 0x14) = 0;
      *(undefined8 *)(this + 0x20) = 0;
      *(undefined4 *)(this + 0x28) = 0;
      *(undefined4 *)(this + 0x30) = 0;
      *(undefined2 *)(this + 0x18) = 0;
      this[0x1a] = (format_string_parser<char>)0x0;
      this[0x2c] = (format_string_parser<char>)0x0;
      *(undefined4 *)(this + 0x10) = 0x16;
      return false;
    }
    *(longlong *)(this + 0x20) = lVar3;
    *(longlong *)(this + 8) = local_res8[0];
  }
  return true;
}



/* ---- scan_optional_length_modifier @ 1800093d0 ---- */

/* Library Function - Single Match
    private: void __cdecl
   __crt_stdio_input::format_string_parser<char>::scan_optional_length_modifier(void) __ptr64
   
   Libraries: Visual Studio 2015 Debug, Visual Studio 2015 Release */

void __thiscall
__crt_stdio_input::format_string_parser<char>::scan_optional_length_modifier
          (format_string_parser<char> *this)

{
  char cVar1;
  char *pcVar2;
  
  pcVar2 = *(char **)(this + 8);
  if (*pcVar2 == 'I') {
    cVar1 = pcVar2[1];
    if ((cVar1 == '3') && (pcVar2[2] == '2')) {
      *(undefined4 *)(this + 0x28) = 9;
      *(char **)(this + 8) = pcVar2 + 3;
      return;
    }
    if ((cVar1 == '6') && (pcVar2[2] == '4')) {
      *(char **)(this + 8) = pcVar2 + 3;
    }
    else {
      if (0x20 < (byte)(cVar1 + 0xa8U)) {
        return;
      }
      if ((0x120821001U >> ((ulonglong)(byte)(cVar1 + 0xa8U) & 0x3f) & 1) == 0) {
        return;
      }
      *(char **)(this + 8) = pcVar2 + 1;
    }
    *(undefined4 *)(this + 0x28) = 10;
  }
  else {
    if (*pcVar2 == 'L') {
      *(undefined4 *)(this + 0x28) = 8;
      *(char **)(this + 8) = pcVar2 + 1;
      return;
    }
    if (*pcVar2 == 'T') {
      *(undefined4 *)(this + 0x28) = 0xb;
      *(char **)(this + 8) = pcVar2 + 1;
      return;
    }
    if (*pcVar2 == 'h') {
      if (pcVar2[1] != 'h') {
        *(char **)(this + 8) = pcVar2 + 1;
        *(undefined4 *)(this + 0x28) = 2;
        return;
      }
      *(undefined4 *)(this + 0x28) = 1;
      *(char **)(this + 8) = pcVar2 + 2;
      return;
    }
    if (*pcVar2 == 'j') {
      *(undefined4 *)(this + 0x28) = 5;
      *(char **)(this + 8) = pcVar2 + 1;
      return;
    }
    if (*pcVar2 == 'l') {
      if (pcVar2[1] != 'l') {
        *(char **)(this + 8) = pcVar2 + 1;
        *(undefined4 *)(this + 0x28) = 3;
        return;
      }
      *(undefined4 *)(this + 0x28) = 4;
      *(char **)(this + 8) = pcVar2 + 2;
      return;
    }
    if (*pcVar2 == 't') {
      *(undefined4 *)(this + 0x28) = 7;
      *(char **)(this + 8) = pcVar2 + 1;
      return;
    }
    if (*pcVar2 == 'z') {
      *(undefined4 *)(this + 0x28) = 6;
      *(char **)(this + 8) = pcVar2 + 1;
      return;
    }
  }
  return;
}



/* ---- scan_scanset_range @ 1800094fc ---- */

/* WARNING: Removing unreachable block (ram,0x0001800095fd) */
/* WARNING: Removing unreachable block (ram,0x0001800095ce) */
/* Library Function - Single Match
    private: bool __cdecl __crt_stdio_input::format_string_parser<char>::scan_scanset_range(void)
   __ptr64
   
   Libraries: Visual Studio 2015 Debug, Visual Studio 2015 Release */

bool __thiscall
__crt_stdio_input::format_string_parser<char>::scan_scanset_range(format_string_parser<char> *this)

{
  format_string_parser<char> *pfVar1;
  byte bVar2;
  byte *pbVar3;
  byte *pbVar4;
  byte bVar5;
  byte bVar6;
  longlong lVar7;
  format_string_parser<char> *pfVar8;
  bool bVar9;
  
  pfVar1 = this + 0x34;
  if (pfVar1 == (format_string_parser<char> *)0x0) {
    *(undefined8 *)(this + 0x10) = 0xc;
    *(undefined2 *)(this + 0x18) = 0;
    this[0x1a] = (format_string_parser<char>)0x0;
    *(undefined8 *)(this + 0x20) = 0;
    *(undefined4 *)(this + 0x28) = 0;
    this[0x2c] = (format_string_parser<char>)0x0;
    *(undefined4 *)(this + 0x30) = 0;
  }
  else {
    FUN_180003320((undefined1 (*) [16])pfVar1,0,0x20);
    bVar9 = **(char **)(this + 8) == '^';
    if (bVar9) {
      *(char **)(this + 8) = *(char **)(this + 8) + 1;
    }
    if (**(char **)(this + 8) == ']') {
      *(char **)(this + 8) = *(char **)(this + 8) + 1;
      this[0x3f] = (format_string_parser<char>)((byte)this[0x3f] | 0x20);
    }
    pbVar3 = *(byte **)(this + 8);
    bVar6 = *pbVar3;
    while (bVar6 != 0x5d) {
      pbVar4 = *(byte **)(this + 8);
      bVar6 = *pbVar4;
      if (bVar6 == 0) break;
      if (((bVar6 == 0x2d) && (pbVar4 != pbVar3)) && (bVar2 = pbVar4[1], bVar2 != 0x5d)) {
        bVar6 = pbVar4[-1];
        bVar5 = bVar2;
        if (bVar2 < bVar6) {
          bVar5 = bVar6;
          bVar6 = bVar2;
        }
        for (; bVar6 != (byte)(bVar5 + 1); bVar6 = bVar6 + 1) {
          this[(ulonglong)(bVar6 >> 3) + 0x34] =
               (format_string_parser<char>)
               ((byte)this[(ulonglong)(bVar6 >> 3) + 0x34] | (byte)(1 << (bVar6 & 7)));
        }
      }
      else {
        this[(ulonglong)(bVar6 >> 3) + 0x34] =
             (format_string_parser<char>)
             ((byte)this[(ulonglong)(bVar6 >> 3) + 0x34] | (byte)(1 << (bVar6 & 7)));
      }
      *(longlong *)(this + 8) = *(longlong *)(this + 8) + 1;
      bVar6 = **(byte **)(this + 8);
    }
    if (**(char **)(this + 8) != '\0') {
      if (bVar9) {
        lVar7 = (longlong)(this + 0x54) - (longlong)pfVar1;
        if (this + 0x54 < pfVar1) {
          lVar7 = 0;
        }
        if (lVar7 != 0) {
          pfVar8 = pfVar1;
          do {
            *pfVar8 = (format_string_parser<char>)~(byte)*pfVar8;
            pfVar8 = pfVar8 + 1;
          } while ((longlong)pfVar8 - (longlong)pfVar1 != lVar7);
        }
      }
      *(longlong *)(this + 8) = *(longlong *)(this + 8) + 1;
      return true;
    }
    *(undefined8 *)(this + 0x10) = 0x16;
    *(undefined2 *)(this + 0x18) = 0;
    this[0x1a] = (format_string_parser<char>)0x0;
    *(undefined8 *)(this + 0x20) = 0;
    *(undefined4 *)(this + 0x28) = 0;
    this[0x2c] = (format_string_parser<char>)0x0;
    *(undefined4 *)(this + 0x30) = 0;
  }
  return false;
}



/* ---- write_character @ 180009690 ---- */

/* Library Function - Single Match
    private: bool __cdecl __crt_stdio_input::input_processor<char,class
   __crt_stdio_input::string_input_adapter<char> >::write_character(wchar_t __unaligned * __ptr64
   const,unsigned __int64,wchar_t __unaligned * __ptr64 & __ptr64,unsigned __int64 & __ptr64,char)
   __ptr64
   
   Library: Visual Studio 2015 Release */

bool __thiscall
__crt_stdio_input::input_processor<char,__crt_stdio_input::string_input_adapter<char>_>::
write_character(input_processor<char,__crt_stdio_input::string_input_adapter<char>_> *this,
               wchar_t *param_1,__uint64 param_2,wchar_t **param_3,__uint64 *param_4,char param_5)

{
  undefined1 *puVar1;
  char cVar2;
  ushort *puVar3;
  ulonglong uVar4;
  wchar_t local_res8 [4];
  undefined1 uStack0000000000000031;
  
  cVar2 = param_5;
  uVar4 = (ulonglong)(byte)param_5;
  uStack0000000000000031 = 0;
  puVar3 = __pctype_func();
  if ((puVar3[uVar4] & 0x8000) != 0) {
    puVar1 = *(undefined1 **)(this + 0x18);
    if (puVar1 == *(undefined1 **)(this + 0x10)) {
      uStack0000000000000031 = 0xff;
    }
    else {
      uStack0000000000000031 = *puVar1;
      *(undefined1 **)(this + 0x18) = puVar1 + 1;
    }
  }
  local_res8[0] = L'?';
  _mbtowc_l(local_res8,&param_5,(longlong)(int)(*(_locale_t *)(this + 0x78))->locinfo->lc_collate_cp
            ,*(_locale_t *)(this + 0x78));
  **param_3 = (short)cVar2;
  *param_3 = *param_3 + 1;
  *param_4 = *param_4 - 1;
  return true;
}



/* ---- write_integer @ 18000972c ---- */

/* Library Function - Single Match
    private: bool __cdecl __crt_stdio_input::input_processor<char,class
   __crt_stdio_input::string_input_adapter<char> >::write_integer(unsigned __int64,bool) __ptr64
   
   Library: Visual Studio 2015 Release */

bool __thiscall
__crt_stdio_input::input_processor<char,__crt_stdio_input::string_input_adapter<char>_>::
write_integer(input_processor<char,__crt_stdio_input::string_input_adapter<char>_> *this,
             __uint64 param_1,bool param_2)

{
  __uint64 *p_Var1;
  bool bVar2;
  ulong *puVar3;
  __uint64 _Var4;
  
  *(longlong *)(this + 0x80) = *(longlong *)(this + 0x80) + 8;
  p_Var1 = *(__uint64 **)(*(longlong *)(this + 0x80) + -8);
  if (p_Var1 == (__uint64 *)0x0) {
    puVar3 = __doserrno();
    *puVar3 = 0x16;
    FUN_18000aff4();
LAB_180009761:
    bVar2 = false;
  }
  else {
    if (param_2) {
      *(longlong *)(this + 0x88) = *(longlong *)(this + 0x88) + 1;
    }
    _Var4 = format_string_parser<char>::length((format_string_parser<char> *)(this + 0x20));
    if (_Var4 == 1) {
      *(char *)p_Var1 = (char)param_1;
    }
    else if (_Var4 == 2) {
      *(short *)p_Var1 = (short)param_1;
    }
    else if (_Var4 == 4) {
      *(int *)p_Var1 = (int)param_1;
    }
    else {
      if (_Var4 != 8) goto LAB_180009761;
      *p_Var1 = param_1;
    }
    bVar2 = true;
  }
  return bVar2;
}



/* ---- FUN_1800097b0 @ 1800097b0 ---- */

/* WARNING: Function: __security_check_cookie replaced with injection: security_check_cookie */

int FUN_1800097b0(undefined8 param_1,longlong param_2,longlong param_3,longlong param_4,
                 __crt_locale_pointers *param_5,undefined8 param_6)

{
  int iVar1;
  ulong *puVar2;
  undefined1 auStack_128 [32];
  longlong local_108;
  longlong lStack_100;
  longlong local_f8;
  longlong local_f0;
  undefined1 local_e8 [16];
  char local_d8;
  undefined8 local_c8;
  longlong local_c0;
  longlong lStack_b8;
  longlong local_b0;
  undefined8 local_a8;
  longlong local_a0;
  undefined4 local_98;
  undefined4 local_94;
  undefined2 local_90;
  undefined1 local_8e;
  undefined8 local_88;
  undefined4 local_80;
  undefined1 local_7c;
  undefined4 local_78;
  undefined1 local_74 [36];
  undefined1 *local_50;
  undefined8 local_48;
  undefined8 local_40;
  undefined8 local_38;
  ulonglong local_28;
  
  local_28 = DAT_18001c000 ^ (ulonglong)auStack_128;
  if ((param_2 == 0) || (param_4 == 0)) {
    puVar2 = __doserrno();
    *puVar2 = 0x16;
    FUN_18000aff4();
    iVar1 = -1;
  }
  else {
    if (param_3 == -1) {
      param_3 = -1;
      do {
        param_3 = param_3 + 1;
      } while (*(char *)(param_2 + param_3) != '\0');
    }
    _LocaleUpdate::_LocaleUpdate((_LocaleUpdate *)&local_f0,param_5);
    lStack_100 = param_3 + param_2;
    local_98 = 0;
    local_108 = param_2;
    local_f8 = param_2;
    local_c8 = param_1;
    local_c0 = param_2;
    lStack_b8 = lStack_100;
    local_b0 = param_2;
    local_a8 = param_1;
    local_a0 = param_4;
    FUN_180003320((undefined1 (*) [16])local_74,0,0x20);
    local_50 = local_e8;
    local_94 = 0;
    local_48 = param_6;
    local_90 = 0;
    local_8e = 0;
    local_88 = 0;
    local_80 = 0;
    local_7c = 0;
    local_78 = 0;
    local_40 = 0;
    local_38 = 0;
    iVar1 = __crt_stdio_input::input_processor<char,__crt_stdio_input::string_input_adapter<char>_>
            ::process((input_processor<char,__crt_stdio_input::string_input_adapter<char>_> *)
                      &local_c8);
    if (local_d8 != '\0') {
      *(uint *)(local_f0 + 0x3a8) = *(uint *)(local_f0 + 0x3a8) & 0xfffffffd;
    }
  }
  return iVar1;
}



/* ---- memcpy_s @ 1800098f8 ---- */

/* Library Function - Single Match
    memcpy_s
   
   Libraries: Visual Studio 2010 Release, Visual Studio 2012 Release, Visual Studio 2015 Debug,
   Visual Studio 2015 Release */

errno_t __cdecl memcpy_s(void *_Dst,rsize_t _DstSize,void *_Src,rsize_t _MaxCount)

{
  ulong *puVar1;
  ulong uVar2;
  
  if (_MaxCount == 0) {
LAB_180009915:
    uVar2 = 0;
  }
  else {
    if (_Dst == (void *)0x0) {
LAB_18000991e:
      puVar1 = __doserrno();
      uVar2 = 0x16;
    }
    else {
      if ((_Src != (void *)0x0) && (_MaxCount <= _DstSize)) {
        FUN_180002ed0(_Dst,_Src,_MaxCount);
        goto LAB_180009915;
      }
      FUN_180003320(_Dst,0,_DstSize);
      if (_Src == (void *)0x0) goto LAB_18000991e;
      if (_MaxCount <= _DstSize) {
        return 0x16;
      }
      puVar1 = __doserrno();
      uVar2 = 0x22;
    }
    *puVar1 = uVar2;
    FUN_18000aff4();
  }
  return uVar2;
}



/* ---- wcsncat_s @ 180009980 ---- */

/* Library Function - Single Match
    wcsncat_s
   
   Library: Visual Studio 2015 Release */

errno_t __cdecl wcsncat_s(wchar_t *_Dst,rsize_t _SizeInWords,wchar_t *_Src,rsize_t _MaxCount)

{
  wchar_t wVar1;
  rsize_t rVar2;
  ulong *puVar3;
  wchar_t *pwVar4;
  rsize_t rVar5;
  ulong uVar6;
  longlong lVar7;
  
  if (_MaxCount == 0) {
    if (_Dst == (wchar_t *)0x0) {
      if (_SizeInWords == 0) {
        return 0;
      }
    }
    else {
LAB_1800099c9:
      if (_SizeInWords != 0) {
        pwVar4 = _Dst;
        rVar5 = _SizeInWords;
        if ((_MaxCount == 0) || (_Src != (wchar_t *)0x0)) {
          do {
            if (*pwVar4 == L'\0') break;
            pwVar4 = pwVar4 + 1;
            rVar5 = rVar5 - 1;
          } while (rVar5 != 0);
          if (rVar5 != 0) {
            rVar2 = _MaxCount;
            if (_MaxCount == 0xffffffffffffffff) {
              lVar7 = (longlong)_Src - (longlong)pwVar4;
              do {
                wVar1 = *(wchar_t *)(lVar7 + (longlong)pwVar4);
                *pwVar4 = wVar1;
                pwVar4 = pwVar4 + 1;
                if (wVar1 == L'\0') break;
                rVar5 = rVar5 - 1;
              } while (rVar5 != 0);
            }
            else {
              for (; rVar2 != 0; rVar2 = rVar2 - 1) {
                wVar1 = *_Src;
                _Src = _Src + 1;
                *pwVar4 = wVar1;
                pwVar4 = pwVar4 + 1;
                if ((wVar1 == L'\0') || (rVar5 = rVar5 - 1, rVar5 == 0)) break;
              }
              if (rVar2 == 0) {
                *pwVar4 = L'\0';
              }
            }
            if (rVar5 != 0) {
              return 0;
            }
            if (_MaxCount == 0xffffffffffffffff) {
              _Dst[_SizeInWords - 1] = L'\0';
              return 0x50;
            }
            *_Dst = L'\0';
            puVar3 = __doserrno();
            uVar6 = 0x22;
            goto LAB_1800099ac;
          }
          *_Dst = L'\0';
        }
        else {
          *_Dst = L'\0';
        }
      }
    }
  }
  else if (_Dst != (wchar_t *)0x0) goto LAB_1800099c9;
  puVar3 = __doserrno();
  uVar6 = 0x16;
LAB_1800099ac:
  *puVar3 = uVar6;
  FUN_18000aff4();
  return uVar6;
}



/* ---- strcpy_s @ 180009a80 ---- */

/* Library Function - Single Match
    strcpy_s
   
   Libraries: Visual Studio 2015 Release, Visual Studio 2017 Release, Visual Studio 2019 Release */

errno_t __cdecl strcpy_s(char *_Dst,rsize_t _SizeInBytes,char *_Src)

{
  char cVar1;
  ulong *puVar2;
  ulong uVar3;
  char *pcVar4;
  
  if ((_Dst != (char *)0x0) && (_SizeInBytes != 0)) {
    if (_Src != (char *)0x0) {
      pcVar4 = _Dst;
      do {
        cVar1 = pcVar4[(longlong)_Src - (longlong)_Dst];
        *pcVar4 = cVar1;
        pcVar4 = pcVar4 + 1;
        if (cVar1 == '\0') break;
        _SizeInBytes = _SizeInBytes - 1;
      } while (_SizeInBytes != 0);
      if (_SizeInBytes != 0) {
        return 0;
      }
      *_Dst = '\0';
      puVar2 = __doserrno();
      uVar3 = 0x22;
      goto LAB_180009aa3;
    }
    *_Dst = '\0';
  }
  puVar2 = __doserrno();
  uVar3 = 0x16;
LAB_180009aa3:
  *puVar2 = uVar3;
  FUN_18000aff4();
  return uVar3;
}



/* ---- strncpy_s @ 180009ae0 ---- */

/* Library Function - Single Match
    strncpy_s
   
   Library: Visual Studio 2015 Release */

errno_t __cdecl strncpy_s(char *_Dst,rsize_t _SizeInBytes,char *_Src,rsize_t _MaxCount)

{
  char cVar1;
  ulong *puVar2;
  char *pcVar3;
  ulong uVar4;
  rsize_t rVar5;
  rsize_t rVar6;
  
  if (_MaxCount == 0) {
    if (_Dst == (char *)0x0) {
      if (_SizeInBytes == 0) {
        return 0;
      }
    }
    else {
LAB_180009b26:
      if (_SizeInBytes != 0) {
        if (_MaxCount == 0) {
          *_Dst = '\0';
          return 0;
        }
        if (_Src != (char *)0x0) {
          pcVar3 = _Dst;
          rVar5 = _SizeInBytes;
          rVar6 = _MaxCount;
          if (_MaxCount == 0xffffffffffffffff) {
            do {
              cVar1 = pcVar3[(longlong)_Src - (longlong)_Dst];
              *pcVar3 = cVar1;
              pcVar3 = pcVar3 + 1;
              if (cVar1 == '\0') break;
              rVar5 = rVar5 - 1;
            } while (rVar5 != 0);
          }
          else {
            do {
              cVar1 = pcVar3[(longlong)_Src - (longlong)_Dst];
              *pcVar3 = cVar1;
              pcVar3 = pcVar3 + 1;
              if ((cVar1 == '\0') || (rVar5 = rVar5 - 1, rVar5 == 0)) break;
              rVar6 = rVar6 - 1;
            } while (rVar6 != 0);
            if (rVar6 == 0) {
              *pcVar3 = '\0';
            }
          }
          if (rVar5 != 0) {
            return 0;
          }
          if (_MaxCount == 0xffffffffffffffff) {
            _Dst[_SizeInBytes - 1] = '\0';
            return 0x50;
          }
          *_Dst = '\0';
          puVar2 = __doserrno();
          uVar4 = 0x22;
          goto LAB_180009b09;
        }
        *_Dst = '\0';
      }
    }
  }
  else if (_Dst != (char *)0x0) goto LAB_180009b26;
  puVar2 = __doserrno();
  uVar4 = 0x16;
LAB_180009b09:
  *puVar2 = uVar4;
  FUN_18000aff4();
  return uVar4;
}



/* ---- _initterm @ 180009bb4 ---- */

/* Library Function - Single Match
    _initterm
   
   Library: Visual Studio 2015 Release */

void _initterm(undefined8 *param_1,undefined8 *param_2)

{
  code *pcVar1;
  ulonglong uVar2;
  ulonglong uVar3;
  
  uVar2 = 0;
  uVar3 = (ulonglong)((longlong)param_2 + (7 - (longlong)param_1)) >> 3;
  if (param_2 < param_1) {
    uVar3 = uVar2;
  }
  if (uVar3 != 0) {
    do {
      pcVar1 = (code *)*param_1;
      if (pcVar1 != (code *)0x0) {
        (*(code *)PTR__guard_check_icall_180012238)(pcVar1);
        (*pcVar1)();
      }
      param_1 = param_1 + 1;
      uVar2 = uVar2 + 1;
    } while (uVar2 != uVar3);
  }
  return;
}



/* ---- _initterm_e @ 180009c2c ---- */

/* Library Function - Single Match
    _initterm_e
   
   Library: Visual Studio 2015 Release */

undefined8 _initterm_e(undefined8 *param_1,undefined8 *param_2)

{
  code *pcVar1;
  undefined8 uVar2;
  
  do {
    if (param_1 == param_2) {
      return 0;
    }
    pcVar1 = (code *)*param_1;
    if (pcVar1 != (code *)0x0) {
      (*(code *)PTR__guard_check_icall_180012238)(pcVar1);
      uVar2 = (*pcVar1)();
      if ((int)uVar2 != 0) {
        return uVar2;
      }
    }
    param_1 = param_1 + 1;
  } while( true );
}



/* ---- _seh_filter_dll @ 180009c78 ---- */

/* Library Function - Single Match
    _seh_filter_dll
   
   Library: Visual Studio 2015 Release */

undefined4 _seh_filter_dll(int param_1,undefined8 param_2)

{
  undefined4 uVar1;
  
  if (param_1 != -0x1f928c9d) {
    return 0;
  }
  uVar1 = _seh_filter_exe(-0x1f928c9d,param_2);
  return uVar1;
}



/* ---- _seh_filter_exe @ 180009c8c ---- */

/* Library Function - Single Match
    _seh_filter_exe
   
   Library: Visual Studio 2015 Release */

undefined4 _seh_filter_exe(int param_1,undefined8 param_2)

{
  int iVar1;
  undefined4 uVar2;
  int *piVar3;
  code *pcVar4;
  undefined8 uVar5;
  __acrt_ptd *p_Var6;
  int *piVar7;
  int *piVar8;
  
  p_Var6 = __acrt_getptd_noexit();
  if (p_Var6 != (__acrt_ptd *)0x0) {
    piVar3 = *(int **)p_Var6;
    for (piVar8 = piVar3;
        (piVar7 = (int *)0x0, piVar8 != piVar3 + 0x30 && (piVar7 = piVar8, *piVar8 != param_1));
        piVar8 = piVar8 + 4) {
    }
    if ((piVar7 != (int *)0x0) && (pcVar4 = *(code **)(piVar7 + 2), pcVar4 != (code *)0x0)) {
      if (pcVar4 == (code *)0x5) {
        piVar7[2] = 0;
        piVar7[3] = 0;
        return 1;
      }
      if (pcVar4 != (code *)0x1) {
        uVar5 = *(undefined8 *)(p_Var6 + 8);
        *(undefined8 *)(p_Var6 + 8) = param_2;
        iVar1 = piVar7[1];
        if (iVar1 == 8) {
          for (piVar8 = piVar3 + 0xc; piVar8 != piVar3 + 0x30; piVar8 = piVar8 + 4) {
            piVar8[2] = 0;
            piVar8[3] = 0;
          }
          uVar2 = *(undefined4 *)(p_Var6 + 0x10);
          if (*piVar7 == -0x3fffff73) {
            *(undefined4 *)(p_Var6 + 0x10) = 0x82;
          }
          else if (*piVar7 == -0x3fffff72) {
            *(undefined4 *)(p_Var6 + 0x10) = 0x83;
          }
          else if (*piVar7 == -0x3fffff71) {
            *(undefined4 *)(p_Var6 + 0x10) = 0x86;
          }
          else if (*piVar7 == -0x3fffff70) {
            *(undefined4 *)(p_Var6 + 0x10) = 0x81;
          }
          else if (*piVar7 == -0x3fffff6f) {
            *(undefined4 *)(p_Var6 + 0x10) = 0x84;
          }
          else if (*piVar7 == -0x3fffff6e) {
            *(undefined4 *)(p_Var6 + 0x10) = 0x8a;
          }
          else if (*piVar7 == -0x3fffff6d) {
            *(undefined4 *)(p_Var6 + 0x10) = 0x85;
          }
          else if (*piVar7 == -0x3ffffd4c) {
            *(undefined4 *)(p_Var6 + 0x10) = 0x8e;
          }
          else if (*piVar7 == -0x3ffffd4b) {
            *(undefined4 *)(p_Var6 + 0x10) = 0x8d;
          }
          (*(code *)PTR__guard_check_icall_180012238)(pcVar4);
          (*pcVar4)(8,*(undefined4 *)(p_Var6 + 0x10));
          *(undefined4 *)(p_Var6 + 0x10) = uVar2;
        }
        else {
          piVar7[2] = 0;
          piVar7[3] = 0;
          (*(code *)PTR__guard_check_icall_180012238)(pcVar4);
          (*pcVar4)(iVar1);
        }
        *(undefined8 *)(p_Var6 + 8) = uVar5;
      }
      return 0xffffffff;
    }
  }
  return 0;
}



/* ---- FUN_180009e1c @ 180009e1c ---- */

bool FUN_180009e1c(int param_1)

{
  return param_1 == -0x1f928c9d;
}



/* ---- common_exit @ 180009e28 ---- */

/* Library Function - Single Match
    void __cdecl common_exit(int,enum _crt_exit_cleanup_mode,enum _crt_exit_return_mode)
   
   Library: Visual Studio 2015 Release */

void __cdecl common_exit(int param_1,_crt_exit_cleanup_mode param_2,_crt_exit_return_mode param_3)

{
  byte bVar1;
  byte bVar2;
  HMODULE pHVar3;
  int *piVar4;
  undefined *puVar5;
  code *pcVar6;
  
  if ((((param_3 == 0) && (pHVar3 = GetModuleHandleW((LPCWSTR)0x0), pHVar3 != (HMODULE)0x0)) &&
      ((short)pHVar3->unused == 0x5a4d)) &&
     (((piVar4 = (int *)((longlong)&pHVar3->unused + (longlong)pHVar3[0xf].unused),
       *piVar4 == 0x4550 && ((short)piVar4[6] == 0x20b)) &&
      ((0xe < (uint)piVar4[0x21] && (piVar4[0x3e] != 0)))))) {
    try_cor_exit_process(param_1);
  }
  __acrt_lock(2);
  if (DAT_18001d080 != '\0') goto LAB_180009f62;
  LOCK();
  DAT_18001d070 = 1;
  UNLOCK();
  if (param_2 == 0) {
    bVar2 = (byte)DAT_18001c000 & 0x3f;
    bVar1 = 0x40 - bVar2 & 0x3f;
    if (DAT_18001d078 != (((ulonglong)(0 >> bVar1) | 0L << 0x40 - bVar1) ^ DAT_18001c000)) {
      pcVar6 = (code *)((DAT_18001c000 ^ DAT_18001d078) >> bVar2 |
                       (DAT_18001c000 ^ DAT_18001d078) << 0x40 - bVar2);
      (*(code *)PTR__guard_check_icall_180012238)(pcVar6);
      (*pcVar6)(0,0,0);
    }
    puVar5 = &DAT_18001d1b8;
LAB_180009f17:
    _execute_onexit_table(puVar5);
  }
  else if (param_2 == 1) {
    puVar5 = &DAT_18001d1d0;
    goto LAB_180009f17;
  }
  if (param_2 == 0) {
    _initterm((undefined8 *)&DAT_180012288,(undefined8 *)&DAT_1800122a8);
  }
  _initterm((undefined8 *)&DAT_1800122b0,(undefined8 *)&DAT_1800122b8);
  if (param_3 == 0) {
    DAT_18001d080 = '\x01';
  }
LAB_180009f62:
  __acrt_unlock(2);
  if (param_3 != 0) {
    return;
  }
  exit_or_terminate_process(param_1);
  pcVar6 = (code *)swi(3);
  (*pcVar6)();
  return;
}



/* ---- exit_or_terminate_process @ 180009f94 ---- */

/* Library Function - Single Match
    void __cdecl exit_or_terminate_process(unsigned int)
   
   Library: Visual Studio 2015 Release */

void __cdecl exit_or_terminate_process(uint param_1)

{
  bool bVar1;
  HANDLE hProcess;
  
  bVar1 = __acrt_is_packaged_app();
  if ((bVar1) && ((*(uint *)((longlong)ProcessEnvironmentBlock + 0xbc) >> 8 & 1) == 0)) {
    hProcess = GetCurrentProcess();
    TerminateProcess(hProcess,param_1);
  }
  try_cor_exit_process(param_1);
                    /* WARNING: Subroutine does not return */
  ExitProcess(param_1);
}



/* ---- try_cor_exit_process @ 180009fe0 ---- */

/* Library Function - Single Match
    void __cdecl try_cor_exit_process(unsigned int)
   
   Library: Visual Studio 2015 Release */

void __cdecl try_cor_exit_process(uint param_1)

{
  BOOL BVar1;
  FARPROC pFVar2;
  HMODULE local_res10 [3];
  
  local_res10[0] = (HMODULE)0x0;
  BVar1 = GetModuleHandleExW(0,L"mscoree.dll",local_res10);
  if (BVar1 != 0) {
    pFVar2 = GetProcAddress(local_res10[0],"CorExitProcess");
    if (pFVar2 != (FARPROC)0x0) {
      (*(code *)PTR__guard_check_icall_180012238)(pFVar2);
      (*pFVar2)((ulonglong)param_1);
    }
  }
  if (local_res10[0] != (HMODULE)0x0) {
    FreeLibrary(local_res10[0]);
  }
  return;
}



/* ---- FUN_18000a04c @ 18000a04c ---- */

void FUN_18000a04c(undefined8 param_1)

{
  DAT_18001d078 = param_1;
  return;
}



/* ---- _cexit @ 18000a054 ---- */

/* Library Function - Single Match
    _cexit
   
   Library: Visual Studio 2015 Release */

void __cdecl _cexit(void)

{
  common_exit(0,0,1);
  return;
}



/* ---- FUN_18000a064 @ 18000a064 ---- */

void FUN_18000a064(int param_1)

{
  common_exit(param_1,2,0);
  return;
}



/* ---- FUN_18000a070 @ 18000a070 ---- */

undefined4 FUN_18000a070(void)

{
  return DAT_18001d070;
}



/* ---- parse_command_line<char> @ 18000a078 ---- */

/* Library Function - Single Match
    void __cdecl parse_command_line<char>(char * __ptr64,char * __ptr64 * __ptr64,char *
   __ptr64,unsigned __int64 * __ptr64,unsigned __int64 * __ptr64)
   
   Library: Visual Studio 2015 Release */

void __cdecl
parse_command_line<char>
          (char *param_1,char **param_2,char *param_3,__uint64 *param_4,__uint64 *param_5)

{
  bool bVar1;
  bool bVar2;
  uint uVar3;
  int iVar4;
  char *pcVar5;
  char cVar6;
  
  *param_5 = 0;
  *param_4 = 1;
  if (param_2 != (char **)0x0) {
    *param_2 = param_3;
    param_2 = param_2 + 1;
  }
  bVar2 = false;
  do {
    if (*param_1 == '\"') {
      bVar2 = !bVar2;
      cVar6 = '\"';
      pcVar5 = param_1 + 1;
    }
    else {
      *param_5 = *param_5 + 1;
      if (param_3 != (char *)0x0) {
        *param_3 = *param_1;
        param_3 = param_3 + 1;
      }
      cVar6 = *param_1;
      pcVar5 = param_1 + 1;
      iVar4 = _ismbblead((int)cVar6);
      if (iVar4 != 0) {
        *param_5 = *param_5 + 1;
        if (param_3 != (char *)0x0) {
          *param_3 = *pcVar5;
          param_3 = param_3 + 1;
        }
        pcVar5 = param_1 + 2;
      }
      if (cVar6 == '\0') {
        pcVar5 = pcVar5 + -1;
        goto LAB_18000a12a;
      }
    }
    param_1 = pcVar5;
  } while ((bVar2) || ((cVar6 != ' ' && (cVar6 != '\t'))));
  if (param_3 != (char *)0x0) {
    param_3[-1] = '\0';
  }
LAB_18000a12a:
  bVar2 = false;
  while (*pcVar5 != '\0') {
    for (; (*pcVar5 == ' ' || (*pcVar5 == '\t')); pcVar5 = pcVar5 + 1) {
    }
    if (*pcVar5 == '\0') break;
    if (param_2 != (char **)0x0) {
      *param_2 = param_3;
      param_2 = param_2 + 1;
    }
    *param_4 = *param_4 + 1;
    while( true ) {
      bVar1 = true;
      uVar3 = 0;
      for (; *pcVar5 == '\\'; pcVar5 = pcVar5 + 1) {
        uVar3 = uVar3 + 1;
      }
      if (*pcVar5 == '\"') {
        if ((uVar3 & 1) == 0) {
          if ((bVar2) && (pcVar5[1] == '\"')) {
            pcVar5 = pcVar5 + 1;
          }
          else {
            bVar1 = false;
            bVar2 = !bVar2;
          }
        }
        uVar3 = uVar3 >> 1;
      }
      while (uVar3 != 0) {
        uVar3 = uVar3 - 1;
        if (param_3 != (char *)0x0) {
          *param_3 = '\\';
          param_3 = param_3 + 1;
        }
        *param_5 = *param_5 + 1;
      }
      cVar6 = *pcVar5;
      if ((cVar6 == '\0') || ((!bVar2 && ((cVar6 == ' ' || (cVar6 == '\t')))))) break;
      if (bVar1) {
        if (param_3 != (char *)0x0) {
          *param_3 = cVar6;
          param_3 = param_3 + 1;
        }
        iVar4 = _ismbblead((int)*pcVar5);
        if (iVar4 != 0) {
          *param_5 = *param_5 + 1;
          pcVar5 = pcVar5 + 1;
          if (param_3 != (char *)0x0) {
            *param_3 = *pcVar5;
            param_3 = param_3 + 1;
          }
        }
        *param_5 = *param_5 + 1;
      }
      pcVar5 = pcVar5 + 1;
    }
    if (param_3 != (char *)0x0) {
      *param_3 = '\0';
      param_3 = param_3 + 1;
    }
    *param_5 = *param_5 + 1;
  }
  if (param_2 != (char **)0x0) {
    *param_2 = (char *)0x0;
  }
  *param_4 = *param_4 + 1;
  return;
}



/* ---- __acrt_allocate_buffer_for_argv @ 18000a234 ---- */

/* Library Function - Single Match
    __acrt_allocate_buffer_for_argv
   
   Library: Visual Studio 2015 Release */

LPVOID __acrt_allocate_buffer_for_argv(ulonglong param_1,ulonglong param_2,ulonglong param_3)

{
  undefined1 auVar1 [16];
  LPVOID pvVar2;
  
  if ((param_1 < 0x1fffffffffffffff) &&
     (auVar1._8_8_ = 0, auVar1._0_8_ = param_3,
     param_2 < SUB168((ZEXT816(0) << 0x40 | ZEXT816(0xffffffffffffffff)) / auVar1,0))) {
    if (param_2 * param_3 < param_1 * -8 - 1) {
      pvVar2 = _calloc_base(param_2 * param_3 + param_1 * 8,1);
      _free_base((LPVOID)0x0);
      return pvVar2;
    }
  }
  return (LPVOID)0x0;
}



/* ---- _configure_narrow_argv @ 18000a298 ---- */

/* WARNING: Globals starting with '_' overlap smaller symbols at the same address */
/* Library Function - Single Match
    _configure_narrow_argv
   
   Library: Visual Studio 2015 Release */

ulonglong _configure_narrow_argv(int param_1)

{
  char **ppcVar1;
  __uint64 _Var2;
  ulong *puVar3;
  char **ppcVar4;
  ulonglong uVar5;
  char *pcVar6;
  ulonglong uVar7;
  char **local_res10;
  __uint64 local_res18;
  __uint64 local_res20;
  
  if (1 < param_1 - 1U) {
    puVar3 = __doserrno();
    *puVar3 = 0x16;
    FUN_18000aff4();
    return 0x16;
  }
  __acrt_initialize_multibyte();
  GetModuleFileNameA((HMODULE)0x0,&DAT_18001d090,0x104);
  uVar7 = 0;
  _DAT_18001da20 = &DAT_18001d090;
  if ((DAT_18001da10 == (char *)0x0) || (pcVar6 = DAT_18001da10, *DAT_18001da10 == '\0')) {
    pcVar6 = &DAT_18001d090;
  }
  local_res18 = 0;
  local_res20 = 0;
  parse_command_line<char>(pcVar6,(char **)0x0,(char *)0x0,&local_res18,&local_res20);
  _Var2 = local_res18;
  ppcVar4 = __acrt_allocate_buffer_for_argv(local_res18,local_res20,1);
  if (ppcVar4 == (char **)0x0) {
    puVar3 = __doserrno();
    uVar7 = 0xc;
    *puVar3 = 0xc;
  }
  else {
    parse_command_line<char>(pcVar6,ppcVar4,(char *)(ppcVar4 + _Var2),&local_res18,&local_res20);
    if (param_1 != 1) {
      local_res10 = (char **)0x0;
      uVar5 = thunk_FUN_18000c56c((longlong *)ppcVar4,&local_res10);
      ppcVar1 = local_res10;
      if ((int)uVar5 != 0) {
        _free_base(local_res10);
        local_res10 = (char **)0x0;
        _free_base(ppcVar4);
        return uVar5 & 0xffffffff;
      }
      _DAT_18001d9fc = 0;
      pcVar6 = *local_res10;
      uVar5 = uVar7;
      while (pcVar6 != (char *)0x0) {
        local_res10 = local_res10 + 1;
        uVar5 = uVar5 + 1;
        _DAT_18001d9fc = (int)uVar5;
        pcVar6 = *local_res10;
      }
      local_res10 = (char **)0x0;
      DAT_18001da00 = ppcVar1;
      _free_base((LPVOID)0x0);
      local_res10 = (char **)0x0;
      goto LAB_18000a3f6;
    }
    _DAT_18001d9fc = (int)local_res18 + -1;
    DAT_18001da00 = ppcVar4;
  }
  ppcVar4 = (char **)0x0;
LAB_18000a3f6:
  _free_base(ppcVar4);
  return uVar7;
}



/* ---- common_initialize_environment_nolock<char> @ 18000a410 ---- */

/* Library Function - Single Match
    int __cdecl common_initialize_environment_nolock<char>(void)
   
   Library: Visual Studio 2015 Release */

int __cdecl common_initialize_environment_nolock<char>(void)

{
  undefined8 *puVar1;
  int iVar2;
  LPSTR pCVar3;
  undefined8 *puVar4;
  
  iVar2 = 0;
  if (DAT_18001d198 == (undefined8 *)0x0) {
    __acrt_initialize_multibyte();
    pCVar3 = __dcrt_get_narrow_environment_from_os();
    if (pCVar3 == (LPSTR)0x0) {
      iVar2 = -1;
    }
    else {
      puVar4 = FUN_18000a47c(pCVar3);
      puVar1 = puVar4;
      if (puVar4 == (undefined8 *)0x0) {
        iVar2 = -1;
        puVar4 = DAT_18001d198;
        puVar1 = DAT_18001d1b0;
      }
      DAT_18001d1b0 = puVar1;
      DAT_18001d198 = puVar4;
      _free_base((LPVOID)0x0);
    }
    _free_base(pCVar3);
  }
  else {
    iVar2 = 0;
  }
  return iVar2;
}



/* ---- FUN_18000a47c @ 18000a47c ---- */

undefined8 * FUN_18000a47c(char *param_1)

{
  errno_t eVar1;
  longlong lVar2;
  undefined8 *puVar3;
  char *pcVar4;
  undefined8 *puVar5;
  longlong lVar6;
  ulonglong _SizeInBytes;
  undefined8 *puVar7;
  undefined8 *puVar8;
  
  puVar7 = (undefined8 *)0x0;
  puVar5 = puVar7;
  for (pcVar4 = param_1; *pcVar4 != '\0'; pcVar4 = pcVar4 + lVar2 + 2) {
    if (*pcVar4 != '=') {
      puVar5 = (undefined8 *)((longlong)puVar5 + 1);
    }
    lVar6 = -1;
    do {
      lVar2 = lVar6;
      lVar6 = lVar2 + 1;
    } while (pcVar4[lVar6] != '\0');
  }
  puVar3 = _calloc_base((longlong)puVar5 + 1,8);
  puVar5 = puVar7;
  puVar8 = puVar3;
  if (puVar3 != (undefined8 *)0x0) {
    for (; puVar5 = puVar3, *param_1 != '\0'; param_1 = param_1 + _SizeInBytes) {
      lVar6 = -1;
      do {
        lVar2 = lVar6;
        lVar6 = lVar2 + 1;
      } while (param_1[lVar6] != '\0');
      _SizeInBytes = lVar2 + 2;
      if (*param_1 != '=') {
        pcVar4 = _calloc_base(_SizeInBytes,1);
        if (pcVar4 == (char *)0x0) {
          free_environment<>(puVar3);
          _free_base((LPVOID)0x0);
          puVar5 = puVar7;
          break;
        }
        eVar1 = strcpy_s(pcVar4,_SizeInBytes,param_1);
        if (eVar1 != 0) {
                    /* WARNING: Subroutine does not return */
          _invoke_watson((wchar_t *)0x0,(wchar_t *)0x0,(wchar_t *)0x0,0,0);
        }
        *puVar8 = pcVar4;
        puVar8 = puVar8 + 1;
        _free_base((LPVOID)0x0);
      }
    }
  }
  _free_base((LPVOID)0x0);
  return puVar5;
}



/* ---- free_environment<> @ 18000a578 ---- */

/* Library Function - Multiple Matches With Same Base Name
    void __cdecl free_environment<char>(char * __ptr64 * __ptr64 const)
    void __cdecl free_environment<wchar_t>(wchar_t * __ptr64 * __ptr64 const)
   
   Libraries: Visual Studio 2015 Release, Visual Studio 2017 Release, Visual Studio 2019 Release */

void free_environment<>(undefined8 *param_1)

{
  LPVOID pvVar1;
  undefined8 *puVar2;
  
  if (param_1 != (undefined8 *)0x0) {
    pvVar1 = (LPVOID)*param_1;
    puVar2 = param_1;
    while (pvVar1 != (LPVOID)0x0) {
      _free_base(pvVar1);
      puVar2 = puVar2 + 1;
      pvVar1 = (LPVOID)*puVar2;
    }
    _free_base(param_1);
  }
  return;
}



/* ---- uninitialize_environment_internal<> @ 18000a5bc ---- */

/* Library Function - Multiple Matches With Same Base Name
    void __cdecl uninitialize_environment_internal<char>(char * __ptr64 * __ptr64 & __ptr64)
    void __cdecl uninitialize_environment_internal<wchar_t>(wchar_t * __ptr64 * __ptr64 & __ptr64)
   
   Libraries: Visual Studio 2015 Release, Visual Studio 2017 Release, Visual Studio 2019 Release */

void uninitialize_environment_internal<>(undefined8 *param_1)

{
  if ((undefined8 *)*param_1 != DAT_18001d1b0) {
    free_environment<>((undefined8 *)*param_1);
  }
  return;
}



/* ---- uninitialize_environment_internal<> @ 18000a5d8 ---- */

/* Library Function - Multiple Matches With Same Base Name
    void __cdecl uninitialize_environment_internal<char>(char * __ptr64 * __ptr64 & __ptr64)
    void __cdecl uninitialize_environment_internal<wchar_t>(wchar_t * __ptr64 * __ptr64 & __ptr64)
   
   Libraries: Visual Studio 2015 Release, Visual Studio 2017 Release, Visual Studio 2019 Release */

void uninitialize_environment_internal<>(undefined8 *param_1)

{
  if ((undefined8 *)*param_1 != DAT_18001d1a8) {
    free_environment<>((undefined8 *)*param_1);
  }
  return;
}



/* ---- __dcrt_uninitialize_environments_nolock @ 18000a5f4 ---- */

/* Library Function - Single Match
    __dcrt_uninitialize_environments_nolock
   
   Libraries: Visual Studio 2015 Release, Visual Studio 2017 Release, Visual Studio 2019 Release */

void __dcrt_uninitialize_environments_nolock(void)

{
  uninitialize_environment_internal<>(&DAT_18001d198);
  uninitialize_environment_internal<>((undefined8 *)&DAT_18001d1a0);
  free_environment<>(DAT_18001d1b0);
  free_environment<>(DAT_18001d1a8);
  return;
}



/* ---- common_initialize_environment_nolock<char> @ 18000a62c ---- */

int __cdecl common_initialize_environment_nolock<char>(void)

{
  undefined8 *puVar1;
  int iVar2;
  LPSTR pCVar3;
  undefined8 *puVar4;
  
  iVar2 = 0;
  if (DAT_18001d198 == (undefined8 *)0x0) {
    __acrt_initialize_multibyte();
    pCVar3 = __dcrt_get_narrow_environment_from_os();
    if (pCVar3 == (LPSTR)0x0) {
      iVar2 = -1;
    }
    else {
      puVar4 = FUN_18000a47c(pCVar3);
      puVar1 = puVar4;
      if (puVar4 == (undefined8 *)0x0) {
        iVar2 = -1;
        puVar4 = DAT_18001d198;
        puVar1 = DAT_18001d1b0;
      }
      DAT_18001d1b0 = puVar1;
      DAT_18001d198 = puVar4;
      _free_base((LPVOID)0x0);
    }
    _free_base(pCVar3);
  }
  else {
    iVar2 = 0;
  }
  return iVar2;
}



/* ---- operator()<<lambda_b8c45f8f788dd370798f47cfe8ac3a86>,<lambda_4e60a939b0d047cfe11ddc22648dfba9>&___ptr64,<lambda_332c3edc96d0294ec56c57d38c1cdfd5>_> @ 18000a634 ---- */

/* Library Function - Single Match
    public: int __cdecl __crt_seh_guarded_call<int>::operator()<class
   <lambda_b8c45f8f788dd370798f47cfe8ac3a86>,class <lambda_4e60a939b0d047cfe11ddc22648dfba9> &
   __ptr64,class <lambda_332c3edc96d0294ec56c57d38c1cdfd5> >(class
   <lambda_b8c45f8f788dd370798f47cfe8ac3a86> && __ptr64,class
   <lambda_4e60a939b0d047cfe11ddc22648dfba9> & __ptr64,class
   <lambda_332c3edc96d0294ec56c57d38c1cdfd5> && __ptr64) __ptr64
   
   Library: Visual Studio 2015 Release */

int __thiscall
__crt_seh_guarded_call<int>::
operator()<<lambda_b8c45f8f788dd370798f47cfe8ac3a86>,<lambda_4e60a939b0d047cfe11ddc22648dfba9>&___ptr64,<lambda_332c3edc96d0294ec56c57d38c1cdfd5>_>
          (__crt_seh_guarded_call<int> *this,<lambda_b8c45f8f788dd370798f47cfe8ac3a86> *param_1,
          <lambda_4e60a939b0d047cfe11ddc22648dfba9> *param_2,
          <lambda_332c3edc96d0294ec56c57d38c1cdfd5> *param_3)

{
  int iVar1;
  
  __acrt_lock(*(int *)param_1);
  iVar1 = <lambda_4e60a939b0d047cfe11ddc22648dfba9>::operator()(param_2);
  __acrt_unlock(*(int *)param_3);
  return iVar1;
}



/* ---- operator()<<lambda_e24bbb7b643b32fcea6fa61b31d4c984>,<lambda_275893d493268fdec8709772e3fcec0e>&___ptr64,<lambda_9d71df4d7cf3f480f8d633942495c3b0>_> @ 18000a670 ---- */

/* Library Function - Single Match
    public: int __cdecl __crt_seh_guarded_call<int>::operator()<class
   <lambda_e24bbb7b643b32fcea6fa61b31d4c984>,class <lambda_275893d493268fdec8709772e3fcec0e> &
   __ptr64,class <lambda_9d71df4d7cf3f480f8d633942495c3b0> >(class
   <lambda_e24bbb7b643b32fcea6fa61b31d4c984> && __ptr64,class
   <lambda_275893d493268fdec8709772e3fcec0e> & __ptr64,class
   <lambda_9d71df4d7cf3f480f8d633942495c3b0> && __ptr64) __ptr64
   
   Library: Visual Studio 2015 Release */

int __thiscall
__crt_seh_guarded_call<int>::
operator()<<lambda_e24bbb7b643b32fcea6fa61b31d4c984>,<lambda_275893d493268fdec8709772e3fcec0e>&___ptr64,<lambda_9d71df4d7cf3f480f8d633942495c3b0>_>
          (__crt_seh_guarded_call<int> *this,<lambda_e24bbb7b643b32fcea6fa61b31d4c984> *param_1,
          <lambda_275893d493268fdec8709772e3fcec0e> *param_2,
          <lambda_9d71df4d7cf3f480f8d633942495c3b0> *param_3)

{
  ulonglong uVar1;
  ulonglong *puVar2;
  sbyte sVar3;
  byte bVar4;
  int iVar5;
  ulonglong *puVar6;
  code *pcVar7;
  ulonglong *puVar8;
  uint uVar9;
  ulonglong *puVar10;
  ulonglong *puVar11;
  ulonglong *puVar12;
  
  __acrt_lock(*(int *)param_1);
  puVar6 = (ulonglong *)**(longlong **)param_2;
  if (puVar6 == (ulonglong *)0x0) {
    iVar5 = -1;
  }
  else {
    uVar9 = (uint)DAT_18001c000 & 0x3f;
    sVar3 = (sbyte)uVar9;
    puVar8 = (ulonglong *)
             ((DAT_18001c000 ^ *puVar6) >> sVar3 | (DAT_18001c000 ^ *puVar6) << 0x40 - sVar3);
    puVar6 = (ulonglong *)
             ((DAT_18001c000 ^ puVar6[1]) >> sVar3 | (DAT_18001c000 ^ puVar6[1]) << 0x40 - sVar3);
    puVar11 = puVar8;
    puVar12 = puVar6;
    if ((longlong)puVar8 - 1U < 0xfffffffffffffffe) {
      while( true ) {
        bVar4 = -(char)uVar9 & 0x3f;
        uVar1 = (0UL >> bVar4 | 0L << 0x40 - bVar4) ^ DAT_18001c000;
        do {
          puVar6 = puVar6 + -1;
          if (puVar6 < puVar8) goto LAB_18000a728;
        } while (*puVar6 == uVar1);
        if (puVar6 < puVar8) break;
        bVar4 = (byte)DAT_18001c000 & 0x3f;
        pcVar7 = (code *)((DAT_18001c000 ^ *puVar6) >> bVar4 |
                         (DAT_18001c000 ^ *puVar6) << 0x40 - bVar4);
        *puVar6 = uVar1;
        (*(code *)PTR__guard_check_icall_180012238)(pcVar7);
        (*pcVar7)();
        uVar9 = (uint)DAT_18001c000 & 0x3f;
        uVar1 = DAT_18001c000 ^ *(ulonglong *)**(longlong **)param_2;
        sVar3 = (sbyte)uVar9;
        puVar10 = (ulonglong *)(uVar1 >> sVar3 | uVar1 << 0x40 - sVar3);
        uVar1 = ((ulonglong *)**(longlong **)param_2)[1] ^ DAT_18001c000;
        puVar2 = (ulonglong *)(uVar1 >> sVar3 | uVar1 << 0x40 - sVar3);
        if ((puVar10 != puVar11) || (puVar2 != puVar12)) {
          puVar6 = puVar2;
          puVar8 = puVar10;
          puVar11 = puVar10;
          puVar12 = puVar2;
        }
      }
LAB_18000a728:
      if (puVar8 != (ulonglong *)0xffffffffffffffff) {
        _free_base(puVar8);
      }
      bVar4 = 0x40 - ((byte)DAT_18001c000 & 0x3f) & 0x3f;
      uVar1 = (0UL >> bVar4 | 0L << 0x40 - bVar4) ^ DAT_18001c000;
      *(ulonglong *)**(undefined8 **)param_2 = uVar1;
      *(ulonglong *)(**(longlong **)param_2 + 8) = uVar1;
      *(ulonglong *)(**(longlong **)param_2 + 0x10) = uVar1;
    }
    iVar5 = 0;
  }
  __acrt_unlock(*(int *)param_3);
  return iVar5;
}



/* ---- operator() @ 18000a810 ---- */

/* Library Function - Single Match
    public: int __cdecl <lambda_4e60a939b0d047cfe11ddc22648dfba9>::operator()(void)const __ptr64
   
   Library: Visual Studio 2015 Release */

int __thiscall
<lambda_4e60a939b0d047cfe11ddc22648dfba9>::operator()
          (<lambda_4e60a939b0d047cfe11ddc22648dfba9> *this)

{
  int iVar1;
  LPVOID pvVar2;
  byte bVar3;
  ulonglong *puVar4;
  ulonglong *puVar5;
  ulonglong uVar6;
  LPVOID pvVar7;
  ulonglong uVar8;
  ulonglong uVar9;
  ulonglong uVar10;
  ulonglong *puVar11;
  
  uVar8 = 0;
  puVar5 = (ulonglong *)**(longlong **)this;
  if (puVar5 == (ulonglong *)0x0) {
LAB_18000a83d:
    iVar1 = -1;
  }
  else {
    bVar3 = (byte)DAT_18001c000 & 0x3f;
    pvVar7 = (LPVOID)((*puVar5 ^ DAT_18001c000) >> bVar3 | (*puVar5 ^ DAT_18001c000) << 0x40 - bVar3
                     );
    puVar11 = (ulonglong *)
              ((puVar5[1] ^ DAT_18001c000) >> bVar3 | (puVar5[1] ^ DAT_18001c000) << 0x40 - bVar3);
    puVar5 = (ulonglong *)
             ((puVar5[2] ^ DAT_18001c000) >> bVar3 | (puVar5[2] ^ DAT_18001c000) << 0x40 - bVar3);
    if (puVar11 == puVar5) {
      uVar6 = (longlong)puVar5 - (longlong)pvVar7 >> 3;
      uVar9 = uVar6;
      if (0x200 < uVar6) {
        uVar9 = 0x200;
      }
      uVar10 = uVar9 + uVar6;
      if (uVar9 + uVar6 == 0) {
        uVar10 = 0x20;
      }
      if (uVar10 < uVar6) {
LAB_18000a8c4:
        uVar10 = uVar6 + 4;
        pvVar2 = _recalloc_base(pvVar7,uVar10,8);
        _free_base((LPVOID)0x0);
        if (pvVar2 == (LPVOID)0x0) goto LAB_18000a83d;
      }
      else {
        pvVar2 = _recalloc_base(pvVar7,uVar10,8);
        _free_base((LPVOID)0x0);
        if (pvVar2 == (LPVOID)0x0) goto LAB_18000a8c4;
      }
      pvVar7 = pvVar2;
      puVar11 = (ulonglong *)((longlong)pvVar7 + uVar6 * 8);
      puVar5 = (ulonglong *)((longlong)pvVar7 + uVar10 * 8);
      bVar3 = -((byte)DAT_18001c000 & 0x3f) & 0x3f;
      uVar6 = (0UL >> bVar3 | 0L << 0x40 - bVar3) ^ DAT_18001c000;
      uVar9 = (ulonglong)((longlong)puVar5 + (7 - (longlong)puVar11)) >> 3;
      if (puVar5 < puVar11) {
        uVar9 = uVar8;
      }
      puVar4 = puVar11;
      if (uVar9 != 0) {
        do {
          uVar8 = uVar8 + 1;
          *puVar4 = uVar6;
          puVar4 = puVar4 + 1;
        } while (uVar8 != uVar9);
      }
    }
    bVar3 = -((byte)DAT_18001c000 & 0x3f) & 0x3f;
    *puVar11 = (**(ulonglong **)(this + 8) >> bVar3 | **(ulonglong **)(this + 8) << 0x40 - bVar3) ^
               DAT_18001c000;
    bVar3 = -((byte)DAT_18001c000 & 0x3f) & 0x3f;
    *(ulonglong *)**(undefined8 **)this =
         ((ulonglong)pvVar7 >> bVar3 | (longlong)pvVar7 << 0x40 - bVar3) ^ DAT_18001c000;
    bVar3 = -((byte)DAT_18001c000 & 0x3f) & 0x3f;
    *(ulonglong *)(**(longlong **)this + 8) =
         ((ulonglong)(puVar11 + 1) >> bVar3 | (longlong)(puVar11 + 1) << 0x40 - bVar3) ^
         DAT_18001c000;
    bVar3 = 0x40 - ((byte)DAT_18001c000 & 0x3f) & 0x3f;
    iVar1 = 0;
    *(ulonglong *)(**(longlong **)this + 0x10) =
         ((ulonglong)puVar5 >> bVar3 | (longlong)puVar5 << 0x40 - bVar3) ^ DAT_18001c000;
  }
  return iVar1;
}



/* ---- FUN_18000a9ec @ 18000a9ec ---- */

void FUN_18000a9ec(undefined8 param_1)

{
  _register_onexit_function(&DAT_18001d1b8,param_1);
  return;
}



/* ---- _execute_onexit_table @ 18000a9fc ---- */

/* Library Function - Single Match
    _execute_onexit_table
   
   Library: Visual Studio 2015 Release */

void _execute_onexit_table(undefined8 param_1)

{
  undefined8 local_res8;
  __crt_seh_guarded_call<int> local_res10 [8];
  undefined4 local_res18 [2];
  undefined4 local_res20 [2];
  undefined8 *local_18 [3];
  
  local_18[0] = &local_res8;
  local_res18[0] = 2;
  local_res20[0] = 2;
  local_res8 = param_1;
  __crt_seh_guarded_call<int>::
  operator()<<lambda_e24bbb7b643b32fcea6fa61b31d4c984>,<lambda_275893d493268fdec8709772e3fcec0e>&___ptr64,<lambda_9d71df4d7cf3f480f8d633942495c3b0>_>
            (local_res10,(<lambda_e24bbb7b643b32fcea6fa61b31d4c984> *)local_res20,
             (<lambda_275893d493268fdec8709772e3fcec0e> *)local_18,
             (<lambda_9d71df4d7cf3f480f8d633942495c3b0> *)local_res18);
  return;
}



/* ---- _initialize_onexit_table @ 18000aa38 ---- */

/* Library Function - Single Match
    _initialize_onexit_table
   
   Library: Visual Studio 2015 Release */

undefined8 _initialize_onexit_table(ulonglong *param_1)

{
  byte bVar1;
  ulonglong uVar2;
  
  if (param_1 == (ulonglong *)0x0) {
    return 0xffffffff;
  }
  if (*param_1 == param_1[2]) {
    bVar1 = 0x40 - ((byte)DAT_18001c000 & 0x3f) & 0x3f;
    uVar2 = (0UL >> bVar1 | 0L << 0x40 - bVar1) ^ DAT_18001c000;
    *param_1 = uVar2;
    param_1[1] = uVar2;
    param_1[2] = uVar2;
  }
  return 0;
}



/* ---- _register_onexit_function @ 18000aa78 ---- */

/* Library Function - Single Match
    _register_onexit_function
   
   Libraries: Visual Studio 2015 Release, Visual Studio 2017 Release */

void _register_onexit_function(undefined8 param_1,undefined8 param_2)

{
  undefined8 local_res8;
  undefined8 local_res10;
  __crt_seh_guarded_call<int> local_res18 [8];
  undefined4 local_res20 [2];
  undefined4 local_28 [2];
  undefined8 *local_20;
  undefined8 *local_18;
  
  local_20 = &local_res8;
  local_18 = &local_res10;
  local_res20[0] = 2;
  local_28[0] = 2;
  local_res8 = param_1;
  local_res10 = param_2;
  __crt_seh_guarded_call<int>::
  operator()<<lambda_b8c45f8f788dd370798f47cfe8ac3a86>,<lambda_4e60a939b0d047cfe11ddc22648dfba9>&___ptr64,<lambda_332c3edc96d0294ec56c57d38c1cdfd5>_>
            (local_res18,(<lambda_b8c45f8f788dd370798f47cfe8ac3a86> *)local_28,
             (<lambda_4e60a939b0d047cfe11ddc22648dfba9> *)&local_20,
             (<lambda_332c3edc96d0294ec56c57d38c1cdfd5> *)local_res20);
  return;
}



/* ---- FUN_18000aad4 @ 18000aad4 ---- */

undefined8 FUN_18000aad4(void)

{
  undefined8 uVar1;
  
  _initialize_onexit_table((ulonglong *)&DAT_18001d1b8);
  uVar1 = _initialize_onexit_table((ulonglong *)&DAT_18001d1d0);
  return CONCAT71((int7)((ulonglong)uVar1 >> 8),1);
}



/* ---- FUN_18000aaf8 @ 18000aaf8 ---- */

undefined1 FUN_18000aaf8(void)

{
  __dcrt_uninitialize_environments_nolock();
  return 1;
}



/* ---- FUN_18000ab08 @ 18000ab08 ---- */

undefined8 FUN_18000ab08(void)

{
  byte bVar1;
  undefined8 uVar2;
  ulonglong uVar3;
  
  bVar1 = 0x40 - ((byte)DAT_18001c000 & 0x3f) & 0x3f;
  uVar3 = (0UL >> bVar1 | 0L << 0x40 - bVar1) ^ DAT_18001c000;
  FUN_18000af44(uVar3);
  FUN_18000d8f4(uVar3);
  FUN_18000d9e8(uVar3);
  FUN_18000dcc4(uVar3);
  uVar2 = FUN_18000a04c(uVar3);
  return CONCAT71((int7)((ulonglong)uVar2 >> 8),1);
}



/* ---- FUN_18000ab64 @ 18000ab64 ---- */

undefined8 FUN_18000ab64(void)

{
  int iVar1;
  undefined8 uVar2;
  
  LOCK();
  iVar1 = *(int *)PTR_DAT_18001c4f8;
  *(int *)PTR_DAT_18001c4f8 = *(int *)PTR_DAT_18001c4f8 + -1;
  UNLOCK();
  if ((iVar1 == 1) && ((undefined4 *)PTR_DAT_18001c4f8 != &DAT_18001c2d0)) {
    _free_base(PTR_DAT_18001c4f8);
    PTR_DAT_18001c4f8 = (undefined *)&DAT_18001c2d0;
  }
  _free_base(DAT_18001da60);
  DAT_18001da60 = (LPVOID)0x0;
  _free_base(DAT_18001da68);
  DAT_18001da68 = (LPVOID)0x0;
  _free_base(DAT_18001da00);
  DAT_18001da00 = (LPVOID)0x0;
  uVar2 = _free_base(DAT_18001da08);
  DAT_18001da08 = (LPVOID)0x0;
  return CONCAT71((int7)((ulonglong)uVar2 >> 8),1);
}



/* ---- FUN_18000abf4 @ 18000abf4 ---- */

void FUN_18000abf4(void)

{
  __acrt_execute_initializers(&PTR_LAB_180013bc0,(undefined8 *)&DAT_180013cb0);
  return;
}



/* ---- __acrt_thread_attach @ 18000ac08 ---- */

/* Library Function - Single Match
    __acrt_thread_attach
   
   Library: Visual Studio 2015 Release */

bool __acrt_thread_attach(void)

{
  __acrt_ptd *p_Var1;
  
  p_Var1 = __acrt_getptd_noexit();
  return p_Var1 != (__acrt_ptd *)0x0;
}



/* ---- __acrt_thread_detach @ 18000ac1c ---- */

/* Library Function - Single Match
    __acrt_thread_detach
   
   Libraries: Visual Studio 2015 Release, Visual Studio 2017 Release, Visual Studio 2019 Release */

undefined1 __acrt_thread_detach(void)

{
  __acrt_freeptd();
  return 1;
}



/* ---- FUN_18000ac2c @ 18000ac2c ---- */

void FUN_18000ac2c(void)

{
  __acrt_execute_uninitializers(&PTR_LAB_180013bc0,(undefined8 *)&DAT_180013cb0);
  return;
}



/* ---- FUN_18000ac40 @ 18000ac40 ---- */

undefined1 FUN_18000ac40(void)

{
  __acrt_uninitialize_ptd();
  return 1;
}



/* ---- terminate @ 18000ac50 ---- */

/* Library Function - Single Match
    terminate
   
   Library: Visual Studio 2015 Release */

void terminate(void)

{
  code *pcVar1;
  __acrt_ptd *p_Var2;
  
  p_Var2 = FUN_18000b630();
  pcVar1 = *(code **)(p_Var2 + 0x18);
  if (pcVar1 != (code *)0x0) {
    (*(code *)PTR__guard_check_icall_180012238)(pcVar1);
    (*pcVar1)();
  }
                    /* WARNING: Subroutine does not return */
  abort();
}



/* ---- _free_base @ 18000ac78 ---- */

/* Library Function - Single Match
    _free_base
   
   Libraries: Visual Studio 2015 Release, Visual Studio 2017 Release, Visual Studio 2019 Release */

void _free_base(LPVOID param_1)

{
  BOOL BVar1;
  DWORD DVar2;
  ulong uVar3;
  ulong *puVar4;
  
  if ((param_1 != (LPVOID)0x0) && (BVar1 = HeapFree(DAT_18001da28,0,param_1), BVar1 == 0)) {
    puVar4 = __doserrno();
    DVar2 = GetLastError();
    uVar3 = __acrt_errno_from_os_error(DVar2);
    *puVar4 = uVar3;
  }
  return;
}



/* ---- _malloc_base @ 18000acb8 ---- */

/* Library Function - Single Match
    _malloc_base
   
   Library: Visual Studio 2015 Release */

LPVOID _malloc_base(ulonglong param_1)

{
  int iVar1;
  LPVOID pvVar2;
  ulong *puVar3;
  
  if (param_1 < 0xffffffffffffffe1) {
    if (param_1 == 0) {
      param_1 = 1;
    }
    do {
      pvVar2 = HeapAlloc(DAT_18001da28,0,param_1);
      if (pvVar2 != (LPVOID)0x0) {
        return pvVar2;
      }
      iVar1 = FUN_18000dd14();
    } while ((iVar1 != 0) && (iVar1 = _callnewh(param_1), iVar1 != 0));
  }
  puVar3 = __doserrno();
  *puVar3 = 0xc;
  return (LPVOID)0x0;
}



/* ---- abort @ 18000ad18 ---- */

/* Library Function - Single Match
    abort
   
   Library: Visual Studio 2015 Release */

void __cdecl abort(void)

{
  code *pcVar1;
  longlong lVar2;
  BOOL BVar3;
  undefined1 *puVar4;
  undefined1 auStack_28 [8];
  undefined1 auStack_20 [32];
  
  puVar4 = auStack_28;
  lVar2 = __acrt_get_sigabrt_handler();
  if (lVar2 != 0) {
    raise(0x16);
  }
  if ((DAT_18001c034 & 2) != 0) {
    BVar3 = IsProcessorFeaturePresent(0x17);
    puVar4 = auStack_28;
    if (BVar3 != 0) {
      pcVar1 = (code *)swi(0x29);
      (*pcVar1)(7);
      puVar4 = auStack_20;
    }
    *(undefined8 *)(puVar4 + -8) = 0x18000ad62;
    __acrt_call_reportfault(3,0x40000015,1);
  }
  *(undefined8 *)(puVar4 + -8) = 0x18000ad6c;
  FUN_18000a064(3);
  pcVar1 = (code *)swi(3);
  (*pcVar1)();
  return;
}



/* ---- _calloc_base @ 18000ad70 ---- */

/* Library Function - Single Match
    _calloc_base
   
   Library: Visual Studio 2015 Release */

LPVOID _calloc_base(ulonglong param_1,ulonglong param_2)

{
  int iVar1;
  LPVOID pvVar2;
  ulong *puVar3;
  size_t dwBytes;
  
  if ((param_1 == 0) || (param_2 <= 0xffffffffffffffe0 / param_1)) {
    dwBytes = param_1 * param_2;
    if (dwBytes == 0) {
      dwBytes = 1;
    }
    do {
      pvVar2 = HeapAlloc(DAT_18001da28,8,dwBytes);
      if (pvVar2 != (LPVOID)0x0) {
        return pvVar2;
      }
      iVar1 = FUN_18000dd14();
    } while ((iVar1 != 0) && (iVar1 = _callnewh(dwBytes), iVar1 != 0));
  }
  puVar3 = __doserrno();
  *puVar3 = 0xc;
  return (LPVOID)0x0;
}



/* ---- __acrt_call_reportfault @ 18000ade8 ---- */

/* WARNING: Function: __security_check_cookie replaced with injection: security_check_cookie */
/* Library Function - Single Match
    __acrt_call_reportfault
   
   Library: Visual Studio 2015 Release */

void __acrt_call_reportfault(int param_1,DWORD param_2,DWORD param_3)

{
  BOOL BVar1;
  LONG LVar2;
  PRUNTIME_FUNCTION FunctionEntry;
  undefined1 local_res8 [8];
  undefined1 auStackY_608 [32];
  DWORD64 local_5c8;
  _EXCEPTION_POINTERS local_5c0;
  PVOID local_5b0;
  ulonglong local_5a8 [2];
  EXCEPTION_RECORD local_598;
  _CONTEXT local_4f8;
  ulonglong local_28;
  
  local_28 = DAT_18001c000 ^ (ulonglong)auStackY_608;
  if (param_1 != -1) {
    FUN_180002a4c();
  }
  FUN_180003320((undefined1 (*) [16])&local_598,0,0x98);
  FUN_180003320((undefined1 (*) [16])&local_4f8,0,0x4d0);
  local_5c0.ExceptionRecord = &local_598;
  local_5c0.ContextRecord = &local_4f8;
  RtlCaptureContext(&local_4f8);
  FunctionEntry = RtlLookupFunctionEntry(local_4f8.Rip,&local_5c8,(PUNWIND_HISTORY_TABLE)0x0);
  if (FunctionEntry != (PRUNTIME_FUNCTION)0x0) {
    RtlVirtualUnwind(0,local_5c8,local_4f8.Rip,FunctionEntry,&local_4f8,&local_5b0,local_5a8,
                     (PKNONVOLATILE_CONTEXT_POINTERS)0x0);
  }
  local_4f8.Rsp = (DWORD64)local_res8;
  local_598.ExceptionCode = param_2;
  local_598.ExceptionFlags = param_3;
  BVar1 = IsDebuggerPresent();
  SetUnhandledExceptionFilter((LPTOP_LEVEL_EXCEPTION_FILTER)0x0);
  LVar2 = UnhandledExceptionFilter(&local_5c0);
  if (((LVar2 == 0) && (BVar1 == 0)) && (param_1 != -1)) {
    FUN_180002a4c();
  }
  return;
}



/* ---- FUN_18000af44 @ 18000af44 ---- */

/* WARNING: Globals starting with '_' overlap smaller symbols at the same address */

void FUN_18000af44(undefined8 param_1)

{
  _DAT_18001d1e8 = param_1;
  return;
}



/* ---- FUN_18000af4c @ 18000af4c ---- */

/* WARNING: Globals starting with '_' overlap smaller symbols at the same address */

void FUN_18000af4c(wchar_t *param_1,wchar_t *param_2,wchar_t *param_3,uint param_4,uintptr_t param_5
                  )

{
  __acrt_ptd *p_Var1;
  byte bVar2;
  code *UNRECOVERED_JUMPTABLE;
  
  p_Var1 = __acrt_getptd_noexit();
  if (((p_Var1 == (__acrt_ptd *)0x0) ||
      (UNRECOVERED_JUMPTABLE = *(code **)(p_Var1 + 0x3b8), UNRECOVERED_JUMPTABLE == (code *)0x0)) &&
     (bVar2 = (byte)DAT_18001c000 & 0x3f,
     UNRECOVERED_JUMPTABLE =
          (code *)((DAT_18001c000 ^ _DAT_18001d1e8) >> bVar2 |
                  (DAT_18001c000 ^ _DAT_18001d1e8) << 0x40 - bVar2),
     UNRECOVERED_JUMPTABLE == (code *)0x0)) {
                    /* WARNING: Subroutine does not return */
    _invoke_watson(param_1,param_2,param_3,param_4,param_5);
  }
  (*(code *)PTR__guard_check_icall_180012238)(UNRECOVERED_JUMPTABLE);
                    /* WARNING: Could not recover jumptable at 0x00018000afb9. Too many branches */
                    /* WARNING: Treating indirect jump as call */
  (*UNRECOVERED_JUMPTABLE)(param_1,param_2,param_3,param_4);
  return;
}



/* ---- FUN_18000aff4 @ 18000aff4 ---- */

void FUN_18000aff4(void)

{
  FUN_18000af4c((wchar_t *)0x0,(wchar_t *)0x0,(wchar_t *)0x0,0,0);
  return;
}



/* ---- _invoke_watson @ 18000b014 ---- */

/* Library Function - Single Match
    _invoke_watson
   
   Library: Visual Studio 2015 Release */

void __cdecl
_invoke_watson(wchar_t *param_1,wchar_t *param_2,wchar_t *param_3,uint param_4,uintptr_t param_5)

{
  code *pcVar1;
  BOOL BVar2;
  HANDLE hProcess;
  undefined1 *puVar3;
  undefined1 auStack_28 [8];
  undefined1 auStack_20 [32];
  
  puVar3 = auStack_28;
  BVar2 = IsProcessorFeaturePresent(0x17);
  if (BVar2 != 0) {
    pcVar1 = (code *)swi(0x29);
    (*pcVar1)(5);
    puVar3 = auStack_20;
  }
  *(undefined8 *)(puVar3 + -8) = 0x18000b041;
  __acrt_call_reportfault(2,0xc0000417,1);
  *(undefined8 *)(puVar3 + -8) = 0x18000b047;
  hProcess = GetCurrentProcess();
                    /* WARNING: Could not recover jumptable at 0x00018000b053. Too many branches */
                    /* WARNING: Treating indirect jump as call */
  TerminateProcess(hProcess,0xc0000417);
  return;
}



/* ---- __acrt_errno_from_os_error @ 18000b05c ---- */

/* Library Function - Single Match
    __acrt_errno_from_os_error
   
   Libraries: Visual Studio 2015 Release, Visual Studio 2017 Release, Visual Studio 2019 Release */

undefined4 __acrt_errno_from_os_error(int param_1)

{
  uint uVar1;
  undefined4 uVar2;
  ulonglong uVar3;
  int *piVar4;
  
  uVar3 = 0;
  piVar4 = &DAT_180013cb0;
  do {
    if (param_1 == *piVar4) {
      return *(undefined4 *)(&UNK_180013cb4 + uVar3 * 8);
    }
    uVar1 = (int)uVar3 + 1;
    uVar3 = (ulonglong)uVar1;
    piVar4 = piVar4 + 2;
  } while (uVar1 < 0x2d);
  if (param_1 - 0x13U < 0x12) {
    return 0xd;
  }
  uVar2 = 0x16;
  if (param_1 - 0xbcU < 0xf) {
    uVar2 = 8;
  }
  return uVar2;
}



/* ---- __acrt_errno_map_os_error @ 18000b0a4 ---- */

/* Library Function - Single Match
    __acrt_errno_map_os_error
   
   Library: Visual Studio 2015 Release */

void __acrt_errno_map_os_error(int param_1)

{
  undefined4 uVar1;
  __acrt_ptd *p_Var2;
  __acrt_ptd *p_Var3;
  
  p_Var2 = __acrt_getptd_noexit();
  if (p_Var2 == (__acrt_ptd *)0x0) {
    p_Var2 = (__acrt_ptd *)&DAT_18001c03c;
  }
  else {
    p_Var2 = p_Var2 + 0x24;
  }
  *(int *)p_Var2 = param_1;
  p_Var3 = __acrt_getptd_noexit();
  p_Var2 = (__acrt_ptd *)&DAT_18001c038;
  if (p_Var3 != (__acrt_ptd *)0x0) {
    p_Var2 = p_Var3 + 0x20;
  }
  uVar1 = __acrt_errno_from_os_error(param_1);
  *(undefined4 *)p_Var2 = uVar1;
  return;
}



/* ---- __doserrno @ 18000b0f4 ---- */

/* Library Function - Single Match
    __doserrno
   
   Library: Visual Studio 2015 Release */

ulong * __cdecl __doserrno(void)

{
  __acrt_ptd *p_Var1;
  
  p_Var1 = __acrt_getptd_noexit();
  if (p_Var1 == (__acrt_ptd *)0x0) {
    p_Var1 = (__acrt_ptd *)&DAT_18001c03c;
  }
  else {
    p_Var1 = p_Var1 + 0x24;
  }
  return (ulong *)p_Var1;
}



/* ---- __doserrno @ 18000b114 ---- */

/* Library Function - Single Match
    __doserrno
   
   Library: Visual Studio 2015 Release */

ulong * __cdecl __doserrno(void)

{
  __acrt_ptd *p_Var1;
  
  p_Var1 = __acrt_getptd_noexit();
  if (p_Var1 == (__acrt_ptd *)0x0) {
    p_Var1 = (__acrt_ptd *)&DAT_18001c038;
  }
  else {
    p_Var1 = p_Var1 + 0x20;
  }
  return (ulong *)p_Var1;
}



/* ---- __pctype_func @ 18000b134 ---- */

/* Library Function - Single Match
    __pctype_func
   
   Library: Visual Studio 2015 Release */

ushort * __cdecl __pctype_func(void)

{
  __acrt_ptd *p_Var1;
  undefined8 *local_res8 [4];
  
  p_Var1 = FUN_18000b630();
  local_res8[0] = *(undefined8 **)(p_Var1 + 0x90);
  FUN_18000b7c4((longlong)p_Var1,(longlong *)local_res8);
  return (ushort *)*local_res8[0];
}



/* ---- _isctype_l @ 18000b164 ---- */

/* WARNING: Function: __security_check_cookie replaced with injection: security_check_cookie */
/* Library Function - Single Match
    _isctype_l
   
   Library: Visual Studio 2015 Release */

int __cdecl _isctype_l(int _C,int _Type,_locale_t _Locale)

{
  int iVar1;
  BOOL BVar2;
  int iVar3;
  undefined1 auStackY_88 [32];
  CHAR local_48;
  CHAR local_47;
  undefined1 local_46;
  longlong local_40;
  localeinfo_struct local_38;
  char local_28;
  ushort local_20 [4];
  ulonglong local_18;
  
  local_18 = DAT_18001c000 ^ (ulonglong)auStackY_88;
  _LocaleUpdate::_LocaleUpdate((_LocaleUpdate *)&local_40,(__crt_locale_pointers *)_Locale);
  if (_C + 1U < 0x101) {
    local_20[0] = *(ushort *)(*(longlong *)local_38.locinfo + (longlong)_C * 2);
  }
  else {
    iVar1 = _isleadbyte_l(_C >> 8 & 0xff,&local_38);
    iVar3 = 1;
    if (iVar1 == 0) {
      local_47 = '\0';
      local_48 = (CHAR)_C;
    }
    else {
      iVar3 = 2;
      local_46 = 0;
      local_48 = (CHAR)((uint)_C >> 8);
      local_47 = (CHAR)_C;
    }
    local_20[0] = 0;
    local_20[1] = 0;
    local_20[2] = 0;
    BVar2 = __acrt_GetStringTypeA
                      ((__crt_locale_pointers *)&local_38,1,&local_48,iVar3,local_20,
                       (local_38.locinfo)->lc_time_cp,1);
    if (BVar2 == 0) {
      if (local_28 != '\0') {
        *(uint *)(local_40 + 0x3a8) = *(uint *)(local_40 + 0x3a8) & 0xfffffffd;
      }
      return 0;
    }
  }
  if (local_28 != '\0') {
    *(uint *)(local_40 + 0x3a8) = *(uint *)(local_40 + 0x3a8) & 0xfffffffd;
  }
  return (uint)local_20[0] & _Type;
}



/* ---- operator()<> @ 18000b274 ---- */

/* Library Function - Multiple Matches With Same Base Name
    public: void __cdecl __crt_seh_guarded_call<void>::operator()<class
   <lambda_46352004c1216016012b18bd6f87e700>,class <lambda_3bd07e1a1191394380780325891bf33f> &
   __ptr64,class <lambda_334532d3f185bcaa59b5be82d7d22bff> >(class
   <lambda_46352004c1216016012b18bd6f87e700> && __ptr64,class
   <lambda_3bd07e1a1191394380780325891bf33f> & __ptr64,class
   <lambda_334532d3f185bcaa59b5be82d7d22bff> && __ptr64) __ptr64
    public: void __cdecl __crt_seh_guarded_call<void>::operator()<class
   <lambda_f2e299630e499de9f9a165e60fcd3db5>,class <lambda_2ae9d31cdba2644fcbeaf08da7c24588> &
   __ptr64,class <lambda_40d01ff24d0e7b3814fdbdcee8eab3c7> >(class
   <lambda_f2e299630e499de9f9a165e60fcd3db5> && __ptr64,class
   <lambda_2ae9d31cdba2644fcbeaf08da7c24588> & __ptr64,class
   <lambda_40d01ff24d0e7b3814fdbdcee8eab3c7> && __ptr64) __ptr64
   
   Libraries: Visual Studio 2015 Release, Visual Studio 2017 Release, Visual Studio 2019 Release */

void operator()<>(undefined8 param_1,int *param_2,undefined8 *param_3,int *param_4)

{
  int iVar1;
  int *piVar2;
  
  __acrt_lock(*param_2);
  piVar2 = *(int **)(*(longlong *)*param_3 + 0x88);
  if (piVar2 != (int *)0x0) {
    LOCK();
    iVar1 = *piVar2;
    *piVar2 = *piVar2 + -1;
    UNLOCK();
    if ((iVar1 == 1) && (piVar2 != &DAT_18001c2d0)) {
      _free_base(piVar2);
    }
  }
  __acrt_unlock(*param_4);
  return;
}



/* ---- operator()<> @ 18000b2d4 ---- */

/* Library Function - Multiple Matches With Same Base Name
    public: void __cdecl __crt_seh_guarded_call<void>::operator()<class
   <lambda_5e887d1dcbef67a5eb4283622ba103bf>,class <lambda_4466841279450cc726390878d4a41900> &
   __ptr64,class <lambda_341c25c0346d94847f1f3c463c57e077> >(class
   <lambda_5e887d1dcbef67a5eb4283622ba103bf> && __ptr64,class
   <lambda_4466841279450cc726390878d4a41900> & __ptr64,class
   <lambda_341c25c0346d94847f1f3c463c57e077> && __ptr64) __ptr64
    public: void __cdecl __crt_seh_guarded_call<void>::operator()<class
   <lambda_aa87e3671a710a21b5dc78c0bdf72e11>,class <lambda_92619d2358a28f41a33ba319515a20b9> &
   __ptr64,class <lambda_6992ecaafeb10aed2b74cb1fae11a551> >(class
   <lambda_aa87e3671a710a21b5dc78c0bdf72e11> && __ptr64,class
   <lambda_92619d2358a28f41a33ba319515a20b9> & __ptr64,class
   <lambda_6992ecaafeb10aed2b74cb1fae11a551> && __ptr64) __ptr64
   
   Libraries: Visual Studio 2015 Release, Visual Studio 2017 Release, Visual Studio 2019 Release */

void operator()<>(undefined8 param_1,int *param_2,undefined8 *param_3,int *param_4)

{
  __acrt_lock(*param_2);
  replace_current_thread_locale_nolock
            (*(__acrt_ptd **)*param_3,(__crt_locale_data *)**(undefined8 **)param_3[1]);
  __acrt_unlock(*param_4);
  return;
}



/* ---- operator()<> @ 18000b31c ---- */

/* Library Function - Multiple Matches With Same Base Name
    public: void __cdecl __crt_seh_guarded_call<void>::operator()<class
   <lambda_0ae27a3a962d80f24befdcbee591983d>,class <lambda_8d0ee55de4b1038c4002e0adecdf1839> &
   __ptr64,class <lambda_dc504788e8f1664fe9b84e20bfb512f2> >(class
   <lambda_0ae27a3a962d80f24befdcbee591983d> && __ptr64,class
   <lambda_8d0ee55de4b1038c4002e0adecdf1839> & __ptr64,class
   <lambda_dc504788e8f1664fe9b84e20bfb512f2> && __ptr64) __ptr64
    public: void __cdecl __crt_seh_guarded_call<void>::operator()<class
   <lambda_72d1df2b273a38828b1ce30cbf4cdab5>,class <lambda_876a65b173b8412d3a47c70a915b0cf4> &
   __ptr64,class <lambda_41932305e351933ebe8f8be3ed8bb5dc> >(class
   <lambda_72d1df2b273a38828b1ce30cbf4cdab5> && __ptr64,class
   <lambda_876a65b173b8412d3a47c70a915b0cf4> & __ptr64,class
   <lambda_41932305e351933ebe8f8be3ed8bb5dc> && __ptr64) __ptr64
   
   Libraries: Visual Studio 2015 Release, Visual Studio 2017 Release, Visual Studio 2019 Release */

void operator()<>(undefined8 param_1,int *param_2,undefined8 *param_3,int *param_4)

{
  __acrt_lock(*param_2);
  LOCK();
  **(int **)(*(longlong *)*param_3 + 0x88) = **(int **)(*(longlong *)*param_3 + 0x88) + 1;
  UNLOCK();
  __acrt_unlock(*param_4);
  return;
}



/* ---- operator()<> @ 18000b35c ---- */

/* Library Function - Multiple Matches With Same Base Name
    public: void __cdecl __crt_seh_guarded_call<void>::operator()<class
   <lambda_2d41944a1d46af3157314b8a01080d33>,class <lambda_8f455de75cd7d7f24b4096f044d8b9e6> &
   __ptr64,class <lambda_aa500f224e6afead328df44964fe2772> >(class
   <lambda_2d41944a1d46af3157314b8a01080d33> && __ptr64,class
   <lambda_8f455de75cd7d7f24b4096f044d8b9e6> & __ptr64,class
   <lambda_aa500f224e6afead328df44964fe2772> && __ptr64) __ptr64
    public: void __cdecl __crt_seh_guarded_call<void>::operator()<class
   <lambda_fb3a7dec4e47f37f22dae91bb15c9095>,class <lambda_698284760c8add0bfb0756c19673e34b> &
   __ptr64,class <lambda_dfb8eca1e75fef3034a8fb18dd509707> >(class
   <lambda_fb3a7dec4e47f37f22dae91bb15c9095> && __ptr64,class
   <lambda_698284760c8add0bfb0756c19673e34b> & __ptr64,class
   <lambda_dfb8eca1e75fef3034a8fb18dd509707> && __ptr64) __ptr64
   
   Libraries: Visual Studio 2015 Release, Visual Studio 2017 Release, Visual Studio 2019 Release */

void operator()<>(undefined8 param_1,int *param_2,undefined8 *param_3,int *param_4)

{
  __acrt_lock(*param_2);
  replace_current_thread_locale_nolock(*(__acrt_ptd **)*param_3,(__crt_locale_data *)0x0);
  __acrt_unlock(*param_4);
  return;
}



/* ---- construct_ptd_array @ 18000b39c ---- */

/* Library Function - Single Match
    void __cdecl construct_ptd_array(struct __acrt_ptd * __ptr64 const)
   
   Library: Visual Studio 2015 Release */

void __cdecl construct_ptd_array(__acrt_ptd *param_1)

{
  undefined1 local_res10 [8];
  int local_res18 [2];
  int local_res20 [2];
  int local_38 [2];
  __acrt_ptd *local_30;
  undefined8 *local_28;
  __acrt_ptd **local_20;
  __acrt_ptd **local_18;
  undefined8 **local_10;
  
  local_20 = &local_30;
  local_res18[0] = 5;
  local_res20[0] = 5;
  local_18 = &local_30;
  local_10 = &local_28;
  local_38[0] = 4;
  local_38[1] = 4;
  local_28 = &DAT_18001d1f8;
  *(undefined4 *)(param_1 + 0x28) = 1;
  *(undefined **)param_1 = &DAT_180013ac0;
  *(undefined4 *)(param_1 + 0x3a8) = 1;
  *(undefined4 **)(param_1 + 0x88) = &DAT_18001c2d0;
  *(undefined2 *)(param_1 + 0xbc) = 0x43;
  *(undefined2 *)(param_1 + 0x1c2) = 0x43;
  *(undefined8 *)(param_1 + 0x3a0) = 0;
  local_30 = param_1;
  operator()<>(local_res10,local_res20,&local_20,local_res18);
  operator()<>(local_res10,local_38 + 1,&local_18,local_38);
  return;
}



/* ---- FUN_18000b46c @ 18000b46c ---- */

void FUN_18000b46c(__acrt_ptd *param_1)

{
  if (param_1 != (__acrt_ptd *)0x0) {
    destroy_ptd_array(param_1);
    _free_base(param_1);
  }
  return;
}



/* ---- destroy_ptd_array @ 18000b48c ---- */

/* Library Function - Single Match
    void __cdecl destroy_ptd_array(struct __acrt_ptd * __ptr64 const)
   
   Libraries: Visual Studio 2015 Release, Visual Studio 2017 Release, Visual Studio 2019 Release */

void __cdecl destroy_ptd_array(__acrt_ptd *param_1)

{
  undefined1 local_res10 [8];
  int local_res18 [2];
  int local_res20 [2];
  int local_28 [2];
  __acrt_ptd *local_20;
  __acrt_ptd **local_18;
  __acrt_ptd **local_10;
  
  local_18 = &local_20;
  local_res18[0] = 5;
  local_res20[0] = 5;
  local_10 = &local_20;
  local_28[0] = 4;
  local_28[1] = 4;
  local_20 = param_1;
  if (*(undefined **)param_1 != &DAT_180013ac0) {
    _free_base(*(undefined **)param_1);
  }
  _free_base(*(LPVOID *)(local_20 + 0x70));
  _free_base(*(LPVOID *)(local_20 + 0x58));
  _free_base(*(LPVOID *)(local_20 + 0x60));
  _free_base(*(LPVOID *)(local_20 + 0x68));
  _free_base(*(LPVOID *)(local_20 + 0x48));
  _free_base(*(LPVOID *)(local_20 + 0x50));
  _free_base(*(LPVOID *)(local_20 + 0x78));
  _free_base(*(LPVOID *)(local_20 + 0x80));
  _free_base(*(LPVOID *)(local_20 + 0x3c0));
  operator()<>(local_res10,local_res20,&local_18,local_res18);
  operator()<>(local_res10,local_28 + 1,&local_10,local_28);
  return;
}



/* ---- replace_current_thread_locale_nolock @ 18000b584 ---- */

/* Library Function - Single Match
    void __cdecl replace_current_thread_locale_nolock(struct __acrt_ptd * __ptr64 const,struct
   __crt_locale_data * __ptr64 const)
   
   Libraries: Visual Studio 2015 Release, Visual Studio 2017 Release, Visual Studio 2019 Release */

void __cdecl replace_current_thread_locale_nolock(__acrt_ptd *param_1,__crt_locale_data *param_2)

{
  undefined **ppuVar1;
  
  if (*(longlong *)(param_1 + 0x90) != 0) {
    __acrt_release_locale_ref(*(longlong *)(param_1 + 0x90));
    ppuVar1 = *(undefined ***)(param_1 + 0x90);
    if (((ppuVar1 != DAT_18001d1f8) && (ppuVar1 != &PTR_DAT_18001c050)) &&
       (*(int *)(ppuVar1 + 2) == 0)) {
      __acrt_free_locale(ppuVar1);
    }
  }
  *(__crt_locale_data **)(param_1 + 0x90) = param_2;
  if (param_2 != (__crt_locale_data *)0x0) {
    __acrt_add_locale_ref((longlong)param_2);
  }
  return;
}



/* ---- __acrt_freeptd @ 18000b5ec ---- */

/* Library Function - Single Match
    __acrt_freeptd
   
   Library: Visual Studio 2015 Release */

void __acrt_freeptd(void)

{
  __acrt_ptd *p_Var1;
  
  if (DAT_18001c040 != 0xffffffff) {
    p_Var1 = (__acrt_ptd *)__acrt_FlsGetValue(DAT_18001c040);
    if (p_Var1 != (__acrt_ptd *)0x0) {
      __acrt_FlsSetValue(DAT_18001c040,(LPVOID)0x0);
      destroy_ptd_array(p_Var1);
      _free_base(p_Var1);
    }
  }
  return;
}



/* ---- FUN_18000b630 @ 18000b630 ---- */

__acrt_ptd * FUN_18000b630(void)

{
  DWORD dwErrCode;
  int iVar1;
  __acrt_ptd *p_Var2;
  
  dwErrCode = GetLastError();
  if (DAT_18001c040 == 0xffffffff) {
LAB_18000b65a:
    p_Var2 = _calloc_base(1,0x3c8);
    if (p_Var2 == (__acrt_ptd *)0x0) {
      p_Var2 = (__acrt_ptd *)0x0;
    }
    else {
      iVar1 = __acrt_FlsSetValue(DAT_18001c040,p_Var2);
      if (iVar1 != 0) {
        construct_ptd_array(p_Var2);
        _free_base((LPVOID)0x0);
        goto LAB_18000b69b;
      }
    }
    _free_base(p_Var2);
  }
  else {
    p_Var2 = (__acrt_ptd *)__acrt_FlsGetValue(DAT_18001c040);
    if (p_Var2 == (__acrt_ptd *)0x0) goto LAB_18000b65a;
LAB_18000b69b:
    if (p_Var2 != (__acrt_ptd *)0x0) {
      SetLastError(dwErrCode);
      return p_Var2;
    }
  }
  SetLastError(dwErrCode);
                    /* WARNING: Subroutine does not return */
  abort();
}



/* ---- __acrt_getptd_noexit @ 18000b6c4 ---- */

/* Library Function - Single Match
    __acrt_getptd_noexit
   
   Library: Visual Studio 2015 Release */

__acrt_ptd * __acrt_getptd_noexit(void)

{
  DWORD dwErrCode;
  int iVar1;
  __acrt_ptd *p_Var2;
  
  dwErrCode = GetLastError();
  if ((DAT_18001c040 == 0xffffffff) ||
     (p_Var2 = (__acrt_ptd *)__acrt_FlsGetValue(DAT_18001c040), p_Var2 == (__acrt_ptd *)0x0)) {
    p_Var2 = _calloc_base(1,0x3c8);
    if (p_Var2 == (__acrt_ptd *)0x0) {
      p_Var2 = (__acrt_ptd *)0x0;
    }
    else {
      iVar1 = __acrt_FlsSetValue(DAT_18001c040,p_Var2);
      if (iVar1 != 0) {
        construct_ptd_array(p_Var2);
        _free_base((LPVOID)0x0);
        goto LAB_18000b736;
      }
    }
    _free_base(p_Var2);
  }
  else {
LAB_18000b736:
    if (p_Var2 != (__acrt_ptd *)0x0) {
      SetLastError(dwErrCode);
      return p_Var2;
    }
  }
  SetLastError(dwErrCode);
  return (__acrt_ptd *)0x0;
}



/* ---- __acrt_initialize_ptd @ 18000b764 ---- */

/* Library Function - Single Match
    __acrt_initialize_ptd
   
   Library: Visual Studio 2015 Release */

ulonglong __acrt_initialize_ptd(void)

{
  ulonglong uVar1;
  __acrt_ptd *p_Var2;
  uint7 extraout_var;
  
  uVar1 = __acrt_FlsAlloc(FUN_18000b46c);
  DAT_18001c040 = (int)uVar1;
  if (DAT_18001c040 != -1) {
    p_Var2 = __acrt_getptd_noexit();
    if (p_Var2 != (__acrt_ptd *)0x0) {
      return CONCAT71((int7)((ulonglong)p_Var2 >> 8),1);
    }
    __acrt_uninitialize_ptd();
    uVar1 = (ulonglong)extraout_var << 8;
  }
  return uVar1 & 0xffffffffffffff00;
}



/* ---- __acrt_uninitialize_ptd @ 18000b7a0 ---- */

/* Library Function - Single Match
    __acrt_uninitialize_ptd
   
   Library: Visual Studio 2015 Release */

undefined1 __acrt_uninitialize_ptd(void)

{
  if (DAT_18001c040 != 0xffffffff) {
    __acrt_FlsFree(DAT_18001c040);
    DAT_18001c040 = 0xffffffff;
  }
  return 1;
}



/* ---- FUN_18000b7c4 @ 18000b7c4 ---- */

void FUN_18000b7c4(longlong param_1,longlong *param_2)

{
  undefined **ppuVar1;
  
  if ((*param_2 != DAT_18001d1f8) && ((DAT_18001c810 & *(uint *)(param_1 + 0x3a8)) == 0)) {
    ppuVar1 = FUN_18000e244();
    *param_2 = (longlong)ppuVar1;
  }
  return;
}



/* ---- FUN_18000b7f8 @ 18000b7f8 ---- */

void FUN_18000b7f8(longlong param_1,longlong *param_2)

{
  int *piVar1;
  
  if (((undefined *)*param_2 != PTR_DAT_18001c4f8) &&
     ((DAT_18001c810 & *(uint *)(param_1 + 0x3a8)) == 0)) {
    piVar1 = FUN_18000d228();
    *param_2 = (longlong)piVar1;
  }
  return;
}



/* ---- FUN_18000b82c @ 18000b82c ---- */

undefined4 FUN_18000b82c(void)

{
  undefined4 uVar1;
  
  uVar1 = DAT_18001d1f0;
  LOCK();
  DAT_18001d1f0 = 1;
  UNLOCK();
  return uVar1;
}



/* ---- __acrt_uninitialize_locale @ 18000b838 ---- */

/* Library Function - Single Match
    __acrt_uninitialize_locale
   
   Library: Visual Studio 2015 Release */

void __acrt_uninitialize_locale(void)

{
  if (DAT_18001d1f8 != &PTR_DAT_18001c050) {
    __acrt_lock(4);
    DAT_18001d1f8 = _updatetlocinfoEx_nolock(&DAT_18001d1f8,&PTR_DAT_18001c050);
    __acrt_unlock(4);
  }
  return;
}



/* ---- isspace @ 18000b880 ---- */

/* Library Function - Single Match
    isspace
   
   Library: Visual Studio 2015 Release */

int __cdecl isspace(int _C)

{
  uint uVar1;
  longlong local_28;
  localeinfo_struct local_20;
  char local_10;
  
  if (DAT_18001d1f0 == 0) {
    uVar1 = *(ushort *)(PTR_DAT_18001c050 + (longlong)_C * 2) & 8;
  }
  else {
    _LocaleUpdate::_LocaleUpdate((_LocaleUpdate *)&local_28,(__crt_locale_pointers *)0x0);
    if ((int)(local_20.locinfo)->lc_collate_cp < 2) {
      uVar1 = *(ushort *)(*(longlong *)local_20.locinfo + (longlong)_C * 2) & 8;
    }
    else {
      uVar1 = _isctype_l(_C,8,&local_20);
    }
    if (local_10 != '\0') {
      *(uint *)(local_28 + 0x3a8) = *(uint *)(local_28 + 0x3a8) & 0xfffffffd;
    }
  }
  return uVar1;
}



/* ---- make_c_string_character_source<> @ 18000b8f4 ---- */

/* Library Function - Multiple Matches With Same Base Name
    class __crt_strtox::c_string_character_source<char> __cdecl
   __crt_strtox::make_c_string_character_source<char,char * __ptr64 * __ptr64>(char const * __ptr64
   const,char * __ptr64 * __ptr64 const)
    class __crt_strtox::c_string_character_source<wchar_t> __cdecl
   __crt_strtox::make_c_string_character_source<wchar_t,wchar_t * __ptr64 * __ptr64>(wchar_t const *
   __ptr64 const,wchar_t * __ptr64 * __ptr64 const)
   
   Library: Visual Studio 2015 Release */

undefined8 *
make_c_string_character_source<>(undefined8 *param_1,undefined8 param_2,undefined8 *param_3)

{
  *param_1 = param_2;
  param_1[1] = param_3;
  if (param_3 != (undefined8 *)0x0) {
    *param_3 = param_2;
  }
  return param_1;
}



/* ---- strtoull @ 18000b908 ---- */

/* Library Function - Single Match
    strtoull
   
   Library: Visual Studio 2015 Release */

void strtoull(undefined8 param_1,undefined8 *param_2,undefined4 param_3)

{
  undefined8 *puVar1;
  undefined8 local_18 [2];
  
  puVar1 = make_c_string_character_source<>(local_18,param_1,param_2);
  __crt_strtox::parse_integer<unsigned___int64,__crt_strtox::c_string_character_source<char>_>
            (0,puVar1,param_3,0);
  return;
}



/* ---- _mbtowc_l @ 18000b938 ---- */

/* Library Function - Single Match
    _mbtowc_l
   
   Library: Visual Studio 2015 Release */

int __cdecl _mbtowc_l(wchar_t *_DstCh,char *_SrcCh,size_t _SrcSizeInBytes,_locale_t _Locale)

{
  int iVar1;
  ulong *puVar2;
  uint uVar3;
  longlong local_28;
  localeinfo_struct local_20;
  char local_10;
  
  if ((_SrcCh != (char *)0x0) && (_SrcSizeInBytes != 0)) {
    if (*_SrcCh != '\0') {
      _LocaleUpdate::_LocaleUpdate((_LocaleUpdate *)&local_28,(__crt_locale_pointers *)_Locale);
      if ((local_20.locinfo)->locale_name[2] == (wchar_t *)0x0) {
        if (_DstCh != (wchar_t *)0x0) {
          *_DstCh = (ushort)(byte)*_SrcCh;
        }
        uVar3 = 1;
      }
      else {
        iVar1 = _isleadbyte_l((uint)(byte)*_SrcCh,&local_20);
        uVar3 = 1;
        if (iVar1 == 0) {
          iVar1 = MultiByteToWideChar((local_20.locinfo)->lc_time_cp,9,_SrcCh,1,_DstCh,
                                      (uint)(_DstCh != (wchar_t *)0x0));
          if (iVar1 != 0) goto LAB_18000ba66;
        }
        else {
          uVar3 = (local_20.locinfo)->lc_collate_cp;
          if ((((1 < (int)uVar3) && ((int)uVar3 <= (int)_SrcSizeInBytes)) &&
              (iVar1 = MultiByteToWideChar((local_20.locinfo)->lc_time_cp,9,_SrcCh,uVar3,_DstCh,
                                           (uint)(_DstCh != (wchar_t *)0x0)), iVar1 != 0)) ||
             (((ulonglong)(longlong)(int)(local_20.locinfo)->lc_collate_cp <= _SrcSizeInBytes &&
              (_SrcCh[1] != '\0')))) {
            uVar3 = (local_20.locinfo)->lc_collate_cp;
            goto LAB_18000ba66;
          }
        }
        puVar2 = __doserrno();
        uVar3 = 0xffffffff;
        *puVar2 = 0x2a;
      }
LAB_18000ba66:
      if (local_10 == '\0') {
        return uVar3;
      }
      *(uint *)(local_28 + 0x3a8) = *(uint *)(local_28 + 0x3a8) & 0xfffffffd;
      return uVar3;
    }
    if (_DstCh != (wchar_t *)0x0) {
      *_DstCh = L'\0';
    }
  }
  return 0;
}



/* ---- FUN_18000ba80 @ 18000ba80 ---- */

void FUN_18000ba80(wchar_t *param_1,char *param_2,size_t param_3)

{
  _mbtowc_l(param_1,param_2,param_3,(_locale_t)0x0);
  return;
}



/* ---- _fileno @ 18000ba88 ---- */

/* Library Function - Single Match
    _fileno
   
   Library: Visual Studio 2015 Release */

int __cdecl _fileno(FILE *_File)

{
  int iVar1;
  ulong *puVar2;
  
  if (_File == (FILE *)0x0) {
    puVar2 = __doserrno();
    *puVar2 = 0x16;
    FUN_18000aff4();
    iVar1 = -1;
  }
  else {
    iVar1 = _File->_flag;
  }
  return iVar1;
}



/* ---- __acrt_initialize_stdio @ 18000bab0 ---- */

/* Library Function - Single Match
    __acrt_initialize_stdio
   
   Library: Visual Studio 2015 Release */

undefined8 __acrt_initialize_stdio(void)

{
  longlong lVar1;
  undefined *puVar2;
  undefined4 *puVar3;
  longlong lVar4;
  longlong lVar5;
  
  lVar1 = 0;
  lVar4 = 3;
  if (DAT_18001d200 == 0) {
    DAT_18001d200 = 0x200;
  }
  else if (DAT_18001d200 < 3) {
    DAT_18001d200 = 3;
  }
  DAT_18001d208 = _calloc_base((longlong)DAT_18001d200,8);
  _free_base((LPVOID)0x0);
  if (DAT_18001d208 == (LPVOID)0x0) {
    DAT_18001d200 = 3;
    DAT_18001d208 = _calloc_base(3,8);
    _free_base((LPVOID)0x0);
    if (DAT_18001d208 == (LPVOID)0x0) {
      return 0xffffffff;
    }
  }
  puVar3 = &DAT_18001c1d8;
  puVar2 = &DAT_18001c1c0;
  lVar5 = lVar1;
  do {
    __acrt_InitializeCriticalSectionEx((LPCRITICAL_SECTION)(puVar2 + 0x30),4000,0);
    *(undefined **)(lVar5 + (longlong)DAT_18001d208) = puVar2;
    if (*(longlong *)((&DAT_18001d210)[lVar1 >> 6] + 0x28 + (ulonglong)((uint)lVar1 & 0x3f) * 0x40)
        + 2U < 3) {
      *puVar3 = 0xfffffffe;
    }
    lVar1 = lVar1 + 1;
    puVar2 = puVar2 + 0x58;
    lVar5 = lVar5 + 8;
    puVar3 = puVar3 + 0x16;
    lVar4 = lVar4 + -1;
  } while (lVar4 != 0);
  return 0;
}



/* ---- __acrt_uninitialize_stdio @ 18000bbd0 ---- */

/* Library Function - Single Match
    __acrt_uninitialize_stdio
   
   Library: Visual Studio 2015 Release */

void __acrt_uninitialize_stdio(void)

{
  longlong lVar1;
  
  FUN_18000e76c();
  _fcloseall();
  lVar1 = 0;
  do {
    __acrt_stdio_free_buffer_nolock(*(undefined8 **)(lVar1 + (longlong)DAT_18001d208));
    DeleteCriticalSection
              ((LPCRITICAL_SECTION)(*(longlong *)(lVar1 + (longlong)DAT_18001d208) + 0x30));
    lVar1 = lVar1 + 8;
  } while (lVar1 != 0x18);
  _free_base(DAT_18001d208);
  DAT_18001d208 = (LPVOID)0x0;
  return;
}



/* ---- FUN_18000bc2c @ 18000bc2c ---- */

void FUN_18000bc2c(longlong param_1)

{
                    /* WARNING: Could not recover jumptable at 0x00018000bc30. Too many branches */
                    /* WARNING: Treating indirect jump as call */
  EnterCriticalSection(param_1 + 0x30);
  return;
}



/* ---- FUN_18000bc38 @ 18000bc38 ---- */

void FUN_18000bc38(longlong param_1)

{
                    /* WARNING: Could not recover jumptable at 0x00018000bc3c. Too many branches */
                    /* WARNING: Treating indirect jump as call */
  LeaveCriticalSection(param_1 + 0x30);
  return;
}



/* ---- fegetround @ 18000bc44 ---- */

/* Library Function - Single Match
    fegetround
   
   Library: Visual Studio 2015 Release */

uint fegetround(void)

{
  uint uVar1;
  
  uVar1 = FUN_18000e89c();
  return uVar1 & 0x300;
}



/* ---- initialize_inherited_file_handles_nolock @ 18000bc58 ---- */

/* Library Function - Single Match
    void __cdecl initialize_inherited_file_handles_nolock(void)
   
   Library: Visual Studio 2015 Release */

void __cdecl initialize_inherited_file_handles_nolock(void)

{
  DWORD DVar1;
  longlong lVar2;
  byte *pbVar3;
  longlong lVar4;
  uint *puVar5;
  uint uVar6;
  ulonglong uVar7;
  _STARTUPINFOW local_78;
  
  GetStartupInfoW(&local_78);
  lVar4 = 0;
  if ((local_78.cbReserved2 != 0) && ((uint *)local_78.lpReserved2 != (uint *)0x0)) {
    puVar5 = (uint *)((longlong)local_78.lpReserved2 + 4);
    pbVar3 = (byte *)((longlong)(int)*(uint *)local_78.lpReserved2 + (longlong)puVar5);
    uVar6 = 0x2000;
    if ((int)*(uint *)local_78.lpReserved2 < 0x2000) {
      uVar6 = *(uint *)local_78.lpReserved2;
    }
    __acrt_lowio_ensure_fh_exists(uVar6);
    if ((int)DAT_18001d610 < (int)uVar6) {
      uVar6 = DAT_18001d610;
    }
    uVar7 = (ulonglong)uVar6;
    if (uVar6 != 0) {
      do {
        if ((((*(longlong *)pbVar3 != -1) && (*(longlong *)pbVar3 != -2)) && ((*puVar5 & 1) != 0))
           && (((*puVar5 & 8) != 0 || (DVar1 = GetFileType(*(HANDLE *)pbVar3), DVar1 != 0)))) {
          lVar2 = (ulonglong)((uint)lVar4 & 0x3f) * 0x40 + (&DAT_18001d210)[lVar4 >> 6];
          *(undefined8 *)(lVar2 + 0x28) = *(undefined8 *)pbVar3;
          *(byte *)(lVar2 + 0x38) = (byte)*puVar5;
        }
        lVar4 = lVar4 + 1;
        puVar5 = (uint *)((longlong)puVar5 + 1);
        pbVar3 = pbVar3 + 8;
        uVar7 = uVar7 - 1;
      } while (uVar7 != 0);
    }
  }
  return;
}



/* ---- initialize_stdio_handles_nolock @ 18000bd44 ---- */

/* Library Function - Single Match
    void __cdecl initialize_stdio_handles_nolock(void)
   
   Library: Visual Studio 2015 Release */

void __cdecl initialize_stdio_handles_nolock(void)

{
  uint uVar1;
  HANDLE hFile;
  DWORD nStdHandle;
  longlong lVar2;
  uint uVar3;
  longlong lVar4;
  
  uVar3 = 0;
  lVar4 = 0;
  do {
    lVar2 = (ulonglong)(uVar3 & 0x3f) * 0x40 + (&DAT_18001d210)[(longlong)(int)uVar3 >> 6];
    if (*(longlong *)(lVar2 + 0x28) + 2U < 2) {
      *(undefined1 *)(lVar2 + 0x38) = 0x81;
      if (uVar3 == 0) {
        nStdHandle = 0xfffffff6;
      }
      else if (uVar3 == 1) {
        nStdHandle = 0xfffffff5;
      }
      else {
        nStdHandle = 0xfffffff4;
      }
      hFile = GetStdHandle(nStdHandle);
      if ((longlong)hFile + 1U < 2) {
        uVar1 = 0;
      }
      else {
        uVar1 = GetFileType(hFile);
      }
      if (uVar1 == 0) {
        *(byte *)(lVar2 + 0x38) = *(byte *)(lVar2 + 0x38) | 0x40;
        *(undefined8 *)(lVar2 + 0x28) = 0xfffffffffffffffe;
        if (DAT_18001d208 != 0) {
          *(undefined4 *)(*(longlong *)(lVar4 + DAT_18001d208) + 0x18) = 0xfffffffe;
        }
      }
      else {
        *(HANDLE *)(lVar2 + 0x28) = hFile;
        if ((uVar1 & 0xff) == 2) {
          *(byte *)(lVar2 + 0x38) = *(byte *)(lVar2 + 0x38) | 0x40;
        }
        else if ((uVar1 & 0xff) == 3) {
          *(byte *)(lVar2 + 0x38) = *(byte *)(lVar2 + 0x38) | 8;
        }
      }
    }
    else {
      *(byte *)(lVar2 + 0x38) = *(byte *)(lVar2 + 0x38) | 0x80;
    }
    uVar3 = uVar3 + 1;
    lVar4 = lVar4 + 8;
  } while (uVar3 != 3);
  return;
}



/* ---- __acrt_initialize_lowio @ 18000be40 ---- */

/* Library Function - Single Match
    __acrt_initialize_lowio
   
   Library: Visual Studio 2015 Release */

bool __acrt_initialize_lowio(void)

{
  longlong lVar1;
  bool bVar2;
  
  __acrt_lock(7);
  lVar1 = __acrt_lowio_ensure_fh_exists(0);
  bVar2 = (int)lVar1 == 0;
  if (bVar2) {
    initialize_inherited_file_handles_nolock();
    initialize_stdio_handles_nolock();
  }
  __acrt_unlock(7);
  return bVar2;
}



/* ---- __acrt_uninitialize_lowio @ 18000be7c ---- */

/* Library Function - Single Match
    __acrt_uninitialize_lowio
   
   Libraries: Visual Studio 2015 Release, Visual Studio 2017 Release */

undefined1 __acrt_uninitialize_lowio(void)

{
  ulonglong uVar1;
  
  uVar1 = 0;
  do {
    if (*(LPCRITICAL_SECTION *)((longlong)&DAT_18001d210 + uVar1) != (LPCRITICAL_SECTION)0x0) {
      __acrt_lowio_destroy_handle_array(*(LPCRITICAL_SECTION *)((longlong)&DAT_18001d210 + uVar1));
      *(undefined8 *)((longlong)&DAT_18001d210 + uVar1) = 0;
    }
    uVar1 = uVar1 + 8;
  } while (uVar1 < 0x400);
  return 1;
}



/* ---- __acrt_initialize_locks @ 18000bebc ---- */

/* Library Function - Single Match
    __acrt_initialize_locks
   
   Library: Visual Studio 2015 Release */

undefined8 __acrt_initialize_locks(void)

{
  undefined8 uVar1;
  ulonglong uVar2;
  uint uVar3;
  
  uVar2 = 0;
  do {
    uVar1 = __acrt_InitializeCriticalSectionEx
                      ((LPCRITICAL_SECTION)(&DAT_18001d620 + uVar2 * 0x28),4000,0);
    if ((int)uVar1 == 0) {
      uVar2 = __acrt_uninitialize_locks();
      return uVar2 & 0xffffffffffffff00;
    }
    DAT_18001d828 = DAT_18001d828 + 1;
    uVar3 = (int)uVar2 + 1;
    uVar2 = (ulonglong)uVar3;
  } while (uVar3 < 0xd);
  return CONCAT71((int7)((ulonglong)uVar1 >> 8),1);
}



/* ---- __acrt_lock @ 18000bf04 ---- */

/* Library Function - Multiple Matches With Different Base Names
    __acrt_lock
    __acrt_unlock
   
   Library: Visual Studio 2015 Release */

void __acrt_lock(int param_1)

{
                    /* WARNING: Could not recover jumptable at 0x00018000bf16. Too many branches */
                    /* WARNING: Treating indirect jump as call */
  EnterCriticalSection(&DAT_18001d620 + (longlong)param_1 * 0x28);
  return;
}



/* ---- __acrt_uninitialize_locks @ 18000bf20 ---- */

/* Library Function - Single Match
    __acrt_uninitialize_locks
   
   Libraries: Visual Studio 2015 Release, Visual Studio 2017 Release, Visual Studio 2019 Release */

undefined8 __acrt_uninitialize_locks(void)

{
  undefined8 in_RAX;
  undefined8 extraout_RAX;
  ulonglong uVar1;
  
  uVar1 = (ulonglong)DAT_18001d828;
  while ((int)uVar1 != 0) {
    uVar1 = (ulonglong)((int)uVar1 - 1);
    DeleteCriticalSection((LPCRITICAL_SECTION)(&DAT_18001d620 + uVar1 * 0x28));
    DAT_18001d828 = DAT_18001d828 - 1;
    in_RAX = extraout_RAX;
  }
  return CONCAT71((int7)((ulonglong)in_RAX >> 8),1);
}



/* ---- __acrt_unlock @ 18000bf58 ---- */

/* Library Function - Single Match
    __acrt_unlock
   
   Library: Visual Studio 2015 Release */

void __acrt_unlock(int param_1)

{
                    /* WARNING: Could not recover jumptable at 0x00018000bf6a. Too many branches */
                    /* WARNING: Treating indirect jump as call */
  LeaveCriticalSection(&DAT_18001d620 + (longlong)param_1 * 0x28);
  return;
}



/* ---- try_get_function @ 18000bf74 ---- */

/* Library Function - Single Match
    void * __ptr64 __cdecl try_get_function(enum `anonymous namespace'::function_id,char const *
   __ptr64 const,enum A0x1dd686d3::module_id const * __ptr64 const,enum A0x1dd686d3::module_id const
   * __ptr64 const)
   
   Library: Visual Studio 2015 Release */

void * __cdecl
try_get_function(function_id param_1,char *param_2,module_id *param_3,module_id *param_4)

{
  longlong lVar1;
  module_id mVar2;
  LPCWSTR lpLibFileName;
  byte bVar3;
  DWORD DVar4;
  HMODULE hLibModule;
  FARPROC pFVar5;
  void *pvVar6;
  
  bVar3 = (byte)DAT_18001c000 & 0x3f;
  pvVar6 = (void *)((DAT_18001c000 ^ (&DAT_18001d8d0)[param_1]) >> bVar3 |
                   (DAT_18001c000 ^ (&DAT_18001d8d0)[param_1]) << 0x40 - bVar3);
  if (pvVar6 != (void *)0xffffffffffffffff) {
    if (pvVar6 != (void *)0x0) {
      return pvVar6;
    }
    for (; param_3 != param_4; param_3 = param_3 + 1) {
      mVar2 = *param_3;
      hLibModule = (HMODULE)(&DAT_18001d830)[mVar2];
      if (hLibModule == (HMODULE)0x0) {
        lpLibFileName = (LPCWSTR)(&PTR_u_api_ms_win_appmodel_runtime_l1_1_180014aa0)[mVar2];
        hLibModule = LoadLibraryExW(lpLibFileName,(HANDLE)0x0,0x800);
        if (hLibModule == (HMODULE)0x0) {
          DVar4 = GetLastError();
          if (DVar4 == 0x57) {
            hLibModule = LoadLibraryExW(lpLibFileName,(HANDLE)0x0,0);
          }
          else {
            hLibModule = (HMODULE)0x0;
          }
        }
        if (hLibModule != (HMODULE)0x0) {
          LOCK();
          lVar1 = (&DAT_18001d830)[mVar2];
          (&DAT_18001d830)[mVar2] = hLibModule;
          UNLOCK();
          if (lVar1 != 0) {
            FreeLibrary(hLibModule);
          }
          goto LAB_18000c070;
        }
        LOCK();
        (&DAT_18001d830)[mVar2] = 0xffffffffffffffff;
        UNLOCK();
      }
      else if (hLibModule != (HMODULE)0xffffffffffffffff) {
LAB_18000c070:
        if (hLibModule != (HMODULE)0x0) goto LAB_18000c08b;
      }
    }
    hLibModule = (HMODULE)0x0;
LAB_18000c08b:
    if ((hLibModule != (HMODULE)0x0) &&
       (pFVar5 = GetProcAddress(hLibModule,param_2), pFVar5 != (FARPROC)0x0)) {
      bVar3 = 0x40 - ((byte)DAT_18001c000 & 0x3f) & 0x3f;
      LOCK();
      (&DAT_18001d8d0)[param_1] =
           ((ulonglong)pFVar5 >> bVar3 | (longlong)pFVar5 << 0x40 - bVar3) ^ DAT_18001c000;
      UNLOCK();
      return pFVar5;
    }
    bVar3 = 0x40 - ((byte)DAT_18001c000 & 0x3f) & 0x3f;
    LOCK();
    (&DAT_18001d8d0)[param_1] = (0xffffffffffffffffU >> bVar3 | -1L << 0x40 - bVar3) ^ DAT_18001c000
    ;
    UNLOCK();
  }
  return (void *)0x0;
}



/* ---- __acrt_FlsAlloc @ 18000c114 ---- */

/* Library Function - Single Match
    __acrt_FlsAlloc
   
   Library: Visual Studio 2015 Release */

void __acrt_FlsAlloc(undefined8 param_1)

{
  code *pcVar1;
  
  pcVar1 = try_get_function(3,"FlsAlloc",(module_id *)&DAT_180014fd0,(module_id *)&DAT_180014fd8);
  if (pcVar1 == (code *)0x0) {
    TlsAlloc();
  }
  else {
    (*(code *)PTR__guard_check_icall_180012238)(pcVar1);
    (*pcVar1)(param_1);
  }
  return;
}



/* ---- __acrt_FlsFree @ 18000c16c ---- */

/* Library Function - Single Match
    __acrt_FlsFree
   
   Library: Visual Studio 2015 Release */

void __acrt_FlsFree(DWORD param_1)

{
  code *pcVar1;
  
  pcVar1 = try_get_function(4,"FlsFree",(module_id *)&DAT_180014fd8,(module_id *)&DAT_180014fe0);
  if (pcVar1 == (code *)0x0) {
    TlsFree(param_1);
  }
  else {
    (*(code *)PTR__guard_check_icall_180012238)(pcVar1);
    (*pcVar1)(param_1);
  }
  return;
}



/* ---- __acrt_FlsGetValue @ 18000c1c4 ---- */

/* Library Function - Single Match
    __acrt_FlsGetValue
   
   Library: Visual Studio 2015 Release */

void __acrt_FlsGetValue(DWORD param_1)

{
  code *pcVar1;
  
  pcVar1 = try_get_function(5,"FlsGetValue",(module_id *)&DAT_180014fe0,(module_id *)&DAT_180014fe8)
  ;
  if (pcVar1 == (code *)0x0) {
    TlsGetValue(param_1);
  }
  else {
    (*(code *)PTR__guard_check_icall_180012238)(pcVar1);
    (*pcVar1)(param_1);
  }
  return;
}



/* ---- __acrt_FlsSetValue @ 18000c21c ---- */

/* Library Function - Single Match
    __acrt_FlsSetValue
   
   Library: Visual Studio 2015 Release */

void __acrt_FlsSetValue(DWORD param_1,LPVOID param_2)

{
  code *pcVar1;
  
  pcVar1 = try_get_function(6,"FlsSetValue",(module_id *)&DAT_180014fe8,(module_id *)&DAT_180014ff0)
  ;
  if (pcVar1 == (code *)0x0) {
    TlsSetValue(param_1,param_2);
  }
  else {
    (*(code *)PTR__guard_check_icall_180012238)(pcVar1);
    (*pcVar1)(param_1,param_2);
  }
  return;
}



/* ---- __acrt_InitializeCriticalSectionEx @ 18000c284 ---- */

/* Library Function - Single Match
    __acrt_InitializeCriticalSectionEx
   
   Library: Visual Studio 2015 Release */

void __acrt_InitializeCriticalSectionEx(LPCRITICAL_SECTION param_1,DWORD param_2,undefined4 param_3)

{
  code *pcVar1;
  
  pcVar1 = try_get_function(0x14,"InitializeCriticalSectionEx",(module_id *)&DAT_180015010,
                            (module_id *)&DAT_180015018);
  if (pcVar1 == (code *)0x0) {
    InitializeCriticalSectionAndSpinCount(param_1,param_2);
  }
  else {
    (*(code *)PTR__guard_check_icall_180012238)(pcVar1);
    (*pcVar1)(param_1,param_2,param_3);
  }
  return;
}



/* ---- __acrt_LCMapStringEx @ 18000c2fc ---- */

/* Library Function - Single Match
    __acrt_LCMapStringEx
   
   Library: Visual Studio 2015 Release */

void __acrt_LCMapStringEx
               (wchar_t *param_1,DWORD param_2,LPCWSTR param_3,int param_4,LPWSTR param_5,
               int param_6,undefined8 param_7,undefined8 param_8,undefined8 param_9)

{
  LCID Locale;
  code *pcVar1;
  
  pcVar1 = try_get_function(0x16,"LCMapStringEx",(module_id *)&DAT_180015018,
                            (module_id *)"LCMapStringEx");
  if (pcVar1 == (code *)0x0) {
    Locale = __acrt_LocaleNameToLCID(param_1,0);
    LCMapStringW(Locale,param_2,param_3,param_4,param_5,param_6);
  }
  else {
    (*(code *)PTR__guard_check_icall_180012238)(pcVar1);
    (*pcVar1)(param_1,param_2,param_3,param_4,param_5,param_6,param_7,param_8,param_9);
  }
  return;
}



/* ---- __acrt_LocaleNameToLCID @ 18000c3ec ---- */

/* Library Function - Single Match
    __acrt_LocaleNameToLCID
   
   Library: Visual Studio 2015 Release */

void __acrt_LocaleNameToLCID(wchar_t *param_1,undefined4 param_2)

{
  code *pcVar1;
  
  pcVar1 = try_get_function(0x18,"LocaleNameToLCID",(module_id *)&DAT_180015030,
                            (module_id *)"LocaleNameToLCID");
  if (pcVar1 == (code *)0x0) {
    __acrt_DownlevelLocaleNameToLCID(param_1);
  }
  else {
    (*(code *)PTR__guard_check_icall_180012238)(pcVar1);
    (*pcVar1)(param_1,param_2);
  }
  return;
}



/* ---- __acrt_initialize_winapi_thunks @ 18000c454 ---- */

/* Library Function - Single Match
    __acrt_initialize_winapi_thunks
   
   Library: Visual Studio 2015 Release */

undefined8 __acrt_initialize_winapi_thunks(void)

{
  byte bVar1;
  ulonglong uVar2;
  longlong lVar3;
  ulonglong *puVar4;
  
  bVar1 = 0x40 - ((byte)DAT_18001c000 & 0x3f) & 0x3f;
  uVar2 = ((ulonglong)(0 >> bVar1) | 0L << 0x40 - bVar1) ^ DAT_18001c000;
  puVar4 = &DAT_18001d8d0;
  for (lVar3 = 0x20; lVar3 != 0; lVar3 = lVar3 + -1) {
    *puVar4 = uVar2;
    puVar4 = puVar4 + 1;
  }
  return CONCAT71((int7)(uVar2 >> 8),1);
}



/* ---- __acrt_is_packaged_app @ 18000c48c ---- */

/* Library Function - Single Match
    __acrt_is_packaged_app
   
   Library: Visual Studio 2015 Release */

bool __acrt_is_packaged_app(void)

{
  int iVar1;
  code *pcVar2;
  bool bVar3;
  undefined4 local_res8 [2];
  
  if (DAT_18001d9d0 == 0) {
    pcVar2 = try_get_function(8,"GetCurrentPackageId",(module_id *)&DAT_180014ff0,
                              (module_id *)"GetCurrentPackageId");
    if (pcVar2 != (code *)0x0) {
      local_res8[0] = 0;
      (*(code *)PTR__guard_check_icall_180012238)(pcVar2);
      iVar1 = (*pcVar2)(local_res8,0);
      if (iVar1 == 0x7a) {
        LOCK();
        UNLOCK();
        DAT_18001d9d0 = 1;
        return true;
      }
    }
    LOCK();
    DAT_18001d9d0 = 2;
    UNLOCK();
    bVar3 = false;
  }
  else {
    bVar3 = DAT_18001d9d0 == 1;
  }
  return bVar3;
}



/* ---- __acrt_uninitialize_winapi_thunks @ 18000c514 ---- */

/* Library Function - Single Match
    __acrt_uninitialize_winapi_thunks
   
   Libraries: Visual Studio 2015 Release, Visual Studio 2017 Release, Visual Studio 2019 Release */

undefined8 __acrt_uninitialize_winapi_thunks(char param_1)

{
  HMODULE hLibModule;
  undefined8 *in_RAX;
  undefined8 *puVar1;
  
  if (param_1 == '\0') {
    puVar1 = &DAT_18001d830;
    do {
      hLibModule = (HMODULE)*puVar1;
      if (hLibModule != (HMODULE)0x0) {
        if (hLibModule != (HMODULE)0xffffffffffffffff) {
          FreeLibrary(hLibModule);
        }
        *puVar1 = 0;
      }
      puVar1 = puVar1 + 1;
      in_RAX = &DAT_18001d8d0;
    } while (puVar1 != &DAT_18001d8d0);
  }
  return CONCAT71((int7)((ulonglong)in_RAX >> 8),1);
}



/* ---- FUN_18000c56c @ 18000c56c ---- */

ulonglong FUN_18000c56c(longlong *param_1,undefined8 *param_2)

{
  char *pcVar1;
  uint uVar2;
  errno_t eVar3;
  ulong *puVar4;
  ulonglong uVar5;
  uchar *puVar6;
  longlong lVar7;
  LPVOID pvVar8;
  longlong *plVar9;
  longlong *plVar10;
  ulonglong uVar11;
  ulonglong uVar12;
  ulonglong uVar13;
  longlong *plVar14;
  longlong lVar15;
  rsize_t _MaxCount;
  ulonglong uVar16;
  ulonglong local_res18;
  char *local_res20;
  longlong *local_58;
  longlong *plStack_50;
  undefined8 local_48;
  
  uVar11 = 0;
  if (param_2 == (undefined8 *)0x0) {
    puVar4 = __doserrno();
    *puVar4 = 0x16;
    FUN_18000aff4();
    uVar5 = 0x16;
  }
  else {
    *param_2 = 0;
    lVar7 = *param_1;
    local_58 = (longlong *)0x0;
    plStack_50 = (longlong *)0x0;
    local_48 = 0;
    while (plVar14 = plStack_50, plVar10 = local_58, lVar7 != 0) {
      local_res18 = CONCAT53(local_res18._3_5_,0x3f2a);
      puVar6 = (uchar *)FID_conflict_fallbackMethod((char *)*param_1,(char *)&local_res18);
      if (puVar6 == (uchar *)0x0) {
        uVar2 = FUN_18000c778((char *)*param_1,(char *)0x0,0,(longlong *)&local_58);
      }
      else {
        uVar2 = expand_argument_wildcards<>((uchar *)*param_1,puVar6,(longlong *)&local_58);
      }
      uVar5 = (ulonglong)uVar2;
      plVar10 = local_58;
      plVar14 = plStack_50;
      if (uVar2 != 0) goto LAB_18000c70c;
      param_1 = param_1 + 1;
      lVar7 = *param_1;
    }
    local_res18 = 0;
    uVar16 = ((longlong)plStack_50 - (longlong)local_58 >> 3) + 1;
    uVar5 = ((longlong)plStack_50 - (longlong)local_58) + 7U >> 3;
    if (plStack_50 < local_58) {
      uVar5 = uVar11;
    }
    plVar9 = local_58;
    uVar12 = uVar11;
    uVar13 = uVar11;
    if (uVar5 != 0) {
      do {
        lVar7 = -1;
        do {
          lVar7 = lVar7 + 1;
        } while (*(char *)(*plVar9 + lVar7) != '\0');
        plVar9 = plVar9 + 1;
        uVar13 = uVar13 + 1 + lVar7;
        uVar12 = uVar12 + 1;
        local_res18 = uVar13;
      } while (uVar12 != uVar5);
    }
    pvVar8 = __acrt_allocate_buffer_for_argv(uVar16,local_res18,1);
    uVar5 = 0xffffffffffffffff;
    if (pvVar8 != (LPVOID)0x0) {
      pcVar1 = (char *)((longlong)pvVar8 + uVar16 * 8);
      local_res20 = pcVar1;
      if (plVar10 != plVar14) {
        plVar9 = plVar10;
        do {
          lVar7 = -1;
          do {
            lVar15 = lVar7;
            lVar7 = lVar15 + 1;
          } while (((char *)*plVar9)[lVar7] != '\0');
          _MaxCount = lVar15 + 2;
          eVar3 = strncpy_s(local_res20,(rsize_t)(pcVar1 + (local_res18 - (longlong)local_res20)),
                            (char *)*plVar9,_MaxCount);
          if (eVar3 != 0) {
                    /* WARNING: Subroutine does not return */
            _invoke_watson((wchar_t *)0x0,(wchar_t *)0x0,(wchar_t *)0x0,0,0);
          }
          *(char **)(((longlong)pvVar8 - (longlong)plVar10) + (longlong)plVar9) = local_res20;
          local_res20 = local_res20 + _MaxCount;
          plVar9 = plVar9 + 1;
        } while (plVar9 != plVar14);
      }
      *param_2 = pvVar8;
      uVar5 = uVar11;
    }
    _free_base((LPVOID)0x0);
LAB_18000c70c:
    uVar16 = (ulonglong)((longlong)plVar14 + (7 - (longlong)plVar10)) >> 3;
    if (plVar14 < plVar10) {
      uVar16 = uVar11;
    }
    plVar14 = plVar10;
    if (uVar16 != 0) {
      do {
        _free_base((LPVOID)*plVar14);
        uVar11 = uVar11 + 1;
        plVar14 = plVar14 + 1;
      } while (uVar11 != uVar16);
    }
    _free_base(plVar10);
    uVar5 = uVar5 & 0xffffffff;
  }
  return uVar5;
}



/* ---- FUN_18000c778 @ 18000c778 ---- */

int FUN_18000c778(char *param_1,char *param_2,rsize_t param_3,longlong *param_4)

{
  int iVar1;
  errno_t eVar2;
  char *_Dst;
  longlong lVar3;
  ulonglong _MaxCount;
  ulonglong _SizeInBytes;
  longlong lVar4;
  
  lVar3 = -1;
  do {
    lVar4 = lVar3;
    lVar3 = lVar4 + 1;
  } while (param_1[lVar3] != '\0');
  _MaxCount = lVar4 + 2;
  if (-param_3 - 1 < _MaxCount) {
    iVar1 = 0xc;
  }
  else {
    _SizeInBytes = param_3 + 1 + _MaxCount;
    _Dst = _calloc_base(_SizeInBytes,1);
    if (param_3 != 0) {
      eVar2 = strncpy_s(_Dst,_SizeInBytes,param_2,param_3);
      if (eVar2 != 0) {
                    /* WARNING: Subroutine does not return */
        _invoke_watson((wchar_t *)0x0,(wchar_t *)0x0,(wchar_t *)0x0,0,0);
      }
    }
    eVar2 = strncpy_s(_Dst + param_3,_SizeInBytes - param_3,param_1,_MaxCount);
    if (eVar2 != 0) {
                    /* WARNING: Subroutine does not return */
      _invoke_watson((wchar_t *)0x0,(wchar_t *)0x0,(wchar_t *)0x0,0,0);
    }
    iVar1 = expand_if_necessary(param_4);
    if (iVar1 == 0) {
      *(char **)param_4[1] = _Dst;
      param_4[1] = param_4[1] + 8;
      iVar1 = 0;
    }
    else {
      _free_base(_Dst);
    }
    _free_base((LPVOID)0x0);
  }
  return iVar1;
}



/* ---- expand_argument_wildcards<> @ 18000c888 ---- */

/* WARNING: Function: __security_check_cookie replaced with injection: security_check_cookie */
/* Library Function - Multiple Matches With Same Base Name
    int __cdecl expand_argument_wildcards<char>(char * __ptr64 const,char * __ptr64 const,class
   `anonymous namespace'::argument_list<char> & __ptr64)
    int __cdecl expand_argument_wildcards<char>(char * __ptr64 const,char * __ptr64 const,class
   `anonymous namespace'::argument_list<char> & __ptr64)
   
   Library: Visual Studio 2015 Release */

int expand_argument_wildcards<>(uchar *param_1,uchar *param_2,longlong *param_3)

{
  byte bVar1;
  int iVar2;
  BOOL BVar3;
  HANDLE hFindFile;
  byte bVar4;
  longlong lVar5;
  longlong lVar6;
  undefined1 auStackY_1a8 [32];
  _WIN32_FIND_DATAA local_178;
  ulonglong local_38;
  
  local_38 = DAT_18001c000 ^ (ulonglong)auStackY_1a8;
  while ((param_2 != param_1 &&
         ((0x2d < (byte)(*param_2 - 0x2f) ||
          ((0x200000000801U >> ((longlong)(char)(*param_2 - 0x2f) & 0x3fU) & 1) == 0))))) {
    param_2 = (uchar *)FUN_18000f174(param_1,param_2);
  }
  if ((*param_2 == ':') && (param_2 != param_1 + 1)) {
    iVar2 = FUN_18000c778((char *)param_1,(char *)0x0,0,param_3);
  }
  else {
    bVar4 = *param_2 - 0x2f;
    if ((0x2d < bVar4) || (bVar1 = 1, (0x200000000801U >> ((longlong)(char)bVar4 & 0x3fU) & 1) == 0)
       ) {
      bVar1 = 0;
    }
    FUN_180003320((undefined1 (*) [16])&local_178,0,0x140);
    hFindFile = FindFirstFileExA((LPCSTR)param_1,FindExInfoStandard,&local_178,FindExSearchNameMatch
                                 ,(LPVOID)0x0,0);
    if (hFindFile == (HANDLE)0xffffffffffffffff) {
      iVar2 = FUN_18000c778((char *)param_1,(char *)0x0,0,param_3);
    }
    else {
      lVar6 = param_3[1] - *param_3 >> 3;
      do {
        if (((local_178.cFileName[0] != '.') ||
            ((local_178.cFileName[1] != '\0' &&
             ((local_178.cFileName[1] != '.' || (local_178.cFileName[2] != '\0')))))) &&
           (iVar2 = FUN_18000c778(local_178.cFileName,(char *)param_1,
                                  -(ulonglong)bVar1 & (ulonglong)(param_2 + (1 - (longlong)param_1))
                                  ,param_3), iVar2 != 0)) goto LAB_18000c979;
        BVar3 = FindNextFileA(hFindFile,&local_178);
      } while (BVar3 != 0);
      lVar5 = param_3[1] - *param_3 >> 3;
      iVar2 = 0;
      if (lVar6 != lVar5) {
        qsort((void *)(*param_3 + lVar6 * 8),lVar5 - lVar6,8,(_PtFuncCompare *)&LAB_18000c558);
      }
    }
LAB_18000c979:
    if (hFindFile != (HANDLE)0xffffffffffffffff) {
      FindClose(hFindFile);
    }
  }
  return iVar2;
}



/* ---- expand_if_necessary @ 18000ca34 ---- */

/* Library Function - Multiple Matches With Same Base Name
    private: int __cdecl `anonymous namespace'::argument_list<char>::expand_if_necessary(void)
   __ptr64
    private: int __cdecl `anonymous namespace'::argument_list<char>::expand_if_necessary(void)
   __ptr64
    private: int __cdecl `anonymous namespace'::argument_list<wchar_t>::expand_if_necessary(void)
   __ptr64
    private: int __cdecl `anonymous namespace'::argument_list<wchar_t>::expand_if_necessary(void)
   __ptr64
   
   Library: Visual Studio 2015 Release */

undefined4 expand_if_necessary(longlong *param_1)

{
  longlong lVar1;
  LPVOID pvVar2;
  undefined4 uVar3;
  ulonglong uVar4;
  
  if (param_1[1] == param_1[2]) {
    uVar3 = 0;
    if (*param_1 == 0) {
      pvVar2 = _calloc_base(4,8);
      *param_1 = (longlong)pvVar2;
      _free_base((LPVOID)0x0);
      lVar1 = *param_1;
      if (lVar1 != 0) {
        param_1[1] = lVar1;
        param_1[2] = lVar1 + 0x20;
        goto LAB_18000ca55;
      }
    }
    else {
      uVar4 = param_1[2] - *param_1 >> 3;
      if (uVar4 < 0x8000000000000000) {
        pvVar2 = _recalloc_base((void *)*param_1,uVar4 * 2,8);
        if (pvVar2 == (LPVOID)0x0) {
          uVar3 = 0xc;
        }
        else {
          *param_1 = (longlong)pvVar2;
          param_1[1] = (longlong)((longlong)pvVar2 + uVar4 * 8);
          param_1[2] = (longlong)((longlong)pvVar2 + uVar4 * 0x10);
        }
        _free_base((LPVOID)0x0);
        return uVar3;
      }
    }
    uVar3 = 0xc;
  }
  else {
LAB_18000ca55:
    uVar3 = 0;
  }
  return uVar3;
}



/* ---- thunk_FUN_18000c56c @ 18000cafc ---- */

ulonglong thunk_FUN_18000c56c(longlong *param_1,undefined8 *param_2)

{
  char *pcVar1;
  uint uVar2;
  errno_t eVar3;
  ulong *puVar4;
  ulonglong uVar5;
  uchar *puVar6;
  longlong lVar7;
  LPVOID pvVar8;
  longlong *plVar9;
  longlong *plVar10;
  ulonglong uVar11;
  ulonglong uVar12;
  ulonglong uVar13;
  longlong *plVar14;
  longlong lVar15;
  rsize_t _MaxCount;
  ulonglong uVar16;
  ulonglong uStackX_18;
  char *pcStackX_20;
  longlong *plStack_58;
  longlong *plStack_50;
  undefined8 uStack_48;
  
  uVar11 = 0;
  if (param_2 == (undefined8 *)0x0) {
    puVar4 = __doserrno();
    *puVar4 = 0x16;
    FUN_18000aff4();
    uVar5 = 0x16;
  }
  else {
    *param_2 = 0;
    lVar7 = *param_1;
    plStack_58 = (longlong *)0x0;
    plStack_50 = (longlong *)0x0;
    uStack_48 = 0;
    while (plVar14 = plStack_50, plVar10 = plStack_58, lVar7 != 0) {
      uStackX_18 = CONCAT53(uStackX_18._3_5_,0x3f2a);
      puVar6 = (uchar *)FID_conflict_fallbackMethod((char *)*param_1,(char *)&uStackX_18);
      if (puVar6 == (uchar *)0x0) {
        uVar2 = FUN_18000c778((char *)*param_1,(char *)0x0,0,(longlong *)&plStack_58);
      }
      else {
        uVar2 = expand_argument_wildcards<>((uchar *)*param_1,puVar6,(longlong *)&plStack_58);
      }
      uVar5 = (ulonglong)uVar2;
      plVar10 = plStack_58;
      plVar14 = plStack_50;
      if (uVar2 != 0) goto LAB_18000c70c;
      param_1 = param_1 + 1;
      lVar7 = *param_1;
    }
    uStackX_18 = 0;
    uVar16 = ((longlong)plStack_50 - (longlong)plStack_58 >> 3) + 1;
    uVar5 = ((longlong)plStack_50 - (longlong)plStack_58) + 7U >> 3;
    if (plStack_50 < plStack_58) {
      uVar5 = uVar11;
    }
    plVar9 = plStack_58;
    uVar12 = uVar11;
    uVar13 = uVar11;
    if (uVar5 != 0) {
      do {
        lVar7 = -1;
        do {
          lVar7 = lVar7 + 1;
        } while (*(char *)(*plVar9 + lVar7) != '\0');
        plVar9 = plVar9 + 1;
        uVar13 = uVar13 + 1 + lVar7;
        uVar12 = uVar12 + 1;
        uStackX_18 = uVar13;
      } while (uVar12 != uVar5);
    }
    pvVar8 = __acrt_allocate_buffer_for_argv(uVar16,uStackX_18,1);
    uVar5 = 0xffffffffffffffff;
    if (pvVar8 != (LPVOID)0x0) {
      pcVar1 = (char *)((longlong)pvVar8 + uVar16 * 8);
      pcStackX_20 = pcVar1;
      if (plVar10 != plVar14) {
        plVar9 = plVar10;
        do {
          lVar7 = -1;
          do {
            lVar15 = lVar7;
            lVar7 = lVar15 + 1;
          } while (((char *)*plVar9)[lVar7] != '\0');
          _MaxCount = lVar15 + 2;
          eVar3 = strncpy_s(pcStackX_20,(rsize_t)(pcVar1 + (uStackX_18 - (longlong)pcStackX_20)),
                            (char *)*plVar9,_MaxCount);
          if (eVar3 != 0) {
                    /* WARNING: Subroutine does not return */
            _invoke_watson((wchar_t *)0x0,(wchar_t *)0x0,(wchar_t *)0x0,0,0);
          }
          *(char **)(((longlong)pvVar8 - (longlong)plVar10) + (longlong)plVar9) = pcStackX_20;
          pcStackX_20 = pcStackX_20 + _MaxCount;
          plVar9 = plVar9 + 1;
        } while (plVar9 != plVar14);
      }
      *param_2 = pvVar8;
      uVar5 = uVar11;
    }
    _free_base((LPVOID)0x0);
LAB_18000c70c:
    uVar16 = (ulonglong)((longlong)plVar14 + (7 - (longlong)plVar10)) >> 3;
    if (plVar14 < plVar10) {
      uVar16 = uVar11;
    }
    plVar14 = plVar10;
    if (uVar16 != 0) {
      do {
        _free_base((LPVOID)*plVar14);
        uVar11 = uVar11 + 1;
        plVar14 = plVar14 + 1;
      } while (uVar11 != uVar16);
    }
    _free_base(plVar10);
    uVar5 = uVar5 & 0xffffffff;
  }
  return uVar5;
}



/* ---- operator()<> @ 18000cb04 ---- */

/* Library Function - Multiple Matches With Same Base Name
    public: void __cdecl __crt_seh_guarded_call<void>::operator()<class
   <lambda_99476a1ad63dd22509b5d3e65b0ffc95>,class <lambda_ad1ced32f4ac17aa236e5ef05d6b3b7c> &
   __ptr64,class <lambda_f7424dd8d45958661754dc4f2697e9c3> >(class
   <lambda_99476a1ad63dd22509b5d3e65b0ffc95> && __ptr64,class
   <lambda_ad1ced32f4ac17aa236e5ef05d6b3b7c> & __ptr64,class
   <lambda_f7424dd8d45958661754dc4f2697e9c3> && __ptr64) __ptr64
    public: void __cdecl __crt_seh_guarded_call<void>::operator()<class
   <lambda_d80eeec6fff315bfe5c115232f3240e3>,class <lambda_6e4b09c48022b2350581041d5f6b0c4c> &
   __ptr64,class <lambda_2358e3775559c9db80273638284d5e45> >(class
   <lambda_d80eeec6fff315bfe5c115232f3240e3> && __ptr64,class
   <lambda_6e4b09c48022b2350581041d5f6b0c4c> & __ptr64,class
   <lambda_2358e3775559c9db80273638284d5e45> && __ptr64) __ptr64
   
   Libraries: Visual Studio 2015 Release, Visual Studio 2017 Release, Visual Studio 2019 Release */

void operator()<>(undefined8 param_1,int *param_2,undefined8 *param_3,int *param_4)

{
  __acrt_lock(*param_2);
  FUN_18000cb3c(param_3);
  __acrt_unlock(*param_4);
  return;
}



/* ---- FUN_18000cb3c @ 18000cb3c ---- */

/* WARNING: Globals starting with '_' overlap smaller symbols at the same address */

void FUN_18000cb3c(undefined8 *param_1)

{
  undefined8 *puVar1;
  int iVar2;
  undefined8 uVar3;
  undefined8 *puVar4;
  undefined8 *puVar5;
  ulong *puVar6;
  undefined8 *puVar7;
  longlong lVar8;
  longlong lVar9;
  
  _DAT_18001d9d4 = *(undefined4 *)(*(longlong *)(*(longlong *)*param_1 + 0x88) + 4);
  _DAT_18001d9d8 = *(undefined4 *)(*(longlong *)(*(longlong *)*param_1 + 0x88) + 8);
  _DAT_18001d9f0 = *(undefined8 *)(*(longlong *)(*(longlong *)*param_1 + 0x88) + 0x220);
  puVar4 = (undefined8 *)(*(longlong *)(*(longlong *)*param_1 + 0x88) + 0xc);
  if (puVar4 == (undefined8 *)0x0) {
    _DAT_18001d9e0 = 0;
    _DAT_18001d9e8 = 0;
    puVar6 = __doserrno();
    *puVar6 = 0x16;
    FUN_18000aff4();
  }
  else {
    _DAT_18001d9e0 = *puVar4;
    _DAT_18001d9e8 = *(undefined4 *)(*(longlong *)(*(longlong *)*param_1 + 0x88) + 0x14);
  }
  lVar9 = 2;
  puVar4 = (undefined8 *)(*(longlong *)(*(longlong *)*param_1 + 0x88) + 0x18);
  if (puVar4 == (undefined8 *)0x0) {
    FUN_180003320((undefined1 (*) [16])&DAT_18001c600,0,0x101);
    puVar6 = __doserrno();
    *puVar6 = 0x16;
    FUN_18000aff4();
  }
  else {
    lVar8 = 2;
    puVar5 = (undefined8 *)&DAT_18001c600;
    do {
      uVar3 = puVar4[1];
      *puVar5 = *puVar4;
      puVar5[1] = uVar3;
      uVar3 = puVar4[3];
      puVar5[2] = puVar4[2];
      puVar5[3] = uVar3;
      uVar3 = puVar4[5];
      puVar5[4] = puVar4[4];
      puVar5[5] = uVar3;
      uVar3 = puVar4[7];
      puVar5[6] = puVar4[6];
      puVar5[7] = uVar3;
      uVar3 = puVar4[9];
      puVar5[8] = puVar4[8];
      puVar5[9] = uVar3;
      uVar3 = puVar4[0xb];
      puVar5[10] = puVar4[10];
      puVar5[0xb] = uVar3;
      uVar3 = puVar4[0xd];
      puVar5[0xc] = puVar4[0xc];
      puVar5[0xd] = uVar3;
      puVar7 = puVar5 + 0x10;
      puVar1 = puVar4 + 0xe;
      uVar3 = puVar4[0xf];
      puVar4 = puVar4 + 0x10;
      puVar5[0xe] = *puVar1;
      puVar5[0xf] = uVar3;
      lVar8 = lVar8 + -1;
      puVar5 = puVar7;
    } while (lVar8 != 0);
    *(undefined1 *)puVar7 = *(undefined1 *)puVar4;
  }
  puVar5 = (undefined8 *)(*(longlong *)(*(longlong *)*param_1 + 0x88) + 0x119);
  puVar4 = (undefined8 *)&DAT_18001c710;
  if (puVar5 == (undefined8 *)0x0) {
    FUN_180003320((undefined1 (*) [16])&DAT_18001c710,0,0x100);
    puVar6 = __doserrno();
    *puVar6 = 0x16;
    FUN_18000aff4();
  }
  else {
    do {
      uVar3 = puVar5[1];
      *puVar4 = *puVar5;
      puVar4[1] = uVar3;
      uVar3 = puVar5[3];
      puVar4[2] = puVar5[2];
      puVar4[3] = uVar3;
      uVar3 = puVar5[5];
      puVar4[4] = puVar5[4];
      puVar4[5] = uVar3;
      uVar3 = puVar5[7];
      puVar4[6] = puVar5[6];
      puVar4[7] = uVar3;
      uVar3 = puVar5[9];
      puVar4[8] = puVar5[8];
      puVar4[9] = uVar3;
      uVar3 = puVar5[0xb];
      puVar4[10] = puVar5[10];
      puVar4[0xb] = uVar3;
      uVar3 = puVar5[0xd];
      puVar4[0xc] = puVar5[0xc];
      puVar4[0xd] = uVar3;
      puVar1 = puVar5 + 0xe;
      uVar3 = puVar5[0xf];
      puVar5 = puVar5 + 0x10;
      puVar4[0xe] = *puVar1;
      puVar4[0xf] = uVar3;
      lVar9 = lVar9 + -1;
      puVar4 = puVar4 + 0x10;
    } while (lVar9 != 0);
  }
  LOCK();
  iVar2 = *(int *)PTR_DAT_18001c4f8;
  *(int *)PTR_DAT_18001c4f8 = *(int *)PTR_DAT_18001c4f8 + -1;
  UNLOCK();
  if ((iVar2 == 1) && ((undefined4 *)PTR_DAT_18001c4f8 != &DAT_18001c2d0)) {
    _free_base(PTR_DAT_18001c4f8);
  }
  PTR_DAT_18001c4f8 = *(undefined **)(*(longlong *)*param_1 + 0x88);
  LOCK();
  **(int **)(*(longlong *)*param_1 + 0x88) = **(int **)(*(longlong *)*param_1 + 0x88) + 1;
  UNLOCK();
  return;
}



/* ---- getSystemCP @ 18000cd54 ---- */

/* Library Function - Single Match
    int __cdecl getSystemCP(int)
   
   Library: Visual Studio 2015 Release */

int __cdecl getSystemCP(int param_1)

{
  longlong local_28;
  longlong local_20;
  char local_10;
  
  _LocaleUpdate::_LocaleUpdate((_LocaleUpdate *)&local_28,(__crt_locale_pointers *)0x0);
  DAT_18001d9ec = 0;
  if (param_1 == -2) {
    DAT_18001d9ec = 1;
    param_1 = GetOEMCP();
  }
  else if (param_1 == -3) {
    DAT_18001d9ec = 1;
    param_1 = GetACP();
  }
  else if (param_1 == -4) {
    DAT_18001d9ec = 1;
    param_1 = *(UINT *)(local_20 + 0xc);
  }
  if (local_10 != '\0') {
    *(uint *)(local_28 + 0x3a8) = *(uint *)(local_28 + 0x3a8) & 0xfffffffd;
  }
  return param_1;
}



/* ---- setSBCS @ 18000cdd4 ---- */

/* Library Function - Single Match
    void __cdecl setSBCS(struct __crt_multibyte_data * __ptr64)
   
   Library: Visual Studio 2015 Release */

void __cdecl setSBCS(__crt_multibyte_data *param_1)

{
  longlong lVar1;
  __crt_multibyte_data *p_Var2;
  longlong lVar3;
  __crt_multibyte_data *p_Var4;
  
  p_Var2 = param_1 + 0x18;
  lVar3 = 0x101;
  FUN_180003320((undefined1 (*) [16])p_Var2,0,0x101);
  *(undefined8 *)(param_1 + 4) = 0;
  *(undefined8 *)(param_1 + 0x220) = 0;
  p_Var4 = param_1 + 0xc;
  for (lVar1 = 6; lVar1 != 0; lVar1 = lVar1 + -1) {
    *(undefined2 *)p_Var4 = 0;
    p_Var4 = p_Var4 + 2;
  }
  do {
    *p_Var2 = p_Var2[(longlong)&DAT_18001c2d0 - (longlong)param_1];
    p_Var2 = p_Var2 + 1;
    lVar3 = lVar3 + -1;
  } while (lVar3 != 0);
  p_Var2 = param_1 + 0x119;
  lVar1 = 0x100;
  do {
    *p_Var2 = p_Var2[(longlong)&DAT_18001c2d0 - (longlong)param_1];
    p_Var2 = p_Var2 + 1;
    lVar1 = lVar1 + -1;
  } while (lVar1 != 0);
  return;
}



/* ---- setSBUpLow @ 18000ce64 ---- */

/* WARNING: Function: __security_check_cookie replaced with injection: security_check_cookie */
/* Library Function - Single Match
    void __cdecl setSBUpLow(struct __crt_multibyte_data * __ptr64)
   
   Library: Visual Studio 2015 Release */

void __cdecl setSBUpLow(__crt_multibyte_data *param_1)

{
  byte bVar1;
  __crt_multibyte_data _Var2;
  BOOL BVar3;
  uint uVar4;
  CHAR *pCVar5;
  ulonglong uVar6;
  __crt_multibyte_data *p_Var7;
  BYTE *pBVar8;
  WORD *pWVar9;
  longlong lVar10;
  undefined1 auStackY_788 [32];
  _cpinfo local_738;
  CHAR local_718 [231];
  __crt_multibyte_data a_Stack_631 [25];
  char local_618 [231];
  __crt_multibyte_data a_Stack_531 [25];
  char local_518 [256];
  WORD local_418 [512];
  ulonglong local_18;
  
  local_18 = DAT_18001c000 ^ (ulonglong)auStackY_788;
  BVar3 = GetCPInfo(*(UINT *)(param_1 + 4),&local_738);
  lVar10 = 0x100;
  if (BVar3 == 0) {
    uVar4 = 0;
    p_Var7 = param_1 + 0x19;
    do {
      if (uVar4 - 0x41 < 0x1a) {
        *p_Var7 = (__crt_multibyte_data)((byte)*p_Var7 | 0x10);
        _Var2 = (__crt_multibyte_data)((char)uVar4 + 0x20);
LAB_18000d00a:
        p_Var7[0x100] = _Var2;
      }
      else {
        if (uVar4 - 0x61 < 0x1a) {
          *p_Var7 = (__crt_multibyte_data)((byte)*p_Var7 | 0x20);
          _Var2 = (__crt_multibyte_data)((char)uVar4 - 0x20);
          goto LAB_18000d00a;
        }
        p_Var7[0x100] = (__crt_multibyte_data)0x0;
      }
      uVar4 = uVar4 + 1;
      p_Var7 = p_Var7 + 1;
    } while (uVar4 < 0x100);
  }
  else {
    uVar4 = 0;
    pCVar5 = local_718;
    do {
      *pCVar5 = (CHAR)uVar4;
      uVar4 = uVar4 + 1;
      pCVar5 = pCVar5 + 1;
    } while (uVar4 < 0x100);
    pBVar8 = local_738.LeadByte;
    local_718[0] = ' ';
    while (local_738.LeadByte[0] != 0) {
      bVar1 = pBVar8[1];
      uVar6 = (ulonglong)local_738.LeadByte[0];
      while ((uVar4 = (uint)uVar6, uVar4 <= bVar1 && (uVar4 < 0x100))) {
        local_718[uVar6] = ' ';
        uVar6 = (ulonglong)(uVar4 + 1);
      }
      pBVar8 = pBVar8 + 2;
      local_738.LeadByte[0] = *pBVar8;
    }
    __acrt_GetStringTypeA
              ((__crt_locale_pointers *)0x0,1,local_718,0x100,local_418,*(UINT *)(param_1 + 4),0);
    __acrt_LCMapStringA((__crt_locale_pointers *)0x0,*(wchar_t **)(param_1 + 0x220),0x100,local_718,
                        0x100,local_618,0x100,*(int *)(param_1 + 4),0);
    __acrt_LCMapStringA((__crt_locale_pointers *)0x0,*(wchar_t **)(param_1 + 0x220),0x200,local_718,
                        0x100,local_518,0x100,*(int *)(param_1 + 4),0);
    pWVar9 = local_418;
    p_Var7 = param_1 + 0x19;
    do {
      if ((*pWVar9 & 1) == 0) {
        if ((*pWVar9 & 2) != 0) {
          *p_Var7 = (__crt_multibyte_data)((byte)*p_Var7 | 0x20);
          _Var2 = p_Var7[(longlong)(a_Stack_531 + -(longlong)param_1)];
          goto LAB_18000cfc5;
        }
        p_Var7[0x100] = (__crt_multibyte_data)0x0;
      }
      else {
        *p_Var7 = (__crt_multibyte_data)((byte)*p_Var7 | 0x10);
        _Var2 = p_Var7[(longlong)(a_Stack_631 + -(longlong)param_1)];
LAB_18000cfc5:
        p_Var7[0x100] = _Var2;
      }
      p_Var7 = p_Var7 + 1;
      pWVar9 = pWVar9 + 1;
      lVar10 = lVar10 + -1;
    } while (lVar10 != 0);
  }
  return;
}



/* ---- FUN_18000d048 @ 18000d048 ---- */

int FUN_18000d048(int param_1,char param_2)

{
  int iVar1;
  int *piVar2;
  undefined8 *puVar3;
  int iVar4;
  __crt_multibyte_data *p_Var5;
  undefined8 *puVar6;
  undefined8 uVar7;
  ulong *puVar8;
  __crt_multibyte_data *p_Var9;
  longlong lVar10;
  __crt_multibyte_data *p_Var11;
  undefined1 local_res18 [8];
  int local_res20 [2];
  int local_38 [2];
  __acrt_ptd *local_30;
  __acrt_ptd **local_28 [2];
  
  local_30 = FUN_18000b630();
  FUN_18000d228();
  iVar4 = getSystemCP(param_1);
  if (iVar4 == *(int *)(*(longlong *)(local_30 + 0x88) + 4)) {
    return 0;
  }
  p_Var5 = _malloc_base(0x228);
  if (p_Var5 != (__crt_multibyte_data *)0x0) {
    lVar10 = 4;
    puVar3 = *(undefined8 **)(local_30 + 0x88);
    p_Var11 = p_Var5;
    do {
      p_Var9 = p_Var11;
      puVar6 = puVar3;
      uVar7 = puVar6[1];
      *(undefined8 *)p_Var9 = *puVar6;
      *(undefined8 *)(p_Var9 + 8) = uVar7;
      uVar7 = puVar6[3];
      *(undefined8 *)(p_Var9 + 0x10) = puVar6[2];
      *(undefined8 *)(p_Var9 + 0x18) = uVar7;
      uVar7 = puVar6[5];
      *(undefined8 *)(p_Var9 + 0x20) = puVar6[4];
      *(undefined8 *)(p_Var9 + 0x28) = uVar7;
      uVar7 = puVar6[7];
      *(undefined8 *)(p_Var9 + 0x30) = puVar6[6];
      *(undefined8 *)(p_Var9 + 0x38) = uVar7;
      uVar7 = puVar6[9];
      *(undefined8 *)(p_Var9 + 0x40) = puVar6[8];
      *(undefined8 *)(p_Var9 + 0x48) = uVar7;
      uVar7 = puVar6[0xb];
      *(undefined8 *)(p_Var9 + 0x50) = puVar6[10];
      *(undefined8 *)(p_Var9 + 0x58) = uVar7;
      uVar7 = puVar6[0xd];
      *(undefined8 *)(p_Var9 + 0x60) = puVar6[0xc];
      *(undefined8 *)(p_Var9 + 0x68) = uVar7;
      uVar7 = puVar6[0xf];
      *(undefined8 *)(p_Var9 + 0x70) = puVar6[0xe];
      *(undefined8 *)(p_Var9 + 0x78) = uVar7;
      lVar10 = lVar10 + -1;
      puVar3 = puVar6 + 0x10;
      p_Var11 = p_Var9 + 0x80;
    } while (lVar10 != 0);
    uVar7 = puVar6[0x11];
    *(undefined8 *)(p_Var9 + 0x80) = puVar6[0x10];
    *(undefined8 *)(p_Var9 + 0x88) = uVar7;
    uVar7 = puVar6[0x13];
    *(undefined8 *)(p_Var9 + 0x90) = puVar6[0x12];
    *(undefined8 *)(p_Var9 + 0x98) = uVar7;
    *(undefined8 *)(p_Var9 + 0xa0) = puVar6[0x14];
    *(undefined4 *)p_Var5 = 0;
    uVar7 = _setmbcp_nolock(iVar4,p_Var5);
    iVar4 = (int)uVar7;
    if (iVar4 != -1) {
      if (param_2 == '\0') {
        FUN_18000b82c();
      }
      piVar2 = *(int **)(local_30 + 0x88);
      LOCK();
      iVar1 = *piVar2;
      *piVar2 = *piVar2 + -1;
      UNLOCK();
      if ((iVar1 == 1) && (*(undefined4 **)(local_30 + 0x88) != &DAT_18001c2d0)) {
        _free_base(*(undefined4 **)(local_30 + 0x88));
      }
      *(undefined4 *)p_Var5 = 1;
      p_Var11 = (__crt_multibyte_data *)0x0;
      *(__crt_multibyte_data **)(local_30 + 0x88) = p_Var5;
      if ((((byte)local_30[0x3a8] & 2) == 0) && (((byte)DAT_18001c810 & 1) == 0)) {
        local_28[0] = &local_30;
        local_res20[0] = 5;
        local_38[0] = 5;
        operator()<>(local_res18,local_38,local_28,local_res20);
        if (param_2 != '\0') {
          PTR_DAT_18001c1b0 = PTR_DAT_18001c4f8;
        }
      }
      goto LAB_18000d139;
    }
    puVar8 = __doserrno();
    *puVar8 = 0x16;
  }
  iVar4 = -1;
  p_Var11 = p_Var5;
LAB_18000d139:
  _free_base(p_Var11);
  return iVar4;
}



/* ---- __acrt_initialize_multibyte @ 18000d200 ---- */

/* Library Function - Single Match
    __acrt_initialize_multibyte
   
   Library: Visual Studio 2015 Release */

undefined4 __acrt_initialize_multibyte(void)

{
  int in_EAX;
  
  if (DAT_18001d9f8 == '\0') {
    in_EAX = FUN_18000d048(-3,'\x01');
    DAT_18001d9f8 = '\x01';
  }
  return CONCAT31((int3)((uint)in_EAX >> 8),1);
}



/* ---- FUN_18000d228 @ 18000d228 ---- */

int * FUN_18000d228(void)

{
  int iVar1;
  __acrt_ptd *p_Var2;
  int *piVar3;
  
  p_Var2 = FUN_18000b630();
  if (((*(uint *)(p_Var2 + 0x3a8) & DAT_18001c810) == 0) || (*(longlong *)(p_Var2 + 0x90) == 0)) {
    __acrt_lock(5);
    piVar3 = *(int **)(p_Var2 + 0x88);
    if (piVar3 != (int *)PTR_DAT_18001c4f8) {
      if (piVar3 != (int *)0x0) {
        LOCK();
        iVar1 = *piVar3;
        *piVar3 = *piVar3 + -1;
        UNLOCK();
        if ((iVar1 == 1) && (piVar3 != &DAT_18001c2d0)) {
          _free_base(piVar3);
        }
      }
      *(undefined **)(p_Var2 + 0x88) = PTR_DAT_18001c4f8;
      piVar3 = (int *)PTR_DAT_18001c4f8;
      LOCK();
      *(int *)PTR_DAT_18001c4f8 = *(int *)PTR_DAT_18001c4f8 + 1;
      UNLOCK();
    }
    __acrt_unlock(5);
  }
  else {
    piVar3 = *(int **)(p_Var2 + 0x88);
  }
  if (piVar3 == (int *)0x0) {
                    /* WARNING: Subroutine does not return */
    abort();
  }
  return piVar3;
}



/* ---- _setmbcp_nolock @ 18000d2e8 ---- */

/* WARNING: Function: __security_check_cookie replaced with injection: security_check_cookie */
/* Library Function - Single Match
    _setmbcp_nolock
   
   Library: Visual Studio 2015 Release */

undefined8 _setmbcp_nolock(int param_1,__crt_multibyte_data *param_2)

{
  byte bVar1;
  int iVar2;
  uint uVar3;
  BOOL BVar4;
  uint *puVar5;
  __crt_multibyte_data *p_Var6;
  undefined *puVar7;
  BYTE *pBVar8;
  longlong lVar9;
  ulonglong uVar10;
  byte *pbVar11;
  uint uVar12;
  undefined *puVar13;
  undefined *puVar14;
  byte *pbVar15;
  uint uVar16;
  byte *pbVar17;
  undefined1 auStack_68 [32];
  _cpinfo local_48;
  ulonglong local_30;
  
  local_30 = DAT_18001c000 ^ (ulonglong)auStack_68;
  uVar3 = getSystemCP(param_1);
  puVar13 = (undefined *)0x0;
  if (uVar3 != 0) {
    puVar5 = &DAT_18001c510;
    puVar7 = puVar13;
    do {
      if (*puVar5 == uVar3) {
        FUN_180003320((undefined1 (*) [16])(param_2 + 0x18),0,0x101);
        pbVar17 = &DAT_18001c500;
        lVar9 = 4;
        pbVar15 = &DAT_18001c520 + (longlong)puVar7 * 0x30;
        do {
          bVar1 = *pbVar15;
          pbVar11 = pbVar15;
          while ((bVar1 != 0 && (pbVar11[1] != 0))) {
            bVar1 = *pbVar11;
            uVar12 = (uint)bVar1;
            if (bVar1 <= pbVar11[1]) {
              uVar16 = (uint)bVar1;
              do {
                uVar16 = uVar16 + 1;
                if (0x100 < uVar16) break;
                uVar12 = uVar12 + 1;
                param_2[(ulonglong)uVar16 + 0x18] =
                     (__crt_multibyte_data)((byte)param_2[(ulonglong)uVar16 + 0x18] | *pbVar17);
              } while (uVar12 <= pbVar11[1]);
            }
            pbVar11 = pbVar11 + 2;
            bVar1 = *pbVar11;
          }
          pbVar15 = pbVar15 + 8;
          pbVar17 = pbVar17 + 1;
          lVar9 = lVar9 + -1;
        } while (lVar9 != 0);
        *(uint *)(param_2 + 4) = uVar3;
        *(undefined4 *)(param_2 + 8) = 1;
        puVar14 = PTR_u_ja_JP_180015050;
        if (((uVar3 != 0x3a4) && (puVar14 = PTR_u_zh_CN_180015058, uVar3 != 0x3a8)) &&
           ((puVar14 = PTR_u_ko_KR_180015060, uVar3 != 0x3b5 && (puVar14 = puVar13, uVar3 == 0x3b6))
           )) {
          puVar14 = PTR_u_zh_TW_180015068;
        }
        *(undefined **)(param_2 + 0x220) = puVar14;
        p_Var6 = param_2 + 0xc;
        lVar9 = 6;
        do {
          *(undefined2 *)p_Var6 =
               *(undefined2 *)(p_Var6 + ((longlong)puVar7 * 0x30 - (longlong)param_2) + 0x18001c508)
          ;
          p_Var6 = p_Var6 + 2;
          lVar9 = lVar9 + -1;
        } while (lVar9 != 0);
        goto LAB_18000d55f;
      }
      uVar12 = (int)puVar7 + 1;
      puVar7 = (undefined *)(ulonglong)uVar12;
      puVar5 = puVar5 + 0xc;
    } while (uVar12 < 5);
    if ((uVar3 - 65000 < 2) || (BVar4 = IsValidCodePage(uVar3 & 0xffff), BVar4 == 0)) {
      return 0xffffffff;
    }
    BVar4 = GetCPInfo(uVar3,&local_48);
    if (BVar4 != 0) {
      FUN_180003320((undefined1 (*) [16])(param_2 + 0x18),0,0x101);
      *(uint *)(param_2 + 4) = uVar3;
      *(undefined8 *)(param_2 + 0x220) = 0;
      if (local_48.MaxCharSize < 2) {
        *(undefined4 *)(param_2 + 8) = 0;
      }
      else {
        pBVar8 = local_48.LeadByte;
        while ((local_48.LeadByte[0] != 0 && (pBVar8[1] != 0))) {
          bVar1 = *pBVar8;
          if ((uint)bVar1 <= (uint)pBVar8[1]) {
            uVar3 = (uint)bVar1;
            uVar10 = (ulonglong)(((uint)pBVar8[1] - (uint)bVar1) + 1);
            do {
              uVar3 = uVar3 + 1;
              param_2[(ulonglong)uVar3 + 0x18] =
                   (__crt_multibyte_data)((byte)param_2[(ulonglong)uVar3 + 0x18] | 4);
              uVar10 = uVar10 - 1;
            } while (uVar10 != 0);
          }
          pBVar8 = pBVar8 + 2;
          local_48.LeadByte[0] = *pBVar8;
        }
        p_Var6 = param_2 + 0x1a;
        lVar9 = 0xfe;
        do {
          *p_Var6 = (__crt_multibyte_data)((byte)*p_Var6 | 8);
          p_Var6 = p_Var6 + 1;
          lVar9 = lVar9 + -1;
        } while (lVar9 != 0);
        iVar2 = *(int *)(param_2 + 4);
        puVar7 = PTR_u_ja_JP_180015050;
        if ((((iVar2 != 0x3a4) && (puVar7 = PTR_u_zh_CN_180015058, iVar2 != 0x3a8)) &&
            (puVar7 = PTR_u_ko_KR_180015060, iVar2 != 0x3b5)) &&
           (puVar7 = PTR_u_zh_TW_180015068, iVar2 != 0x3b6)) {
          puVar7 = puVar13;
        }
        *(undefined **)(param_2 + 0x220) = puVar7;
        *(undefined4 *)(param_2 + 8) = 1;
      }
      p_Var6 = param_2 + 0xc;
      for (lVar9 = 6; lVar9 != 0; lVar9 = lVar9 + -1) {
        *(undefined2 *)p_Var6 = 0;
        p_Var6 = p_Var6 + 2;
      }
LAB_18000d55f:
      setSBUpLow(param_2);
      return 0;
    }
    if (DAT_18001d9ec == 0) {
      return 0xffffffff;
    }
  }
  setSBCS(param_2);
  return 0;
}



/* ---- x_ismbbtype_l @ 18000d590 ---- */

/* Library Function - Single Match
    int __cdecl x_ismbbtype_l(struct __crt_locale_pointers * __ptr64,unsigned int,int,int)
   
   Libraries: Visual Studio 2015, Visual Studio 2017, Visual Studio 2019 */

int __cdecl x_ismbbtype_l(__crt_locale_pointers *param_1,uint param_2,int param_3,int param_4)

{
  uint uVar1;
  int iVar2;
  longlong local_28;
  longlong *local_20;
  longlong local_18;
  char local_10;
  
  _LocaleUpdate::_LocaleUpdate((_LocaleUpdate *)&local_28,param_1);
  if ((*(byte *)((ulonglong)(param_2 & 0xff) + 0x19 + local_18) & (byte)param_4) == 0) {
    if (param_3 == 0) {
      uVar1 = 0;
    }
    else {
      uVar1 = (uint)*(ushort *)(*local_20 + (ulonglong)(param_2 & 0xff) * 2) & param_3;
    }
    iVar2 = 0;
    if (uVar1 == 0) goto LAB_18000d5e2;
  }
  iVar2 = 1;
LAB_18000d5e2:
  if (local_10 != '\0') {
    *(uint *)(local_28 + 0x3a8) = *(uint *)(local_28 + 0x3a8) & 0xfffffffd;
  }
  return iVar2;
}



/* ---- _ismbblead @ 18000d608 ---- */

/* Library Function - Single Match
    _ismbblead
   
   Library: Visual Studio 2015 Release */

int __cdecl _ismbblead(uint _C)

{
  int iVar1;
  
  iVar1 = x_ismbbtype_l((__crt_locale_pointers *)0x0,_C,0,4);
  return iVar1;
}



/* ---- FUN_18000d61c @ 18000d61c ---- */

/* WARNING: Globals starting with '_' overlap smaller symbols at the same address */

undefined1 FUN_18000d61c(void)

{
  DAT_18001da10 = GetCommandLineA();
  _DAT_18001da18 = GetCommandLineW();
  return 1;
}



/* ---- __dcrt_get_narrow_environment_from_os @ 18000d644 ---- */

/* Library Function - Single Match
    __dcrt_get_narrow_environment_from_os
   
   Library: Visual Studio 2015 Release */

LPSTR __dcrt_get_narrow_environment_from_os(void)

{
  WCHAR WVar1;
  int cbMultiByte;
  int iVar2;
  LPWCH lpWideCharStr;
  longlong lVar3;
  LPSTR lpMultiByteStr;
  WCHAR *pWVar5;
  LPSTR pCVar6;
  LPSTR pCVar7;
  longlong lVar4;
  
  lpWideCharStr = GetEnvironmentStringsW();
  pCVar7 = (LPSTR)0x0;
  if (lpWideCharStr != (LPWCH)0x0) {
    WVar1 = *lpWideCharStr;
    pWVar5 = lpWideCharStr;
    while (WVar1 != L'\0') {
      lVar3 = -1;
      do {
        lVar4 = lVar3;
        lVar3 = lVar4 + 1;
      } while (pWVar5[lVar3] != L'\0');
      pWVar5 = pWVar5 + lVar4 + 2;
      WVar1 = *pWVar5;
    }
    iVar2 = (int)((longlong)pWVar5 + (2 - (longlong)lpWideCharStr) >> 1);
    cbMultiByte = WideCharToMultiByte(0,0,lpWideCharStr,iVar2,(LPSTR)0x0,0,(LPCSTR)0x0,(LPBOOL)0x0);
    if (cbMultiByte != 0) {
      lpMultiByteStr = _malloc_base((longlong)cbMultiByte);
      pCVar6 = pCVar7;
      if ((lpMultiByteStr != (LPSTR)0x0) &&
         (iVar2 = WideCharToMultiByte(0,0,lpWideCharStr,iVar2,lpMultiByteStr,cbMultiByte,(LPCSTR)0x0
                                      ,(LPBOOL)0x0), iVar2 != 0)) {
        pCVar6 = lpMultiByteStr;
        lpMultiByteStr = pCVar7;
      }
      _free_base(lpMultiByteStr);
      pCVar7 = pCVar6;
    }
  }
  if (lpWideCharStr != (LPWCH)0x0) {
    FreeEnvironmentStringsW(lpWideCharStr);
  }
  return pCVar7;
}



/* ---- _recalloc_base @ 18000d748 ---- */

LPVOID _recalloc_base(void *param_1,ulonglong param_2,ulonglong param_3)

{
  ulong *puVar1;
  size_t sVar2;
  LPVOID pvVar3;
  ulonglong uVar4;
  
  if ((param_2 == 0) || (param_3 <= 0xffffffffffffffe0 / param_2)) {
    if (param_1 == (void *)0x0) {
      sVar2 = 0;
    }
    else {
      sVar2 = _msize(param_1);
    }
    uVar4 = param_2 * param_3;
    pvVar3 = _realloc_base(param_1,uVar4);
    if ((pvVar3 != (LPVOID)0x0) && (sVar2 < uVar4)) {
      FUN_180003320((undefined1 (*) [16])((longlong)pvVar3 + sVar2),0,uVar4 - sVar2);
    }
  }
  else {
    puVar1 = __doserrno();
    *puVar1 = 0xc;
    pvVar3 = (LPVOID)0x0;
  }
  return pvVar3;
}



/* ---- _recalloc_base @ 18000d750 ---- */

/* Library Function - Single Match
    _recalloc_base
   
   Library: Visual Studio 2015 Release */

LPVOID _recalloc_base(void *param_1,ulonglong param_2,ulonglong param_3)

{
  ulong *puVar1;
  size_t sVar2;
  LPVOID pvVar3;
  ulonglong uVar4;
  
  if ((param_2 == 0) || (param_3 <= 0xffffffffffffffe0 / param_2)) {
    if (param_1 == (void *)0x0) {
      sVar2 = 0;
    }
    else {
      sVar2 = _msize(param_1);
    }
    uVar4 = param_2 * param_3;
    pvVar3 = _realloc_base(param_1,uVar4);
    if ((pvVar3 != (LPVOID)0x0) && (sVar2 < uVar4)) {
      FUN_180003320((undefined1 (*) [16])((longlong)pvVar3 + sVar2),0,uVar4 - sVar2);
    }
  }
  else {
    puVar1 = __doserrno();
    *puVar1 = 0xc;
    pvVar3 = (LPVOID)0x0;
  }
  return pvVar3;
}



/* ---- FUN_18000d7e8 @ 18000d7e8 ---- */

bool FUN_18000d7e8(void)

{
  DAT_18001da28 = GetProcessHeap();
  return DAT_18001da28 != (HANDLE)0x0;
}



/* ---- __acrt_execute_initializers @ 18000d810 ---- */

/* Library Function - Single Match
    __acrt_execute_initializers
   
   Library: Visual Studio 2015 Release */

undefined8 __acrt_execute_initializers(undefined8 *param_1,undefined8 *param_2)

{
  code *pcVar1;
  undefined8 *in_RAX;
  undefined8 *puVar2;
  
  puVar2 = param_1;
  if (param_1 != param_2) {
    do {
      pcVar1 = (code *)*puVar2;
      if (pcVar1 != (code *)0x0) {
        (*(code *)PTR__guard_check_icall_180012238)(pcVar1);
        in_RAX = (undefined8 *)(*pcVar1)();
        if ((char)in_RAX == '\0') break;
      }
      puVar2 = puVar2 + 2;
    } while (puVar2 != param_2);
    if (puVar2 != param_2) {
      if (puVar2 != param_1) {
        puVar2 = puVar2 + -1;
        do {
          if ((puVar2[-1] != 0) && (pcVar1 = (code *)*puVar2, pcVar1 != (code *)0x0)) {
            (*(code *)PTR__guard_check_icall_180012238)(pcVar1);
            (*pcVar1)(0);
          }
          in_RAX = puVar2 + -1;
          puVar2 = puVar2 + -2;
        } while (in_RAX != param_1);
      }
      return (ulonglong)in_RAX & 0xffffffffffffff00;
    }
  }
  return CONCAT71((int7)((ulonglong)in_RAX >> 8),1);
}



/* ---- __acrt_execute_uninitializers @ 18000d8a4 ---- */

/* Library Function - Single Match
    __acrt_execute_uninitializers
   
   Library: Visual Studio 2015 Release */

undefined8 __acrt_execute_uninitializers(undefined8 *param_1,undefined8 *param_2)

{
  code *pcVar1;
  undefined8 *in_RAX;
  undefined8 *puVar2;
  
  if (param_1 != param_2) {
    puVar2 = param_2 + -1;
    do {
      pcVar1 = (code *)*puVar2;
      if (pcVar1 != (code *)0x0) {
        (*(code *)PTR__guard_check_icall_180012238)(pcVar1);
        (*pcVar1)(0);
      }
      in_RAX = puVar2 + -1;
      puVar2 = puVar2 + -2;
    } while (in_RAX != param_1);
  }
  return CONCAT71((int7)((ulonglong)in_RAX >> 8),1);
}



/* ---- FUN_18000d8f4 @ 18000d8f4 ---- */

/* WARNING: Globals starting with '_' overlap smaller symbols at the same address */

void FUN_18000d8f4(undefined8 param_1)

{
  _DAT_18001da30 = param_1;
  return;
}



/* ---- _callnewh @ 18000d8fc ---- */

/* Library Function - Single Match
    _callnewh
   
   Library: Visual Studio 2015 Release */

int __cdecl _callnewh(size_t _Size)

{
  int iVar1;
  code *pcVar2;
  
  pcVar2 = (code *)_query_new_handler();
  if (pcVar2 != (code *)0x0) {
    (*(code *)PTR__guard_check_icall_180012238)(pcVar2);
    iVar1 = (*pcVar2)(_Size);
    if (iVar1 != 0) {
      return 1;
    }
  }
  return 0;
}



/* ---- _query_new_handler @ 18000d93c ---- */

/* WARNING: Globals starting with '_' overlap smaller symbols at the same address */
/* Library Function - Single Match
    _query_new_handler
   
   Library: Visual Studio 2015 Release */

ulonglong _query_new_handler(void)

{
  byte bVar1;
  ulonglong uVar2;
  
  __acrt_lock(0);
  bVar1 = (byte)DAT_18001c000 & 0x3f;
  uVar2 = DAT_18001c000 ^ _DAT_18001da30;
  __acrt_unlock(0);
  return uVar2 >> bVar1 | uVar2 << 0x40 - bVar1;
}



/* ---- operator()<> @ 18000d970 ---- */

/* WARNING: Globals starting with '_' overlap smaller symbols at the same address */
/* Library Function - Multiple Matches With Same Base Name
    public: void (__cdecl*__cdecl __crt_seh_guarded_call<void (__cdecl*)(int)>::operator()<class
   <lambda_450d765d439847d4c735a33c368b5fc0>,class <lambda_44731a7d0e6d81c3e6aa82d741081786> &
   __ptr64,class <lambda_601a2a7da3b7a96e9554ac7215c4b07c> >(class
   <lambda_450d765d439847d4c735a33c368b5fc0> && __ptr64,class
   <lambda_44731a7d0e6d81c3e6aa82d741081786> & __ptr64,class
   <lambda_601a2a7da3b7a96e9554ac7215c4b07c> && __ptr64) __ptr64)(int)
    public: void (__cdecl*__cdecl __crt_seh_guarded_call<void (__cdecl*)(int)>::operator()<class
   <lambda_c36588078e9f5dfd39652860aa6b3aaf>,class <lambda_ec61778202f4f5fc7e7711acc23c3bca> &
   __ptr64,class <lambda_dc9d2797ccde5d239b4a0efae8ebd7db> >(class
   <lambda_c36588078e9f5dfd39652860aa6b3aaf> && __ptr64,class
   <lambda_ec61778202f4f5fc7e7711acc23c3bca> & __ptr64,class
   <lambda_dc9d2797ccde5d239b4a0efae8ebd7db> && __ptr64) __ptr64)(int)
   
   Libraries: Visual Studio 2015 Release, Visual Studio 2017 Release, Visual Studio 2019 Release */

ulonglong operator()<>(undefined8 param_1,int *param_2,undefined8 param_3,int *param_4)

{
  byte bVar1;
  ulonglong uVar2;
  
  __acrt_lock(*param_2);
  bVar1 = (byte)DAT_18001c000 & 0x3f;
  uVar2 = DAT_18001c000 ^ _DAT_18001da48;
  __acrt_unlock(*param_4);
  return uVar2 >> bVar1 | uVar2 << 0x40 - bVar1;
}



/* ---- __acrt_get_sigabrt_handler @ 18000d9b8 ---- */

/* Library Function - Single Match
    __acrt_get_sigabrt_handler
   
   Library: Visual Studio 2015 Release */

void __acrt_get_sigabrt_handler(void)

{
  undefined1 local_res8 [8];
  int local_res10 [2];
  int local_res18 [4];
  
  local_res10[0] = 3;
  local_res18[0] = 3;
  operator()<>(local_res8,local_res18,local_res8,local_res10);
  return;
}



/* ---- FUN_18000d9e8 @ 18000d9e8 ---- */

/* WARNING: Globals starting with '_' overlap smaller symbols at the same address */

void FUN_18000d9e8(undefined8 param_1)

{
  _DAT_18001da38 = param_1;
  _DAT_18001da40 = param_1;
  _DAT_18001da48 = param_1;
  _DAT_18001da50 = param_1;
  return;
}



/* ---- raise @ 18000da08 ---- */

/* Library Function - Single Match
    raise
   
   Library: Visual Studio 2015 Release */

int __cdecl raise(int _SigNum)

{
  bool bVar1;
  ulong *puVar2;
  __acrt_ptd *p_Var3;
  longlong lVar4;
  byte bVar5;
  longlong lVar6;
  code *pcVar7;
  ulonglong *puVar8;
  __acrt_ptd *p_Var9;
  undefined4 local_res18;
  longlong local_res20;
  
  p_Var3 = (__acrt_ptd *)0x0;
  p_Var9 = (__acrt_ptd *)0x0;
  local_res18 = 0;
  bVar1 = true;
  if (_SigNum == 2) {
LAB_18000dac3:
    if (_SigNum == 2) {
      puVar8 = (ulonglong *)&DAT_18001da38;
    }
    else if (_SigNum == 6) {
LAB_18000dae0:
      puVar8 = (ulonglong *)&DAT_18001da48;
      p_Var9 = p_Var3;
    }
    else if (_SigNum == 0xf) {
      puVar8 = (ulonglong *)&DAT_18001da50;
    }
    else if (_SigNum == 0x15) {
      puVar8 = (ulonglong *)&DAT_18001da40;
      p_Var9 = p_Var3;
    }
    else {
      if (_SigNum == 0x16) goto LAB_18000dae0;
      puVar8 = (ulonglong *)0x0;
      p_Var9 = p_Var3;
    }
  }
  else {
    if (_SigNum != 4) {
      if (_SigNum != 6) {
        if ((_SigNum == 8) || (_SigNum == 0xb)) goto LAB_18000da5c;
        if ((_SigNum != 0xf) && (1 < _SigNum - 0x15U)) goto LAB_18000daa0;
      }
      goto LAB_18000dac3;
    }
LAB_18000da5c:
    p_Var9 = __acrt_getptd_noexit();
    if (p_Var9 == (__acrt_ptd *)0x0) {
      return -1;
    }
    lVar4 = *(longlong *)p_Var9;
    lVar6 = DAT_180013b80 * 0x10 + lVar4;
    for (; lVar4 != lVar6; lVar4 = lVar4 + 0x10) {
      if (*(int *)(lVar4 + 4) == _SigNum) goto LAB_18000da94;
    }
    lVar4 = 0;
LAB_18000da94:
    if (lVar4 == 0) {
LAB_18000daa0:
      puVar2 = __doserrno();
      *puVar2 = 0x16;
      FUN_18000aff4();
      return -1;
    }
    puVar8 = (ulonglong *)(lVar4 + 8);
    bVar1 = false;
  }
  local_res20 = 0;
  if (bVar1) {
    __acrt_lock(3);
    bVar5 = (byte)DAT_18001c000 & 0x3f;
    pcVar7 = (code *)((DAT_18001c000 ^ *puVar8) >> bVar5 | (DAT_18001c000 ^ *puVar8) << 0x40 - bVar5
                     );
  }
  else {
    pcVar7 = (code *)*puVar8;
  }
  if (pcVar7 == (code *)0x1) goto LAB_18000dc15;
  if (pcVar7 == (code *)0x0) {
    if (bVar1) {
      __acrt_unlock(3);
    }
    FUN_18000a064(3);
  }
  if (((uint)_SigNum < 0xc) && ((0x910U >> (_SigNum & 0x1fU) & 1) != 0)) {
    local_res20 = *(longlong *)(p_Var9 + 8);
    *(longlong *)(p_Var9 + 8) = 0;
    if (_SigNum == 8) {
      p_Var3 = FUN_18000b630();
      local_res18 = *(undefined4 *)(p_Var3 + 0x10);
      p_Var3 = FUN_18000b630();
      *(undefined4 *)(p_Var3 + 0x10) = 0x8c;
      goto LAB_18000dbb8;
    }
  }
  else {
LAB_18000dbb8:
    if (_SigNum == 8) {
      lVar4 = DAT_180013b88 * 0x10 + *(longlong *)p_Var9;
      lVar6 = DAT_180013b90 * 0x10 + lVar4;
      for (; lVar4 != lVar6; lVar4 = lVar4 + 0x10) {
        *(undefined8 *)(lVar4 + 8) = 0;
      }
      goto LAB_18000dc15;
    }
  }
  bVar5 = 0x40 - ((byte)DAT_18001c000 & 0x3f) & 0x3f;
  *puVar8 = ((ulonglong)(0 >> bVar5) | 0L << 0x40 - bVar5) ^ DAT_18001c000;
LAB_18000dc15:
  if (bVar1) {
    __acrt_unlock(3);
  }
  if (pcVar7 != (code *)0x1) {
    if (_SigNum == 8) {
      p_Var3 = FUN_18000b630();
      (*(code *)PTR__guard_check_icall_180012238)(pcVar7);
      (*pcVar7)(8,*(undefined4 *)(p_Var3 + 0x10));
    }
    else {
      (*(code *)PTR__guard_check_icall_180012238)(pcVar7);
      (*pcVar7)(_SigNum);
    }
    if ((((uint)_SigNum < 0xc) && ((0x910U >> (_SigNum & 0x1fU) & 1) != 0)) &&
       (*(longlong *)(p_Var9 + 8) = local_res20, _SigNum == 8)) {
      p_Var9 = FUN_18000b630();
      *(undefined4 *)(p_Var9 + 0x10) = local_res18;
    }
  }
  return 0;
}



/* ---- FUN_18000dca4 @ 18000dca4 ---- */

/* WARNING: Globals starting with '_' overlap smaller symbols at the same address */

bool FUN_18000dca4(void)

{
  byte bVar1;
  
  bVar1 = (byte)DAT_18001c000 & 0x3f;
  return (DAT_18001c000 ^ _DAT_18001da58) >> bVar1 != 0 ||
         (DAT_18001c000 ^ _DAT_18001da58) << 0x40 - bVar1 != 0;
}



/* ---- FUN_18000dcc4 @ 18000dcc4 ---- */

/* WARNING: Globals starting with '_' overlap smaller symbols at the same address */

void FUN_18000dcc4(undefined8 param_1)

{
  _DAT_18001da58 = param_1;
  return;
}



/* ---- __acrt_invoke_user_matherr @ 18000dccc ---- */

/* WARNING: Globals starting with '_' overlap smaller symbols at the same address */
/* Library Function - Single Match
    __acrt_invoke_user_matherr
   
   Library: Visual Studio 2015 Release */

undefined8 __acrt_invoke_user_matherr(undefined8 param_1)

{
  undefined8 uVar1;
  byte bVar2;
  code *pcVar3;
  
  bVar2 = (byte)DAT_18001c000 & 0x3f;
  pcVar3 = (code *)((DAT_18001c000 ^ _DAT_18001da58) >> bVar2 |
                   (DAT_18001c000 ^ _DAT_18001da58) << 0x40 - bVar2);
  if (pcVar3 == (code *)0x0) {
    uVar1 = 0;
  }
  else {
    (*(code *)PTR__guard_check_icall_180012238)(pcVar3);
    uVar1 = (*pcVar3)(param_1);
  }
  return uVar1;
}



/* ---- FUN_18000dd14 @ 18000dd14 ---- */

undefined4 FUN_18000dd14(void)

{
  return DAT_18001da70;
}



/* ---- _isleadbyte_l @ 18000dd1c ---- */

/* Library Function - Single Match
    _isleadbyte_l
   
   Library: Visual Studio 2015 Release */

int __cdecl _isleadbyte_l(int _C,_locale_t _Locale)

{
  ushort uVar1;
  longlong local_28;
  longlong *local_20;
  char local_10;
  
  _LocaleUpdate::_LocaleUpdate((_LocaleUpdate *)&local_28,(__crt_locale_pointers *)_Locale);
  uVar1 = *(ushort *)(*local_20 + (ulonglong)(_C & 0xff) * 2);
  if (local_10 != '\0') {
    *(uint *)(local_28 + 0x3a8) = *(uint *)(local_28 + 0x3a8) & 0xfffffffd;
  }
  return uVar1 & 0x8000;
}



/* ---- __acrt_GetStringTypeA @ 18000dd5c ---- */

/* WARNING: Function: __security_check_cookie replaced with injection: security_check_cookie */
/* WARNING: Function: _alloca_probe replaced with injection: alloca_probe */
/* Library Function - Single Match
    __acrt_GetStringTypeA
   
   Library: Visual Studio 2015 Release */

BOOL __acrt_GetStringTypeA
               (__crt_locale_pointers *param_1,DWORD param_2,LPCSTR param_3,int param_4,
               LPWORD param_5,UINT param_6,int param_7)

{
  ulonglong uVar1;
  longlong lVar2;
  int iVar3;
  BOOL BVar4;
  ulonglong uVar5;
  undefined4 *puVar6;
  ulonglong uVar7;
  undefined1 (*lpSrcStr) [16];
  undefined1 *puVar8;
  undefined1 *puVar9;
  undefined1 auStackY_88 [32];
  longlong local_58;
  longlong local_50;
  char local_40;
  ulonglong local_38;
  
  puVar8 = auStackY_88;
  puVar9 = auStackY_88;
  local_38 = DAT_18001c000 ^ (ulonglong)&local_58;
  _LocaleUpdate::_LocaleUpdate((_LocaleUpdate *)&local_58,param_1);
  if (param_6 == 0) {
    param_6 = *(UINT *)(local_50 + 0xc);
  }
  iVar3 = MultiByteToWideChar(param_6,(-(uint)(param_7 != 0) & 8) + 1,param_3,param_4,(LPWSTR)0x0,0)
  ;
  if (iVar3 == 0) {
    BVar4 = 0;
    goto LAB_18000ded4;
  }
  uVar1 = (longlong)iVar3 * 2;
  if ((uVar1 + 0x10 & -(ulonglong)(uVar1 < uVar1 + 0x10)) == 0) {
    lpSrcStr = (undefined1 (*) [16])0x0;
    puVar9 = auStackY_88;
LAB_18000de6f:
    if (lpSrcStr == (undefined1 (*) [16])0x0) goto LAB_18000debc;
    *(undefined8 *)(puVar9 + -8) = 0x18000de81;
    FUN_180003320(lpSrcStr,0,uVar1);
    *(int *)(puVar9 + 0x28) = iVar3;
    *(undefined1 (**) [16])(puVar9 + 0x20) = lpSrcStr;
    *(undefined8 *)(puVar9 + -8) = 0x18000de9e;
    iVar3 = MultiByteToWideChar(param_6,1,param_3,param_4,*(LPWSTR *)(puVar9 + 0x20),
                                *(int *)(puVar9 + 0x28));
    if (iVar3 == 0) goto LAB_18000debc;
    *(undefined8 *)(puVar9 + -8) = 0x18000deb8;
    BVar4 = GetStringTypeW(param_2,(LPCWSTR)lpSrcStr,iVar3,param_5);
  }
  else {
    uVar7 = uVar1 + 0x10;
    if (0x400 < (-(ulonglong)(uVar1 < uVar1 + 0x10) & uVar1 + 0x10)) {
      puVar6 = _malloc_base(-(ulonglong)(uVar1 < uVar7) & uVar7);
      lpSrcStr = (undefined1 (*) [16])0x0;
      puVar9 = auStackY_88;
      if (puVar6 != (undefined4 *)0x0) {
        *puVar6 = 0xdddd;
        goto LAB_18000de67;
      }
      goto LAB_18000de6f;
    }
    uVar7 = -(ulonglong)(uVar1 < uVar7) & uVar7;
    uVar5 = uVar7 + 0xf;
    if (uVar5 <= uVar7) {
      uVar5 = 0xffffffffffffff0;
    }
    lVar2 = -(uVar5 & 0xfffffffffffffff0);
    puVar9 = auStackY_88 + lVar2;
    puVar8 = auStackY_88 + lVar2;
    puVar6 = (undefined4 *)((longlong)&local_58 + lVar2);
    lpSrcStr = (undefined1 (*) [16])0x0;
    if (puVar6 != (undefined4 *)0x0) {
      *puVar6 = 0xcccc;
LAB_18000de67:
      lpSrcStr = (undefined1 (*) [16])(puVar6 + 4);
      puVar9 = puVar8;
      goto LAB_18000de6f;
    }
LAB_18000debc:
    BVar4 = 0;
  }
  if ((lpSrcStr != (undefined1 (*) [16])0x0) && (*(int *)lpSrcStr[-1] == 0xdddd)) {
    *(undefined8 *)(puVar9 + -8) = 0x18000ded4;
    _free_base(lpSrcStr + -1);
  }
LAB_18000ded4:
  if (local_40 != '\0') {
    *(uint *)(local_58 + 0x3a8) = *(uint *)(local_58 + 0x3a8) & 0xfffffffd;
  }
  *(undefined8 *)(puVar9 + -8) = 0x18000def3;
  return BVar4;
}



/* ---- __acrt_add_locale_ref @ 18000df10 ---- */

/* Library Function - Single Match
    __acrt_add_locale_ref
   
   Library: Visual Studio 2015 Release */

void __acrt_add_locale_ref(longlong param_1)

{
  int *piVar1;
  undefined8 *puVar2;
  longlong lVar3;
  
  LOCK();
  *(int *)(param_1 + 0x10) = *(int *)(param_1 + 0x10) + 1;
  UNLOCK();
  piVar1 = *(int **)(param_1 + 0xe0);
  if (piVar1 != (int *)0x0) {
    LOCK();
    *piVar1 = *piVar1 + 1;
    UNLOCK();
  }
  piVar1 = *(int **)(param_1 + 0xf0);
  if (piVar1 != (int *)0x0) {
    LOCK();
    *piVar1 = *piVar1 + 1;
    UNLOCK();
  }
  piVar1 = *(int **)(param_1 + 0xe8);
  if (piVar1 != (int *)0x0) {
    LOCK();
    *piVar1 = *piVar1 + 1;
    UNLOCK();
  }
  piVar1 = *(int **)(param_1 + 0x100);
  if (piVar1 != (int *)0x0) {
    LOCK();
    *piVar1 = *piVar1 + 1;
    UNLOCK();
  }
  puVar2 = (undefined8 *)(param_1 + 0x38);
  lVar3 = 6;
  do {
    if (((undefined *)puVar2[-2] != &DAT_18001c1b8) &&
       (piVar1 = (int *)*puVar2, piVar1 != (int *)0x0)) {
      LOCK();
      *piVar1 = *piVar1 + 1;
      UNLOCK();
    }
    if ((puVar2[-3] != 0) && (piVar1 = (int *)puVar2[-1], piVar1 != (int *)0x0)) {
      LOCK();
      *piVar1 = *piVar1 + 1;
      UNLOCK();
    }
    puVar2 = puVar2 + 4;
    lVar3 = lVar3 + -1;
  } while (lVar3 != 0);
  __acrt_locale_add_lc_time_reference(*(undefined ***)(param_1 + 0x120));
  return;
}



/* ---- __acrt_free_locale @ 18000df9c ---- */

/* Library Function - Single Match
    __acrt_free_locale
   
   Library: Visual Studio 2015 Release */

void __acrt_free_locale(LPVOID param_1)

{
  int *piVar1;
  longlong lVar2;
  undefined8 *puVar3;
  undefined8 *puVar4;
  
  if ((((*(undefined ***)((longlong)param_1 + 0xf8) != (undefined **)0x0) &&
       (*(undefined ***)((longlong)param_1 + 0xf8) != &PTR_DAT_18001c820)) &&
      (*(int **)((longlong)param_1 + 0xe0) != (int *)0x0)) &&
     (**(int **)((longlong)param_1 + 0xe0) == 0)) {
    piVar1 = *(int **)((longlong)param_1 + 0xf0);
    if ((piVar1 != (int *)0x0) && (*piVar1 == 0)) {
      _free_base(piVar1);
      __acrt_locale_free_monetary(*(longlong *)((longlong)param_1 + 0xf8));
    }
    piVar1 = *(int **)((longlong)param_1 + 0xe8);
    if ((piVar1 != (int *)0x0) && (*piVar1 == 0)) {
      _free_base(piVar1);
      __acrt_locale_free_numeric(*(undefined8 **)((longlong)param_1 + 0xf8));
    }
    _free_base(*(LPVOID *)((longlong)param_1 + 0xe0));
    _free_base(*(LPVOID *)((longlong)param_1 + 0xf8));
  }
  if ((*(int **)((longlong)param_1 + 0x100) != (int *)0x0) &&
     (**(int **)((longlong)param_1 + 0x100) == 0)) {
    _free_base((LPVOID)(*(longlong *)((longlong)param_1 + 0x108) + -0xfe));
    _free_base((LPVOID)(*(longlong *)((longlong)param_1 + 0x110) + -0x80));
    _free_base((LPVOID)(*(longlong *)((longlong)param_1 + 0x118) + -0x80));
    _free_base(*(LPVOID *)((longlong)param_1 + 0x100));
  }
  __acrt_locale_free_lc_time_if_unreferenced(*(undefined ***)((longlong)param_1 + 0x120));
  puVar3 = (undefined8 *)((longlong)param_1 + 0x128);
  lVar2 = 6;
  puVar4 = (undefined8 *)((longlong)param_1 + 0x38);
  do {
    if ((((undefined *)puVar4[-2] != &DAT_18001c1b8) &&
        (piVar1 = (int *)*puVar4, piVar1 != (int *)0x0)) && (*piVar1 == 0)) {
      _free_base(piVar1);
      _free_base((LPVOID)*puVar3);
    }
    if (((puVar4[-3] != 0) && (piVar1 = (int *)puVar4[-1], piVar1 != (int *)0x0)) && (*piVar1 == 0))
    {
      _free_base(piVar1);
    }
    puVar3 = puVar3 + 1;
    puVar4 = puVar4 + 4;
    lVar2 = lVar2 + -1;
  } while (lVar2 != 0);
  _free_base(param_1);
  return;
}



/* ---- __acrt_locale_add_lc_time_reference @ 18000e114 ---- */

/* Library Function - Single Match
    __acrt_locale_add_lc_time_reference
   
   Libraries: Visual Studio 2015 Release, Visual Studio 2017 Release, Visual Studio 2019 Release */

int __acrt_locale_add_lc_time_reference(undefined **param_1)

{
  int *piVar1;
  int iVar2;
  
  if ((param_1 != (undefined **)0x0) && (param_1 != &PTR_DAT_180014420)) {
    LOCK();
    piVar1 = (int *)((longlong)param_1 + 0x15c);
    iVar2 = *piVar1;
    *piVar1 = *piVar1 + 1;
    UNLOCK();
    return iVar2 + 1;
  }
  return 0x7fffffff;
}



/* ---- __acrt_locale_free_lc_time_if_unreferenced @ 18000e13c ---- */

/* Library Function - Single Match
    __acrt_locale_free_lc_time_if_unreferenced
   
   Libraries: Visual Studio 2015 Release, Visual Studio 2017 Release, Visual Studio 2019 Release */

void __acrt_locale_free_lc_time_if_unreferenced(undefined **param_1)

{
  if (((param_1 != (undefined **)0x0) && (param_1 != &PTR_DAT_180014420)) &&
     (*(int *)((longlong)param_1 + 0x15c) == 0)) {
    __acrt_locale_free_time(param_1);
    _free_base(param_1);
  }
  return;
}



/* ---- __acrt_locale_release_lc_time_reference @ 18000e174 ---- */

/* Library Function - Single Match
    __acrt_locale_release_lc_time_reference
   
   Libraries: Visual Studio 2015 Release, Visual Studio 2017 Release, Visual Studio 2019 Release */

int __acrt_locale_release_lc_time_reference(undefined **param_1)

{
  int *piVar1;
  int iVar2;
  
  if ((param_1 != (undefined **)0x0) && (param_1 != &PTR_DAT_180014420)) {
    LOCK();
    piVar1 = (int *)((longlong)param_1 + 0x15c);
    iVar2 = *piVar1;
    *piVar1 = *piVar1 + -1;
    UNLOCK();
    return iVar2 + -1;
  }
  return 0x7fffffff;
}



/* ---- __acrt_release_locale_ref @ 18000e19c ---- */

/* Library Function - Single Match
    __acrt_release_locale_ref
   
   Library: Visual Studio 2015 Release */

void __acrt_release_locale_ref(longlong param_1)

{
  int *piVar1;
  undefined8 *puVar2;
  longlong lVar3;
  
  if (param_1 != 0) {
    LOCK();
    *(int *)(param_1 + 0x10) = *(int *)(param_1 + 0x10) + -1;
    UNLOCK();
    piVar1 = *(int **)(param_1 + 0xe0);
    if (piVar1 != (int *)0x0) {
      LOCK();
      *piVar1 = *piVar1 + -1;
      UNLOCK();
    }
    piVar1 = *(int **)(param_1 + 0xf0);
    if (piVar1 != (int *)0x0) {
      LOCK();
      *piVar1 = *piVar1 + -1;
      UNLOCK();
    }
    piVar1 = *(int **)(param_1 + 0xe8);
    if (piVar1 != (int *)0x0) {
      LOCK();
      *piVar1 = *piVar1 + -1;
      UNLOCK();
    }
    piVar1 = *(int **)(param_1 + 0x100);
    if (piVar1 != (int *)0x0) {
      LOCK();
      *piVar1 = *piVar1 + -1;
      UNLOCK();
    }
    puVar2 = (undefined8 *)(param_1 + 0x38);
    lVar3 = 6;
    do {
      if (((undefined *)puVar2[-2] != &DAT_18001c1b8) &&
         (piVar1 = (int *)*puVar2, piVar1 != (int *)0x0)) {
        LOCK();
        *piVar1 = *piVar1 + -1;
        UNLOCK();
      }
      if ((puVar2[-3] != 0) && (piVar1 = (int *)puVar2[-1], piVar1 != (int *)0x0)) {
        LOCK();
        *piVar1 = *piVar1 + -1;
        UNLOCK();
      }
      puVar2 = puVar2 + 4;
      lVar3 = lVar3 + -1;
    } while (lVar3 != 0);
    __acrt_locale_release_lc_time_reference(*(undefined ***)(param_1 + 0x120));
  }
  return;
}



/* ---- FUN_18000e244 @ 18000e244 ---- */

undefined ** FUN_18000e244(void)

{
  __acrt_ptd *p_Var1;
  undefined **ppuVar2;
  
  p_Var1 = FUN_18000b630();
  if (((*(uint *)(p_Var1 + 0x3a8) & DAT_18001c810) == 0) ||
     (ppuVar2 = *(undefined ***)(p_Var1 + 0x90), ppuVar2 == (undefined **)0x0)) {
    __acrt_lock(4);
    ppuVar2 = _updatetlocinfoEx_nolock((undefined8 *)(p_Var1 + 0x90),DAT_18001d1f8);
    __acrt_unlock(4);
    if (ppuVar2 == (undefined **)0x0) {
                    /* WARNING: Subroutine does not return */
      abort();
    }
  }
  return ppuVar2;
}



/* ---- _updatetlocinfoEx_nolock @ 18000e2b4 ---- */

/* Library Function - Single Match
    _updatetlocinfoEx_nolock
   
   Library: Visual Studio 2015 Release */

undefined ** _updatetlocinfoEx_nolock(undefined8 *param_1,undefined **param_2)

{
  undefined **ppuVar1;
  
  if ((param_2 == (undefined **)0x0) || (param_1 == (undefined8 *)0x0)) {
    param_2 = (undefined **)0x0;
  }
  else {
    ppuVar1 = (undefined **)*param_1;
    if (ppuVar1 != param_2) {
      *param_1 = param_2;
      __acrt_add_locale_ref((longlong)param_2);
      if (((ppuVar1 != (undefined **)0x0) &&
          (__acrt_release_locale_ref((longlong)ppuVar1), *(int *)(ppuVar1 + 2) == 0)) &&
         (ppuVar1 != &PTR_DAT_18001c050)) {
        __acrt_free_locale(ppuVar1);
      }
    }
  }
  return param_2;
}



/* ---- __acrt_locale_free_monetary @ 18000e31c ---- */

/* Library Function - Single Match
    __acrt_locale_free_monetary
   
   Libraries: Visual Studio 2015 Release, Visual Studio 2017 Release, Visual Studio 2019 Release */

void __acrt_locale_free_monetary(longlong param_1)

{
  if (param_1 != 0) {
    if (*(undefined **)(param_1 + 0x18) != PTR_DAT_18001c838) {
      _free_base(*(undefined **)(param_1 + 0x18));
    }
    if (*(undefined **)(param_1 + 0x20) != PTR_DAT_18001c840) {
      _free_base(*(undefined **)(param_1 + 0x20));
    }
    if (*(undefined **)(param_1 + 0x28) != PTR_DAT_18001c848) {
      _free_base(*(undefined **)(param_1 + 0x28));
    }
    if (*(undefined **)(param_1 + 0x30) != PTR_DAT_18001c850) {
      _free_base(*(undefined **)(param_1 + 0x30));
    }
    if (*(undefined **)(param_1 + 0x38) != PTR_DAT_18001c858) {
      _free_base(*(undefined **)(param_1 + 0x38));
    }
    if (*(undefined **)(param_1 + 0x40) != PTR_DAT_18001c860) {
      _free_base(*(undefined **)(param_1 + 0x40));
    }
    if (*(undefined **)(param_1 + 0x48) != PTR_DAT_18001c868) {
      _free_base(*(undefined **)(param_1 + 0x48));
    }
    if (*(undefined **)(param_1 + 0x68) != PTR_DAT_18001c888) {
      _free_base(*(undefined **)(param_1 + 0x68));
    }
    if (*(undefined **)(param_1 + 0x70) != PTR_DAT_18001c890) {
      _free_base(*(undefined **)(param_1 + 0x70));
    }
    if (*(undefined **)(param_1 + 0x78) != PTR_DAT_18001c898) {
      _free_base(*(undefined **)(param_1 + 0x78));
    }
    if (*(undefined **)(param_1 + 0x80) != PTR_DAT_18001c8a0) {
      _free_base(*(undefined **)(param_1 + 0x80));
    }
    if (*(undefined **)(param_1 + 0x88) != PTR_DAT_18001c8a8) {
      _free_base(*(undefined **)(param_1 + 0x88));
    }
    if (*(undefined **)(param_1 + 0x90) != PTR_DAT_18001c8b0) {
      _free_base(*(undefined **)(param_1 + 0x90));
    }
  }
  return;
}



/* ---- __acrt_locale_free_numeric @ 18000e428 ---- */

/* Library Function - Single Match
    __acrt_locale_free_numeric
   
   Libraries: Visual Studio 2015 Release, Visual Studio 2017 Release, Visual Studio 2019 Release */

void __acrt_locale_free_numeric(undefined8 *param_1)

{
  if (param_1 != (undefined8 *)0x0) {
    if ((undefined *)*param_1 != PTR_DAT_18001c820) {
      _free_base((undefined *)*param_1);
    }
    if ((undefined *)param_1[1] != PTR_DAT_18001c828) {
      _free_base((undefined *)param_1[1]);
    }
    if ((undefined *)param_1[2] != PTR_DAT_18001c830) {
      _free_base((undefined *)param_1[2]);
    }
    if ((undefined *)param_1[0xb] != PTR_DAT_18001c878) {
      _free_base((undefined *)param_1[0xb]);
    }
    if ((undefined *)param_1[0xc] != PTR_DAT_18001c880) {
      _free_base((undefined *)param_1[0xc]);
    }
  }
  return;
}



/* ---- free_crt_array_internal @ 18000e494 ---- */

/* Library Function - Single Match
    void __cdecl free_crt_array_internal(void const * __ptr64 * __ptr64 const,unsigned __int64)
   
   Library: Visual Studio 2015 Release */

void __cdecl free_crt_array_internal(void **param_1,__uint64 param_2)

{
  ulonglong uVar1;
  ulonglong uVar2;
  
  uVar2 = 0;
  uVar1 = (ulonglong)((longlong)(param_1 + param_2) + (7 - (longlong)param_1)) >> 3;
  if (param_1 + param_2 < param_1) {
    uVar1 = uVar2;
  }
  if (uVar1 != 0) {
    do {
      _free_base(*param_1);
      uVar2 = uVar2 + 1;
      param_1 = param_1 + 1;
    } while (uVar2 != uVar1);
  }
  return;
}



/* ---- __acrt_locale_free_time @ 18000e4ec ---- */

/* Library Function - Single Match
    __acrt_locale_free_time
   
   Library: Visual Studio 2015 Release */

void __acrt_locale_free_time(void **param_1)

{
  if (param_1 != (void **)0x0) {
    free_crt_array_internal(param_1,7);
    free_crt_array_internal(param_1 + 7,7);
    free_crt_array_internal(param_1 + 0xe,0xc);
    free_crt_array_internal(param_1 + 0x1a,0xc);
    free_crt_array_internal(param_1 + 0x26,2);
    _free_base(param_1[0x28]);
    _free_base(param_1[0x29]);
    _free_base(param_1[0x2a]);
    free_crt_array_internal(param_1 + 0x2c,7);
    free_crt_array_internal(param_1 + 0x33,7);
    free_crt_array_internal(param_1 + 0x3a,0xc);
    free_crt_array_internal(param_1 + 0x46,0xc);
    free_crt_array_internal(param_1 + 0x52,2);
    _free_base(param_1[0x54]);
    _free_base(param_1[0x55]);
    _free_base(param_1[0x56]);
    _free_base(param_1[0x57]);
  }
  return;
}



/* ---- _fcloseall @ 18000e5f4 ---- */

/* Library Function - Single Match
    _fcloseall
   
   Library: Visual Studio 2015 Release */

int __cdecl _fcloseall(void)

{
  longlong lVar1;
  int iVar2;
  int iVar3;
  longlong lVar4;
  int local_18;
  
  local_18 = 0;
  __acrt_lock(8);
  for (iVar3 = 3; iVar3 != DAT_18001d200; iVar3 = iVar3 + 1) {
    lVar4 = (longlong)iVar3;
    lVar1 = *(longlong *)(DAT_18001d208 + lVar4 * 8);
    if (lVar1 != 0) {
      if (((*(uint *)(lVar1 + 0x14) >> 0xd & 1) != 0) &&
         (iVar2 = fclose(*(FILE **)(DAT_18001d208 + lVar4 * 8)), iVar2 != -1)) {
        local_18 = local_18 + 1;
      }
      DeleteCriticalSection((LPCRITICAL_SECTION)(*(longlong *)(DAT_18001d208 + lVar4 * 8) + 0x30));
      _free_base(*(LPVOID *)(DAT_18001d208 + lVar4 * 8));
      *(undefined8 *)(DAT_18001d208 + lVar4 * 8) = 0;
    }
  }
  __acrt_unlock(8);
  return local_18;
}



/* ---- __acrt_stdio_flush_nolock @ 18000e6a8 ---- */

/* Library Function - Single Match
    __acrt_stdio_flush_nolock
   
   Library: Visual Studio 2015 Release */

undefined8 __acrt_stdio_flush_nolock(FILE *param_1)

{
  uint *puVar1;
  char *_Buf;
  int _FileHandle;
  uint uVar2;
  uint _MaxCharCount;
  
  if ((((byte)*(undefined4 *)((longlong)&param_1->_base + 4) & 3) == 2) &&
     (((ulonglong)param_1->_base & 0xc000000000) != 0)) {
    _MaxCharCount = *(int *)&param_1->_ptr - param_1->_cnt;
    *(undefined4 *)&param_1->_base = 0;
    _Buf = *(char **)&param_1->_cnt;
    param_1->_ptr = _Buf;
    if (0 < (int)_MaxCharCount) {
      _FileHandle = _fileno(param_1);
      uVar2 = _write(_FileHandle,_Buf,_MaxCharCount);
      if (_MaxCharCount != uVar2) {
        LOCK();
        puVar1 = (uint *)((longlong)&param_1->_base + 4);
        *puVar1 = *puVar1 | 0x10;
        UNLOCK();
        return 0xffffffff;
      }
      if ((*(uint *)((longlong)&param_1->_base + 4) >> 2 & 1) != 0) {
        LOCK();
        puVar1 = (uint *)((longlong)&param_1->_base + 4);
        *puVar1 = *puVar1 & 0xfffffffd;
        UNLOCK();
      }
    }
  }
  return 0;
}



/* ---- _fflush_nolock @ 18000e720 ---- */

/* Library Function - Single Match
    _fflush_nolock
   
   Library: Visual Studio 2015 Release */

int __cdecl _fflush_nolock(FILE *_File)

{
  int iVar1;
  undefined8 uVar2;
  
  if (_File == (FILE *)0x0) {
    iVar1 = common_flush_all(0);
    return iVar1;
  }
  uVar2 = __acrt_stdio_flush_nolock(_File);
  if ((int)uVar2 == 0) {
    if ((*(uint *)((longlong)&_File->_base + 4) >> 0xb & 1) != 0) {
      iVar1 = _fileno(_File);
      iVar1 = _commit(iVar1);
      if (iVar1 != 0) goto LAB_18000e741;
    }
    iVar1 = 0;
  }
  else {
LAB_18000e741:
    iVar1 = -1;
  }
  return iVar1;
}



/* ---- FUN_18000e76c @ 18000e76c ---- */

void FUN_18000e76c(void)

{
  common_flush_all(1);
  return;
}



/* ---- common_flush_all @ 18000e778 ---- */

/* Library Function - Single Match
    common_flush_all
   
   Library: Visual Studio 2015 Release */

int common_flush_all(int param_1)

{
  undefined8 *puVar1;
  FILE *_File;
  int iVar2;
  undefined8 *puVar3;
  int local_38;
  int local_34;
  
  local_34 = 0;
  local_38 = 0;
  __acrt_lock(8);
  puVar1 = DAT_18001d208 + DAT_18001d200;
  for (puVar3 = DAT_18001d208; puVar3 != puVar1; puVar3 = puVar3 + 1) {
    _File = (FILE *)*puVar3;
    if (_File != (FILE *)0x0) {
      FUN_18000bc2c((longlong)_File);
      if ((*(uint *)((longlong)&_File->_base + 4) >> 0xd & 1) != 0) {
        if (param_1 == 1) {
          iVar2 = _fflush_nolock(_File);
          if (iVar2 != -1) {
            local_34 = local_34 + 1;
          }
        }
        else if (((param_1 == 0) && ((*(uint *)((longlong)&_File->_base + 4) >> 1 & 1) != 0)) &&
                (iVar2 = _fflush_nolock(_File), iVar2 == -1)) {
          local_38 = -1;
        }
      }
      FUN_18000bc38((longlong)_File);
    }
  }
  __acrt_unlock(8);
  if (param_1 == 1) {
    local_38 = local_34;
  }
  return local_38;
}



/* ---- __acrt_stdio_free_buffer_nolock @ 18000e85c ---- */

/* Library Function - Single Match
    __acrt_stdio_free_buffer_nolock
   
   Libraries: Visual Studio 2015 Release, Visual Studio 2017 Release */

void __acrt_stdio_free_buffer_nolock(undefined8 *param_1)

{
  if (((*(uint *)((longlong)param_1 + 0x14) >> 0xd & 1) != 0) &&
     ((*(uint *)((longlong)param_1 + 0x14) >> 6 & 1) != 0)) {
    _free_base((LPVOID)param_1[1]);
    LOCK();
    *(uint *)((longlong)param_1 + 0x14) = *(uint *)((longlong)param_1 + 0x14) & 0xfffffebf;
    UNLOCK();
    param_1[1] = 0;
    *param_1 = 0;
    *(undefined4 *)(param_1 + 2) = 0;
  }
  return;
}



/* ---- FUN_18000e89c @ 18000e89c ---- */

uint FUN_18000e89c(void)

{
  uint uVar1;
  
  uVar1 = FUN_1800102c0(0,0);
  return uVar1 & 799;
}



/* ---- __acrt_lowio_create_handle_array @ 18000e8b4 ---- */

/* Library Function - Single Match
    __acrt_lowio_create_handle_array
   
   Library: Visual Studio 2015 Release */

undefined8 * __acrt_lowio_create_handle_array(void)

{
  undefined8 *puVar1;
  undefined8 *puVar2;
  undefined8 *puVar3;
  undefined8 *puVar4;
  
  puVar2 = _calloc_base(0x40,0x40);
  puVar3 = (undefined8 *)0x0;
  if ((puVar2 != (undefined8 *)0x0) && (puVar3 = puVar2, puVar2 != puVar2 + 0x200)) {
    puVar4 = puVar2 + 6;
    do {
      __acrt_InitializeCriticalSectionEx((LPCRITICAL_SECTION)(puVar4 + -6),4000,0);
      puVar4[-1] = 0xffffffffffffffff;
      *puVar4 = 0;
      *(undefined4 *)(puVar4 + 1) = 0xa0a0000;
      *(undefined1 *)((longlong)puVar4 + 0xc) = 10;
      *(byte *)((longlong)puVar4 + 0xd) = *(byte *)((longlong)puVar4 + 0xd) & 0xf8;
      *(undefined1 *)((longlong)puVar4 + 0xe) = 0;
      puVar1 = puVar4 + 2;
      puVar4 = puVar4 + 8;
    } while (puVar1 != puVar2 + 0x200);
  }
  _free_base((LPVOID)0x0);
  return puVar3;
}



/* ---- __acrt_lowio_destroy_handle_array @ 18000e94c ---- */

/* Library Function - Single Match
    __acrt_lowio_destroy_handle_array
   
   Library: Visual Studio 2015 Release */

void __acrt_lowio_destroy_handle_array(LPCRITICAL_SECTION param_1)

{
  LPCRITICAL_SECTION lpCriticalSection;
  
  if (param_1 != (LPCRITICAL_SECTION)0x0) {
    for (lpCriticalSection = param_1;
        lpCriticalSection != (LPCRITICAL_SECTION)&param_1[0x66].OwningThread;
        lpCriticalSection = (LPCRITICAL_SECTION)&lpCriticalSection[1].LockSemaphore) {
      DeleteCriticalSection(lpCriticalSection);
    }
    _free_base(param_1);
  }
  return;
}



/* ---- __acrt_lowio_ensure_fh_exists @ 18000e99c ---- */

/* Library Function - Single Match
    __acrt_lowio_ensure_fh_exists
   
   Library: Visual Studio 2015 Release */

longlong __acrt_lowio_ensure_fh_exists(uint param_1)

{
  int iVar1;
  ulong *puVar2;
  undefined8 *puVar3;
  longlong lVar4;
  longlong lVar5;
  
  lVar4 = 0;
  if (param_1 < 0x2000) {
    __acrt_lock(7);
    lVar5 = lVar4;
    iVar1 = DAT_18001d610;
    while (iVar1 <= (int)param_1) {
      if ((&DAT_18001d210)[lVar5] == 0) {
        puVar3 = __acrt_lowio_create_handle_array();
        (&DAT_18001d210)[lVar5] = puVar3;
        if (puVar3 == (undefined8 *)0x0) {
          lVar4 = 0xc;
          break;
        }
        iVar1 = DAT_18001d610 + 0x40;
        DAT_18001d610 = iVar1;
      }
      lVar5 = lVar5 + 1;
    }
    __acrt_unlock(7);
  }
  else {
    puVar2 = __doserrno();
    lVar4 = 9;
    *puVar2 = 9;
    FUN_18000aff4();
  }
  return lVar4;
}



/* ---- FID_conflict:__acrt_lowio_lock_fh @ 18000ea54 ---- */

/* Library Function - Multiple Matches With Different Base Names
    __acrt_lowio_lock_fh
    __acrt_lowio_unlock_fh
   
   Library: Visual Studio 2015 Release */

void FID_conflict___acrt_lowio_lock_fh(uint param_1)

{
                    /* WARNING: Could not recover jumptable at 0x00018000ea70. Too many branches */
                    /* WARNING: Treating indirect jump as call */
  EnterCriticalSection
            ((ulonglong)(param_1 & 0x3f) * 0x40 + (&DAT_18001d210)[(longlong)(int)param_1 >> 6]);
  return;
}



/* ---- FID_conflict:__acrt_lowio_lock_fh @ 18000ea78 ---- */

/* Library Function - Multiple Matches With Different Base Names
    __acrt_lowio_lock_fh
    __acrt_lowio_unlock_fh
   
   Library: Visual Studio 2015 Release */

void FID_conflict___acrt_lowio_lock_fh(uint param_1)

{
                    /* WARNING: Could not recover jumptable at 0x00018000ea94. Too many branches */
                    /* WARNING: Treating indirect jump as call */
  LeaveCriticalSection
            ((ulonglong)(param_1 & 0x3f) * 0x40 + (&DAT_18001d210)[(longlong)(int)param_1 >> 6]);
  return;
}



/* ---- _free_osfhnd @ 18000ea9c ---- */

/* Library Function - Single Match
    _free_osfhnd
   
   Library: Visual Studio 2015 Release */

int __cdecl _free_osfhnd(int param_1)

{
  int iVar1;
  ulong *puVar2;
  DWORD nStdHandle;
  longlong lVar3;
  
  if ((-1 < param_1) && ((uint)param_1 < DAT_18001d610)) {
    lVar3 = (ulonglong)(param_1 & 0x3f) * 0x40;
    if (((*(byte *)((&DAT_18001d210)[(longlong)param_1 >> 6] + 0x38 + lVar3) & 1) != 0) &&
       (*(longlong *)((&DAT_18001d210)[(longlong)param_1 >> 6] + 0x28 + lVar3) != -1)) {
      iVar1 = FUN_1800105d0();
      if (iVar1 == 1) {
        if (param_1 == 0) {
          nStdHandle = 0xfffffff6;
        }
        else if (param_1 == 1) {
          nStdHandle = 0xfffffff5;
        }
        else {
          if (param_1 != 2) goto LAB_18000eb1c;
          nStdHandle = 0xfffffff4;
        }
        SetStdHandle(nStdHandle,(HANDLE)0x0);
      }
LAB_18000eb1c:
      *(undefined8 *)((&DAT_18001d210)[(longlong)param_1 >> 6] + 0x28 + lVar3) = 0xffffffffffffffff;
      return 0;
    }
  }
  puVar2 = __doserrno();
  *puVar2 = 9;
  puVar2 = __doserrno();
  *puVar2 = 0;
  return -1;
}



/* ---- _get_osfhandle @ 18000eb58 ---- */

/* Library Function - Single Match
    _get_osfhandle
   
   Library: Visual Studio 2015 Release */

intptr_t __cdecl _get_osfhandle(int _FileHandle)

{
  ulong *puVar1;
  longlong lVar2;
  
  if (_FileHandle == -2) {
    puVar1 = __doserrno();
    *puVar1 = 0;
    puVar1 = __doserrno();
    *puVar1 = 9;
  }
  else {
    if ((-1 < _FileHandle) && ((uint)_FileHandle < DAT_18001d610)) {
      lVar2 = (ulonglong)(_FileHandle & 0x3f) * 0x40;
      if ((*(byte *)((&DAT_18001d210)[(longlong)_FileHandle >> 6] + 0x38 + lVar2) & 1) != 0) {
        return *(intptr_t *)((&DAT_18001d210)[(longlong)_FileHandle >> 6] + 0x28 + lVar2);
      }
    }
    puVar1 = __doserrno();
    *puVar1 = 0;
    puVar1 = __doserrno();
    *puVar1 = 9;
    FUN_18000aff4();
  }
  return -1;
}



/* ---- GetTableIndexFromLocaleName @ 18000ebd0 ---- */

/* Library Function - Single Match
    int __cdecl GetTableIndexFromLocaleName(wchar_t const * __ptr64)
   
   Library: Visual Studio 2015 Release */

int __cdecl GetTableIndexFromLocaleName(wchar_t *param_1)

{
  int iVar1;
  ushort uVar2;
  ushort uVar3;
  longlong lVar4;
  longlong lVar5;
  ushort *puVar6;
  int iVar7;
  int iVar8;
  
  iVar7 = 0;
  iVar8 = 0xe3;
  while( true ) {
    lVar4 = 0x55;
    iVar1 = (iVar8 + iVar7) / 2;
    puVar6 = (ushort *)(&PTR_DAT_180016b10)[(longlong)iVar1 * 2];
    lVar5 = (longlong)param_1 - (longlong)puVar6;
    do {
      uVar3 = *(ushort *)(lVar5 + (longlong)puVar6);
      if ((ushort)(uVar3 - 0x41) < 0x1a) {
        uVar3 = uVar3 + 0x20;
      }
      uVar2 = *puVar6;
      if ((ushort)(uVar2 - 0x41) < 0x1a) {
        uVar2 = uVar2 + 0x20;
      }
      puVar6 = puVar6 + 1;
      lVar4 = lVar4 + -1;
    } while (((lVar4 != 0) && (uVar3 != 0)) && (uVar3 == uVar2));
    if ((uint)uVar3 == (uint)uVar2) break;
    if ((int)((uint)uVar3 - (uint)uVar2) < 0) {
      iVar8 = iVar1 + -1;
    }
    else {
      iVar7 = iVar1 + 1;
    }
    if (iVar8 < iVar7) {
      return -1;
    }
  }
  return *(int *)(&DAT_180016b18 + (longlong)iVar1 * 0x10);
}



/* ---- __acrt_DownlevelLocaleNameToLCID @ 18000ec98 ---- */

/* Library Function - Single Match
    __acrt_DownlevelLocaleNameToLCID
   
   Library: Visual Studio 2015 Release */

undefined4 __acrt_DownlevelLocaleNameToLCID(wchar_t *param_1)

{
  int iVar1;
  
  if (((param_1 != (wchar_t *)0x0) && (iVar1 = GetTableIndexFromLocaleName(param_1), -1 < iVar1)) &&
     ((ulonglong)(longlong)iVar1 < 0xe4)) {
    return *(undefined4 *)(&DAT_1800150c0 + (longlong)iVar1 * 0x10);
  }
  return 0;
}



/* ---- shortsort @ 18000ecd0 ---- */

/* Library Function - Single Match
    void __cdecl shortsort(char * __ptr64,char * __ptr64,unsigned __int64,int (__cdecl*)(void const
   * __ptr64,void const * __ptr64))
   
   Library: Visual Studio 2015 Release */

void __cdecl
shortsort(char *param_1,char *param_2,__uint64 param_3,_func_int_void_ptr_void_ptr *param_4)

{
  char cVar1;
  char *pcVar2;
  int iVar3;
  char *pcVar4;
  __uint64 _Var5;
  
  for (; pcVar2 = param_1, pcVar4 = param_1, param_1 < param_2; param_2 = param_2 + -param_3) {
    while (pcVar4 = pcVar4 + param_3, pcVar4 <= param_2) {
      (*(code *)PTR__guard_check_icall_180012238)(param_4);
      iVar3 = (*param_4)(pcVar4,pcVar2);
      if (0 < iVar3) {
        pcVar2 = pcVar4;
      }
    }
    if ((pcVar2 != param_2) && (param_3 != 0)) {
      pcVar4 = param_2;
      _Var5 = param_3;
      do {
        cVar1 = pcVar4[(longlong)pcVar2 - (longlong)param_2];
        pcVar4[(longlong)pcVar2 - (longlong)param_2] = *pcVar4;
        *pcVar4 = cVar1;
        pcVar4 = pcVar4 + 1;
        _Var5 = _Var5 - 1;
      } while (_Var5 != 0);
    }
  }
  return;
}



/* ---- qsort @ 18000eda0 ---- */

/* WARNING: Function: __security_check_cookie replaced with injection: security_check_cookie */
/* Library Function - Single Match
    qsort
   
   Library: Visual Studio 2015 Release */

void __cdecl
qsort(void *_Base,size_t _NumOfElements,size_t _SizeOfElements,_PtFuncCompare *_PtFuncCompare)

{
  ulonglong uVar1;
  char cVar2;
  int iVar3;
  ulong *puVar4;
  char *pcVar5;
  char *pcVar6;
  char *pcVar7;
  char *pcVar8;
  size_t sVar9;
  longlong lVar10;
  char *pcVar11;
  undefined1 auStack_458 [32];
  undefined8 auStack_438 [62];
  undefined8 auStack_248 [62];
  ulonglong local_58;
  
  local_58 = DAT_18001c000 ^ (ulonglong)auStack_458;
  if ((((_Base == (void *)0x0) && (_NumOfElements != 0)) || (_SizeOfElements == 0)) ||
     (_PtFuncCompare == (_PtFuncCompare *)0x0)) {
    puVar4 = __doserrno();
    *puVar4 = 0x16;
    FUN_18000aff4();
  }
  else if (1 < _NumOfElements) {
    lVar10 = 0;
    pcVar11 = (char *)((_NumOfElements - 1) * _SizeOfElements + (longlong)_Base);
LAB_18000ee31:
    while( true ) {
      uVar1 = (ulonglong)((longlong)pcVar11 - (longlong)_Base) / _SizeOfElements + 1;
      if (uVar1 < 9) break;
      pcVar7 = (char *)((longlong)_Base + (uVar1 >> 1) * _SizeOfElements);
      (*(code *)PTR__guard_check_icall_180012238)
                (_PtFuncCompare,(ulonglong)((longlong)pcVar11 - (longlong)_Base) % _SizeOfElements);
      iVar3 = (*_PtFuncCompare)(_Base,pcVar7);
      if ((0 < iVar3) && (_Base != pcVar7)) {
        pcVar6 = pcVar7;
        sVar9 = _SizeOfElements;
        do {
          cVar2 = pcVar6[(longlong)_Base - (longlong)pcVar7];
          pcVar6[(longlong)_Base - (longlong)pcVar7] = *pcVar6;
          *pcVar6 = cVar2;
          pcVar6 = pcVar6 + 1;
          sVar9 = sVar9 - 1;
        } while (sVar9 != 0);
      }
      (*(code *)PTR__guard_check_icall_180012238)(_PtFuncCompare);
      iVar3 = (*_PtFuncCompare)(_Base,pcVar11);
      if ((0 < iVar3) && (_Base != pcVar11)) {
        pcVar6 = pcVar11;
        sVar9 = _SizeOfElements;
        do {
          cVar2 = pcVar6[(longlong)_Base - (longlong)pcVar11];
          pcVar6[(longlong)_Base - (longlong)pcVar11] = *pcVar6;
          *pcVar6 = cVar2;
          pcVar6 = pcVar6 + 1;
          sVar9 = sVar9 - 1;
        } while (sVar9 != 0);
      }
      (*(code *)PTR__guard_check_icall_180012238)(_PtFuncCompare);
      iVar3 = (*_PtFuncCompare)(pcVar7,pcVar11);
      pcVar6 = _Base;
      pcVar8 = pcVar11;
      if ((0 < iVar3) && (pcVar7 != pcVar11)) {
        pcVar5 = pcVar11;
        sVar9 = _SizeOfElements;
        do {
          cVar2 = pcVar5[(longlong)pcVar7 - (longlong)pcVar11];
          pcVar5[(longlong)pcVar7 - (longlong)pcVar11] = *pcVar5;
          *pcVar5 = cVar2;
          pcVar5 = pcVar5 + 1;
          sVar9 = sVar9 - 1;
        } while (sVar9 != 0);
      }
LAB_18000ef40:
      if (pcVar6 < pcVar7) {
        do {
          pcVar6 = pcVar6 + _SizeOfElements;
          if (pcVar7 <= pcVar6) goto LAB_18000ef68;
          (*(code *)PTR__guard_check_icall_180012238)(_PtFuncCompare);
          iVar3 = (*_PtFuncCompare)(pcVar6,pcVar7);
        } while (iVar3 < 1);
        if (pcVar7 <= pcVar6) goto LAB_18000ef68;
      }
      else {
LAB_18000ef68:
        do {
          pcVar6 = pcVar6 + _SizeOfElements;
          if (pcVar11 < pcVar6) break;
          (*(code *)PTR__guard_check_icall_180012238)(_PtFuncCompare);
          iVar3 = (*_PtFuncCompare)(pcVar6,pcVar7);
        } while (iVar3 < 1);
      }
      do {
        pcVar8 = pcVar8 + -_SizeOfElements;
        if (pcVar8 <= pcVar7) break;
        (*(code *)PTR__guard_check_icall_180012238)(_PtFuncCompare);
        iVar3 = (*_PtFuncCompare)(pcVar8,pcVar7);
      } while (0 < iVar3);
      if (pcVar6 <= pcVar8) {
        if (pcVar6 != pcVar8) {
          pcVar5 = pcVar8;
          sVar9 = _SizeOfElements;
          do {
            cVar2 = pcVar5[(longlong)pcVar6 - (longlong)pcVar8];
            pcVar5[(longlong)pcVar6 - (longlong)pcVar8] = *pcVar5;
            *pcVar5 = cVar2;
            pcVar5 = pcVar5 + 1;
            sVar9 = sVar9 - 1;
          } while (sVar9 != 0);
        }
        if (pcVar7 == pcVar8) {
          pcVar7 = pcVar6;
        }
        goto LAB_18000ef40;
      }
      pcVar8 = pcVar8 + _SizeOfElements;
      if (pcVar7 < pcVar8) {
        do {
          pcVar8 = pcVar8 + -_SizeOfElements;
          if (pcVar8 <= pcVar7) goto LAB_18000f014;
          (*(code *)PTR__guard_check_icall_180012238)(_PtFuncCompare);
          iVar3 = (*_PtFuncCompare)(pcVar8,pcVar7);
        } while (iVar3 == 0);
        if (pcVar8 <= pcVar7) goto LAB_18000f014;
      }
      else {
LAB_18000f014:
        do {
          pcVar8 = pcVar8 + -_SizeOfElements;
          if (pcVar8 <= _Base) break;
          (*(code *)PTR__guard_check_icall_180012238)(_PtFuncCompare);
          iVar3 = (*_PtFuncCompare)(pcVar8,pcVar7);
        } while (iVar3 == 0);
      }
      if ((longlong)pcVar8 - (longlong)_Base < (longlong)pcVar11 - (longlong)pcVar6)
      goto LAB_18000f069;
      if (_Base < pcVar8) {
        auStack_438[lVar10] = _Base;
        auStack_248[lVar10] = pcVar8;
        lVar10 = lVar10 + 1;
      }
      _Base = pcVar6;
      if (pcVar11 <= pcVar6) goto LAB_18000ee57;
    }
    shortsort(_Base,pcVar11,_SizeOfElements,(_func_int_void_ptr_void_ptr *)_PtFuncCompare);
    goto LAB_18000ee57;
  }
  return;
LAB_18000f069:
  if (pcVar6 < pcVar11) {
    auStack_438[lVar10] = pcVar6;
    auStack_248[lVar10] = pcVar11;
    lVar10 = lVar10 + 1;
  }
  pcVar11 = pcVar8;
  if (pcVar8 <= _Base) {
LAB_18000ee57:
    lVar10 = lVar10 + -1;
    if (lVar10 < 0) {
      return;
    }
    _Base = (char *)auStack_438[lVar10];
    pcVar11 = (char *)auStack_248[lVar10];
  }
  goto LAB_18000ee31;
}



/* ---- FID_conflict:fallbackMethod @ 18000f0d4 ---- */

/* WARNING: Function: __security_check_cookie replaced with injection: security_check_cookie */
/* Library Function - Multiple Matches With Different Base Names
    fallbackMethod
    strpbrk
   
   Libraries: Visual Studio 2015 Release, Visual Studio 2017 Release, Visual Studio 2019 Release */

char * __cdecl FID_conflict_fallbackMethod(char *_Str,char *_Control)

{
  byte bVar1;
  code *pcVar2;
  ulonglong uVar3;
  char *pcVar4;
  undefined1 auStack_58 [32];
  byte abStack_38 [32];
  ulonglong local_18;
  
  local_18 = DAT_18001c000 ^ (ulonglong)auStack_58;
  uVar3 = 0;
  do {
    if (0x1f < uVar3) {
      __report_rangecheckfailure();
      pcVar2 = (code *)swi(3);
      pcVar4 = (char *)(*pcVar2)();
      return pcVar4;
    }
    abStack_38[uVar3] = 0;
    uVar3 = uVar3 + 1;
  } while ((longlong)uVar3 < 0x20);
  bVar1 = *_Control;
  while (bVar1 != 0) {
    _Control = _Control + 1;
    abStack_38[bVar1 >> 3] = abStack_38[bVar1 >> 3] | (byte)(1 << (bVar1 & 7));
    bVar1 = *_Control;
  }
  while( true ) {
    bVar1 = *_Str;
    if (bVar1 == 0) {
      return (char *)0x0;
    }
    if ((abStack_38[bVar1 >> 3] & (byte)(1 << (bVar1 & 7))) != 0) break;
    _Str = _Str + 1;
  }
  return (char *)(byte *)_Str;
}



/* ---- FUN_18000f174 @ 18000f174 ---- */

void FUN_18000f174(uchar *param_1,uchar *param_2)

{
  _mbsdec_l(param_1,param_2,(_locale_t)0x0);
  return;
}



/* ---- _mbsdec_l @ 18000f17c ---- */

/* Library Function - Single Match
    _mbsdec_l
   
   Library: Visual Studio 2015 Release */

uchar * __cdecl _mbsdec_l(uchar *_Start,uchar *_Pos,_locale_t _Locale)

{
  ulong *puVar1;
  byte *pbVar2;
  longlong local_28 [2];
  longlong local_18;
  char local_10;
  
  if ((_Start == (uchar *)0x0) || (_Pos == (uchar *)0x0)) {
    puVar1 = __doserrno();
    *puVar1 = 0x16;
    FUN_18000aff4();
  }
  else if (_Start < _Pos) {
    _LocaleUpdate::_LocaleUpdate((_LocaleUpdate *)local_28,(__crt_locale_pointers *)_Locale);
    if (*(int *)(local_18 + 8) != 0) {
      pbVar2 = _Pos + -1;
      do {
        pbVar2 = pbVar2 + -1;
        if (pbVar2 < _Start) break;
      } while ((*(byte *)((ulonglong)*pbVar2 + 0x19 + local_18) & 4) != 0);
      _Pos = _Pos + -(ulonglong)((int)_Pos - (int)pbVar2 & 1);
    }
    if (local_10 == '\0') {
      return _Pos + -1;
    }
    *(uint *)(local_28[0] + 0x3a8) = *(uint *)(local_28[0] + 0x3a8) & 0xfffffffd;
    return _Pos + -1;
  }
  return (uchar *)0x0;
}



/* ---- FUN_18000f214 @ 18000f214 ---- */

bool FUN_18000f214(void)

{
  undefined4 uVar1;
  
  uVar1 = __acrt_initialize_multibyte();
  return (char)uVar1 == '\0';
}



/* ---- __acrt_LCMapStringA_stat @ 18000f22c ---- */

/* WARNING: Function: _alloca_probe replaced with injection: alloca_probe */
/* WARNING: Function: __security_check_cookie replaced with injection: security_check_cookie */
/* Library Function - Single Match
    int __cdecl __acrt_LCMapStringA_stat(struct __crt_locale_pointers * __ptr64,wchar_t const *
   __ptr64,unsigned long,char const * __ptr64,int,char * __ptr64,int,int,int)
   
   Library: Visual Studio 2015 Release */

int __cdecl
__acrt_LCMapStringA_stat
          (__crt_locale_pointers *param_1,wchar_t *param_2,ulong param_3,char *param_4,int param_5,
          char *param_6,int param_7,int param_8,int param_9)

{
  longlong lVar1;
  wchar_t *pwVar2;
  int iVar3;
  int iVar4;
  int iVar5;
  size_t sVar6;
  ulonglong uVar7;
  undefined4 *puVar8;
  ulonglong uVar9;
  LPCWSTR lpWideCharStr;
  undefined1 *puVar10;
  undefined1 *puVar11;
  undefined1 *puVar12;
  undefined1 *puVar13;
  LPCWSTR pWVar14;
  undefined1 auStackY_88 [32];
  wchar_t *local_38;
  ulonglong local_30;
  
  puVar10 = auStackY_88;
  puVar12 = auStackY_88;
  local_30 = DAT_18001c000 ^ (ulonglong)&local_38;
  iVar4 = param_5;
  local_38 = param_2;
  if (0 < param_5) {
    sVar6 = __strncnt(param_4,(longlong)param_5);
    iVar5 = (int)sVar6;
    iVar4 = iVar5 + 1;
    if (param_5 <= iVar5) {
      iVar4 = iVar5;
    }
  }
  if (param_8 == 0) {
    param_8 = *(UINT *)(*(longlong *)param_1 + 0xc);
  }
  iVar3 = MultiByteToWideChar(param_8,(-(uint)(param_9 != 0) & 8) + 1,param_4,iVar4,(LPWSTR)0x0,0);
  iVar5 = 0;
  puVar13 = auStackY_88;
  if (iVar3 == 0) goto LAB_18000f53f;
  uVar7 = (longlong)iVar3 * 2;
  if ((uVar7 + 0x10 & -(ulonglong)(uVar7 < uVar7 + 0x10)) == 0) {
    pWVar14 = (LPCWSTR)0x0;
LAB_18000f357:
    if (pWVar14 == (LPCWSTR)0x0) goto LAB_18000f525;
    *(int *)(puVar12 + 0x28) = iVar3;
    *(LPCWSTR *)(puVar12 + 0x20) = pWVar14;
    *(undefined8 *)(puVar12 + -8) = 0x18000f37e;
    iVar4 = MultiByteToWideChar(param_8,1,param_4,iVar4,*(LPWSTR *)(puVar12 + 0x20),
                                *(int *)(puVar12 + 0x28));
    if (iVar4 == 0) goto LAB_18000f525;
    *(undefined8 *)(puVar12 + 0x40) = 0;
    *(undefined8 *)(puVar12 + 0x38) = 0;
    *(undefined8 *)(puVar12 + 0x30) = 0;
    pwVar2 = local_38;
    *(undefined4 *)(puVar12 + 0x28) = 0;
    *(undefined8 *)(puVar12 + 0x20) = 0;
    *(undefined8 *)(puVar12 + -8) = 0x18000f3b8;
    iVar5 = __acrt_LCMapStringEx
                      (pwVar2,param_3,pWVar14,iVar3,*(LPWSTR *)(puVar12 + 0x20),
                       *(int *)(puVar12 + 0x28),*(undefined8 *)(puVar12 + 0x30),
                       *(undefined8 *)(puVar12 + 0x38),*(undefined8 *)(puVar12 + 0x40));
    if (iVar5 == 0) goto LAB_18000f525;
    if ((param_3 & 0x400) == 0) {
      uVar7 = (longlong)iVar5 * 2;
      if ((uVar7 + 0x10 & -(ulonglong)(uVar7 < uVar7 + 0x10)) == 0) {
        lpWideCharStr = (LPCWSTR)0x0;
      }
      else {
        uVar9 = uVar7 + 0x10;
        if ((-(ulonglong)(uVar7 < uVar7 + 0x10) & uVar7 + 0x10) < 0x401) {
          uVar9 = -(ulonglong)(uVar7 < uVar9) & uVar9;
          uVar7 = uVar9 + 0xf;
          if (uVar7 <= uVar9) {
            uVar7 = 0xffffffffffffff0;
          }
          *(undefined8 *)(puVar12 + -8) = 0x18000f470;
          lVar1 = -(uVar7 & 0xfffffffffffffff0);
          puVar11 = puVar12 + lVar1;
          puVar8 = (undefined4 *)(puVar12 + lVar1 + 0x50);
          puVar12 = puVar12 + lVar1;
          if (puVar8 == (undefined4 *)0x0) goto LAB_18000f525;
          *puVar8 = 0xcccc;
          puVar12 = puVar11;
        }
        else {
          *(undefined8 *)(puVar12 + -8) = 0x18000f497;
          puVar8 = _malloc_base(-(ulonglong)(uVar7 < uVar9) & uVar9);
          lpWideCharStr = (LPCWSTR)0x0;
          if (puVar8 == (undefined4 *)0x0) goto LAB_18000f4ad;
          *puVar8 = 0xdddd;
        }
        lpWideCharStr = (LPCWSTR)(puVar8 + 4);
      }
LAB_18000f4ad:
      if (lpWideCharStr != (LPCWSTR)0x0) {
        *(undefined8 *)(puVar12 + 0x40) = 0;
        *(undefined8 *)(puVar12 + 0x38) = 0;
        *(undefined8 *)(puVar12 + 0x30) = 0;
        *(int *)(puVar12 + 0x28) = iVar5;
        *(LPCWSTR *)(puVar12 + 0x20) = lpWideCharStr;
        *(undefined8 *)(puVar12 + -8) = 0x18000f4de;
        iVar4 = __acrt_LCMapStringEx
                          (pwVar2,param_3,pWVar14,iVar3,*(LPWSTR *)(puVar12 + 0x20),
                           *(int *)(puVar12 + 0x28),*(undefined8 *)(puVar12 + 0x30),
                           *(undefined8 *)(puVar12 + 0x38),*(undefined8 *)(puVar12 + 0x40));
        if (iVar4 != 0) {
          *(undefined8 *)(puVar12 + 0x38) = 0;
          *(undefined8 *)(puVar12 + 0x30) = 0;
          if (param_7 == 0) {
            *(undefined4 *)(puVar12 + 0x28) = 0;
            *(undefined8 *)(puVar12 + 0x20) = 0;
          }
          else {
            *(int *)(puVar12 + 0x28) = param_7;
            *(char **)(puVar12 + 0x20) = param_6;
          }
          *(undefined8 *)(puVar12 + -8) = 0x18000f50e;
          iVar5 = WideCharToMultiByte(param_8,0,lpWideCharStr,iVar5,*(LPSTR *)(puVar12 + 0x20),
                                      *(int *)(puVar12 + 0x28),*(LPCSTR *)(puVar12 + 0x30),
                                      *(LPBOOL *)(puVar12 + 0x38));
          if (iVar5 != 0) {
            if (*(int *)(lpWideCharStr + -8) == 0xdddd) {
              *(undefined8 *)(puVar12 + -8) = 0x18000f585;
              _free_base(lpWideCharStr + -8);
            }
            goto LAB_18000f527;
          }
        }
        if (*(int *)(lpWideCharStr + -8) == 0xdddd) {
          *(undefined8 *)(puVar12 + -8) = 0x18000f525;
          _free_base(lpWideCharStr + -8);
        }
      }
      goto LAB_18000f525;
    }
    if (param_7 != 0) {
      if (iVar5 <= param_7) {
        *(undefined8 *)(puVar12 + 0x40) = 0;
        *(undefined8 *)(puVar12 + 0x38) = 0;
        *(undefined8 *)(puVar12 + 0x30) = 0;
        *(int *)(puVar12 + 0x28) = param_7;
        *(char **)(puVar12 + 0x20) = param_6;
        *(undefined8 *)(puVar12 + -8) = 0x18000f411;
        iVar5 = __acrt_LCMapStringEx
                          (pwVar2,param_3,pWVar14,iVar3,*(LPWSTR *)(puVar12 + 0x20),
                           *(int *)(puVar12 + 0x28),*(undefined8 *)(puVar12 + 0x30),
                           *(undefined8 *)(puVar12 + 0x38),*(undefined8 *)(puVar12 + 0x40));
        if (iVar5 != 0) goto LAB_18000f527;
      }
      goto LAB_18000f525;
    }
  }
  else {
    uVar9 = uVar7 + 0x10;
    if (0x400 < (-(ulonglong)(uVar7 < uVar7 + 0x10) & uVar7 + 0x10)) {
      puVar8 = _malloc_base(-(ulonglong)(uVar7 < uVar9) & uVar9);
      pWVar14 = (LPCWSTR)0x0;
      puVar12 = auStackY_88;
      if (puVar8 != (undefined4 *)0x0) {
        *puVar8 = 0xdddd;
        goto LAB_18000f34f;
      }
      goto LAB_18000f357;
    }
    uVar9 = -(ulonglong)(uVar7 < uVar9) & uVar9;
    uVar7 = uVar9 + 0xf;
    if (uVar7 <= uVar9) {
      uVar7 = 0xffffffffffffff0;
    }
    lVar1 = -(uVar7 & 0xfffffffffffffff0);
    puVar10 = auStackY_88 + lVar1;
    puVar8 = (undefined4 *)((longlong)&local_38 + lVar1);
    pWVar14 = (LPCWSTR)0x0;
    puVar12 = auStackY_88 + lVar1;
    if (puVar8 != (undefined4 *)0x0) {
      *puVar8 = 0xcccc;
LAB_18000f34f:
      pWVar14 = (LPCWSTR)(puVar8 + 4);
      puVar12 = puVar10;
      goto LAB_18000f357;
    }
LAB_18000f525:
    iVar5 = 0;
  }
LAB_18000f527:
  puVar13 = puVar12;
  if ((pWVar14 != (LPCWSTR)0x0) && (*(int *)(pWVar14 + -8) == 0xdddd)) {
    *(undefined8 *)(puVar12 + -8) = 0x18000f53d;
    _free_base(pWVar14 + -8);
  }
LAB_18000f53f:
  *(undefined8 *)(puVar13 + -8) = 0x18000f54b;
  return iVar5;
}



/* ---- __acrt_LCMapStringA @ 18000f588 ---- */

/* Library Function - Single Match
    __acrt_LCMapStringA
   
   Library: Visual Studio 2015 Release */

void __acrt_LCMapStringA(__crt_locale_pointers *param_1,wchar_t *param_2,ulong param_3,char *param_4
                        ,int param_5,char *param_6,int param_7,int param_8,int param_9)

{
  longlong local_28;
  __crt_locale_pointers local_20 [16];
  char local_10;
  
  _LocaleUpdate::_LocaleUpdate((_LocaleUpdate *)&local_28,param_1);
  __acrt_LCMapStringA_stat(local_20,param_2,param_3,param_4,param_5,param_6,param_7,param_8,param_9)
  ;
  if (local_10 != '\0') {
    *(uint *)(local_28 + 0x3a8) = *(uint *)(local_28 + 0x3a8) & 0xfffffffd;
  }
  return;
}



/* ---- _msize @ 18000f620 ---- */

/* Library Function - Single Match
    _msize
   
   Library: Visual Studio 2015 Release */

size_t __cdecl _msize(void *_Memory)

{
  ulong *puVar1;
  size_t sVar2;
  
  if (_Memory == (void *)0x0) {
    puVar1 = __doserrno();
    *puVar1 = 0x16;
    FUN_18000aff4();
    return 0xffffffffffffffff;
  }
                    /* WARNING: Could not recover jumptable at 0x00018000f652. Too many branches */
                    /* WARNING: Treating indirect jump as call */
  sVar2 = HeapSize(DAT_18001da28,0,_Memory);
  return sVar2;
}



/* ---- _realloc_base @ 18000f65c ---- */

/* Library Function - Single Match
    _realloc_base
   
   Library: Visual Studio 2015 Release */

LPVOID _realloc_base(LPVOID param_1,ulonglong param_2)

{
  int iVar1;
  LPVOID pvVar2;
  ulong *puVar3;
  
  if (param_1 == (LPVOID)0x0) {
    pvVar2 = _malloc_base(param_2);
  }
  else {
    if (param_2 == 0) {
      _free_base(param_1);
    }
    else {
      if (param_2 < 0xffffffffffffffe1) {
        do {
          pvVar2 = HeapReAlloc(DAT_18001da28,0,param_1,param_2);
          if (pvVar2 != (LPVOID)0x0) {
            return pvVar2;
          }
          iVar1 = FUN_18000dd14();
        } while ((iVar1 != 0) && (iVar1 = _callnewh(param_2), iVar1 != 0));
      }
      puVar3 = __doserrno();
      *puVar3 = 0xc;
    }
    pvVar2 = (LPVOID)0x0;
  }
  return pvVar2;
}



/* ---- _isatty @ 18000f6e0 ---- */

/* Library Function - Single Match
    _isatty
   
   Library: Visual Studio 2015 Release */

int __cdecl _isatty(int _FileHandle)

{
  ulong *puVar1;
  
  if (_FileHandle == -2) {
    puVar1 = __doserrno();
    *puVar1 = 9;
  }
  else {
    if ((-1 < _FileHandle) && ((uint)_FileHandle < DAT_18001d610)) {
      return *(byte *)((&DAT_18001d210)[(longlong)_FileHandle >> 6] + 0x38 +
                      (ulonglong)(_FileHandle & 0x3f) * 0x40) & 0x40;
    }
    puVar1 = __doserrno();
    *puVar1 = 9;
    FUN_18000aff4();
  }
  return 0;
}



/* ---- _fclose_nolock @ 18000f740 ---- */

/* Library Function - Single Match
    _fclose_nolock
   
   Library: Visual Studio 2015 Release */

int __cdecl _fclose_nolock(FILE *_File)

{
  int iVar1;
  int iVar2;
  ulong *puVar3;
  undefined8 uVar4;
  
  if (_File == (FILE *)0x0) {
    puVar3 = __doserrno();
    *puVar3 = 0x16;
    FUN_18000aff4();
    iVar1 = -1;
  }
  else {
    iVar1 = -1;
    if ((*(uint *)((longlong)&_File->_base + 4) >> 0xd & 1) != 0) {
      uVar4 = __acrt_stdio_flush_nolock(_File);
      iVar1 = (int)uVar4;
      __acrt_stdio_free_buffer_nolock(&_File->_ptr);
      iVar2 = _fileno(_File);
      iVar2 = _close(iVar2);
      if (iVar2 < 0) {
        iVar1 = -1;
      }
      else if (_File->_tmpfname != (char *)0x0) {
        _free_base(_File->_tmpfname);
        _File->_tmpfname = (char *)0x0;
      }
    }
    __acrt_stdio_free_stream(_File);
  }
  return iVar1;
}



/* ---- fclose @ 18000f7c4 ---- */

/* Library Function - Single Match
    fclose
   
   Library: Visual Studio 2015 Release */

int __cdecl fclose(FILE *_File)

{
  int iVar1;
  ulong *puVar2;
  
  if (_File == (FILE *)0x0) {
    puVar2 = __doserrno();
    *puVar2 = 0x16;
    FUN_18000aff4();
  }
  else {
    if ((*(uint *)((longlong)&_File->_base + 4) >> 0xc & 1) == 0) {
      FUN_18000bc2c((longlong)_File);
      iVar1 = _fclose_nolock(_File);
      FUN_18000bc38((longlong)_File);
      return iVar1;
    }
    __acrt_stdio_free_stream();
  }
  return -1;
}



/* ---- operator()<<lambda_b521505b218e5242e90febf6bfebc422>,<lambda_6978c1fb23f02e42e1d9e99668cc68aa>&___ptr64,<lambda_314360699dd331753a4119843814e9a7>_> @ 18000f830 ---- */

/* Library Function - Single Match
    public: int __cdecl __crt_seh_guarded_call<int>::operator()<class
   <lambda_b521505b218e5242e90febf6bfebc422>,class <lambda_6978c1fb23f02e42e1d9e99668cc68aa> &
   __ptr64,class <lambda_314360699dd331753a4119843814e9a7> >(class
   <lambda_b521505b218e5242e90febf6bfebc422> && __ptr64,class
   <lambda_6978c1fb23f02e42e1d9e99668cc68aa> & __ptr64,class
   <lambda_314360699dd331753a4119843814e9a7> && __ptr64) __ptr64
   
   Library: Visual Studio 2015 Release */

int __thiscall
__crt_seh_guarded_call<int>::
operator()<<lambda_b521505b218e5242e90febf6bfebc422>,<lambda_6978c1fb23f02e42e1d9e99668cc68aa>&___ptr64,<lambda_314360699dd331753a4119843814e9a7>_>
          (__crt_seh_guarded_call<int> *this,<lambda_b521505b218e5242e90febf6bfebc422> *param_1,
          <lambda_6978c1fb23f02e42e1d9e99668cc68aa> *param_2,
          <lambda_314360699dd331753a4119843814e9a7> *param_3)

{
  uint _FileHandle;
  BOOL BVar1;
  DWORD DVar2;
  HANDLE hFile;
  ulong *puVar3;
  int iVar4;
  
  FID_conflict___acrt_lowio_lock_fh(*(uint *)param_1);
  _FileHandle = **(uint **)param_2;
  if ((*(byte *)((&DAT_18001d210)[(longlong)(int)_FileHandle >> 6] + 0x38 +
                (ulonglong)(_FileHandle & 0x3f) * 0x40) & 1) != 0) {
    hFile = (HANDLE)_get_osfhandle(_FileHandle);
    BVar1 = FlushFileBuffers(hFile);
    iVar4 = 0;
    if (BVar1 != 0) goto LAB_18000f8a8;
    puVar3 = __doserrno();
    DVar2 = GetLastError();
    *puVar3 = DVar2;
  }
  puVar3 = __doserrno();
  *puVar3 = 9;
  iVar4 = -1;
LAB_18000f8a8:
  FID_conflict___acrt_lowio_lock_fh(*(uint *)param_3);
  return iVar4;
}



/* ---- _commit @ 18000f8bc ---- */

/* Library Function - Single Match
    _commit
   
   Library: Visual Studio 2015 Release */

int __cdecl _commit(int _FileHandle)

{
  int iVar1;
  ulong *puVar2;
  int local_res8 [2];
  __crt_seh_guarded_call<int> local_res10 [8];
  int local_res18 [2];
  int local_res20 [2];
  int *local_18 [3];
  
  local_res8[0] = _FileHandle;
  if (_FileHandle == -2) {
    puVar2 = __doserrno();
    *puVar2 = 9;
  }
  else {
    if (((-1 < _FileHandle) && ((uint)_FileHandle < DAT_18001d610)) &&
       ((*(byte *)((&DAT_18001d210)[(longlong)_FileHandle >> 6] + 0x38 +
                  (ulonglong)(_FileHandle & 0x3f) * 0x40) & 1) != 0)) {
      local_18[0] = local_res8;
      local_res18[0] = _FileHandle;
      local_res20[0] = _FileHandle;
      iVar1 = __crt_seh_guarded_call<int>::
              operator()<<lambda_b521505b218e5242e90febf6bfebc422>,<lambda_6978c1fb23f02e42e1d9e99668cc68aa>&___ptr64,<lambda_314360699dd331753a4119843814e9a7>_>
                        (local_res10,(<lambda_b521505b218e5242e90febf6bfebc422> *)local_res20,
                         (<lambda_6978c1fb23f02e42e1d9e99668cc68aa> *)local_18,
                         (<lambda_314360699dd331753a4119843814e9a7> *)local_res18);
      return iVar1;
    }
    puVar2 = __doserrno();
    *puVar2 = 9;
    FUN_18000aff4();
  }
  return -1;
}



/* ---- write_double_translated_ansi_nolock @ 18000f950 ---- */

/* WARNING: Function: __security_check_cookie replaced with injection: security_check_cookie */
/* Library Function - Single Match
    struct `anonymous namespace'::write_result __cdecl write_double_translated_ansi_nolock(int,char
   const * __ptr64 const,unsigned int)
   
   Library: Visual Studio 2015 Release */

DWORD * __cdecl write_double_translated_ansi_nolock(int param_1,char *param_2,uint param_3)

{
  byte bVar1;
  byte bVar2;
  longlong lVar3;
  int iVar4;
  uint nNumberOfBytesToWrite;
  BOOL BVar5;
  DWORD DVar6;
  ushort *puVar7;
  undefined4 in_register_0000000c;
  DWORD *pDVar8;
  byte *pbVar9;
  longlong lVar10;
  byte *pbVar11;
  undefined4 in_register_00000084;
  size_t sVar12;
  ulonglong in_R9;
  byte *pbVar13;
  longlong lVar14;
  undefined1 auStackY_b8 [32];
  wchar_t local_78 [2];
  undefined2 local_74 [2];
  uint local_70;
  UINT local_6c;
  HANDLE local_68;
  byte *local_60;
  byte local_58;
  byte local_57;
  CHAR local_50 [8];
  ulonglong local_48;
  
  pbVar11 = (byte *)CONCAT44(in_register_00000084,param_3);
  pDVar8 = (DWORD *)CONCAT44(in_register_0000000c,param_1);
  local_48 = DAT_18001c000 ^ (ulonglong)auStackY_b8;
  lVar14 = (longlong)(int)(uint)param_2 >> 6;
  lVar10 = (ulonglong)((uint)param_2 & 0x3f) * 0x40;
  pbVar13 = pbVar11 + (in_R9 & 0xffffffff);
  local_68 = *(HANDLE *)((&DAT_18001d210)[lVar14] + 0x28 + lVar10);
  local_60 = pbVar11;
  local_6c = GetConsoleCP();
  pDVar8[0] = 0;
  pDVar8[1] = 0;
  pDVar8[2] = 0;
  do {
    do {
      if (pbVar13 <= pbVar11) {
        return pDVar8;
      }
      bVar1 = *pbVar11;
      local_78[0] = L'\0';
      lVar3 = (&DAT_18001d210)[lVar14];
      bVar2 = *(byte *)(lVar3 + 0x3d + lVar10);
      if ((bVar2 & 4) == 0) {
        puVar7 = __pctype_func();
        if ((puVar7[*pbVar11] & 0x8000) == 0) {
          sVar12 = 1;
          pbVar9 = pbVar11;
          goto LAB_18000fa48;
        }
        if (pbVar13 <= pbVar11) {
          *(byte *)((&DAT_18001d210)[lVar14] + 0x3e + lVar10) = *pbVar11;
          pbVar11 = (byte *)((&DAT_18001d210)[lVar14] + 0x3d + lVar10);
          *pbVar11 = *pbVar11 | 4;
          pDVar8[1] = pDVar8[1] + 1;
          return pDVar8;
        }
        iVar4 = FUN_18000ba80(local_78,(char *)pbVar11,2);
        if (iVar4 == -1) {
          return pDVar8;
        }
        pbVar11 = pbVar11 + 1;
      }
      else {
        local_58 = *(byte *)(lVar3 + 0x3e + lVar10);
        *(byte *)(lVar3 + 0x3d + lVar10) = bVar2 & 0xfb;
        sVar12 = 2;
        pbVar9 = &local_58;
        local_57 = bVar1;
LAB_18000fa48:
        iVar4 = FUN_18000ba80(local_78,(char *)pbVar9,sVar12);
        if (iVar4 == -1) {
          return pDVar8;
        }
      }
      pbVar11 = pbVar11 + 1;
      nNumberOfBytesToWrite =
           WideCharToMultiByte(local_6c,0,local_78,1,local_50,5,(LPCSTR)0x0,(LPBOOL)0x0);
      if (nNumberOfBytesToWrite == 0) {
        return pDVar8;
      }
      BVar5 = WriteFile(local_68,local_50,nNumberOfBytesToWrite,&local_70,(LPOVERLAPPED)0x0);
      if (BVar5 == 0) goto LAB_18000fb26;
      pDVar8[1] = (pDVar8[2] - (int)local_60) + (int)pbVar11;
      if (local_70 < nNumberOfBytesToWrite) {
        return pDVar8;
      }
    } while (bVar1 != 10);
    local_74[0] = 0xd;
    BVar5 = WriteFile(local_68,local_74,1,&local_70,(LPOVERLAPPED)0x0);
    if (BVar5 == 0) {
LAB_18000fb26:
      DVar6 = GetLastError();
      *pDVar8 = DVar6;
      return pDVar8;
    }
    if (local_70 == 0) {
      return pDVar8;
    }
    pDVar8[2] = pDVar8[2] + 1;
    pDVar8[1] = pDVar8[1] + 1;
  } while( true );
}



/* ---- write_text_ansi_nolock @ 18000fb58 ---- */

/* WARNING: Function: _alloca_probe replaced with injection: alloca_probe */
/* WARNING: Function: __security_check_cookie replaced with injection: security_check_cookie */
/* Library Function - Single Match
    struct `anonymous namespace'::write_result __cdecl write_text_ansi_nolock(int,char const *
   __ptr64 const,unsigned int)
   
   Library: Visual Studio 2015 Release */

DWORD * __cdecl write_text_ansi_nolock(int param_1,char *param_2,uint param_3)

{
  char cVar1;
  longlong lVar2;
  HANDLE hFile;
  BOOL BVar3;
  DWORD DVar4;
  undefined4 in_register_0000000c;
  DWORD *pDVar5;
  char *pcVar6;
  char *pcVar7;
  uint nNumberOfBytesToWrite;
  char *pcVar8;
  undefined4 in_register_00000084;
  ulonglong in_R9;
  undefined1 auStackY_1468 [32];
  uint local_1438 [4];
  char local_1428 [5120];
  ulonglong local_28;
  undefined8 local_20;
  
  pcVar7 = (char *)CONCAT44(in_register_00000084,param_3);
  pDVar5 = (DWORD *)CONCAT44(in_register_0000000c,param_1);
  local_20 = 0x18000fb70;
  local_28 = DAT_18001c000 ^ (ulonglong)auStackY_1468;
  pcVar6 = pcVar7 + (in_R9 & 0xffffffff);
  *pDVar5 = 0;
  pDVar5[1] = 0;
  lVar2 = (&DAT_18001d210)[(longlong)(int)(uint)param_2 >> 6];
  pDVar5[2] = 0;
  hFile = *(HANDLE *)(lVar2 + 0x28 + (ulonglong)((uint)param_2 & 0x3f) * 0x40);
  do {
    if (pcVar6 <= pcVar7) {
      return pDVar5;
    }
    pcVar8 = local_1428;
    do {
      if (pcVar6 <= pcVar7) break;
      cVar1 = *pcVar7;
      pcVar7 = pcVar7 + 1;
      if (cVar1 == '\n') {
        pDVar5[2] = pDVar5[2] + 1;
        *pcVar8 = '\r';
        pcVar8 = pcVar8 + 1;
      }
      *pcVar8 = cVar1;
      pcVar8 = pcVar8 + 1;
    } while (pcVar8 < local_1428 + 0x13ff);
    nNumberOfBytesToWrite = (int)pcVar8 - (int)local_1428;
    BVar3 = WriteFile(hFile,local_1428,nNumberOfBytesToWrite,local_1438,(LPOVERLAPPED)0x0);
    if (BVar3 == 0) {
      DVar4 = GetLastError();
      *pDVar5 = DVar4;
      return pDVar5;
    }
    pDVar5[1] = pDVar5[1] + local_1438[0];
    if (local_1438[0] < nNumberOfBytesToWrite) {
      return pDVar5;
    }
  } while( true );
}



/* ---- write_text_utf16le_nolock @ 18000fc60 ---- */

/* WARNING: Function: _alloca_probe replaced with injection: alloca_probe */
/* WARNING: Function: __security_check_cookie replaced with injection: security_check_cookie */
/* Library Function - Single Match
    struct `anonymous namespace'::write_result __cdecl write_text_utf16le_nolock(int,char const *
   __ptr64 const,unsigned int)
   
   Library: Visual Studio 2015 Release */

DWORD * __cdecl write_text_utf16le_nolock(int param_1,char *param_2,uint param_3)

{
  short sVar1;
  longlong lVar2;
  HANDLE hFile;
  uint nNumberOfBytesToWrite;
  BOOL BVar3;
  DWORD DVar4;
  undefined4 in_register_0000000c;
  DWORD *pDVar5;
  short *psVar6;
  short *psVar7;
  short *psVar8;
  undefined4 in_register_00000084;
  ulonglong in_R9;
  undefined1 auStackY_1468 [32];
  uint local_1438 [4];
  short local_1428 [2560];
  ulonglong local_28;
  undefined8 local_20;
  
  psVar8 = (short *)CONCAT44(in_register_00000084,param_3);
  pDVar5 = (DWORD *)CONCAT44(in_register_0000000c,param_1);
  local_20 = 0x18000fc78;
  local_28 = DAT_18001c000 ^ (ulonglong)auStackY_1468;
  psVar7 = (short *)((in_R9 & 0xffffffff) + (longlong)psVar8);
  *pDVar5 = 0;
  pDVar5[1] = 0;
  lVar2 = (&DAT_18001d210)[(longlong)(int)(uint)param_2 >> 6];
  pDVar5[2] = 0;
  hFile = *(HANDLE *)(lVar2 + 0x28 + (ulonglong)((uint)param_2 & 0x3f) * 0x40);
  do {
    if (psVar7 <= psVar8) {
      return pDVar5;
    }
    psVar6 = local_1428;
    do {
      if (psVar7 <= psVar8) break;
      sVar1 = *psVar8;
      psVar8 = psVar8 + 1;
      if (sVar1 == 10) {
        pDVar5[2] = pDVar5[2] + 2;
        *psVar6 = 0xd;
        psVar6 = psVar6 + 1;
      }
      *psVar6 = sVar1;
      psVar6 = psVar6 + 1;
    } while (psVar6 < local_1428 + 0x9ff);
    nNumberOfBytesToWrite = (int)((longlong)psVar6 - (longlong)local_1428 >> 1) * 2;
    BVar3 = WriteFile(hFile,local_1428,nNumberOfBytesToWrite,local_1438,(LPOVERLAPPED)0x0);
    if (BVar3 == 0) {
      DVar4 = GetLastError();
      *pDVar5 = DVar4;
      return pDVar5;
    }
    pDVar5[1] = pDVar5[1] + local_1438[0];
    if (local_1438[0] < nNumberOfBytesToWrite) {
      return pDVar5;
    }
  } while( true );
}



/* ---- write_text_utf8_nolock @ 18000fd7c ---- */

/* WARNING: Function: _alloca_probe replaced with injection: alloca_probe */
/* WARNING: Function: __security_check_cookie replaced with injection: security_check_cookie */
/* Library Function - Single Match
    struct `anonymous namespace'::write_result __cdecl write_text_utf8_nolock(int,char const *
   __ptr64 const,unsigned int)
   
   Library: Visual Studio 2015 Release */

DWORD * __cdecl write_text_utf8_nolock(int param_1,char *param_2,uint param_3)

{
  WCHAR WVar1;
  HANDLE hFile;
  uint uVar2;
  BOOL BVar3;
  DWORD DVar4;
  WCHAR *pWVar5;
  undefined4 in_register_0000000c;
  DWORD *pDVar6;
  uint uVar7;
  ulonglong uVar8;
  WCHAR *pWVar9;
  undefined4 in_register_00000084;
  uint in_R9D;
  WCHAR *pWVar10;
  undefined1 auStackY_1498 [32];
  DWORD local_1458 [4];
  WCHAR local_1448 [856];
  CHAR local_d98 [3424];
  ulonglong local_38;
  undefined8 local_30;
  
  pWVar9 = (WCHAR *)CONCAT44(in_register_00000084,param_3);
  pDVar6 = (DWORD *)CONCAT44(in_register_0000000c,param_1);
  local_30 = 0x18000fd98;
  local_38 = DAT_18001c000 ^ (ulonglong)auStackY_1498;
  pWVar10 = (WCHAR *)((ulonglong)in_R9D + (longlong)pWVar9);
  hFile = *(HANDLE *)
           ((&DAT_18001d210)[(longlong)(int)(uint)param_2 >> 6] + 0x28 +
           (ulonglong)((uint)param_2 & 0x3f) * 0x40);
  *pDVar6 = 0;
  pDVar6[1] = 0;
  pDVar6[2] = 0;
  do {
    if (pWVar10 <= pWVar9) {
      return pDVar6;
    }
    pWVar5 = local_1448;
    do {
      if (pWVar10 <= pWVar9) break;
      WVar1 = *pWVar9;
      pWVar9 = pWVar9 + 1;
      if (WVar1 == L'\n') {
        *pWVar5 = L'\r';
        pWVar5 = pWVar5 + 1;
      }
      *pWVar5 = WVar1;
      pWVar5 = pWVar5 + 1;
    } while (pWVar5 < local_1448 + 0x354);
    uVar2 = WideCharToMultiByte(0xfde9,0,local_1448,
                                (int)((longlong)pWVar5 - (longlong)local_1448 >> 1),local_d98,0xd55,
                                (LPCSTR)0x0,(LPBOOL)0x0);
    if (uVar2 == 0) {
LAB_18000feb7:
      DVar4 = GetLastError();
      *pDVar6 = DVar4;
      return pDVar6;
    }
    uVar8 = 0;
    if (uVar2 != 0) {
      do {
        BVar3 = WriteFile(hFile,local_d98 + uVar8,uVar2 - (int)uVar8,local_1458,(LPOVERLAPPED)0x0);
        if (BVar3 == 0) goto LAB_18000feb7;
        uVar7 = (int)uVar8 + local_1458[0];
        uVar8 = (ulonglong)uVar7;
      } while (uVar7 < uVar2);
    }
    pDVar6[1] = (int)pWVar9 - param_3;
  } while( true );
}



/* ---- _write @ 18000fef0 ---- */

/* Library Function - Single Match
    _write
   
   Library: Visual Studio 2015 Release */

int __cdecl _write(int _FileHandle,void *_Buf,uint _MaxCharCount)

{
  int iVar1;
  ulong *puVar2;
  longlong lVar3;
  
  if (_FileHandle == -2) {
    puVar2 = __doserrno();
    *puVar2 = 0;
    puVar2 = __doserrno();
    *puVar2 = 9;
  }
  else {
    if ((-1 < _FileHandle) && ((uint)_FileHandle < DAT_18001d610)) {
      lVar3 = (ulonglong)(_FileHandle & 0x3f) * 0x40;
      if ((*(byte *)((&DAT_18001d210)[(longlong)_FileHandle >> 6] + 0x38 + lVar3) & 1) != 0) {
        FID_conflict___acrt_lowio_lock_fh(_FileHandle);
        iVar1 = -1;
        if ((*(byte *)((&DAT_18001d210)[(longlong)_FileHandle >> 6] + 0x38 + lVar3) & 1) == 0) {
          puVar2 = __doserrno();
          *puVar2 = 9;
          puVar2 = __doserrno();
          *puVar2 = 0;
        }
        else {
          iVar1 = _write_nolock(_FileHandle,_Buf,_MaxCharCount);
        }
        FID_conflict___acrt_lowio_lock_fh(_FileHandle);
        return iVar1;
      }
    }
    puVar2 = __doserrno();
    *puVar2 = 0;
    puVar2 = __doserrno();
    *puVar2 = 9;
    FUN_18000aff4();
  }
  return -1;
}



/* ---- _write_nolock @ 18000ffdc ---- */

/* Library Function - Single Match
    _write_nolock
   
   Library: Visual Studio 2015 Release */

int __cdecl _write_nolock(int _FileHandle,void *_Buf,uint _MaxCharCount)

{
  char cVar1;
  wchar_t _WCh;
  DWORD DVar2;
  wchar_t wVar3;
  wint_t wVar4;
  int iVar5;
  BOOL BVar6;
  ulong *puVar7;
  __acrt_ptd *p_Var8;
  undefined8 *puVar9;
  int iVar10;
  uint uVar11;
  longlong lVar12;
  longlong lVar13;
  wchar_t *pwVar14;
  DWORD local_68;
  DWORD DStack_64;
  int local_60;
  undefined8 local_58;
  longlong local_48;
  DWORD local_40 [2];
  
  iVar10 = 0;
  if (_MaxCharCount == 0) {
    return 0;
  }
  if (_Buf == (void *)0x0) {
LAB_18001000f:
    puVar7 = __doserrno();
    *puVar7 = 0;
    puVar7 = __doserrno();
    *puVar7 = 0x16;
    FUN_18000aff4();
    return -1;
  }
  lVar12 = (longlong)_FileHandle >> 6;
  lVar13 = (ulonglong)(_FileHandle & 0x3f) * 0x40;
  cVar1 = *(char *)((&DAT_18001d210)[lVar12] + 0x39 + lVar13);
  local_48 = lVar12;
  if (((byte)(cVar1 - 1U) < 2) && ((~_MaxCharCount & 1) == 0)) goto LAB_18001000f;
  if ((*(byte *)((&DAT_18001d210)[lVar12] + 0x38 + lVar13) & 0x20) != 0) {
    common_lseek_nolock<__int64>(_FileHandle,0,2);
  }
  local_58 = 0;
  iVar5 = _isatty(_FileHandle);
  uVar11 = (uint)_Buf;
  if ((((iVar5 == 0) || ((*(byte *)((&DAT_18001d210)[lVar12] + 0x38 + lVar13) & 0x80) == 0)) ||
      ((p_Var8 = FUN_18000b630(), *(longlong *)(*(longlong *)(p_Var8 + 0x90) + 0x138) == 0 &&
       (*(char *)((&DAT_18001d210)[lVar12] + 0x39 + lVar13) == '\0')))) ||
     (BVar6 = GetConsoleMode(*(HANDLE *)((&DAT_18001d210)[lVar12] + 0x28 + lVar13),local_40),
     BVar6 == 0)) {
    if ((*(byte *)((&DAT_18001d210)[lVar12] + 0x38 + lVar13) & 0x80) != 0) {
      if (cVar1 == '\0') {
        puVar9 = (undefined8 *)
                 write_text_ansi_nolock((int)&local_68,(char *)(ulonglong)(uint)_FileHandle,uVar11);
      }
      else if (cVar1 == '\x01') {
        puVar9 = (undefined8 *)
                 write_text_utf8_nolock((int)&local_68,(char *)(ulonglong)(uint)_FileHandle,uVar11);
      }
      else {
        if (cVar1 != '\x02') goto LAB_18001022c;
        puVar9 = (undefined8 *)
                 write_text_utf16le_nolock
                           ((int)&local_68,(char *)(ulonglong)(uint)_FileHandle,uVar11);
      }
      goto LAB_180010183;
    }
    local_68 = 0;
    DStack_64 = 0;
    local_60 = 0;
    BVar6 = WriteFile(*(HANDLE *)((&DAT_18001d210)[lVar12] + 0x28 + lVar13),_Buf,_MaxCharCount,
                      &DStack_64,(LPOVERLAPPED)0x0);
    iVar10 = local_60;
    if (BVar6 == 0) {
      local_68 = GetLastError();
      iVar10 = local_60;
    }
  }
  else {
    if (cVar1 == '\0') {
      puVar9 = (undefined8 *)
               write_double_translated_ansi_nolock
                         ((int)&local_68,(char *)(ulonglong)(uint)_FileHandle,uVar11);
LAB_180010183:
      local_58 = *puVar9;
      iVar10 = *(int *)(puVar9 + 1);
      goto LAB_18001022c;
    }
    if (1 < (byte)(cVar1 - 1U)) goto LAB_18001022c;
    local_68 = 0;
    DStack_64 = 0;
    iVar10 = 0;
    DVar2 = DStack_64;
    for (pwVar14 = _Buf; DStack_64 = DVar2,
        pwVar14 < (wchar_t *)((longlong)_Buf + (ulonglong)_MaxCharCount); pwVar14 = pwVar14 + 1) {
      _WCh = *pwVar14;
      wVar3 = _putwch_nolock(_WCh);
      if (wVar3 != _WCh) {
LAB_18001015f:
        local_68 = GetLastError();
        lVar12 = local_48;
        break;
      }
      DStack_64 = DVar2 + 2;
      if (_WCh == L'\n') {
        wVar4 = _putwch_nolock(L'\r');
        if (wVar4 != 0xd) goto LAB_18001015f;
        DStack_64 = DVar2 + 3;
        iVar10 = iVar10 + 1;
      }
      lVar12 = local_48;
      DVar2 = DStack_64;
    }
  }
  local_58 = CONCAT44(DStack_64,local_68);
LAB_18001022c:
  iVar5 = (int)((ulonglong)local_58 >> 0x20);
  if (iVar5 != 0) {
    return iVar5 - iVar10;
  }
  if ((int)local_58 != 0) {
    if ((int)local_58 == 5) {
      puVar7 = __doserrno();
      *puVar7 = 9;
      puVar7 = __doserrno();
      *puVar7 = 5;
      return -1;
    }
    __acrt_errno_map_os_error((int)local_58);
    return -1;
  }
  if (((*(byte *)((&DAT_18001d210)[lVar12] + 0x38 + lVar13) & 0x40) != 0) &&
     (*(char *)_Buf == '\x1a')) {
    return 0;
  }
  puVar7 = __doserrno();
  *puVar7 = 0x1c;
  puVar7 = __doserrno();
  *puVar7 = 0;
  return -1;
}



/* ---- FUN_1800102c0 @ 1800102c0 ---- */

void FUN_1800102c0(uint param_1,uint param_2)

{
  common_control87(param_1,param_2 & 0xfff7ffff);
  return;
}



/* ---- common_control87 @ 1800102cc ---- */

/* Library Function - Single Match
    common_control87
   
   Library: Visual Studio 2015 Release */

uint common_control87(uint param_1,uint param_2)

{
  uint uVar1;
  uint uVar2;
  uint uVar3;
  
  uVar1 = _get_fpsr();
  uVar2 = 0;
  if ((uVar1 & 0x80) != 0) {
    uVar2 = 0x10;
  }
  if ((uVar1 & 0x200) != 0) {
    uVar2 = uVar2 | 8;
  }
  if ((uVar1 >> 10 & 1) != 0) {
    uVar2 = uVar2 | 4;
  }
  if ((uVar1 & 0x800) != 0) {
    uVar2 = uVar2 | 2;
  }
  if ((uVar1 & 0x1000) != 0) {
    uVar2 = uVar2 | 1;
  }
  if ((uVar1 & 0x100) != 0) {
    uVar2 = uVar2 | 0x80000;
  }
  uVar3 = uVar1 & 0x6000;
  if (uVar3 != 0) {
    if (uVar3 == 0x2000) {
      uVar2 = uVar2 | 0x100;
    }
    else if (uVar3 == 0x4000) {
      uVar2 = uVar2 | 0x200;
    }
    else if (uVar3 == 0x6000) {
      uVar2 = uVar2 | 0x300;
    }
  }
  uVar1 = uVar1 & 0x8040;
  if (uVar1 == 0x40) {
    uVar2 = uVar2 | 0x2000000;
  }
  else if (uVar1 == 0x8000) {
    uVar2 = uVar2 | 0x3000000;
  }
  else if (uVar1 == 0x8040) {
    uVar2 = uVar2 | 0x1000000;
  }
  uVar1 = ~(param_2 & 0x308031f) & uVar2 | param_1 & param_2 & 0x308031f;
  if (uVar1 != uVar2) {
    uVar3 = 0;
    if ((uVar1 & 0x10) != 0) {
      uVar3 = 0x80;
    }
    if ((uVar1 & 8) != 0) {
      uVar3 = uVar3 | 0x200;
    }
    if ((uVar1 & 4) != 0) {
      uVar3 = uVar3 | 0x400;
    }
    if ((uVar1 & 2) != 0) {
      uVar3 = uVar3 | 0x800;
    }
    if ((uVar1 & 1) != 0) {
      uVar3 = uVar3 | 0x1000;
    }
    if ((uVar1 >> 0x13 & 1) != 0) {
      uVar3 = uVar3 | 0x100;
    }
    uVar2 = uVar1 & 0x300;
    if (uVar2 != 0) {
      if (uVar2 == 0x100) {
        uVar3 = uVar3 | 0x2000;
      }
      else if (uVar2 == 0x200) {
        uVar3 = uVar3 | 0x4000;
      }
      else if (uVar2 == 0x300) {
        uVar3 = uVar3 | 0x6000;
      }
    }
    uVar1 = uVar1 & 0x3000000;
    if (uVar1 == 0x1000000) {
      uVar3 = uVar3 | 0x8040;
    }
    else if (uVar1 == 0x2000000) {
      uVar3 = uVar3 | 0x40;
    }
    else if (uVar1 == 0x3000000) {
      uVar3 = uVar3 | 0x8000;
    }
    if ((DAT_18001c8c0 == '\0') || ((uVar3 & 0x40) == 0)) {
      uVar3 = uVar3 & 0xffffffbf;
      FUN_180010590(uVar3);
    }
    else {
      FUN_180010590(uVar3);
    }
    uVar2 = 0;
    if ((uVar3 & 0x80) != 0) {
      uVar2 = 0x10;
    }
    if ((uVar3 & 0x200) != 0) {
      uVar2 = uVar2 | 8;
    }
    if ((uVar3 >> 10 & 1) != 0) {
      uVar2 = uVar2 | 4;
    }
    if ((uVar3 >> 0xb & 1) != 0) {
      uVar2 = uVar2 | 2;
    }
    if ((uVar3 >> 0xc & 1) != 0) {
      uVar2 = uVar2 | 1;
    }
    if ((uVar3 & 0x100) != 0) {
      uVar2 = uVar2 | 0x80000;
    }
    uVar1 = uVar3 & 0x6000;
    if (uVar1 != 0) {
      if (uVar1 == 0x2000) {
        uVar2 = uVar2 | 0x100;
      }
      else if (uVar1 == 0x4000) {
        uVar2 = uVar2 | 0x200;
      }
      else if (uVar1 == 0x6000) {
        uVar2 = uVar2 | 0x300;
      }
    }
    uVar3 = uVar3 & 0x8040;
    if (uVar3 == 0x40) {
      uVar2 = uVar2 | 0x2000000;
    }
    else if (uVar3 == 0x8000) {
      uVar2 = uVar2 | 0x3000000;
    }
    else if (uVar3 == 0x8040) {
      uVar2 = uVar2 | 0x1000000;
    }
  }
  return uVar2;
}



/* ---- _get_fpsr @ 180010580 ---- */

/* Library Function - Single Match
    _get_fpsr
   
   Library: Visual Studio 2015 Release */

undefined4 _get_fpsr(void)

{
  return MXCSR;
}



/* ---- FUN_180010590 @ 180010590 ---- */

void FUN_180010590(undefined4 param_1)

{
  MXCSR = param_1;
  return;
}



/* ---- _fclrf @ 18001059a ---- */

/* Library Function - Single Match
    _fclrf
   
   Library: Visual Studio */

void _fclrf(void)

{
  MXCSR = MXCSR & 0xffffffc0;
  return;
}



/* ---- FUN_1800105d0 @ 1800105d0 ---- */

undefined4 FUN_1800105d0(void)

{
  return DAT_18001da7c;
}



/* ---- __strncnt @ 1800105d8 ---- */

/* Library Function - Single Match
    __strncnt
   
   Library: Visual Studio 2015 Release */

size_t __cdecl __strncnt(char *_String,size_t _Cnt)

{
  char cVar1;
  size_t sVar2;
  
  sVar2 = 0;
  cVar1 = *_String;
  while ((cVar1 != '\0' && (sVar2 != _Cnt))) {
    sVar2 = sVar2 + 1;
    cVar1 = _String[sVar2];
  }
  return sVar2;
}



/* ---- FUN_1800105f0 @ 1800105f0 ---- */

/* WARNING: Globals starting with '_' overlap smaller symbols at the same address */

double FUN_1800105f0(void)

{
  undefined1 auVar1 [16];
  undefined1 auVar2 [16];
  undefined1 auVar3 [16];
  undefined1 auVar4 [16];
  undefined1 auVar5 [16];
  undefined1 auVar6 [16];
  ulonglong uVar7;
  ulonglong uVar8;
  double dVar9;
  undefined1 auVar10 [16];
  undefined1 auVar11 [16];
  undefined1 in_ZMM0 [64];
  double dVar12;
  double dVar13;
  double dVar14;
  undefined1 auVar15 [16];
  double dVar16;
  undefined1 auVar17 [16];
  undefined1 auVar18 [16];
  undefined1 auVar19 [16];
  double dVar20;
  
  dVar9 = in_ZMM0._0_8_;
  auVar10 = in_ZMM0._0_16_;
  if (DAT_18001da84 == 0) {
    if ((double)((ulonglong)dVar9 & (ulonglong)DAT_1800183d0) == DAT_1800183d0) {
      if (dVar9 == DAT_1800183d0) {
        return dVar9;
      }
      if (dVar9 != DAT_1800183c0) {
        return (double)((ulonglong)dVar9 | _DAT_1800183f0);
      }
    }
    else {
      dVar20 = (double)(int)(((ulonglong)dVar9 >> 0x34) - _DAT_180018400);
      if (0.0 < dVar9) {
        dVar13 = (double)((ulonglong)dVar9 & (ulonglong)DAT_180018420);
        dVar12 = dVar9;
        if (dVar20 == DAT_180018540) {
          dVar20 = (double)((ulonglong)dVar13 | (ulonglong)DAT_1800184b0) - DAT_1800184b0;
          dVar12 = (double)((ulonglong)dVar20 & (ulonglong)DAT_180018420);
          dVar20 = (double)(int)((uint)((ulonglong)dVar20 >> 0x34) - _DAT_180018550);
          dVar13 = dVar12;
        }
        uVar7 = ((ulonglong)dVar12 & _DAT_180018430) + ((ulonglong)dVar12 & _DAT_180018440) * 2;
        if ((double)((ulonglong)(dVar9 - DAT_1800184b0) & _DAT_1800185a0) < DAT_180018560) {
          dVar9 = dVar9 - DAT_1800184b0;
          dVar20 = dVar9 / (DAT_1800184a0 + dVar9);
          dVar12 = dVar20 + dVar20;
          dVar13 = dVar12 * dVar12;
          dVar14 = dVar13 * dVar12;
          dVar16 = (double)((ulonglong)dVar9 & (ulonglong)DAT_1800185f0);
          dVar9 = (((DAT_1800185c0 * dVar13 + DAT_1800185b0) * dVar14 +
                   (DAT_1800185e0 * dVar13 + DAT_1800185d0) * dVar14 * dVar14 * dVar12) -
                  dVar9 * dVar20) + (dVar9 - dVar16);
          return dVar16 * DAT_180018470 + dVar9 * DAT_180018470 + dVar9 * DAT_180018460 +
                 dVar16 * DAT_180018460;
        }
        uVar8 = uVar7 >> 0x2c;
        dVar12 = ((double)(uVar7 | (ulonglong)DAT_1800184c0) -
                 (double)((ulonglong)dVar13 | (ulonglong)DAT_1800184c0)) *
                 *(double *)(&DAT_180019630 + uVar8 * 8);
        dVar9 = dVar12 * dVar12;
        return *(double *)(&DAT_180018610 + uVar8 * 8) + DAT_180018480 * dVar20 +
               *(double *)(&DAT_180018e20 + uVar8 * 8) +
               (DAT_180018490 * dVar20 -
               ((DAT_180018500 * dVar12 + _DAT_1800184f0) * dVar9 + dVar12 +
               ((DAT_180018530 * dVar12 + DAT_180018520) * dVar12 + DAT_180018510) * dVar9 * dVar9)
               * DAT_180018450);
      }
      if (dVar9 == 0.0) {
        dVar9 = (double)FUN_180011170(dVar9,DAT_1800183c0,DAT_180018600);
        return dVar9;
      }
    }
    dVar9 = (double)FUN_180011170(dVar9,DAT_1800183e0,DAT_180018604);
    return dVar9;
  }
  auVar17 = vpsrlq_avx(auVar10,0x34);
  auVar1._8_8_ = _UNK_180018408;
  auVar1._0_8_ = _DAT_180018400;
  auVar17 = vpsubq_avx(auVar17,auVar1);
  auVar17 = vcvtdq2pd_avx(auVar17);
  dVar20 = auVar17._0_8_;
  auVar17._8_8_ = _UNK_1800183d8;
  auVar17._0_8_ = DAT_1800183d0;
  auVar17 = vpand_avx(auVar10,auVar17);
  if (auVar17._0_8_ == DAT_1800183d0) {
    if (dVar9 != DAT_1800183d0) {
      if (dVar9 == DAT_1800183c0) goto LAB_180010b40;
      dVar9 = (double)FUN_180011170(dVar9,(ulonglong)dVar9 | _DAT_1800183f0,DAT_180018608);
    }
    return dVar9;
  }
  if (0.0 < dVar9) {
    auVar17 = vpand_avx(auVar10,_DAT_180018420);
    if (dVar20 == DAT_180018540) {
      auVar10._8_8_ = _UNK_1800184b8;
      auVar10._0_8_ = DAT_1800184b0;
      auVar10 = vpor_avx(auVar17,auVar10);
      auVar15._8_8_ = 0;
      auVar15._0_8_ = auVar10._0_8_ - DAT_1800184b0;
      auVar17 = vpsrlq_avx(auVar15,0x34);
      auVar10 = vpand_avx(auVar15,_DAT_180018420);
      auVar18._4_12_ = _UNK_180018554;
      auVar18._0_4_ = _DAT_180018550;
      auVar17 = vpsubd_avx(auVar17,auVar18);
      auVar17 = vcvtdq2pd_avx(auVar17);
      dVar20 = auVar17._0_8_;
      auVar17 = auVar10;
    }
    auVar2._8_8_ = _UNK_180018438;
    auVar2._0_8_ = _DAT_180018430;
    auVar1 = vpand_avx(auVar10,auVar2);
    auVar3._8_8_ = _UNK_180018448;
    auVar3._0_8_ = _DAT_180018440;
    auVar18 = vpand_avx(auVar10,auVar3);
    auVar18 = vpsllq_avx(auVar18,1);
    auVar1 = vpaddq_avx(auVar18,auVar1);
    auVar19._8_8_ = 0;
    auVar19._0_8_ = dVar9 - DAT_1800184b0;
    auVar6._8_8_ = _UNK_1800185a8;
    auVar6._0_8_ = _DAT_1800185a0;
    auVar18 = vpand_avx(auVar19,auVar6);
    if (auVar18._0_8_ < DAT_180018560) {
      dVar13 = auVar10._0_8_ - DAT_1800184b0;
      dVar14 = dVar13 / (DAT_1800184a0 + dVar13);
      dVar9 = dVar14 + dVar14;
      dVar20 = dVar9 * dVar9;
      dVar12 = dVar20 * dVar9;
      auVar11._8_8_ = 0;
      auVar11._0_8_ = dVar13;
      auVar10 = vpand_avx(auVar11,_DAT_1800185f0);
      dVar16 = auVar10._0_8_;
      dVar9 = (((dVar20 * DAT_1800185c0 + DAT_1800185b0) * dVar12 +
               (dVar20 * DAT_1800185e0 + DAT_1800185d0) * dVar12 * dVar12 * dVar9) - dVar13 * dVar14
              ) + (dVar13 - dVar16);
      return dVar16 * DAT_180018470 + dVar9 * DAT_180018470 + dVar9 * DAT_180018460 +
             dVar16 * DAT_180018460;
    }
    uVar7 = auVar1._0_8_ >> 0x2c;
    auVar4._8_8_ = _UNK_1800184c8;
    auVar4._0_8_ = DAT_1800184c0;
    auVar10 = vpor_avx(auVar17,auVar4);
    auVar5._8_8_ = _UNK_1800184c8;
    auVar5._0_8_ = DAT_1800184c0;
    auVar17 = vpor_avx(auVar1,auVar5);
    dVar9 = (auVar17._0_8_ - auVar10._0_8_) * *(double *)(&DAT_180019630 + uVar7 * 8);
    dVar12 = dVar9 * dVar9;
    return dVar20 * DAT_180018480 + *(double *)(&DAT_180018610 + uVar7 * 8) +
           *(double *)(&DAT_180018e20 + uVar7 * 8) +
           (dVar20 * DAT_180018490 -
           ((dVar9 * (dVar9 * DAT_180018530 + DAT_180018520) + DAT_180018510) * dVar12 * dVar12 +
           (dVar9 * DAT_180018500 + DAT_1800184c0) * dVar12 + dVar9) * DAT_180018450);
  }
  if (dVar9 == 0.0) {
    dVar9 = (double)FUN_180011170(dVar9,DAT_1800183c0,DAT_180018600);
    return dVar9;
  }
LAB_180010b40:
  dVar9 = (double)FUN_180011170(dVar9,DAT_1800183e0,DAT_180018604);
  return dVar9;
}



/* ---- common_lseek_nolock<__int64> @ 180010b9c ---- */

/* Library Function - Single Match
    __int64 __cdecl common_lseek_nolock<__int64>(int,__int64,int)
   
   Library: Visual Studio 2015 Release */

__int64 __cdecl common_lseek_nolock<__int64>(int param_1,__int64 param_2,int param_3)

{
  byte *pbVar1;
  BOOL BVar2;
  DWORD DVar3;
  HANDLE hFile;
  ulong *puVar4;
  LARGE_INTEGER local_res20;
  
  hFile = (HANDLE)_get_osfhandle(param_1);
  if (hFile == (HANDLE)0xffffffffffffffff) {
    puVar4 = __doserrno();
    *puVar4 = 9;
  }
  else {
    BVar2 = SetFilePointerEx(hFile,(LARGE_INTEGER)param_2,&local_res20,param_3);
    if (BVar2 == 0) {
      DVar3 = GetLastError();
      __acrt_errno_map_os_error(DVar3);
    }
    else if (local_res20.QuadPart != -1) {
      pbVar1 = (byte *)((&DAT_18001d210)[(longlong)param_1 >> 6] + 0x38 +
                       (ulonglong)(param_1 & 0x3f) * 0x40);
      *pbVar1 = *pbVar1 & 0xfd;
      return (__int64)local_res20.s;
    }
  }
  return -1;
}



/* ---- common_lseek_nolock<__int64> @ 180010c38 ---- */

__int64 __cdecl common_lseek_nolock<__int64>(int param_1,__int64 param_2,int param_3)

{
  byte *pbVar1;
  BOOL BVar2;
  DWORD DVar3;
  HANDLE hFile;
  ulong *puVar4;
  LARGE_INTEGER LStackX_20;
  
  hFile = (HANDLE)_get_osfhandle(param_1);
  if (hFile == (HANDLE)0xffffffffffffffff) {
    puVar4 = __doserrno();
    *puVar4 = 9;
  }
  else {
    BVar2 = SetFilePointerEx(hFile,(LARGE_INTEGER)param_2,&LStackX_20,param_3);
    if (BVar2 == 0) {
      DVar3 = GetLastError();
      __acrt_errno_map_os_error(DVar3);
    }
    else if (LStackX_20.QuadPart != -1) {
      pbVar1 = (byte *)((&DAT_18001d210)[(longlong)param_1 >> 6] + 0x38 +
                       (ulonglong)(param_1 & 0x3f) * 0x40);
      *pbVar1 = *pbVar1 & 0xfd;
      return (__int64)LStackX_20.s;
    }
  }
  return -1;
}



/* ---- operator()<<lambda_bfedae4ebbf01fab1bb6dcc6a9e276e0>,<lambda_2fe9b910cf3cbf4a0ab98a02ba45b3ec>&___ptr64,<lambda_237c231691f317818eb88cc1d5d642d6>_> @ 180010c40 ---- */

/* Library Function - Single Match
    public: int __cdecl __crt_seh_guarded_call<int>::operator()<class
   <lambda_bfedae4ebbf01fab1bb6dcc6a9e276e0>,class <lambda_2fe9b910cf3cbf4a0ab98a02ba45b3ec> &
   __ptr64,class <lambda_237c231691f317818eb88cc1d5d642d6> >(class
   <lambda_bfedae4ebbf01fab1bb6dcc6a9e276e0> && __ptr64,class
   <lambda_2fe9b910cf3cbf4a0ab98a02ba45b3ec> & __ptr64,class
   <lambda_237c231691f317818eb88cc1d5d642d6> && __ptr64) __ptr64
   
   Library: Visual Studio 2015 Release */

int __thiscall
__crt_seh_guarded_call<int>::
operator()<<lambda_bfedae4ebbf01fab1bb6dcc6a9e276e0>,<lambda_2fe9b910cf3cbf4a0ab98a02ba45b3ec>&___ptr64,<lambda_237c231691f317818eb88cc1d5d642d6>_>
          (__crt_seh_guarded_call<int> *this,<lambda_bfedae4ebbf01fab1bb6dcc6a9e276e0> *param_1,
          <lambda_2fe9b910cf3cbf4a0ab98a02ba45b3ec> *param_2,
          <lambda_237c231691f317818eb88cc1d5d642d6> *param_3)

{
  uint _FileHandle;
  int iVar1;
  ulong *puVar2;
  
  FID_conflict___acrt_lowio_lock_fh(*(uint *)param_1);
  _FileHandle = **(uint **)param_2;
  if ((*(byte *)((&DAT_18001d210)[(longlong)(int)_FileHandle >> 6] + 0x38 +
                (ulonglong)(_FileHandle & 0x3f) * 0x40) & 1) == 0) {
    puVar2 = __doserrno();
    *puVar2 = 9;
    iVar1 = -1;
  }
  else {
    iVar1 = _close_nolock(_FileHandle);
  }
  FID_conflict___acrt_lowio_lock_fh(*(uint *)param_3);
  return iVar1;
}



/* ---- _close @ 180010cb4 ---- */

/* Library Function - Single Match
    _close
   
   Library: Visual Studio 2015 Release */

int __cdecl _close(int _FileHandle)

{
  int iVar1;
  ulong *puVar2;
  int local_res8 [2];
  __crt_seh_guarded_call<int> local_res10 [8];
  int local_res18 [2];
  int local_res20 [2];
  int *local_18 [3];
  
  local_res8[0] = _FileHandle;
  if (_FileHandle == -2) {
    puVar2 = __doserrno();
    *puVar2 = 0;
    puVar2 = __doserrno();
    *puVar2 = 9;
  }
  else {
    if (((-1 < _FileHandle) && ((uint)_FileHandle < DAT_18001d610)) &&
       ((*(byte *)((&DAT_18001d210)[(longlong)_FileHandle >> 6] + 0x38 +
                  (ulonglong)(_FileHandle & 0x3f) * 0x40) & 1) != 0)) {
      local_18[0] = local_res8;
      local_res18[0] = _FileHandle;
      local_res20[0] = _FileHandle;
      iVar1 = __crt_seh_guarded_call<int>::
              operator()<<lambda_bfedae4ebbf01fab1bb6dcc6a9e276e0>,<lambda_2fe9b910cf3cbf4a0ab98a02ba45b3ec>&___ptr64,<lambda_237c231691f317818eb88cc1d5d642d6>_>
                        (local_res10,(<lambda_bfedae4ebbf01fab1bb6dcc6a9e276e0> *)local_res20,
                         (<lambda_2fe9b910cf3cbf4a0ab98a02ba45b3ec> *)local_18,
                         (<lambda_237c231691f317818eb88cc1d5d642d6> *)local_res18);
      return iVar1;
    }
    puVar2 = __doserrno();
    *puVar2 = 0;
    puVar2 = __doserrno();
    *puVar2 = 9;
    FUN_18000aff4();
  }
  return -1;
}



/* ---- _close_nolock @ 180010d58 ---- */

/* Library Function - Single Match
    _close_nolock
   
   Library: Visual Studio 2015 Release */

int __cdecl _close_nolock(int _FileHandle)

{
  BOOL BVar1;
  DWORD DVar2;
  int iVar3;
  intptr_t iVar4;
  intptr_t iVar5;
  HANDLE hObject;
  
  iVar4 = _get_osfhandle(_FileHandle);
  if (iVar4 != -1) {
    if (((_FileHandle == 1) && ((*(byte *)(DAT_18001d210 + 0xb8) & 1) != 0)) ||
       ((_FileHandle == 2 && ((*(byte *)(DAT_18001d210 + 0x78) & 1) != 0)))) {
      iVar4 = _get_osfhandle(2);
      iVar5 = _get_osfhandle(1);
      if (iVar5 == iVar4) goto LAB_180010d72;
    }
    hObject = (HANDLE)_get_osfhandle(_FileHandle);
    BVar1 = CloseHandle(hObject);
    if (BVar1 == 0) {
      DVar2 = GetLastError();
      goto LAB_180010dcd;
    }
  }
LAB_180010d72:
  DVar2 = 0;
LAB_180010dcd:
  _free_osfhnd(_FileHandle);
  *(undefined1 *)
   ((&DAT_18001d210)[(longlong)_FileHandle >> 6] + 0x38 + (ulonglong)(_FileHandle & 0x3f) * 0x40) =
       0;
  if (DVar2 == 0) {
    iVar3 = 0;
  }
  else {
    __acrt_errno_map_os_error(DVar2);
    iVar3 = -1;
  }
  return iVar3;
}



/* ---- __acrt_stdio_free_stream @ 180010e14 ---- */

/* Library Function - Single Match
    void __cdecl __acrt_stdio_free_stream(class __crt_stdio_stream)
   
   Library: Visual Studio 2015 Release */

void __cdecl __acrt_stdio_free_stream(undefined8 *param_1)

{
  *param_1 = 0;
  param_1[1] = 0;
  *(undefined4 *)(param_1 + 2) = 0;
  *(undefined4 *)(param_1 + 3) = 0xffffffff;
  *(undefined4 *)((longlong)param_1 + 0x1c) = 0;
  *(undefined4 *)(param_1 + 4) = 0;
  param_1[5] = 0;
  LOCK();
  *(undefined4 *)((longlong)param_1 + 0x14) = 0;
  UNLOCK();
  return;
}



/* ---- _putwch_nolock @ 180010e58 ---- */

/* Library Function - Single Match
    _putwch_nolock
   
   Library: Visual Studio 2015 Release */

wint_t __cdecl _putwch_nolock(wchar_t _WCh)

{
  BOOL BVar1;
  wchar_t local_res8 [4];
  DWORD local_res10 [6];
  
  local_res8[0] = _WCh;
  if (DAT_18001c8d0 == (HANDLE)0xfffffffffffffffe) {
    __dcrt_lowio_initialize_console_output();
  }
  if ((DAT_18001c8d0 == (HANDLE)0xffffffffffffffff) ||
     (BVar1 = WriteConsoleW(DAT_18001c8d0,local_res8,1,local_res10,(LPVOID)0x0), BVar1 == 0)) {
    local_res8[0] = L'\xffff';
  }
  return local_res8[0];
}



/* ---- FUN_180010eb4 @ 180010eb4 ---- */

undefined8
FUN_180010eb4(int param_1,undefined8 param_2,undefined8 param_3,undefined8 param_4,
             undefined8 param_5,undefined8 param_6,uint param_7)

{
  undefined8 uVar1;
  int local_38 [2];
  undefined8 local_30;
  undefined8 local_28;
  undefined8 local_20;
  undefined8 local_18;
  
  local_20 = param_5;
  local_18 = param_6;
  local_38[0] = param_1;
  local_30 = param_3;
  local_28 = param_4;
  _ctrlfp(param_7,0xffc0);
  uVar1 = __acrt_invoke_user_matherr(local_38);
  if ((int)uVar1 == 0) {
    _set_errno_from_matherr(param_1);
  }
  return local_18;
}



/* ---- _exception_enabled @ 180010f1c ---- */

/* Library Function - Single Match
    _exception_enabled
   
   Library: Visual Studio 2015 Release */

bool _exception_enabled(uint param_1,ulonglong param_2)

{
  uint uVar1;
  
  uVar1 = param_1 & 0x1f;
  if (((param_1 & 8) == 0) || (-1 < (char)param_2)) {
    if (((param_1 & 4) == 0) || ((param_2 & 0x200) == 0)) {
      if (((param_1 & 1) == 0) || ((param_2 & 0x400) == 0)) {
        if (((param_1 & 2) != 0) && ((param_2 & 0x800) != 0)) {
          if ((param_1 & 0x10) != 0) {
            _set_statfp(0x10);
          }
          uVar1 = param_1 & 0x1d;
        }
      }
      else {
        _set_statfp(8);
        uVar1 = param_1 & 0x1e;
      }
    }
    else {
      _set_statfp(4);
      uVar1 = param_1 & 0x1b;
    }
  }
  else {
    _set_statfp(1);
    uVar1 = param_1 & 0x17;
  }
  if (((param_1 & 0x10) != 0) && ((param_2 >> 0xc & 1) != 0)) {
    _set_statfp(0x20);
    uVar1 = uVar1 & 0xffffffef;
  }
  return uVar1 == 0;
}



/* ---- FUN_180010fd8 @ 180010fd8 ---- */

/* WARNING: Function: __security_check_cookie replaced with injection: security_check_cookie */

undefined8
FUN_180010fd8(undefined8 param_1,uint param_2,undefined8 param_3,int param_4,uint param_5,
             uint param_6,undefined8 param_7,undefined8 param_8,int param_9)

{
  undefined8 uVar1;
  bool bVar2;
  uint uVar3;
  undefined4 extraout_var_00;
  undefined7 extraout_var;
  undefined1 auStackY_118 [32];
  ulonglong local_d8;
  undefined8 local_d0;
  undefined8 local_c8;
  uint local_b8 [12];
  undefined8 local_88;
  uint local_78;
  ulonglong local_48;
  
  local_48 = DAT_18001c000 ^ (ulonglong)auStackY_118;
  uVar3 = _ctrlfp(0x1f80,0xffc0);
  local_d8 = CONCAT44(extraout_var_00,uVar3);
  local_d0 = param_3;
  local_c8 = param_3;
  bVar2 = _exception_enabled(param_5,local_d8);
  uVar1 = param_8;
  if ((int)CONCAT71(extraout_var,bVar2) == 0) {
    if (param_9 == 2) {
      local_88 = param_8;
      local_78 = local_78 & 0xffffffe3 | 3;
    }
    _raise_exc(local_b8,&local_d8,(ulonglong)param_5,param_2,(uint *)&param_7,(uint *)&local_d0);
  }
  bVar2 = FUN_18000dca4();
  if ((bVar2) && (param_4 != 0)) {
    local_d0 = FUN_180010eb4(param_4,(ulonglong)param_6,param_1,param_7,uVar1,local_d0,
                             (uint)local_d8);
  }
  else {
    _set_errno_from_matherr(param_4);
    _ctrlfp((uint)local_d8,0xffc0);
  }
  return local_d0;
}



/* ---- __acrt_initialize_fma3 @ 180011100 ---- */

/* WARNING: Removing unreachable block (ram,0x000180011119) */
/* Library Function - Single Match
    __acrt_initialize_fma3
   
   Libraries: Visual Studio 2015 Release, Visual Studio 2017 Release, Visual Studio 2019 Release */

undefined8 __acrt_initialize_fma3(void)

{
  longlong lVar1;
  undefined8 uVar2;
  byte in_XCR0;
  
  DAT_18001da80 = 0;
  lVar1 = cpuid_Version_info(1);
  if ((*(uint *)(lVar1 + 0xc) & 0x18001000) == 0x18001000) {
    uVar2 = xinuse(0);
    DAT_18001da80 = (uint)((in_XCR0 & (byte)uVar2 & 6) == 6);
  }
  DAT_18001da84 = DAT_18001da80;
  return 0;
}



/* ---- FUN_180011170 @ 180011170 ---- */

void FUN_180011170(undefined8 param_1,undefined8 param_2,int param_3)

{
  FUN_180011190(param_1,param_2,param_3,0x1b,"log10");
  return;
}



/* ---- FUN_180011190 @ 180011190 ---- */

undefined8
FUN_180011190(undefined8 param_1,undefined8 param_2,int param_3,uint param_4,undefined8 param_5)

{
  int iVar1;
  uint uVar2;
  uint uVar3;
  
  if (param_3 == 1) {
    iVar1 = 2;
    uVar3 = 0x22;
    uVar2 = 4;
  }
  else {
    if (param_3 != 2) {
      return param_2;
    }
    uVar3 = 0x21;
    uVar2 = 8;
    iVar1 = 1;
  }
  FUN_180010fd8(param_5,param_4,param_2,iVar1,uVar2,uVar3,param_1,0,1);
  return param_2;
}



/* ---- __dcrt_lowio_initialize_console_output @ 180011228 ---- */

/* Library Function - Single Match
    __dcrt_lowio_initialize_console_output
   
   Libraries: Visual Studio 2015 Debug, Visual Studio 2015 Release */

void __dcrt_lowio_initialize_console_output(void)

{
  DAT_18001c8d0 = CreateFileW(L"CONOUT$",0x40000000,3,(LPSECURITY_ATTRIBUTES)0x0,3,0,(HANDLE)0x0);
  return;
}



/* ---- FUN_180011264 @ 180011264 ---- */

void FUN_180011264(void)

{
  if (1 < (longlong)DAT_18001c8d0 + 2U) {
    CloseHandle(DAT_18001c8d0);
  }
  return;
}



/* ---- _raise_exc @ 180011284 ---- */

/* Library Function - Single Match
    _raise_exc
   
   Library: Visual Studio 2015 Release */

void _raise_exc(uint *param_1,ulonglong *param_2,ulonglong param_3,uint param_4,uint *param_5,
               uint *param_6)

{
  _raise_exc_ex(param_1,param_2,param_3,param_4,param_5,param_6,0);
  return;
}



/* ---- _raise_exc_ex @ 1800112ac ---- */

/* Library Function - Single Match
    _raise_exc_ex
   
   Library: Visual Studio 2015 Release */

void _raise_exc_ex(uint *param_1,ulonglong *param_2,ulonglong param_3,uint param_4,uint *param_5,
                  uint *param_6,int param_7)

{
  uint uVar1;
  DWORD dwExceptionCode;
  uint *local_res8;
  
  dwExceptionCode = 0xc000000d;
  param_1[1] = 0;
  param_1[2] = 0;
  param_1[3] = 0;
  if ((param_3 & 0x10) != 0) {
    dwExceptionCode = 0xc000008f;
    param_1[1] = param_1[1] | 1;
  }
  if ((param_3 & 2) != 0) {
    dwExceptionCode = 0xc0000093;
    param_1[1] = param_1[1] | 2;
  }
  if ((param_3 & 1) != 0) {
    dwExceptionCode = 0xc0000091;
    param_1[1] = param_1[1] | 4;
  }
  if ((param_3 & 4) != 0) {
    dwExceptionCode = 0xc000008e;
    param_1[1] = param_1[1] | 8;
  }
  if ((param_3 & 8) != 0) {
    dwExceptionCode = 0xc0000090;
    param_1[1] = param_1[1] | 0x10;
  }
  param_1[2] = param_1[2] ^ (~((int)(*param_2 >> 7) << 4) ^ param_1[2]) & 0x10;
  param_1[2] = param_1[2] ^ (~((int)(*param_2 >> 9) << 3) ^ param_1[2]) & 8;
  param_1[2] = param_1[2] ^ (~((int)(*param_2 >> 10) << 2) ^ param_1[2]) & 4;
  param_1[2] = param_1[2] ^ (~((int)(*param_2 >> 0xb) * 2) ^ param_1[2]) & 2;
  param_1[2] = param_1[2] ^ (~((uint)*param_2 >> 0xc) ^ param_1[2]) & 1;
  local_res8 = param_1;
  uVar1 = _statfp();
  if ((uVar1 & 1) != 0) {
    local_res8[3] = local_res8[3] | 0x10;
  }
  if ((uVar1 & 4) != 0) {
    local_res8[3] = local_res8[3] | 8;
  }
  if ((uVar1 & 8) != 0) {
    local_res8[3] = local_res8[3] | 4;
  }
  if ((uVar1 & 0x10) != 0) {
    local_res8[3] = local_res8[3] | 2;
  }
  if ((uVar1 & 0x20) != 0) {
    local_res8[3] = local_res8[3] | 1;
  }
  uVar1 = (uint)*param_2 & 0x6000;
  if (((uint)*param_2 & 0x6000) == 0) {
    *local_res8 = *local_res8 & 0xfffffffc;
  }
  else if (uVar1 == 0x2000) {
    *local_res8 = *local_res8 & 0xfffffffd;
    *local_res8 = *local_res8 | 1;
  }
  else if (uVar1 == 0x4000) {
    *local_res8 = *local_res8 & 0xfffffffe;
    *local_res8 = *local_res8 | 2;
  }
  else if (uVar1 == 0x6000) {
    *local_res8 = *local_res8 | 3;
  }
  *local_res8 = *local_res8 & 0xfffe001f;
  *local_res8 = *local_res8 | (param_4 & 0xfff) << 5;
  local_res8[8] = local_res8[8] | 1;
  if (param_7 == 0) {
    local_res8[8] = local_res8[8] & 0xffffffe3 | 2;
    *(undefined8 *)(local_res8 + 4) = *(undefined8 *)param_5;
    local_res8[0x18] = local_res8[0x18] | 1;
    local_res8[0x18] = local_res8[0x18] & 0xffffffe3 | 2;
    *(undefined8 *)(local_res8 + 0x14) = *(undefined8 *)param_6;
  }
  else {
    local_res8[8] = local_res8[8] & 0xffffffe1;
    local_res8[4] = *param_5;
    local_res8[0x18] = local_res8[0x18] | 1;
    local_res8[0x18] = local_res8[0x18] & 0xffffffe1;
    local_res8[0x14] = *param_6;
  }
  _clrfp();
  RaiseException(dwExceptionCode,0,1,(ULONG_PTR *)&local_res8);
  if ((local_res8[2] & 0x10) != 0) {
    *param_2 = *param_2 & 0xffffffffffffff7f;
  }
  if ((local_res8[2] & 8) != 0) {
    *param_2 = *param_2 & 0xfffffffffffffdff;
  }
  if ((local_res8[2] & 4) != 0) {
    *param_2 = *param_2 & 0xfffffffffffffbff;
  }
  if ((local_res8[2] & 2) != 0) {
    *param_2 = *param_2 & 0xfffffffffffff7ff;
  }
  if ((local_res8[2] & 1) != 0) {
    *param_2 = *param_2 & 0xffffffffffffefff;
  }
  uVar1 = *local_res8 & 3;
  if (uVar1 == 0) {
    *param_2 = *param_2 & 0xffffffffffff9fff;
  }
  else if (uVar1 == 1) {
    *param_2 = *param_2 & 0xffffffffffffbfff;
    *param_2 = *param_2 | 0x2000;
  }
  else if (uVar1 == 2) {
    *param_2 = *param_2 & 0xffffffffffffdfff;
    *param_2 = *param_2 | 0x4000;
  }
  else if (uVar1 == 3) {
    *param_2 = *param_2 | 0x6000;
  }
  if (param_7 == 0) {
    *(undefined8 *)param_6 = *(undefined8 *)(local_res8 + 0x14);
  }
  else {
    *param_6 = local_res8[0x14];
  }
  return;
}



/* ---- _set_errno_from_matherr @ 1800115b4 ---- */

/* Library Function - Single Match
    _set_errno_from_matherr
   
   Libraries: Visual Studio 2012 Release, Visual Studio 2015 Release, Visual Studio 2017 Release,
   Visual Studio 2019 Release */

void _set_errno_from_matherr(int param_1)

{
  ulong *puVar1;
  
  if (param_1 == 1) {
    puVar1 = __doserrno();
    *puVar1 = 0x21;
  }
  else if (param_1 - 2U < 2) {
    puVar1 = __doserrno();
    *puVar1 = 0x22;
  }
  return;
}



/* ---- _clrfp @ 1800115e4 ---- */

/* Library Function - Single Match
    _clrfp
   
   Library: Visual Studio 2015 Release */

uint _clrfp(void)

{
  uint uVar1;
  
  uVar1 = _get_fpsr();
  _fclrf();
  return uVar1 & 0x3f;
}



/* ---- _ctrlfp @ 180011604 ---- */

/* Library Function - Single Match
    _ctrlfp
   
   Libraries: Visual Studio 2010 Release, Visual Studio 2012 Release, Visual Studio 2015 Release,
   Visual Studio 2019 Release */

uint _ctrlfp(uint param_1,uint param_2)

{
  uint uVar1;
  uint uVar2;
  
  uVar1 = _get_fpsr();
  uVar2 = (~param_2 | 0xffff807f) & uVar1 | param_1 & param_2;
  if ((DAT_18001c8d8 == '\0') || ((uVar2 & 0x40) == 0)) {
    FUN_180010590(uVar2 & 0xffffffbf);
  }
  else {
    FUN_180010590(uVar2);
  }
  return uVar1;
}



/* ---- _set_statfp @ 180011680 ---- */

/* Library Function - Single Match
    _set_statfp
   
   Library: Visual Studio 2015 Release */

void _set_statfp(uint param_1)

{
  uint uVar1;
  
  uVar1 = _get_fpsr();
  FUN_180010590(uVar1 | param_1 & 0x3f);
  return;
}



/* ---- _statfp @ 1800116a0 ---- */

/* Library Function - Single Match
    _statfp
   
   Library: Visual Studio 2015 Release */

uint _statfp(void)

{
  uint uVar1;
  
  uVar1 = _get_fpsr();
  return uVar1 & 0x3f;
}



/* ---- IsProcessorFeaturePresent @ 1800116b2 ---- */

BOOL __stdcall IsProcessorFeaturePresent(DWORD ProcessorFeature)

{
  BOOL BVar1;
  
                    /* WARNING: Could not recover jumptable at 0x0001800116b2. Too many branches */
                    /* WARNING: Treating indirect jump as call */
  BVar1 = IsProcessorFeaturePresent(ProcessorFeature);
  return BVar1;
}



/* ---- RtlUnwindEx @ 1800116b8 ---- */

void __stdcall
RtlUnwindEx(PVOID TargetFrame,PVOID TargetIp,PEXCEPTION_RECORD ExceptionRecord,PVOID ReturnValue,
           PCONTEXT ContextRecord,PUNWIND_HISTORY_TABLE HistoryTable)

{
                    /* WARNING: Could not recover jumptable at 0x0001800116b8. Too many branches */
                    /* WARNING: Treating indirect jump as call */
  RtlUnwindEx(TargetFrame,TargetIp,ExceptionRecord,ReturnValue,ContextRecord,HistoryTable);
  return;
}



/* ---- _FindPESection @ 1800116c0 ---- */

/* Library Function - Single Match
    _FindPESection
   
   Libraries: Visual Studio 2015 Release, Visual Studio 2017 Release, Visual Studio 2019 Release */

PIMAGE_SECTION_HEADER __cdecl _FindPESection(PBYTE pImageBase,DWORD_PTR rva)

{
  int iVar1;
  PIMAGE_SECTION_HEADER p_Var2;
  uint uVar3;
  
  iVar1 = *(int *)(pImageBase + 0x3c);
  uVar3 = 0;
  p_Var2 = (PIMAGE_SECTION_HEADER)
           (pImageBase +
           (ulonglong)*(ushort *)(pImageBase + (longlong)iVar1 + 0x14) + 0x18 + (longlong)iVar1);
  if (*(ushort *)(pImageBase + (longlong)iVar1 + 6) != 0) {
    do {
      if ((p_Var2->VirtualAddress <= rva) &&
         (rva < (p_Var2->Misc).PhysicalAddress + p_Var2->VirtualAddress)) {
        return p_Var2;
      }
      uVar3 = uVar3 + 1;
      p_Var2 = p_Var2 + 1;
    } while (uVar3 < *(ushort *)(pImageBase + (longlong)iVar1 + 6));
  }
  return (PIMAGE_SECTION_HEADER)0x0;
}



/* ---- _IsNonwritableInCurrentImage @ 180011710 ---- */

/* Library Function - Single Match
    _IsNonwritableInCurrentImage
   
   Library: Visual Studio 2015 Release */

BOOL __cdecl _IsNonwritableInCurrentImage(PBYTE pTarget)

{
  BOOL BVar1;
  uint uVar2;
  PIMAGE_SECTION_HEADER p_Var3;
  
  BVar1 = _ValidateImageBase((PBYTE)&IMAGE_DOS_HEADER_180000000);
  uVar2 = 0;
  if (BVar1 != 0) {
    p_Var3 = _FindPESection((PBYTE)&IMAGE_DOS_HEADER_180000000,(DWORD_PTR)(pTarget + -0x180000000));
    uVar2 = 0;
    if (p_Var3 != (PIMAGE_SECTION_HEADER)0x0) {
      uVar2 = ~(p_Var3->Characteristics >> 0x1f) & 1;
    }
  }
  return uVar2;
}



/* ---- _ValidateImageBase @ 180011760 ---- */

/* Library Function - Single Match
    _ValidateImageBase
   
   Library: Visual Studio 2015 Release */

BOOL __cdecl _ValidateImageBase(PBYTE pImageBase)

{
  uint uVar1;
  
  if (*(short *)pImageBase != 0x5a4d) {
    return 0;
  }
  uVar1 = 0;
  if (*(int *)(pImageBase + *(int *)(pImageBase + 0x3c)) == 0x4550) {
    uVar1 = (uint)((short)*(int *)((longlong)(pImageBase + *(int *)(pImageBase + 0x3c)) + 0x18) ==
                  0x20b);
  }
  return uVar1;
}



/* ---- memcmp @ 1800117a0 ---- */

/* Library Function - Single Match
    memcmp
   
   Library: Visual Studio */

int __cdecl memcmp(void *_Buf1,void *_Buf2,size_t _Size)

{
  uint uVar1;
  ulonglong uVar2;
  longlong lVar3;
  ulonglong uVar4;
  bool bVar5;
  
  lVar3 = (longlong)_Buf2 - (longlong)_Buf1;
  if (7 < _Size) {
    for (; ((ulonglong)_Buf1 & 7) != 0; _Buf1 = (void *)((longlong)_Buf1 + 1)) {
      bVar5 = (byte)*(ulonglong *)_Buf1 < *(byte *)(lVar3 + (longlong)_Buf1);
      if ((byte)*(ulonglong *)_Buf1 != *(byte *)(lVar3 + (longlong)_Buf1)) goto LAB_1800117e3;
      _Size = _Size - 1;
    }
    if (_Size >> 3 != 0) {
      uVar4 = _Size >> 5;
      if (uVar4 != 0) {
        do {
          uVar2 = *(ulonglong *)_Buf1;
          if (uVar2 != *(ulonglong *)(lVar3 + (longlong)_Buf1)) goto LAB_180011854;
          uVar2 = *(ulonglong *)((longlong)_Buf1 + 8);
          if (uVar2 != *(ulonglong *)(lVar3 + 8 + (longlong)_Buf1)) {
LAB_180011850:
            _Buf1 = (void *)((longlong)_Buf1 + 8);
            goto LAB_180011854;
          }
          uVar2 = *(ulonglong *)((longlong)_Buf1 + 0x10);
          if (uVar2 != *(ulonglong *)(lVar3 + 0x10 + (longlong)_Buf1)) {
LAB_18001184c:
            _Buf1 = (void *)((longlong)_Buf1 + 8);
            goto LAB_180011850;
          }
          uVar2 = *(ulonglong *)((longlong)_Buf1 + 0x18);
          if (uVar2 != *(ulonglong *)(lVar3 + 0x18 + (longlong)_Buf1)) {
            _Buf1 = (void *)((longlong)_Buf1 + 8);
            goto LAB_18001184c;
          }
          _Buf1 = (void *)((longlong)_Buf1 + 0x20);
          uVar4 = uVar4 - 1;
        } while (uVar4 != 0);
        _Size = _Size & 0x1f;
      }
      uVar4 = _Size >> 3;
      if (uVar4 != 0) {
        do {
          uVar2 = *(ulonglong *)_Buf1;
          if (uVar2 != *(ulonglong *)(lVar3 + (longlong)_Buf1)) {
LAB_180011854:
            uVar4 = *(ulonglong *)((longlong)_Buf1 + lVar3);
            uVar1 = (uint)((uVar2 >> 0x38 | (uVar2 & 0xff000000000000) >> 0x28 |
                            (uVar2 & 0xff0000000000) >> 0x18 | (uVar2 & 0xff00000000) >> 8 |
                            (uVar2 & 0xff000000) << 8 | (uVar2 & 0xff0000) << 0x18 |
                            (uVar2 & 0xff00) << 0x28 | uVar2 << 0x38) <
                          (uVar4 >> 0x38 | (uVar4 & 0xff000000000000) >> 0x28 |
                           (uVar4 & 0xff0000000000) >> 0x18 | (uVar4 & 0xff00000000) >> 8 |
                           (uVar4 & 0xff000000) << 8 | (uVar4 & 0xff0000) << 0x18 |
                           (uVar4 & 0xff00) << 0x28 | uVar4 << 0x38));
            return (1 - uVar1) - (uint)(uVar1 != 0);
          }
          _Buf1 = (void *)((longlong)_Buf1 + 8);
          uVar4 = uVar4 - 1;
        } while (uVar4 != 0);
        _Size = _Size & 7;
      }
    }
  }
  while( true ) {
    if (_Size == 0) {
      return 0;
    }
    bVar5 = (byte)*(ulonglong *)_Buf1 < *(byte *)(lVar3 + (longlong)_Buf1);
    if ((byte)*(ulonglong *)_Buf1 != *(byte *)(lVar3 + (longlong)_Buf1)) break;
    _Buf1 = (void *)((longlong)_Buf1 + 1);
    _Size = _Size - 1;
  }
LAB_1800117e3:
  return (1 - (uint)bVar5) - (uint)(bVar5 != 0);
}



/* ---- _guard_dispatch_icall @ 180011880 ---- */

/* WARNING: This is an inlined function */

void _guard_dispatch_icall(void)

{
  code *UNRECOVERED_JUMPTABLE;
  
                    /* WARNING: Could not recover jumptable at 0x000180011880. Too many branches */
                    /* WARNING: Treating indirect jump as call */
  (*UNRECOVERED_JUMPTABLE)();
  return;
}



/* ---- FUN_180011890 @ 180011890 ---- */

void FUN_180011890(undefined8 param_1,longlong param_2)

{
  __scrt_release_startup_lock(*(char *)(param_2 + 0x40));
  return;
}



/* ---- FUN_1800118a7 @ 1800118a7 ---- */

void FUN_1800118a7(undefined8 param_1,longlong param_2)

{
  FUN_1800026d8();
  __scrt_release_startup_lock(*(char *)(param_2 + 0x38));
  return;
}



/* ---- FUN_1800118c3 @ 1800118c3 ---- */

void FUN_1800118c3(undefined8 *param_1,longlong param_2)

{
  __scrt_dllmain_exception_filter
            (*(undefined8 *)(param_2 + 0x60),*(int *)(param_2 + 0x68),
             *(undefined8 *)(param_2 + 0x70),FUN_180001f54,*(int *)*param_1,param_1);
  return;
}



/* ---- FUN_1800118f9 @ 1800118f9 ---- */

bool FUN_1800118f9(undefined8 *param_1)

{
  return *(int *)*param_1 == -0x3ffffffb;
}



/* ---- FUN_180011911 @ 180011911 ---- */

void FUN_180011911(undefined8 *param_1)

{
  FUN_180009e1c(*(int *)*param_1);
  return;
}



/* ---- FUN_18001192c @ 18001192c ---- */

void FUN_18001192c(void)

{
  __acrt_unlock(2);
  return;
}



/* ---- FUN_180011945 @ 180011945 ---- */

void FUN_180011945(undefined8 param_1,longlong param_2)

{
  __acrt_unlock(**(int **)(param_2 + 0x88));
  return;
}



/* ---- FUN_180011962 @ 180011962 ---- */

void FUN_180011962(void)

{
  __acrt_unlock(5);
  return;
}



/* ---- FUN_18001197b @ 18001197b ---- */

void FUN_18001197b(void)

{
  __acrt_unlock(0);
  return;
}



/* ---- FUN_180011991 @ 180011991 ---- */

void FUN_180011991(undefined8 param_1,longlong param_2)

{
  __acrt_unlock(**(int **)(param_2 + 0x48));
  return;
}



/* ---- FUN_1800119ab @ 1800119ab ---- */

void FUN_1800119ab(undefined8 param_1,longlong param_2)

{
  if (*(char *)(param_2 + 0x80) != '\0') {
    __acrt_unlock(3);
  }
  return;
}



/* ---- FUN_1800119cf @ 1800119cf ---- */

void FUN_1800119cf(void)

{
  __acrt_unlock(4);
  return;
}



/* ---- FUN_1800119e8 @ 1800119e8 ---- */

void FUN_1800119e8(void)

{
  __acrt_unlock(8);
  return;
}



/* ---- FUN_180011a01 @ 180011a01 ---- */

void FUN_180011a01(undefined8 param_1,longlong param_2)

{
  FUN_18000bc38(*(longlong *)(param_2 + 0x68));
  return;
}



/* ---- FUN_180011a1b @ 180011a1b ---- */

void FUN_180011a1b(void)

{
  __acrt_unlock(8);
  return;
}



/* ---- FUN_180011a34 @ 180011a34 ---- */

void FUN_180011a34(void)

{
  __acrt_unlock(7);
  return;
}



/* ---- FUN_180011a4d @ 180011a4d ---- */

void FUN_180011a4d(undefined8 param_1,longlong param_2)

{
  FUN_18000bc38(*(longlong *)(param_2 + 0x30));
  return;
}



/* ---- FUN_180011a65 @ 180011a65 ---- */

void FUN_180011a65(undefined8 param_1,longlong param_2)

{
  FID_conflict___acrt_lowio_lock_fh(*(uint *)(param_2 + 0x50));
  return;
}



/* ---- FUN_180011a7c @ 180011a7c ---- */

undefined8 FUN_180011a7c(undefined8 *param_1)

{
  undefined8 uVar1;
  
  if ((*(int *)*param_1 == -0x3ffffffb) || (*(int *)*param_1 == -0x3fffffe3)) {
    uVar1 = 1;
  }
  else {
    uVar1 = 0;
  }
  return uVar1;
}



/* ---- FUN_180011aa8 @ 180011aa8 ---- */

void FUN_180011aa8(undefined8 param_1,longlong param_2)

{
  FID_conflict___acrt_lowio_lock_fh(**(uint **)(param_2 + 0x48));
  return;
}



/* ---- FUN_180011ad0 @ 180011ad0 ---- */

bool FUN_180011ad0(undefined8 *param_1)

{
  return *(int *)*param_1 == -0x3ffffffb;
}



