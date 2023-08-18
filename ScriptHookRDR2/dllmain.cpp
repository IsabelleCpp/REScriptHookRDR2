// dllmain.cpp : Defines the entry point for the DLL application.
#include "pch.h"
#include "ScriptHook.h"

BOOL APIENTRY DllMain( HMODULE hModule,
                       DWORD  ul_reason_for_call,
                       LPVOID lpReserved
                     )
{

    HMODULE ohModule;
    CHAR ModuleName[MAX_PATH];
    static bool ScriptHookInited = false;
    if (ul_reason_for_call == DLL_PROCESS_ATTACH && !ScriptHookInited)
    {
        ScriptHookInited = true;
        GetModuleFileNameA(hModule, ModuleName, sizeof(ModuleName));
        GetModuleHandleExA(GET_MODULE_HANDLE_EX_FLAG_PIN, ModuleName, &ohModule); // Pin the module
        ScriptHook_Log_Message("// RDR 2 SCRIPT HOOK (build %s, v1.0.1491.17)", "Feb  9 2023");
        ScriptHook_Log_Message("//     (C) Alexander Blade 2019-2023");
        Init_Start();
    }
    return TRUE;
}

