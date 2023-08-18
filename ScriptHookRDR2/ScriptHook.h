#pragma once
#include "pch.h"
template <typename... Args>
void ScriptHook_Log_Message_Cpp(const std::string& format, Args... args);
void ScriptHook_Log_Message(const char* Format, ...);
int vsprintf_s_0x400(char* Buffer, const char* Format, ...);
void Init_Start();