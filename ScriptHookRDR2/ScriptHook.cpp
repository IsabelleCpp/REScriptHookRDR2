#include "pch.h"
#include "ScriptHook.h"
#include <shellapi.h>
#include <vector>
#include <map>
#include <set>
#include <filesystem>
#include <iterator>

// Define the version names
#define VERSION_NAMES \
    X(VER_AUTO) \
    X(VER_1_0_1207_60) \
    X(VER_1_0_1207_69) \
    X(VER_1_0_1207_73) \
    X(VER_1_0_1207_77) \
    X(VER_1_0_1207_80) \
    X(VER_1_0_1232_13) \
    X(VER_1_0_1232_17) \
    X(VER_1_0_1311_12) \
    X(VER_1_0_1436_25) \
    X(VER_1_0_1436_31) \
    X(VER_1_0_1491_16) \
    X(VER_1_0_1491_17)

// Helper macro to create version enum and access function
#define X(name) name,
enum eGameVersion {
    VERSION_NAMES
    NumVersions
};
#undef X


class Logger {
public:
    Logger(const std::string& logFileName) : lastMessageBuffer(""), logBuffer(""), fileName(logFileName) {}

    template <typename... Args>
    void LogMessage(const std::string& format, Args... args) {
        std::stringstream messageStream;
        messageStream << format;

        std::string message = FormatString(messageStream, args...);

        if (message.substr(0, 2) == "//") {
            finalMessage = message + "\n";
        }
        else {
            finalMessage = GetFormattedTimestamp() + message + "\n";
        }

        if (lastMessageBuffer.find(message) == std::string::npos) {
            lastMessageBuffer = message;

            if (!finalMessage.empty()) {
                logBuffer += finalMessage;
            }

            std::ofstream stream(fileName.c_str(), std::ios::binary);

            if (stream) {
                stream << logBuffer;
                stream.close();
            }
        }
    }

private:
    std::string lastMessageBuffer;
    std::string logBuffer;
    std::string fileName;
    std::string finalMessage;

    std::string GetFormattedTimestamp() {
        auto now = std::chrono::system_clock::now();
        auto time_point = std::chrono::system_clock::to_time_t(now);
        auto duration = now.time_since_epoch();

        auto hours = std::chrono::duration_cast<std::chrono::hours>(duration);
        duration -= hours;
        auto minutes = std::chrono::duration_cast<std::chrono::minutes>(duration);
        duration -= minutes;
        auto seconds = std::chrono::duration_cast<std::chrono::seconds>(duration);

        std::stringstream ss;
        ss << '[' << std::setw(2) << std::setfill('0') << hours.count() % 24 << ':'
            << std::setw(2) << minutes.count() % 60 << ':'
            << std::setw(2) << seconds.count() % 60 << "] ";

        return ss.str();
    }


    template <typename T, typename... Args>
    std::string FormatString(std::stringstream& ss, T value, Args... args) {
        ss << value;
        return FormatString(ss, args...);
    }

    std::string FormatString(std::stringstream& ss) {
        return ss.str();
    }
};

template <typename... Args>
void ScriptHook_Log_Message_Cpp(const std::string& format, Args... args) {
    static Logger logger("ScriptHookRDR2.log");

    logger.LogMessage(format, args...);
}

int vsprintf_s_0x400(char* Buffer, const char* Format, ...)
{
    va_list ArgList; // [rsp+0x40] [rbp+0x18] BYREF

    va_start(ArgList, Format);
    return vsprintf_s(Buffer, 0x400ui64, Format, ArgList);
}

void __stdcall CheckForUpdates()
{
    char UpdateRequired; // bl
    HKEY SHKey; // [rsp+0x30] [rbp-0x18] BYREF
    struct _FILETIME SystemTimeAsFileTime; // [rsp+0x38] [rbp-0x10] BYREF
    unsigned __int64 CurrentTime; // [rsp+0x50] [rbp+0x8] BYREF
    DWORD cbData; // [rsp+0x58] [rbp+0x10] BYREF
    DWORD Type; // [rsp+0x60] [rbp+0x18] BYREF
    unsigned __int64 SavedTime; // [rsp+0x68] [rbp+0x20] BYREF

    if (RegOpenKeyA(HKEY_CURRENT_USER, "Software\\ScriptHookRDR2", &SHKey)
        && RegCreateKeyA(HKEY_CURRENT_USER, "Software\\ScriptHookRDR2", &SHKey))
    {
        return;
    }
    GetSystemTimeAsFileTime(&SystemTimeAsFileTime);
    CurrentTime = *(unsigned __int64*)&SystemTimeAsFileTime / 0x989680 + 1240428288;
    cbData = 4;
    if (RegQueryValueExA(SHKey, "1.0.1491.17", 0i64, &Type, (LPBYTE)&SavedTime, &cbData))
    {
        UpdateRequired = 0;
    }
    else
    {
        if (Type != 4 || SavedTime + 864000 >= CurrentTime)
        {
            UpdateRequired = 0;
            goto Exit;
        }
        UpdateRequired = 1;
    }
    RegSetValueExA(SHKey, "1.0.1491.17", 0, 4u, (const BYTE*)&CurrentTime, 4u);
Exit:
    RegCloseKey(SHKey);
    if (UpdateRequired)
    {
        if (MessageBoxA(0i64, "CHECK FOR SCRIPT HOOK RDR 2 UPDATES ?", "SCRIPT HOOK RDR 2", 0x24u) == 6)
        {
            ShellExecuteA(0i64, 0i64, "http://dev-c.com/rdr2/scripthookrdr2/", 0i64, 0i64, 5);
            ExitProcess(0);
        }
    }
}

uintptr_t RDR2_RVA;
int GameVersion;
typedef void(*KeyboardHandler)(DWORD key, WORD repeats, BYTE scanCode, BOOL isExtended, BOOL isWithAlt, BOOL wasDownBefore, BOOL isUpNow);
std::vector<KeyboardHandler>KeyboardHandlerVector;
bool ScriptHookRDR2_dev_Exists;
struct Data0x10
{
    DWORD d1;
    DWORD d2;
    DWORD d3;
    DWORD d4;
};
struct Array0x10
{
    Data0x10 Array[0xFF];
};

struct VirtualKeyDataEntry
{
    DWORD TickCountWhenPressed;
    DWORD isWithAlt;
    DWORD wasDownBefore;
    DWORD isUpNow;
};

VirtualKeyDataEntry VkStatesArray[0xFF];

struct Array10x4
{
    Data0x10 Array[4];
};

struct ResultDest
{
    DWORD Dst0;
    BYTE gap4[4];
    DWORD Dst8;
    BYTE gapC[4];
    DWORD Dst10;
    BYTE gap14[4];
    DWORD dword18;
    BYTE gap1C[4];
};



struct GameVersion {
    const char* name;
};

const struct GameVersion GameVersionTable[] = {
    { "VER_AUTO" },
    { "VER_1_0_1207_60" },
    { "VER_1_0_1207_69" },
    { "VER_1_0_1207_73" },
    { "VER_1_0_1207_77" },
    { "VER_1_0_1207_80" },
    { "VER_1_0_1232_13" },
    { "VER_1_0_1232_17" },
    { "VER_1_0_1311_12" },
    { "VER_1_0_1436_25" },
    { "VER_1_0_1436_31" },
    { "VER_1_0_1491_16" },
    { "VER_1_0_1491_17" }
};
struct Vector_Type1 {
    size_t index;
    BYTE Byte;
};
struct VectorValTest1 {
    Vector_Type1* _Myfirst; // pointer to beginning of array
    Vector_Type1* _Mylast; // pointer to current end of sequence
    Vector_Type1* _Myend; // pointer to end of array
};
typedef std::vector<Vector_Type1> _Vector_val_1;
char EmptyBuffer[] { 0, 0, 0, 0 };

typedef void(*LP_SCRIPT_MAIN)(void);

struct core_sh_script
{
    HMODULE ScriptBase;
    std::string ScriptPath;
    std::string ScriptName;
    std::set<LP_SCRIPT_MAIN> MainScriptsSet;
};

std::vector<std::shared_ptr<core_sh_script>>ScriptVector;
std::set<std::string> ScriptPathsSet;

struct struct_ThreadTable
{
    uintptr_t qword0;
    DWORD ThreadId;
    DWORD dwordC;
    DWORD Count;
    DWORD dword14;
    uintptr_t qword18;
};

struct core_sh_thread
{
    DWORD ThreadIdParam;
    DWORD WaitUntilThisTime;
    LPVOID pFiber;
    uintptr_t ThreadStartAddress;
    std::shared_ptr<core_sh_script> sh_script;
};


struct ThreadTreeMyValue
{
    int ThreadId;
    int UnusedHigh;
    std::shared_ptr<core_sh_thread> sh_thread;
    bool operator<(const ThreadTreeMyValue& rhs) const noexcept
    {
        return this->ThreadId < rhs.ThreadId;
    }
};

std::set<ThreadTreeMyValue> ThreadTree;
LPVOID lpFiber;

struct MapValPair
{
    void* first; // the first stored value
    void* second; // the second stored value
};
struct _Tree_node_def {
    _Tree_node_def* _Left; // left subtree, or smallest element if head
    _Tree_node_def* _Parent; // parent, or root of tree if head
    _Tree_node_def* _Right; // right subtree, or largest element if head
    char _Color; // _Red or _Black, _Black if head
    char _Isnil; // true only if head (also nil) node; TRANSITION, should be bool
    MapValPair _Myval; // the stored value, unused if head

    enum _Redbl { // colors for link to parent
        _Red,
        _Black
    };
};
struct Test_Tree_val {
    _Tree_node_def _Myhead;
    size_t _Mysize;
};

struct char_String_val
{
    union _Bxty { // storage for small buffer or pointer to larger one
        char _Buf[0x10];
        char* _Ptr;
        char _Alias[0x10]; // TRANSITION, ABI: _Alias is preserved for binary compatibility (especially /clr)
    } _Bx;

    size_t _Mysize = 0; // current length of string
    size_t _Myres = 0; // current storage reserved for strin
};


bool __fastcall FindPattern(unsigned __int64* pResult, std::string Pattern, int Skips)
{
    size_t ByteArraySize; // eax
    char c1; // r12
    char c2; // r15
    uintptr_t ModuleHandleA; // rax
    PIMAGE_NT_HEADERS ntHeaders; // rdx
    PIMAGE_SECTION_HEADER First_Section;
    uintptr_t SectionStartAddr; // r8
    uintptr_t SectionEnd; // r9
    bool WasPatternFound = false; // al
    _Vector_val_1 byteArray; // [rsp+0x28] [rbp-0x71] BYREF
    Vector_Type1 ByteData; // [rsp+0x40] [rbp-0x59] BYREF
    std::string ByteString; // [rsp+0x90] [rbp-0x9] BYREF

    if (Pattern.size())
    {
        std::erase(Pattern, ' ');
    }
    std::size_t PatternStringSize = Pattern.size();
    if (!PatternStringSize || (PatternStringSize & 1) != 0)
    {
        return WasPatternFound;
    }
    ByteArraySize = PatternStringSize / 2;

    for (std::size_t i = 0; i < ByteArraySize; ++i) {
        c1 = Pattern[2 * i];

        c2 = Pattern[2 * i + 1];
        if (c1 == '?' || c2 == '?')
        {
            if (c1 != c2)
            {
                return WasPatternFound;
            }
        }
        else
        {
            ByteString = Pattern.substr(2 * i, 2);
            ByteData.index = i;
            ByteData.Byte = std::stoi(ByteString, nullptr, 16);
            byteArray.push_back(ByteData);
        }
    }
    ModuleHandleA = (uintptr_t)GetModuleHandleA(0i64);
    ntHeaders = reinterpret_cast<PIMAGE_NT_HEADERS>(ModuleHandleA + reinterpret_cast<PIMAGE_DOS_HEADER>(ModuleHandleA)->e_lfanew);
    First_Section = IMAGE_FIRST_SECTION(ntHeaders);
    SectionStartAddr = ModuleHandleA + First_Section->VirtualAddress;
    SectionEnd = SectionStartAddr + First_Section->Misc.VirtualSize - ByteArraySize;

    if (!byteArray.size())
    {
        return WasPatternFound;
    }

    for (; SectionStartAddr < SectionEnd; ++SectionStartAddr)
    {
        WasPatternFound = true;

        for (const auto& ByteStruct : byteArray)
        {
            if (*(BYTE*)(ByteStruct.index + SectionStartAddr) != ByteStruct.Byte)
            {
                WasPatternFound = false;
                break;
            }
        }

        if (WasPatternFound)
        {
            if (!Skips)
                *pResult = SectionStartAddr;
            --Skips;
        }
    }


    return WasPatternFound;
}

struct GameAddress {
    uintptr_t VER[NumVersions];
};

struct GetNativeAddrFromHashStruct
{
    uintptr_t f1;
    uintptr_t f2;
    uintptr_t f3;
    uintptr_t f4;
    uintptr_t f5;
    DWORD flags_low;
    DWORD flags_high;
    uintptr_t f7;
    uintptr_t f8;
    uintptr_t* pHashInAddrOut;
};

typedef void(__fastcall* GetNativeAddrFromHash_Type)(GetNativeAddrFromHashStruct*);

struct GameAddresses
{
    GameAddress GetNativeAddrFromHash; // GetNativeAddrFromHash_Type
    GameAddress ga2;
    GameAddress ga3;
    GameAddress ga4;
    GameAddress ga5;
    GameAddress ga6;
    GameAddress ga7;
    GameAddress ga8;
    GameAddress ga9;
    GameAddress ga10;
    GameAddress ga11;
};

GameAddresses MainAddressTable {
    { 
        0, 0x142A10078, 0x142A15A5C, 0x142A17B04, 0x142A18134,
        0x142A18A58, 0x142A505C0, 0x142A50E78, 0x142AC3D4C,
        0x142B35C34, 0x142AC6F58, 0x142AE4238, 0x142AE4154 
    }, 
    {
            0,
        0x143314058, 0x14331AFF8, 0x14331EFC8, 0x14331EFD8, 
        0x14331FFD8, 0x143364F98, 0x143365FC8, 0x1433E90B8, 
        0x143496258, 0x143407850, 0x143426F18, 0x143426F18
    }, 
    {
            0,
        0x1457C3F40, 0x1457CB320, 0x1457D0480, 0x1457D05B0, 
        0x1457D1770, 0x14581D5D0, 0x14581E6F0, 0x1459097B8, 
        0x1459E1488, 0x145953ED8, 0x14598FDC8, 0x14598FEC8
    }, 
    {
            0, 
        0x1457C3B00, 0x1457CAEE0, 0x1457D0040, 0x1457D0170, 
        0x1457D1330, 0x14581D190, 0x14581E2B0, 0x145909370, 
        0x1459E1040, 0x145953A90, 0x14598FDD0, 0x14598FED0
    }, 
    {
            0, 
        0x14594EA4C, 0x145955E2C, 0x14595B16C, 0x14595B29C, 
        0x14595C46C, 0x1459A852C, 0x1459A964C, 0x145A9643C, 
        0x145B6E1DC, 0x145AE0C60, 0x145B1CF90, 0x145B1D080
    }, 
    {
            0, 
        0x14A0, 0x14A0, 0x14A0, 0x14A0, 
        0x14A0, 0x14A8, 0x14A8, 0x16D8,
        0x16F0, 0x16F0, 0x1700, 0x1700
    }, 
    {
            0, 0x145DF8674, 
        0x145DFF720, 0x145E04764, 0x145E04764, 0x145E06764, 
        0x145E5967C, 0x145E5A67C, 0x145F5A8A8, 0x146057E1C, 
        0x145FD1E24, 0x14600F4D4, 0x14600F4D4
    }, 
    {
            0, 0, 0, 0, 0, 0,
        0, 0, 0, 0x143ACB5D0, 0x143A3D930, 0x143A60760, 
        0x143A60760
    }, 
    {
            0, 0x140A488F4, 0x140A4D254, 0x140A4D25C, 
        0x140A4D450, 0x140A4D534, 0x140A563E0, 0x140A563E0, 
        0x140A8BBC4, 0x140AB9330, 0x140A9BD54, 0x140A9E850, 
        0x140A9E850
    }, 
    {
        0, 0x142A17054, 0x142A1CA38, 0x142A1EAE0, 
        0x142A1F110, 0x142A1FA34, 0x142A575AC, 0x142A57E64, 
        0x142ACAEC0, 0x142B3D5AC, 0x142ACE754, 0x142AEC1F4,
        0x142AEC110
    },
    { 
        0, 0x142A14E38, 0x142A1A81C, 0x142A1C8C4, 
        0x142A1CEF4, 0x142A1D818, 0x142A55380, 0x142A55C38, 
        0x142AC8C60, 0x142B3B078, 0x142ACC264, 0x142AE9AE0,
        0x142AE99FC 
    }
};

int GetGameVerAuto()
{
    uintptr_t v1; // rcx
    uintptr_t v2; // rcx
    uintptr_t v3; // rax
    uintptr_t v4; // rcx
    uintptr_t v5; // rcx
    uintptr_t Result; // [rsp+50h] [rbp+10h] BYREF

    if (!FindPattern(&Result, "48 89 5C 24 08 48 89 7C 24 10 45 33 D2 4C 8B", 0))
        return -1;
    MainAddressTable.GetNativeAddrFromHash.VER[VER_AUTO] = Result - RDR2_RVA;

    if (!FindPattern(&Result, "48 8B CB 48 89 03 33 C0 48 89 83 ?? ?? 00 00 89", 1))
        return -1;
    v1 = *(int*)(Result - 4);

    MainAddressTable.ga2.VER[VER_AUTO] = Result + v1 - RDR2_RVA;

    if (!FindPattern(&Result, "41 56 48 83 EC 30 89 91 C4 06 00 00 48 8B E9 8B", 0))
        return -1;

    v2 = *(int*)(Result + 0x43);
    MainAddressTable.ga3.VER[VER_AUTO] = Result + 0x47 + v2 - RDR2_RVA;
    v3 = *(int*)(Result + 0x57) - RDR2_RVA;
    MainAddressTable.ga4.VER[VER_AUTO] = Result + 0x4E + *(int*)(Result + 0x4A) - RDR2_RVA;
    MainAddressTable.ga5.VER[VER_AUTO] = Result + 0x5B + v3;
    MainAddressTable.ga6.VER[VER_AUTO] = *(int*)(Result + 0x5D);

    if (!FindPattern(&Result, "0F B7 C0 89 05 ?? ?? ?? ?? 85 C0 75", 0))
        return -1;
    v4 = *(int*)(Result - 4);
    MainAddressTable.ga7.VER[VER_AUTO] = Result + v4 - RDR2_RVA;

    if (!FindPattern(&Result, "C7 05 ?? ?? ?? ?? E1 E1 E1 FF", 0))
        return -1;
    v5 = *(int*)(Result + 2);
    MainAddressTable.ga8.VER[VER_AUTO] = Result + 0xA + v5 - RDR2_RVA;

    if (!FindPattern(&Result, "40 53 48 83 EC 20 8A D9 E8 ?? ?? ?? ?? 41 B8 FF", 0))
        return -1;
    MainAddressTable.ga9.VER[VER_AUTO] = Result - RDR2_RVA;
    
    if (!FindPattern(&Result, "83 79 10 00 44 8B D2 74 43 33 D2 41 8B C2 F7 71", 0))
        return -1;
    MainAddressTable.ga10.VER[VER_AUTO] = Result - RDR2_RVA;

    if (!FindPattern(&Result, "48 8B F1 48 83 C1 10 33 FF 32 DB E8", 0))
        return -1;
    MainAddressTable.ga11.VER[VER_AUTO] = Result - RDR2_RVA - 0x1A;
    return 0i64;
}

int Get_GameVersion()
{
    unsigned int MajorVer; // eax
    int Minor_Ver; // ecx
    int MinorVer; // ecx

    MajorVer = *(DWORD*)(RDR2_RVA + 0x140870000i64);
    if (MajorVer > 0x5DE8CC8B)
    {
        switch (MajorVer)
        {
        case 0x8B48D38B:
            MinorVer = *(DWORD*)(RDR2_RVA + 0x143200000i64);
            if (MinorVer == 0x6D8AE802)
                return 6i64;
            if (MinorVer == 0x1D9A0589)
                return 7i64;
            break;
        case 0xD233FF87:
            return 4i64;
        case 0xD68B4808:
            return 10i64;
        case 0xE870290F:
            return 9i64;
        }
    }
    else
    {
        switch (MajorVer)
        {
        case 0x5DE8CC8Bu:
            return 1i64;
        case 0x2A5D3A4u:
            return 5i64;
        case 0x573F72Fu:
            return 8i64;
        case 0x100FFF94u:
            Minor_Ver = *(DWORD*)(RDR2_RVA + 0x143200000i64);
            if (Minor_Ver == 0xD043280F)
                return 11i64;
            if (Minor_Ver == 0x11F48B)
                return 12i64;
            break;
        case 0x18488948u:
            return 2i64;
        case 0x39CCC328u:
            return 3i64;
        }
    }
    return GetGameVerAuto();
}

void SCRIPT_HOOK_RDR2_CRITICAL_ERROR(const char* Format, ...)
{
    CHAR Text[1024]; // [rsp+20h] [rbp-418h] BYREF
    va_list va; // [rsp+448h] [rbp+10h] BYREF

    va_start(va, Format);
    vsprintf_s(Text, 0x400ui64, Format, va);
    ScriptHook_Log_Message(Text);
    MessageBoxA(0i64, Text, "SCRIPT HOOK RDR2 CRITICAL ERROR", MB_ICONERROR);
    ExitProcess(0);
}
typedef unsigned int(__fastcall* CoreFuncType)(Core_this_Struct*, uintptr_t);

CoreFuncType Original_CoreFuncAddr;

uintptr_t DefaultNativeValue_From_0xAAAAAAAAAAAAAAAA;

uintptr_t GetNativeAddrFromHash_Wrapper(uintptr_t NativeHash)
{
    uintptr_t HashInAddrOut; // [rsp+20h] [rbp-78h] BYREF
    GetNativeAddrFromHashStruct GetNativeAddrFromHashStruct{0}; // [rsp+30h] [rbp-68h] BYREF

    HashInAddrOut = NativeHash;
    GetNativeAddrFromHashStruct.flags_high = 1;
    GetNativeAddrFromHashStruct.pHashInAddrOut = &HashInAddrOut;
    auto GetNativeAddrFromHash = (GetNativeAddrFromHash_Type)(RDR2_RVA + MainAddressTable.GetNativeAddrFromHash.VER[GameVersion]);
    GetNativeAddrFromHash(&GetNativeAddrFromHashStruct);
    return HashInAddrOut;
}

int NativesVersion = 0;

int GetNativesVer()
{
    int ver; // eax

    ver = NativesVersion;
    if (!NativesVersion)
    {
        if (!DefaultNativeValue_From_0xAAAAAAAAAAAAAAAA)
            DefaultNativeValue_From_0xAAAAAAAAAAAAAAAA = GetNativeAddrFromHash_Wrapper(0xAAAAAAAAAAAAAAAAui64);
        if (GetNativeAddrFromHash_Wrapper(0xA1253A3C870B6843ui64) == DefaultNativeValue_From_0xAAAAAAAAAAAAAAAA)
        {
            if (GetNativeAddrFromHash_Wrapper(0x4170B650590B3B00ui64) == DefaultNativeValue_From_0xAAAAAAAAAAAAAAAA)
            {
                ver = NativesVersion;
                if (!NativesVersion)
                    SCRIPT_HOOK_RDR2_CRITICAL_ERROR("FATAL: Can't determinate natives version");
            }
            else
            {
                ver = 1;
                NativesVersion = 1;
            }
        }
        else
        {
            ver = 2;
            NativesVersion = 2;
        }
    }
    return ver;
}

struct NativesVecData
{
    uintptr_t Hash;
    uintptr_t Address;
};

bool NativesVectorArrayInited = false;
std::vector<NativesVecData>* NativesVectorArray[256];

uintptr_t GetNativeFromIndex8bits(uintptr_t Hash)
{
    std::vector<NativesVecData>* VectorEntry;

    if (!NativesVectorArrayInited)
    {
        memset(NativesVectorArray, 0, sizeof(NativesVectorArray));
        NativesVectorArrayInited = true;
    }
    VectorEntry = NativesVectorArray[(unsigned __int8)Hash];
    if (!VectorEntry)
        return 0;

    auto it = std::find_if(VectorEntry->begin(), VectorEntry->end(),
        [Hash](const NativesVecData& entry) {
            return entry.Hash == Hash;
        });

    if (it == VectorEntry->end())
        return 0;

    return it->Address;
}


void AppendNativeToVec(uintptr_t Hash, uintptr_t Address)
{
    if (!NativesVectorArrayInited)
    {
        memset(NativesVectorArray, 0, sizeof(NativesVectorArray));
        NativesVectorArrayInited = true;
    }

    std::vector<NativesVecData>* NativeVec = NativesVectorArray[(unsigned __int8)Hash];

    if (!NativeVec)
    {
        NativeVec = new std::vector<NativesVecData>;
        NativesVectorArray[(unsigned __int8)Hash] = NativeVec;
    }

    NativesVecData Data;
    Data.Hash = Hash;
    Data.Address = Address;

    NativeVec->push_back(Data);
}

struct GameContext;

typedef __int64(__fastcall* NativeFunc)(GameContext*);

struct GameContext {
    uintptr_t* pRetValues;
    DWORD ArgCount;
    DWORD Padding;
    uintptr_t* pArgs;
    DWORD ResultCount;
    DWORD Padding2;
    ResultDest* ResultDestinations[4];
    Array10x4 ResultsSrc;
    NativeFunc Native;
};

struct NativeContext
{
    uintptr_t Args[0x20];
    uintptr_t RetValues[0x20];
    GameContext GamePart;
};

NativeContext NativesContext;
WNDPROC OriginalWinProc;

void __fastcall Call_KeyboardHandlers(DWORD key, WORD repeats, BYTE scanCode, BOOL isExtended, BOOL isWithAlt, BOOL wasDownBefore, BOOL isUpNow)
{
    for (const auto& KeyboardFunc : KeyboardHandlerVector)
    {
        KeyboardFunc(
            key,
            repeats,
            scanCode,
            isExtended,
            isWithAlt,
            wasDownBefore,
            isUpNow);
    }
  
    if (key < 0xFF)
    {
        VkStatesArray[key].TickCountWhenPressed = GetTickCount();
        VkStatesArray[key].isWithAlt = isWithAlt;
        VkStatesArray[key].wasDownBefore = wasDownBefore;
        VkStatesArray[key].isUpNow = isUpNow;
    }
}

LRESULT CALLBACK WndProchook(HWND hwnd, UINT message, WPARAM wParam, LPARAM lParam) {
    switch (message) {
        case WM_KEYDOWN:
        case WM_SYSKEYDOWN:
        case WM_KEYUP:
        case WM_SYSKEYUP: {

            WORD vkCode = LOWORD(wParam);                                 // virtual-key code

            WORD repeatCount = LOWORD(lParam);                            // repeat count, > 0 if several keydown messages was combined into one message

            WORD keyFlags = HIWORD(lParam);

            WORD scanCode = LOBYTE(keyFlags);                             // scan code
            
            BOOL isExtendedKey = (keyFlags & KF_EXTENDED) == KF_EXTENDED; // extended-key flag, 1 if scancode has 0xE0 prefix

            BOOL wasKeyDown = (keyFlags & KF_REPEAT) == KF_REPEAT;        // previous key-state flag, 1 on autorepeat
            
            BOOL isKeyReleased = (keyFlags & KF_UP) == KF_UP;             // transition-state flag, 1 on keyup
            
            BOOL isWithAlt = (keyFlags & KF_ALTDOWN) == KF_ALTDOWN;

            Call_KeyboardHandlers(vkCode, repeatCount, scanCode, isExtendedKey, isWithAlt, wasKeyDown, isKeyReleased);

            break;
        }
    }

    return OriginalWinProc(hwnd, message, wParam, lParam);
}

bool IS_THREAD_INACTIVE()
{
    unsigned int ThreadId; // edi
    NativeFunc IS_THREAD_ACTIVE_Native; // rbx
    uintptr_t NativeAddrFromHash_Wrapper; // rax
    DWORD k; // eax
    bool ignoreKilledState = false; // [rsp+30h] [rbp+8h]

    const auto it = std::find_if(ThreadTree.begin(), ThreadTree.end(), [](const ThreadTreeMyValue& Thread) {
    return !Thread.sh_thread->ThreadStartAddress;
        });

    if (it == ThreadTree.end()) {
        // No active thread found
        return true;
    }

    ThreadId = it->ThreadId;
    IS_THREAD_ACTIVE_Native = (NativeFunc)GetNativeFromIndex8bits(0x46E9AE36D8FA6417ui64);
    if (!IS_THREAD_ACTIVE_Native)
    {
        GetNativesVer();
        IS_THREAD_ACTIVE_Native = (NativeFunc)GetNativeAddrFromHash_Wrapper(0x46E9AE36D8FA6417ui64);
        AppendNativeToVec(0x46E9AE36D8FA6417ui64, (uintptr_t)IS_THREAD_ACTIVE_Native);
    }
    NativeAddrFromHash_Wrapper = DefaultNativeValue_From_0xAAAAAAAAAAAAAAAA;
    if (!DefaultNativeValue_From_0xAAAAAAAAAAAAAAAA)
    {
        NativeAddrFromHash_Wrapper = GetNativeAddrFromHash_Wrapper(0xAAAAAAAAAAAAAAAAui64);
        DefaultNativeValue_From_0xAAAAAAAAAAAAAAAA = NativeAddrFromHash_Wrapper;
    }
    if (!IS_THREAD_ACTIVE_Native || IS_THREAD_ACTIVE_Native == (NativeFunc)NativeAddrFromHash_Wrapper)
        SCRIPT_HOOK_RDR2_CRITICAL_ERROR("FATAL: Can't find native 0x%016llX", 0x46E9AE36D8FA6417i64);
    memset(&NativesContext, 0, sizeof(NativesContext));
    NativesContext.GamePart.pArgs = NativesContext.Args;
    NativesContext.GamePart.Native = IS_THREAD_ACTIVE_Native;
    NativesContext.GamePart.pRetValues = NativesContext.RetValues;
    NativesContext.Args[NativesContext.GamePart.ArgCount] = ThreadId;
    NativesContext.GamePart.pArgs[++NativesContext.GamePart.ArgCount] = ignoreKilledState;
    ++NativesContext.GamePart.ArgCount;
    NativesContext.GamePart.Native(&NativesContext.GamePart);
    for (k = NativesContext.GamePart.ResultCount; NativesContext.GamePart.ResultCount; k = NativesContext.GamePart.ResultCount)
    {
        --k;
        NativesContext.GamePart.ResultCount = k;
        auto ResultDestinations = NativesContext.GamePart.ResultDestinations[k];
        ResultDestinations->Dst0 = NativesContext.GamePart.ResultsSrc.Array[k].d1;
        ResultDestinations->Dst8 = NativesContext.GamePart.ResultsSrc.Array[k].d2;
        ResultDestinations->Dst10 = NativesContext.GamePart.ResultsSrc.Array[k].d3;
    }
    return *(DWORD*)NativesContext.GamePart.pRetValues == 0;
}

struct Core_this_Struct
{
    BYTE gap0[8];
    unsigned int tid;
    BYTE gapC[4];
    DWORD NeedsWait;
    DWORD NormalCondition;
    BYTE gap18[1708];
    DWORD arg2;
    BYTE gap6C8[16];
    DWORD Id;
};


int SCRIPT_HOOK_RDR2_ERROR(const char* Format, ...)
{
    char Buffer[1024]; // [rsp+20h] [rbp-818h] BYREF
    CHAR Text[1024]; // [rsp+420h] [rbp-418h] BYREF
    va_list va; // [rsp+848h] [rbp+10h] BYREF

    va_start(va, Format);
    vsprintf_s(Buffer, 0x400ui64, Format, va);
    ScriptHook_Log_Message(Buffer);
    vsprintf_s_0x400(Text, "%s\n\nPress OK to continue.", Buffer);
    return MessageBoxA(0i64, Text, "SCRIPT HOOK RDR2 ERROR", 0x10u);
}
struct struct_p_FiberParam
{
    BYTE gap0[16];
    void (*pfunc10)(void);
    uintptr_t qword18;
    uintptr_t qword20;
};
uintptr_t* nativeCall(void);

bool GET_IS_LOADING_SCREEN_ACTIVE_wrapper()
{
    NativeFunc GET_IS_LOADING_SCREEN_ACTIVE; // rbx
    uintptr_t NativeAddrFromHash_Wrapper; // rax

    GET_IS_LOADING_SCREEN_ACTIVE = (NativeFunc)GetNativeFromIndex8bits(0x71D4BF5890659B0Cui64);
    if (!GET_IS_LOADING_SCREEN_ACTIVE)
    {
        GetNativesVer();
        GET_IS_LOADING_SCREEN_ACTIVE = (NativeFunc)GetNativeAddrFromHash_Wrapper(0x71D4BF5890659B0Cui64);
        AppendNativeToVec(0x71D4BF5890659B0Cui64, (uintptr_t)GET_IS_LOADING_SCREEN_ACTIVE);
    }
    NativeAddrFromHash_Wrapper = DefaultNativeValue_From_0xAAAAAAAAAAAAAAAA;
    if (!DefaultNativeValue_From_0xAAAAAAAAAAAAAAAA)
    {
        NativeAddrFromHash_Wrapper = GetNativeAddrFromHash_Wrapper(0xAAAAAAAAAAAAAAAAui64);
        DefaultNativeValue_From_0xAAAAAAAAAAAAAAAA = NativeAddrFromHash_Wrapper;
    }
    if (!GET_IS_LOADING_SCREEN_ACTIVE
        || GET_IS_LOADING_SCREEN_ACTIVE == (NativeFunc)NativeAddrFromHash_Wrapper)
    {
        SCRIPT_HOOK_RDR2_CRITICAL_ERROR("FATAL: Can't find native 0x%016llX", 0x71D4BF5890659B0Ci64);
    }
    memset(&NativesContext, 0, sizeof(NativesContext));
    NativesContext.GamePart.pArgs = NativesContext.Args;
    NativesContext.GamePart.pRetValues = NativesContext.RetValues;
    NativesContext.GamePart.Native = GET_IS_LOADING_SCREEN_ACTIVE;
    return *(unsigned int*)nativeCall();
}

void __stdcall REQUEST_SCRIPT_WITH_NAME_HASH_0x6758BF00()
{
    NativeFunc NativeFromIndex8bits; // rbx
    uintptr_t NativeAddrFromHash_Wrapper; // rax

    NativeFromIndex8bits = (NativeFunc)GetNativeFromIndex8bits(0xF6B9CE3F8D5B9B74ui64);
    if (!NativeFromIndex8bits)
    {
        GetNativesVer();
        NativeFromIndex8bits = (NativeFunc)GetNativeAddrFromHash_Wrapper(0xF6B9CE3F8D5B9B74ui64);
        AppendNativeToVec(0xF6B9CE3F8D5B9B74ui64, (uintptr_t)NativeFromIndex8bits);
    }
    NativeAddrFromHash_Wrapper = DefaultNativeValue_From_0xAAAAAAAAAAAAAAAA;
    if (!DefaultNativeValue_From_0xAAAAAAAAAAAAAAAA)
    {
        NativeAddrFromHash_Wrapper = GetNativeAddrFromHash_Wrapper(0xAAAAAAAAAAAAAAAAui64);
        DefaultNativeValue_From_0xAAAAAAAAAAAAAAAA = NativeAddrFromHash_Wrapper;
    }
    if (!NativeFromIndex8bits || NativeFromIndex8bits == (NativeFunc)NativeAddrFromHash_Wrapper)
        SCRIPT_HOOK_RDR2_CRITICAL_ERROR("FATAL: Can't find native 0x%016llX", 0xF6B9CE3F8D5B9B74ui64);
    memset(&NativesContext, 0, sizeof(NativesContext));
    NativesContext.GamePart.pRetValues = NativesContext.RetValues;
    NativesContext.GamePart.pArgs = NativesContext.Args;
    NativesContext.GamePart.Native = NativeFromIndex8bits;
    NativesContext.Args[NativesContext.GamePart.ArgCount++] = 0x6758BF00i64;
    nativeCall();
}

uintptr_t GetThreadLocalStoragePointer()
{
    return __readgsqword(0x58); // NtCurrentTeb()->ThreadLocalStoragePointer;
}
int Coretid = -1;

char __fastcall CallThreadMainFunc(void (*main)(void))
{
    __try {
        main();
    }
    __except (1) {
        return 0;
    }

    return 1;
}

void __fastcall FiberStartAddress(__int64 ThreadIdlpFiberParameter)
{
    auto it = std::find_if(ThreadTree.begin(), ThreadTree.end(), [ThreadIdlpFiberParameter](const ThreadTreeMyValue& Thread) {
        return Thread.ThreadId == ThreadIdlpFiberParameter;
        });

    if (it == ThreadTree.end())
    {
        ThreadTreeMyValue MyValue{};
        MyValue.ThreadId = ThreadIdlpFiberParameter;
        it = ThreadTree.insert(MyValue).first;
    }
 
    ScriptHook_Log_Message(
        "CORE: Waiting to launch '%s' (0x%016llX), id %d",
        it->sh_thread->sh_script->ScriptName,
        it->sh_thread->ThreadStartAddress,
        it->sh_thread->ThreadIdParam);

    while (GET_IS_LOADING_SCREEN_ACTIVE_wrapper())
        scriptWait(0);

    ScriptHook_Log_Message(
        "CORE: Launching main() for '%s' (0x%016llX), id %d",
        it->sh_thread->sh_script->ScriptName,
        it->sh_thread->ThreadStartAddress,
        it->sh_thread->ThreadIdParam);

    if (!CallThreadMainFunc((void (*)(void))it->sh_thread->ThreadStartAddress))
    {
        SCRIPT_HOOK_RDR2_ERROR(
            "CORE: An exception occurred while executing '%s' (0x%016llX), id %d",
            it->sh_thread->sh_script->ScriptName,
            it->sh_thread->ThreadStartAddress,
            it->sh_thread->ThreadIdParam);
    }

    scriptWait(86400000);
}

__int64 __fastcall CoreHook(Core_this_Struct* main, unsigned int a2)
{
    CoreFuncType CoreOrigFunc; // r14
    uintptr_t ThreadTableRVA; // r13
    __int64 RDR2RVA; // r15
    __int64 RVAga5; // rdi
    __int64 RVAga6; // rbx
    bool* pSomeBool; // rbx
    void(__fastcall * SomeRelevantFunc)(uintptr_t); // r12
    Core_this_Struct* this_1; // rdi
    __int64 unusedvar; // rcx
    ThreadTreeNode* ThreadTree_Myhead_1; // rdi
    ThreadTreeNode* ThreadTree_Node_1; // rbx
    ThreadTreeNode* ThreadTree_Node__Right; // rax
    ThreadTreeNode* kk; // rax
    ThreadTreeNode* jj; // rax
    ThreadTreeNode* _ThreadTreeNode; // rbx
    core::sh_thread* ShThreadObject; // rcx
    ThreadTreeNode* ThreadTreeNode_Right; // rax
    ThreadTreeNode* nn; // rax
    ThreadTreeNode* mm; // rax
    ThreadTreeNode* ThreadTree_Myhead_1_Parent; // r14
    ThreadTreeNode* ThreadTree_Myhead_1_Parent_1; // rsi
    std::_Ref_count_obj__core::sh_thread__* ThreadTreeShThreadRefCount; // rbx
    __int64(__fastcall * START_NEW_SCRIPT_WITH_NAME_HASH)(_QWORD); // rbx
    uintptr_t NativeAddrFromHash_Wrapper; // rax
    DWORD i1; // eax
    __int64 UselessIndex; // rax
    ArgRetData* UselessDstResults; // rcx
    __int64 NewThreadId; // rcx
    ThreadTreeNode* ThreadTree_Myhead_Parent; // rax
    ThreadTreeNode* InsetionResultNode; // rbx
    core::sh_thread* sh_thread__Object; // rdx
    ThreadTreeNode* ThreadNode_1; // rax
    ThreadTreeNode* UnusedVar_1; // rcx
    std::_Ref_count_obj__core::sh_thread__* ShThreadRefCOutnObj; // rax
    std::_Ref_count_obj__core::sh_thread__* ShThreadRefcountObj; // rcx
    std::_Ref_count_obj__core::sh_thread__* ShThreadRefCOutnObj2_1; // rbx
    MainRefCountObjStruct* ScriptVector__Myfirst; // rsi
    MainRefCountObjStruct* ScriptVector_Mylast; // r15
    std__Set* ScriptVecHead; // r14
    std__Set* ScriptVecNode; // rbx
    QWORD SCRIPT_MAIN; // r12
    __int64(__fastcall * START_NEW_SCRIPT_WITH_NAME_HASH_1)(_QWORD); // rdi
    int NativsVersion; // eax
    __int64 DefNativevalueIrrelevant_1; // rax
    DWORD ResultCount; // eax
    __int64 PointlessResultCount; // rax
    ArgRetData* DstresultPointless; // rcx
    core::sh_thread* NewMainShThread_Object; // rdx
    std::_Ref_count_obj__core::sh_script__* ScriptVector__Myfirst_RefCountObj; // rax
    core::sh_script* ScriptVector__Myfirst_Object; // r8
    std::_Ref_count_obj__core::sh_script__* ThreadIdParam; // rcx
    std::_Ref_count_obj__core::sh_script__* NewMainShThread_Object_sh_script_RefCountObj_1; // rdi
    ThreadTreeNode* ThreadTree_Myhead_Parent_1; // rax
    ThreadTreeNode* ThreadTree_Myhead_2; // rdi
    core::sh_thread* NewMainShThread_Object_1; // rdx
    ThreadTreeNode* ShThreadNode; // rax
    ThreadTreeNode* UnusedVar_2; // rcx
    std::_Ref_count_obj__core::sh_thread__* NewMainShThread_RefCountObj; // rax
    std::_Ref_count_obj__core::sh_thread__* ShThreadRefCOutnObj2_2; // rcx
    std::_Ref_count_obj__core::sh_thread__* ThreadTree_Myhead_2_MyValue_MainShThread_RefCountObj_1; // rdi
    std::_Ref_count_obj__core::sh_thread__* NewMainShThread_RefCountObj_1; // rdi
    std__Set* ScriptVecNode_Right; // rax
    std__Set* i3; // rax
    std__Set* i2; // rax
    struct_ThreadTable* ThreadTableCopyToCheck; // rax
    unsigned int CoreOrigFuncReturnValue; // edi
    std::_Ref_count_obj__core::sh_thread__* sh_thread___RefCountObj; // rbx
    int Id; // r9d
    signed int tid; // edx
    ThreadTreeNode* Parent; // rax
    ThreadTreeNode* _NodeResult; // rcx
    ThreadTreeNode** pNodeResult; // rax
    struct_ThreadTable* ThreadTable; // r13
    __int64 tid_1; // rcx
    ThreadTreeNode* _Parent; // rax
    ThreadTreeNode* iterator; // rbx
    ThreadTreeNode* ThreadNode; // rax
    ThreadTreeNode* UndefinedVar; // rcx
    std::_Ref_count_obj__core::sh_thread__* sh_thread_RefCount; // r15
    core::sh_thread* sh_Thread_Object; // rsi
    int NeedsWait; // eax
    DWORD TickCount; // eax
    core::sh_thread* VirtualKey_R_Expiration_Or_shtObject; // rcx
    ThreadTreeNode* ThreadTree_Myhead; // rdi
    ThreadTreeNode* ThreadTree_Node; // rbx
    core::sh_thread* Object; // rax
    ThreadTreeNode* ThreadtreeRightNode; // rax
    ThreadTreeNode* m; // rax
    ThreadTreeNode* k; // rax
    __int64 UnusedVar_3; // rcx
    MainRefCountObjStructForShThread* MainShThread_1; // rax
    StringSetStruct* StdStringSetHead; // rdi
    StringSetStruct* StdStringSetNode; // rbx
    char_String_val* p_lpModuleName; // rcx
    HMODULE ModuleHandleA; // rax
    StringSetStruct* Std_StringRightNode; // rax
    StringSetStruct* ii; // rax
    StringSetStruct* n; // rax
    StringSetStruct* Std_Set_Strings_Myhead; // rdi
    StringSetStruct* Std_Set_Strings_Node; // rbx
    char_String_val* p_lpLibFileName; // rcx
    StringSetStruct* Right; // rax
    StringSetStruct* j; // rax
    StringSetStruct* i; // rax
    __int64 RDR2RVA_2; // r12
    uintptr_t ThreadTableRVA_2; // rax
    MainRefCountObjStruct* Myfirst; // rbx
    MainRefCountObjStruct* Mylast; // rsi
    std__Set* ScriptHead; // rdi
    std__Set* ScriptNode; // rax
    LP_SCRIPT_MAIN ScriptMainFunc; // r14
    __int64 Unused; // rcx
    MainRefCountObjStructForShThread* MainShThread; // rax
    std::_Ref_count_obj__core::sh_thread__* RefCountObj; // r14
    __int64 BeepCount_1; // rbx
    __int64 BeepCount; // rbx
    __int64 RDR2RVA_1; // [rsp+30h] [rbp-D0h]
    uintptr_t ThreadTableRVA_1; // [rsp+40h] [rbp-C0h]
    CoreFuncType CoreOrigFunc_1; // [rsp+50h] [rbp-B0h]
    unsigned int tid_2; // [rsp+5Ch] [rbp-A4h] BYREF
    MainRefCountObjStructForShThread NewMainShThread; // [rsp+60h] [rbp-A0h] BYREF
    MainRefCountObjStructForShThread AudioTest_sh_Thread; // [rsp+70h] [rbp-90h] BYREF
    __int64 DefNativevalueIrrelevant; // [rsp+80h] [rbp-80h] BYREF
    bool* ThreadTableNotEmptyBool; // [rsp+88h] [rbp-78h]
    __int64 DefNativevalueIrrelevant_2; // [rsp+90h] [rbp-70h] BYREF
    MainRefCountObjStructForShThread sh_thread__; // [rsp+98h] [rbp-68h] BYREF
    __int64 _BG_SET_TEXT_SCALE; // [rsp+A8h] [rbp-58h] BYREF
    __int64(__fastcall * START_NEW_SCRIPT_WITH_NAME_HASH_Old)(_QWORD); // [rsp+B0h] [rbp-50h] BYREF
    __int64 Old_SET_TEXT_SCALE; // [rsp+B8h] [rbp-48h] BYREF
    std__Set* Script_Node; // [rsp+C0h] [rbp-40h] BYREF
    __int64(__fastcall * START_NEW_SCRIPT_WITH_NAME_HASH_2)(_QWORD); // [rsp+C8h] [rbp-38h] BYREF
    ThreadTreeNode* Myhead; // [rsp+D0h] [rbp-30h] BYREF
    unsigned int* p_tid_2; // [rsp+D8h] [rbp-28h] BYREF
    struct_ThreadTable* ThreadTableCopyToStore; // [rsp+E0h] [rbp-20h]
    std_ThreadTreeResult_std_pair NodeResult__; // [rsp+E8h] [rbp-18h] BYREF
    MainRefCountObjStruct* ScriptVector___Mylast; // [rsp+F8h] [rbp-8h]
    MainRefCountObjStructForShThread MainshThread; // [rsp+100h] [rbp+0h] BYREF
    std_ThreadTreeResult_std_pair threadNodeinsertionResult; // [rsp+110h] [rbp+10h] BYREF
    std::_Ref_count_obj__core::sh_thread__* ShThreadRefCOutnObj2; // [rsp+128h] [rbp+28h]
    std::_Ref_count_obj__core::sh_script__* NewMainShThread_Object_sh_script_RefCountObj; // [rsp+138h] [rbp+38h]
    MainRefCountObjStructForShThread ShThreadMainRefCountObject; // [rsp+140h] [rbp+40h] BYREF
    std::_Ref_count_obj__core::sh_thread__* ThreadTree_Myhead_2_MyValue_MainShThread_RefCountObj; // [rsp+158h] [rbp+58h]
    __int64 UnusedVar; // [rsp+160h] [rbp+60h]
    GetNativeAddrFromHashStruct irrelevantnativesStruct_1; // [rsp+170h] [rbp+70h] BYREF
    GetNativeAddrFromHashStruct irrelevantnativesStruct_2; // [rsp+1C0h] [rbp+C0h] BYREF
    GetNativeAddrFromHashStruct irrelevantnativesStruct; // [rsp+210h] [rbp+110h] BYREF
    GetNativeAddrFromHashStruct irrelevantnativesStruct_3; // [rsp+260h] [rbp+160h] BYREF
    GetNativeAddrFromHashStruct IrrelevantNativeFromhashStruct; // [rsp+2B0h] [rbp+1B0h] BYREF
    GetNativeAddrFromHashStruct irrelevantnativesStruct_4; // [rsp+300h] [rbp+200h] BYREF
    char_String_val lpLibFileName; // [rsp+350h] [rbp+250h] BYREF
    char_String_val lpModuleName; // [rsp+370h] [rbp+270h] BYREF

    CoreOrigFunc = Original_CoreFuncAddr;
    CoreOrigFunc_1 = Original_CoreFuncAddr;
    ThreadTableRVA = MainAddressTable.ga3.VER[GameVersion];
    ThreadTableRVA_1 = ThreadTableRVA;
    RDR2RVA = RDR2_RVA;
    RDR2RVA_1 = RDR2_RVA;
    RVAga5 = *(unsigned int*)(RDR2_RVA + MainAddressTable.ga5.VER[GameVersion]);
    RVAga6 = DWORD(MainAddressTable.ga6.VER[GameVersion]);
    pSomeBool = (bool*)(*((uintptr_t*)GetThreadLocalStoragePointer() + RVAga5) + RVAga6);
    ThreadTableNotEmptyBool = pSomeBool;
    SomeRelevantFunc = (void(__fastcall*)(uintptr_t))(MainAddressTable.ga9.VER[GameVersion] + RDR2_RVA);
    if (Coretid == -1)
        goto Init;
    if (Coretid != GetCurrentThreadId())
        SCRIPT_HOOK_RDR2_CRITICAL_ERROR("FATAL: Core tid mismatch");
    if (Coretid == -1)
    {
    Init:
        Coretid = GetCurrentThreadId();
        ConvertThreadToFiber(0i64);
        lpFiber = (PVOID)__readgsqword(0x20); // FIELD_OFFSET(NT_TIB, FiberData); // OR GetCurrentFiber();
    }
    this_1 = main;
    if (main->Id != 0xC7DC3A09 || main->NormalCondition || !IS_THREAD_INACTIVE())
    {
        Id = main->Id;
        tid = main->tid;

        auto it = std::find_if(ThreadTree.begin(), ThreadTree.end(), [tid](const ThreadTreeMyValue& Thread) {
            return Thread.ThreadId == tid;
        });

        if (Id != 0x6758BF00 || it == ThreadTree.end()) {
            if (Id == 0x3DEB3185)
            {
                ScriptHook_Log_Message("CORE: Terminating the game, disable mods in order to go Online");
                BeepCount = 3i64;
                do
                {
                    MessageBeep(0);
                    Sleep(0xC8u);
                    --BeepCount;
                } while (BeepCount);
                ExitProcess(0);
            }
            return CoreOrigFunc(main, a2);
        }
        main->arg2 = a2;
        ThreadTable = *(struct_ThreadTable**)(RDR2RVA + ThreadTableRVA);
        *(uintptr_t*)(RDR2RVA + ThreadTableRVA_1) = (uintptr_t)main;
        *pSomeBool = 1;

        auto it = std::find_if(ThreadTree.begin(), ThreadTree.end(), [tid](const ThreadTreeMyValue& Thread) {
            return Thread.ThreadId == tid;
        });

        if (it == ThreadTree.end())
        {
            ThreadTreeMyValue MyValue{};
            MyValue.ThreadId = tid;
            it = ThreadTree.insert(MyValue).first;
        }
       
        if (it->sh_thread->ThreadStartAddress)
        {
            if (!it->sh_thread->pFiber)
                it->sh_thread->pFiber = CreateFiber(0i64, (LPFIBER_START_ROUTINE)FiberStartAddress, (LPVOID)it->sh_thread->ThreadIdParam);
            NeedsWait = main->NeedsWait;
            if (!NeedsWait || NeedsWait == 1 && sh_Thread_Object->WaitUntilThisTime <= GetTickCount())
            {
                main->NeedsWait = 0;
                SwitchToFiber(sh_Thread_Object->pFiber);
            }
            RDR2RVA_2 = RDR2RVA_1;
            goto SetThreadTable;
        }
        main->NeedsWait = 0;
        if (ScriptHookRDR2_dev_Exists)
        {
            if (GetTickCount() < VkStatesArray[VK_CONTROL].TickCountWhenPressed + 5000
                && !VkStatesArray[VK_CONTROL].isUpNow)
            {
                TickCount = GetTickCount();
                auto VK_R_Expiration = (VkStatesArray['R'].TickCountWhenPressed + 100);
                if (TickCount < VK_R_Expiration)
                {
                    if (VkStatesArray['R'].isUpNow)
                    {
                        VkStatesArray['R'] = VirtualKeyDataEntry{0};
                        
                        if (ThreadTree._Mysize <= 1ui64)
                        {
                            if (ThreadTree._Mysize == 1 && ScriptVector._Myfirst == ScriptVector._Mylast)
                            {
                                Std_Set_Strings_Myhead = Std_Set_Strings._Myhead;
                                Std_Set_Strings_Node = Std_Set_Strings._Myhead->_Left;
                                while (Std_Set_Strings_Node != Std_Set_Strings_Myhead)
                                {
                                    lpLibFileName._Myres = 15i64;
                                    lpLibFileName._Mysize = 0i64;
                                    lpLibFileName._Bx._Buf[0] = 0;
                                    Std_SubString(&lpLibFileName, &Std_Set_Strings_Node->String, 0i64, 0xFFFFFFFFFFFFFFFFui64);
                                    p_lpLibFileName = &lpLibFileName;
                                    if (lpLibFileName._Myres >= 0x10)
                                        p_lpLibFileName = (char_String_val*)lpLibFileName._Bx._Ptr;
                                    LoadLibraryA(p_lpLibFileName->_Bx._Buf);
                                    if (lpLibFileName._Myres >= 0x10)
                                        j_free(lpLibFileName._Bx._Ptr);
                                    if (!Std_Set_Strings_Node->_Isnil)
                                    {
                                        Right = Std_Set_Strings_Node->_Right;
                                        if (Right->_Isnil)
                                        {
                                            for (i = Std_Set_Strings_Node->_Parent; !i->_Isnil; i = i->_Parent)
                                            {
                                                if (Std_Set_Strings_Node != i->_Right)
                                                    break;
                                                Std_Set_Strings_Node = i;
                                            }
                                            Std_Set_Strings_Node = i;
                                        }
                                        else
                                        {
                                            Std_Set_Strings_Node = Std_Set_Strings_Node->_Right;
                                            for (j = Right->_Left; !j->_Isnil; j = j->_Left)
                                                Std_Set_Strings_Node = j;
                                        }
                                    }
                                }
                                REQUEST_SCRIPT_WITH_NAME_HASH_0x6758BF00();
                                SomeRelevantFunc(0i64);
                                RDR2RVA_2 = RDR2RVA_1;
                                ThreadTableRVA_2 = ThreadTableRVA_1;
                                *(_QWORD*)(RDR2RVA_1 + ThreadTableRVA_1) = 0i64;
                                Myfirst = ScriptVector._Myfirst;
                                Mylast = ScriptVector._Mylast;
                                if (ScriptVector._Myfirst != ScriptVector._Mylast)
                                {
                                    do
                                    {
                                        ScriptHead = Myfirst->Object->Set_Of_LP_SCRIPT_MAIN._Myhead;
                                        ScriptNode = ScriptHead->_Left;
                                        for (Script_Node = ScriptNode; Script_Node != ScriptHead; ScriptNode = Script_Node)
                                        {
                                            ScriptMainFunc = ScriptNode->SCRIPT_MAIN;
                                            Construct_ShThread(&AudioTest_sh_Thread);
                                            AudioTest_sh_Thread.Object->ThreadIdParam = START_NEW_SCRIPT_WITH_NAME_AudioTest_HASH();
                                            AcquireRefCountObject(
                                                (MainRefCountObjStructForShThread*)&AudioTest_sh_Thread.Object->sh_script,
                                                (MainRefCountObjStructForShThread*)Myfirst);
                                            AudioTest_sh_Thread.Object->ThreadStartAddress = (QWORD)ScriptMainFunc;
                                            MainShThread = GetMainShThread(Unused, AudioTest_sh_Thread.Object);
                                            AcquireRefCountObject(MainShThread, &AudioTest_sh_Thread);
                                            RefCountObj = AudioTest_sh_Thread.RefCountObj;
                                            if (AudioTest_sh_Thread.RefCountObj)
                                            {
                                                if (!_InterlockedDecrement(&AudioTest_sh_Thread.RefCountObj->Count_8))
                                                {
                                                    RefCountObj->Vftbl->RefCount8Release((std::_Ref_count_obj__core::sh_script__*)RefCountObj);
                                                    if (!_InterlockedDecrement(&RefCountObj->Count_C))
                                                        RefCountObj->Vftbl->RefCountCRelease((std::_Ref_count_obj__core::sh_script__*)RefCountObj);
                                                }
                                            }
                                            GetNextScriptNode(&Script_Node);
                                        }
                                        ++Myfirst;
                                    } while (Myfirst != Mylast);
                                    ThreadTableRVA_2 = ThreadTableRVA_1;
                                }
                                this_1 = main;
                                *(_QWORD*)(RDR2RVA_1 + ThreadTableRVA_2) = main;
                                SET_SCRIPT_WITH_NAME_audiotest_HASH_AS_NO_LONGER_NEEDED();
                                BeepCount_1 = 3i64;
                                do
                                {
                                    MessageBeep(0);
                                    Sleep(0xC8u);
                                    --BeepCount_1;
                                } while (BeepCount_1);
                                goto NeedsWait;
                            }
                        }
                        else
                        {
                            ThreadTree_Myhead = ThreadTree._Myhead;
                            ThreadTree_Node = ThreadTree._Myhead->_Left;
                            while (ThreadTree_Node != ThreadTree_Myhead)
                            {
                                Object = ThreadTree_Node->_MyValue.MainShThread.Object;
                                if (Object->ThreadStartAddress)
                                {
                                    if ((unsigned int)IS_THREAD_ACTIVE(
                                        (__int64)VirtualKey_R_Expiration_Or_shtObject,
                                        Object->ThreadIdParam))
                                        TERMINATE_THREAD_wrapp(ThreadTree_Node->_MyValue.MainShThread.Object->ThreadIdParam);
                                    VirtualKey_R_Expiration_Or_shtObject = ThreadTree_Node->_MyValue.MainShThread.Object;
                                    if (VirtualKey_R_Expiration_Or_shtObject->pFiber)
                                        DeleteFiber(VirtualKey_R_Expiration_Or_shtObject->pFiber);
                                }
                                if (!ThreadTree_Node->_Isnil)
                                {
                                    ThreadtreeRightNode = ThreadTree_Node->_Right;
                                    if (ThreadtreeRightNode->_Isnil)
                                    {
                                        for (k = ThreadTree_Node->_Parent; !k->_Isnil; k = k->_Parent)
                                        {
                                            if (ThreadTree_Node != k->_Right)
                                                break;
                                            ThreadTree_Node = k;
                                        }
                                        ThreadTree_Node = k;
                                    }
                                    else
                                    {
                                        ThreadTree_Node = ThreadTree_Node->_Right;
                                        for (m = ThreadtreeRightNode->_Left; !m->_Isnil; m = m->_Left)
                                            ThreadTree_Node = m;
                                    }
                                }
                            }
                            FreeThreadTree();
                            MainShThread_1 = GetMainShThread(UnusedVar_3, sh_Thread_Object);
                            AcquireRefCountObject(MainShThread_1, &ShThreadMainRefCountObject);
                            StdStringSetHead = Std_Set_Strings._Myhead;
                            StdStringSetNode = Std_Set_Strings._Myhead->_Left;
                            while (StdStringSetNode != StdStringSetHead)
                            {
                                lpModuleName._Myres = 15i64;
                                lpModuleName._Mysize = 0i64;
                                lpModuleName._Bx._Buf[0] = 0;
                                Std_SubString(&lpModuleName, &StdStringSetNode->String, 0i64, 0xFFFFFFFFFFFFFFFFui64);
                                p_lpModuleName = &lpModuleName;
                                if (lpModuleName._Myres >= 0x10)
                                    p_lpModuleName = (char_String_val*)lpModuleName._Bx._Ptr;
                                ModuleHandleA = GetModuleHandleA(p_lpModuleName->_Bx._Buf);
                                FreeLibrary(ModuleHandleA);
                                if (lpModuleName._Myres >= 0x10)
                                    j_free(lpModuleName._Bx._Ptr);
                                if (!StdStringSetNode->_Isnil)
                                {
                                    Std_StringRightNode = StdStringSetNode->_Right;
                                    if (Std_StringRightNode->_Isnil)
                                    {
                                        for (n = StdStringSetNode->_Parent; !n->_Isnil; n = n->_Parent)
                                        {
                                            if (StdStringSetNode != n->_Right)
                                                break;
                                            StdStringSetNode = n;
                                        }
                                        StdStringSetNode = n;
                                    }
                                    else
                                    {
                                        StdStringSetNode = StdStringSetNode->_Right;
                                        for (ii = Std_StringRightNode->_Left; !ii->_Isnil; ii = ii->_Left)
                                            StdStringSetNode = ii;
                                    }
                                }
                            }
                            DecrementRefCoutnForScripts();
                            MessageBeep(0);
                            this_1 = main;
                        }
                    }
                }
            }
        }
        RDR2RVA_2 = RDR2RVA_1;
    NeedsWait:
        this_1->NeedsWait = 1;
    SetThreadTable:
        *(_QWORD*)(RDR2RVA_2 + ThreadTableRVA_1) = ThreadTable;
        *ThreadTableNotEmptyBool = ThreadTable != 0i64;
        CoreOrigFuncReturnValue = this_1->NeedsWait;
        if (sh_thread_RefCount)
        {
            if (!_InterlockedDecrement(&sh_thread_RefCount->Count_8))
            {
                sh_thread_RefCount->Vftbl->RefCount8Release((std::_Ref_count_obj__core::sh_script__*)sh_thread_RefCount);
                if (!_InterlockedDecrement(&sh_thread_RefCount->Count_C))
                    sh_thread_RefCount->Vftbl->RefCountCRelease((std::_Ref_count_obj__core::sh_script__*)sh_thread_RefCount);
            }
        }
        return CoreOrigFuncReturnValue;
    }
    ScriptHook_Log_Message("CORE: Creating threads");
    main->arg2 = a2;
    ThreadTableCopyToStore = *(struct_ThreadTable**)(RDR2RVA + ThreadTableRVA);
    *(_QWORD*)(RDR2RVA + ThreadTableRVA) = main;
    *pSomeBool = 1;
    ThreadTree_Myhead_1 = ThreadTree._Myhead;
    ThreadTree_Node_1 = ThreadTree._Myhead->_Left;
    if (ThreadTree._Myhead->_Left != ThreadTree._Myhead)
    {
        do
        {
            if ((unsigned int)IS_THREAD_ACTIVE(unusedvar, ThreadTree_Node_1->_MyValue.ThreadId))
                SCRIPT_HOOK_RDR2_CRITICAL_ERROR("FATAL: Creating threads while previous are still active");
            if (!ThreadTree_Node_1->_Isnil)
            {
                ThreadTree_Node__Right = ThreadTree_Node_1->_Right;
                if (ThreadTree_Node__Right->_Isnil)
                {
                    for (jj = ThreadTree_Node_1->_Parent; !jj->_Isnil; jj = jj->_Parent)
                    {
                        if (ThreadTree_Node_1 != jj->_Right)
                            break;
                        ThreadTree_Node_1 = jj;
                    }
                    ThreadTree_Node_1 = jj;
                }
                else
                {
                    ThreadTree_Node_1 = ThreadTree_Node_1->_Right;
                    for (kk = ThreadTree_Node__Right->_Left; !kk->_Isnil; kk = kk->_Left)
                        ThreadTree_Node_1 = kk;
                }
            }
        } while (ThreadTree_Node_1 != ThreadTree_Myhead_1);
        ThreadTree_Myhead_1 = ThreadTree._Myhead;
    }
    _ThreadTreeNode = ThreadTree_Myhead_1->_Left;
    if (ThreadTree_Myhead_1->_Left != ThreadTree_Myhead_1)
    {
        do
        {
            ShThreadObject = _ThreadTreeNode->_MyValue.MainShThread.Object;
            if (ShThreadObject->pFiber)
                DeleteFiber(ShThreadObject->pFiber);
            if (!_ThreadTreeNode->_Isnil)
            {
                ThreadTreeNode_Right = _ThreadTreeNode->_Right;
                if (ThreadTreeNode_Right->_Isnil)
                {
                    for (mm = _ThreadTreeNode->_Parent; !mm->_Isnil; mm = mm->_Parent)
                    {
                        if (_ThreadTreeNode != mm->_Right)
                            break;
                        _ThreadTreeNode = mm;
                    }
                    _ThreadTreeNode = mm;
                }
                else
                {
                    _ThreadTreeNode = _ThreadTreeNode->_Right;
                    for (nn = ThreadTreeNode_Right->_Left; !nn->_Isnil; nn = nn->_Left)
                        _ThreadTreeNode = nn;
                }
            }
        } while (_ThreadTreeNode != ThreadTree_Myhead_1);
        ThreadTree_Myhead_1 = ThreadTree._Myhead;
    }
    ThreadTree_Myhead_1_Parent = ThreadTree_Myhead_1->_Parent;
    ThreadTree_Myhead_1_Parent_1 = ThreadTree_Myhead_1_Parent;
    if (!ThreadTree_Myhead_1_Parent->_Isnil)
    {
        do
        {
            RecursiveThreadtreeCleanup(&ThreadTree, ThreadTree_Myhead_1_Parent_1->_Right);
            ThreadTree_Myhead_1_Parent_1 = ThreadTree_Myhead_1_Parent_1->_Left;
            ThreadTreeShThreadRefCount = ThreadTree_Myhead_1_Parent->_MyValue.MainShThread.RefCountObj;
            if (ThreadTreeShThreadRefCount)
            {
                if (!_InterlockedDecrement(&ThreadTreeShThreadRefCount->Count_8))
                {
                    ThreadTreeShThreadRefCount->Vftbl->RefCount8Release((std::_Ref_count_obj__core::sh_script__*)ThreadTreeShThreadRefCount);
                    if (!_InterlockedDecrement(&ThreadTreeShThreadRefCount->Count_C))
                        ThreadTreeShThreadRefCount->Vftbl->RefCountCRelease((std::_Ref_count_obj__core::sh_script__*)ThreadTreeShThreadRefCount);
                }
            }
            j_free(ThreadTree_Myhead_1_Parent);
            ThreadTree_Myhead_1_Parent = ThreadTree_Myhead_1_Parent_1;
        } while (!ThreadTree_Myhead_1_Parent_1->_Isnil);
        ThreadTree_Myhead_1 = ThreadTree._Myhead;
    }
    ThreadTree_Myhead_1->_Parent = ThreadTree_Myhead_1;
    ThreadTree._Myhead->_Left = ThreadTree._Myhead;
    ThreadTree._Myhead->_Right = ThreadTree._Myhead;
    ThreadTree._Mysize = 0i64;
    REQUEST_SCRIPT_WITH_NAME_HASH_0x6758BF00();
    SomeRelevantFunc(0i64);
    *(_QWORD*)(RDR2RVA + ThreadTableRVA) = 0i64;
    Construct_ShThread(&sh_thread__);
    START_NEW_SCRIPT_WITH_NAME_HASH = (__int64(__fastcall*)(_QWORD))GetNativeFromIndex8bits(0xEB1C67C3A5333A92ui64);
    if (!START_NEW_SCRIPT_WITH_NAME_HASH)
    {
        GetNativesVer();
        START_NEW_SCRIPT_WITH_NAME_HASH = (__int64(__fastcall*)(_QWORD))GetNativeAddrFromHash_Wrapper(0xEB1C67C3A5333A92ui64);
        AppendNativeToVec(0xEB1C67C3A5333A92ui64, (uintptr_t)START_NEW_SCRIPT_WITH_NAME_HASH);
    }
    NativeAddrFromHash_Wrapper = DefaultNativeValue_From_0xAAAAAAAAAAAAAAAA;
    if (!DefaultNativeValue_From_0xAAAAAAAAAAAAAAAA)
    {
        NativeAddrFromHash_Wrapper = GetNativeAddrFromHash_Wrapper(0xAAAAAAAAAAAAAAAAui64);
        DefaultNativeValue_From_0xAAAAAAAAAAAAAAAA = NativeAddrFromHash_Wrapper;
    }
    if (!START_NEW_SCRIPT_WITH_NAME_HASH
        || START_NEW_SCRIPT_WITH_NAME_HASH == (__int64(__fastcall*)(_QWORD))NativeAddrFromHash_Wrapper)
    {
        SCRIPT_HOOK_RDR2_CRITICAL_ERROR("FATAL: Can't find native 0x%016llX", 0xEB1C67C3A5333A92ui64);
    }
    memset(&NativesContext, 0, sizeof(NativesContext));
    NativesContext.pArgs = (uintptr_t*)&NativesContext;
    NativesContext.pRetValues = NativesContext.RetValues;
    NativesContext.Native = START_NEW_SCRIPT_WITH_NAME_HASH;
    NativesContext.Args[NativesContext.ArgCount++] = 0x6758BF00i64;
    NativesContext.pArgs[NativesContext.ArgCount++] = 1024i64;
    NativesContext.Native(&NativesContext.pRetValues);
    for (i1 = NativesContext.ResultCount; NativesContext.ResultCount; i1 = NativesContext.ResultCount)
    {
        UselessIndex = i1 - 1;
        NativesContext.ResultCount = UselessIndex;
        UselessDstResults = NativesContext.ArgRetDataArrayCopy[UselessIndex];
        UselessDstResults->dword0 = NativesContext.ArgRetDataArray.Array[(unsigned int)UselessIndex].TickCountWhenPressed;
        UselessDstResults->dword8 = NativesContext.ArgRetDataArray.Array[(unsigned int)UselessIndex].d2;
        UselessDstResults->dword10 = NativesContext.ArgRetDataArray.Array[(unsigned int)UselessIndex].WasDownBefore;
    }
    NewThreadId = *(unsigned int*)NativesContext.pRetValues;
    sh_thread__.Object->ThreadIdParam = NewThreadId;
    ThreadTree_Myhead_Parent = ThreadTree._Myhead->_Parent;
    InsetionResultNode = ThreadTree._Myhead;
    while (!ThreadTree_Myhead_Parent->_Isnil)
    {
        if (ThreadTree_Myhead_Parent->_MyValue.ThreadId >= (int)NewThreadId)
        {
            InsetionResultNode = ThreadTree_Myhead_Parent;
            ThreadTree_Myhead_Parent = ThreadTree_Myhead_Parent->_Left;
        }
        else
        {
            ThreadTree_Myhead_Parent = ThreadTree_Myhead_Parent->_Right;
        }
    }
    sh_thread__Object = sh_thread__.Object;
    if (InsetionResultNode == ThreadTree._Myhead
        || sh_thread__.Object->ThreadIdParam < InsetionResultNode->_MyValue.ThreadId)
    {
        MainshThread.Object = sh_thread__.Object;
        ThreadNode_1 = GetThreadNode(NewThreadId, (__int64)sh_thread__.Object, &MainshThread);
        std::set::insertToThreadTree(
            UnusedVar_1,
            &threadNodeinsertionResult,
            InsetionResultNode,
            &ThreadNode_1->_MyValue,
            ThreadNode_1);
        InsetionResultNode = threadNodeinsertionResult.iterator;
        sh_thread__Object = sh_thread__.Object;
    }
    ShThreadRefCOutnObj = sh_thread__.RefCountObj;
    if (sh_thread__.RefCountObj)
        _InterlockedIncrement(&sh_thread__.RefCountObj->Count_8);
    ShThreadRefCOutnObj2 = InsetionResultNode->_MyValue.MainShThread.RefCountObj;
    ShThreadRefcountObj = ShThreadRefCOutnObj2;
    InsetionResultNode->_MyValue.MainShThread.RefCountObj = ShThreadRefCOutnObj;
    InsetionResultNode->_MyValue.MainShThread.Object = sh_thread__Object;
    if (ShThreadRefcountObj)
    {
        if (!_InterlockedDecrement(&ShThreadRefcountObj->Count_8))
        {
            ShThreadRefCOutnObj2_1 = ShThreadRefCOutnObj2;
            ShThreadRefCOutnObj2->Vftbl->RefCount8Release((std::_Ref_count_obj__core::sh_script__*)ShThreadRefCOutnObj2);
            if (!_InterlockedDecrement(&ShThreadRefCOutnObj2_1->Count_C))
                ShThreadRefCOutnObj2->Vftbl->RefCountCRelease((std::_Ref_count_obj__core::sh_script__*)ShThreadRefCOutnObj2);
        }
    }
    ScriptVector__Myfirst = ScriptVector._Myfirst;
    ScriptVector_Mylast = ScriptVector._Mylast;
    ScriptVector___Mylast = ScriptVector._Mylast;
    while (ScriptVector__Myfirst != ScriptVector_Mylast)
    {
        ScriptVecHead = ScriptVector__Myfirst->Object->Set_Of_LP_SCRIPT_MAIN._Myhead;
        ScriptVecNode = ScriptVecHead->_Left;
        if (ScriptVecHead->_Left != ScriptVecHead)
        {
            while (1)
            {
                SCRIPT_MAIN = (QWORD)ScriptVecNode->SCRIPT_MAIN;
                Construct_ShThread(&NewMainShThread);
                START_NEW_SCRIPT_WITH_NAME_HASH_1 = (__int64(__fastcall*)(_QWORD))GetNativeFromIndex8bits(0xEB1C67C3A5333A92ui64);
                if (!START_NEW_SCRIPT_WITH_NAME_HASH_1)
                    break;
            StartNewScript:
                DefNativevalueIrrelevant_1 = DefaultNativeValue_From_0xAAAAAAAAAAAAAAAA;
                if (!DefaultNativeValue_From_0xAAAAAAAAAAAAAAAA)
                {
                    DefNativevalueIrrelevant = 0xAAAAAAAAAAAAAAAAui64;
                    memset(&IrrelevantNativeFromhashStruct, 0, 0x2C);
                    IrrelevantNativeFromhashStruct.f7 = 0i64;
                    IrrelevantNativeFromhashStruct.f8 = 0i64;
                    IrrelevantNativeFromhashStruct.flags_high = 1;
                    IrrelevantNativeFromhashStruct.pHashInAddrOut = (uintptr_t*)&DefNativevalueIrrelevant;
                    ((void(__fastcall*)(GetNativeAddrFromHashStruct*))(MainAddressTable.GetNativeAddrFromHash.VER[GameVersion]
                        + RDR2_RVA))(&IrrelevantNativeFromhashStruct);
                    DefNativevalueIrrelevant_1 = DefNativevalueIrrelevant;
                    DefaultNativeValue_From_0xAAAAAAAAAAAAAAAA = DefNativevalueIrrelevant;
                }
                if (!START_NEW_SCRIPT_WITH_NAME_HASH_1
                    || START_NEW_SCRIPT_WITH_NAME_HASH_1 == (__int64(__fastcall*)(_QWORD))DefNativevalueIrrelevant_1)
                {
                    SCRIPT_HOOK_RDR2_CRITICAL_ERROR("FATAL: Can't find native 0x%016llX", 0xEB1C67C3A5333A92ui64);
                }
                memset(&NativesContext, 0, sizeof(NativesContext));
                NativesContext.pArgs = (uintptr_t*)&NativesContext;
                NativesContext.pRetValues = NativesContext.RetValues;
                NativesContext.Native = START_NEW_SCRIPT_WITH_NAME_HASH_1;
                NativesContext.Args[NativesContext.ArgCount++] = 0x6758BF00i64;
                NativesContext.pArgs[NativesContext.ArgCount++] = 0x400i64;
                NativesContext.Native(&NativesContext.pRetValues);
                ResultCount = NativesContext.ResultCount;
                if (NativesContext.ResultCount)
                {
                    do
                    {
                        PointlessResultCount = ResultCount - 1;
                        NativesContext.ResultCount = PointlessResultCount;
                        DstresultPointless = NativesContext.ArgRetDataArrayCopy[PointlessResultCount];
                        DstresultPointless->dword0 = NativesContext.ArgRetDataArray.Array[(unsigned int)PointlessResultCount].TickCountWhenPressed;
                        DstresultPointless->dword8 = NativesContext.ArgRetDataArray.Array[(unsigned int)PointlessResultCount].d2;
                        DstresultPointless->dword10 = NativesContext.ArgRetDataArray.Array[(unsigned int)PointlessResultCount].WasDownBefore;
                        ResultCount = NativesContext.ResultCount;
                    } while (NativesContext.ResultCount);
                    ScriptVector_Mylast = ScriptVector___Mylast;
                }
                NewMainShThread.Object->ThreadIdParam = *(_DWORD*)NativesContext.pRetValues;
                NewMainShThread_Object = NewMainShThread.Object;
                ScriptVector__Myfirst_RefCountObj = ScriptVector__Myfirst->RefCountObj;
                ScriptVector__Myfirst_Object = ScriptVector__Myfirst->Object;
                if (ScriptVector__Myfirst_RefCountObj)
                    _InterlockedIncrement(&ScriptVector__Myfirst_RefCountObj->Count_8);
                NewMainShThread_Object_sh_script_RefCountObj = NewMainShThread_Object->sh_script.RefCountObj;
                ThreadIdParam = NewMainShThread_Object_sh_script_RefCountObj;
                NewMainShThread_Object->sh_script.RefCountObj = ScriptVector__Myfirst_RefCountObj;
                NewMainShThread_Object->sh_script.Object = ScriptVector__Myfirst_Object;
                if (ThreadIdParam)
                {
                    if (!_InterlockedDecrement(&ThreadIdParam->Count_8))
                    {
                        NewMainShThread_Object_sh_script_RefCountObj_1 = NewMainShThread_Object_sh_script_RefCountObj;
                        NewMainShThread_Object_sh_script_RefCountObj->Vftbl->RefCount8Release(NewMainShThread_Object_sh_script_RefCountObj);
                        if (!_InterlockedDecrement(&NewMainShThread_Object_sh_script_RefCountObj_1->Count_C))
                            NewMainShThread_Object_sh_script_RefCountObj->Vftbl->RefCountCRelease(NewMainShThread_Object_sh_script_RefCountObj);
                    }
                }
                NewMainShThread.Object->ThreadStartAddress = SCRIPT_MAIN;
                ThreadTree_Myhead_Parent_1 = ThreadTree._Myhead->_Parent;
                ThreadTree_Myhead_2 = ThreadTree._Myhead;
                NewMainShThread_Object_1 = NewMainShThread.Object;
                if (!ThreadTree_Myhead_Parent_1->_Isnil)
                {
                    ThreadIdParam = (std::_Ref_count_obj__core::sh_script__*)(unsigned int)NewMainShThread.Object->ThreadIdParam;
                    do
                    {
                        if (ThreadTree_Myhead_Parent_1->_MyValue.ThreadId >= (int)ThreadIdParam)
                        {
                            ThreadTree_Myhead_2 = ThreadTree_Myhead_Parent_1;
                            ThreadTree_Myhead_Parent_1 = ThreadTree_Myhead_Parent_1->_Left;
                        }
                        else
                        {
                            ThreadTree_Myhead_Parent_1 = ThreadTree_Myhead_Parent_1->_Right;
                        }
                    } while (!ThreadTree_Myhead_Parent_1->_Isnil);
                }
                if (ThreadTree_Myhead_2 == ThreadTree._Myhead
                    || NewMainShThread.Object->ThreadIdParam < ThreadTree_Myhead_2->_MyValue.ThreadId)
                {
                    MainshThread.RefCountObj = (std::_Ref_count_obj__core::sh_thread__*)NewMainShThread.Object;
                    ShThreadNode = GetThreadNode(
                        (__int64)ThreadIdParam,
                        (__int64)NewMainShThread.Object,
                        (MainRefCountObjStructForShThread*)&MainshThread.RefCountObj);
                    std::set::insertToThreadTree(
                        UnusedVar_2,
                        (std_ThreadTreeResult_std_pair*)&threadNodeinsertionResult.inserted,
                        ThreadTree_Myhead_2,
                        &ShThreadNode->_MyValue,
                        ShThreadNode);
                    ThreadTree_Myhead_2 = *(ThreadTreeNode**)&threadNodeinsertionResult.inserted;
                    NewMainShThread_Object_1 = NewMainShThread.Object;
                }
                NewMainShThread_RefCountObj = NewMainShThread.RefCountObj;
                if (NewMainShThread.RefCountObj)
                    _InterlockedIncrement(&NewMainShThread.RefCountObj->Count_8);
                ThreadTree_Myhead_2_MyValue_MainShThread_RefCountObj = ThreadTree_Myhead_2->_MyValue.MainShThread.RefCountObj;
                ShThreadRefCOutnObj2_2 = ThreadTree_Myhead_2_MyValue_MainShThread_RefCountObj;
                ThreadTree_Myhead_2->_MyValue.MainShThread.RefCountObj = NewMainShThread_RefCountObj;
                ThreadTree_Myhead_2->_MyValue.MainShThread.Object = NewMainShThread_Object_1;
                if (ShThreadRefCOutnObj2_2)
                {
                    if (!_InterlockedDecrement(&ShThreadRefCOutnObj2_2->Count_8))
                    {
                        ThreadTree_Myhead_2_MyValue_MainShThread_RefCountObj_1 = ThreadTree_Myhead_2_MyValue_MainShThread_RefCountObj;
                        ThreadTree_Myhead_2_MyValue_MainShThread_RefCountObj->Vftbl->RefCount8Release((std::_Ref_count_obj__core::sh_script__*)ThreadTree_Myhead_2_MyValue_MainShThread_RefCountObj);
                        if (!_InterlockedDecrement(&ThreadTree_Myhead_2_MyValue_MainShThread_RefCountObj_1->Count_C))
                            ThreadTree_Myhead_2_MyValue_MainShThread_RefCountObj->Vftbl->RefCountCRelease((std::_Ref_count_obj__core::sh_script__*)ThreadTree_Myhead_2_MyValue_MainShThread_RefCountObj);
                    }
                }
                NewMainShThread_RefCountObj_1 = NewMainShThread.RefCountObj;
                if (NewMainShThread.RefCountObj)
                {
                    if (!_InterlockedDecrement(&NewMainShThread.RefCountObj->Count_8))
                    {
                        NewMainShThread_RefCountObj_1->Vftbl->RefCount8Release((std::_Ref_count_obj__core::sh_script__*)NewMainShThread_RefCountObj_1);
                        if (!_InterlockedDecrement(&NewMainShThread_RefCountObj_1->Count_C))
                            NewMainShThread_RefCountObj_1->Vftbl->RefCountCRelease((std::_Ref_count_obj__core::sh_script__*)NewMainShThread_RefCountObj_1);
                    }
                }
                if (!ScriptVecNode->_Isnil)
                {
                    ScriptVecNode_Right = ScriptVecNode->_Right;
                    if (ScriptVecNode_Right->_Isnil)
                    {
                        for (i2 = ScriptVecNode->_Parent; !i2->_Isnil; i2 = i2->_Parent)
                        {
                            if (ScriptVecNode != i2->_Right)
                                break;
                            ScriptVecNode = i2;
                        }
                        ScriptVecNode = i2;
                    }
                    else
                    {
                        ScriptVecNode = ScriptVecNode->_Right;
                        for (i3 = ScriptVecNode_Right->_Left; !i3->_Isnil; i3 = i3->_Left)
                            ScriptVecNode = i3;
                    }
                }
                if (ScriptVecNode == ScriptVecHead)
                    goto Next;
            }
            NativsVersion = NativesVersion;
            if (!NativesVersion)
            {
                if (!DefaultNativeValue_From_0xAAAAAAAAAAAAAAAA)
                {
                    DefNativevalueIrrelevant_2 = 0xAAAAAAAAAAAAAAAAui64;
                    memset(&irrelevantnativesStruct, 0, 44);
                    irrelevantnativesStruct.f7 = 0i64;
                    irrelevantnativesStruct.f8 = 0i64;
                    irrelevantnativesStruct.flags_high = 1;
                    irrelevantnativesStruct.pHashInAddrOut = (uintptr_t*)&DefNativevalueIrrelevant_2;
                    ((void(__fastcall*)(GetNativeAddrFromHashStruct*))(MainAddressTable.GetNativeAddrFromHash.VER[GameVersion]
                        + RDR2_RVA))(&irrelevantnativesStruct);
                    DefaultNativeValue_From_0xAAAAAAAAAAAAAAAA = DefNativevalueIrrelevant_2;
                }
                _BG_SET_TEXT_SCALE = 0xA1253A3C870B6843ui64;
                memset(&irrelevantnativesStruct_1, 0, 0x2C);
                irrelevantnativesStruct_1.f7 = 0i64;
                irrelevantnativesStruct_1.f8 = 0i64;
                irrelevantnativesStruct_1.flags_high = 1;
                irrelevantnativesStruct_1.pHashInAddrOut = (uintptr_t*)&_BG_SET_TEXT_SCALE;
                ((void(__fastcall*)(GetNativeAddrFromHashStruct*))(MainAddressTable.GetNativeAddrFromHash.VER[GameVersion]
                    + RDR2_RVA))(&irrelevantnativesStruct_1);
                if (_BG_SET_TEXT_SCALE != DefaultNativeValue_From_0xAAAAAAAAAAAAAAAA)
                {
                    NativesVersion = 2;
                    goto Continue;
                }
                Old_SET_TEXT_SCALE = 0x4170B650590B3B00i64;
                memset(&irrelevantnativesStruct_2, 0, 44);
                irrelevantnativesStruct_2.f7 = 0i64;
                irrelevantnativesStruct_2.f8 = 0i64;
                irrelevantnativesStruct_2.flags_high = 1;
                irrelevantnativesStruct_2.pHashInAddrOut = (uintptr_t*)&Old_SET_TEXT_SCALE;
                ((void(__fastcall*)(GetNativeAddrFromHashStruct*))(MainAddressTable.GetNativeAddrFromHash.VER[GameVersion]
                    + RDR2_RVA))(&irrelevantnativesStruct_2);
                if (Old_SET_TEXT_SCALE != DefaultNativeValue_From_0xAAAAAAAAAAAAAAAA)
                {
                    NativesVersion = 1;
                    goto OldCase;
                }
                NativsVersion = NativesVersion;
                if (!NativesVersion)
                    SCRIPT_HOOK_RDR2_CRITICAL_ERROR("FATAL: Can't determinate natives version");
            }
            if (NativsVersion == 2)
            {
            Continue:
                START_NEW_SCRIPT_WITH_NAME_HASH_2 = (__int64(__fastcall*)(_QWORD))0xEB1C67C3A5333A92i64;
                memset(&irrelevantnativesStruct_3, 0, 44);
                irrelevantnativesStruct_3.f7 = 0i64;
                irrelevantnativesStruct_3.f8 = 0i64;
                irrelevantnativesStruct_3.flags_high = 1;
                irrelevantnativesStruct_3.pHashInAddrOut = (uintptr_t*)&START_NEW_SCRIPT_WITH_NAME_HASH_2;
                ((void(__fastcall*)(GetNativeAddrFromHashStruct*))(MainAddressTable.GetNativeAddrFromHash.VER[GameVersion]
                    + RDR2_RVA))(&irrelevantnativesStruct_3);
                START_NEW_SCRIPT_WITH_NAME_HASH_1 = START_NEW_SCRIPT_WITH_NAME_HASH_2;
            }
            else
            {
            OldCase:
                START_NEW_SCRIPT_WITH_NAME_HASH_Old = (__int64(__fastcall*)(_QWORD))0xEB1C67C3A5333A92i64;
                memset(&irrelevantnativesStruct_4, 0, 44);
                irrelevantnativesStruct_4.f7 = 0i64;
                irrelevantnativesStruct_4.f8 = 0i64;
                irrelevantnativesStruct_4.flags_high = 1;
                irrelevantnativesStruct_4.pHashInAddrOut = (uintptr_t*)&START_NEW_SCRIPT_WITH_NAME_HASH_Old;
                ((void(__fastcall*)(GetNativeAddrFromHashStruct*))(MainAddressTable.GetNativeAddrFromHash.VER[GameVersion]
                    + RDR2_RVA))(&irrelevantnativesStruct_4);
                START_NEW_SCRIPT_WITH_NAME_HASH_1 = START_NEW_SCRIPT_WITH_NAME_HASH_Old;
            }
            AppendNativeToVec(0xEB1C67C3A5333A92ui64, (uintptr_t)START_NEW_SCRIPT_WITH_NAME_HASH_1);
            goto StartNewScript;
        }
    Next:
        ++ScriptVector__Myfirst;
    }
    *(_QWORD*)(RDR2RVA_1 + ThreadTableRVA) = main;
    SET_SCRIPT_WITH_NAME_audiotest_HASH_AS_NO_LONGER_NEEDED();
    ThreadTableCopyToCheck = ThreadTableCopyToStore;
    *(_QWORD*)(RDR2RVA_1 + ThreadTableRVA) = ThreadTableCopyToStore;
    *ThreadTableNotEmptyBool = ThreadTableCopyToCheck != 0i64;
    ScriptHook_Log_Message("CORE: Created %d threads (including control)", ThreadTree._Mysize);
    CoreOrigFuncReturnValue = CoreOrigFunc_1(main, a2);
    sh_thread___RefCountObj = sh_thread__.RefCountObj;
    if (sh_thread__.RefCountObj)
    {
        if (!_InterlockedDecrement(&sh_thread__.RefCountObj->Count_8))
        {
            sh_thread___RefCountObj->Vftbl->RefCount8Release((std::_Ref_count_obj__core::sh_script__*)sh_thread___RefCountObj);
            if (!_InterlockedDecrement(&sh_thread___RefCountObj->Count_C))
                sh_thread___RefCountObj->Vftbl->RefCountCRelease((std::_Ref_count_obj__core::sh_script__*)sh_thread___RefCountObj);
        }
    }
    return CoreOrigFuncReturnValue;
}

ATOM RegisterClassW_Hook(WNDCLASSW* pClass)
{
    const std::wstring sgaWindowString = L"sgaWindow";

    if (sgaWindowString == pClass->lpszClassName)
    {
        OriginalWinProc = pClass->lpfnWndProc;
        pClass->lpfnWndProc = WndProchook;
    }
    return RegisterClassW(pClass);
}

struct Script_Pool_Entry
{
    unsigned __int8* padding;
    unsigned __int8* ScriptHandleBaseAddress;
};

struct Pool
{
    uintptr_t qword0;
    char* HandleTable;
    char* CountTable;
    int PoolEntrySize;
    DWORD HandleSize;
    uintptr_t Unk1;
    uintptr_t UnkSize;
    uintptr_t Unk3;
};

struct PoolTableEntry
{
    DWORD hashid;
    DWORD RetValue;
    PoolTableEntry* Next;
};

struct Pool_Main
{
    uintptr_t unk0;
    PoolTableEntry** PoolTable;
    DWORD Size;
    DWORD unkd;
};

Pool* ScriptPool0x7311A8D7;
Pool* ObjectsPool0x39958261;
Pool* PedsPool0x8DA12117;
Pool* PickupsPool0xAD2BCC1A;
Pool* VehiclesPool0xF820AAA9;

DWORD __fastcall Update_Pool_Hook(Pool_Main* PoolUpd, unsigned int hashid, unsigned int RetValue, Pool* pPool)
{
    unsigned int Size; // r8d
    PoolTableEntry* Entry; // rcx

    Size = PoolUpd->Size;
    if (Size)
    {
        Entry = PoolUpd->PoolTable[hashid % Size];
        if (Entry)
        {
            while (Entry->hashid != hashid)
            {
                Entry = Entry->Next;
                if (!Entry)
                    goto Exit;
            }
            if (Entry->RetValue != -1)
                RetValue = Entry->RetValue;
        }
    }
Exit:
    switch (hashid)
    {
    case 0x1182232Cu:
        ScriptHook_Log_Message("INIT: Pool 1 extended");
        break;
    case 0x3EEA2DA9u:
        ScriptHook_Log_Message("INIT: Pool 4 extended");
        return RetValue;
    case 0x7311A8D7u:
        ScriptHook_Log_Message("INIT: Pool 2 extended");
        ScriptPool0x7311A8D7 = pPool;
        return RetValue;
    case 0xEF7129CB:
        ScriptHook_Log_Message("INIT: Pool 3 extended");
        return RetValue;
    case 0x39958261u:
        ObjectsPool0x39958261 = pPool;
        return RetValue;
    case 0x8DA12117:
        PedsPool0x8DA12117 = pPool;
        return RetValue;
    case 0xAD2BCC1A:
        PickupsPool0xAD2BCC1A = pPool;
        return RetValue;
    case 0xF820AAA9:
        VehiclesPool0xF820AAA9 = pPool;
        return RetValue;
    }
    return RetValue;
}

eGameVersion getGameVersion()
{
    return (eGameVersion)GameVersion;
}
unsigned __int64* __fastcall getGlobalPtr(int i)
{
    return (unsigned __int64*)(*(uintptr_t*)(MainAddressTable.ga4.VER[GameVersion] + 8i64 * ((i >> 18) & 0x3F) + RDR2_RVA)
        + 8i64 * (i & 0x3FFFF));
}

unsigned __int8* __fastcall getScriptHandleBaseAddress(int index)
{
    int Offset; // r8d
    Script_Pool_Entry* pScriptEntry; // rax

    if (index != -1
        && ScriptPool0x7311A8D7
        && (Offset = index >> 8, index >> 8 < ScriptPool0x7311A8D7->PoolEntrySize)
        && ScriptPool0x7311A8D7->CountTable[Offset] >= 0
        && (pScriptEntry = (Script_Pool_Entry*)&ScriptPool0x7311A8D7->HandleTable[Offset * ScriptPool0x7311A8D7->HandleSize]) != 0i64)
    {
        return pScriptEntry->ScriptHandleBaseAddress;
    }
    else
    {
        return 0i64;
    }
}

void keyboardHandlerRegister(KeyboardHandler KH) {
    if (std::find(KeyboardHandlerVector.begin(), KeyboardHandlerVector.end(), KH) != KeyboardHandlerVector.end()) {
        SCRIPT_HOOK_RDR2_CRITICAL_ERROR("FATAL: Keyboard handler is already registered 0x%016llX", KH);
        return;
    }

    KeyboardHandlerVector.push_back(KH);
}

void keyboardHandlerUnregister(KeyboardHandler KH) {
    auto it = std::find(KeyboardHandlerVector.begin(), KeyboardHandlerVector.end(), KH);

    if (it == KeyboardHandlerVector.end()) {
        // Handler not found, handle error
        SCRIPT_HOOK_RDR2_CRITICAL_ERROR("FATAL: Trying to unregister unknown keyboard handler 0x%016llX", KH);
        return;
    }

    KeyboardHandlerVector.erase(it);
}

uintptr_t* nativeCall(void)
{
    DWORD cc; // eax
    DWORD c; // rax
    ResultDest* ResultDstEntry; // rcx

    NativesContext.GamePart.Native(&NativesContext.GamePart);
    for (cc = NativesContext.GamePart.ResultCount;  NativesContext.GamePart.ResultCount; cc = NativesContext.GamePart.ResultCount)
    {
        c = cc - 1;
        NativesContext.GamePart.ResultCount = c;
        ResultDstEntry = NativesContext.GamePart.ResultDestinations[c];
        ResultDstEntry->Dst0 = NativesContext.GamePart.ResultsSrc.Array[c].d1;
        ResultDstEntry->Dst8 = NativesContext.GamePart.ResultsSrc.Array[c].d2;
        ResultDstEntry->Dst10 = NativesContext.GamePart.ResultsSrc.Array[c].d3;
    }
    return  NativesContext.GamePart.pRetValues;
}

__int64 __fastcall sub_180008540(__int64 a1)
{
    int* v1; // rax
    bool v2; // zf
    bool v3; // sf
    __int64 result; // rax

    v1 = *(int**)(a1 + 16);
    v2 = *v1 == 0;
    v3 = *v1 < 0;
    result = RDR2_RVA;
    *(BYTE*)(MainAddressTable.ga8.VER[GameVersion] + RDR2_RVA + 0x1E) = !v3 && !v2;
    return result;
}

DWORD* __fastcall sub_180008510(__int64 a1)
{
    DWORD* result; // rax
    uintptr_t v2; // r8
    char v3; // cl

    result = *(DWORD**)(a1 + 16);
    v2 = RDR2_RVA + MainAddressTable.ga8.VER[GameVersion];
    v3 = *(BYTE*)(v2 + 0x1C);
    if (*result)
        v3 = 0;
    *(BYTE*)(v2 + 0x1C) = v3;
    return result;
}

void __fastcall nativeInit(uintptr_t Hash)
{
    NativeFunc NativeAddr; // rbx
    uintptr_t Hash_1; // rcx
    NativeFunc NativeAddrFromHash_Wrapper; // rax

    NativeAddr = (NativeFunc)GetNativeFromIndex8bits(Hash);
    if (!NativeAddr)
    {
        if (GetNativesVer() != 2)
            goto Default;
        switch (Hash)
        {
        case 0x1BE39DBAA7263CA5ui64:
            NativeAddr = (NativeFunc)sub_180008540;
            break;
        case 0x4170B650590B3B00ui64:
            Hash_1 = 0xA1253A3C870B6843ui64;
            goto GetNative;
        case 0x50A41AD966910F03ui64:
            Hash_1 = 0x16FA5CE47F184F1Ei64;
            goto GetNative;
        case 0xBE5261939FBECB8Cui64:
            NativeAddr = (NativeFunc)sub_180008510;
            break;
        case 0xD79334A4BB99BAD1ui64:
            Hash_1 = 0x16794E044C9EFB58i64;
        GetNative:
            NativeAddr = (NativeFunc)GetNativeAddrFromHash_Wrapper(Hash_1);
            break;
        default:
        Default:
            Hash_1 = Hash;
            goto GetNative;
        }
        AppendNativeToVec(Hash, (uintptr_t)NativeAddr);
    }
    NativeAddrFromHash_Wrapper = (NativeFunc)DefaultNativeValue_From_0xAAAAAAAAAAAAAAAA;
    if (!DefaultNativeValue_From_0xAAAAAAAAAAAAAAAA)
    {
        NativeAddrFromHash_Wrapper = (NativeFunc)GetNativeAddrFromHash_Wrapper(0xAAAAAAAAAAAAAAAAui64);
        DefaultNativeValue_From_0xAAAAAAAAAAAAAAAA = (__int64)NativeAddrFromHash_Wrapper;
    }
    if (!NativeAddr || NativeAddr == NativeAddrFromHash_Wrapper)
        SCRIPT_HOOK_RDR2_CRITICAL_ERROR("FATAL: Can't find native 0x%016llX", Hash);
    memset(&NativesContext, 0, sizeof(NativesContext));
    NativesContext.GamePart.Native = NativeAddr;
    NativesContext.GamePart.pRetValues = NativesContext.RetValues;
    NativesContext.GamePart.pArgs = NativesContext.Args;
}

void __fastcall nativePush64(uintptr_t Arg)
{
    NativesContext.GamePart.pArgs[NativesContext.GamePart.ArgCount++] = Arg;
}

void __fastcall scriptRegister(HMODULE hModule, LP_SCRIPT_MAIN SCRIPT_MAIN)
{
    std::shared_ptr<core_sh_script> sh_script; // [rsp+30h] [rbp-D0h] BYREF

    // Get the module file name
    char TempCDllPath[MAX_PATH];
    GetModuleFileNameA(hModule, TempCDllPath, sizeof(TempCDllPath));

    std::string DllPath(TempCDllPath);

    // Extract the DllName using std::filesystem
    std::string DllName = std::filesystem::path(DllPath).filename().string();

    ScriptHook_Log_Message("INIT: Registering script '%s' (0x%016llX)", DllName, SCRIPT_MAIN);

    for (const auto& Script : ScriptVector) {
        const auto& MainScriptsSet = Script->MainScriptsSet;

        if (MainScriptsSet.find(SCRIPT_MAIN) != MainScriptsSet.end()) {
            SCRIPT_HOOK_RDR2_CRITICAL_ERROR("FATAL: Script is already registered '%s' (0x%016llX)", DllName, SCRIPT_MAIN);
            return;  // Script is already registered
        }
    }
           
    sh_script->ScriptBase = hModule;
    sh_script->ScriptPath = DllPath;
    sh_script->ScriptName = DllName;
    sh_script->MainScriptsSet.insert(SCRIPT_MAIN);

    ScriptVector.push_back(sh_script);
    ScriptPathsSet.insert(DllPath);
}

void __fastcall scriptRegisterAdditionalThread(HMODULE hModule, LP_SCRIPT_MAIN SCRIPT_MAIN)
{

    auto it = std::find_if(ScriptVector.begin(), ScriptVector.end(), [hModule, SCRIPT_MAIN](const std::shared_ptr<core_sh_script>& Script) {
        return Script->ScriptBase == hModule &&
            Script->MainScriptsSet.find(SCRIPT_MAIN) == Script->MainScriptsSet.end();
    });

    if (it == ScriptVector.end()) {
        // Script not found, handle error
        SCRIPT_HOOK_RDR2_CRITICAL_ERROR("FATAL: Trying to register additional thread 0x%016llX to unk script", SCRIPT_MAIN);
        return;
    }
   
    ScriptHook_Log_Message("INIT: Registering additional script thread '%s' (0x%016llX)", it->get()->ScriptName, SCRIPT_MAIN);
    it->get()->MainScriptsSet.insert(SCRIPT_MAIN);
}

void __fastcall scriptUnregister(LP_SCRIPT_MAIN SCRIPT_MAIN)
{
    auto it = std::find_if(ScriptVector.begin(), ScriptVector.end(), [SCRIPT_MAIN](const std::shared_ptr<core_sh_script>& Script) {
        return Script->MainScriptsSet.find(SCRIPT_MAIN) != Script->MainScriptsSet.end();
    });

    if (it == ScriptVector.end()) {
        // Script not found, handle error
        SCRIPT_HOOK_RDR2_CRITICAL_ERROR("FATAL: Trying to unregister unk script using main 0x%016llX", SCRIPT_MAIN);
        return;
    }
    ScriptHook_Log_Message("UNINIT: Unregistering script '%s'", it->get()->ScriptName);

    ScriptVector.erase(it);
}

void __fastcall scriptUnregister(HMODULE hModule)
{
    auto it = std::find_if(ScriptVector.begin(), ScriptVector.end(), [hModule](const std::shared_ptr<core_sh_script>& Script) {
        return Script->ScriptBase == hModule;
    });

    if (it == ScriptVector.end()) {
        // Script not found, handle error
        SCRIPT_HOOK_RDR2_CRITICAL_ERROR("FATAL: Trying to unregister unk script using module handle 0x%016llX", hModule);
        return;
    }

    ScriptHook_Log_Message("UNINIT: Unregistering script '%s'", it->get()->ScriptName);

    ScriptVector.erase(it);
}

void __fastcall scriptWait(unsigned long WaitTime)
{
    auto ga3 = MainAddressTable.ga3.VER[GameVersion];
    auto ThreadTable = *(struct_ThreadTable**)(RDR2_RVA + ga3);
    if (!ThreadTable)
    {
        // Thread not found, handle error
        SCRIPT_HOOK_RDR2_CRITICAL_ERROR("FATAL: scriptWait() called on unk thread");
        return;
    }

    DWORD ThreadId = ThreadTable->ThreadId;

    const auto it = std::find_if(ThreadTree.begin(), ThreadTree.end(), [ThreadId](const ThreadTreeMyValue& Thread) {
        return Thread.ThreadId == ThreadId;
    });

    if (it == ThreadTree.end()) {
        // Thread not found, handle error
        SCRIPT_HOOK_RDR2_CRITICAL_ERROR("FATAL: scriptWait() called on unk thread");
        return;
    }

    if (ThreadTable->Count != 2)
    {
        auto it = std::find_if(ThreadTree.begin(), ThreadTree.end(), [ThreadId](const ThreadTreeMyValue& Thread) {
            return Thread.ThreadId == ThreadId;
        });

        if (it == ThreadTree.end()) {
            ThreadTreeMyValue MyValue{};
            MyValue.ThreadId = ThreadId;
            it = ThreadTree.insert(MyValue).first;
        }
       
        it->sh_thread->WaitUntilThisTime = WaitTime + GetTickCount();
        ThreadTable->Count = 1;
    }
    SwitchToFiber(lpFiber);
}
int __fastcall worldGetAllObjects(int* Array, int Size)
{
    Pool* ScriptPool; // r9
    unsigned int Count; // ebx
    __int64 Size_1; // r10
    int (__stdcall * GetObjectsByHandleFunc)(char*); // r12
    Pool* ObjectsPool; // r8
    int ObjectsPoolEntrySize; // edx
    int index; // edi
    __int64 Size_2; // r14
    __int64 CountTableIndex; // rbp
    __int64 ArrayIndex; // rsi
    char* ObjectHandle; // rcx
    int Object; // eax

    ScriptPool = ScriptPool0x7311A8D7;
    Count = 0;
    Size_1 = Size;
    GetObjectsByHandleFunc = (int (__stdcall*)(char*))(MainAddressTable.ga11.VER[GameVersion] + RDR2_RVA);
    if (!ScriptPool0x7311A8D7)
        return 0i64;
    ObjectsPool = ObjectsPool0x39958261;
    if (!ObjectsPool0x39958261)
        return 0i64;
    ObjectsPoolEntrySize = ObjectsPool0x39958261->PoolEntrySize;
    index = 0;
    if (ObjectsPoolEntrySize <= 0)
        return 0i64;
    Size_2 = Size_1;
    CountTableIndex = 0i64;
    ArrayIndex = 0i64;
    do
    {
        if (ArrayIndex >= Size_2 || ScriptPool->PoolEntrySize - (ScriptPool->UnkSize & 0x3FFFFFFF) <= 0x100)
            break;
        if (index < ObjectsPoolEntrySize && ObjectsPool->CountTable[CountTableIndex] >= 0)
        {
            ObjectHandle = &ObjectsPool->HandleTable[index * ObjectsPool->HandleSize];
            if (ObjectHandle)
            {
                Object = GetObjectsByHandleFunc(ObjectHandle);
                ScriptPool = ScriptPool0x7311A8D7;
                ObjectsPool = ObjectsPool0x39958261;
                Array[ArrayIndex] = Object;
                ++Count;
                ++ArrayIndex;
            }
        }
        ObjectsPoolEntrySize = ObjectsPool->PoolEntrySize;
        ++index;
        ++CountTableIndex;
    } while (index < ObjectsPoolEntrySize);
    return Count;
}
int __fastcall worldGetAllPeds(int* Array, int Size)
{
    Pool* ScriptPool; // r9
    unsigned int Count; // ebx
    __int64 Size_1; // r10
    int(__stdcall * GetObjectFromHandleFunc)(char*); // r12
    Pool* PedsPool; // r8
    int PoolEntrySize; // edx
    int i; // edi
    __int64 Size_2; // r14
    __int64 CountTableIndex; // rbp
    __int64 ArrayIndex; // rsi
    char* PedHandle; // rcx
    int Ped; // eax

    ScriptPool = ScriptPool0x7311A8D7;
    Count = 0;
    Size_1 = Size;
    GetObjectFromHandleFunc = (int(__stdcall*)(char*))(MainAddressTable.ga11.VER[GameVersion] + RDR2_RVA);
    if (!ScriptPool0x7311A8D7)
        return 0i64;
    PedsPool = PedsPool0x8DA12117;
    if (!PedsPool0x8DA12117)
        return 0i64;
    PoolEntrySize = PedsPool0x8DA12117->PoolEntrySize;
    i = 0;
    if (PoolEntrySize <= 0)
        return 0i64;
    Size_2 = Size_1;
    CountTableIndex = 0i64;
    ArrayIndex = 0i64;
    do
    {
        if (ArrayIndex >= Size_2 || ScriptPool->PoolEntrySize - (ScriptPool->UnkSize & 0x3FFFFFFF) <= 0x100)
            break;
        if (i < PoolEntrySize && PedsPool->CountTable[CountTableIndex] >= 0)
        {
            PedHandle = &PedsPool->HandleTable[i * PedsPool->HandleSize];
            if (PedHandle)
            {
                Ped = GetObjectFromHandleFunc(PedHandle);
                ScriptPool = ScriptPool0x7311A8D7;
                PedsPool = PedsPool0x8DA12117;
                Array[ArrayIndex] = Ped;
                ++Count;
                ++ArrayIndex;
            }
        }
        PoolEntrySize = PedsPool->PoolEntrySize;
        ++i;
        ++CountTableIndex;
    } while (i < PoolEntrySize);
    return Count;
}
int __fastcall worldGetAllPickups(int* Array, int Size)
{
    Pool* ScriptPool; // r9
    unsigned int Count; // ebx
    __int64 Size_1; // r10
    int(__stdcall * GetObjectFromHandleFunc)(char*); // r12
    Pool* PickUpsPool; // r8
    int PoolEntrySize; // edx
    int i; // edi
    __int64 Size_2; // r14
    __int64 CountTableIndex; // rbp
    __int64 ArrayIndex; // rsi
    char* PickupHandle; // rcx
    int PickupObject; // eax

    ScriptPool = ScriptPool0x7311A8D7;
    Count = 0;
    Size_1 = Size;
    GetObjectFromHandleFunc = (int(__stdcall*)(char*))(MainAddressTable.ga11.VER[GameVersion] + RDR2_RVA);
    if (!ScriptPool0x7311A8D7)
        return 0i64;
    PickUpsPool = PickupsPool0xAD2BCC1A;
    if (!PickupsPool0xAD2BCC1A)
        return 0i64;
    PoolEntrySize = PickupsPool0xAD2BCC1A->PoolEntrySize;
    i = 0;
    if (PoolEntrySize <= 0)
        return 0i64;
    Size_2 = Size_1;
    CountTableIndex = 0i64;
    ArrayIndex = 0i64;
    do
    {
        if (ArrayIndex >= Size_2 || ScriptPool->PoolEntrySize - (ScriptPool->UnkSize & 0x3FFFFFFF) <= 256)
            break;
        if (i < PoolEntrySize && PickUpsPool->CountTable[CountTableIndex] >= 0)
        {
            PickupHandle = &PickUpsPool->HandleTable[i * PickUpsPool->HandleSize];
            if (PickupHandle)
            {
                PickupObject = GetObjectFromHandleFunc(PickupHandle);
                ScriptPool = ScriptPool0x7311A8D7;
                PickUpsPool = PickupsPool0xAD2BCC1A;
                Array[ArrayIndex] = PickupObject;
                ++Count;
                ++ArrayIndex;
            }
        }
        PoolEntrySize = PickUpsPool->PoolEntrySize;
        ++i;
        ++CountTableIndex;
    } while (i < PoolEntrySize);
    return Count;
}
int __fastcall worldGetAllVehicles(int* Array, int Size)
{
    Pool* ScriptPool; // r9
    unsigned int Count; // ebx
    __int64 Size_1; // r10
    int(__stdcall * GetObjectFromHandleFunc)(char*); // r12
    Pool* VehiclesPool; // r8
    int PoolEntrySize; // edx
    int i; // edi
    __int64 Size_2; // r14
    __int64 CountTableIndex; // rbp
    __int64 ArrayIndex; // rsi
    char* VehicleHandle; // rcx
    int VehicleObject; // eax

    ScriptPool = ScriptPool0x7311A8D7;
    Count = 0;
    Size_1 = Size;
    GetObjectFromHandleFunc = (int(__stdcall*)(char*))(MainAddressTable.ga11.VER[GameVersion] + RDR2_RVA);
    if (!ScriptPool0x7311A8D7)
        return 0i64;
    VehiclesPool = VehiclesPool0xF820AAA9;
    if (!VehiclesPool0xF820AAA9)
        return 0i64;
    PoolEntrySize = VehiclesPool0xF820AAA9->PoolEntrySize;
    i = 0;
    if (PoolEntrySize <= 0)
        return 0i64;
    Size_2 = Size_1;
    CountTableIndex = 0i64;
    ArrayIndex = 0i64;
    do
    {
        if (ArrayIndex >= Size_2 || ScriptPool->PoolEntrySize - (ScriptPool->UnkSize & 0x3FFFFFFF) <= 256)
            break;
        if (i < PoolEntrySize && VehiclesPool->CountTable[CountTableIndex] >= 0)
        {
            VehicleHandle = &VehiclesPool->HandleTable[i * VehiclesPool->HandleSize];
            if (VehicleHandle)
            {
                VehicleObject = GetObjectFromHandleFunc(VehicleHandle);
                ScriptPool = ScriptPool0x7311A8D7;
                VehiclesPool = VehiclesPool0xF820AAA9;
                Array[ArrayIndex] = VehicleObject;
                ++Count;
                ++ArrayIndex;
            }
        }
        PoolEntrySize = VehiclesPool->PoolEntrySize;
        ++i;
        ++CountTableIndex;
    } while (i < PoolEntrySize);
    return Count;
}

void __stdcall InitHooks()
{
    uintptr_t Original_CoreFunc; // rbx
    DWORD oldprot; // r8d
    uintptr_t pRegisterClassW_Import; // rbx
    DWORD oldprot_1; // r8d
    uintptr_t Update_Pool_Func; // rbx
    DWORD oldprot_2; // r8d
    DWORD flOldProtect; // [rsp+30h] [rbp+8h] BYREF

    Original_CoreFunc = RDR2_RVA + MainAddressTable.ga2.VER[GameVersion];
    Original_CoreFuncAddr = *(uintptr_t*)(Original_CoreFunc + 0x10);
    VirtualProtect((LPVOID)(Original_CoreFunc + 0x10), 8ui64, 0x40u, &flOldProtect);
    oldprot = flOldProtect;
    *(uintptr_t*)(Original_CoreFunc + 0x10) = (uintptr_t)Core_Hook;
    VirtualProtect((LPVOID)(Original_CoreFunc + 0x10), 8ui64, oldprot, &flOldProtect);
    pRegisterClassW_Import = MainAddressTable.ga7.VER[GameVersion] + RDR2_RVA;
    VirtualProtect((LPVOID)pRegisterClassW_Import, 8ui64, 0x40u, &flOldProtect);
    oldprot_1 = flOldProtect;
    *(uintptr_t*)pRegisterClassW_Import = (uintptr_t)RegisterClassW_Hook;
    VirtualProtect((LPVOID)pRegisterClassW_Import, 8ui64, oldprot_1, &flOldProtect);
    Update_Pool_Func = (uintptr_t)(MainAddressTable.ga10.VER[GameVersion] + RDR2_RVA);
    VirtualProtect((LPVOID)Update_Pool_Func, 0x10ui64, 0x40u, &flOldProtect);
    oldprot_2 = flOldProtect;
    *(uintptr_t*)((char*)Update_Pool_Func + 5) = (uintptr_t)Update_Pool_Hook;
    *(DWORD*)Update_Pool_Func = 0x48C88B4C;
    *((BYTE*)Update_Pool_Func + 4) = 0xB8;
    *(WORD*)((char*)Update_Pool_Func + 13) = 0xC350;
    VirtualProtect((LPVOID)Update_Pool_Func, 0x10ui64, oldprot_2, &flOldProtect);
}

void Init_Start()
{
    char DevFileExists; // al
    FILE* Stream; // [rsp+0x40] [rbp+0x8] BYREF

    ScriptHook_Log_Message("INIT: Started");
    RDR2_RVA = (uintptr_t)GetModuleHandleA(0i64) - 0x140000000i64;
    GameVersion = Get_GameVersion();
    if (GameVersion == -1)
    {
        ScriptHook_Log_Message("FATAL: Unknown game version");
        if (MessageBoxA(
            0i64,
            "FATAL: Unknown game version, check http://dev-c.com for updates\n"
            "\n"
            "WOULD YOU LIKE TO CHECK DOWNLOAD PAGE NOW ?\n"
            "\n"
            "http://dev-c.com/rdr2/scripthookrdr2/\n"
            "\n"
            "Supported versions:\n"
            "1.0.1207.58/80, 1.0.1232.13/17, 1.0.1311.12, 1.0.1436.25/31\n"
            "1.0.1491.16/17\n"
            "\n",
            "SCRIPT HOOK RDR 2 CRITICAL ERROR",
            0x14u) == IDYES)
            ShellExecuteA(0i64, 0i64, "http://dev-c.com/rdr2/scripthookrdr2/", 0i64, 0i64, SW_SHOW);
        ExitProcess(0);
    }
    CheckForUpdates();
    memset(&VkStatesArray, 0, sizeof(VkStatesArray));
    InitHooks();
    Stream = 0i64;
    fopen_s(&Stream, "ScriptHookRDR2.dev", "rb");
    if (Stream)
    {
        fclose(Stream);
        DevFileExists = 1;
    }
    else
    {
        DevFileExists = 0;
    }
    ScriptHookRDR2_dev_Exists = DevFileExists;
    ScriptHook_Log_Message("INIT: Success, game version is %s", GameVersionTable[GameVersion]);
}

void ScriptHook_Log_Message(const char* Format, ...)
{
    const char* LastMessage_Buf; // rax
    char* Message_Buf_rel_LastMessageBuf; // r8
    int Message_Buf_Char; // ecx
    int NotEqual; // edx
    size_t FinalMsgBuf_cc; // rbx
    size_t MessageBuf_cc; // r8
    const void* LogBuf; // rcx
    FILE* Stream; // [rsp+0x30] [rbp-0xD0] BYREF
    __time64_t Time; // [rsp+0x38] [rbp-0xC8] BYREF
    struct tm Tm; // [rsp+0x40] [rbp-0xC0] BYREF
    char Message_Buf[1024]; // [rsp+0x70] [rbp-0x90] BYREF
    char FinalMsgBuf[1024]; // [rsp+0x470] [rbp+0x370] BYREF
    va_list ArgList; // [rsp+0x8A8] [rbp+0x7A8] BYREF
    static std::string LastMessageStdString;
    static std::string ScriptHookRDR2_LogString;

    va_start(ArgList, Format);
    vsprintf_s(Message_Buf, 0x400ui64, Format, ArgList);
    LastMessage_Buf = LastMessageStdString.c_str();
    Message_Buf_rel_LastMessageBuf = (char*)(Message_Buf - LastMessage_Buf);
    do
    {
        Message_Buf_Char = (unsigned __int8)Message_Buf_rel_LastMessageBuf[(__int64)LastMessage_Buf];
        NotEqual = (unsigned __int8)*LastMessage_Buf - Message_Buf_Char;
        if (NotEqual)
            break;
        ++LastMessage_Buf;
    } while (Message_Buf_Char);
    if (NotEqual)
    {
        FinalMsgBuf_cc = -1i64;
        if (Message_Buf[0])
        {
            MessageBuf_cc = -1i64;
            do
                ++MessageBuf_cc;
            while (Message_Buf[MessageBuf_cc]);
        }
        else
        {
            MessageBuf_cc = 0i64;
        }
        LastMessageStdString.assign(Message_Buf, MessageBuf_cc);

        if (Message_Buf[0] == '/' && Message_Buf[1] == '/')
        {
            vsprintf_s_0x400(FinalMsgBuf, "%s\n", Message_Buf);
        }
        else
        {
            Time = _time64(0i64);
            _localtime64_s(&Tm, &Time);
            vsprintf_s_0x400(
                FinalMsgBuf,
                "[%02d:%02d:%02d] %s\n",
                (unsigned int)Tm.tm_hour,
                (unsigned int)Tm.tm_min,
                Tm.tm_sec,
                Message_Buf);
        }
        if (FinalMsgBuf[0])
        {
            do
                ++FinalMsgBuf_cc;
            while (FinalMsgBuf[FinalMsgBuf_cc]);
        }
        else
        {
            FinalMsgBuf_cc = 0i64;
        }
        ScriptHookRDR2_LogString.append(FinalMsgBuf, FinalMsgBuf_cc);
        Stream = 0i64;
        fopen_s(&Stream, "ScriptHookRDR2.log", "wb");
        if (Stream)
        {
            LogBuf = ScriptHookRDR2_LogString.c_str();
            fwrite(LogBuf, 1ui64, ScriptHookRDR2_LogString.size(), Stream);
            fflush(Stream);
            fclose(Stream);
        }
    }
}
