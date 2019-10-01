#if _WIN32
#ifndef WIN32_LEAN_AND_MEAN
#define WIN32_LEAN_AND_MEAN 1
#endif
#ifndef NOMINMAX
#define NOMINMAX
#endif
#include <windows.h>
#include <io.h>
#include <DbgHelp.h>
#include <TlHelp32.h>
#elif defined(__SWITCH__)
#include <cstring>
#include "nxstl/thread"
#else
#include <sys/ioctl.h>
#include <unistd.h>
#include <dlfcn.h>
#include <cxxabi.h>
#include <cstring>
#if __linux__
#include <sys/prctl.h>
#endif
#endif

#include <fcntl.h>
#include <chrono>
#include <mutex>
#include <thread>
#include <string>
#include <unordered_map>
#include <cstdio>
#include <cinttypes>
#include <signal.h>
#include "logvisor/logvisor.hpp"

/* ANSI sequences */
#define RED "\x1b[1;31m"
#define YELLOW "\x1b[1;33m"
#define GREEN "\x1b[1;32m"
#define MAGENTA "\x1b[1;35m"
#define CYAN "\x1b[1;36m"
#define BOLD "\x1b[1m"
#define NORMAL "\x1b[0m"

#if _WIN32
#define FOREGROUND_WHITE FOREGROUND_RED | FOREGROUND_GREEN | FOREGROUND_BLUE
#endif

#pragma GCC diagnostic ignored "-Wformat-truncation"

void logvisorBp() {}

namespace logvisor {
static Module Log("logvisor");

static std::unordered_map<std::thread::id, const char*> ThreadMap;

static void AddThreadToMap(const char* name) {
  auto lk = LockLog();
  ThreadMap[std::this_thread::get_id()] = name;
}

void RegisterThreadName(const char* name) {
  AddThreadToMap(name);
#if __APPLE__
  pthread_setname_np(name);
#elif __linux__
  prctl(PR_SET_NAME, name);
#elif _MSC_VER
  struct {
    DWORD dwType;     // Must be 0x1000.
    LPCSTR szName;    // Pointer to name (in user addr space).
    DWORD dwThreadID; // Thread ID (-1=caller thread).
    DWORD dwFlags;    // Reserved for future use, must be zero.
  } info = {0x1000, name, (DWORD)-1, 0};
  __try {
    RaiseException(0x406D1388, 0, sizeof(info) / sizeof(ULONG_PTR), (ULONG_PTR*)&info);
  } __except (EXCEPTION_EXECUTE_HANDLER) {}
#endif
}

#if _WIN32
#pragma comment(lib, "Dbghelp.lib")

#if defined(WINAPI_FAMILY) && WINAPI_FAMILY != WINAPI_FAMILY_DESKTOP_APP
#define WINDOWS_STORE 1
#else
#define WINDOWS_STORE 0
#endif

void KillProcessTree() {
  DWORD myprocID = GetCurrentProcessId();
  PROCESSENTRY32 pe = {};
  pe.dwSize = sizeof(PROCESSENTRY32);

  HANDLE hSnap = ::CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, 0);

  if (::Process32First(hSnap, &pe)) {
    BOOL bContinue = TRUE;

    // kill child processes
    while (bContinue) {
      // only kill child processes and let console window remain
      if (pe.th32ParentProcessID == myprocID && wcscmp(pe.szExeFile, L"conhost.exe")) {
        HANDLE hChildProc = ::OpenProcess(PROCESS_ALL_ACCESS, FALSE, pe.th32ProcessID);

        if (hChildProc) {
          ::TerminateProcess(hChildProc, 1);
          ::CloseHandle(hChildProc);
        }
      }

      bContinue = ::Process32Next(hSnap, &pe);
    }
  }
}

[[noreturn]] void logvisorAbort() {
#if !WINDOWS_STORE
  unsigned int i;
  void* stack[100];
  unsigned short frames;
  SYMBOL_INFO* symbol;
  HANDLE process;

  process = GetCurrentProcess();
  SymInitialize(process, NULL, TRUE);
  frames = CaptureStackBackTrace(0, 100, stack, NULL);
  symbol = (SYMBOL_INFO*)calloc(sizeof(SYMBOL_INFO) + 256 * sizeof(char), 1);
  symbol->MaxNameLen = 255;
  symbol->SizeOfStruct = sizeof(SYMBOL_INFO);

  for (i = 0; i < frames; i++) {
    SymFromAddr(process, (DWORD64)(stack[i]), 0, symbol);

    std::fprintf(stderr, "%i: %s - 0x%0llX", frames - i - 1, symbol->Name, symbol->Address);

    DWORD dwDisplacement;
    IMAGEHLP_LINE64 line;
    SymSetOptions(SYMOPT_LOAD_LINES);

    line.SizeOfStruct = sizeof(IMAGEHLP_LINE64);
    if (SymGetLineFromAddr64(process, (DWORD64)(stack[i]), &dwDisplacement, &line)) {
      // SymGetLineFromAddr64 returned success
      std::fprintf(stderr, " LINE %d\n", int(line.LineNumber));
    } else {
      std::fputc('\n', stderr);
    }
  }

  std::fflush(stderr);
  std::free(symbol);

#endif

  KillProcessTree();

  // If you caught one of the above signals, it is likely you just
  // want to quit your program right now.
#ifndef NDEBUG
  signal(SIGABRT, SIG_DFL);
  abort();
#else
  exit(1);
#endif
}

#elif defined(__SWITCH__)
[[noreturn]] void logvisorAbort() { exit(1); }
#else

void KillProcessTree() {}

#include <execinfo.h>
[[noreturn]] void logvisorAbort() {
  void* array[128];
  size_t size = backtrace(array, 128);

  constexpr size_t exeBufSize = 1024 + 1;
  char exeNameBuffer[exeBufSize] = {};

#if __linux__
  readlink("/proc/self/exe", exeNameBuffer, exeBufSize);
#endif

#if __APPLE__
  std::string cmdLineStr = fmt::format(fmt("atos -p {}"), getpid());
#else
  std::string cmdLineStr = fmt::format(fmt("2>/dev/null addr2line -C -f -e \"{}\""), exeNameBuffer);
#endif

  for (size_t i = 0; i < size; i++) {
#if __linux__
    Dl_info dlip;
    if (dladdr(array[i], &dlip))
      cmdLineStr += fmt::format(fmt(" 0x{:016X}"), (uintptr_t)((uint8_t*)array[i] - (uint8_t*)dlip.dli_fbase));
    else
      cmdLineStr += fmt::format(fmt(" 0x{:016X}"), (uintptr_t)array[i]);
#else
    cmdLineStr += fmt::format(fmt(" 0x{:016X}"), (uintptr_t)array[i]);
#endif
  }

  FILE* fp = popen(cmdLineStr.c_str(), "r");
  if (fp) {
    char readBuf[256];
    size_t readSz;
    while ((readSz = fread(readBuf, 1, 256, fp)))
      std::fwrite(readBuf, 1, readSz, stderr);
    pclose(fp);
  } else {
    for (size_t i = 0; i < size; i++) {
      std::fputs("- ", stderr);
      Dl_info dlip;
      if (dladdr(array[i], &dlip)) {
        int status;
        char* demangledName = abi::__cxa_demangle(dlip.dli_sname, nullptr, nullptr, &status);
        std::fprintf(stderr, "%p(%s+%p)\n", dlip.dli_saddr, demangledName ? demangledName : dlip.dli_sname,
                     (void*)((uint8_t*)array[i] - (uint8_t*)dlip.dli_fbase));
        std::free(demangledName);
      } else {
        std::fprintf(stderr, "%p\n", array[i]);
      }
    }
  }

  std::fflush(stderr);
  std::fflush(stdout);
  KillProcessTree();

#ifndef NDEBUG
  signal(SIGABRT, SIG_DFL);
  abort();
#else
  exit(1);
#endif
}

#endif

LogMutex _LogMutex;

static void AbortHandler(int signum) {
  _LogMutex.enabled = false;
  switch (signum) {
  case SIGSEGV:
    Log.report(logvisor::Fatal, fmt("Segmentation Fault"));
    break;
  case SIGILL:
    Log.report(logvisor::Fatal, fmt("Bad Execution"));
    break;
  case SIGFPE:
    Log.report(logvisor::Fatal, fmt("Floating Point Exception"));
    break;
  case SIGABRT:
    Log.report(logvisor::Fatal, fmt("Abort Signal"));
    break;
  default:
    Log.report(logvisor::Fatal, fmt("unknown signal {}"), signum);
    break;
  }
}

uint64_t _LogCounter;

std::vector<std::unique_ptr<ILogger>> MainLoggers;
std::atomic_size_t ErrorCount(0);
static std::chrono::steady_clock MonoClock;
static std::chrono::steady_clock::time_point GlobalStart = MonoClock.now();
static inline std::chrono::steady_clock::duration CurrentUptime() { return MonoClock.now() - GlobalStart; }
std::atomic_uint_fast64_t FrameIndex(0);

static inline int ConsoleWidth() {
  int retval = 80;
#if _WIN32
#if !WINDOWS_STORE
  CONSOLE_SCREEN_BUFFER_INFO info;
  GetConsoleScreenBufferInfo(GetStdHandle(STD_OUTPUT_HANDLE), &info);
  retval = info.dwSize.X - 1;
#endif
#elif defined(__SWITCH__)
  return 80;
#else
  struct winsize w;
  if (ioctl(STDOUT_FILENO, TIOCGWINSZ, &w) != -1)
    retval = w.ws_col;
#endif
  if (retval < 10)
    return 10;
  return retval;
}

#if _WIN32
static HANDLE Term = 0;
#else
static const char* Term = nullptr;
#endif
bool XtermColor = false;
struct ConsoleLogger : public ILogger {
  ConsoleLogger() {
#if _WIN32
#if !WINDOWS_STORE
    const char* conemuANSI = getenv("ConEmuANSI");
    if (conemuANSI && !strcmp(conemuANSI, "ON"))
      XtermColor = true;
#endif
    if (!Term)
      Term = GetStdHandle(STD_ERROR_HANDLE);
#else
    if (!Term) {
      Term = getenv("TERM");
      if (Term && !strncmp(Term, "xterm", 5)) {
        XtermColor = true;
        putenv((char*)"TERM=xterm-16color");
      }
    }
#endif
  }

  static void _reportHead(const char* modName, const char* sourceInfo, Level severity) {
    /* Clear current line out */
    const int width = ConsoleWidth();
    std::fputc('\r', stderr);
    for (int w = 0; w < width; ++w)
      std::fputc(' ', stderr);
    std::fputc('\r', stderr);

    const std::chrono::steady_clock::duration tm = CurrentUptime();
    const double tmd = tm.count() * std::chrono::steady_clock::duration::period::num /
                       static_cast<double>(std::chrono::steady_clock::duration::period::den);
    const std::thread::id thrId = std::this_thread::get_id();
    const char* thrName = nullptr;
    if (ThreadMap.find(thrId) != ThreadMap.end())
      thrName = ThreadMap[thrId];

    if (XtermColor) {
      std::fputs(BOLD "[", stderr);
      fmt::print(stderr, fmt(GREEN "{:.4f} "), tmd);
      const uint_fast64_t fIdx = FrameIndex.load();
      if (fIdx != 0)
        fmt::print(stderr, fmt("({}) "), fIdx);
      switch (severity) {
      case Info:
        std::fputs(BOLD CYAN "INFO", stderr);
        break;
      case Warning:
        std::fputs(BOLD YELLOW "WARNING", stderr);
        break;
      case Error:
        std::fputs(RED BOLD "ERROR", stderr);
        break;
      case Fatal:
        std::fputs(BOLD RED "FATAL ERROR", stderr);
        break;
      default:
        break;
      };
      fmt::print(stderr, fmt(NORMAL BOLD " {}"), modName);
      if (sourceInfo)
        fmt::print(stderr, fmt(BOLD YELLOW " {{}}"), sourceInfo);
      if (thrName)
        fmt::print(stderr, fmt(BOLD MAGENTA " ({})"), thrName);
      std::fputs(NORMAL BOLD "] " NORMAL, stderr);
    } else {
#if _WIN32
#if !WINDOWS_STORE
      SetConsoleTextAttribute(Term, FOREGROUND_INTENSITY | FOREGROUND_WHITE);
      std::fputc('[', stderr);
      SetConsoleTextAttribute(Term, FOREGROUND_INTENSITY | FOREGROUND_GREEN);
      fmt::print(stderr, fmt("{:.4f} "), tmd);
      const uint64_t fi = FrameIndex.load();
      if (fi != 0)
        std::fprintf(stderr, "(%" PRIu64 ") ", fi);
      switch (severity) {
      case Info:
        SetConsoleTextAttribute(Term, FOREGROUND_INTENSITY | FOREGROUND_GREEN | FOREGROUND_BLUE);
        std::fputs("INFO", stderr);
        break;
      case Warning:
        SetConsoleTextAttribute(Term, FOREGROUND_INTENSITY | FOREGROUND_RED | FOREGROUND_GREEN);
        std::fputs("WARNING", stderr);
        break;
      case Error:
        SetConsoleTextAttribute(Term, FOREGROUND_INTENSITY | FOREGROUND_RED);
        std::fputs("ERROR", stderr);
        break;
      case Fatal:
        SetConsoleTextAttribute(Term, FOREGROUND_INTENSITY | FOREGROUND_RED);
        std::fputs("FATAL ERROR", stderr);
        break;
      default:
        break;
      }
      SetConsoleTextAttribute(Term, FOREGROUND_INTENSITY | FOREGROUND_WHITE);
      fmt::print(stderr, fmt(" {}"), modName);
      SetConsoleTextAttribute(Term, FOREGROUND_INTENSITY | FOREGROUND_RED | FOREGROUND_GREEN);
      if (sourceInfo)
        fmt::print(stderr, fmt(" {{}}"), sourceInfo);
      SetConsoleTextAttribute(Term, FOREGROUND_INTENSITY | FOREGROUND_RED | FOREGROUND_BLUE);
      if (thrName)
        fmt::print(stderr, fmt(" ({})"), thrName);
      SetConsoleTextAttribute(Term, FOREGROUND_INTENSITY | FOREGROUND_WHITE);
      std::fputs("] ", stderr);
      SetConsoleTextAttribute(Term, FOREGROUND_WHITE);
#endif
#else
      std::fputc('[', stderr);
      fmt::print(stderr, fmt("{:.4f} "), tmd);
      uint_fast64_t fIdx = FrameIndex.load();
      if (fIdx)
        fmt::print(stderr, fmt("({}) "), fIdx);
      switch (severity) {
      case Info:
        std::fputs("INFO", stderr);
        break;
      case Warning:
        std::fputs("WARNING", stderr);
        break;
      case Error:
        std::fputs("ERROR", stderr);
        break;
      case Fatal:
        std::fputs("FATAL ERROR", stderr);
        break;
      default:
        break;
      }
      fmt::print(stderr, fmt(" {}"), modName);
      if (sourceInfo)
        fmt::print(stderr, fmt(" {{}}"), sourceInfo);
      if (thrName)
        fmt::print(stderr, fmt(" ({})"), thrName);
      std::fputs("] ", stderr);
#endif
    }
  }

  void report(const char* modName, Level severity, fmt::string_view format, fmt::format_args args) override {
    _reportHead(modName, nullptr, severity);
    fmt::vprint(stderr, format, args);
    std::fputc('\n', stderr);
    std::fflush(stderr);
  }

  void report(const char* modName, Level severity, fmt::wstring_view format, fmt::wformat_args args) override {
    _reportHead(modName, nullptr, severity);
    fmt::vprint(stderr, format, args);
    std::fputc('\n', stderr);
    std::fflush(stderr);
  }

  void reportSource(const char* modName, Level severity, const char* file, unsigned linenum, fmt::string_view format,
                    fmt::format_args args) override {
    _reportHead(modName, fmt::format(fmt("{}:{}"), file, linenum).c_str(), severity);
    fmt::vprint(stderr, format, args);
    std::fputc('\n', stderr);
    std::fflush(stderr);
  }

  void reportSource(const char* modName, Level severity, const char* file, unsigned linenum, fmt::wstring_view format,
                    fmt::wformat_args args) override {
    _reportHead(modName, fmt::format(fmt("{}:{}"), file, linenum).c_str(), severity);
    fmt::vprint(stderr, format, args);
    std::fputc('\n', stderr);
    std::fflush(stderr);
  }
};

static bool ConsoleLoggerRegistered = false;

void RegisterConsoleLogger() {
  /* Otherwise construct new console logger */
  if (!ConsoleLoggerRegistered) {
    MainLoggers.emplace_back(new ConsoleLogger);
    ConsoleLoggerRegistered = true;
  }
}

#if _WIN32
void CreateWin32Console() {
#if !WINDOWS_STORE
  /* Debug console */
  AllocConsole();

  std::freopen("CONIN$", "r", stdin);
  std::freopen("CONOUT$", "w", stdout);
  std::freopen("CONOUT$", "w", stderr);
#endif
}
#endif

void RegisterStandardExceptions() {
  signal(SIGABRT, AbortHandler);
  signal(SIGSEGV, AbortHandler);
  signal(SIGILL, AbortHandler);
  signal(SIGFPE, AbortHandler);
}

struct FileLogger : public ILogger {
  FILE* fp;
  virtual void openFile() = 0;
  virtual void closeFile() { std::fclose(fp); }

  void _reportHead(const char* modName, const char* sourceInfo, Level severity) {
    const std::chrono::steady_clock::duration tm = CurrentUptime();
    const double tmd = tm.count() * std::chrono::steady_clock::duration::period::num /
                       static_cast<double>(std::chrono::steady_clock::duration::period::den);
    const std::thread::id thrId = std::this_thread::get_id();
    const char* thrName = nullptr;
    if (ThreadMap.find(thrId) != ThreadMap.end()) {
      thrName = ThreadMap[thrId];
    }

    std::fputc('[', fp);
    std::fprintf(fp, "%5.4f ", tmd);
    const uint_fast64_t fIdx = FrameIndex.load();
    if (fIdx != 0) {
      std::fprintf(fp, "(%" PRIu64 ") ", fIdx);
    }
    switch (severity) {
    case Info:
      std::fputs("INFO", fp);
      break;
    case Warning:
      std::fputs("WARNING", fp);
      break;
    case Error:
      std::fputs("ERROR", fp);
      break;
    case Fatal:
      std::fputs("FATAL ERROR", fp);
      break;
    default:
      break;
    };
    std::fprintf(fp, " %s", modName);
    if (sourceInfo) {
      std::fprintf(fp, " {%s}", sourceInfo);
    }
    if (thrName) {
      std::fprintf(fp, " (%s)", thrName);
    }
    std::fputs("] ", fp);
  }

  void report(const char* modName, Level severity, fmt::string_view format, fmt::format_args args) override {
    openFile();
    _reportHead(modName, nullptr, severity);
    fmt::vprint(fp, format, args);
    std::fputc('\n', fp);
    closeFile();
  }

  void report(const char* modName, Level severity, fmt::wstring_view format, fmt::wformat_args args) override {
    openFile();
    _reportHead(modName, nullptr, severity);
    fmt::vprint(fp, format, args);
    std::fputc('\n', fp);
    closeFile();
  }

  void reportSource(const char* modName, Level severity, const char* file, unsigned linenum, fmt::string_view format,
                    fmt::format_args args) override {
    openFile();
    _reportHead(modName, fmt::format(fmt("{}:{}"), file, linenum).c_str(), severity);
    fmt::vprint(fp, format, args);
    std::fputc('\n', fp);
    closeFile();
  }

  void reportSource(const char* modName, Level severity, const char* file, unsigned linenum, fmt::wstring_view format,
                    fmt::wformat_args args) override {
    openFile();
    _reportHead(modName, fmt::format(fmt("{}:{}"), file, linenum).c_str(), severity);
    fmt::vprint(fp, format, args);
    std::fputc('\n', fp);
    closeFile();
  }
};

struct FileLogger8 : public FileLogger {
  const char* m_filepath;
  FileLogger8(const char* filepath) : m_filepath(filepath) {}
  void openFile() override { fp = std::fopen(m_filepath, "a"); }
};

void RegisterFileLogger(const char* filepath) {
  /* Otherwise construct new file logger */
  MainLoggers.emplace_back(new FileLogger8(filepath));
}

#if LOG_UCS2

struct FileLogger16 : public FileLogger {
  const wchar_t* m_filepath;
  FileLogger16(const wchar_t* filepath) : m_filepath(filepath) {}
  void openFile() override { fp = _wfopen(m_filepath, L"a"); }
};

void RegisterFileLogger(const wchar_t* filepath) {
  /* Determine if file logger already added */
  for (auto& logger : MainLoggers) {
    FileLogger16* filelogger = dynamic_cast<FileLogger16*>(logger.get());
    if (filelogger) {
      if (!wcscmp(filepath, filelogger->m_filepath))
        return;
    }
  }

  /* Otherwise construct new file logger */
  MainLoggers.emplace_back(new FileLogger16(filepath));
}

#endif

} // namespace logvisor
