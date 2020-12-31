#pragma once

#include <cstring>
#include <cstdio>
#include <cstdlib>
#include <vector>
#include <atomic>
#include <memory>
#include <mutex>

#define FMT_STRING_ALIAS 1
#define FMT_ENFORCE_COMPILE_STRING 1
#include <fmt/format.h>

#if defined(__SWITCH__) && !defined(LOGVISOR_NX_LM)
#define LOGVISOR_NX_LM 0
#endif

extern "C" void logvisorBp();
#define log_typeid(type) std::hash<std::string>()(#type)

namespace logvisor {

[[noreturn]] void logvisorAbort();

#if _WIN32 && UNICODE
#define LOG_UCS2 1
#endif

/* True if ANSI color available */
extern bool XtermColor;

/**
 * @brief Severity level for log messages
 */
enum Level {
  Info,    /**< Non-error informative message */
  Warning, /**< Non-error warning message */
  Error,   /**< Recoverable error message */
  Fatal    /**< Non-recoverable error message (throws exception) */
};

/**
 * @brief Backend interface for receiving app-wide log events
 */
struct ILogger {
private:
  uint64_t m_typeHash;
public:
  ILogger(uint64_t typeHash) : m_typeHash(typeHash) {}
  virtual ~ILogger() = default;
  virtual void report(const char* modName, Level severity, fmt::string_view format, fmt::format_args args) = 0;
  virtual void report(const char* modName, Level severity, fmt::wstring_view format, fmt::wformat_args args) = 0;
  virtual void reportSource(const char* modName, Level severity, const char* file, unsigned linenum,
                            fmt::string_view format, fmt::format_args args) = 0;
  virtual void reportSource(const char* modName, Level severity, const char* file, unsigned linenum,
                            fmt::wstring_view format, fmt::wformat_args args) = 0;

  [[nodiscard]] uint64_t  getTypeId() const { return m_typeHash; }
};

/**
 * @brief Terminate all child processes
 *
 * Implicitly called on abort condition.
 */
void KillProcessTree();

/**
 * @brief Assign calling thread a descriptive name
 * @param name Descriptive thread name
 */
void RegisterThreadName(const char* name);

/**
 * @brief Centralized logger vector
 *
 * All loggers added to this vector will receive reports as they occur
 */
extern std::vector<std::unique_ptr<ILogger>> MainLoggers;

/**
 * @brief Centralized error counter
 *
 * All submodules accumulate this value
 */
extern std::atomic_size_t ErrorCount;

/**
 * @brief Centralized frame index
 *
 * All log events include this as part of their timestamp if non-zero.
 * The default value is zero, the app is responsible for updating it
 * within its main loop.
 */
extern std::atomic_uint_fast64_t FrameIndex;

/**
 * @brief Centralized logging lock
 *
 * Ensures logging streams aren't written concurrently
 */
struct LogMutex {
  bool enabled = true;
  std::recursive_mutex mutex;
  ~LogMutex() { enabled = false; }
  std::unique_lock<std::recursive_mutex> lock() {
    if (enabled)
      return std::unique_lock<std::recursive_mutex>(mutex);
    else
      return std::unique_lock<std::recursive_mutex>();
  }
};
extern LogMutex _LogMutex;

/**
 * @brief Take a centralized lock for the logging output stream(s)
 * @return RAII mutex lock
 */
inline std::unique_lock<std::recursive_mutex> LockLog() { return _LogMutex.lock(); }

extern uint64_t _LogCounter;

/**
 * @brief Get current count of logging events
 * @return Log Count
 */
inline uint64_t GetLogCounter() { return _LogCounter; }

/**
 * @brief Restore centralized logger vector to default state (silent operation)
 */
inline void UnregisterLoggers() { MainLoggers.clear(); }

/**
 * @brief Construct and register a real-time console logger singleton
 *
 * This will output to stderr on POSIX platforms and spawn a new console window on Windows.
 * If there's already a registered console logger, this is a no-op.
 */
void RegisterConsoleLogger();

/**
 * @brief Construct and register a file logger
 * @param filepath Path to write the file
 *
 * If there's already a file logger registered to the same file, this is a no-op.
 */
void RegisterFileLogger(const char* filepath);

/**
 * @brief Register signal handlers with system for common client exceptions
 */
void RegisterStandardExceptions();

#if _WIN32
/**
 * @brief Spawn an application-owned cmd.exe window for displaying console output
 */
void CreateWin32Console();
#endif

#if LOG_UCS2

/**
 * @brief Construct and register a file logger (wchar_t version)
 * @param filepath Path to write the file
 *
 * If there's already a file logger registered to the same file, this is a no-op.
 */
void RegisterFileLogger(const wchar_t* filepath);

#endif

/**
 * @brief This is constructed per-subsystem in a locally centralized fashion
 */
class Module {
  const char* m_modName;

  template <typename Char>
  void _vreport(Level severity, fmt::basic_string_view<Char> format,
                fmt::basic_format_args<fmt::buffer_context<Char>> args) {
    auto lk = LockLog();
    ++_LogCounter;
    if (severity == Fatal)
      RegisterConsoleLogger();
    for (auto& logger : MainLoggers)
      logger->report(m_modName, severity, format, args);
    if (severity == Error || severity == Fatal)
      logvisorBp();
    if (severity == Fatal)
      logvisorAbort();
    else if (severity == Error)
      ++ErrorCount;
  }

  template <typename Char>
  void _vreportSource(Level severity, const char* file, unsigned linenum, fmt::basic_string_view<Char> format,
                      fmt::basic_format_args<fmt::buffer_context<Char>> args) {
    auto lk = LockLog();
    ++_LogCounter;
    if (severity == Fatal)
      RegisterConsoleLogger();
    for (auto& logger : MainLoggers)
      logger->reportSource(m_modName, severity, file, linenum, format, args);
    if (severity == Error || severity == Fatal)
      logvisorBp();
    if (severity == Fatal)
      logvisorAbort();
    else if (severity == Error)
      ++ErrorCount;
  }

public:
  constexpr Module(const char* modName) : m_modName(modName) {}

  /**
   * @brief Route new log message to centralized ILogger
   * @param severity Level of log report severity
   * @param format fmt-style format string
   */
  template <typename S, typename... Args, typename Char = fmt::char_t<S>>
  void report(Level severity, const S& format, Args&&... args) {
    if (MainLoggers.empty() && severity != Level::Fatal)
      return;
    _vreport(severity, fmt::to_string_view<Char>(format),
             fmt::basic_format_args<fmt::buffer_context<Char>>(
                 fmt::internal::make_args_checked<Args...>(format, std::forward<Args>(args)...)));
  }

  template <typename Char>
  void vreport(Level severity, fmt::basic_string_view<Char> format,
               fmt::basic_format_args<fmt::buffer_context<Char>> args) {
    if (MainLoggers.empty() && severity != Level::Fatal)
      return;
    _vreport(severity, format, args);
  }

  /**
   * @brief Route new log message with source info to centralized ILogger
   * @param severity Level of log report severity
   * @param file Source file name from __FILE__ macro
   * @param linenum Source line number from __LINE__ macro
   * @param format fmt-style format string
   */
  template <typename S, typename... Args, typename Char = fmt::char_t<S>>
  void reportSource(Level severity, const char* file, unsigned linenum, const S& format, Args&&... args) {
    if (MainLoggers.empty() && severity != Level::Fatal)
      return;
    _vreportSource(severity, file, linenum, fmt::to_string_view<Char>(format),
                   fmt::basic_format_args<fmt::buffer_context<Char>>(
                       fmt::internal::make_args_checked<Args...>(format, std::forward<Args>(args)...)));
  }

  template <typename Char>
  void vreportSource(Level severity, const char* file, unsigned linenum, fmt::basic_string_view<Char> format,
                     fmt::basic_format_args<fmt::buffer_context<Char>> args) {
    if (MainLoggers.empty() && severity != Level::Fatal)
      return;
    _vreportSource(severity, file, linenum, format, args);
  }
};

#define FMT_CUSTOM_FORMATTER(tp, fmtstr, ...) \
namespace fmt { \
template <> \
struct formatter<tp, char> { \
  template <typename ParseContext> \
  constexpr auto parse(ParseContext &ctx) { return ctx.begin(); } \
  template <typename FormatContext> \
  auto format(const tp &obj, FormatContext &ctx) { \
    return format_to(ctx.out(), FMT_STRING(fmtstr), __VA_ARGS__); \
  } \
}; \
template <> \
struct formatter<tp, wchar_t> { \
  template <typename ParseContext> \
  constexpr auto parse(ParseContext &ctx) { return ctx.begin(); } \
  template <typename FormatContext> \
  auto format(const tp &obj, FormatContext &ctx) { \
    return format_to(ctx.out(), FMT_STRING(L##fmtstr), __VA_ARGS__); \
  } \
}; \
template <> \
struct formatter<tp, char16_t> { \
  template <typename ParseContext> \
  constexpr auto parse(ParseContext &ctx) { return ctx.begin(); } \
  template <typename FormatContext> \
  auto format(const tp &obj, FormatContext &ctx) { \
    return format_to(ctx.out(), FMT_STRING(u##fmtstr), __VA_ARGS__); \
  } \
}; \
template <> \
struct formatter<tp, char32_t> { \
  template <typename ParseContext> \
  constexpr auto parse(ParseContext &ctx) { return ctx.begin(); } \
  template <typename FormatContext> \
  auto format(const tp &obj, FormatContext &ctx) { \
    return format_to(ctx.out(), FMT_STRING(U##fmtstr), __VA_ARGS__); \
  } \
}; \
}

} // namespace logvisor

template <typename S, typename... Args, typename Char = fmt::char_t<S>>
void quicklog(const S& format, Args&&... args) {
  logvisor::MainLoggers[0]->report(
      "quick", logvisor::Info, fmt::to_string_view<Char>(format),
      fmt::basic_format_args<fmt::buffer_context<Char>>(
          fmt::internal::make_args_checked<Args...>(format, std::forward<Args>(args)...)));
}
