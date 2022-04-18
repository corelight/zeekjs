#pragma once
#include <chrono>
using std::chrono::duration_cast;
using std::chrono::microseconds;
using std::chrono::seconds;
using std::chrono::system_clock;

#include <zeek/Event.h>
#include <zeek/Stmt.h>

namespace plugin::Corelight_ZeekJS::Js {

/*
 * A callable to be implemented for a given Javascript engine.
 */
class EventHandler {
 public:
  virtual void operator()(const zeek::IntrusivePtr<zeek::Event> event) = 0;
};

struct HookHandlerResult {
  zeek::detail::StmtFlowType flow = zeek::detail::FLOW_NEXT;
};

/*
 * A callable to be implemented for a given Javascript engine.
 */
class HookHandler {
 public:
  virtual HookHandlerResult operator()(const zeek::Args& args) = 0;
};

/* Poor man's logging */
#define eprintf(...)                                        \
  do {                                                      \
    auto __now = system_clock::now().time_since_epoch();    \
    auto __us = duration_cast<microseconds>(__now).count(); \
    std::fprintf(stderr, "[ ERROR ] %s: ", __func__);       \
    std::fprintf(stderr, __VA_ARGS__);                      \
    std::fprintf(stderr, "\n");                             \
  } while (0);

// #define DEBUG 1
#ifdef DEBUG
#define dprintf(...)                                                       \
  do {                                                                     \
    auto __now = system_clock::now().time_since_epoch();                   \
    auto __us = duration_cast<microseconds>(__now).count();                \
    std::fprintf(stderr, "%lf [ DEBUG ] %s ", __us / 1000000.0, __func__); \
    std::fprintf(stderr, __VA_ARGS__);                                     \
    std::fprintf(stderr, "\n");                                            \
  } while (0);
#else
#define dprintf(...) \
  do {               \
  } while (0);
#endif
}  // namespace plugin::Corelight_ZeekJS::Js
