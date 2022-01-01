#pragma once

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
#define eprintf(...)                        \
  do {                                      \
    std::fprintf(stderr, "[ ERROR ] ");     \
    std::fprintf(stderr, "%s: ", __func__); \
    std::fprintf(stderr, __VA_ARGS__);      \
    std::fprintf(stderr, "\n");             \
  } while (0);

// #define DEBUG 1
#ifdef DEBUG
#define dprintf(...)                        \
  do {                                      \
    std::fprintf(stderr, "[ DEBUG ] ");     \
    std::fprintf(stderr, "%s: ", __func__); \
    std::fprintf(stderr, __VA_ARGS__);      \
    std::fprintf(stderr, "\n");             \
  } while (0);
#else
#define dprintf(...) \
  do {               \
  } while (0);
#endif
}  // namespace plugin::Corelight_ZeekJS::Js
