#pragma once

#include <zeek/DebugLogger.h>
#include <zeek/Event.h>
#include <zeek/Stmt.h>
#include <zeek/plugin/Plugin.h>

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
#define eprintf(fmt, ...)                             \
  do {                                                \
    std::fprintf(stderr, "[ ERROR ] %s: ", __func__); \
    std::fprintf(stderr, fmt, __VA_ARGS__);           \
    std::fprintf(stderr, "\n");                       \
  } while (0);

#ifdef DEBUG
#define dprintf(fmt, ...)                                                    \
  do {                                                                       \
    PLUGIN_DBG_LOG(::plugin::Corelight_ZeekJS::plugin, "%s: " fmt, __func__, \
                   __VA_ARGS__);                                             \
  } while (0);
#else
#define dprintf(fmt, ...)
#endif
}  // namespace plugin::Corelight_ZeekJS::Js
