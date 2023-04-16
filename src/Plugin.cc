#include "Plugin.h"
#include "IOLoop.h"
#include "Nodejs.h"
#include "ZeekCompat.h"
#include "config.h"
#include "zeekjs.bif.h"

#include <zeek/Expr.h>
#include <zeek/Frame.h>
#include <zeek/Func.h>
#include <zeek/ID.h>
#include <zeek/RunState.h>
#include <zeek/Trigger.h>
#include <zeek/iosource/Manager.h>
#include <zeek/iosource/PktSrc.h>

#include <filesystem>

namespace plugin::Corelight_ZeekJS {
Plugin plugin;
}

using namespace plugin::Corelight_ZeekJS;

zeek::plugin::Configuration Plugin::Configure() {
  zeek::plugin::Configuration config;
  config.name = "Zeek::JavaScript";
  config.description = "Experimental JavaScript support for Zeek";
  config.version.major = ZEEKJS_VERSION_MAJOR;
  config.version.minor = ZEEKJS_VERSION_MINOR;
  config.version.patch = ZEEKJS_VERSION_PATCH;
  return config;
}

void Plugin::InitPreScript() {
  zeek::plugin::Plugin::InitPreScript();
  EnableHook(zeek::plugin::HOOK_DRAIN_EVENTS);
  EnableHook(zeek::plugin::HOOK_LOAD_FILE);
}

void Plugin::InitPostScript() {
  zeek::plugin::Plugin::InitPostScript();

  zeek::VectorValPtr files = zeek::id::find_val<zeek::VectorVal>("JavaScript::files");
  std::vector<std::filesystem::path> std_files = load_files;
  for (unsigned int i = 0; i < files->Size(); i++) {
    const auto& vp = files->ValAt(i);
    zeek::StringValPtr filename = {zeek::NewRef{}, vp->AsStringVal()};

    std_files.emplace_back(filename->ToStdString());
  }

  // If no Javascript files were hooked, no need to initialize Node/V8.
  if (std_files.size() == 0) {
    DisableHook(zeek::plugin::HOOK_DRAIN_EVENTS);
    return;
  }

  // Okay, initialize Node.js
  PLUGIN_DBG_LOG(plugin, "Hooked %ld .js files: Initializing!", std_files.size());
  std::string main_script_source =
      zeek::id::find_val<zeek::StringVal>("JavaScript::main_script_source")
          ->ToStdString();

  size_t initial_heap_size_in_bytes =
      zeek::id::find_val<zeek::Val>("JavaScript::initial_heap_size_in_bytes")
          ->AsCount();
  size_t maximum_heap_size_in_bytes =
      zeek::id::find_val<zeek::Val>("JavaScript::maximum_heap_size_in_bytes")
          ->AsCount();
  int thread_pool_size = static_cast<int>(
      zeek::id::find_val<zeek::Val>("JavaScript::thread_pool_size")->AsCount());

  bool exit_on_uncaught_exceptions =
      zeek::id::find_val<zeek::Val>("JavaScript::exit_on_uncaught_exceptions")
          ->AsBool();

  nodejs = new plugin::Nodejs::Instance();

  if (!nodejs->Init(&plugin, main_script_source, std_files, initial_heap_size_in_bytes,
                    maximum_heap_size_in_bytes, exit_on_uncaught_exceptions,
                    thread_pool_size)) {
    zeek::reporter->Error("Failed to initialize nodejs");
    return;
  }

  // Register Node's loop as an IO source with the iosource mgr
  loop_io_source =
      std::make_unique<plugin::Corelight_ZeekJS::IOLoop::LoopSource>(nodejs);
  zeek::iosource_mgr->Register(loop_io_source.get(), false, false);
  if (!zeek::iosource_mgr->RegisterFd(loop_io_source->GetFd(), loop_io_source.get())) {
    zeek::reporter->Error("Failed to register LoopSource");
    return;
  }

  // Another IO source allowing to kick Zeek's IO loop
  auto pipe_io_source = new plugin::Corelight_ZeekJS::IOLoop::PipeSource(nodejs);
  zeek::iosource_mgr->Register(pipe_io_source, true /*dont_count*/);
  if (!zeek::iosource_mgr->RegisterFd(pipe_io_source->GetFd(), pipe_io_source)) {
    zeek::reporter->Error("Failed to register PipeSource");
    return;
  }

  nodejs->SetZeekNotifier(pipe_io_source);

  // Run the loop once to get things started.
  nodejs->Process();
}

// Take over files ending with .js
int Plugin::HookLoadFile(const zeek::plugin::Plugin::LoadType,
                         const std::string& file,
                         const std::string& resolved) {
  if (file.find(".js", file.size() - 3) != std::string::npos) {
    PLUGIN_DBG_LOG(plugin, "Hooked .js file=%s (%s)", file.c_str(), resolved.c_str());
    load_files.emplace_back(resolved);
    return 1;
  }

  if (file.find(".cjs", file.size() - 4) != std::string::npos) {
    PLUGIN_DBG_LOG(plugin, "Hooked .cjs file=%s (%s)", file.c_str(), resolved.c_str());
    load_files.emplace_back(resolved);
    return 1;
  }

  return -1;
}

void Plugin::HookDrainEvents() {
  // Don't act on draining when a packet is being dispatched.
  if (zeek::run_state::processing_start_time != 0.0)
    return;

  if (!nodejs)
    return;

#ifdef ZEEKJS_LOOP_DEBUG
  dprintf(
      "event_mgr: size=%d | iosource size=%d | "
      "timer_mgr size=%ld | nodejs alive=%d\n",
      zeek::event_mgr.Size(), zeek::iosource_mgr->Size(),
      zeek::detail::timer_mgr->Size(), nodejs->IsAlive());
#endif

  nodejs->UpdateTime();

  // If any callbacks into Javascript happened prevoiusly
  // and currently we're not processing a packet, run
  // Process() housekeeping now.
  if (nodejs->WasJsCalled()) {
    nodejs->Process();
    nodejs->SetJsCalled(false);
  }

  // Decide if we should close the Node.js IO source in
  // order to have Zeek shutdown.
  //
  // If Zeek is terminating and the IO source is still open,
  // close it now.
  if (zeek::run_state::terminating) {
    if (loop_io_source->IsOpen())
      loop_io_source->UpdateClosed(true);

    return;
  }

  if (zeek::BifConst::exit_only_after_terminate)
    return;

  // If we're reading traces and the packet source
  // has closed, remove us from the IO loop as well.
  //
  // This may not always be the right thing to do,
  // but then there's exit_only_after_terminate=T
  // to prevent this.
  auto ps = zeek::iosource_mgr->GetPktSrc();
  if (ps && !ps->IsLive() && !ps->IsOpen()) {
    loop_io_source->UpdateClosed(true);
    return;
  }

  // Is there a HTTP server or something running?
  if (nodejs->IsAlive())
    return;

  // Other live IO source existing?
  if (zeek::iosource_mgr->Size() > 1)
    return;

  // Does the event manager have work scheduled?
  if (zeek::event_mgr.Size() > 0)
    return;

  // Emit a beforeExit event that can be used by JavaScript to
  // schedule more work and keep the IO loop going.
  if (loop_io_source->IsOpen()) {
    nodejs->BeforeExit();
    if (nodejs->IsAlive()) {
      return;
    }
  }

  loop_io_source->UpdateClosed(true);
}

namespace {
//
// Custom zeek::detail::Stmt implementation where Exec()
// is calling back into Javascript land via a Js::EventHandler
// implementation.
//
// Someone is going to call me out for this.
class InvokeJsEventHandlerStmt : public zeek::detail::Stmt {
 public:
  InvokeJsEventHandlerStmt(zeek::EventHandler* zeek_eh, Js::EventHandler* js_eh)
      : zeek::detail::Stmt(zeek::detail::STMT_ANY),
        zeek_event_handler(zeek_eh),
        js_event_handler(js_eh) {}

  zeek::ValPtr Exec(zeek::detail::Frame* f, zeek::detail::StmtFlowType& flow) override {
    flow = zeek::detail::FLOW_NEXT;
    zeek::Args args = *f->GetFuncArgs();

    zeek::IntrusivePtr<zeek::Event> e =
        zeek::make_intrusive<zeek::Event>(zeek_event_handler, args);
    (*js_event_handler)(e);

    return nullptr;
  }

  zeek::detail::StmtPtr Duplicate() override {
    eprintf("%s", "Duplicate() on InvokeJsEventHandlerStmt not implemented");
    return {zeek::NewRef{}, this};
  }

  zeek::detail::TraversalCode Traverse(
      zeek::detail::TraversalCallback* cb) const override {
    return zeek::detail::TC_CONTINUE;
  }

 private:
  zeek::EventHandler* zeek_event_handler;
  Js::EventHandler* js_event_handler;
};

class InvokeJsHookHandlerStmt : public zeek::detail::Stmt {
 public:
  InvokeJsHookHandlerStmt(Js::HookHandler* js_hh)
      : zeek::detail::Stmt(zeek::detail::STMT_ANY), js_hook_handler(js_hh) {}

  zeek::ValPtr Exec(zeek::detail::Frame* f, zeek::detail::StmtFlowType& flow) override {
    zeek::Args args = *f->GetFuncArgs();
    plugin::Corelight_ZeekJS::Js::HookHandlerResult result = (*js_hook_handler)(args);

    if (result.flow != zeek::detail::FLOW_NEXT) {
      dprintf("hook result != FLOW_NEXT, overwriting with %d", result.flow);
      flow = result.flow;
    }

    // Does this actually matter?
    return nullptr;
  }

  zeek::detail::StmtPtr Duplicate() override {
    eprintf("%s", "Duplicate() on InvokeJsHookHandlerStmt not implemented");
    return {zeek::NewRef{}, this};
  }

  zeek::detail::TraversalCode Traverse(
      zeek::detail::TraversalCallback* cb) const override {
    return zeek::detail::TC_CONTINUE;
  }

 private:
  Js::HookHandler* js_hook_handler;
};
}  // namespace

bool Plugin::RegisterAsScriptFuncBody(zeek::EventHandlerPtr zeek_eh,
                                      Js::EventHandler* js_eh,
                                      int priority) {
  zeek::FuncPtr func = zeek_eh->GetFunc();
  zeek::detail::StmtPtr stmt =
      zeek::make_intrusive<InvokeJsEventHandlerStmt>(zeek_eh.Ptr(), js_eh);
  std::vector<zeek::detail::IDPtr> inits;  // ? What are inits?

  // 0 framesize
  func->AddBody(stmt, inits, 0, priority);

  return true;
}

bool Plugin::RegisterJsEventHandler(const std::string& name,
                                    Js::EventHandler* js_eh,
                                    int priority) {
  PLUGIN_DBG_LOG(plugin, "Registering %s priority=%d, js_eh=%p", name.c_str(), priority,
                 js_eh);

  zeek::EventHandler* zeek_eh = zeek::event_registry->Lookup(name);

  // XXX EventHandlerPtr behaves awkward in bool expressions. It checks
  //     if any bodies are registered as well, so using a raw pointer
  //     here (and not just because I don't know any better).
  if (!zeek_eh) {
    zeek::reporter->Error("Unknown event %s", name.c_str());
    // for (const auto& h: zeek::event_registry->AllHandlers()) {
    //	zeek::reporter->Error("- %s", h.c_str());
    //}
    return false;
  }

  // Ensure Zeek generates the event if no Zeek event handlers  exist.
  zeek_eh->SetGenerateAlways();

  RegisterAsScriptFuncBody(zeek_eh, js_eh, priority);

  PLUGIN_DBG_LOG(plugin, "Registered %s", name.c_str());
  return true;
}

bool Plugin::RegisterJsHookHandler(const std::string& name,
                                   Js::HookHandler* js_hh,
                                   int priority) {
  PLUGIN_DBG_LOG(plugin, "Registering %s priority=%d, js_hh=%p", name.c_str(), priority,
                 js_hh);

  const zeek::detail::IDPtr& id = zeek::id::find(name);
  if (!id) {
    zeek::reporter->Error("Unknown identifier %s", name.c_str());
    return false;
  }

  const zeek::TypePtr t = id->GetType();
  if (!zeek::IsFunc(t->Tag())) {  // TODO: Check flavor, hook.
    zeek::reporter->Error("Not a function: %s", name.c_str());
    return false;
  }
  zeek::Func* func = id->GetVal()->AsFunc();

  dprintf("Have a func=%p %s priority=%d", func, func->Name(), priority);

  zeek::detail::StmtPtr stmt = zeek::make_intrusive<InvokeJsHookHandlerStmt>(js_hh);
  std::vector<zeek::detail::IDPtr> inits;  // ? What are inits?
  func->AddBody(stmt, inits, 0, priority);

  PLUGIN_DBG_LOG(plugin, "Added body to %s", func->Name());
  return true;
}

// Inspired from from EventStmt::Exec
bool Plugin::Event(const std::string& name, const zeek::Args& args) {
  PLUGIN_DBG_LOG(plugin, "Event %s with %lu args", name.c_str(), args.size());
  zeek::EventHandler* zeek_eh = zeek::event_registry->Lookup(name);
  if (!zeek_eh) {
    zeek::reporter->Error("Unknown event %s", name.c_str());
    return false;
  }

  zeek::event_mgr.Enqueue(zeek_eh, args);

  return true;
}

zeek::ValPtr Plugin::Invoke(const std::string& name,
                            zeek::Args& args,
                            const std::string& file_name,
                            int line_number) {
  PLUGIN_DBG_LOG(plugin, "Invoke %s with %lu args", name.c_str(), args.size());

  zeek::FuncPtr func = zeek::id::find_func(name);

  // Setup a fake call frame for Zeek. We need to provide
  // CallExpr with Zeek 4.0. Use one that doesn't have any
  // parameters, so we don't need to deal with the details.
  //
  // If possible, just ignore this for now.
  auto js_frame = zeek::detail::Frame(0, nullptr, &args);
  auto location =
      zeek::detail::Location(file_name.c_str(), line_number, line_number, 0, 0);

  zeek::detail::IDPtr fake_func = zeek::id::find("zeek_version");
  zeek::detail::NameExpr fake_func_expr(fake_func);
  zeek::detail::ListExpr fake_list_expr;
  zeek::detail::CallExpr fake_call_expr({zeek::NewRef{}, &fake_func_expr},
                                        {zeek::NewRef{}, &fake_list_expr});
  fake_call_expr.SetLocationInfo(&location);
  js_frame.SetCall(&fake_call_expr);

  return func->Invoke(&args, &js_frame);
}

void Plugin::Done() {
  zeek::plugin::Plugin::Done();
  PLUGIN_DBG_LOG(plugin, "Done...");
  if (nodejs) {
    nodejs->Done();
    delete nodejs;
    nodejs = nullptr;
  }
}
