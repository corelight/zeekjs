#pragma once
#include <filesystem>
#include <optional>

#include <node/node.h>
#include <node/v8.h>
#include <uv.h>

#include "IOLoop.h"
#include "ZeekJS.h"

// Prototypes for plugin hooks.
namespace plugin::Corelight_ZeekJS {
class Plugin;
}

namespace plugin::Nodejs {

class EventHandler;

// Helper class for wrapping a zeek::ValPtr into a v8::Object.
// creating Zeek
class ZeekValWrapper {
 public:
  ZeekValWrapper(v8::Isolate* isolate);

  // Wrap anything into a v8::Value. Some types are converted
  // directly like strings and numbers. Others return a "proxy"
  // object which keeps a reference to the original ValPtr and
  // uses below callbacks.
  //
  // Not everything is implemented.
  v8::Local<v8::Value> Wrap(const zeek::ValPtr& vp);

  struct Result {
    bool ok;
    zeek::ValPtr val;
    std::string error;
  };

  // Convert a v8::Value to a ValPtr of the given type. If the
  // conversion fails, e.g. if type is IPAddr, but v8_val not
  // a string that conforms to an IP, returns ValPtr(nullptr).
  //
  // Very little is implemented.
  Result ToZeekVal(v8::Local<v8::Value> v8_val, const zeek::TypePtr& type);

  // Callbacks used for Zeek sets.
  static void ZeekRecordEnumerator(const v8::PropertyCallbackInfo<v8::Array>& info);
  static void ZeekRecordGetter(v8::Local<v8::Name> property,
                               const v8::PropertyCallbackInfo<v8::Value>& info);
  static void ZeekRecordQuery(v8::Local<v8::Name> property,
                              const v8::PropertyCallbackInfo<v8::Integer>& info);
  // Callbacks used for Zeek tables.
  static void ZeekTableEnumerator(const v8::PropertyCallbackInfo<v8::Array>& info);
  static void ZeekTableIndexGetter(uint32_t index,
                                   const v8::PropertyCallbackInfo<v8::Value>& info);
  static void ZeekTableGetter(v8::Local<v8::Name> property,
                              const v8::PropertyCallbackInfo<v8::Value>& info);

  // String conversion helpers
  v8::Local<v8::String> v8_str_intern(const char* s);
  v8::Local<v8::String> v8_str(const char* s);

 private:
  v8::Isolate* isolate_;
  v8::Global<v8::ObjectTemplate> record_template_;
  v8::Global<v8::ObjectTemplate> table_template_;
  v8::Global<v8::String> port_str_;
  v8::Global<v8::String> proto_str_;
  v8::Global<v8::String> toJSON_str_;
};

// Class holding Node.js and V8 state.
class Instance {
 public:
  Instance();

  bool Init(plugin::Corelight_ZeekJS::Plugin* plugin,
            const std::string& main_script_source,
            const std::vector<std::filesystem::path>& files,
            size_t initial_heap_size_in_bytes,
            size_t maximum_heap_size_in_bytes,
            bool exit_on_uncaught_exceptions,
            int thread_pool_size);

  void Done();

  void SetZeekNotifier(plugin::Corelight_ZeekJS::IOLoop::PipeSource* n) {
    zeek_notifier_ = n;
  }

  // Called by the thin JsLoopIOSource
  int GetLoopFd();
  void Process();
  void UpdateTime();
  double GetNextTimeout();

  //
  // Invoked from Javascript to register the given function as
  // an event handler.
  //
  bool RegisterEventFunction(v8::Local<v8::String> v8_name,
                             v8::Local<v8::Function> v8_func,
                             int priority);

  bool RegisterHookFunction(v8::Local<v8::String> v8_name,
                            v8::Local<v8::Function> v8_func,
                            int priority);

  // Raise event on the Zeek side.
  bool ZeekEvent(v8::Local<v8::String> v8_name, v8::Local<v8::Array> v8_args);
  // Invoke the given Zeek function with the provided args
  v8::Local<v8::Value> ZeekInvoke(v8::Local<v8::String> v8_name,
                                  v8::Local<v8::Array> v8_args);

  // Callbacks attached to the zeek object.
  static void PrintCallback(const v8::FunctionCallbackInfo<v8::Value>& args);
  static void ZeekGet(v8::Local<v8::Name> name,
                      const v8::PropertyCallbackInfo<v8::Value>& info);
  static void ZeekOnCallback(const v8::FunctionCallbackInfo<v8::Value>& args);
  static void ZeekHookCallback(const v8::FunctionCallbackInfo<v8::Value>& args);
  static void ZeekEventCallback(const v8::FunctionCallbackInfo<v8::Value>& args);
  static void ZeekInvokeCallback(const v8::FunctionCallbackInfo<v8::Value>& args);

  v8::Global<v8::Context>& GetContext() { return context_; };

  v8::Isolate* GetIsolate() { return isolate_; };
  [[nodiscard]] v8::Local<v8::Value> Wrap(const zeek::ValPtr& vp) const {
    return zeek_val_wrapper_.get()->Wrap(vp);
  }

  friend class EventHandler;
  friend class HookHandler;

 private:
  void SetupZeekObject(v8::Local<v8::Context> context,
                       v8::Isolate* isolate,
                       const std::vector<std::filesystem::path>& files);
  bool ExecuteAndWaitForInit(v8::Local<v8::Context> context,
                             v8::Isolate* isolate,
                             const std::string& main_script_source);

  std::optional<zeek::Args> v8_to_zeek_args(const zeek::FuncType* ft,
                                            v8::Local<v8::Array> v8_args);

  // Back-referene for to register the callback handlers.
  plugin::Corelight_ZeekJS::Plugin* plugin_;

  std::unique_ptr<node::MultiIsolatePlatform> node_platform_;
  std::shared_ptr<node::ArrayBufferAllocator> node_allocator_;
  // Not sure this is clever.
  std::unique_ptr<node::IsolateData, decltype(&node::FreeIsolateData)>
      node_isolate_data_;
  std::unique_ptr<node::Environment, decltype(&node::FreeEnvironment)>
      node_environment_;
  uv_loop_t loop;

  v8::Isolate* isolate_;
  v8::Global<v8::Context> context_;

  // Wrapping.
  std::unique_ptr<ZeekValWrapper> zeek_val_wrapper_;

  // Allows kicking/notifying the Zeek IO loop.
  plugin::Corelight_ZeekJS::IOLoop::PipeSource* zeek_notifier_;
};

class EventHandler : public plugin::Corelight_ZeekJS::Js::EventHandler {
 public:
  EventHandler(Instance* instance, v8::Isolate* isolate, v8::Local<v8::Function> func)
      : instance_(instance), isolate_(isolate) {
    func_.Reset(isolate_, func);
  }

  void operator()(const zeek::IntrusivePtr<zeek::Event> event) override;

 private:
  Instance* instance_;

  v8::Isolate* isolate_;
  v8::Global<v8::Function> func_;
};

class HookHandler : public plugin::Corelight_ZeekJS::Js::HookHandler {
 public:
  HookHandler(Instance* instance, v8::Isolate* isolate, v8::Local<v8::Function> func)
      : instance_(instance), isolate_(isolate) {
    func_.Reset(isolate_, func);
  }

  plugin::Corelight_ZeekJS::Js::HookHandlerResult operator()(
      const zeek::Args& args) override;

 private:
  Instance* instance_;

  v8::Isolate* isolate_;
  v8::Global<v8::Function> func_;
};

}  // namespace plugin::Nodejs
