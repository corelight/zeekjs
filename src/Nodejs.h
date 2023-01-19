#pragma once
#include <filesystem>
#include <optional>
#include <vector>

#include <node/node.h>
#include <node/v8.h>
#include <uv.h>

#include "IOLoop.h"
#include "Types.h"
#include "ZeekJS.h"

// Prototypes for plugin hooks.
namespace plugin::Corelight_ZeekJS {
class Plugin;
}

namespace plugin::Nodejs {

class EventHandler;

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

  void BeforeExit();
  void Done();

  void SetZeekNotifier(plugin::Corelight_ZeekJS::IOLoop::PipeSource* n) {
    zeek_notifier_ = n;
  }

  // Called by the thin JsLoopIOSource
  int GetLoopFd();
  void Process();
  void UpdateTime();
  double GetNextTimeout();
  bool IsAlive();

  void SetJsCalled(bool js_called = true) { js_called_ = js_called; };
  bool WasJsCalled() { return js_called_; };

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

  v8::MaybeLocal<v8::Value> ZeekAs(v8::Local<v8::String> v8_name,
                                   v8::Local<v8::Value> v8_arg);

  // Callbacks attached to the zeek object.
  static void PrintCallback(const v8::FunctionCallbackInfo<v8::Value>& args);
  static void ZeekGet(v8::Local<v8::Name> name,
                      const v8::PropertyCallbackInfo<v8::Value>& info);
  static void ZeekOnCallback(const v8::FunctionCallbackInfo<v8::Value>& args);
  static void ZeekHookCallback(const v8::FunctionCallbackInfo<v8::Value>& args);
  static void ZeekEventCallback(const v8::FunctionCallbackInfo<v8::Value>& args);
  static void ZeekInvokeCallback(const v8::FunctionCallbackInfo<v8::Value>& args);
  static void ZeekAsCallback(const v8::FunctionCallbackInfo<v8::Value>& args);
  static void ZeekSelectFieldsCallback(const v8::FunctionCallbackInfo<v8::Value>& args);
  static void AddZeekObject(v8::Local<v8::Object> exports,
                            v8::Isolate* isolate,
                            v8::Local<v8::Context> context,
                            Instance* instance);

  v8::Isolate* GetIsolate() { return isolate_; };
  const std::vector<std::filesystem::path>& GetFiles() { return files_; };
  v8::Local<v8::Value> Wrap(const zeek::ValPtr& vp, int attr_mask = 0) {
    return zeek_val_wrapper_->Wrap(vp, attr_mask);
  }
  v8::Local<v8::Value> WrapAsObject(const zeek::ValPtr& vp, int attr_mask = 0) {
    return zeek_val_wrapper_->WrapAsObject(vp, attr_mask);
  }
  bool Unwrap(v8::Local<v8::Object> obj, ZeekValWrap** wrap) {
    return zeek_val_wrapper_->Unwrap(GetIsolate(), obj, wrap);
  }

  // The "process" object.
  v8::Local<v8::Object> GetProcessObj() { return process_obj_.Get(GetIsolate()); }

  friend class EventHandler;
  friend class HookHandler;

 private:
  bool ExecuteAndWaitForInit(v8::Local<v8::Context> context,
                             v8::Isolate* isolate,
                             const std::string& main_script_source);

  std::optional<zeek::Args> v8_to_zeek_args(const zeek::FuncType* ft,
                                            v8::Local<v8::Array> v8_args);

  // Files to be loaded
  std::vector<std::filesystem::path> files_;

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

  // Wrapping.
  std::unique_ptr<ZeekValWrapper> zeek_val_wrapper_;

  // Allows kicking/notifying the Zeek IO loop.
  plugin::Corelight_ZeekJS::IOLoop::PipeSource* zeek_notifier_;

  // Marker for HookDrainEvents() whether instance->Process() should be called.
  bool js_called_ = false;

  // Handle to the Node.js "process" object. Used for top-level CallbackScope
  // invocations. This is the object that Node.js uses for CheckImmediate and
  // RunTimers, so lets do that, too.
  v8::Global<v8::Object> process_obj_;
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
