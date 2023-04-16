#pragma once

#include <filesystem>
#include <memory>
#include <vector>

#include <zeek/Event.h>
#include <zeek/EventRegistry.h>
#include <zeek/iosource/IOSource.h>
#include <zeek/plugin/Plugin.h>

#include "IOLoop.h"
#include "Nodejs.h"

namespace plugin::Corelight_ZeekJS {

class Plugin : public zeek::plugin::Plugin {
 public:
  void InitPreScript() override;
  void InitPostScript() override;
  void HookDrainEvents() override;
  int HookLoadFile(const zeek::plugin::Plugin::LoadType,
                   const std::string& file,
                   const std::string& resolved) override;

  void Done() override;

  // Methods for use by the Node.js Instance.
  //
  // These do not know about Javascript / or V8 specifics.
  bool RegisterJsEventHandler(const std::string& name,
                              Js::EventHandler* js_eh,
                              int priority);

  bool RegisterJsHookHandler(const std::string& name,
                             Js::HookHandler* js_eh,
                             int priority);

  // Invoke the given event with args.
  bool Event(const std::string& name, const zeek::Args& args);

  // Invoke the given function with args.
  zeek::ValPtr Invoke(const std::string& name,
                      zeek::Args& args,
                      const std::string& file_name,
                      int line_number);

 protected:
  zeek::plugin::Configuration Configure() override;

 private:
  // Add the given Javascript event handler as new body
  // into the given Zeek handler as function
  bool RegisterAsScriptFuncBody(zeek::EventHandlerPtr zeek_eh,
                                Js::EventHandler* js_eh,
                                int priority);

  std::vector<std::filesystem::path> load_files;
  plugin::Nodejs::Instance* nodejs;
  std::unique_ptr<plugin::Corelight_ZeekJS::IOLoop::LoopSource> loop_io_source;
};

extern Plugin plugin;

}  // namespace plugin::Corelight_ZeekJS
