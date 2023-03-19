#pragma once
#include <array>
#include <stdexcept>

#include <zeek/iosource/IOSource.h>

namespace plugin::Nodejs {
class Instance;
}

namespace plugin::Corelight_ZeekJS::IOLoop {

/*
 * Tiny layer between Nodejs::Instance and the zeek::iosource::IOSource
 * world. Not sure how useful really, but at least it disconnects lifetime
 * of the Node.js instance and the IOSource as the IOManager deletes the
 * IOSources registered with it.
 */
class LoopSource : public zeek::iosource::IOSource {
 public:
  LoopSource(plugin::Nodejs::Instance* instance) : instance_(instance) {
    SetClosed(false);
  }

  void Process() override;

  double GetNextTimeout() override;

  const char* Tag() override { return "LoopSource"; };

  void UpdateTime();

  int GetFd();

  void UpdateClosed(bool closed) { SetClosed(closed); }

 private:
  plugin::Nodejs::Instance* instance_ = nullptr;
};

// IOSource build around pipe() for kicking the Zeek IO loop
class PipeSource : public zeek::iosource::IOSource {
 public:
  PipeSource(plugin::Nodejs::Instance* instance);
  ~PipeSource() override;

  void Process() override;

  double GetNextTimeout() override { return -1.0; };

  const char* Tag() override { return "PipeSource"; }

  int GetFd();

  void Notify();

 private:
  plugin::Nodejs::Instance* instance_ = nullptr;
  std::array<int, 2> notify_pipe_;
};

}  // namespace plugin::Corelight_ZeekJS::IOLoop
