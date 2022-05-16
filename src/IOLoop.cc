#include <stdexcept>

// pipe2, O_CLOEXEC, ...
#include <fcntl.h>
#include <unistd.h>

#include "IOLoop.h"
#include "Nodejs.h"

namespace plugin::Corelight_ZeekJS::IOLoop {

void LoopSource::Process() {
  instance_->Process();
}

double LoopSource::GetNextTimeout() {
  return instance_->GetNextTimeout();
}

void LoopSource::Done() {
  dprintf("LoopSource unregistered");

  // We manage our own lifetime.
  delete this;
}

void LoopSource::UpdateTime() {
  instance_->UpdateTime();
}

int LoopSource::GetFd() {
  return instance_->GetLoopFd();
}

PipeSource::PipeSource(plugin::Nodejs::Instance* instance) : instance_(instance) {
  if (pipe2(notify_pipe_.data(), O_CLOEXEC | O_NONBLOCK)) {
    throw std::runtime_error("Failed to create notify_pipe");
  }
  SetClosed(false);
}

PipeSource::~PipeSource() {
  if (close(notify_pipe_[0]) != 0)
    eprintf("Failed to close _notify_pipe[0]");
  if (close(notify_pipe_[1]) != 0)
    eprintf("Failed to close _notify_pipe[0]");
}

void PipeSource::Process() {
  char c;
  ssize_t r;
  if ((r = read(notify_pipe_[0], &c, 1)) != 1) {
    eprintf("r=%zd error=%s", r, strerror(errno));
    throw std::runtime_error("Failed to read notification");
  }
  instance_->Process();
}

int PipeSource::GetFd() {
  return notify_pipe_[0];
}

void PipeSource::Notify() {
  ssize_t r;
  if ((r = write(notify_pipe_[1], "n", 1) != 1)) {
    eprintf("r=%zd error=%s", r, strerror(errno));
    throw std::runtime_error("Failed to send notification");
  }
}

}  // namespace plugin::Corelight_ZeekJS::IOLoop
