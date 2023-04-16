#include <stdexcept>

// pipe(), O_CLOEXEC, ...
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

void LoopSource::UpdateTime() {
  instance_->UpdateTime();
}

int LoopSource::GetFd() {
  return instance_->GetLoopFd();
}

PipeSource::PipeSource(plugin::Nodejs::Instance* instance) : instance_(instance) {
  if (pipe(notify_pipe_.data())) {
    throw std::runtime_error("Failed to create notify_pipe");
  }
  if (fcntl(notify_pipe_[0], F_SETFD, O_CLOEXEC) ||
      fcntl(notify_pipe_[1], F_SETFD, O_CLOEXEC)) {
    throw std::runtime_error("Failed to set pipe close-on-exec");
  }
  if (fcntl(notify_pipe_[0], F_SETFL, O_NONBLOCK) ||
      fcntl(notify_pipe_[1], F_SETFL, O_NONBLOCK)) {
    throw std::runtime_error("Failed to set pipe non-blocking");
  }
  SetClosed(false);
}

PipeSource::~PipeSource() {
  if (close(notify_pipe_[0]) != 0)
    eprintf("%s", "Failed to close _notify_pipe[0]");
  if (close(notify_pipe_[1]) != 0)
    eprintf("%s", "Failed to close _notify_pipe[0]");
}

void PipeSource::Process() {
  char c;
  ssize_t r = read(notify_pipe_[0], &c, 1);
  if (r != 1) {
    eprintf("PipeSource read failed: r=%zd error=%s", r, strerror(errno));
    throw std::runtime_error("Failed to read notification");
  }
  instance_->Process();
}

int PipeSource::GetFd() {
  return notify_pipe_[0];
}

void PipeSource::Notify() {
  ssize_t r = write(notify_pipe_[1], "n", 1);
  if (r != 1) {
    eprintf("PipeSource write failed: r=%zd error=%s", r, strerror(errno));
    throw std::runtime_error("Failed to send notification");
  }
}

}  // namespace plugin::Corelight_ZeekJS::IOLoop
