#pragma once

#include <cassert>
#include <condition_variable>
#include <future>
#include <mutex>
#include <queue>
#include <thread>
#include <type_traits>
#include <utility>

namespace plugin::Nodejs {

/**
 * Helper class to offload execution of function to a separate thread.
 */
class Executor {
 public:
  Executor() : t(std::thread([this] { Loop(); })) {}
  ~Executor() {
    {
      std::unique_lock lk{mtx};
      stop = true;
      cv.notify_one();
    }

    try {
      t.join();
      // NOLINTNEXTLINE(bugprone-empty-catch)
    } catch (...) {
      // swallow
    }
  }

  /**
   * Runs the given function and arguments in the thread
   * started by this executor and waits for the result.
   */
  template <typename Func>
  auto Run(Func f) {
    using ret_type = std::invoke_result_t<Func>;

    // If Run() is invoked by the internal executor thread,
    // just execute f() directly, otherwise this
    // results in a dead lock.
    if (std::this_thread::get_id() == t.get_id()) {
      return f();
    }

    auto r = Submit(std::forward<Func>(f));
    r.wait();

    if constexpr (std::is_same_v<ret_type, void>) {
      return;
    } else {
      return r.get();
    }
  }

 private:
  /**
   * Submit a function its arguments for execution by the executor,
   * returning a future.
   */
  template <typename Func>
  auto Submit(Func f) {
    using ret_type = std::invoke_result_t<Func>;

    std::promise<ret_type> r;
    auto result = r.get_future();

    auto lc =
        std::packaged_task<void()>([r = std::move(r), f = std::move(f)]() mutable {
          if constexpr (std::is_same_v<ret_type, void>) {
            f();
            r.set_value();
          } else {
            auto invoked = f();
            r.set_value(invoked);
          }
        });

    {
      std::unique_lock lk{mtx};
      queue.push(std::move(lc));
      cv.notify_one();
    }

    return result;
  }

  /**
   * Dequeue and execute the pending task.
   */
  void Loop() {
    while (true) {
      std::packaged_task<void()> task;

      // Wait for a task in the queue.
      {
        std::unique_lock lk{mtx};

        while (queue.empty() && !stop)
          cv.wait(lk);

        assert(stop || !queue.empty());

        if (stop && queue.empty())
          break;

        task = std::move(queue.front());  // fetch the task
        queue.pop();                      // consumes the task
      }

      // If we get here, we picked up a task, run it.
      task();
    }
  }

  std::mutex mtx;  // Protects `queue` and `stop`.
  bool stop = false;
  std::condition_variable cv;
  std::queue<std::packaged_task<void()>> queue;
  std::thread t;  // Last member so ctr'd after all deps.
};

}  // namespace plugin::Nodejs
