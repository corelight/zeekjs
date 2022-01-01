#pragma once

#include <node/node.h>
#include <node/v8.h>

#include <zeek/Reporter.h>

namespace plugin::Nodejs {

// Inspiration from node_errors.cc
void PrintUncaughtException(v8::Local<v8::Message> msg, v8::Local<v8::Value> exc) {
  v8::Isolate* isolate = msg->GetIsolate();
  v8::Local<v8::Context> context = isolate->GetCurrentContext();

  v8::String::Utf8Value exc_value(isolate,
                                  exc->ToDetailString(context).ToLocalChecked());
  std::fprintf(stderr, "Uncaught %s\n", *exc_value);

  v8::ScriptOrigin origin = msg->GetScriptOrigin();
  int line = msg->GetLineNumber(context).FromJust();
  v8::String::Utf8Value resource_name(isolate, origin.ResourceName());
  v8::Local<v8::String> source_line = msg->GetSourceLine(context).ToLocalChecked();
  v8::String::Utf8Value source_line_value(isolate, source_line);
  std::fprintf(stderr, "%s:%i\n%s\n\n", *resource_name, line, *source_line_value);

  std::fprintf(stderr, "Thrown at:\n");
  v8::Local<v8::StackTrace> trace = msg->GetStackTrace();

  for (int i = 0; i < trace->GetFrameCount(); i++) {
    v8::Local<v8::StackFrame> frame = trace->GetFrame(isolate, i);
    v8::String::Utf8Value script_name(isolate, frame->GetScriptName());
    v8::String::Utf8Value func_name(isolate, frame->GetFunctionName());

    std::fprintf(stderr, "    at %s (%s:%i:%i)\n", *func_name, *script_name,
                 frame->GetLineNumber(), frame->GetColumn());
  }
  node::async_id async_id = node::AsyncHooksGetExecutionAsyncId(isolate);
  node::async_id async_trigger_id = node::AsyncHooksGetTriggerAsyncId(isolate);
  if (async_id != 0) {
    std::fprintf(
        stderr,
        "Also, the async stack is likely corrupt (async_id=%f async_trigger_id=%f)\n",
        async_id, async_trigger_id);
  }
}
}  // namespace plugin::Nodejs
