#include "Nodejs.h"
#include "IOLoop.h"

#include <algorithm>
#include <chrono>
#include <filesystem>
#include <memory>
#include <string>
#include <thread>
#include <vector>

#include <node/node.h>
#include <node/v8.h>

// Using RegisterJsEventHandler on the passed plugin.
#include "Helpers.h"
#include "Plugin.h"

#include "zeek/Scope.h"  // global_scope()->Vars()
#include "zeek/Val.h"    // Val::nil

using namespace plugin::Nodejs;

static v8::Local<v8::String> v8_str_intern(v8::Isolate* i, const char* s) {
  return v8::String::NewFromUtf8(i, s, v8::NewStringType::kInternalized)
      .ToLocalChecked();
}

static v8::Local<v8::String> v8_str(v8::Isolate* i, const char* s) {
  return v8::String::NewFromUtf8(i, s).ToLocalChecked();
}

// Callbacks for zeek.vars
static void ZeekGlobalVarsGetter(v8::Local<v8::Name> property,
                                 const v8::PropertyCallbackInfo<v8::Value>& info) {
  v8::Isolate* isolate = info.GetIsolate();

  auto zeek_obj = v8::Local<v8::Object>::Cast(info.Data());
  auto field = v8::Local<v8::External>::Cast(zeek_obj->GetInternalField(0));
  auto instance = static_cast<Instance*>(field->Value());

  v8::String::Utf8Value arg(isolate, property);
  dprintf("Property... %s", *arg);
  if (*arg) {
    const zeek::detail::IDPtr& id = zeek::id::find(*arg);
    if (!id)
      return;
    info.GetReturnValue().Set(instance->Wrap(id->GetVal()));
  }
}

static void ZeekGlobalVarsEnumerator(const v8::PropertyCallbackInfo<v8::Array>& info) {
  v8::Isolate* isolate = info.GetIsolate();
  v8::Local<v8::Context> context = isolate->GetCurrentContext();

  const std::map<std::string, zeek::detail::IDPtr, std::less<>>& globals =
      zeek::detail::global_scope()->Vars();

  if (globals.size() > INT_MAX) {
    eprintf("Too many entries in globals: %lu", globals.size());
    return;
  }

  int size = static_cast<int>(globals.size());
  int i = 0;
  v8::Local<v8::Array> array = v8::Array::New(isolate, size);
  for (const auto& entry : globals) {
    if (!entry.second->HasVal())
      continue;

    // There's not much we can do with functions.
    if (zeek::IsFunc(entry.second->GetType()->Tag()))
      continue;

    v8::Local<v8::String> entry_name = ::v8_str_intern(isolate, entry.first.c_str());
    v8::Local<v8::Name> name = v8::Local<v8::Name>::New(isolate, entry_name);

    array->Set(context, i++, name).Check();
  }

  info.GetReturnValue().Set(array);
}

// Call a Javascript function with Zeek land arguments.
//
// The caller is supposed to enter the IsolateScope and HandleScope so that
// the result can be returned as v8::Local without dealing with
// EscapableHandleScope and Escape().
static v8::Local<v8::Value> callFunction(v8::Isolate* isolate,
                                         Instance* instance,
                                         v8::Local<v8::Function> func,
                                         const zeek::Args& args) {
  v8::Local<v8::Context> context = isolate->GetCurrentContext();

  // TODO: Who's the receiver if the function is bound? Shouldn't it be
  //       the object the function is bounded to?
  //       https://developer.mozilla.org/en-US/docs/Web/JavaScript/Reference/Global_objects/Function/bind
  v8::Local<v8::Object> receiver = context->Global();
  node::Environment* env = node::GetCurrentEnvironment(context);
  node::CallbackScope callback_scope(env, instance->GetProcessObj(), {0, 0});

  instance->SetJsCalled();

  v8::Local<v8::Value> result;
  std::vector<v8::Local<v8::Value>> v8_args;

  for (auto const& arg : args)
    v8_args.push_back(instance->Wrap(arg));

  auto argc = static_cast<int>(args.size());
  if (func->Call(context, receiver, argc, &v8_args[0]).ToLocal(&result))
    return result;

  // If we get here, we either exit due to an unhandled exception, or
  // if ZeekJS::exit_on_uncaught_exceptions=F, the user will need to
  // figure out what's going on.

  return v8::Undefined(isolate);
}

// Invoke the registered v8::Function for the given Event
void plugin::Nodejs::EventHandler::operator()(
    const zeek::IntrusivePtr<zeek::Event> event) {
  v8::Isolate::Scope isolate_scope(isolate_);
  v8::HandleScope handle_scope(isolate_);
  v8::Local<v8::Function> func = func_.Get(isolate_);
  callFunction(isolate_, instance_, func, event->Args());
}

// Invoke the registered v8::Function for a hook, returning a HookHandlerResult
plugin::Corelight_ZeekJS::Js::HookHandlerResult HookHandler::operator()(
    const zeek::Args& args) {
  v8::Isolate::Scope isolate_scope(isolate_);
  v8::HandleScope handle_scope(isolate_);
  v8::Local<v8::Function> func = func_.Get(isolate_);
  plugin::Corelight_ZeekJS::Js::HookHandlerResult hh_result;

  v8::Local<v8::Value> result = callFunction(isolate_, instance_, func, args);

#ifdef DEBUG
  v8::String::Utf8Value result_str(isolate_, result);
  v8::String::Utf8Value result_type_str(isolate_, result->TypeOf(isolate_));
  dprintf("Hook function returned %s: %s", *result_type_str, *result_str);
#endif

  // When a hook explicitly returns false, use FLOW_BREAK to indicate
  // to zeek that that this hook vetoed continuation of processing.
  if (result->IsFalse())
    hh_result.flow = zeek::detail::FLOW_BREAK;

  return hh_result;
}
Instance::Instance()
    : node_isolate_data_(nullptr, node::FreeIsolateData),
      node_environment_(nullptr, node::FreeEnvironment) {}

// Poor print function. Might make sense to hook it through to
// Stmt::do_print_stmp
void Instance::PrintCallback(const v8::FunctionCallbackInfo<v8::Value>& args) {
  v8::Isolate* isolate = args.GetIsolate();
  if (args.Length() != 1) {
    isolate->ThrowException(v8_str(isolate, "print expected 1 arg"));
    return;
  }

  v8::HandleScope scope(isolate);
  v8::Local<v8::Value> arg = args[0];
  v8::String::Utf8Value value(isolate, arg);
  std::printf("%s\n", *value);
}

//
// Callback for zeek.event
//
// zeek.event('my_event', [arg1, ...])
//
void Instance::ZeekEventCallback(const v8::FunctionCallbackInfo<v8::Value>& args) {
  v8::Isolate* isolate = args.GetIsolate();
  auto zeek_obj = v8::Local<v8::Object>::Cast(args.Data());
  auto field = v8::Local<v8::External>::Cast(zeek_obj->GetInternalField(0));
  auto instance = static_cast<Instance*>(field->Value());

  if (args.Length() < 1 || args.Length() > 2) {
    isolate->ThrowException(v8_str(isolate, "Expected 1 or 2 args"));
    return;
  }

  if (!args[0]->IsString()) {
    isolate->ThrowException(v8_str(isolate, "Expected string as first argument"));
    return;
  }

  v8::Local<v8::String> name = v8::Local<v8::String>::Cast(args[0]);
  v8::Local<v8::Array> v8_args;
  if (args.Length() == 2) {
    if (!args[1]->IsArray()) {
      isolate->ThrowException(v8_str(isolate, "Expected array as second argument"));
      return;
    }

    v8_args = v8::Local<v8::Array>::Cast(args[1]);
  } else {
    v8_args = v8::Array::New(isolate, 0);
  }

#ifdef DEBUG
  v8::String::Utf8Value utf8name(isolate, args[0]);
  dprintf("Event for %s", *utf8name);
#endif

  // If this fails, ZeekEvent() will have thrown internally.
  instance->ZeekEvent(name, v8_args);
}

//
// Callback for zeek.invoke
//
// zeek.invoke('zeek_version')
// zeek.invoke('sqrt', [4])
//
void Instance::ZeekInvokeCallback(const v8::FunctionCallbackInfo<v8::Value>& args) {
  v8::Isolate* isolate = args.GetIsolate();
  auto zeek_obj = v8::Local<v8::Object>::Cast(args.Data());
  auto field = v8::Local<v8::External>::Cast(zeek_obj->GetInternalField(0));
  auto instance = static_cast<Instance*>(field->Value());

  if (args.Length() < 1 || args.Length() > 2) {
    isolate->ThrowException(v8_str(isolate, "Expected 1 or 2 args"));
    return;
  }

  if (!args[0]->IsString()) {
    isolate->ThrowException(v8_str(isolate, "Expected string as first argument"));
    return;
  }

  auto name = v8::Local<v8::String>::Cast(args[0]);
  v8::Local<v8::Array> v8_args;
  if (args.Length() == 2) {
    if (!args[1]->IsArray()) {
      isolate->ThrowException(v8_str(isolate, "Expected array as second argument"));
      return;
    }

    v8_args = v8::Local<v8::Array>::Cast(args[1]);
  } else {
    v8_args = v8::Array::New(isolate, 0);
  }

  v8::Local<v8::Value> ret = instance->ZeekInvoke(name, v8_args);
  args.GetReturnValue().Set(ret);
}

//
// Callback for zeek.as
//
// zeek.as(typename, data)
//
void Instance::ZeekAsCallback(const v8::FunctionCallbackInfo<v8::Value>& args) {
  v8::Isolate* isolate = args.GetIsolate();
  auto zeek_obj = v8::Local<v8::Object>::Cast(args.Data());
  auto field = v8::Local<v8::External>::Cast(zeek_obj->GetInternalField(0));
  auto instance = static_cast<Instance*>(field->Value());

  if (args.Length() != 2) {
    isolate->ThrowException(v8_str(isolate, "Expected 2 args"));
    return;
  }

  if (!args[0]->IsString()) {
    isolate->ThrowException(
        v8::Exception::TypeError(v8_str(isolate, "Expected string as first argument")));
    return;
  }

  v8::MaybeLocal<v8::Value> maybe_value =
      instance->ZeekAs(v8::Local<v8::String>::Cast(args[0]), args[1]);

  // instance->ZeekAs() should have thrown something.
  if (maybe_value.IsEmpty())
    return;

  args.GetReturnValue().Set(maybe_value.ToLocalChecked());
}

//
// Callback for zeek.select_fields
//
// zeek.select_fields(obj, attr_mask)
// zeek.select_fields(obj, zeek.ATTR_LOG)
//
void Instance::ZeekSelectFieldsCallback(
    const v8::FunctionCallbackInfo<v8::Value>& args) {
  v8::Isolate* isolate = args.GetIsolate();

  auto zeek_obj = v8::Local<v8::Object>::Cast(args.Data());
  auto field = v8::Local<v8::External>::Cast(zeek_obj->GetInternalField(0));
  auto instance = static_cast<Instance*>(field->Value());

  if (args.Length() != 2) {
    isolate->ThrowException(v8_str(isolate, "Expected 2 args"));
    return;
  }

  if (!args[0]->IsObject()) {
    isolate->ThrowException(v8_str(isolate, "Expected object as first argument"));
    return;
  }
  if (!args[1]->IsNumber()) {
    isolate->ThrowException(v8_str(isolate, "Expected number as second argument"));
    return;
  }

  auto obj = v8::Local<v8::Object>::Cast(args[0]);

  ZeekValWrap* wrap = nullptr;
  if (!instance->Unwrap(obj, &wrap)) {
    isolate->ThrowException(v8_str(isolate, "Obj does not wrap a Zeek value"));
    return;
  }
  int attr_mask = static_cast<int>(v8::Local<v8::Number>::Cast(args[1])->Value());

  // Slightly ad-hoc protection from wrong attribute filtering masks.
  if (attr_mask > ZEEKJS_ATTR_LOG) {
    isolate->ThrowException(
        v8_str(isolate, "invalid attribute mask - only 0 or 1 allowed"));
    return;
  }

  // dprintf("select_fields() wrap=%p vp=%p attr_mask=%x", wrap, wrap->GetVal(),
  //        attr_mask);
  ZeekValWrap* new_wrap = ZeekValWrap::Make(isolate, wrap->GetWrapper(), obj,
                                            wrap->GetVal()->Ref(), attr_mask);
  args.GetReturnValue().Set(new_wrap->GetHandle(isolate));
}

// Convert the v8_args to zeek::Args according to the parameters expected by ft.
std::optional<zeek::Args> Instance::v8_to_zeek_args(const zeek::FuncType* ft,
                                                    v8::Local<v8::Array> v8_args) {
  zeek::Args args;
  const zeek::RecordTypePtr& params = ft->Params();
  v8::Local<v8::Context> context = isolate_->GetCurrentContext();

  auto total_params = static_cast<uint32_t>(params->NumFields());
  uint32_t required_params =
      std::count_if(params->Types()->begin(), params->Types()->end(), [](auto pt) {
        return pt->GetAttr(zeek::detail::ATTR_OPTIONAL) == zeek::detail::Attr::nil;
      });

  if ((uint32_t)v8_args->Length() < required_params ||
      v8_args->Length() > total_params) {
    std::string error = zeek::util::fmt(
        "Wrong number of parameters. %d provided, %d required, %d total",
        v8_args->Length(), required_params, total_params);
    isolate_->ThrowException(v8_str(isolate_, error.c_str()));
    return std::nullopt;
  }

  // Convert all the v8_args to Zeek land...
  uint32_t i = 0;
  for (; i < v8_args->Length(); i++) {
    auto idx = static_cast<int>(i);
    zeek::TypePtr arg_type = params->GetFieldType(idx);
    v8::Local<v8::Value> v8_val = v8_args->Get(context, i).ToLocalChecked();

    ZeekValWrapper::Result result = zeek_val_wrapper_->ToZeekVal(v8_val, arg_type);
    if (!result.ok) {
      isolate_->ThrowException(v8_str(isolate_, result.error.c_str()));
      return std::nullopt;
    }

    args.push_back(result.val);
  }

  // ..any remaining optional/default parameters are filled with Zeek's defaults.
  for (; i < total_params; i++)
    args.push_back(params->FieldDefault(static_cast<int>(i)));

  return args;
}

bool Instance::ZeekEvent(v8::Local<v8::String> v8_name, v8::Local<v8::Array> v8_args) {
  v8::String::Utf8Value utf8name(isolate_, v8_name);

  // XXX: This is a bit annoying, but to convert the args we need
  //      to know the types of the parameters from the EventHandler
  //      func type.
  zeek::EventHandler* zeek_eh = zeek::event_registry->Lookup(*utf8name);
  if (!zeek_eh) {
    std::string error = "Unknown event ";
    error += *utf8name;
    isolate_->ThrowException(v8_str(isolate_, error.c_str()));
    return false;
  }

  zeek::FuncTypePtr ft = zeek_eh->GetType();
  std::optional<zeek::Args> args = v8_to_zeek_args(ft.get(), v8_args);
  if (!args)
    return false;

  return plugin_->Event(*utf8name, *args);
}

v8::Local<v8::Value> Instance::ZeekInvoke(v8::Local<v8::String> v8_name,
                                          v8::Local<v8::Array> v8_args) {
  v8::String::Utf8Value name_str(isolate_, v8_name);
  dprintf("invoke for %s", *name_str);
  const zeek::detail::IDPtr& id = zeek::id::find(*name_str);
  if (!id) {
    isolate_->ThrowException(
        v8_str(isolate_, zeek::util::fmt("Unknown function: %s", *name_str)));
    return v8::Undefined(isolate_);
  }

  const zeek::TypePtr t = id->GetType();
  if (!zeek::IsFunc(t->Tag())) {
    isolate_->ThrowException(v8_str(isolate_, "Not a function"));
    return v8::Undefined(isolate_);
  }

  const zeek::FuncType* ft = t->AsFuncType();
  if (ft->Flavor() == zeek::FUNC_FLAVOR_EVENT) {
    isolate_->ThrowException(v8_str(isolate_, "Cannot invoke event, use zeek.event()"));
    return v8::Undefined(isolate_);
  }

  // Non-implemented function? Exported but not defined?
  if (!id->GetVal()) {
    isolate_->ThrowException(v8_str(isolate_, "Function without value"));
    return v8::Undefined(isolate_);
  }

  std::optional<zeek::Args> args = v8_to_zeek_args(ft, v8_args);
  if (!args)
    return v8::Undefined(isolate_);

  // Extract information from the caller so we can setup a call stack
  // for Zeek to use for Reporter::info.
  v8::Local<v8::StackTrace> stack_trace =
      v8::StackTrace::CurrentStackTrace(isolate_, 1, v8::StackTrace::kOverview);
  v8::Local<v8::StackFrame> frame = stack_trace->GetFrame(isolate_, 0);

  v8::String::Utf8Value script_str(isolate_, frame->GetScriptNameOrSourceURL());
  int line_number = frame->GetLineNumber();

  zeek::ValPtr ret = plugin_->Invoke(*name_str, *args, *script_str, line_number);

  // Throw if the call returned nil and this isn't a void or any function.
  if (ret == zeek::Val::nil) {
    zeek::TypeTag tag = ft->Yield()->Tag();
    if (tag != zeek::TYPE_VOID && tag != zeek::TYPE_ANY) {
      isolate_->ThrowException(v8_str(isolate_, "Function call returned nil"));
      return v8::Undefined(isolate_);
    }
  }

#ifdef DEBUG
  const std::string& type_name =
      ret != zeek::Val::nil ? ret->GetType()->GetName() : "nil";
  dprintf("invoke for %s returned: %s", *name_str, type_name.c_str());
#endif
  return zeek_val_wrapper_->Wrap(ret);
}

namespace {
// Uhm, uhm, uhm... the base types don't have identifiers and
// I haven't found a nice lookup table to get access to them.
zeek::TypePtr try_name_to_basetype(const std::string& name) {
  for (int i = 0; i <= zeek::TYPE_ERROR; i++) {
    auto tag = static_cast<zeek::TypeTag>(i);
    if (name == zeek::type_name(tag)) {
      return zeek::base_type(tag);
      break;
    }
  }
  return nullptr;
}
}  // namespace

v8::MaybeLocal<v8::Value> Instance::ZeekAs(v8::Local<v8::String> v8_name,
                                           v8::Local<v8::Value> v8_arg) {
  std::string name = *v8::String::Utf8Value(isolate_, v8_name);
  const zeek::detail::IDPtr& id = zeek::id::find(name);

  zeek::TypePtr as_type;

  if (!id)
    as_type = try_name_to_basetype(name);
  else
    as_type = id->GetType();

  if (!as_type) {
    isolate_->ThrowException(
        v8_str(isolate_, zeek::util::fmt("'%s' is not a Zeek type", name.c_str())));
    return {};
  }

  ZeekValWrapper::Result result = zeek_val_wrapper_->ToZeekVal(v8_arg, as_type);
  if (!result.ok) {
    isolate_->ThrowException(
        v8::Exception::TypeError(v8_str(isolate_, result.error.c_str())));
    return {};
  }

  return {WrapAsObject(result.val)};
}

// Common arguments for zeek.on and zeek.hook.
//
// zeek.on(name [, options ], function)
// zeek.hook(name [, options ], function)
struct HandlerArgs {
  v8::Local<v8::Function> func;
  v8::Local<v8::String> name;
  int priority;
  bool error;

  static HandlerArgs Parse(const v8::FunctionCallbackInfo<v8::Value>& args) {
    v8::Isolate* isolate = args.GetIsolate();
    HandlerArgs result = {.error = true};

    if (args.Length() < 2 || args.Length() > 3) {
      isolate->ThrowException(v8_str(isolate, "Expected 2 or 3 args"));
      return result;
    }

    if (!args[0]->IsString()) {
      isolate->ThrowException(v8_str(isolate, "Expected string as first parameter"));
      return result;
    }

    result.name = v8::Local<v8::String>::Cast(args[0]);

    int priority = 0;
    int func_idx = 0;

    if (args.Length() == 2) {
      func_idx = 1;
    } else if (args.Length() == 3) {
      // zeek.on(name, options, function) form.
      func_idx = 2;
      if (!args[1]->IsObject()) {
        isolate->ThrowException(v8_str(isolate, "Expected options to be an object"));
        return result;
      }

      auto options = v8::Local<v8::Object>::Cast(args[1]);
      v8::Local<v8::Name> v8_priority_key =
          v8::Local<v8::Name>::New(isolate, v8_str_intern(isolate, "priority"));
      v8::MaybeLocal<v8::Value> priority_maybe =
          options->Get(isolate->GetCurrentContext(), v8_priority_key);
      if (!priority_maybe.IsEmpty()) {
        v8::Local<v8::Value> priority_val = priority_maybe.ToLocalChecked();
        if (!priority_val->IsNumber()) {
          isolate->ThrowException(v8_str(isolate, "options.priority is not a number"));
          return result;
        }
        result.priority = v8::Local<v8::Int32>::Cast(priority_val)->Value();
      }
    }

    if (!args[func_idx]->IsFunction()) {
      isolate->ThrowException(v8_str(isolate, "Expected string and function"));
      return result;
    }

    result.func = v8::Local<v8::Function>::Cast(args[func_idx]);
    result.error = false;
    return result;
  };
};

void Instance::ZeekOnCallback(const v8::FunctionCallbackInfo<v8::Value>& args) {
  v8::Isolate* isolate = args.GetIsolate();
  auto zeek_obj = v8::Local<v8::Object>::Cast(args.Data());
  auto field = v8::Local<v8::External>::Cast(zeek_obj->GetInternalField(0));
  auto instance = static_cast<Instance*>(field->Value());

  HandlerArgs ha = HandlerArgs::Parse(args);
  if (ha.error)  // HandlerArgs::Parse will have thrown.
    return;

  if (!instance->RegisterEventFunction(ha.name, ha.func, ha.priority)) {
    isolate->ThrowException(v8_str(isolate, "Failed to register function"));
  }
}

void Instance::ZeekHookCallback(const v8::FunctionCallbackInfo<v8::Value>& args) {
  v8::Isolate* isolate = args.GetIsolate();
  auto zeek_obj = v8::Local<v8::Object>::Cast(args.Data());
  auto field = v8::Local<v8::External>::Cast(zeek_obj->GetInternalField(0));
  auto instance = static_cast<Instance*>(field->Value());

  HandlerArgs ha = HandlerArgs::Parse(args);
  if (ha.error)  // HandlerArgs::Parse will have thrown.
    return;

  if (!instance->RegisterHookFunction(ha.name, ha.func, ha.priority)) {
    isolate->ThrowException(v8_str(isolate, "Failed to register function"));
  }
}

bool Instance::RegisterEventFunction(v8::Local<v8::String> v8_name,
                                     v8::Local<v8::Function> func,
                                     int priority) {
  v8::String::Utf8Value utf8name(GetIsolate(), v8_name);
  auto handler = new plugin::Nodejs::EventHandler(this, GetIsolate(), func);
  return plugin_->RegisterJsEventHandler(*utf8name, handler, priority);
}

bool Instance::RegisterHookFunction(v8::Local<v8::String> v8_name,
                                    v8::Local<v8::Function> func,
                                    int priority) {
  v8::String::Utf8Value utf8name(isolate_, v8_name);
  auto handler = new HookHandler(this, isolate_, func);
  if (!plugin_->RegisterJsHookHandler(*utf8name, handler, priority)) {
    isolate_->ThrowException(v8_str(isolate_, "Failed to register hook"));
    return false;
  }
  return true;
}

// Add zeek object to the given exports.
//
// Not yet sure this is the right way to go about it :-/
void Instance::AddZeekObject(v8::Local<v8::Object> exports,
                             v8::Isolate* isolate,
                             v8::Local<v8::Context> context,
                             Instance* instance) {
  v8::Local<v8::ObjectTemplate> zeek_tmpl = v8::ObjectTemplate::New(isolate);
  zeek_tmpl->SetInternalFieldCount(1);
  v8::Local<v8::Object> zeek_obj = zeek_tmpl->NewInstance(context).ToLocalChecked();
  zeek_obj->SetInternalField(0, v8::External::New(isolate, instance));

  v8::Local<v8::String> on_str = v8_str_intern(isolate, "on");
  v8::Local<v8::FunctionTemplate> zeek_on_tmpl =
      v8::FunctionTemplate::New(isolate, ZeekOnCallback, zeek_obj);
  zeek_obj->Set(context, on_str, zeek_on_tmpl->GetFunction(context).ToLocalChecked())
      .Check();

  // TODO: Make this use the PrintStmt if possible.
  v8::Local<v8::String> print_str = v8_str_intern(isolate, "print");
  v8::Local<v8::FunctionTemplate> zeek_print_tmpl =
      v8::FunctionTemplate::New(isolate, PrintCallback, zeek_obj);
  zeek_obj
      ->Set(context, print_str, zeek_print_tmpl->GetFunction(context).ToLocalChecked())
      .Check();

  v8::Local<v8::String> event_str = v8_str_intern(isolate, "event");
  v8::Local<v8::FunctionTemplate> zeek_event_tmpl =
      v8::FunctionTemplate::New(isolate, ZeekEventCallback, zeek_obj);
  zeek_obj
      ->Set(context, event_str, zeek_event_tmpl->GetFunction(context).ToLocalChecked())
      .Check();

  v8::Local<v8::String> hook_str = v8_str_intern(isolate, "hook");
  v8::Local<v8::FunctionTemplate> zeek_hook_tmpl =
      v8::FunctionTemplate::New(isolate, ZeekHookCallback, zeek_obj);
  zeek_obj
      ->Set(context, hook_str, zeek_hook_tmpl->GetFunction(context).ToLocalChecked())
      .Check();

  // invoke
  v8::Local<v8::String> invoke_str = v8_str_intern(isolate, "invoke");
  v8::Local<v8::FunctionTemplate> zeek_invoke_tmpl =
      v8::FunctionTemplate::New(isolate, ZeekInvokeCallback, zeek_obj);
  zeek_obj
      ->Set(context, invoke_str,
            zeek_invoke_tmpl->GetFunction(context).ToLocalChecked())
      .Check();

  // as
  v8::Local<v8::String> as_str = v8_str_intern(isolate, "as");
  v8::Local<v8::FunctionTemplate> zeek_as_tmpl =
      v8::FunctionTemplate::New(isolate, ZeekAsCallback, zeek_obj);
  zeek_obj->Set(context, as_str, zeek_as_tmpl->GetFunction(context).ToLocalChecked())
      .Check();

  // select_fields
  v8::Local<v8::String> select_fields_str = v8_str_intern(isolate, "select_fields");
  v8::Local<v8::FunctionTemplate> zeek_select_fields_tmpl =
      v8::FunctionTemplate::New(isolate, ZeekSelectFieldsCallback, zeek_obj);
  zeek_obj
      ->Set(context, select_fields_str,
            zeek_select_fields_tmpl->GetFunction(context).ToLocalChecked())
      .Check();

  // I'm not sure that is great, but should allow us to do things like:
  // zeek.ATTR_LOG | zeek.ATTR_OPTIONAL. Numbering is independent of the
  // Zeek side AttrTag enum.
  v8::Local<v8::String> attr_log_str = v8_str_intern(isolate, "ATTR_LOG");
  zeek_obj->Set(context, attr_log_str, v8::Number::New(isolate, ZEEKJS_ATTR_LOG))
      .Check();

  // global_vars dictionary
  v8::Local<v8::String> globals_str = v8_str_intern(isolate, "global_vars");
  v8::Local<v8::ObjectTemplate> zeek_globals_tmpl = v8::ObjectTemplate::New(isolate);
  zeek_globals_tmpl->SetInternalFieldCount(1);

  v8::NamedPropertyHandlerConfiguration global_vars_conf = {nullptr};
  global_vars_conf.getter = ZeekGlobalVarsGetter;
  global_vars_conf.enumerator = ZeekGlobalVarsEnumerator;
  global_vars_conf.data = zeek_obj;
  zeek_globals_tmpl->SetHandler(global_vars_conf);

  v8::Local<v8::Object> zeek_global_vars_obj =
      zeek_globals_tmpl->NewInstance(context).ToLocalChecked();
  zeek_global_vars_obj->SetInternalField(0, v8::External::New(isolate, instance));
  zeek_obj->Set(context, globals_str, zeek_global_vars_obj).Check();

  // Files to be loaded by the bootstrapping script.
  v8::Local<v8::String> zeekjs_files_str = v8_str(isolate, "__zeek_javascript_files");
  auto files = instance->GetFiles();
  v8::Local<v8::Array> array = v8::Array::New(isolate, static_cast<int>(files.size()));
  for (unsigned long i = 0; i < files.size(); i++) {
    v8::Local<v8::String> v8_file = v8_str(isolate, files[i].c_str());
    array->Set(context, i, v8_file).Check();
  }
  zeek_obj->Set(context, zeekjs_files_str, array).Check();

  auto zeek_str = v8_str_intern(isolate, "zeek");
  exports->Set(context, zeek_str, zeek_obj).Check();
}

// Register the zeekjs module.
//
// Currently, exports a zeek object that can be accessed as follows:
//
//     const zeek = process._linkedBinding('zeekjs').zeek;
//
static void RegisterModule(v8::Local<v8::Object> exports,
                           v8::Local<v8::Value> m,
                           v8::Local<v8::Context> context,
                           void* priv) {
  auto instance = static_cast<Instance*>(priv);
  v8::Isolate* isolate = context->GetIsolate();

  Instance::AddZeekObject(exports, isolate, context, instance);
};

bool Instance::ExecuteAndWaitForInit(v8::Local<v8::Context> context,
                                     v8::Isolate* isolate,
                                     const std::string& main_script_source) {
  // Oookay, go run the main script
  v8::MaybeLocal<v8::Value> ret =
      node::LoadEnvironment(node_environment_.get(), main_script_source.c_str());

  if (ret.IsEmpty()) {
    // TODO: Introspect the error a bit.
    eprintf("%s", "LoadEnvironment() exception!?");
    return false;
  }

  // The main script is supposed to define an javascript_init() function
  // in the global scope that we'll be calling first.
  const char* init_name = "zeek_javascript_init";
  v8::Local<v8::String> v8_init_name = v8_str_intern(GetIsolate(), init_name);
  v8::Local<v8::Value> init_val;

  if (!context->Global()->Get(context, v8_init_name).ToLocal(&init_val)) {
    eprintf("Failed to get %s function from main script", init_name);
    return false;
  }
  if (!init_val->IsFunction()) {
    v8::Local<v8::String> typeof_str = init_val->TypeOf(GetIsolate());
    v8::String::Utf8Value typeof_utf8(isolate_, typeof_str);

    eprintf("No %s found or not a function (%s)", init_name, *typeof_utf8);
    return false;
  }

  // Call init
  auto init_fun = v8::Local<v8::Function>::Cast(init_val);
  v8::Local<v8::Value> result;
  if (!init_fun->Call(context, context->Global(), 0, nullptr).ToLocal(&result)) {
    eprintf("Error calling %s)", init_name);
    return false;
  }

  v8::Local<v8::String> result_typeof_str = result->TypeOf(GetIsolate());
  v8::String::Utf8Value result_typeof_utf8(isolate_, result_typeof_str);
  dprintf("init() result=%s %d", *result_typeof_utf8, result->IsPromise());

  // If we got back a Promise from zeekjs_init(), run the JS IO loop
  // until it's not pending anymore.
  if (result->IsPromise()) {
    auto promise = v8::Local<v8::Promise>::Cast(result);
    dprintf("%s returned promise, state=%d - running JS loop", init_name,
            promise->State());
    while (promise->State() == v8::Promise::PromiseState::kPending) {
      uv_run(&loop, UV_RUN_ONCE);
      node_platform_->FlushForegroundTasks(GetIsolate());
    }

    if (promise->State() == v8::Promise::PromiseState::kRejected) {
      eprintf("%s promise was rejected", init_name);
      return false;
    }
  }

  return true;
}

bool Instance::Init(plugin::Corelight_ZeekJS::Plugin* plugin,
                    const std::string& main_script_source,
                    const std::vector<std::filesystem::path>& files,
                    size_t initial_heap_size_in_bytes,
                    size_t maximum_heap_size_in_bytes,
                    bool exit_on_uncaught_exceptions,
                    int thread_pool_size) {
  plugin_ = plugin;
  files_ = files;

  std::vector<std::string> args{"zeek"};
  std::vector<std::string> exec_args;
  std::vector<std::string> errors;

  // Disable async-hooks-checks if we try to keep going on
  // uncaught exceptions. An uncaught exception in a timer
  // callback corrupts the async stack and setting this flag
  // prevents node exiting due to this.
  if (!exit_on_uncaught_exceptions) {
    args.emplace_back("--no-force-async-hooks-checks");
    args.emplace_back("--trace-uncaught");
  }

#if NODE_VERSION_AT_LEAST(18, 11, 0)
  auto flags = node::ProcessInitializationFlags::kLegacyInitializeNodeWithArgsBehavior;
#if NODE_VERSION_AT_LEAST(20, 6, 0)
  // Let Node.js initialize the Oilpan cppgc garbage collector.
  flags = node::ProcessInitializationFlags::Flags(
      flags & (~node::ProcessInitializationFlags::kNoInitializeCppgc));
#endif

  auto result = node::InitializeOncePerProcess(args, flags);
  int r = result->exit_code();
#else
  int r = node::InitializeNodeWithArgs(&args, &exec_args, &errors);
#endif

  if (r != 0) {
    eprintf("Node initialization failed: %d", r);
    return false;
  }

  dprintf("Node initialized. Compiled with %s", NODE_VERSION);

  node_platform_ = node::MultiIsolatePlatform::Create(thread_pool_size);
  v8::V8::InitializePlatform(node_platform_.get());
  v8::V8::Initialize();
  dprintf("V8 initialized. Version %s", v8::V8::GetVersion());

  r = uv_loop_init(&loop);
  if (r != 0) {
    eprintf("uv_loop_init() failed: %s", uv_err_name(r));
    return false;
  }

  node_allocator_ = node::ArrayBufferAllocator::Create();
  if (!node_allocator_) {
    eprintf("%s", "Failed to create ArrayBufferAllocator");
    return false;
  }

  isolate_ = v8::Isolate::Allocate();
  if (!isolate_) {
    eprintf("%s", "Could not allocate Isolate");
    return false;
  }

  node_platform_->RegisterIsolate(isolate_, &loop);

  v8::ResourceConstraints constraints;
  constraints.ConfigureDefaultsFromHeapSize(initial_heap_size_in_bytes,
                                            maximum_heap_size_in_bytes);

  v8::Isolate::CreateParams params;
  params.constraints = constraints;
  params.array_buffer_allocator_shared = node_allocator_;

  v8::Isolate::Initialize(isolate_, params);

  node::IsolateSettings isolate_settings;

  if (!exit_on_uncaught_exceptions) {
    // Register our own message listener for printing uncaught exceptions
    // rather than the Node.js one that terminates the process.
    isolate_settings.flags =
        isolate_settings.flags & ~node::MESSAGE_LISTENER_WITH_ERROR_LEVEL;

    GetIsolate()->SetCaptureStackTraceForUncaughtExceptions(true);

    auto message_listener = [](v8::Local<v8::Message> message,
                               v8::Local<v8::Value> error) -> void {
      v8::Isolate* isolate = message->GetIsolate();
      PrintUncaughtException(message, error);
    };
    isolate_->AddMessageListener(message_listener);
  }

  node::SetIsolateUpForNode(GetIsolate(), isolate_settings);

  v8::Isolate::Scope isolate_scope(GetIsolate());
  v8::HandleScope handle_scope(GetIsolate());

  // ObjectTemplate for our global
  v8::Local<v8::ObjectTemplate> global = v8::ObjectTemplate::New(GetIsolate());

  // This is the global context we have. We enter it and that's it.
  v8::Local<v8::Context> context = v8::Context::New(GetIsolate(), nullptr, global);
  context->Enter();

  node_isolate_data_ = {node::CreateIsolateData(isolate_, &loop, node_platform_.get(),
                                                node_allocator_.get()),
                        &node::FreeIsolateData};

  node_environment_ = {
      node::CreateEnvironment(node_isolate_data_.get(), context, args, exec_args),
      &node::FreeEnvironment};

  zeek_val_wrapper_ = std::make_unique<ZeekValWrapper>(GetIsolate());

  node::AddLinkedBinding(node_environment_.get(), "zeekjs", RegisterModule, this);

  if (!ExecuteAndWaitForInit(context, GetIsolate(), main_script_source))
    return false;

  auto process = v8::Local<v8::Object>::Cast(
      context->Global()->Get(context, v8_str(isolate_, "process")).ToLocalChecked());
  process_obj_.Reset(isolate_, process);

  return true;
}

// Emit process 'beforeExit'
void Instance::BeforeExit() {
  v8::Isolate* isolate = GetIsolate();
  v8::Isolate::Scope isolate_scope(isolate);
  node::EmitProcessBeforeExit(node_environment_.get()).Check();
}

void Instance::Done() {
  using namespace std::chrono_literals;

  if (node_environment_) {
    // HACK: Add a small grace period waiting for the JavaScript IO loop
    // to complete during shutdown. E.g. if you send out an HTTP request
    // shortly before Zeek is shutting down, for example, using zeek -r <pcap>
    // and pushing out HTTP requests for every log, this should allow to
    // process any outstanding responses. On the flip-side, it will prolong
    // the shutdown when things like active sockets or pipes exist. If a user
    // closes/cleans them at zeek_done() time, that would speed-up shutdown.
    //
    // TODO: This should probably be configurable rather than 200msec
    //       hard-coded...
    for (int i = 0; i < 200; i++) {
      Process();
      if (!IsAlive()) {
        dprintf("uv_loop not alive anymore on iteration %d", i);
        break;
      }
      std::this_thread::sleep_for(1ms);
    }

    // Emit process 'exit' event
    v8::Isolate* isolate = GetIsolate();
    v8::Isolate::Scope isolate_scope(isolate);
    node::EmitProcessExit(node_environment_.get());
  }
}

int Instance::GetLoopFd() {
  return uv_backend_fd(&loop);
}

// Update the loops notion of now in case we've been blocked for a bit.
void Instance::UpdateTime() {
  uv_update_time(&loop);
}

// Implementation for GetNextTimeout() for the IOSource.
double Instance::GetNextTimeout() {
  int alive = uv_loop_alive(&loop);
  double timeout = uv_backend_timeout(&loop);  // in ms
  // dprintf("Have timeout %f alive=%d", timeout, alive);
  if (!alive || timeout < 0.0)
    return -1;

  return timeout / 1000;
}

bool Instance::IsAlive() {
  return uv_loop_alive(&loop) == 1;
}

struct UvHandle {
  void* h;
  uv_handle_type t;
  int fd;
  int active;
  int ref;
};
inline bool operator==(const UvHandle& l, const UvHandle& r) {
  return l.h == r.h && l.fd == r.fd && l.active == r.active;
}

// uv_walk() callback for collecting all handles with an FD
// into a vector provided by arg (std::vector<UvHandle>*)
static void collectUvHandles(uv_handle_t* h, void* arg) {
  auto handles = static_cast<std::vector<UvHandle>*>(arg);

  int fd = -1;
  uv_fileno(h, &fd);
  uv_handle_type t = uv_handle_get_type(h);

#define NO_ZEEKJS_LOOP_DEBUG
#ifdef ZEEKJS_LOOP_DEBUG
  const char* type_name = uv_handle_type_name(t);
  dprintf("Adding h=%p type=%-7s fd=%d active=%d has_ref=%d", h, type_name, fd,
          uv_is_active(h), uv_has_ref(h));
#endif
  handles->push_back(
      {.h = h, .t = t, .fd = fd, .active = uv_is_active(h), .ref = uv_has_ref(h)});
};

// Process the Javascript IO loop.
//
// This does a single uv_run() in NOWAIT mode followed by foreground
// task flush.
//
// Some trickiness: If we detect that uv_run() or task flushing changed the
// set of uv_handle_t instances registered with the loop (active or not) we
// do another round or otherwise notify Zeek's IO loop to trigger another
// Instance::Process() on the next loop iteration.
//
// The (understood) reason are TCP handles being connected: They won't show up
// as active in the handle list when the connect() is in progress and they are
// only registered with the IO loop on a subsequent uv__io_poll() round, so
// the loop fd will not become ready/signaled when the TCP connection has
// been established.
//
void Instance::Process() {
  v8::Isolate* isolate = GetIsolate();
  v8::Isolate::Scope isolate_scope(isolate);

  // XXX: This is hard to understand.
  int rounds = 0;
  bool handles_changed = false;
  static std::vector<UvHandle> handles_before;
  static std::vector<UvHandle> handles_after;
  do {
    ++rounds;
    handles_before.clear();

    uv_walk(&loop, collectUvHandles, &handles_before);
    bool more = false;
    do {
      uv_run(&loop, UV_RUN_NOWAIT);
      more = node_platform_->FlushForegroundTasks(GetIsolate());
    } while (more);

    handles_after.clear();
    uv_walk(&loop, collectUvHandles, &handles_after);
    handles_changed = handles_before != handles_after;

#ifdef ZEEKJS_LOOP_DEBUG
    dprintf("Loop debug rounds=%d timeout=%d handles=%ld handles_changed=%d", rounds,
            uv_backend_timeout(&loop), handles_after.size(), handles_changed);
#endif
  } while (handles_changed && rounds < 8);

  if (handles_changed)
    zeek_notifier_->Notify();
}
