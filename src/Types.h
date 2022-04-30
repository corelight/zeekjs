#pragma once
// TODO: This needs some namespace
#include <node/v8.h>

#include "zeek/Val.h"

const int ZEEKJS_ATTR_LOG = 1;

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
  v8::Local<v8::Value> Wrap(const zeek::ValPtr& vp, int attr_mask = 0);

  struct Result {
    bool ok;
    zeek::ValPtr val;
    std::string error;
  };

  // Convert a v8::Value to a ValPtr of the given type. If the
  // conversion fails, e.g. if type is IPAddr, but v8_val not
  // a string that conforms to an IP, returns a Result with an
  // error message.
  //
  Result ToZeekVal(v8::Local<v8::Value> v8_val, const zeek::TypePtr& type);

  // Callbacks used for Zeek tables.
  static void ZeekTableGetter(v8::Local<v8::Name> property,
                              const v8::PropertyCallbackInfo<v8::Value>& info);
  static void ZeekTableIndexGetter(uint32_t index,
                                   const v8::PropertyCallbackInfo<v8::Value>& info);
  static void ZeekTableEnumerator(const v8::PropertyCallbackInfo<v8::Array>& info);

  // Callbacks used for Zeek records.
  static void ZeekRecordGetter(v8::Local<v8::Name> property,
                               const v8::PropertyCallbackInfo<v8::Value>& info);
  static void ZeekRecordQuery(v8::Local<v8::Name> property,
                              const v8::PropertyCallbackInfo<v8::Integer>& info);
  static void ZeekRecordEnumerator(const v8::PropertyCallbackInfo<v8::Array>& info);

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

// Wraps a zeek::ValPtr with enough info to continue wrapping.
//
// This is used as internal field and hooked up with garbage collection
// via SetWeak().
//
class ZeekValWrap {
 public:
  v8::Local<v8::Object> GetHandle(v8::Isolate* isolate) {
    return persistent_obj_.Get(isolate);
  }

  ZeekValWrapper* GetWrapper() { return wrapper_; }
  zeek::Val* GetVal() { return vp_; }
  const int GetAttrMask() { return attr_mask_; };

  static ZeekValWrap* Make(v8::Isolate* isolate,
                           ZeekValWrapper* wrapper,
                           v8::Local<v8::Object> record_obj,
                           zeek::Val* vp,
                           int attr_mask = 0);

 private:
  ZeekValWrap(v8::Isolate* isolate,
              ZeekValWrapper* wrapper,
              v8::Local<v8::Object> record_obj,
              zeek::Val* vp,
              int attr_mask);

  v8::Persistent<v8::Object> persistent_obj_;
  ZeekValWrapper* wrapper_ = nullptr;
  zeek::Val* vp_ = nullptr;
  int attr_mask_ = 0;

  // Callback from V8 to let us know that the Object isn't referenced
  // anymore and we can now Unref() the Val we held on to.
  static void ZeekValWrap_WeakCallback(const v8::WeakCallbackInfo<ZeekValWrap>& data);
};
