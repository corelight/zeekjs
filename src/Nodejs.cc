#include "Nodejs.h"
#include "IOLoop.h"

#include <filesystem>
#include <memory>
#include <string>
#include <vector>

#include <node/node.h>
#include <node/v8.h>

// Using RegisterJsEventHandler on the passed plugin.
#include "Helpers.h"
#include "Plugin.h"
#include "ZeekCompat.h"

// Mostly for converting Val's into Javascript types.
#include "zeek/IPAddr.h"
#include "zeek/Scope.h"
#include "zeek/Type.h"
#include "zeek/Val.h"
#include "zeek/ZeekString.h"
#include "zeek/module_util.h"

using namespace plugin::Nodejs;

static v8::Local<v8::String> v8_str_intern(v8::Isolate* i, const char* s) {
  return v8::String::NewFromUtf8(i, s, v8::NewStringType::kInternalized)
      .ToLocalChecked();
}

static v8::Local<v8::String> v8_str(v8::Isolate* i, const char* s) {
  return v8::String::NewFromUtf8(i, s).ToLocalChecked();
}

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

  static ZeekValWrap* Make(v8::Isolate* isolate,
                           ZeekValWrapper* wrapper,
                           v8::Local<v8::Object> record_obj,
                           zeek::Val* vp) {
    return new ZeekValWrap(isolate, wrapper, record_obj, vp);
  }

 private:
  ZeekValWrap(v8::Isolate* isolate,
              ZeekValWrapper* wrapper,
              v8::Local<v8::Object> record_obj,
              zeek::Val* vp)
      : vp_(vp), wrapper_(wrapper) {
    record_obj->SetAlignedPointerInInternalField(0, this);
    persistent_obj_.Reset(isolate, record_obj);
    persistent_obj_.SetWeak(this, ZeekValWrap_WeakCallback,
                            v8::WeakCallbackType::kParameter);
  }

  v8::Persistent<v8::Object> persistent_obj_;
  zeek::Val* vp_ = nullptr;
  ZeekValWrapper* wrapper_ = nullptr;

  // Callback from V8 to let us know that the Object isn't referenced
  // anymore and we can now Unref() the Val we held on to.
  static void ZeekValWrap_WeakCallback(const v8::WeakCallbackInfo<ZeekValWrap>& data) {
    void* p = data.GetParameter();
    auto wrap = static_cast<ZeekValWrap*>(p);

#ifdef DEBUG
    zeek::TypeTag type_tag = wrap->vp_->GetType()->Tag();
    const std::string& type_name = wrap->vp_->GetType()->GetName();
    dprintf("Unrefing vp_=%p (type tag %d/%s/%s) and deleting wrap=%p", wrap->vp_,
            type_tag, zeek::type_name(type_tag), type_name.c_str(), wrap);
#endif

    if (wrap->vp_)
      zeek::Unref(wrap->vp_);

    wrap->persistent_obj_.Reset();

    delete wrap;
  }
};

// Convert a Javascript value over to a zeek::ValPtr using the given type.
//
// TODO: Refactor.
ZeekValWrapper::Result ZeekValWrapper::ToZeekVal(v8::Local<v8::Value> v8_val,
                                                 const zeek::TypePtr& type) {
  ZeekValWrapper::Result wrap_result = {.ok = true};

  v8::Local<v8::Context> context = isolate_->GetCurrentContext();
  zeek::TypeTag type_tag = type->Tag();
  dprintf("type tag %d/%s val=%s", type_tag, zeek::type_name(type_tag),
          *v8::String::Utf8Value(isolate_, v8_val));

  if (type_tag == zeek::TYPE_ADDR) {
    v8::Local<v8::String> v8_str = v8_val->ToString(context).ToLocalChecked();
    v8::String::Utf8Value utf8_value(isolate_, v8_str);
    in6_addr addr6;

    if (zeek::IPAddr::ConvertString(*utf8_value, &addr6)) {
      wrap_result.val = zeek::make_intrusive<zeek::AddrVal>(zeek::IPAddr(addr6));
      return wrap_result;
    }
  } else if (type_tag == zeek::TYPE_SUBNET) {
    v8::Local<v8::String> v8_str = v8_val->ToString(context).ToLocalChecked();
    v8::String::Utf8Value utf8_value(isolate_, v8_str);
    zeek::IPPrefix ip_prefix;

    if (zeek::IPPrefix::ConvertString(*utf8_value, &ip_prefix)) {
      wrap_result.val = zeek::make_intrusive<zeek::SubNetVal>(ip_prefix);
      return wrap_result;
    } else {
      // Ad-hoc support for the bracketed IPv6 subnet notation as well.
      // For example, [2607:f8b0::]/40.
      if ((*utf8_value)[0] == '[') {
        std::string cleaned = *utf8_value;
        cleaned.erase(0, 1);
        size_t loc = cleaned.find("]/");
        if (loc != std::string::npos) {
          cleaned.erase(loc, 1);
          if (zeek::IPPrefix::ConvertString(cleaned.c_str(), &ip_prefix)) {
            wrap_result.val = zeek::make_intrusive<zeek::SubNetVal>(ip_prefix);
            return wrap_result;
          }
        }
      }
    }
  } else if (type_tag == zeek::TYPE_COUNT) {
    if (v8_val->IsNumber()) {
      v8::MaybeLocal<v8::Uint32> result = v8_val->ToUint32(context);
      wrap_result.val = zeek::val_mgr->Count(result.ToLocalChecked()->Value());
      return wrap_result;
    } else if (v8_val->IsBigInt()) {
      v8::MaybeLocal<v8::BigInt> result = v8_val->ToBigInt(context);
      wrap_result.val = zeek::val_mgr->Count(result.ToLocalChecked()->Uint64Value());
      return wrap_result;
    }
  } else if (type_tag == zeek::TYPE_INT) {
    if (v8_val->IsNumber()) {
      v8::MaybeLocal<v8::Int32> result = v8_val->ToInt32(context);
      wrap_result.val = zeek::val_mgr->Int(result.ToLocalChecked()->Value());
      return wrap_result;
    }
  } else if (type_tag == zeek::TYPE_DOUBLE) {
    if (v8_val->IsNumber()) {
      v8::Maybe<double> result = v8_val->NumberValue(context);
      wrap_result.val =
          plugin::Corelight_ZeekJS::compat::DoubleVal_New(result.ToChecked());
      return wrap_result;
    }

  } else if (type_tag == zeek::TYPE_TIME) {
    if (v8_val->IsNumber()) {
      v8::Maybe<double> result = v8_val->NumberValue(context);
      wrap_result.val =
          plugin::Corelight_ZeekJS::compat::TimeVal_New(result.ToChecked());
      return wrap_result;
    }

  } else if (type_tag == zeek::TYPE_STRING) {
    v8::Local<v8::String> v8_str = v8_val->ToString(context).ToLocalChecked();
    v8::String::Utf8Value utf8_value(isolate_, v8_str);
    wrap_result.val = zeek::make_intrusive<zeek::StringVal>(*utf8_value);
    return wrap_result;

  } else if (type_tag == zeek::TYPE_ENUM) {
    zeek::EnumType* enum_type = type->AsEnumType();
    v8::Local<v8::String> v8_str = v8_val->ToString(context).ToLocalChecked();
    v8::String::Utf8Value utf8_value(isolate_, v8_str);

    std::string module_name = zeek::detail::extract_module_name(*utf8_value);
    std::string var_name = zeek::detail::extract_var_name(*utf8_value);
    bro_int_t enum_int = enum_type->Lookup(module_name, var_name.c_str());
    if (enum_int >= 0) {
      wrap_result.val = enum_type->GetEnumVal(enum_int);
    } else {
      dprintf("Failed to resolve enum %s", *utf8_value);
      wrap_result.ok = false;
      wrap_result.error =
          std::string("Enum value ") + *utf8_value + std::string(" unknown");
    }
    return wrap_result;

  } else if (type_tag == zeek::TYPE_VECTOR) {
    dprintf("Dealing with a vector");
    if (!v8_val->IsArray()) {
      wrap_result.ok = false;
      wrap_result.error = "Expected Javascript array for type vector";
    } else {
      dprintf("Converting to Zeek vector");
      zeek::TypePtr yield_type = type->Yield();
      zeek::VectorTypePtr vtp = zeek::make_intrusive<zeek::VectorType>(type->Yield());
      zeek::VectorValPtr vvp = zeek::make_intrusive<zeek::VectorVal>(vtp);

      v8::Local<v8::Array> v8_array = v8::Local<v8::Array>::Cast(v8_val);
      for (uint32_t i = 0; i < v8_array->Length(); i++) {
        v8::Local<v8::Value> v8_element_value =
            v8_array->Get(context, i).ToLocalChecked();

        ZeekValWrapper::Result element_result = ToZeekVal(v8_element_value, yield_type);
        if (!element_result.ok) {
          wrap_result.ok = false;
          wrap_result.error += "Error converting element: " + element_result.error;
          break;
        }

        plugin::Corelight_ZeekJS::compat::Vector_append(vvp, element_result.val);
      }

      if (wrap_result.ok)
        wrap_result.val = vvp;
    }

    return wrap_result;
  } else if (type_tag == zeek::TYPE_RECORD) {
    // Take the record type and attempt to assign all non-optional
    // fields from the provided Javascript object.
    zeek::RecordTypePtr rt = {zeek::NewRef{},
                              type->AsRecordType()};  // Not sure this needs NewRef
    zeek::RecordValPtr record_val = zeek::make_intrusive<zeek::RecordVal>(rt);

    if (!v8_val->IsObject()) {
      wrap_result.error = "Expected Javascript object for record";
    } else {
      v8::Local<v8::Object> v8_obj = v8::Local<v8::Object>::Cast(v8_val);

      for (int i = 0; i < rt->NumFields() && wrap_result.ok; i++) {
        const char* field_name = rt->FieldName(i);
        const zeek::TypeDecl* field_decl = rt->FieldDecl(i);

        const bool is_optional =
            field_decl->GetAttr(zeek::detail::ATTR_OPTIONAL) != zeek::detail::Attr::nil;

        dprintf("i=%d field_name=%s optional=%d", i, field_name, is_optional);

        v8::Local<v8::String> key = v8_str_intern(field_name);

        // If the v8_obj does not have this field and the field
        // itself isn't optional, bail out.

        v8::MaybeLocal<v8::Value> maybe_value = v8_obj->Get(context, key);
        v8::Local<v8::Value> v8_field_value;

        if (!maybe_value.ToLocal(&v8_field_value)) {
          // No value, but optional, move on to the next field.
          if (is_optional)
            continue;

          wrap_result.ok = false;
          wrap_result.error = std::string("Missing property ") + field_name;
          break;
        }

        ZeekValWrapper::Result field_result =
            ToZeekVal(v8_field_value, field_decl->type);
        if (!field_result.ok) {
          wrap_result.ok = false;
          wrap_result.error += "Error for field ";
          wrap_result.error += field_name;
          wrap_result.error += ": " + field_result.error;
          break;
        }

        record_val->Assign(i, field_result.val);
      }

      if (wrap_result.ok) {
        wrap_result.val = record_val;
        return wrap_result;
      }
    }
  }

  // Could not convert the type. Attempt to provide a meaningful
  // error message, preserving those existing in wrap_result.
  wrap_result.ok = false;
  wrap_result.val = zeek::ValPtr(nullptr);
  v8::String::Utf8Value utf8_value(isolate_, v8_val);
  v8::Local<v8::String> v8_typeof_str = v8_val->TypeOf(isolate_);
  v8::String::Utf8Value utf8_type(isolate_, v8_typeof_str);

  std::string error = "Not able to convert js value '";
  error = "Not able to convert js value '";
  error += *utf8_value + std::string("' of type ") + *utf8_type +
           std::string(" to zeek type ");
  error += zeek::type_name(type_tag);
  if (!wrap_result.error.empty()) {
    error += " (";
    error += wrap_result.error;
    error += ")";
  }
  wrap_result.error = error;

  return wrap_result;
}

void ZeekValWrapper::ZeekTableGetter(v8::Local<v8::Name> property,
                                     const v8::PropertyCallbackInfo<v8::Value>& info) {
  v8::Isolate* isolate = info.GetIsolate();
  v8::Local<v8::Object> receiver = info.This();
  auto wrap =
      static_cast<ZeekValWrap*>(receiver->GetAlignedPointerFromInternalField(0));
  auto tval = static_cast<zeek::TableVal*>(wrap->GetVal());

  v8::String::Utf8Value arg(isolate, property);

  if (!*arg) {
    dprintf("empty arg?");
    return;
  }

  zeek::TableTypePtr ttype = tval->GetType<zeek::TableType>();
  std::vector<zeek::TypePtr> itypes = ttype->GetIndexTypes();
  dprintf("tval=%p ttype=%p itypes=%lu property=%s", tval, ttype.get(), itypes.size(),
          *arg);

  if (itypes.size() != 1) {
    eprintf("Unexpected number of index types: %lu", itypes.size());
    return;
  }

  zeek::TypePtr index_type = itypes[0];
  ZeekValWrapper::Result index_result =
      wrap->GetWrapper()->ToZeekVal(property, index_type);
  if (!index_result.ok)
    return;

  zeek::ValPtr found_val = tval->Find(index_result.val);
  if (!found_val)
    return;

  dprintf("tval=%p ttype=%p itypes=%lu property=%s FOUND", tval, ttype.get(),
          itypes.size(), *arg);

  info.GetReturnValue().Set(wrap->GetWrapper()->Wrap(found_val));
}

// This is slightly insane - when the Enumerator returns a Name that's
// a number, the IndexGetter is called rather than the property getter.
//
// Maybe that's not so insane, but that's why we have the below and
// may convert from Javascript numbers to String keys in Zeek.
void ZeekValWrapper::ZeekTableIndexGetter(
    uint32_t index,
    const v8::PropertyCallbackInfo<v8::Value>& info) {
  v8::Isolate* isolate = info.GetIsolate();
  v8::Local<v8::Object> receiver = info.This();
  auto wrap =
      static_cast<ZeekValWrap*>(receiver->GetAlignedPointerFromInternalField(0));
  auto tval = static_cast<zeek::TableVal*>(wrap->GetVal());

  dprintf("ZeekTableIndexGetter: tval=%p index=%d", tval, index);

  zeek::TableTypePtr ttype = tval->GetType<zeek::TableType>();
  std::vector<zeek::TypePtr> itypes = ttype->GetIndexTypes();
  if (itypes.size() != 1) {
    eprintf("Unexpected number of index types: %lu", itypes.size());
    return;
  }

  zeek::TypePtr index_type = itypes[0];
  v8::Local<v8::Number> v8_index = v8::Uint32::NewFromUnsigned(isolate, index);
  ZeekValWrapper::Result index_result =
      wrap->GetWrapper()->ToZeekVal(v8_index, index_type);
  if (!index_result.ok)
    return;

  zeek::ValPtr val = tval->Find(index_result.val);
  if (!val) {
    eprintf("Failed to lookup value for index=%d", index);
    return;
  }
  info.GetReturnValue().Set(wrap->GetWrapper()->Wrap(val));
}

void ZeekValWrapper::ZeekTableEnumerator(
    const v8::PropertyCallbackInfo<v8::Array>& info) {
  v8::Isolate* isolate = info.GetIsolate();
  v8::Local<v8::Context> context = isolate->GetCurrentContext();
  v8::Local<v8::Object> receiver = info.This();
  auto wrap =
      static_cast<ZeekValWrap*>(receiver->GetAlignedPointerFromInternalField(0));
  auto tval = static_cast<zeek::TableVal*>(wrap->GetVal());

  // Easy v8::Array constructor takes int, print an error and return.
  // There's a separate constructor that takes a size_t, but would need
  // to populate differently...
  if (tval->Size() > INT_MAX) {
    eprintf("Too many entries in table: %u", tval->Size());
    return;
  }
  auto size = static_cast<int>(tval->Size());

#ifdef DEBUG
  zeek::TypeTag tag = tval->GetType()->Tag();
  dprintf("tval tag %d/%s set=%d size=%d", tag, zeek::type_name(tag),
          tval->GetType()->IsSet(), size);
#endif

  // Let's shortcut here, only support ToPureListVal, anything else
  // a bit crazy.
  zeek::ListValPtr lv = tval->ToPureListVal();
  if (!lv) {
    eprintf("Wrapping multi index table is not supported.");
    return;
  }

  v8::Local<v8::Array> array = v8::Array::New(isolate, size);
  for (int i = 0; i < size; i++) {
    // zeek::TypeTag tag = lv->Idx(i)->GetType()->Tag();
    // dprintf("tag idx=%lu %d/%s set=%d size=%lu", i, tag,
    // zeek::type_name(tag), tval->GetType()->IsSet(), size);
    v8::Local<v8::Value> v8_val = wrap->GetWrapper()->Wrap(lv->Idx(i));
    v8::Local<v8::String> v8_str = v8_val->ToString(context).ToLocalChecked();
    v8::Local<v8::Name> v8_name = v8::Local<v8::Name>::New(isolate, v8_str);
    array->Set(context, i, v8_name).Check();
  }

  info.GetReturnValue().Set(array);
}

// Callback for looking up properties of a record.
void ZeekValWrapper::ZeekRecordGetter(v8::Local<v8::Name> property,
                                      const v8::PropertyCallbackInfo<v8::Value>& info) {
  v8::Isolate* isolate = info.GetIsolate();
  v8::Local<v8::Object> receiver = info.This();
  auto wrap =
      static_cast<ZeekValWrap*>(receiver->GetAlignedPointerFromInternalField(0));
  auto rval = static_cast<zeek::RecordVal*>(wrap->GetVal());

  v8::String::Utf8Value arg(isolate, property);

  if (*arg && plugin::Corelight_ZeekJS::compat::Record_has_field(rval, *arg)) {
    zeek::ValPtr vp = rval->GetFieldOrDefault(*arg);
    info.GetReturnValue().Set(wrap->GetWrapper()->Wrap(vp));
  }
}

// Callback for enumerating the properties of a record.
void ZeekValWrapper::ZeekRecordEnumerator(
    const v8::PropertyCallbackInfo<v8::Array>& info) {
  v8::Isolate* isolate = info.GetIsolate();
  v8::Local<v8::Object> receiver = info.This();
  auto wrap =
      static_cast<ZeekValWrap*>(receiver->GetAlignedPointerFromInternalField(0));
  auto rval = static_cast<zeek::RecordVal*>(wrap->GetVal());
  zeek::RecordType* rt = rval->GetType()->AsRecordType();
  v8::Local<v8::Array> array = v8::Array::New(isolate, rt->NumFields());

  for (int i = 0; i < rt->NumFields(); i++) {
    // Should those strings be interned?
    //
    v8::Local<v8::String> field_name = ::v8_str_intern(isolate, rt->FieldName(i));
    v8::Local<v8::Name> name = v8::Local<v8::Name>::New(isolate, field_name);

    array->Set(isolate->GetCurrentContext(), i, name).Check();
  }

  info.GetReturnValue().Set(array);
}

// Implement Query for Zeek records.
void ZeekValWrapper::ZeekRecordQuery(
    v8::Local<v8::Name> property,
    const v8::PropertyCallbackInfo<v8::Integer>& info) {
  v8::Isolate* isolate = info.GetIsolate();
  v8::Local<v8::Object> receiver = info.This();
  auto wrap =
      static_cast<ZeekValWrap*>(receiver->GetAlignedPointerFromInternalField(0));
  auto rval = static_cast<zeek::RecordVal*>(wrap->GetVal());

  v8::String::Utf8Value arg(isolate, property);

  if (*arg && plugin::Corelight_ZeekJS::compat::Record_has_field(rval, *arg)) {
    info.GetReturnValue().Set(v8::PropertyAttribute::ReadOnly);
  }
}

// Callbacks for zeek.vars
static void ZeekGlobalVarsGetter(v8::Local<v8::Name> property,
                                 const v8::PropertyCallbackInfo<v8::Value>& info) {
  v8::Isolate* isolate = info.GetIsolate();

  v8::Local<v8::Object> receiver = info.This();
  auto field = v8::Local<v8::External>::Cast(receiver->GetInternalField(0));
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
  dprintf("Enumerated...");

  info.GetReturnValue().Set(array);
}

ZeekValWrapper::ZeekValWrapper(v8::Isolate* isolate) : isolate_(isolate) {
  v8::Local<v8::ObjectTemplate> record_template = v8::ObjectTemplate::New(isolate_);
  record_template->SetInternalFieldCount(1);
  v8::NamedPropertyHandlerConfiguration record_conf = {nullptr};
  record_conf.getter = ZeekRecordGetter;
  record_conf.enumerator = ZeekRecordEnumerator;
  record_conf.query = ZeekRecordQuery;
  record_template->SetHandler(record_conf);

  record_template_.Reset(isolate_, record_template);

  v8::Local<v8::ObjectTemplate> table_template = v8::ObjectTemplate::New(isolate_);
  table_template->SetInternalFieldCount(1);

  v8::NamedPropertyHandlerConfiguration table_conf = {nullptr};
  table_conf.getter = ZeekTableGetter;
  table_conf.enumerator = ZeekTableEnumerator;
  table_template->SetHandler(table_conf);

  // This is insane
  v8::IndexedPropertyHandlerConfiguration table_indexed_conf = {nullptr};
  table_indexed_conf.getter = ZeekTableIndexGetter;
  table_template->SetHandler(table_indexed_conf);

  table_template_.Reset(isolate, table_template);

  port_str_.Reset(isolate, v8_str_intern("port"));
  proto_str_.Reset(isolate, v8_str_intern("proto"));
  toJSON_str_.Reset(isolate, v8_str_intern("toJSON"));
}

v8::Local<v8::Value> ZeekValWrapper::Wrap(const zeek::ValPtr& vp) {
  v8::Local<v8::Context> context = isolate_->GetCurrentContext();

  // For nil/empty, return undefined. Expect the caller to figure
  // out if this is the right value. E.g. for void functions.
  if (vp == zeek::Val::nil)
    return v8::Undefined(isolate_);

  zeek::TypeTag tag = vp->GetType()->Tag();

  switch (tag) {
    case zeek::TYPE_BOOL:
      return v8::Boolean::New(isolate_, vp->CoerceToInt() ? true : false);
    case zeek::TYPE_COUNT:
      return v8::BigInt::NewFromUnsigned(isolate_, vp->AsCount());
    case zeek::TYPE_INT:
      // Grml, this may be lossy, but making it a bigint: annoying.
      return v8::Number::New(isolate_, static_cast<double>(vp->AsInt()));
    case zeek::TYPE_DOUBLE:
      return v8::Number::New(isolate_, vp->AsDouble());
    case zeek::TYPE_INTERVAL:
      return v8::Number::New(isolate_, vp->AsInterval());
    case zeek::TYPE_TIME:
      return v8::Number::New(isolate_, vp->AsTime());
    case zeek::TYPE_STRING:
      return v8_str(vp->AsString()->CheckString());
    case zeek::TYPE_ADDR:
      return v8_str(vp->AsAddr().AsString().c_str());
    case zeek::TYPE_SUBNET:
      return v8_str(vp->AsSubNet().AsString().c_str());
    case zeek::TYPE_PORT: {
      zeek::PortVal* pvp = vp->AsPortVal();
      v8::Local<v8::Object> obj = v8::Object::New(isolate_);
      obj->Set(context, port_str_.Get(isolate_), v8::Number::New(isolate_, pvp->Port()))
          .Check();
      obj->Set(context, proto_str_.Get(isolate_),
               v8_str_intern(pvp->Protocol().c_str()))  // Should cache.
          .Check();

      static v8::FunctionCallback toJSON_callback =
          [](const v8::FunctionCallbackInfo<v8::Value>& info) -> void {
        v8::Local<v8::Object> receiver = info.This();
        v8::Isolate* isolate = info.GetIsolate();
        v8::Local<v8::Context> context = isolate->GetCurrentContext();
        v8::Local<v8::Value> port =
            receiver->Get(context, ::v8_str_intern(isolate, "port")).ToLocalChecked();

        info.GetReturnValue().Set(port);
      };
      auto toJSON_func = v8::Function::New(context, toJSON_callback).ToLocalChecked();

      obj->Set(context, toJSON_str_.Get(isolate_), toJSON_func).Check();

      return obj;
    }
    case zeek::TYPE_RECORD: {
      v8::Local<v8::ObjectTemplate> tmpl = record_template_.Get(isolate_);
      v8::Local<v8::Object> obj = tmpl->NewInstance(context).ToLocalChecked();
      ZeekValWrap* wrap = ZeekValWrap::Make(isolate_, this, obj, vp->Ref());
      return wrap->GetHandle(isolate_);
    }

    case zeek::TYPE_VECTOR: {
      // Hmm, hmm, maybe we could make this lazy and not
      // construct the full array.
      zeek::VectorVal* vv = vp->AsVectorVal();

      // Could fix, but for now error and return undefined..
      if (vv->Size() > INT_MAX) {
        eprintf("Too many entries in vector: %u", vv->Size());
        return v8::Undefined(isolate_);
      }
      auto size = static_cast<int>(vv->Size());
      v8::Local<v8::Array> array = v8::Array::New(isolate_, size);
      for (int i = 0; i < size; i++) {
        zeek::ValPtr vp = plugin::Corelight_ZeekJS::compat::Vector_val_at(vv, i);
        array->Set(context, i, Wrap(vp)).Check();
      }

      return array;
    }

    case zeek::TYPE_TABLE: {
      zeek::TableVal* tval = vp->AsTableVal();
      // dprintf("Table tval=%p", tval);
      if (tval->GetType()->IsSet()) {
        // XXX: There's something wrong within Zeek.
        //
        // Calling ToPureListVal() on removal hooks
        // crashes when comparing the func flavors.
        //
        // Return null for sets with functions at this
        // point (not clear what to actually do).
        zeek::TableTypePtr tt = tval->GetType<zeek::TableType>();
        std::vector<zeek::TypePtr> types = tt->GetIndices()->GetTypes();

        if (types[0]->Tag() == zeek::TYPE_FUNC) {
          dprintf(
              "ToPureListVal() with functions crashes - returning null "
              "instead");

          // We could construct a set with some
          // function names, but not sure that
          // would be all that useful.
          return v8::Null(isolate_);
        }

        const std::vector<zeek::TypePtr>& tl = tt->GetIndices()->GetTypes();

        zeek::ListValPtr lv;
        if (tl.size() == 1) {
          lv = tval->ToPureListVal();
        } else {
          lv = tval->ToListVal();
        }

        // For expedience, at this point, a set is
        // simply converted to an array. There's Set()
        // but that's not JSON stringify'ble, so...
        auto size = lv->Length();
        v8::Local<v8::Array> array = v8::Array::New(isolate_, size);
        for (int i = 0; i < size; i++)
          array->Set(context, i, Wrap(lv->Idx(i))).Check();
        return array;
      } else {
        // TODO: Precheck for multi keys and just crash or ignore
        //       or whatever.
        //
        // If it's an actual table, use the table_template
        v8::Local<v8::ObjectTemplate> tmpl = table_template_.Get(isolate_);
        v8::Local<v8::Object> obj = tmpl->NewInstance(context).ToLocalChecked();

        ZeekValWrap* wrap = ZeekValWrap::Make(isolate_, this, obj, tval->Ref());
        return wrap->GetHandle(isolate_);
      }
    }
    case zeek::TYPE_ENUM: {
      zeek::EnumVal* eval = vp->AsEnumVal();
      const char* name = vp->GetType()->AsEnumType()->Lookup(eval->AsEnum());
      return v8_str_intern(name);
    }
    case zeek::TYPE_LIST: {  // types (?)
      zeek::ListVal* lval = vp->AsListVal();
      int size = lval->Length();
      v8::Local<v8::Array> array = v8::Array::New(isolate_, size);
      for (int i = 0; i < size; i++)
        array->Set(context, i, Wrap(lval->Idx(i))).Check();

      return array;
    }

    default:
      eprintf("Unhandled type tag %s (%d), returning null", zeek::type_name(tag), tag);
      return v8::Null(isolate_);
  }
}

v8::Local<v8::String> ZeekValWrapper::v8_str_intern(const char* s) {
  return ::v8_str_intern(isolate_, s);
}
v8::Local<v8::String> ZeekValWrapper::v8_str(const char* s) {
  return ::v8_str(isolate_, s);
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
  auto context = v8::Local<v8::Context>::New(isolate, instance->GetContext());
  v8::Context::Scope context_scope(context);

  // TODO: Who's the receiver if the function is bound? Shouldn't it be
  //       the object the function is bounded to?
  //       https://developer.mozilla.org/en-US/docs/Web/JavaScript/Reference/Global_objects/Function/bind
  v8::Local<v8::Value> receiver = context->Global();

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
  v8::Local<v8::Object> receiver = args.This();
  auto field = v8::Local<v8::External>::Cast(receiver->GetInternalField(0));
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
  if (args.Length() == 2)
    v8_args = v8::Local<v8::Array>::Cast(args[1]);
  else
    v8_args = v8::Array::New(isolate, 0);

#ifdef DEBUG
  v8::String::Utf8Value utf8name(isolate, args[0]);
  dprintf("Event for %s", *utf8name);
#endif

  // Assume ZeekEvent internally throws the exception for Javascript land..
  if (!instance->ZeekEvent(name, v8_args)) {
    dprintf("Failed to invoke event");
  }
}

//
// Callback for zeek.invoke
//
// zeek.invoke('zeek_version')
// zeek.invoke('sqrt', [4])
//
void Instance::ZeekInvokeCallback(const v8::FunctionCallbackInfo<v8::Value>& args) {
  v8::Isolate* isolate = args.GetIsolate();
  v8::Local<v8::Object> receiver = args.This();
  auto field = v8::Local<v8::External>::Cast(receiver->GetInternalField(0));
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
  if (args.Length() == 2)
    v8_args = v8::Local<v8::Array>::Cast(args[1]);
  else
    v8_args = v8::Array::New(isolate, 0);

  v8::Local<v8::Value> ret = instance->ZeekInvoke(name, v8_args);
  args.GetReturnValue().Set(ret);
}

// Convert the v8_args to zeek::Args according to the parameters expected by ft.
std::optional<zeek::Args> Instance::v8_to_zeek_args(const zeek::FuncType* ft,
                                                    v8::Local<v8::Array> v8_args) {
  zeek::Args args;
  const zeek::RecordTypePtr& params = ft->Params();
  v8::Local<v8::Context> context = isolate_->GetCurrentContext();

  if ((uint32_t)params->NumFields() != v8_args->Length()) {
    std::string error = "Wrong number of parameters";
    isolate_->ThrowException(v8_str(isolate_, error.c_str()));
    return std::nullopt;
  }

  for (uint32_t i = 0; i < v8_args->Length(); i++) {
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
    std::string msg = "Unknown function: ";
    msg += *name_str;
    isolate_->ThrowException(v8_str(isolate_, msg.c_str()));
    return v8::Undefined(isolate_);
  }

  const zeek::TypePtr t = id->GetType();
  if (!zeek::IsFunc(t->Tag())) {
    isolate_->ThrowException(v8_str(isolate_, "Not a function"));
    return v8::Undefined(isolate_);
  }
  const zeek::FuncType* ft = t->AsFuncType();
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

  // Throw if this isn't a void function and we didn't get a Val back.
  if (ret == zeek::Val::nil && ft->Yield()->Tag() != zeek::TYPE_VOID) {
    isolate_->ThrowException(v8_str(isolate_, "Error calling function"));
    return v8::Undefined(isolate_);
  }

#ifdef DEBUG
  const std::string& type_name =
      ret != zeek::Val::nil ? ret->GetType()->GetName() : "nil";
  dprintf("invoke for %s returned: %s", *name_str, type_name.c_str());
#endif
  return zeek_val_wrapper_->Wrap(ret);
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
  v8::Local<v8::Object> receiver = args.This();
  auto field = v8::Local<v8::External>::Cast(receiver->GetInternalField(0));
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
  v8::Local<v8::Object> receiver = args.This();
  auto field = v8::Local<v8::External>::Cast(receiver->GetInternalField(0));
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

void Instance::SetupZeekObject(v8::Local<v8::Context> context,
                               v8::Isolate* isolate,

                               const std::vector<std::filesystem::path>& files) {
  v8::Local<v8::ObjectTemplate> zeek_tmpl = v8::ObjectTemplate::New(GetIsolate());
  zeek_tmpl->SetInternalFieldCount(1);
  v8::Local<v8::Object> zeek_obj = zeek_tmpl->NewInstance(context).ToLocalChecked();
  zeek_obj->SetInternalField(0, v8::External::New(GetIsolate(), this));

  v8::Local<v8::String> on_str = v8_str_intern(GetIsolate(), "on");
  v8::Local<v8::FunctionTemplate> zeek_on_tmpl =
      v8::FunctionTemplate::New(GetIsolate(), ZeekOnCallback);
  zeek_obj->Set(context, on_str, zeek_on_tmpl->GetFunction(context).ToLocalChecked())
      .Check();

  // TODO: Make this use the PrintStmt if possible.
  v8::Local<v8::String> print_str = v8_str_intern(GetIsolate(), "print");
  v8::Local<v8::FunctionTemplate> zeek_print_tmpl =
      v8::FunctionTemplate::New(GetIsolate(), PrintCallback);
  zeek_obj
      ->Set(context, print_str, zeek_print_tmpl->GetFunction(context).ToLocalChecked())
      .Check();

  v8::Local<v8::String> event_str = v8_str_intern(GetIsolate(), "event");
  v8::Local<v8::FunctionTemplate> zeek_event_tmpl =
      v8::FunctionTemplate::New(GetIsolate(), ZeekEventCallback);
  zeek_obj
      ->Set(context, event_str, zeek_event_tmpl->GetFunction(context).ToLocalChecked())
      .Check();

  v8::Local<v8::String> hook_str = v8_str_intern(GetIsolate(), "hook");
  v8::Local<v8::FunctionTemplate> zeek_hook_tmpl =
      v8::FunctionTemplate::New(GetIsolate(), ZeekHookCallback);
  zeek_obj
      ->Set(context, hook_str, zeek_hook_tmpl->GetFunction(context).ToLocalChecked())
      .Check();

  // invoke
  v8::Local<v8::String> invoke_str = v8_str_intern(GetIsolate(), "invoke");
  v8::Local<v8::FunctionTemplate> zeek_invoke_tmpl =
      v8::FunctionTemplate::New(GetIsolate(), ZeekInvokeCallback);
  zeek_obj
      ->Set(context, invoke_str,
            zeek_invoke_tmpl->GetFunction(context).ToLocalChecked())
      .Check();

  // global_vars dictionary
  v8::Local<v8::String> globals_str = v8_str_intern(GetIsolate(), "global_vars");
  v8::Local<v8::ObjectTemplate> zeek_globals_tmpl =
      v8::ObjectTemplate::New(GetIsolate());
  zeek_globals_tmpl->SetInternalFieldCount(1);

  v8::NamedPropertyHandlerConfiguration global_vars_conf = {nullptr};
  global_vars_conf.getter = ZeekGlobalVarsGetter;
  global_vars_conf.enumerator = ZeekGlobalVarsEnumerator;
  zeek_globals_tmpl->SetHandler(global_vars_conf);

  v8::Local<v8::Object> zeek_global_vars_obj =
      zeek_globals_tmpl->NewInstance(context).ToLocalChecked();
  zeek_global_vars_obj->SetInternalField(0, v8::External::New(GetIsolate(), this));
  zeek_obj->Set(context, globals_str, zeek_global_vars_obj).Check();

  // Files to be loaded by the bootstrapping script.
  v8::Local<v8::String> zeekjs_files_str = v8_str(GetIsolate(), "__zeekjs_files");
  v8::Local<v8::Array> array =
      v8::Array::New(GetIsolate(), static_cast<int>(files.size()));
  for (unsigned long i = 0; i < files.size(); i++) {
    v8::Local<v8::String> v8_file = v8_str(GetIsolate(), files[i].c_str());
    array->Set(context, i, v8_file).Check();
  }
  zeek_obj->Set(context, zeekjs_files_str, array).Check();

  auto zeek_str = v8_str_intern(GetIsolate(), "zeek");
  context->Global()->Set(context, zeek_str, zeek_obj).Check();
}

bool Instance::ExecuteAndWaitForInit(v8::Local<v8::Context> context,
                                     v8::Isolate* isolate,
                                     const std::string& main_script_source) {
  // Oookay, go run the main script
  v8::MaybeLocal<v8::Value> ret =
      node::LoadEnvironment(node_environment_.get(), main_script_source.c_str());

  if (ret.IsEmpty()) {
    // TODO: Introspect the error a bit.
    eprintf("Exception?\n");
    return false;
  }

  // The main script is supposed to define an zeekjs_init() function
  // in the global scope that we can then call.
  const char* init_name = "zeekjs_init";
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
      uv_run(&loop, UV_RUN_DEFAULT);
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

  std::vector<std::string> args = {"zeek"};
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

  int r = node::InitializeNodeWithArgs(&args, &exec_args, &errors);
  if (r != 0) {
    eprintf("InitializeNodeWithArgs() failed: %d\n", r);
    return false;
  }
  dprintf("Node initialized. Compiled with %s", NODE_VERSION);

  node_platform_ = node::MultiIsolatePlatform::Create(thread_pool_size);
  v8::V8::InitializePlatform(node_platform_.get());
  v8::V8::Initialize();
  dprintf("V8 initialized. Version %s", v8::V8::GetVersion());

  r = uv_loop_init(&loop);
  if (r != 0) {
    eprintf("uv_loop_init() failed: %s\n", uv_err_name(r));
    return false;
  }

  node_allocator_ = node::ArrayBufferAllocator::Create();
  if (!node_allocator_) {
    eprintf("Failed to create ArrayBufferAllocator\n");
    return false;
  }

  isolate_ = v8::Isolate::Allocate();
  if (!isolate_) {
    eprintf("Could not allocate Isolate.");
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

  // This is the global context we have.
  v8::Local<v8::Context> context = v8::Context::New(GetIsolate(), nullptr, global);
  context_.Reset(GetIsolate(), context);

  v8::Context::Scope context_scope(context);

  node_isolate_data_ = {node::CreateIsolateData(isolate_, &loop, node_platform_.get(),
                                                node_allocator_.get()),
                        node::FreeIsolateData};

  node_environment_ = {
      node::CreateEnvironment(node_isolate_data_.get(), context, args, exec_args),
      node::FreeEnvironment};

  zeek_val_wrapper_ = std::make_unique<ZeekValWrapper>(GetIsolate());

  SetupZeekObject(context, GetIsolate(), files);

  return ExecuteAndWaitForInit(context, GetIsolate(), main_script_source);
}

void Instance::Done() {
  dprintf("Done()");
  if (node_environment_) {
    node::Stop(node_environment_.get());
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

struct UvHandle {
  void* h;
  int fd;
  int active;
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
  if (fd < 0)
    return;

#ifdef ZEEKJS_LOOP_DEBUG
  uv_handle_type t = uv_handle_get_type(h);
  const char* type_name = uv_handle_type_name(t);
  dprintf("Adding h=%p type=%s fd=%d active=%d", h, type_name, fd, uv_is_active(h));
#endif
  handles->push_back({.h = h, .fd = fd, .active = uv_is_active(h)});
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
  v8::Isolate::Scope isolate_scope(GetIsolate());
  v8::HandleScope handle_scope(GetIsolate());
  v8::Local<v8::Context> context =
      v8::Local<v8::Context>::New(GetIsolate(), GetContext());
  v8::Context::Scope context_scope(context);
  v8::SealHandleScope seal(GetIsolate());

  // XXX: This is hard to understand.
  int round = 0, more = 0, handles_changed;
  std::vector<UvHandle> handles_before;
  std::vector<UvHandle> handles_after;
  while (round < 2) {
    ++round;
    handles_before.clear();
    handles_after.clear();
    handles_changed = 0;

    uv_walk(&loop, collectUvHandles, &handles_before);

    uv_run(&loop, UV_RUN_NOWAIT);
    more = node_platform_->FlushForegroundTasks(GetIsolate());
    if (more)
      continue;

    uv_walk(&loop, collectUvHandles, &handles_after);
    handles_changed = handles_before != handles_after;
    if (handles_changed)
      continue;

    assert(!more && !handles_changed);
    return;
  }

  if (more || handles_changed)
    zeek_notifier_->Notify();
}
