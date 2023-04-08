#include "Types.h"

#include "ZeekCompat.h"
#include "ZeekJS.h"

#include "zeek/IPAddr.h"
#include "zeek/IntrusivePtr.h"
#include "zeek/Type.h"
#include "zeek/Val.h"
#include "zeek/ZeekString.h"
#include "zeek/module_util.h"

namespace {

// Tracking of wrapped Zeek objects. As long as the JavaScript side object wrapping
// a Zeek side object hasn't been collected yet, we can re-use it as Zeek gives us
// the same ZeekVal pointer.
//
// Include the mask, because it's part of a wrap.
using ZeekValWrapKey = std::pair<zeek::Val*, int>;
static std::map<ZeekValWrapKey, ZeekValWrap*> wrapped_objects;

// Zeek allocated strings as external string resource to avoid copying strings into
// the JS heap. The Zeek object "owning" the string is ref'ed/unref'ed to control
// lifetime of the string. Used for StringVal and also field and enum names.
class ExternalZeekStringResource : public v8::String::ExternalOneByteStringResource {
 public:
  ExternalZeekStringResource(zeek::Obj* obj, const char* data, size_t length)
      : obj_(obj), data_(data), length_(length) {
    Ref(obj_);
  }

  void Dispose() override {
    dprintf("Disposing ExternalZeekString: this=%p data=%p length=%lu obj_=%p", this,
            data_, length_, obj_);

    Unref(obj_);
    data_ = nullptr;
    length_ = 0;

    // Calls delete *this
    v8::String::ExternalOneByteStringResource::Dispose();
  }

  [[nodiscard]] const char* data() const override { return data_; }

  [[nodiscard]] size_t length() const override { return length_; };

 private:
  zeek::Obj* obj_;
  const char* data_ = nullptr;
  size_t length_ = -1;
};

v8::Local<v8::String> v8_str_intern(v8::Isolate* i, const char* s) {
  return v8::String::NewFromUtf8(i, s, v8::NewStringType::kInternalized)
      .ToLocalChecked();
}

v8::Local<v8::String> v8_str(v8::Isolate* i, const char* s) {
  return v8::String::NewFromUtf8(i, s).ToLocalChecked();
}

v8::Local<v8::String> v8_str_extern(v8::Isolate* i,
                                    zeek::Obj* obj,
                                    const char* data,
                                    size_t length = 0) {
#ifdef __clang_analyzer__
  // clang-tidy thinks the StringResource object is never freed,
  // hide the allocation from it.
  return v8_str(i, data);
#else
  if (length == 0)
    length = strlen(data);
  auto res = new ExternalZeekStringResource(obj, data, length);
  return v8::String::NewExternalOneByte(i, res).ToLocalChecked();
#endif
}

}  // namespace

ZeekValWrapper::ZeekValWrapper(v8::Isolate* isolate) : isolate_(isolate) {
  wrap_private_key_.Reset(isolate,
                          v8::Private::ForApi(isolate, v8_str("zeekjs::object::tag")));
  v8::Local<v8::ObjectTemplate> record_template = v8::ObjectTemplate::New(isolate_);
  record_template->SetInternalFieldCount(1);
  record_template->SetPrivate(GetWrapPrivateKey(isolate), v8::True(isolate),
                              v8::PropertyAttribute::DontEnum);
  v8::NamedPropertyHandlerConfiguration record_conf = {nullptr};
  record_conf.getter = ZeekRecordGetter;
  record_conf.setter = ZeekRecordSetter;
  record_conf.enumerator = ZeekRecordEnumerator;
  record_conf.query = ZeekRecordQuery;
  record_template->SetHandler(record_conf);

  record_template_.Reset(isolate_, record_template);

  v8::Local<v8::ObjectTemplate> table_template = v8::ObjectTemplate::New(isolate_);
  table_template->SetInternalFieldCount(1);

  v8::NamedPropertyHandlerConfiguration table_conf = {nullptr};
  table_conf.getter = ZeekTableGetter;
  table_conf.setter = ZeekTableSetter;
  table_conf.enumerator = ZeekTableEnumerator;
  table_template->SetHandler(table_conf);

  // This is insane
  v8::IndexedPropertyHandlerConfiguration table_indexed_conf = {nullptr};
  table_indexed_conf.getter = ZeekTableIndexGetter;
  table_indexed_conf.setter = ZeekTableIndexSetter;
  table_template->SetHandler(table_indexed_conf);

  table_template_.Reset(isolate, table_template);

  port_str_.Reset(isolate, v8_str_intern("port"));
  proto_str_.Reset(isolate, v8_str_intern("proto"));
  toJSON_str_.Reset(isolate, v8_str_intern("toJSON"));
}

int ZeekValWrapper::GetRecordFieldOffset(const zeek::RecordTypePtr& rt,
                                         const std::string& field) {
  OffsetMap& map = record_field_offsets[rt];  // Find or add.

  if (const auto& it = map.find(field); it != map.end())
    return it->second;

  int offset = rt->FieldOffset(field.c_str());
  return map.insert({field, offset}).first->second;
}

v8::Local<v8::Object> ZeekValWrapper::WrapAsObject(const zeek::ValPtr& vp,
                                                   int attr_mask) {
  const ZeekValWrapKey k{vp.get(), attr_mask};
  if (auto const& it = ::wrapped_objects.find(k); it != ::wrapped_objects.end()) {
    return it->second->GetHandle(isolate_);
  }

  v8::Local<v8::Context> context = isolate_->GetCurrentContext();
  v8::Local<v8::ObjectTemplate> tmpl = record_template_.Get(isolate_);
  v8::Local<v8::Object> obj = tmpl->NewInstance(context).ToLocalChecked();
  ZeekValWrap* wrap = ZeekValWrap::Make(isolate_, this, obj, vp->Ref(), attr_mask);
  return wrap->GetHandle(isolate_);
}

v8::Local<v8::Value> ZeekValWrapper::Wrap(const zeek::ValPtr& vp, int attr_mask) {
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
    case zeek::TYPE_STRING: {
      auto sv = vp->AsStringVal();
      if (sv->Len() == 0)
        return v8::String::Empty(isolate_);

      auto data = reinterpret_cast<const char*>(sv->Bytes());
      return v8_str_extern(isolate_, sv, data, sv->Len());
    }
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
      return WrapAsObject(vp, attr_mask);
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
        zeek::TableTypePtr tt = tval->GetType<zeek::TableType>();
        auto index_size = tt->GetIndexTypes().size();
        zeek::ListValPtr lv = tval->ToListVal();

        // Set of functions: return null for backwards compat
        if (index_size == 1 && tt->GetIndexTypes()[0]->Tag() == zeek::TYPE_FUNC)
          return v8::Null(isolate_);

        // For expedience, at this point, a set is
        // simply converted to an array. There's Set()
        // but that's not JSON stringify'ble, so...
        auto size = lv->Length();
        v8::Local<v8::Array> array = v8::Array::New(isolate_, size);
        for (int i = 0; i < size; i++) {
          auto& v = lv->Idx(i);
          if (index_size == 1)
            array->Set(context, i, Wrap(v->AsListVal()->Idx(0))).Check();
          else
            array->Set(context, i, Wrap(v)).Check();
        }
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
      zeek::EnumVal* ev = vp->AsEnumVal();
      zeek::EnumType* et = vp->GetType()->AsEnumType();
      const char* name = et->Lookup(ev->AsEnum());
      return v8_str_extern(isolate_, et, name);
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

bool ZeekValWrapper::Unwrap(v8::Isolate* isolate,
                            v8::Local<v8::Object> obj,
                            ZeekValWrap** wrap) {
  v8::Local<v8::Context> context = isolate_->GetCurrentContext();
  if (!obj->HasPrivate(context, GetWrapPrivateKey(isolate)).ToChecked())
    return false;

  *wrap = static_cast<ZeekValWrap*>(obj->GetAlignedPointerFromInternalField(0));

  return true;
}

// Convert a Javascript value over to a zeek::ValPtr using the given type.
//
// TODO: Refactor.
ZeekValWrapper::Result ZeekValWrapper::ToZeekVal(v8::Local<v8::Value> v8_val,
                                                 const zeek::TypePtr& type) {
  ZeekValWrapper::Result wrap_result = {.ok = true};
  v8::Local<v8::Context> context = isolate_->GetCurrentContext();
  zeek::TypeTag type_tag = type->Tag();

#ifdef DEBUG
  v8::Local<v8::String> typeof_str = v8_val->TypeOf(isolate_);
  v8::String::Utf8Value typeof_utf8(isolate_, typeof_str);
  dprintf("type tag %d/%s val=%s (%s)", type_tag, zeek::type_name(type_tag),
          *v8::String::Utf8Value(isolate_, v8_val), *typeof_utf8);
#endif

  // Pass-through fast-path: If this is an object and it's backed by
  // a ZeekValWrap of the same type, just thread it through directly.
  if (v8_val->IsObject()) {
    auto obj = v8::Local<v8::Object>::Cast(v8_val);
    ZeekValWrap* zeek_val_wrap = nullptr;
    if (Unwrap(isolate_, obj, &zeek_val_wrap)) {
      zeek::Val* vp = zeek_val_wrap->GetVal();
      if (type_tag == zeek::TYPE_ANY || vp->GetType()->Tag() == type_tag) {
        wrap_result.val = {zeek::NewRef{}, vp};
        return wrap_result;
      }

      // Give up if the tag disagreed.
      wrap_result.ok = false;
      wrap_result.error = zeek::util::fmt("ZeekValWrap pass-through bad tags: %d != %d",
                                          vp->GetType()->Tag(), type_tag);
      return wrap_result;
    }
  }

  if (type_tag == zeek::TYPE_BOOL && v8_val->IsBoolean()) {
    wrap_result.val = zeek::val_mgr->Bool(v8_val->IsTrue());
    return wrap_result;
  } else if (type_tag == zeek::TYPE_ADDR) {
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
  } else if (type_tag == zeek::TYPE_PORT) {
    // If this is an object, look for "port" and "proto" fields and interpret them.
    // This allows forth and back conversion between Zeek and Javascript
    if (v8_val->IsObject()) {
      auto obj = v8::Local<v8::Object>::Cast(v8_val);
      auto maybe_port = obj->Get(context, port_str_.Get(isolate_));
      auto maybe_proto = obj->Get(context, proto_str_.Get(isolate_));

      v8::Local<v8::Value> port_val = maybe_port.ToLocalChecked();
      v8::Local<v8::Value> proto_val = maybe_proto.ToLocalChecked();
      if (!port_val->IsNumber() || !proto_val->IsString()) {
        wrap_result.ok = false;
        wrap_result.error =
            "Missing property or bad type for port (number) or proto (string)";
        return wrap_result;
      }

      uint32_t port = port_val->ToUint32(context).ToLocalChecked()->Value();
      v8::String::Utf8Value proto_utf8_value(isolate_, proto_val);
      TransportProto proto = TRANSPORT_UNKNOWN;
      if (!strcmp("tcp", *proto_utf8_value)) {
        proto = TRANSPORT_TCP;
      } else if (!strcmp("udp", *proto_utf8_value)) {
        proto = TRANSPORT_UDP;
      } else if (!strcmp("icmp", *proto_utf8_value)) {
        proto = TRANSPORT_ICMP;
      }
      wrap_result.val = zeek::val_mgr->Port(port, proto);
      return wrap_result;
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
      double ts = v8_val->NumberValue(context).ToChecked();
      wrap_result.val = plugin::Corelight_ZeekJS::compat::TimeVal_New(ts);
      return wrap_result;
    } else if (v8_val->IsDate()) {
      double ts = v8::Local<v8::Date>::Cast(v8_val)->ValueOf() / 1000.0;
      wrap_result.val = plugin::Corelight_ZeekJS::compat::TimeVal_New(ts);
      return wrap_result;
    }
  } else if (type_tag == zeek::TYPE_INTERVAL) {
    if (v8_val->IsNumber()) {
      double interval = v8_val->NumberValue(context).ToChecked();
      wrap_result.val = plugin::Corelight_ZeekJS::compat::IntervalVal_New(interval);
      return wrap_result;
    }
  } else if (type_tag == zeek::TYPE_STRING) {
    if (v8_val->IsString()) {
      // TODO/XXX: Don't do UTF8 encoding here, just treat it as binary blob.
      // Look at WriteOneByte(), but need to allocate a buffer.
      v8::Local<v8::String> v8_string = v8::Local<v8::String>::Cast(v8_val);
      v8::String::Utf8Value utf8_value(isolate_, v8_string);
      wrap_result.val = zeek::make_intrusive<zeek::StringVal>(*utf8_value);
      return wrap_result;
    }

  } else if (type_tag == zeek::TYPE_ENUM) {
    zeek::EnumType* enum_type = type->AsEnumType();
    v8::Local<v8::String> v8_str = v8_val->ToString(context).ToLocalChecked();
    v8::String::Utf8Value utf8_value(isolate_, v8_str);

    std::string module_name = zeek::detail::extract_module_name(*utf8_value);
    std::string var_name = zeek::detail::extract_var_name(*utf8_value);
    zeek_int_t enum_int = enum_type->Lookup(module_name, var_name.c_str());
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
    if (!v8_val->IsArray()) {
      wrap_result.ok = false;
      wrap_result.error = "Expected JS type array for Zeek type vector";
    } else {
      v8::Local<v8::Array> v8_array = v8::Local<v8::Array>::Cast(v8_val);
      std::vector<zeek::ValPtr> vals(v8_array->Length());

      for (uint32_t i = 0; i < v8_array->Length(); i++) {
        v8::Local<v8::Value> v8_element_value =
            v8_array->Get(context, i).ToLocalChecked();

        ZeekValWrapper::Result element_result =
            ToZeekVal(v8_element_value, type->Yield());
        if (!element_result.ok) {
          wrap_result.ok = false;
          wrap_result.error +=
              zeek::util::fmt("Error with array element at index %u: %s", i,
                              element_result.error.c_str());
          return wrap_result;
        }

        vals[i] = element_result.val;
      }

      zeek::VectorTypePtr vtp = zeek::make_intrusive<zeek::VectorType>(type->Yield());
      zeek::VectorValPtr vvp = zeek::make_intrusive<zeek::VectorVal>(vtp);

      for (const auto& v : vals)
        plugin::Corelight_ZeekJS::compat::Vector_append(vvp, v);

      wrap_result.val = vvp;
      return wrap_result;
    }

    return wrap_result;
  } else if (type_tag == zeek::TYPE_TABLE) {
    zeek::TableTypePtr table_type = {zeek::NewRef{}, type->AsTableType()};
    const std::vector<zeek::TypePtr>& itypes = table_type->GetIndexTypes();
    // No support for compund indices.
    if (itypes.size() != 1) {
      wrap_result.ok = false;
      wrap_result.error = zeek::util::fmt("Unsupported index size %lu for type %s",
                                          itypes.size(), type->GetName().c_str());
      return wrap_result;
    }

    if (table_type->IsSet()) {
      if (v8_val->IsArray() || v8_val->IsSet()) {
        zeek::TableValPtr table_val = zeek::make_intrusive<zeek::TableVal>(table_type);
        v8::Local<v8::Array> v8_array;
        if (v8_val->IsArray())
          v8_array = v8::Local<v8::Array>::Cast(v8_val);
        else
          v8_array = v8::Local<v8::Set>::Cast(v8_val)->AsArray();

        // Okay we have an array, just convert it over to index type of the set.
        for (uint32_t i = 0; i < v8_array->Length(); i++) {
          ZeekValWrapper::Result index_result =
              ToZeekVal(v8_array->Get(context, i).ToLocalChecked(), itypes[0]);

          if (!index_result.ok) {
            wrap_result.ok = false;
            wrap_result.error =
                zeek::util::fmt("Error with array element at index %u: %s", i,
                                index_result.error.c_str());
            return wrap_result;
          }
          table_val->Assign(index_result.val, zeek::Val::nil);
        }
        wrap_result.val = std::move(table_val);
        return wrap_result;
      }
    } else {
      if (v8_val->IsObject()) {
        zeek::TableValPtr table_val = zeek::make_intrusive<zeek::TableVal>(table_type);
        zeek::TypePtr yield_type = type->Yield();
        v8::Local<v8::Object> v8_obj = v8::Local<v8::Object>::Cast(v8_val);

        v8::Local<v8::Array> v8_names =
            v8_obj->GetOwnPropertyNames(context).ToLocalChecked();

        for (uint32_t i = 0; i < v8_names->Length(); i++) {
          // Property name to Zeek Val
          v8::Local<v8::Value> key = v8_names->Get(context, i).ToLocalChecked();
          ZeekValWrapper::Result index_result = ToZeekVal(key, itypes[0]);

          if (!index_result.ok) {
            wrap_result.ok = false;
            wrap_result.error = index_result.error;
            return wrap_result;
          }

          ZeekValWrapper::Result value_result =
              ToZeekVal(v8_obj->Get(context, key).ToLocalChecked(), yield_type);

          if (!value_result.ok) {
            wrap_result.ok = false;
            wrap_result.error = value_result.error;
            return wrap_result;
          }
          table_val->Assign(index_result.val, value_result.val);
        }
        wrap_result.val = std::move(table_val);
        return wrap_result;
      }
    }
  } else if (type_tag == zeek::TYPE_RECORD) {
    // Take the record type and attempt to assign all non-optional
    // fields from the provided Javascript object.

    if (!v8_val->IsObject()) {
      wrap_result.error = "Expected Javascript object for record of type ";
      wrap_result.error += type->GetName();
    } else {
      zeek::RecordType* rt = type->AsRecordType();
      zeek::RecordTypePtr rtp = {zeek::NewRef{}, rt};  // Not sure this needs NewRef
      zeek::RecordValPtr record_val = zeek::make_intrusive<zeek::RecordVal>(rtp);
      v8::Local<v8::Object> v8_obj = v8::Local<v8::Object>::Cast(v8_val);

      for (int i = 0; i < rt->NumFields() && wrap_result.ok; i++) {
        const zeek::TypeDecl* field_decl = rt->FieldDecl(i);

        const bool is_optional =
            field_decl->GetAttr(zeek::detail::ATTR_OPTIONAL) != zeek::detail::Attr::nil;

        dprintf("i=%d field_name=%s optional=%d", i, field_decl->id, is_optional);

        v8::Local<v8::String> key = v8_str_extern(isolate_, rt, field_decl->id);

        // If the v8_obj does not have this field and the field
        // itself isn't optional, bail out.

        v8::Local<v8::Value> v8_field_value =
            v8_obj->Get(context, key).ToLocalChecked();

        if (v8_field_value->IsUndefined()) {
          if (is_optional)
            continue;

          wrap_result.ok = false;
          wrap_result.error = std::string("missing property ") + field_decl->id;
          wrap_result.error += " for record type " + rt->GetName();
          return wrap_result;
        }

        // If the field is null and it's optional, skip it, otherwise
        // report an error.
        if (v8_field_value->IsNull()) {
          if (is_optional)
            continue;

          wrap_result.ok = false;
          wrap_result.error = std::string("property ") + field_decl->id;
          wrap_result.error += " for record type " + rt->GetName() + " cannot be null";
          return wrap_result;
        }

        ZeekValWrapper::Result field_result =
            ToZeekVal(v8_field_value, field_decl->type);
        if (!field_result.ok) {
          wrap_result.ok = false;
          wrap_result.error += "Error for field ";
          wrap_result.error += field_decl->id;
          wrap_result.error += ": " + field_result.error;
          return wrap_result;
        }

        record_val->Assign(i, field_result.val);
      }

      wrap_result.val = std::move(record_val);
      return wrap_result;
    }
  }

  // Could not convert the type. Attempt to provide a meaningful
  // error message, preserving those existing in wrap_result.
  wrap_result.ok = false;
  wrap_result.val = zeek::ValPtr(nullptr);
  v8::String::Utf8Value utf8_value(isolate_, v8_val);
  v8::Local<v8::String> v8_typeof_str = v8_val->TypeOf(isolate_);
  v8::String::Utf8Value utf8_type(isolate_, v8_typeof_str);

  std::string error = "Unable to convert JS value '";
  error += *utf8_value + std::string("' of type ") + *utf8_type +
           std::string(" to Zeek type ");
  error += (type->IsSet() ? "set" : zeek::type_name(type_tag));
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
  if (wrap->GetVal()->GetType()->Tag() != zeek::TYPE_TABLE)
    return;

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
    v8::Local<v8::Value> error = v8::Exception::TypeError(::v8_str(
        isolate,
        zeek::util::fmt("Unexpected number of index types: %lu", itypes.size())));
    isolate->ThrowException(error);
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

void ZeekValWrapper::ZeekTableSetter(v8::Local<v8::Name> property,
                                     v8::Local<v8::Value> v8_val,
                                     const v8::PropertyCallbackInfo<v8::Value>& info) {
  v8::Isolate* isolate = info.GetIsolate();
  v8::Local<v8::Object> receiver = info.This();
  auto wrap =
      static_cast<ZeekValWrap*>(receiver->GetAlignedPointerFromInternalField(0));
  auto tval = static_cast<zeek::TableVal*>(wrap->GetVal());

  zeek::TableTypePtr ttype = tval->GetType<zeek::TableType>();
  std::vector<zeek::TypePtr> itypes = ttype->GetIndexTypes();
  v8::String::Utf8Value property_utf8(isolate, property);
  dprintf("tval=%p ttype=%p itypes=%lu property=%s", tval, ttype.get(), itypes.size(),
          *property_utf8);

  if (itypes.size() != 1) {
    v8::Local<v8::Value> error = v8::Exception::TypeError(::v8_str(
        isolate,
        zeek::util::fmt("Unexpected number of index types: %lu", itypes.size())));
    isolate->ThrowException(error);
    return;
  }

  zeek::TypePtr index_type = itypes[0];
  ZeekValWrapper::Result property_wrap_result =
      wrap->GetWrapper()->ToZeekVal(property, index_type);
  if (!property_wrap_result.ok) {
    v8::Local<v8::Value> error = v8::Exception::TypeError(::v8_str(
        isolate, zeek::util::fmt("Bad index: %s", property_wrap_result.error.c_str())));
    isolate->ThrowException(error);
    return;
  }

  ZeekValWrapper::Result value_wrap_result =
      wrap->GetWrapper()->ToZeekVal(v8_val, ttype->Yield());
  if (!value_wrap_result.ok) {
    v8::Local<v8::Value> error = v8::Exception::TypeError(::v8_str(
        isolate, zeek::util::fmt("Bad value: %s", value_wrap_result.error.c_str())));
    isolate->ThrowException(error);
    return;
  }

  // Broker forward is on...
  tval->Assign(property_wrap_result.val, value_wrap_result.val);

  info.GetReturnValue().Set(v8_val);
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
    v8::Local<v8::Value> error = v8::Exception::TypeError(::v8_str(
        isolate,
        zeek::util::fmt("Unexpected number of index types: %lu", itypes.size())));
    isolate->ThrowException(error);
    return;
  }

  zeek::TypePtr index_type = itypes[0];
  v8::Local<v8::Value> v8_index = v8::Integer::NewFromUnsigned(isolate, index);

  // Special case: If the underlying Zeek table has TYPE_STRING entries, convert
  // the index to a string as ToZeekVal() won't do that anymore.
  if (index_type->Tag() == zeek::TYPE_STRING)
    v8_index = v8_index->ToString(isolate->GetCurrentContext()).ToLocalChecked();

  ZeekValWrapper::Result index_result =
      wrap->GetWrapper()->ToZeekVal(v8_index, index_type);
  if (!index_result.ok) {
    v8::Local<v8::Value> error = v8::Exception::TypeError(
        ::v8_str(isolate, zeek::util::fmt("unable to convert index %d to %s", index,
                                          zeek::type_name(index_type->Tag()))));
    isolate->ThrowException(error);
    return;
  }

  zeek::ValPtr val = tval->Find(index_result.val);
  if (!val) {
    eprintf("Failed to lookup value for index=%d", index);
    return;
  }
  info.GetReturnValue().Set(wrap->GetWrapper()->Wrap(val));
}

void ZeekValWrapper::ZeekTableIndexSetter(
    uint32_t index,
    v8::Local<v8::Value> v8_val,
    const v8::PropertyCallbackInfo<v8::Value>& info) {
  v8::Isolate* isolate = info.GetIsolate();
  v8::Local<v8::Object> receiver = info.This();
  auto wrap =
      static_cast<ZeekValWrap*>(receiver->GetAlignedPointerFromInternalField(0));
  auto tval = static_cast<zeek::TableVal*>(wrap->GetVal());

  dprintf("tval=%p index=%d", tval, index);

  zeek::TableTypePtr ttype = tval->GetType<zeek::TableType>();
  std::vector<zeek::TypePtr> itypes = ttype->GetIndexTypes();
  if (itypes.size() != 1) {
    v8::Local<v8::Value> error = v8::Exception::TypeError(::v8_str(
        isolate,
        zeek::util::fmt("Unexpected number of index types: %lu", itypes.size())));
    isolate->ThrowException(error);
    return;
  }

  zeek::TypePtr index_type = itypes[0];
  v8::Local<v8::Value> v8_index = v8::Integer::NewFromUnsigned(isolate, index);

  // Special case: If the underlying Zeek table has TYPE_STRING entries, convert
  // the index to a string as ToZeekVal() won't do that anymore. Otherwise assume
  // the Integer an be converted to whatever is in the table (count or int).
  if (index_type->Tag() == zeek::TYPE_STRING)
    v8_index = v8_index->ToString(isolate->GetCurrentContext()).ToLocalChecked();

  ZeekValWrapper::Result index_wrap_result =
      wrap->GetWrapper()->ToZeekVal(v8_index, index_type);
  if (!index_wrap_result.ok) {
    v8::Local<v8::Value> error = v8::Exception::TypeError(
        ::v8_str(isolate, zeek::util::fmt("unable to convert index %d to %s", index,
                                          zeek::type_name(index_type->Tag()))));
    isolate->ThrowException(error);
    return;
  }

  ZeekValWrapper::Result value_wrap_result =
      wrap->GetWrapper()->ToZeekVal(v8_val, ttype->Yield());
  if (!value_wrap_result.ok) {
    v8::Local<v8::Value> error = v8::Exception::TypeError(::v8_str(
        isolate, zeek::util::fmt("Bad value: %s", value_wrap_result.error.c_str())));
    isolate->ThrowException(error);
    return;
  }

  // Broker forward is on...
  tval->Assign(index_wrap_result.val, value_wrap_result.val);

  info.GetReturnValue().Set(v8_val);
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

  zeek::TableTypePtr tt = tval->GetType<zeek::TableType>();

#ifdef DEBUG
  zeek::TypeTag tag = tt->Tag();
  dprintf("tval tag %d/%s set=%d size=%d", tag, zeek::type_name(tag), tt->IsSet(),
          size);
#endif

  // Let's shortcut here, only support Pure lists with size 1
  // of the base types, anything else is a bit nuts.
  const zeek::TypeListPtr& tl = tt->GetIndices();
  if (!tl->IsPure()) {
    isolate->ThrowException(::v8_str(isolate, "can enumerate only pure tables"));
    return;
  }

  if (tl->GetTypes().size() != 1) {
    isolate->ThrowException(::v8_str(isolate, "composite table indices not supported"));
    return;
  }

  if (!zeek::is_atomic_type(tl->GetTypes()[0])) {
    isolate->ThrowException(
        ::v8_str(isolate, "table with non-atomic index not supported"));
    return;
  }

  zeek::ListValPtr lv = tval->ToListVal();
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
  if (wrap->GetVal()->GetType()->Tag() != zeek::TYPE_RECORD)
    return;

  auto rval = wrap->GetVal()->AsRecordVal();
  const auto& rt = rval->GetType<zeek::RecordType>();

  v8::String::Utf8Value arg(isolate, property);

  if (*arg) {
    auto offset = wrap->GetWrapper()->GetRecordFieldOffset(rt, *arg);
    if (offset >= 0) {
      zeek::ValPtr vp = rval->GetFieldOrDefault(offset);
      info.GetReturnValue().Set(wrap->GetWrapper()->Wrap(vp, wrap->GetAttrMask()));
    }
  }
}

// Callback for for setting properties on a record.
void ZeekValWrapper::ZeekRecordSetter(v8::Local<v8::Name> property,
                                      v8::Local<v8::Value> v8_val,
                                      const v8::PropertyCallbackInfo<v8::Value>& info) {
  v8::Isolate* isolate = info.GetIsolate();
  v8::Local<v8::Object> receiver = info.This();
  auto wrap =
      static_cast<ZeekValWrap*>(receiver->GetAlignedPointerFromInternalField(0));
  auto rval = static_cast<zeek::RecordVal*>(wrap->GetVal());
  const auto& rt = rval->GetType<zeek::RecordType>();

  v8::String::Utf8Value arg(isolate, property);
  auto offset = *arg ? wrap->GetWrapper()->GetRecordFieldOffset(rt, *arg) : -1;
  if (offset < 0) {
    v8::Local<v8::Value> error = v8::Exception::TypeError(
        ::v8_str(isolate, zeek::util::fmt("field %s does not exist in record type %s",
                                          *arg, rt->GetName().c_str())));
    isolate->ThrowException(error);
    return;
  }

  zeek::TypePtr field_type = rt->GetFieldType(offset);

#ifdef DEBUG
  v8::Local<v8::String> typeof_str = v8_val->TypeOf(isolate);
  v8::String::Utf8Value typeof_utf8(isolate, typeof_str);
  v8::String::Utf8Value val_utf8(isolate, v8_val);
  dprintf("In setter for %s (%s) %s (%s)", *arg, zeek::type_name(field_type->Tag()),
          *val_utf8, *typeof_utf8);
#endif

  Result wrap_result = wrap->GetWrapper()->ToZeekVal(v8_val, field_type);
  if (!wrap_result.ok) {
    v8::Local<v8::Value> error =
        v8::Exception::TypeError(::v8_str(isolate, wrap_result.error.c_str()));
    isolate->ThrowException(error);
    return;
  }

  rval->Assign(offset, wrap_result.val);
  info.GetReturnValue().Set(v8_val);
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

  std::vector<v8::Local<v8::Value>> names;
  names.reserve(rt->NumFields());

  int attr_mask = wrap->GetAttrMask();

  for (int i = 0; i < rt->NumFields(); i++) {
    const zeek::TypeDecl* const field_decl = rt->FieldDecl(i);
    // Somewhat ad-hoc attribute filtering here.
    if (attr_mask & ZEEKJS_ATTR_LOG &&
        field_decl->GetAttr(zeek::detail::ATTR_LOG) == zeek::detail::Attr::nil) {
      continue;
    }
    v8::Local<v8::String> field_name =
        ::v8_str_extern(isolate, rt, field_decl->id, strlen(field_decl->id));
    names.emplace_back(v8::Local<v8::Name>::Cast(field_name));
  }

  v8::Local<v8::Array> array = v8::Array::New(isolate, names.data(), names.size());
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

v8::Local<v8::String> ZeekValWrapper::v8_str_intern(const char* s) {
  return ::v8_str_intern(isolate_, s);
}
v8::Local<v8::String> ZeekValWrapper::v8_str(const char* s) {
  return ::v8_str(isolate_, s);
}

ZeekValWrap* ZeekValWrap::Make(v8::Isolate* isolate,
                               ZeekValWrapper* wrapper,
                               v8::Local<v8::Object> record_obj,
                               zeek::Val* vp,
                               int attr_mask) {
  return new ZeekValWrap(isolate, wrapper, record_obj, vp, attr_mask);
}

ZeekValWrap::ZeekValWrap(v8::Isolate* isolate,
                         ZeekValWrapper* wrapper,
                         v8::Local<v8::Object> record_obj,
                         zeek::Val* vp,
                         int attr_mask)
    : wrapper_(wrapper), vp_(vp), attr_mask_(attr_mask) {
  record_obj->SetAlignedPointerInInternalField(0, this);
  persistent_obj_.Reset(isolate, record_obj);
  persistent_obj_.SetWeak(this, ZeekValWrap_WeakCallback,
                          v8::WeakCallbackType::kParameter);

  ZeekValWrapKey k{vp_, attr_mask};
  ::wrapped_objects.insert({k, this});

  constexpr int adjust = 8 * sizeof(zeek::RecordVal);
  isolate->AdjustAmountOfExternalAllocatedMemory(adjust);
}

void ZeekValWrap::ZeekValWrap_WeakCallback(
    const v8::WeakCallbackInfo<ZeekValWrap>& data) {
  void* p = data.GetParameter();
  auto wrap = static_cast<ZeekValWrap*>(p);

#ifdef DEBUG
  zeek::TypeTag type_tag = wrap->vp_->GetType()->Tag();
  const std::string& type_name = wrap->vp_->GetType()->GetName();
  dprintf("Unrefing vp_=%p (type tag %d/%s/%s) and deleting wrap=%p", wrap->vp_,
          type_tag, zeek::type_name(type_tag), type_name.c_str(), wrap);
#endif

  ZeekValWrapKey k{wrap->vp_, wrap->attr_mask_};
  ::wrapped_objects.erase(k);

  constexpr int adjust = -8 * static_cast<int>(sizeof(zeek::RecordVal));
  data.GetIsolate()->AdjustAmountOfExternalAllocatedMemory(adjust);

  if (wrap->vp_)
    zeek::Unref(wrap->vp_);

  wrap->persistent_obj_.Reset();

  delete wrap;
}
