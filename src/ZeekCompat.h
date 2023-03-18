#pragma once
// Main reason this is here is that clang-tidy triggers the following and
// we use an ugly ifndef __clang_analyzer__ below to hide the code.
//
// src/zeek/Obj.h:80:4: warning: Call to virtual method 'Obj::SetLocationInfo'
// during construction bypasses virtual dispatch
// [clang-analyzer-optin.cplusplus.VirtualCall]
//
//                         SetLocationInfo(&detail::start_location,
//                         &detail::end_location);

#if __has_include(<zeek/zeek-version.h>)
#include <zeek/zeek-version.h>
#else
#include <zeek/zeek-config.h>
#endif

#include <zeek/Val.h>

namespace plugin::Corelight_ZeekJS::compat {

// Show this to clang-tidy, but hide make_intrusive() calls triggering Obj.h
// errors about virtual function calls in constructors...
#ifdef __clang_analyzer__
zeek::ValPtr DoubleVal_New(double x);
zeek::ValPtr IntervalVal_New(double x);
zeek::ValPtr TimeVal_New(double x);

#else
inline zeek::ValPtr DoubleVal_New(double x) {
  return ::zeek::make_intrusive< ::zeek::DoubleVal>(x);
}

inline zeek::ValPtr TimeVal_New(double x) {
  return ::zeek::make_intrusive< ::zeek::TimeVal>(x);
}

inline zeek::ValPtr IntervalVal_New(double x) {
  return ::zeek::make_intrusive< ::zeek::IntervalVal>(x);
}
#endif

#if ZEEK_VERSION_NUMBER < 40100
// Zeek 4.0 cruft
inline bool Record_has_field(::zeek::RecordVal* rval, const char* field) {
  return rval->GetType()->AsRecordType()->FieldOffset(field) >= 0;
}

inline void Vector_append(const ::zeek::VectorValPtr& vvp, const zeek::ValPtr& vp) {
  vvp->Assign(vvp->Size(), vp);
}

inline ::zeek::ValPtr Vector_val_at(::zeek::VectorVal* vvp, unsigned int index) {
  return vvp->At(index);
}
#else
// Zeek 4.1 and later
bool inline Record_has_field(::zeek::RecordVal* rval, const char* field) {
  return rval->HasField(field);
}

void inline Vector_append(const ::zeek::VectorValPtr& vvp, const zeek::ValPtr& vp) {
  vvp->Append(vp);
}

inline ::zeek::ValPtr Vector_val_at(::zeek::VectorVal* vvp, unsigned int index) {
  return vvp->ValAt(index);
}
#endif

}  // namespace plugin::Corelight_ZeekJS::compat

// Darn it, stuff changed between 4.0 and 4.1 around Stmt:
// - Exec() isn't const anymore
// - Duplicate is new.
//
// We don't really care, but need to please the compiler.

#if ZEEK_VERSION_NUMBER < 40100
#define ZEEKJS_STMT_EXEC_CONST const
#else
#define ZEEKJS_STMT_EXEC_CONST
#define ZEEKJS_STMT_NEEDS_DUPLICATE 1
#endif

// Avoid warnings about bro_int_t in Zeek 5.1. Provide zeek_int_t here for
// older version as well.
#if ZEEK_VERSION_NUMBER < 50100
using zeek_int_t = int64_t;
#endif
