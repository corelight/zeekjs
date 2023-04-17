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

}  // namespace plugin::Corelight_ZeekJS::compat

// Avoid warnings about bro_int_t in Zeek 5.1. Provide zeek_int_t here for
// older version as well.
#if ZEEK_VERSION_NUMBER < 50100
using zeek_int_t = int64_t;
using zeek_uint_t = uint64_t;
#endif
