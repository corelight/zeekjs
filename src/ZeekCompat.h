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

#include <type_traits>
#if __has_include(<zeek/zeek-version.h>)
#include <zeek/zeek-version.h>
#else
#include <zeek/zeek-config.h>
#endif

#include <zeek/StmtEnums.h>
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

#if ZEEK_VERSION_NUMBER < 60200
constexpr zeek::detail::StmtTag STMT_EXTERN = zeek::detail::STMT_ANY;
#else
constexpr zeek::detail::StmtTag STMT_EXTERN = zeek::detail::STMT_EXTERN;
#endif

// In 8.0-dev the Location constructor was changed, deal with that.
template <typename L>
L make_location(const char* name, int line_number) {
  if constexpr (std::is_constructible_v<L, const char*, int, int, int, int>) {
    return L(name, line_number, line_number, 0, 0);
  } else {
    return L(name, line_number, line_number);
  }
}

// Make a detail::Location object for the given name and line.
inline zeek::detail::Location make_location(const char* name, int line_number) {
  return make_location<zeek::detail::Location>(name, line_number);
}

}  // namespace plugin::Corelight_ZeekJS::compat

// Avoid warnings about bro_int_t in Zeek 5.1. Provide zeek_int_t here for
// older version as well.
#if ZEEK_VERSION_NUMBER < 50100
using zeek_int_t = int64_t;
using zeek_uint_t = uint64_t;
#endif
