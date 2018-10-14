// Will be included once by translate.cxx c_unparser::emit_common_header ().

#define STAP_SESSION_STARTING 0
#define STAP_SESSION_RUNNING 1
#define STAP_SESSION_ERROR 2
#define STAP_SESSION_STOPPING 3
#define STAP_SESSION_STOPPED 4

#if defined(__KERNEL__)

#include "linux/common_session_state.h"

#elif defined(__DYNINST__)

#include "dyninst/common_session_state.h"

#endif
