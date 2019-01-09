#include <linux/uidgid.h>

/* We need to check for an exported or inlined from_kuid_munged() */
uid_t bar (struct user_namespace *ns, kuid_t uid) { 
    return (from_kuid_munged(ns, uid));
}
