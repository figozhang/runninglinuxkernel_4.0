/* -*- linux-c -*- 
 * transport_msgs.h - messages exchanged between module and userspace
 *
 * Copyright (C) Red Hat Inc, 2006-2011
 *
 * This file is part of systemtap, and is free software.  You can
 * redistribute it and/or modify it under the terms of the GNU General
 * Public License (GPL); either version 2, or (at your option) any
 * later version.
 */

/*
 * NB: consider backward compatibility implications such as PR12612
 * before changing existing message structures in any way.
 */

#define STP_MODULE_NAME_LEN 128
#define STP_SYMBOL_NAME_LEN 128
#define STP_TZ_NAME_LEN 64
#define STP_REMOTE_URI_LEN 128

struct _stp_trace {
	uint32_t sequence;	/* event number */
	uint32_t pdu_len;	/* length of data after this trace */
};

/* stp control channel command values */
enum
{
	/** stapio sends a STP_START after recieving a STP_TRANSPORT from
	    the module. The module sends STP_START back with result of call
	    systemtap_module_init() which will install all initial probes.  */
	STP_START,
	/** stapio sends STP_EXIT to signal it wants to stop the module
	    itself or in response to receiving a STP_REQUEST_EXIT.
	    The module sends STP_EXIT once _stp_clean_and_exit has been
	    called (the first time) in reponse to a STP_EXIT or an rmmod.  */
	STP_EXIT,
	/** _stp_warn and _stp_error messages from the module.  stapio
	    parses the start if the message payload string to determine
	    whether it is a WARNING: or ERROR:.  */
	STP_OOB_DATA,
	/**  Send by the module (tapset/system.stp) to request stapio to
	     execute a shell command with the given message payload.  */
	STP_SYSTEM,
	/** modules sends STP_TRANSPORT to stapio when ready to recieve a
	    STP_START message.  stapio sends STP_BULK and then STP_START
	    back.  */
	STP_TRANSPORT,
	/** Never used.  */
	STP_CONNECT,
	/** Never used.  */
	STP_DISCONNECT,
	/** Send by the staprun when initializing relayfs in response to a
	    STP_TRANSPORT message with a (empty) 127 char payload.  Silently
	    absorbed by module when in STP_BULKMODE (percpu files), otherwise
	    returns -EINVAL to indicate bulkmode is disabled.  */
	STP_BULK,
	/** Send as first message from staprun stp_main_loop, but never
	    never acted upon. Used to be initial message for message to
	    start requestion symbol data (symbol data is now compiled
	    into the module).  */
	STP_READY,
	/** Send by staprun at startup to notify module of where the kernel
	    (_stext) and all other modules are loaded.  */
        STP_RELOCATION,
	/** Never used.  deprecated STP_TRANSPORT_VERSION == 1 **/
	STP_BUF_INFO,
	/** Never used.  */
	STP_SUBBUFS_CONSUMED,
	/** Used by the module only when STP_TRANSPORT_VERSION == 1 for
	    stapio to write realtime data packet to disk.  */
	STP_REALTIME_DATA,
	/** Send by the module when it gets unloaded or STP_EXIT has been
	    received by stapio.  */
	STP_REQUEST_EXIT,
	/** Send by staprun to notify module of current timezone.
            Only send once at startup.  */
        STP_TZINFO,
	/** Send by staprun to notify module of the user's privilege credentials.
            Only send once at startup.  */
        STP_PRIVILEGE_CREDENTIALS,
	/** Send by staprun to notify module of remote identity, if any.
            Only send once at startup.  */
        STP_REMOTE_ID,
	/** Max number of message types, sanity check only.  */
	STP_MAX_CMD,
  /** Sent by stapio after having recevied STP_TRANSPORT. Notifies
      the module of the target namespaces pid.*/
  STP_NAMESPACES_PID
};

#ifdef DEBUG_TRANS
static const char *_stp_command_name[] = {
	"STP_START",
	"STP_EXIT",
	"STP_OOB_DATA",
	"STP_SYSTEM",
	"STP_TRANSPORT",
	"STP_CONNECT",
	"STP_DISCONNECT",
	"STP_BULK",
	"STP_READY",
	"STP_RELOCATION",
	"STP_BUF_INFO",
	"STP_SUBBUFS_CONSUMED",
	"STP_REALTIME_DATA",
	"STP_REQUEST_EXIT",
	"STP_TZINFO",
	"STP_PRIVILEGE_CREDENTIALS",
	"STP_REMOTE_ID",
  "STP_NAMESPACES_PID",
};
#endif /* DEBUG_TRANS */

/* control channel messages */

/* command to execute: module->stapio */
struct _stp_msg_cmd
{
	char cmd[128];
};

/* Unwind data. stapio->module */
struct _stp_msg_unwind
{
	/* the module name, or "*" for all */
	char name[STP_MODULE_NAME_LEN];
	/* length of unwind data */
	uint32_t unwind_len;
	/* data ...*/
};

/* Request to start probes. */
/* stapio->module->stapio */
struct _stp_msg_start
{
	pid_t target;
        int32_t res;    // for reply: result of systemtap_module_init
};

/* target namespaces pid */
struct _stp_msg_ns_pid
{
  pid_t target;
};

#if STP_TRANSPORT_VERSION == 1
/**** for compatibility with old relayfs ****/
struct _stp_buf_info
{
        int32_t cpu;
        uint32_t produced;
        uint32_t consumed;
        int32_t flushing;
};
struct _stp_consumed_info
{
        int32_t cpu;
        uint32_t consumed;
};
#endif

/* Unwind data. stapio->module */
struct _stp_msg_relocation
{
	char module[STP_MODULE_NAME_LEN];
	char reloc[STP_SYMBOL_NAME_LEN];
	uint64_t address;
};

struct _stp_msg_tzinfo 
{
        int64_t tz_gmtoff;
        char tz_name[STP_TZ_NAME_LEN];
};

struct _stp_msg_privilege_credentials
{
        int32_t pc_group_mask;
};

struct _stp_msg_remote_id
{
        int32_t remote_id;
        char remote_uri[STP_REMOTE_URI_LEN];
};
