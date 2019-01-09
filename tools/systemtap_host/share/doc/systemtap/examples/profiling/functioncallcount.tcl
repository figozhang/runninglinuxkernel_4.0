if {[istarget s390x-*-*] && ![min_kernel_vers_p 3.11.0]} {
    # PR19345: s390x has a kernel bug where you can't probe functions
    # that contain the "lgrl" instruction. RHEL7.0 (3.10.0-123) has
    # this bug. This bug was fixed in RHEL7's kernel 3.10.0-155. So,
    # we won't test this on any kernel less than 3.11.0 on s390x.
    untested "$test (PR19345 - s390x kprobes bug)" 
    continue
}
