if {! [perf_probes_p]} {
    untested "$test (no perf probes support)" 
    continue
}
if {! [uprobes_p]} {
    untested "$test (no uprobes support)" 
    continue
}
