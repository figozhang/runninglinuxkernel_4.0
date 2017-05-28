if {! [plt_probes_p]} {
    # ltrace.stp requires .plt probes
    untested "$test (no plt probe support)" 
    continue
}
