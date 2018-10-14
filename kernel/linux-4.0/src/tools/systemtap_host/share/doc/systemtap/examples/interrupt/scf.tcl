if {[istarget ia64-*-*]} {
    # ia64 has an unsupported dwarf unwind architecture
    untested "$test (no unwind support)" 
    continue
}
