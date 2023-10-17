
// This functions reads /proc/self/maps, finds the begin and end
// of every executable code section with a related filename
// and calls addr2line_init_bfd for each of them, storing the
// resulting Addr2Line object pointer in a red/black tree
// for fast retrieval as function of a program pointer.
void addr2line_init();

//! @brief Print a backtrace with source file and line numbers.
void addr2line_print(FILE* fbacktraces, void** backtrace, size_t backtrace_size);
