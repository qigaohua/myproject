#ifndef LIBDEBUG_H
#define LIBDEBUG_H

#ifdef __cplusplus
extern "C" {
#endif


/*! Initialize backtrace handler, once "Segmentation fault" occured,
 * the backtrace info will be show like "(gdb) bt"
 *
 */
int debug_backtrace_init();


/*! backtrace dump, can be called everywhere in your code
 *
 */
void debug_backtrace_dump();


/*! help analysis signals
 *
 */
int debug_signals_init();

#ifdef __cplusplus
}
#endif
#endif
