#ifndef CONFIG_H
#define CONFIG_H

#undef WITH_HOME

/*
 * 2015.11.25 cxd4
 *
 * To do:  Win32 port of Mupen64 unconditionally calls VCR functions.
 * Therefore the #undef VCR breaks Win32 builds, while Win32 make defines it.
 *
 * Probably should look for a way to detach VCR dependency from Win32 port.
 */
#ifndef _WIN32
#undef VCR_SUPPORT
#endif

#define GTK2_SUPPORT 1

#if defined(_WIN32) && !defined(__WIN32__)
#define __WIN32__
#endif

#endif /* CONFIG_H */
