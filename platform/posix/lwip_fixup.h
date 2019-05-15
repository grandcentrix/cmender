#ifndef LWIP_FIXUP_H
#define LWIP_FIXUP_H

#if LWIP_SOCKET
#ifdef close
#undef close
static inline int close(int s) {
    return lwip_close(s);
}
#endif

#ifdef write
#undef write
static inline int write(int s, const void *dataptr, size_t size) {
    return lwip_write(s, dataptr, size);
}
#endif
#endif

#endif /* LWIP_FIXUP_H */
