#ifndef FD_PUBLIC_H
#define FD_PUBLIC_H

#ifdef __cplusplus
extern "C" {
#endif

struct pipe_screen;
struct pipe_screen_config;
struct renderonly;

struct pipe_screen *fd_screen_create(int fd, const struct pipe_screen_config *config, struct renderonly *ro);

#ifdef __cplusplus
}
#endif

#endif