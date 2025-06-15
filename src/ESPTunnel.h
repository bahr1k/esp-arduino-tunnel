#pragma once

#ifdef __cplusplus
extern "C"
{
#endif

    void startPrivateTunnel(const char *domain, const char *device, const char *secret);
    void startPublicTunnel(const char *domain, const char *device, const char *secret);
    void debugPrivateTunnel(const char *domain, const char *device, const char *secret);
    void debugPublicTunnel(const char *domain, const char *device, const char *secret);

    void start_tunnel(const char *domain, const char *device, const char *secret, bool isPublic, bool debug, bool manualEof, bool blocking);
#ifdef __cplusplus
}
#endif