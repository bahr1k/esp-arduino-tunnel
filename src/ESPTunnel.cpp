#include "EspTunnel.h"
#include <Arduino.h>
#include <stdarg.h>

extern "C"
{
#include "tunnel.h"
}

static void serial_log(const char *tag, const char *fmt, va_list args)
{
	Serial.printf("%s: ", tag);
	Serial.vprintf(fmt, args);
	Serial.println();
}

static void debug_log(int lvl, const char *tag, const char *fmt, ...)
{
	if (lvl > 4)
		return;
	va_list args;
	va_start(args, fmt);
	serial_log(tag, fmt, args);
	va_end(args);
}

static void onlyErrors_log(int lvl, const char *tag, const char *fmt, ...)
{
	if (lvl > 1)
		return;
	va_list args;
	va_start(args, fmt);
	serial_log(tag, fmt, args);
	va_end(args);
}

void start_tunnel(const char *domain, const char *device, const char *secret, bool isPublic, bool debug, bool manualEof, bool blocking)
{
	tunnel_config_t config = TUNNEL_DEFAULT_CONFIG();
	config.domain = domain;
	config.secret = secret;
	config.name = device;
	config.is_public = isPublic;
	config.log_func = debug ? &debug_log : &onlyErrors_log;
	config.auto_eof = !manualEof;
	config.non_block = !blocking;
	tunnel_init(&config);
}

void startPrivateTunnel(const char *domain, const char *device, const char *secret)
{
	start_tunnel(domain, device, secret, false, false, false, false);
}

void startPublicTunnel(const char *domain, const char *device, const char *secret)
{
	start_tunnel(domain, device, secret, true, false, false, false);
}

void debugPrivateTunnel(const char *domain, const char *device, const char *secret)
{
	start_tunnel(domain, device, secret, false, true, false, false);
}

void debugPublicTunnel(const char *domain, const char *device, const char *secret)
{
	start_tunnel(domain, device, secret, true, true, false, false);
}