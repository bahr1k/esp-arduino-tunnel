# esp-arduino-tunnel
Enabling HTTPS access to your device from anywhere
=======
# ESP Tunnel Library for Arduino

**ESP Tunnel** is an Arduino library for ESP32 that allows you to create a secure WebSocket tunnel to a remote service, enabling HTTPS access to your device from anywhere without port forwarding or a static IP address.

## Features

- 📡 Remote HTTPS access to ESP32 behind NAT/firewalls
- 🔐 Secure WebSocket-based tunneling
- 🌍 No port forwarding or public IP required
- ⚙️ Easy integration into Arduino projects
- 🔧 Support for both public and private tunnels
- 🐛 Built-in debugging functions

## How It Works

1. **ESP32** establishes a persistent WebSocket connection to the tunnel service
2. **Tunnel service** accepts incoming HTTPS requests for your domain and forwards them over WebSocket to your ESP32
3. ESP32 handles each request locally (e.g., serving web pages, reading sensors, controlling GPIOs) and returns a response back through the tunnel

## Quick Start

### 1. Get a Domain and Set Up Tunnel

- Register **any** domain or subdomain
- For free subdomains, use services like **No-IP** or **ClouDNS**
- Add your domain to https://device-tunnel.top/ service and get your secret key

### 2. Install the Library

Download the library and add it to your Arduino IDE libraries folder or install via Library Manager.

### 3. Include the Library

```cpp
#include <WiFi.h>
#include <WebServer.h>
#include <ESPTunnel.h>
```

### 4. Configure Parameters

```cpp
// WiFi settings
#define WIFI_SSID "YOUR_WIFI_SSID"
#define WIFI_PASSWORD "YOUR_WIFI_PASSWORD"

// Tunnel settings
#define TUNNEL_DOMAIN "yourdomain.com"           // Your domain
#define TUNNEL_SECRET "your_secret_key"          // Secret key from device-tunnel.top
#define APP_NAME "MyDevice"                      // Device name for routing
```

### 5. Basic Example

```cpp
#include <Arduino.h>
#include <WiFi.h>
#include <WebServer.h>
#include <ESPTunnel.h>

WebServer server(80);

void setup() {
  Serial.begin(115200);
  
void setup() {
  Serial.begin(115200);
  
  // Connect to WiFi
  WiFi.begin(WIFI_SSID, WIFI_PASSWORD);
  while (WiFi.status() != WL_CONNECTED) {
    delay(500);
    Serial.print(".");
  }
  Serial.println("WiFi connected!");
  
  // Start tunnel
  startPublicTunnel(TUNNEL_DOMAIN, APP_NAME, TUNNEL_SECRET);
  
  // Setup web server
  server.on("/", []() {
    server.send(200, "text/html", "<h1>Hello from ESP32!</h1>");
  });
  
  server.begin();
}

void loop() {
  server.handleClient();
  delay(10);
}
```

## API Reference

### Main Functions

#### `startPublicTunnel(domain, device, secret)`
Creates a public tunnel accessible to all users.

**Parameters:**
- `domain` - your domain (string)
- `device` - device name for routing (string)
- `secret` - secret key from tunnel service (string)

#### `startPrivateTunnel(domain, device, secret)`
Creates a private tunnel that requires authorization in device-tunnel.top service.

**Parameters:** same as `startPublicTunnel()`

### Debug Functions

Starts a tunnel with extended logging for debugging.
#### `debugPublicTunnel(domain, device, secret)`
#### `debugPrivateTunnel(domain, device, secret)`

### Advanced Configuration

#### `start_tunnel(domain, device, secret, isPublic, debug, manualEof, blocking)`
Full tunnel configuration with all parameters.

**Parameters:**
- `domain` - domain (string)
- `device` - device name (string)
- `secret` - secret key (string)
- `isPublic` - public access (true/false)
- `debug` - debug mode (true/false)
- `manualEof` - manual end-of-file control (true/false)
- `blocking` - blocking mode (true/false)

## Usage Examples

### Simple Web Server

```cpp
server.on("/", []() {
  server.send(200, "text/html", "<h1>ESP32 Web Server</h1>");
});

server.on("/status", []() {
  server.send(200, "application/json", "{\"status\":\"online\"}");
});
```

### GPIO Control

```cpp
server.on("/led/on", []() {
  digitalWrite(LED_BUILTIN, HIGH);
  server.send(200, "text/plain", "LED ON");
});

server.on("/led/off", []() {
  digitalWrite(LED_BUILTIN, LOW);
  server.send(200, "text/plain", "LED OFF");
});
```

### Reading Sensors

```cpp
server.on("/temperature", []() {
  float temp = readTemperature(); // your reading function
  server.send(200, "application/json", 
    "{\"temperature\":" + String(temp) + "}");
});
```

## Accessing Multiple Devices

If you have multiple ESP32 devices under one domain, you can route by path:

- Device A: `domain = "mygroup.example.com"`, `name = "deviceA"`
- Device B: same domain, `name = "deviceB"`

Then clients can access:
```
https://mygroup.example.com/deviceA/...
https://mygroup.example.com/deviceB/...
```

## Requirements

- ESP32 (ESP8266 not supported)
- Arduino IDE with ESP32 Core installed
- Internet connection
- Registered domain with configured tunnel service

## License

MIT

## Support

If you found a bug or have suggestions for improvement, please create an issue in the project repository.

---

Based on esp-idf-tunnel component: https://github.com/bahr1k/esp-idf-tunnel
