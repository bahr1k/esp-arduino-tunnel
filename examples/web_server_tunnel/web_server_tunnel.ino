#include <Arduino.h>
#include <WiFi.h>
#include <WebServer.h>
#include <ESPTunnel.h>

// WiFi
#define WIFI_SSID "MY_WIFI"
#define WIFI_PASSWORD "MY_WIFI_PASSWORD"

//Your Domain registred in https://device-tunnel.top/
#define TUNNEL_DOMAIN "arduino.ip-ddns.com" 
//Your Secret obtained in https://device-tunnel.top/
#define TUNNEL_SECRET "6lHPnL4BkTznVtn0n9eg0JrEdFjymHQQ1NqhHxW17tpofUH4qpbadH8eNej572ry"  
//Your Device name, any valid in url name
#define APP_NAME "My-World-App" 

WebServer server(80);
extern const char examplePage[] PROGMEM;

void setup() {
  Serial.begin(115200);

  Serial.print("Connecting to WiFi ");
  Serial.println(WIFI_SSID);

  WiFi.mode(WIFI_STA);
  WiFi.begin(WIFI_SSID, WIFI_PASSWORD);
  while (WiFi.status() != WL_CONNECTED) {
    delay(500);
    Serial.print(".");
  }
  Serial.print(" IP address: ");
  Serial.println(WiFi.localIP());

  Serial.println("Run tunnel");
  startPublicTunnel(TUNNEL_DOMAIN, APP_NAME, TUNNEL_SECRET);
  //startPrivateTunnel(TUNNEL_DOMAIN, APP_NAME, TUNNEL_SECRET); //access only via authorization in device-tunnel.top

  Serial.println("Run web server");
  server.on("/", [] {
     server.send(200, "text/html", examplePage);
  });
  server.begin();
}

void loop() {
  server.handleClient();
  delay(50);
}

const char examplePage[] PROGMEM = R"=====(
<!DOCTYPE html>
<html lang="ru">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>Hello, World!</title>
    <style>
        * {
            margin: 0;
            padding: 0;
            box-sizing: border-box;
        }
        body {
            font-family: 'Segoe UI', Tahoma, Geneva, Verdana, sans-serif;
            display: flex;
            justify-content: center;
            align-items: center;
            min-height: 100vh;
            background: linear-gradient(135deg, #667eea 0%, #764ba2 100%);
            color: #ffffff;
            text-align: center;
            overflow: hidden;
            padding: 20px;
        }
        .container {
            background-color: rgba(255, 255, 255, 0.1);
            padding: 50px 70px;
            border-radius: 15px;
            box-shadow: 0 10px 30px rgba(0, 0, 0, 0.2);
            animation: fadeInScaleUp 1s ease-out forwards;
            max-width: 90%;
        }
        @keyframes fadeInScaleUp {
            0% {
                opacity: 0;
                transform: scale(0.9);
            }
            100% {
                opacity: 1;
                transform: scale(1);
            }
        }
        h1 {
            font-size: 3.5em;
            margin-bottom: 0.5em;
            font-weight: 700;
            letter-spacing: 1px;
        }
        p {
            font-size: 1.2em;
            line-height: 1.6;
            max-width: 600px;
            margin: 0 auto;
        }
        .highlight {
            color: #f0e68c;
            font-weight: bold;
        }
        @media (max-width: 768px) {
            .container {
                padding: 40px 30px;
            }
            h1 {
                font-size: 2.8em;
            }
            p {
                font-size: 1.1em;
            }
        }
        @media (max-width: 480px) {
            h1 {
                font-size: 2.2em;
            }
            p {
                font-size: 1em;
            }
            .container {
                padding: 30px 20px;
            }
        }
    </style>
</head>
<body>
    <div class="container">
        <h1>Hello from <span class="highlight">World</span>!</h1>
        <p>This is a simple web page</p>
    </div>
</body>
</html>
)=====";

