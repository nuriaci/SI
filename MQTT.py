import paho.mqtt.client as Client
MQTT_IP=""
MQTT_USERNAME=""
MQTT_PASSWD=""
MQTT_PORT=""

class MQTT(Client):

    def __init__(self, id: str):
        self.ip = MQTT_IP
        self.id = id
        self.username_pw_set(username=MQTT_USERNAME, password=MQTT_PASSWD)

    def connect(self):
        def on_connect(client, userdata, flags, rc, self):
            if rc == 0:
                print("Connected to MQTT Broker!")
                client.subscribe(self.id)
            else:
                print("Failed to connect, return code %d\n", rc)
        # Set Connecting Client ID
        client = Client.Client(self.id)

        client.on_connect = on_connect
        client.connect(self.ip, MQTT_PORT)
        return client

    
