import threading
from paho.mqtt.client import Client

ID_BOB = "Bob"
ID_ALICE = "Alice"


class MQTT(Client):

    MQTT_IP="18.100.158.114"
    MQTT_USERNAME="sinf"
    MQTT_PASSWD="HkxNtvLB3GC5GQRUWfsA"

    def __init__(self, id):
        super().__init__()
        self.id = id
        self.ip = self.MQTT_IP
        self.payload = None
        self.message_event = threading.Event()  # Initialize the event
        self.username_pw_set(username=self.MQTT_USERNAME,
                             password=self.MQTT_PASSWD)



    def on_connect(self,client, userdata, flags, rc):
        if rc == 0:
            print("Connected to MQTT Broker!")
            client.subscribe(self.id)
        else:
            print("Failed to connect, return code %d\n", rc)

    def on_message(self,client, userdata, message):
        self.payload = message.payload
        self.message_event.set()
    
    def connect(self):
        super().connect(self.MQTT_IP,keepalive=60) 
        self.loop_start()  


    def receive_message(self):

        self.message_event.clear()  # Clear the event
        print("Waiting for a message...")
        message_received = self.message_event.wait(timeout=10)
        
        if not message_received:
            print("No se ha recibido ningún mensaje.")
            self.loop_stop()  
            return None
        return self.payload

    def publish_message(self, topic, payload):
        self.publish(topic, payload)
        #print(f"Published message to topic {topic}: {payload}")