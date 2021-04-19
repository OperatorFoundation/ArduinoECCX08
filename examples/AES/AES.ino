#include <ArduinoECCX08.h>

void setup() {
  Serial.begin(9600);
  while (!Serial);

  if (!ECCX08.begin()) {
    Serial.println("Failed to communicate with ECC508/ECC608!");
    while (1);
  }

  if (!ECCX08.locked()) {
    Serial.println("The ECC508/ECC608 is not locked!");
    while (1);
  }
}

void loop() {
  byte mode = 0;
  int slot = 0;
  byte data[16] = {0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0};
  byte result[16];

  int success = ECCX08.aesEncryptECB(mode, slot, data, result);

  if (success == 1) {
    Serial.println("AES encryption succeeded!");
  } else {
    Serial.println("AES encryption failed!");
  }

  delay(1000);
}

