#include "HardwareSerial.h"
#include "ChaCha20.h"

// Create a the ChaCha objects
ChaCha20 EncCipher;
ChaCha20 DecCipher;

// Encryption key
uint8_t Key[32] = {0x61, 0x5C, 0xB4, 0x51, 0xAE, 0x2F, 0x7D, 0x38, 0x28, 0xFE, 0xEE, 0x4D, 0xC7, 0x78, 0xEA, 0x4C, 0x11, 0x12, 0xAC, 0x47, 0x61, 0xF7, 0xD7, 0x8C, 0x94, 0x4F, 0xF7, 0xC6, 0xC0, 0xBE, 0x86, 0xA9};

// Nonce (number used once) for encryption (has to be unique for every encryption)
uint8_t Nonce[8] = {0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07};

// The test-data as a string and vector
const char* PlaneText = "Hello World";
std::vector<uint8_t> PlaneText_Vec (PlaneText, PlaneText+strlen(PlaneText));



// Custom log handler to redirect logs to Serial
void SerialLogHandler(int level, const std::string_view module, const std::string_view msg) {
    const char* out = std::format("{}:  [{}] {}", LOG_LEVEL_STRINGS[level], module, msg).c_str();
     Serial.println(out);  // Print log message over UART
}

// Helper function to print vectors in HEX format
void PrintVectorHEX(std::vector<uint8_t> &data) {
  for (uint16_t j = 0; j < data.size(); j++) {
    Serial.print((char)data[j], HEX);
    Serial.print(" ");
  }
  Serial.println("");
}

// Helper function to print vectors as ASCII characters
void PrintVectorCHAR(std::vector<uint8_t> &data) {
  for (uint16_t j = 0; j < data.size(); j++) {
    Serial.print((char)data[j]);
  }
  Serial.println("");
}



int main(void) {
    Serial.begin(115200);   // Start the serial port at 115200 baud
    Log::addLogger(SerialLogHandler);   // Register our Serial logger for debug output

    EncCipher.setup( Key, sizeof(Key));     // Setup the ciphers with the key (size has to be >= 32)
    DecCipher.setup( Key, sizeof(Key));


    Print_Vector_CHAR(PlaneText_Vec);       // Print the text before encryption
    EncCipher.Encrypt(PlaneText_Vec, Nonce.data(), Nonce.size());   // Encrypt the data with the nonce

    Print_Vector_HEX(PlaneText_Vec);        // Print the cipher-text as HEX and ASCII to show succesfull encryption
    Print_Vector_CHAR(PlaneText_Vec);

    DecCipher.Decrypt(PlaneText_Vec, Nonce.data(), Nonce.size());   // Decrypt the data with the same nonce used for encryption
    Print_Vector_CHAR(PlaneText_Vec);       // Print the decrypted text

    while(1) {}  // Keep running (embedded main loop)
}