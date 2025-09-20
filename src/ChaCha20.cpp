
#include "ChaCha20.h"


ErrorCode ChaCha20::setup(const uint8_t *Key, uint8_t keyLength) { 
  if (Key == nullptr) {
    Log::Alarm("ChaCha", "A nullptr was passed as key");
    return ErrorCode::INVALID_PARAM;
  }

  if (keyLength < 32) {
    Log::Alarm("ChaCha", "Key length has to be >= 32");
    return ErrorCode::INVALID_PARAM;
  }

  _chacha.setKey(Key, keyLength);

  Log::Trace("ChaCha", "Setup done");
  _initDone = true;
  return ErrorCode::OK;
}



ErrorCode ChaCha20::Encrypt(std::vector<uint8_t> &Data, uint8_t Nonce[], uint8_t NonceSize) {
  Log::Trace("ChaCha", "Encryption started");

  if (!_initDone) {
    Log::Alarm("ChaCha", "Not initialized!");
    return ErrorCode::NOT_INITIALIZED;
  }

  if (Data.empty()) {
    Log::Alarm("ChaCha", "No data to encrypt");
    return ErrorCode::INVALID_PARAM;
  }

  if (Nonce == nullptr) {
    Log::Alarm("ChaCha", "A nullptr was passed as nonce");
    return ErrorCode::INVALID_PARAM;
  }

  if (!(NonceSize == 8 || NonceSize == 12)) {
    Log::Alarm("ChaCha", std::format("NonceSize has to be eighter 8 or 12. Passed NonceSize is {}", NonceSize));
    return ErrorCode::INVALID_PARAM;
  }

  if (_CounterChanged && _CounterSize != (16 - NonceSize)) {
    Log::Alarm("ChaCha", std::format("Counter size has to be 16 - NonceSize to fit the chacha matrix. NonceSize is {} while CounterSize is {}", NonceSize, _CounterSize));
    return ErrorCode::INVALID_PARAM;
  }

  // Set nonce
  _chacha.setIV(Nonce, NonceSize);

  // Set counter
  _chacha.setCounter(_Counter, 16 - NonceSize);

  // Encrypt the message
  _chacha.encrypt(Data.data(), Data.data(), Data.size());

  Log::Trace("ChaCha", "Encryption done");
  return ErrorCode::OK;
}



ErrorCode ChaCha20::Decrypt(std::vector<uint8_t> &Data, uint8_t Nonce[], uint8_t NonceSize) {
  Log::Trace("ChaCha", "Decryption started");

  if (!_initDone) {
    Log::Alarm("ChaCha", "Not initialized!");
    return ErrorCode::NOT_INITIALIZED;
  }

  if (Data.empty()) {
    Log::Alarm("ChaCha", "No data to decrypt");
    return ErrorCode::INVALID_PARAM;
  }

  if (Nonce == nullptr) {
    Log::Alarm("ChaCha", "A nullptr was passed as nonce");
    return ErrorCode::INVALID_PARAM;
  }

  if (!(NonceSize == 8 || NonceSize == 12)) {
    Log::Alarm("ChaCha", std::format("NonceSize has to be eighter 8 or 12. Passed NonceSize is {}", NonceSize));
    return ErrorCode::INVALID_PARAM;
  }

  if (_CounterChanged && _CounterSize != (16 - NonceSize)) {
    Log::Alarm("ChaCha", std::format("Counter size has to be 16 - NonceSize to fit the chacha matrix. NonceSize is {} while CounterSize is {}", NonceSize, _CounterSize));
    return ErrorCode::INVALID_PARAM;
  }
  
  // Set nonce
  _chacha.setIV(Nonce, NonceSize);

  // Set counter
  _chacha.setCounter(_Counter, 16 - NonceSize);

  // Decrypt
  _chacha.decrypt(Data.data(), Data.data(), Data.size());

  Log::Trace("ChaCha", "Decryption done");
  return ErrorCode::OK;
}



ErrorCode ChaCha20::changeCounter(uint8_t Counter[], uint8_t CounterSize) {

  if (Counter == nullptr) {
    Log::Alarm("ChaCha", "A nullptr was passed as counter");
    return ErrorCode::INVALID_PARAM;
  }

  if (!(CounterSize == 4 || CounterSize == 8)) {
    Log::Alarm("ChaCha", std::format("CounterSize has to be eighter 4 or 8. Passed NonceSize is {}", CounterSize));
    return ErrorCode::INVALID_PARAM;
  }

  explicit_bzero(_Counter, sizeof(_Counter));
  memcpy(_Counter, Counter, CounterSize);

  _CounterChanged = true;
  _CounterSize = CounterSize;

  Log::Info("ChaCha20", "Successfully changed Counter");
  return ErrorCode::OK;
}
