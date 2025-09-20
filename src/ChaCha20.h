
#pragma once

#include <vector>
#include "Core_ChaCha.h"
#include "ErrorCodes.h"
#include "Logger.h"


class ChaCha20 {
public:

  /** @param Key: The ChaCha encryption-key as a byte-array
   *  @param keyLength: The length of the encyption-key in bytes
  */
  ErrorCode setup (const uint8_t *Key, uint8_t keyLength);

  /** @param Data: The data buffer to encrypt (encrypted in-place)
   *  @param Nonce: A byte-array nonce for the encryption (must be unique for each encryption)
   *  @param NonceSize: The size of the nonce in bytes (must be eighter 8 or 12)
  */
  ErrorCode Encrypt(std::vector<uint8_t> &Data, uint8_t Nonce[], uint8_t NonceSize);

  /** @param Data: The data buffer to decrypt (decrypted in-place)
   *  @param Nonce: A byte-array nonce for the decryption (must match the one used during encryption)
   *  @param NonceSize: The size of the nonce in bytes (must be eighter 8 or 12)
  */
  ErrorCode Decrypt(std::vector<uint8_t> &Data, uint8_t Nonce[], uint8_t NonceSize);

  /** @param Counter: A byte-array representing the initial block counter
   *  @param CounterSize: The size of the counter in bytes (must be eighter 4 or 8 (depending on nonce size))
  */
  ErrorCode changeCounter(uint8_t Counter[], uint8_t CounterSize);


private:

  Core_ChaCha _chacha = Core_ChaCha(20);  // 20 rounds

  bool _initDone = false;
  bool _CounterChanged = false;
  uint8_t _Counter[8] = {0xBE, 0xC9, 0x3F, 0xA6, 0x52, 0xDA, 0x4E, 0x7D};  // Random values, that the counter doesn't start at 0
  uint8_t _CounterSize = 8;
};
