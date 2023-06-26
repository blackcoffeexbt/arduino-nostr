/*
  Nostr.h - Arduino library for Nostr.
  Created by Black Coffee <bc@omg.lol>, March 29th 2023
  Released under MIT License
*/
#include "Arduino.h"
#include "NostrEvent.h"
#include "ArduinoJson.h"
#include <iostream>
#include <base64.h>
#include <aes.h>

#include "Bitcoin.h"
#include "Hash.h"

#include <stdint.h>
#include <stdlib.h>
#include <esp_system.h>
#include <esp_random.h>
#include <esp_wifi.h>

/**
 * @brief Construct a new Nostr Event:: Nostr Event object
 * 
 */
NostrEvent::NostrEvent() {}

/**
 * @brief Write debug data to the Serial output
 * 
 * @param title 
 * @param message 
 */
void NostrEvent::_logToSerialWithTitle(String title, String message) {
    if(_isLoggingEnabled) {
        Serial.println(title);
        Serial.println(message);
        Serial.println("-------");
    }
}

/**
 * @brief Enable or disable verbose logging
 * 
 * @param loggingEnabled 
 */
void NostrEvent::setLogging(bool loggingEnabled) {
  _isLoggingEnabled = loggingEnabled;
}

String NostrEvent::getNoteId(char const *privateKeyHex, char const *pubKeyHex, unsigned long timestamp, String content) {
    size_t docSize = estimateNoteIdJsonDocumentSize(pubKeyHex, content);
    
    char buffer[50]; // Create a buffer to hold the output
    sprintf(buffer, "Size of JsonDocument: %zu", docSize); // %zu is the format specifier for size_t

    DynamicJsonDocument doc(docSize);
    JsonArray data = doc.createNestedArray("data");
    data.add(0);
    data.add(pubKeyHex);
    data.add(timestamp);
    data.add(1);
    data.add(doc.createNestedArray("tags"));
    data.add(content);

    // stringify event to message var
    String message;
    serializeJson(doc["data"], message);
    _logToSerialWithTitle("message is: ", String(message));

    // sha256 of message converted to hex, assign to msghash
    byte hash[64] = { 0 }; // hash
    int hashLen = 0;

    // Get the sha256 hash of the message
    hashLen = sha256(message, hash);
    String msgHash = toHex(hash, hashLen);
    _logToSerialWithTitle("SHA-256: ", msgHash);
    return msgHash;
}

/**
 * @brief Get a serialised string for a nostr note
 * 
 * @param privateKeyHex 
 * @param pubKeyHex 
 * @param timestamp 
 * @param content 
 * @return String 
 */
String NostrEvent::getNote(char const *privateKeyHex, char const *pubKeyHex, unsigned long timestamp, String content) {

    String noteId = getNoteId(privateKeyHex, pubKeyHex, timestamp, content);

    SchnorrSignature signature = getSignature(privateKeyHex, noteId);

    // Generate the JSON object ready for broadcasting
    size_t docSize = estimateFullNoteJsonDocumentSize(noteId, pubKeyHex, content, signature);
    DynamicJsonDocument fullEvent(docSize);
    fullEvent["id"] = noteId;
    fullEvent["pubkey"] = pubKeyHex;
    fullEvent["created_at"] = timestamp;
    fullEvent["kind"] = 1;
    StaticJsonDocument<200> doc;
    fullEvent["tags"] = doc.createNestedArray("test");
    fullEvent["content"] = content;
    fullEvent["sig"] = signature;

    // Serialize the array to JSON
    String json;
    serializeJson(fullEvent, json);

    String serialisedEventData = "[\"EVENT\"," + json + "]";
    // Print the JSON to the serial monitor
    _logToSerialWithTitle("Event JSON", serialisedEventData);
    return serialisedEventData;
}

/**
 * @brief Decrypt a DM event
 * 
 * @param privateKeyHex The account private key in hex format
 * @param serialisedJson the serialised JSON of the entire event from the relay
 * @return String 
 */
String NostrEvent::decryptDm(const char *privateKeyHex, String serialisedJson) {
    // get the content
    StaticJsonDocument<2048> doc;
    deserializeJson(doc, serialisedJson);
    String serialisedTest;
    serializeJson(doc, serialisedTest);
    _logToSerialWithTitle("serialisedTest", serialisedTest);

    String content = doc[2]["content"];

    String encryptedMessage = content.substring(0, content.indexOf("?iv="));
    String encryptedMessageHex = base64ToHex(encryptedMessage);
    int encryptedMessageSize =  encryptedMessageHex.length() / 2;
    byte encryptedMessageBin[encryptedMessageSize];
    fromHex(encryptedMessageHex, encryptedMessageBin, encryptedMessageSize);
    _logToSerialWithTitle("encryptedMessage", encryptedMessage);
    _logToSerialWithTitle("encryptedMessageHex", encryptedMessageHex);

    String iv = content.substring(content.indexOf("?iv=") + 4);
    String ivHex = base64ToHex(iv);
    int ivSize =  16;
    byte ivBin[ivSize];
    fromHex(ivHex, ivBin, ivSize);
    _logToSerialWithTitle("iv", iv);
    _logToSerialWithTitle("ivHex", ivHex);

    int byteSize =  32;
    byte privateKeyBytes[byteSize];
    fromHex(privateKeyHex, privateKeyBytes, byteSize);
    PrivateKey privateKey(privateKeyBytes);

    String senderPubKeyHex = doc[2]["pubkey"];
    _logToSerialWithTitle("senderPubKeyHex", senderPubKeyHex);
    byte senderPublicKeyBin[64];
    fromHex("02" + String(senderPubKeyHex), senderPublicKeyBin, 64);
    PublicKey senderPublicKey(senderPublicKeyBin);
    _logToSerialWithTitle("senderPublicKey.toString() is", senderPublicKey.toString());

    byte sharedPointX[32];
    privateKey.ecdh(senderPublicKey, sharedPointX, false);
    String sharedPointXHex = toHex(sharedPointX, sizeof(sharedPointX));
    _logToSerialWithTitle("sharedPointXHex is", sharedPointXHex);

    String message = _decryptData(sharedPointX, ivBin, encryptedMessageHex);
    message.trim();

    _logToSerialWithTitle("message", message);

    return message;
}

String NostrEvent::_decryptData(byte key[32], byte iv[16], String messageHex) {
  int byteSize =  messageHex.length() / 2;
  byte messageBin[byteSize];
  fromHex(messageHex, messageBin, byteSize);

  AES_ctx ctx;
  AES_init_ctx_iv(&ctx, key, iv);
  AES_CBC_decrypt_buffer(&ctx, messageBin, sizeof(messageBin));

  return String((char *)messageBin).substring(0, byteSize);
}

/**
 * @brief Get a serialised string for a nostr NIP04 encrypted DM
 * 
 * @param privateKeyHex 
 * @param pubKeyHex 
 * @param recipientPubKeyHex 
 * @param timestamp 
 * @param content 
 * @return String 
 */
String NostrEvent::getEncryptedDm(char const *privateKeyHex, char const *pubKeyHex, char const *recipientPubKeyHex, unsigned long timestamp, String content) {
    // Get shared point
    // Create the private key object
    int byteSize =  32;
    byte privateKeyBytes[byteSize];
    fromHex(privateKeyHex, privateKeyBytes, byteSize);
    PrivateKey privateKey(privateKeyBytes);

    byte publicKeyBin[64];
    fromHex("02" + String(recipientPubKeyHex), publicKeyBin, 64);
    PublicKey otherDhPublicKey(publicKeyBin);
    _logToSerialWithTitle("otherDhPublicKey.toString() is", otherDhPublicKey.toString());


    byte sharedPointX[32];
    privateKey.ecdh(otherDhPublicKey, sharedPointX, false);
    String sharedPointXHex = toHex(sharedPointX, sizeof(sharedPointX));
    _logToSerialWithTitle("sharedPointXHex is", sharedPointXHex);

    // Create the initialization vector
    std::array<uint8_t, 16> iv = NostrEvent::getRandomIv();

    String encryptedMessageHex = _encryptData(sharedPointX, iv.data(), content);
    _logToSerialWithTitle("encryptedMessage is", encryptedMessageHex);

    // divide the length of the hex string 2 to get the size of the byte array, since each byte consists of 2 hexadecimal characters.
    int encryptedMessageSize = encryptedMessageHex.length() / 2;
    uint8_t encryptedMessage[encryptedMessageSize];
    fromHex(encryptedMessageHex, encryptedMessage, encryptedMessageSize);

    String encryptedMessageBase64 = hexToBase64(encryptedMessageHex);
    _logToSerialWithTitle("encryptedMessageBase64 is", encryptedMessageBase64);

    String ivHex = toHex(iv.data(), 16);
    _logToSerialWithTitle("ivHex is", ivHex);
    String ivBase64 = hexToBase64(ivHex);
    _logToSerialWithTitle("ivBase64 is", ivBase64);

    encryptedMessageBase64 += "?iv=" + ivBase64;

    String message = _getSerialisedEncryptedDmArray(pubKeyHex, recipientPubKeyHex, timestamp, encryptedMessageBase64);

    byte hash[64] = { 0 }; // hash
    int hashLen = 0;

    // Get the sha256 hash of the message
    hashLen = sha256(message, hash);
    String msgHash = toHex(hash, hashLen);
    _logToSerialWithTitle("SHA-256:", msgHash);

    // Generate the schnorr sig of the messageHash
    SchnorrSignature signature = privateKey.schnorr_sign(hash);
    String signatureHex = String(signature);
    _logToSerialWithTitle("Schnorr sig is: ", signatureHex);

    String serialisedEventData = _getSerialisedEncryptedDmObject(pubKeyHex, recipientPubKeyHex, msgHash, timestamp, encryptedMessageBase64, signatureHex);
    _logToSerialWithTitle("serialisedEventData is", serialisedEventData);
    return serialisedEventData;
}

/**
 * @brief Convert a string to a byte array
 * 
 * @param input 
 * @param padding_diff 
 * @param output 
 */
void NostrEvent::_stringToByteArray(const char* input, int padding_diff, byte* output) {
    int i = 0;
    // remove end-of-string char
    while (input[i] != '\0') {
        output[i] = input[i];
        i++;
    }

    // pad between 1 and 16 bytes
    for (int j = 0; j < padding_diff; j++) {
        output[i + j] = padding_diff;
    }
}

/**
 * @brief AES CBC Encrpyt some data using a keys byte array and an initialisation vector
 * 
 * @param key 
 * @param iv 
 * @param msg 
 * @return String 
 */
String NostrEvent::_encryptData(byte key[32], byte iv[16], String msg) {
    // message has to be padded at the end so it is a multiple of 16
    int padding_diff = msg.length() % 16 == 0 ? 16 : 16 - (msg.length() % 16);

    int byteSize = msg.length() + padding_diff;
    byte messageBin[byteSize];
    _stringToByteArray(msg.c_str(), padding_diff, messageBin);

    AES_ctx ctx;
    AES_init_ctx_iv(&ctx, key, iv);

    AES_CBC_encrypt_buffer(&ctx, messageBin, sizeof(messageBin));

    return toHex(messageBin, sizeof(messageBin));
}

/**
 * @brief
 * 
 * @param pubKeyHex 
 * @param recipientPubKeyHex 
 * @param msgHash 
 * @param timestamp 
 * @param encryptedMessageWithIv 
 * @param schnorrSig 
 * @return String 
 */
String NostrEvent::_getSerialisedEncryptedDmObject(const char *pubKeyHex, const char *recipientPubKeyHex, String msgHash, int timestamp, String encryptedMessageWithIv, String schnorrSig) {
    // compute the required size
    const size_t CAPACITY = JSON_ARRAY_SIZE(6);
    // allocate the memory for the document
    StaticJsonDocument<1000> tagsDoc;
    // parse a JSON array
    String serialisedTagsArray = "[[\"p\",\"" + String(recipientPubKeyHex) + "\"]]";
    _logToSerialWithTitle("serialisedTagsArray is: ", serialisedTagsArray);
    deserializeJson(tagsDoc, serialisedTagsArray);

    // Generate the JSON object ready for broadcasting
    DynamicJsonDocument fullEvent(2000);
    fullEvent["id"] = msgHash;
    fullEvent["pubkey"] = pubKeyHex;
    fullEvent["created_at"] = timestamp;
    fullEvent["kind"] = 4;
    fullEvent["tags"] = tagsDoc;
    fullEvent["content"] = encryptedMessageWithIv;
    fullEvent["sig"] = schnorrSig;

    // Serialize the array to JSON
    String serialisedObject;
    serializeJson(fullEvent, serialisedObject);

    String serialisedEventObject = "[\"EVENT\"," + serialisedObject + "]";
    return serialisedEventObject;
}

/**
 * @brief Get a NIP04 message as an array that can be hashed to create a message ID
 * 
 * @param pubKeyHex 
 * @param recipientPubKeyHex 
 * @param timestamp 
 * @param encryptedMessageWithIv 
 * @return String 
 */
String NostrEvent::_getSerialisedEncryptedDmArray(char const *pubKeyHex, char const *recipientPubKeyHex, int timestamp, String encryptedMessageWithIv) {
    // compute the required size
    const size_t CAPACITY = JSON_ARRAY_SIZE(6);
    // allocate the memory for the document
    StaticJsonDocument<1000> tagsDoc;
    // parse a JSON array
    String serialisedTagsArray = "[[\"p\",\"" + String(recipientPubKeyHex) + "\"]]";
    _logToSerialWithTitle("serialisedTagsArray is: ", serialisedTagsArray);
    deserializeJson(tagsDoc, serialisedTagsArray);

    // size_t docSize = estimateNoteIdJsonDocumentSize(pubKeyHex, encryptedMessageWithIv);
    StaticJsonDocument<2000> doc;



    JsonArray data = doc.createNestedArray("data");

    data.add(0);
    data.add(pubKeyHex);
    data.add(timestamp);
    data.add(4);
    data.add(tagsDoc);
    data.add(encryptedMessageWithIv);

    // :61 stringify event to message var
    String message;
    serializeJson(doc["data"], message);
    _logToSerialWithTitle("message is: ", String(message));

    doc.clear();
    return message;
}

size_t NostrEvent::estimateNoteIdJsonDocumentSize(const char* pubKeyHex, const String& content) {
    // calculate sizes for the individual elements
    size_t sizeOfPubKeyHex = strlen(pubKeyHex) + 1; // +1 for null terminator
    size_t sizeOfContent = content.length() + 1; // +1 for null terminator

    // estimate the size of the document
    size_t estimatedSize =
        JSON_ARRAY_SIZE(6) + // main array with 6 elements
        JSON_ARRAY_SIZE(0) + // nested empty array
        2 * JSON_OBJECT_SIZE(1) + // 2 integers/longs
        JSON_STRING_SIZE(sizeOfPubKeyHex) + // size of pubKeyHex
        JSON_STRING_SIZE(sizeOfContent); // size of content

    // add some extra space to be safe
    estimatedSize += 256; 

    return estimatedSize;
}

size_t NostrEvent::estimateFullNoteJsonDocumentSize(const String& noteId, const String& pubKeyHex, 
                                const String& content, const String& signature) {
    // calculate sizes for the individual elements
    size_t sizeOfNoteId = noteId.length() + 1; // +1 for null terminator
    size_t sizeOfPubKeyHex = pubKeyHex.length() + 1; 
    size_t sizeOfContent = content.length() + 1; 
    size_t sizeOfSignature = signature.length() + 1;

    // estimate the size of the document
    size_t estimatedSize =
        JSON_OBJECT_SIZE(7) + // main object with 7 elements
        JSON_ARRAY_SIZE(1) + // nested array with 1 element
        JSON_STRING_SIZE(sizeOfNoteId) + 
        JSON_STRING_SIZE(sizeOfPubKeyHex) + 
        JSON_STRING_SIZE(sizeOfContent) +
        JSON_STRING_SIZE(sizeOfSignature) + 
        JSON_STRING_SIZE(10) + // 'created_at' - Long value as string
        JSON_STRING_SIZE(1); // 'kind' - Integer value as string

    // add some extra space to be safe
    estimatedSize += 256;

    return estimatedSize;
}

SchnorrSignature NostrEvent::getSignature(char const *privateKeyHex, String noteId) {
        // Create the private key object
    int byteSize =  32;
    byte privateKeyBytes[byteSize];
    fromHex(privateKeyHex, privateKeyBytes, byteSize);
    PrivateKey privateKey(privateKeyBytes);

    // Generate the schnorr sig of the messageHash
    byte messageBytes[byteSize];
    fromHex(noteId, messageBytes, byteSize);
    SchnorrSignature signature = privateKey.schnorr_sign(messageBytes);

    // Device the public key and verify the schnorr sig is valid
    PublicKey pub = privateKey.publicKey();

    if(pub.schnorr_verify(signature, messageBytes)) {
        Serial.println("All good, signature is valid");
    } else {
        Serial.println("Something went wrong, signature is invalid");
    }
    return signature;
}

std::array<uint8_t, 16> NostrEvent::getRandomIv() {
#ifdef UNIT_TEST
    // If unit testing generate a static iv
    std::array<uint8_t, 16> iv = {0x00, 0x01, 0x02, 0x03, 0x04, 0x05,
                                  0x06, 0x07, 0x08, 0x09, 0x0A, 0x0B,
                                  0x0C, 0x0D, 0x0E, 0x0F};
    return iv;
#else
    esp_wifi_start();
    std::array<uint8_t, 16> iv;
    for (auto& i : iv) {
        i = esp_random() % 256;
    }
    return iv;
#endif
}