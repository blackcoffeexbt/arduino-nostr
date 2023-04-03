# Summary

 Members                        | Descriptions                                
--------------------------------|---------------------------------------------
`class `[`NostrEvent`](#class_nostr_event) | 
`class `[`NostrQueueProcessor`](#class_nostr_queue_processor) | 
`class `[`NostrRelayManager`](#class_nostr_relay_manager) | 
`struct `[`AES_ctx`](#struct_a_e_s__ctx) | 

# class `NostrEvent` 

## Summary

 Members                        | Descriptions                                
--------------------------------|---------------------------------------------
`public  `[`NostrEvent`](#class_nostr_event_1ae162084a740f19dfb5dfa3ab71661a7c)`()` | 
`public String `[`getNote`](#class_nostr_event_1a65e97b1db4e42ac59c530740caa625c3)`(char const * privateKeyHex,char const * pubKeyHex,unsigned long timestamp,String content)` | Get a serialised string for a nostr note.
`public String `[`getEncryptedDm`](#class_nostr_event_1ace6112056f6927ed24661aef3fb3461c)`(char const * privateKeyHex,char const * pubKeyHex,char const * recipientPubKeyHex,unsigned long timestamp,String content)` | Get a serialised string for a nostr NIP04 encrypted DM.
`public String `[`decryptDm`](#class_nostr_event_1a6441af6cb16aabace626a4e164e5d5b5)`(const char * privateKeyHex,String serialisedJson)` | 
`public void `[`setLogging`](#class_nostr_event_1a50e8c3007be7db6fd485df82d639317b)`(bool loggingEnabled)` | Enable or disable verbose logging?

## Members

#### `public  `[`NostrEvent`](#class_nostr_event_1ae162084a740f19dfb5dfa3ab71661a7c)`()` 

#### `public String `[`getNote`](#class_nostr_event_1a65e97b1db4e42ac59c530740caa625c3)`(char const * privateKeyHex,char const * pubKeyHex,unsigned long timestamp,String content)` 

Get a serialised string for a nostr note.

#### Parameters
* `privateKeyHex` 

* `pubKeyHex` 

* `timestamp` 

* `content` 

#### Returns
String

#### `public String `[`getEncryptedDm`](#class_nostr_event_1ace6112056f6927ed24661aef3fb3461c)`(char const * privateKeyHex,char const * pubKeyHex,char const * recipientPubKeyHex,unsigned long timestamp,String content)` 

Get a serialised string for a nostr NIP04 encrypted DM.

#### Parameters
* `privateKeyHex` 

* `pubKeyHex` 

* `recipientPubKeyHex` 

* `timestamp` 

* `content` 

#### Returns
String

#### `public String `[`decryptDm`](#class_nostr_event_1a6441af6cb16aabace626a4e164e5d5b5)`(const char * privateKeyHex,String serialisedJson)` 

#### `public void `[`setLogging`](#class_nostr_event_1a50e8c3007be7db6fd485df82d639317b)`(bool loggingEnabled)` 

Enable or disable verbose logging?

#### Parameters
* `loggingEnabled`

# class `NostrQueueProcessor` 

## Summary

 Members                        | Descriptions                                
--------------------------------|---------------------------------------------
`public  `[`NostrQueueProcessor`](#class_nostr_queue_processor_1a6adf1c6851f697a88308763bc5852560)`()` | 
`public bool `[`isFull`](#class_nostr_queue_processor_1adb3ee62ccf8328397bf29bb890e18555)`() const` | 
`public bool `[`isEmpty`](#class_nostr_queue_processor_1a53d818796590fb061ad308fd926a490c)`() const` | 
`public void `[`enqueue`](#class_nostr_queue_processor_1a583a18bfc9da8d61d1b04ca1daaea34e)`(const char item)` | 
`public const char * `[`dequeue`](#class_nostr_queue_processor_1a78ce162cc118beb724dd745fa7b2278a)`()` | 
`public const char * `[`peekFront`](#class_nostr_queue_processor_1a55d1da3ce1b94c47f13148981bdc3b46)`() const` | 

## Members

#### `public  `[`NostrQueueProcessor`](#class_nostr_queue_processor_1a6adf1c6851f697a88308763bc5852560)`()` 

#### `public bool `[`isFull`](#class_nostr_queue_processor_1adb3ee62ccf8328397bf29bb890e18555)`() const` 

#### `public bool `[`isEmpty`](#class_nostr_queue_processor_1a53d818796590fb061ad308fd926a490c)`() const` 

#### `public void `[`enqueue`](#class_nostr_queue_processor_1a583a18bfc9da8d61d1b04ca1daaea34e)`(const char item)` 

#### `public const char * `[`dequeue`](#class_nostr_queue_processor_1a78ce162cc118beb724dd745fa7b2278a)`()` 

#### `public const char * `[`peekFront`](#class_nostr_queue_processor_1a55d1da3ce1b94c47f13148981bdc3b46)`() const` 

# class `NostrRelayManager` 

## Summary

 Members                        | Descriptions                                
--------------------------------|---------------------------------------------
`public  `[`NostrRelayManager`](#class_nostr_relay_manager_1af9ab52c07cd66b3839775b46af4fe4c0)`()` | 
`public void `[`setMinRelaysAndTimeout`](#class_nostr_relay_manager_1a4fc76b81c5086e63157b02687491fda9)`(int minRelays,unsigned long minRelaysTimeout)` | set minimum number of relays and a timeout for this minimum threshold. After this timeout is reached, the message will be broadcast regardless of the number of connected relays
`public void `[`subscribe`](#class_nostr_relay_manager_1a0e3ea54ae22c0420b16b9d8a68464e92)`(String subscriptionJson)` | 
`public void `[`setEventCallback`](#class_nostr_relay_manager_1aadc1eb331765ee4801c6f0b0a6ad77eb)`(const std::string & key,`[`EventCallbackFn`](#class_nostr_relay_manager_1a243e602247df139518bc792d602c8ca0)` callback)` | 
`public void `[`performEventAction`](#class_nostr_relay_manager_1a4fb7716262f75b6c28f165b82c58320f)`(const std::string & key,const char * payload)` | 
`public void `[`enqueueMessage`](#class_nostr_relay_manager_1abe3b960487e0db1ce5a5c0733e323f4e)`(const char item)` | 
`public bool `[`hasEnqueuedMessages`](#class_nostr_relay_manager_1a3ba8c67c7eeb12eaf333ebde2973ca9c)`()` | 
`public void `[`setRelays`](#class_nostr_relay_manager_1a482d1bd0544a6c83d94edc9c56e1185f)`(const char *const new_messages,int size)` | Set the relays to use.
`public void `[`printRelay`](#class_nostr_relay_manager_1a3dd7f690f689c07b28647cd48d921438)`(int index) const` | Print the relay at index: index.
`public void `[`connect`](#class_nostr_relay_manager_1a185daf2a0a8184f8fe10fbc1f7785d17)`(std::function< void(WStype_t, uint8_t *, size_t)> callback)` | Connect to all specified relays.
`public void `[`disconnect`](#class_nostr_relay_manager_1a8bffeb1a5b06f84ed28fa487d9c8eae0)`()` | 
`public void `[`broadcastEvent`](#class_nostr_relay_manager_1a86d9223f14b80529b87e57250bc94490)`(String serialisedEventJson)` | 
`public void `[`broadcastEvents`](#class_nostr_relay_manager_1a19792d96aebf797563b495c41b809335)`()` | Broadcasts messages in m_queue.
`public void `[`loop`](#class_nostr_relay_manager_1a7c6037751f6b8e3d4994d9c7f5e2f1a5)`()` | Keep all relays active.
`public String `[`getNewSubscriptionId`](#class_nostr_relay_manager_1a162f872051063fa354eb605f6d2e6485)`()` | 
`typedef `[`EventCallbackFn`](#class_nostr_relay_manager_1a243e602247df139518bc792d602c8ca0) | 
`typedef `[`EventCallbackMap`](#class_nostr_relay_manager_1a35c0886b3f7605dea0f2ab808e7ce9c1) | 

## Members

#### `public  `[`NostrRelayManager`](#class_nostr_relay_manager_1af9ab52c07cd66b3839775b46af4fe4c0)`()` 

#### `public void `[`setMinRelaysAndTimeout`](#class_nostr_relay_manager_1a4fc76b81c5086e63157b02687491fda9)`(int minRelays,unsigned long minRelaysTimeout)` 

set minimum number of relays and a timeout for this minimum threshold. After this timeout is reached, the message will be broadcast regardless of the number of connected relays

#### Parameters
* `minRelays` 

* `minRelaysTimeout` in milliseconds

#### `public void `[`subscribe`](#class_nostr_relay_manager_1a0e3ea54ae22c0420b16b9d8a68464e92)`(String subscriptionJson)` 

#### `public void `[`setEventCallback`](#class_nostr_relay_manager_1aadc1eb331765ee4801c6f0b0a6ad77eb)`(const std::string & key,`[`EventCallbackFn`](#class_nostr_relay_manager_1a243e602247df139518bc792d602c8ca0)` callback)` 

#### `public void `[`performEventAction`](#class_nostr_relay_manager_1a4fb7716262f75b6c28f165b82c58320f)`(const std::string & key,const char * payload)` 

#### `public void `[`enqueueMessage`](#class_nostr_relay_manager_1abe3b960487e0db1ce5a5c0733e323f4e)`(const char item)` 

#### `public bool `[`hasEnqueuedMessages`](#class_nostr_relay_manager_1a3ba8c67c7eeb12eaf333ebde2973ca9c)`()` 

#### `public void `[`setRelays`](#class_nostr_relay_manager_1a482d1bd0544a6c83d94edc9c56e1185f)`(const char *const new_messages,int size)` 

Set the relays to use.

#### Parameters
* `new_relays` 

* `size`

#### `public void `[`printRelay`](#class_nostr_relay_manager_1a3dd7f690f689c07b28647cd48d921438)`(int index) const` 

Print the relay at index: index.

#### Parameters
* `index`

#### `public void `[`connect`](#class_nostr_relay_manager_1a185daf2a0a8184f8fe10fbc1f7785d17)`(std::function< void(WStype_t, uint8_t *, size_t)> callback)` 

Connect to all specified relays.

#### Parameters
* `callback`

#### `public void `[`disconnect`](#class_nostr_relay_manager_1a8bffeb1a5b06f84ed28fa487d9c8eae0)`()` 

#### `public void `[`broadcastEvent`](#class_nostr_relay_manager_1a86d9223f14b80529b87e57250bc94490)`(String serialisedEventJson)` 

#### `public void `[`broadcastEvents`](#class_nostr_relay_manager_1a19792d96aebf797563b495c41b809335)`()` 

Broadcasts messages in m_queue.

#### `public void `[`loop`](#class_nostr_relay_manager_1a7c6037751f6b8e3d4994d9c7f5e2f1a5)`()` 

Keep all relays active.

#### `public String `[`getNewSubscriptionId`](#class_nostr_relay_manager_1a162f872051063fa354eb605f6d2e6485)`()` 

#### `typedef `[`EventCallbackFn`](#class_nostr_relay_manager_1a243e602247df139518bc792d602c8ca0) 

#### `typedef `[`EventCallbackMap`](#class_nostr_relay_manager_1a35c0886b3f7605dea0f2ab808e7ce9c1) 

# struct `AES_ctx` 

## Summary

 Members                        | Descriptions                                
--------------------------------|---------------------------------------------
`public uint8_t `[`RoundKey`](#struct_a_e_s__ctx_1aa475fe62fd5774891c7a42596f6d9c2e) | 
`public uint8_t `[`Iv`](#struct_a_e_s__ctx_1a1fa4921f7eeaca82eb974899edcdef3a) | 

## Members

#### `public uint8_t `[`RoundKey`](#struct_a_e_s__ctx_1aa475fe62fd5774891c7a42596f6d9c2e) 

#### `public uint8_t `[`Iv`](#struct_a_e_s__ctx_1a1fa4921f7eeaca82eb974899edcdef3a) 

Generated by [Moxygen](https://sourcey.com/moxygen)