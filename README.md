# CcipherFactory

CcipherFactory is the library that encapsulated all related parameters for a specific set of a cryptographic algorithms for operational requirement.

Cryptographic algorithms mostly have some parameters which are configurable during a specific operation. For example for AES encryption, there are different _modes_ and an _iv_ that could be provided by the caller application (or the _iv_ could be generated internally). The same value is required during decryption however, which is expected that the same _iv_ and _mode_ info is to be used during decryption or the decryption shall failed. 

Normally those parameters are pre-selected by application, like AES with key size 256 bits and GCM mode. However this resulted in a cryptosystem that is rigid because those selection will be likely hard coded and when there is a broken algorithm come into light by researcher for example, or any reasons that a mode is more preferable than the pre-selected mode, the crypto system will requires update and testing. By this time, there is likely also a higher level of applications already has some assumption about the cipher text and once some parameters changed, it might affect those application too. 

If the application has provision of the dynamicity of the cryptographic algorithms, those pre-selected parameters shall be stored in external files such as xml/yaml/text/database or anything that make sense. However, we think that a binaray coding is a more appropriate way to deliver the purpose since the cipher text is mostly a set of binary data.

Therefore the library upon signing/encryption cryptographic call, shall produce two outputs: the cipher text and the header.

The header is basically binary encoded structure of the cryptographic parameters. The cipher text is the actual output of the cryptographic algorithm.

During the reverse operations : verification / decryption, both pieces of the data shall be needed to be passed into the library in order for the operation to be successful.

Currently the supported algorithms including:
* Symmetric key
  * Key generation / derivation from password
  * Signing / verification (attached / detached)
  * Encrypt / decrypt (attached / detached) with zlib compression option
* Asymmetric key (currently ECC only)
  * Keypair generation
  * Signing / verification (attached / detached)
  * Encrypt / decryption (attached / detached) with zlib compression option
* Digest
* Key derivation function
  * scrypt
  * hkdf
* Shamir secret sharing 


## Attached vs. Detached

Attached mode is where the final output is the combination of the header and the cipher text. Therefore there is no separate storage required for the header and cipher text, instead a single file is what is needed for the cryptographic operation to operate.

However, in the event that the combined output is not preferable, the application can store the header and cipher text in any location as wished and pass into the library whenever it is requested. 

Note that there is no implicit linkage info between the header and the cipher text is generated for detached mode. It means that the library has no way to check if the header is corresponding to the cipher text being processed and if there is a mixed up, recursive way is the only way to see if the header is correct with the help of the correct key material.


## Actual Supported Cryptographic Algorithms

The actual supported cryptographic algorithms such as for symmetric, asymmetric etc is depending on the underlying cryptographic API. The project is integrated with [ccrypto](https://github.com/cameronian/ccrypto) which normalized the cryptographic API between Ruby and Java runtime.

At CcipherFactory effort has been done to tag as much algorithms as supported by the Ccrypto libraries implemented runtime as possible, which the tagging is done inside lib/ccipher\_factory/encoding/binenc\_constant.rb and its binary structure is defined in lib/ccipher\_factory/encoding/bin\_struct.rb


## Installation

Add this line to your application's Gemfile:

```ruby
# pre-requisite
gem 'ccrypto'

# if Ruby runtime
gem 'ccrypto-ruby'
# if Java runtime
#gem 'ccrypto-java'

# then include this
gem 'ccipher_factory'
```

And then execute:

    $ bundle install

Or install it yourself as:

    $ gem install ccipher_factory


## Usage Examples

Refers to files inside directory spec/ for more usage examples



