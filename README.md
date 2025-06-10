# CBC
CBC_Encryption is a C library that provides functionalities to encrypt and decrypt data using the Cipher Block Chaining (CBC) mode of operation. 
- This library is designed for educational purposes and provides a straightforward interface for encrypting and decrypting text using symmetric key encryption.

## Features
- Encrypt data using the AES algorithm in CBC mode.
- Decrypt data that was encrypted using the AES algorithm in CBC mode.
- Generate a random initialization vector (IV) for each encryption.
- Handle linked list structures for efficient data manipulation.
- Read data from and write data to files.

## Installation
- To use the CBC_Encryption library, you need to compile it from source.
- Ensure you have OpenSSL installed on your system as this library depends on OpenSSL for cryptographic operations.

### Compiling the Library
- Clone the repository:

- git clone [https://github.com/Abdelali-Saaid/CBC_Encryption.git]
- cd CBC_Encryption

### Compile the library:

- gcc -o cbc_encrypt main.c ../src/cbc.c ../src/fileio.c ../src/linkedlist.c -lcrypto

## Usage
Below is an example of how to use the CBC_Encryption library for encryption and decryption.

- Importing the Necessary Headers
- Functions
- readFile
Reads data from a file and stores it in a linked list.

- writeFile
Writes the linked list data to a file.

- displayList
Displays the data in the linked list.

- createNode
Creates a new node with the given data.

- encryptBlock
Encrypts a block of data using the CBC mode.

## License


## Acknowledgments
- This library uses the OpenSSL library for cryptographic operations. 
- For more information about OpenSSL, visit https://www.openssl.org.

## Contributing
If you would like to contribute to this project, please fork the repository and submit a pull request.

## Contact
For any questions or feedback, please contact me.
