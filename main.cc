#include "build/_deps/sodium-src/libsodium/src/libsodium/crypto_pwhash/argon2/argon2-encoding.h"
#include "sodium/crypto_box.h"
#include <CLI/CLI.hpp>
#include <SQLiteCpp/SQLiteCpp.h>
#include <algorithm>
#include <cstdlib>
#include <iostream>
#include <ranges>
#include <sodium.h>
#include <string_view>
#include <unordered_map>

#include "wordlist.hh"

/**
 * Helper that prints a prompt and reads a line in response.
 */
std::string get_line(std::string_view prompt)
{
	std::cout << prompt << std::endl;
	std::string result;
	std::getline(std::cin, result);
	std::cout << std::endl;
	return result;
}

/**
 * Helper that exits the program with an error message if a condition is not
 * true.
 */
void require(bool condition, std::string_view errorMessage)
{
	if (!condition)
	{
		std::cerr << errorMessage << std::endl;
		exit(EXIT_FAILURE);
	}
}

/**
 * Helper that translates a string view containing words from the word list
 * into a vector of bytes.
 */
std::vector<uint8_t> decode_text(std::string_view humanText)
{
	static auto reverseMap = []() {
		std::unordered_map<std::string_view, uint16_t> rm;
		for (int i = 0; i < 0x10000; i++)
		{
			rm[wordList.at(i)] = i;
		}
		return rm;
	}();
	std::vector<uint8_t> result;
	for (const auto word : std::views::split(humanText, ' '))
	{
		uint16_t bytes = reverseMap[std::string_view{word.data(), word.size()}];
		result.push_back(bytes >> 8);
		result.push_back(bytes & 0xff);
	}
	return result;
}

/**
 * Helper that encodes a collection of bytes into a string of human-readable
 * text.
 */
template<typename T>
std::string encode_text(const T &bytes)
{
	require(bytes.size() % 2 == 0,
	        "Encoded text must be padded to a multiple of two");
	std::string result;
	for (auto b = bytes.begin(), e = bytes.end(); b != e; ++b)
	{
		uint16_t bytes = uint16_t(*b) << 8;
		++b;
		bytes += *b;
		result += wordList[bytes];
		result += ' ';
	}
	return result;
}

using PublicKey = std::array<unsigned char, crypto_box_PUBLICKEYBYTES>;
using SecretKey = std::array<unsigned char, crypto_box_SECRETKEYBYTES>;

int main(int argc, char **argv)
{
	std::string                user;
	std::optional<std::string> passphraseFile;
	bool                       decrypt{false};
	// Parse some basic command-line arguments
	CLI::App app;
	app.add_option("-u", user, "The name of the remote user")->required();
	app.add_flag("-d", decrypt, "Decrypt a message (default is to encrypt)");
	app.add_option("-k", passphraseFile, "File containing your passphrase");
	CLI11_PARSE(app, argc, argv);

	// Read the passphrase from either a file or from 
	std::string passphrase;
	if (passphraseFile)
	{
		std::ifstream      file{*passphraseFile, std::ios::binary};
		std::ostringstream sstr;
		sstr << file.rdbuf();
		passphrase = sstr.str();
	}
	else
	{
		passphrase = get_line("Please enter your passphrase");
	}
	require(passphrase.size() >= crypto_pwhash_BYTES_MIN,
	        "Passphrase is too short");

	// Initialise libsodium
	if (sodium_init() == -1)
	{
		exit(EXIT_FAILURE);
	}

	// Derive a root secret from the passphrase
	std::array<unsigned char, crypto_box_SEEDBYTES> keySeed;
	const unsigned char salt[] = "this doens't have to be random";
	static_assert(sizeof(salt) >= crypto_pwhash_SALTBYTES);
	require(crypto_pwhash(keySeed.data(),
	                      keySeed.size(),
	                      passphrase.data(),
	                      passphrase.size(),
	                      salt,
	                      crypto_pwhash_OPSLIMIT_MODERATE,
	                      crypto_pwhash_MEMLIMIT_MODERATE,
	                      crypto_pwhash_ALG_ARGON2ID13) == 0,
	        "Failed to derive key from passphrase");

	// Derive a key pair from the secret.
	SecretKey secretKey;
	PublicKey publicKey;
	require(crypto_box_seed_keypair(
	          publicKey.data(), secretKey.data(), keySeed.data()) == 0,
	        "Failed to construct public key pair");

	// Open the database for storing other users' public keys
	SQLite::Database db("keys.sqlite3",
	                    SQLite::OPEN_READWRITE | SQLite::OPEN_CREATE);
	db.exec(
	  "CREATE TABLE IF NOT EXISTS keys (user TEXT PRIMARY KEY, key BLOB)");

	// Look up the key for this user
	SQLite::Statement query(db, "SELECT key FROM keys WHERE user == ?");
	query.bind(1, user);
	PublicKey otherUsersPublicKey;
	// If we found it, use it.
	if (query.executeStep())
	{
		std::string keyBytes = query.getColumn(0);
		std::copy(
		  keyBytes.begin(), keyBytes.end(), otherUsersPublicKey.begin());
	}
	else
	{
		// Ask for the key and trust on first use
		std::cout << "You have not exchanged keys with this user.  You must "
		             "send them your public key:\n"
		          << encode_text(publicKey) << std::endl;
		std::string encodedKey = get_line("Please enter their key:");
		auto        key        = decode_text(encodedKey);
		std::copy(key.begin(), key.end(), otherUsersPublicKey.begin());
		SQLite::Statement insert(db,
		                         "INSERT INTO keys (user, key) VALUES (?, ?)");
		insert.bind(1, user);
		insert.bind(2, key.data(), key.size());
		insert.executeStep();
	}

	if (!decrypt)
	{
		std::array<unsigned char, crypto_box_NONCEBYTES> nonce;
		randombytes_buf(nonce.data(), nonce.size());
		std::string plainText =
		  get_line("Please enter the message to encrypt:");
		// Pad to a multiple of two bytes
		if (plainText.size() % 2)
		{
			plainText += ' ';
		}
		std::vector<unsigned char> cypherText;
		cypherText.resize(plainText.size() + crypto_box_MACBYTES);
		require(crypto_box_easy(
		          cypherText.data(),
		          reinterpret_cast<const unsigned char *>(plainText.data()),
		          plainText.size(),
		          nonce.data(),
		          otherUsersPublicKey.data(),
		          secretKey.data()) == 0,
		        "Encryption failed");
		std::cout << "Send the following message to the other person:\n"
		          << encode_text(nonce) << encode_text(cypherText) << std::endl;
	}
	else
	{
		std::string humanReadableCypherText =
		  get_line("Please enter the message to decrypt:");
		auto cypherTextAndNonce = decode_text(humanReadableCypherText);
		require(cypherTextAndNonce.size() >
		          crypto_box_NONCEBYTES + crypto_box_MACBYTES,
		        "Message is too short");
		std::vector<unsigned char> plainText;
		plainText.resize(cypherTextAndNonce.size() -
		                 (crypto_box_NONCEBYTES + crypto_box_MACBYTES));
		require(crypto_box_open_easy(
		          plainText.data(),
		          cypherTextAndNonce.data() + crypto_box_NONCEBYTES,
		          cypherTextAndNonce.size() - crypto_box_NONCEBYTES,
		          cypherTextAndNonce.data(),
		          otherUsersPublicKey.data(),
		          secretKey.data()) == 0,
		        "Decryption failed");
		std::cout << "Decrypted message:\n"
		          << std::string_view{reinterpret_cast<const char *>(
		                                plainText.data()),
		                              plainText.size()}
		          << std::endl;
	}
}
