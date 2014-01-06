# encoding: binary
module RbNaCl
  # Password hashing functions
  #
  # These hash functions are designed specifically for the purposes of securely
  # storing passwords in a way that they can be checked against a supplied
  # password but an attacker who obtains a hash cannot easily reverse them back
  # into the original password.
  #
  # Unlike normal hash functions, which are intentionally designed to hash data
  # as quickly as they can while remaining secure, password hashing functions
  # are intentionally designed to be slow so they are hard for attackers to
  # brute force.
  #
  # All password hashing functions take a "salt" value which should be randomly
  # generated on a per-password basis (using RbNaCl::Random, accept no
  # subsitutes)
  #
  # All of them also take a CPU work factor, which increases the amount of
  # computation needed to produce the digest.
  module PasswordHash
    # scrypt: the original sequential memory hard password hashing function.
    # This is also the only password hashing function supported by libsodium,
    # but that's okay, because it's pretty awesome.
    #
    # @param [String] password to be hashed
    # @param [String] salt to make the digest unique
    # @param [Integer] n the CPU cost (e.g. 2**20)
    # @param [Integer] r the memory cost (e.g. 8)
    # @param [Integer] p the parallelization cost (e.g. 1)
    # @param [Integer] digest_size of the output
    #
    # @raise [CryptoError] If calculating the digest fails for some reason.
    #
    # @return [String] The scrypt digest as raw bytes
    def self.scrypt(password, salt, n, r, p, digest_size = 64)
      SCrypt.new(n, r, p, digest_size).digest(password, salt)
    end

    # Returns the Blake2b hash of the given data
    #
    # There's no streaming done, just pass in the data and be done with it.
    # This method returns a 64-byte hash by default.
    #
    # @param [String] data The data, as a collection of bytes
    # @option options [Fixnum] digest_size Size in bytes (1-64, default 64)
    # @option options [String] key 64-byte (or less) key for keyed mode
    #
    # @raise [CryptoError] If the hashing fails for some reason.
    #
    # @return [String] The blake2b hash as raw bytes (Or encoded as per the second argument)
    def self.blake2b(data, options = {})
      key         = options[:key]
      Blake2b.new(options).digest(data)
    end
  end
end
