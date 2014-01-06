# encoding: binary
module RbNaCl
  module PasswordHash
    # The scrypt sequential memory hard password hashing function
    #
    # scrypt is a password hash (or password based KDF). That is to say, where
    # most hash functions are designed to be fast because hashing is often a
    # bottleneck, scrypt is slow by design, because it's trying to "strengthen"
    # the password by combining it with a random "salt" value then perform a
    # series of operation on the result which are slow enough to defeat
    # brute-force password cracking attempts.
    #
    # scrypt is similar to the bcrypt and pbkdf2 password hashes in that it's
    # designed to strengthen passwords, but includes a new design element
    # called "sequential memory hardness" which helps defeat attempts by
    # attackers to compensate for their lack of memory (since they're typically
    # on GPUs or FPGAs) with additional computation.
    class SCrypt
      extend Sodium

      sodium_type      :pwhash
      sodium_primitive :scryptxsalsa208sha256

      # TODO: not available yet
      #sodium_constant  :BYTES_MIN
      #sodium_constant  :BYTES_MAX

      sodium_function  :scrypt,
                       :crypto_scrypt,
                       [:pointer, :ulong_long, :pointer, :ulong_long, :uint64, :uint32, :uint32, :pointer, :ulong_long]

      # Create a new SCrypt password hash object
      #
      # @param [Integer] n the CPU cost (e.g. 2**20)
      # @param [Integer] r the memory cost (e.g. 8)
      # @param [Integer] p the parallelization cost (e.g. 1)
      #
      # @return [RbNaCl::PasswordHash::SCrypt] An SCrypt password hasher object
      def initialize(n, r, p, digest_size = 64)
        # TODO: check values of n, r, and p
        @n, @r, @p = n, r, p

        @digest_size = digest_size

        # TODO: check digest size validity
        #raise LengthError, "digest size too short" if @digest_size < BYTES_MIN
        #raise LengthError, "digest size too long"  if @digest_size > BYTES_MAX
      end

      # Calculate an scrypt digest for a given password and salt
      #
      # @param [String] password to be hashed
      # @param [String] salt to make the digest unique
      #
      # @return [String] scrypt digest of the string as raw bytes
      def digest(password, salt)
        digest = Util.zeros(@digest_size)
        self.class.scrypt(password, password.bytesize, salt, salt.bytesize, @n, @r, @p, digest, @digest_size) || raise(CryptoError, "scrypt failed!")
        digest
      end
    end
  end
end
