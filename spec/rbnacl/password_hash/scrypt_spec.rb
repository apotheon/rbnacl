# encoding: binary
require 'spec_helper'

describe RbNaCl::PasswordHash::SCrypt do
  let(:reference_password) { RbNaCl::TestVectors[:scrypt_password] }
  let(:reference_salt)     { RbNaCl::TestVectors[:scrypt_salt] }
  let(:reference_N)        { RbNaCl::TestVectors[:scrypt_N] }
  let(:reference_r)        { RbNaCl::TestVectors[:scrypt_r] }
  let(:reference_p)        { RbNaCl::TestVectors[:scrypt_p] }
  let(:reference_digest)   { vector :scrypt_digest }

  it "calculates the correct diest for a reference password/salt" do
    digest = RbNaCl::PasswordHash.scrypt(
      reference_password,
      reference_salt,
      reference_N,
      reference_r,
      reference_p
    )

    expect(digest).to eq reference_digest
  end
end
