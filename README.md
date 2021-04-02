# COSE

CBOR Object Signing and Encryption (COSE) [[RFC8152]](https://tools.ietf.org/html/rfc8152) in Elixir.

Currently supports:

- `Sign1` messages with algorithm `eddsa`
- `Encrypt` messages with algorithm `ecdh_ss_hkdf_256` and key `x25519`

Additionally, there is some support for CBOR Web Tokens (`CWT`) [[RFC8392]](https://tools.ietf.org/html/rfc8392).

## Installation

Add `cose` to your list of dependencies in `mix.exs`:

```elixir
def deps do
  [
    {:cose, git: "https://github.com/geonnave/cose-elixir.git"}
  ]
end
```

# Usage

## Sign message for one recipient:

```elixir
alias COSE.{Messages, Keys}

key = Keys.OKP.generate(:sig)
msg = Messages.Sign1.build("content to sign", %{alg: :eddsa})

# sign and COSE-encode
encoded_msg = Messages.Sign1.sign_encode(msg, key)

# COSE-decode to obtain parameters (e.g. key used) + verify signature
decoded_msg = Messages.Sign1.decode(encoded_msg)
verified_msg = Messages.Sign1.verify(decoded_msg, key)
```

## Encrypt message using static-static key agreement and AES

```elixir
alias COSE.{Keys, Headers, Messages}

# generate keys
sender_key = Keys.OKP.generate(:enc)
receiver_key = Keys.OKP.generate(:enc)

# create recipient metadata
recipient = %Messages.Recipient{phdr: %{alg: :ecdh_ss_hkdf_256}}
s = %Messages.SuppPubInfo{key_data_length: 128, protected: Headers.tag_phdr(recipient.phdr)}
context = Messages.ContextKDF.build(:aes_ccm_16_64_128, %Messages.PartyInfo{}, %Messages.PartyInfo{}, s)

# create content-encryption key (same as key-encryption key, as we are using a `direct` algorithm)
kek_bytes = Messages.Recipient.derive_kek(sender_key, receiver_key, context)
cek = %Keys.Symmetric{k: kek_bytes, alg: :aes_ccm_16_64_128}

# prepare message
msg_phdr = %{alg: :aes_ccm_16_64_128}
msg_uhdr = %{iv: COSE.tag_as_byte(:crypto.strong_rand_bytes(12))}
msg = Messages.Encrypt.build("content to encrypt", recipient, msg_phdr, msg_uhdr)

# encrypt + COSE-encode
encoded_msg = Messages.Encrypt.encrypt_encode(msg, cek, msg.uhdr.iv.value)

# COSE-decode to obtain parameters (headers, recipients, etc.) + decrypt
decoded_msg = Messages.Encrypt.decode(encoded_msg)
{:ok, decrypted_msg} = Messages.Encrypt.decrypt(decoded_msg, cek, decoded_msg.uhdr.iv.value)
```

## Issue and verify CBOR Web Token with digital signature

```elixir
alias COSE.{Messages, Keys, CWT}

key = Keys.OKP.generate(:sig)

# create claims, including claims that are application-specific
claims = %{
  expiration: (DateTime.utc_now() |> DateTime.to_unix()) + 60, # one minute
  issuer: "alice",
  subject: "bob",
  custom_claim: "this claim is application-specific",
}
custom_claims = %{custom_claim: 22}

# encode + sign, verify + decode
encoded_token = CWT.sign_encode(claims, key, custom_claims)
verified_token = CWT.verify_decode(encoded_token, key, custom_claims)
```