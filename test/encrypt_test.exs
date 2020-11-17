defmodule COSETest.Encrypt do
  use ExUnit.Case
  doctest COSE
  alias COSE.{Keys, Headers, Messages}
  alias Messages.{Encrypt, PartyInfo, SuppPubInfo, Recipient, ContextKDF}

  describe "enc message" do
    setup do
      d = Base.decode16!("2808973E40E487AECDE3C5516DDCDAD0A8DB7EFC3AE5E4F6378836EF2B336946")
      x = Base.decode16!("AF8D5A671C536E464844959CD4944F85BE733FDCEA4BAFDEA36283057C69DB4E")
      sender_key = Map.put(Keys.OKP.generate(:enc), :d, d) |> Map.put(:x, x)

      d = Base.decode16!("E04A21DF4537172DF1ECA8F8B40273ADCF7986C34F9F2236ECCA3B13C5036E77")
      x = Base.decode16!("49551EDFA9F0A56C8D196FC1685BE2976E0A10C91F29F758EADEFBA31BB5482E")
      receiver_key = Map.put(Keys.OKP.generate(:enc), :d, d) |> Map.put(:x, x)

      recipient = %Recipient{phdr: %{alg: :ecdh_ss_hkdf_256}}
      s = %SuppPubInfo{key_data_length: 128, protected: Headers.tag_phdr(recipient.phdr)}
      context = ContextKDF.build(:aes_ccm_16_64_128, %PartyInfo{}, %PartyInfo{}, s)

      msg_phdr = %{alg: :aes_ccm_16_64_128}
      msg_uhdr = %{iv: COSE.tag_as_byte(<<222, 100, 52, 107, 249, 208, 239, 101, 73, 73, 196, 224>>)}
      msg = Encrypt.build("content to encrypt", recipient, msg_phdr, msg_uhdr)

      {:ok,
       %{
         sender_key: sender_key,
         receiver_key: receiver_key,
         recipient: recipient,
         context: context,
         msg: msg
       }}
    end

    test "context encoding" do
      s = %SuppPubInfo{
        key_data_length: 128,
        protected: Headers.tag_phdr(%{alg: :ecdh_ss_hkdf_256})
      }

      context = ContextKDF.build(:aes_ccm_16_64_128, %PartyInfo{nonce: <<1>>}, %PartyInfo{}, s)

      alg = COSE.algorithm(:aes_ccm_16_64_128)

      assert [^alg, [nil, <<1>>, nil], [nil, nil, nil], [128, %CBOR.Tag{}]] =
               ContextKDF.encode(context)
    end

    test "recipient encoding" do
      recipient = %Recipient{phdr: %{alg: :ecdh_ss_hkdf_256}}
      assert [%CBOR.Tag{}, %{}, nil] = Recipient.encode(recipient)
    end

    test "encrypt message", %{
      msg: msg,
      sender_key: sender_key,
      receiver_key: receiver_key,
      # recipient: recipient,
      context: context
    } do
      # enc structure for aad
      assert ["Encrypt", %CBOR.Tag{}, %CBOR.Tag{value: <<>>}] = Encrypt.enc_structure(msg)

      # key derivation
      kek_bytes = Recipient.derive_kek(sender_key, receiver_key, context)
      assert byte_size(kek_bytes) == 16

      # encryption
      cek = %Keys.Symmetric{k: kek_bytes, alg: :aes_ccm_16_64_128}

      enc_msg = Encrypt.encrypt(msg, cek, msg.uhdr.iv.value)
      {:ok, dec_msg} = Encrypt.decrypt(enc_msg, cek, msg.uhdr.iv.value)
      assert msg.payload == dec_msg.payload

      # cbor encoding
      encoded_msg = Encrypt.encode_cbor(msg, cek, msg.uhdr.iv.value)
      encoded_msg |> Base.encode16() |> IO.inspect()

      decoded_msg = Encrypt.decode_cbor(encoded_msg) |> IO.inspect()
      [recp] = decoded_msg.recipients
      s = %SuppPubInfo{key_data_length: 128, protected: Headers.tag_phdr(recp.phdr)}
      ctx = ContextKDF.build(:aes_ccm_16_64_128, %PartyInfo{}, %PartyInfo{}, s)

      kek_bytes = Recipient.derive_kek(receiver_key, sender_key, ctx)
      cek = %Keys.Symmetric{k: kek_bytes, alg: :aes_ccm_16_64_128}

      {:ok, retrieved_msg} = Encrypt.decrypt(decoded_msg, cek, decoded_msg.uhdr.iv.value)
      assert retrieved_msg.payload == msg.payload
    end
  end
end
