defmodule COSETest do
  use ExUnit.Case
  doctest COSE
  alias COSE.{Keys, Headers, Messages}
  alias Messages.{Sign1, Encrypt, PartyInfo, SuppPubInfo, Recipient, ContextKDF}

  test "generate okp keys" do
    assert Keys.OKP.generate(:enc).kty == :okp
    assert Keys.OKP.generate(:enc).crv == :x25519
    assert Keys.OKP.generate(:sig).crv == :ed25519
  end

  describe "headers" do
    test "encode" do
      assert Headers.translate(%{alg: :eddsa}) == %{1 => -8}
      assert Headers.translate(%{alg: :aes_ccm_16_64_128}) == %{1 => 10}

      assert Headers.translate(%{1 => -8}) == %{alg: :eddsa}

      assert Headers.tag_phdr(%{alg: :eddsa}) == COSE.tag_as_byte(<<0xA1, 0x01, 0x27>>)
      phdr = Headers.tag_phdr(%{alg: :eddsa})
      assert Headers.decode_phdr(phdr) == %{alg: :eddsa}
    end
  end

  describe "sign1 message" do
    setup do
      key = Keys.OKP.generate(:sig)

      d = Base.decode16!("8437C5D1CB4DE744B33B23A943644268A2CC0F11AF66953F74BAB8B395AFCC21")
      x = Base.decode16!("0D89C5C34501D85E9D23EDBFF932AA85B660100C3534D98F8A0722C992D8B324")
      key = Map.put(key, :d, d) |> Map.put(:x, x)

      msg = Sign1.build("content to sign", %{alg: :eddsa})
      {:ok, %{key: key, msg: msg}}
    end

    test "sign", %{key: key, msg: msg} do
      msg = Sign1.sign(msg, key)
      assert Sign1.verify(msg, key)

      # alter signature
      <<_::binary-size(3)>> <> tmp = msg.signature.value
      altered_signature = "aaa" <> tmp
      altered_msg = Map.put(msg, :signature, COSE.tag_as_byte(altered_signature))
      refute Sign1.verify(altered_msg, key)
    end

    test "encode", %{key: key, msg: msg} do
      encoded_msg = Sign1.encode(msg, key)
      decoded_msg = Sign1.decode(encoded_msg, key)
      assert decoded_msg == Sign1.sign(msg, key)
    end
  end

  describe "enc message" do
    setup do
      sender_key = Keys.OKP.generate(:enc)
      receiver_key = Keys.OKP.generate(:enc)

      recipient = %Recipient{phdr: %{alg: :ecdh_ss_hkdf_256}}
      u = %PartyInfo{}
      v = %PartyInfo{}
      s = %SuppPubInfo{key_data_length: 128, protected: Headers.tag_phdr(recipient.phdr)}
      context = ContextKDF.build(:aes_ccm_16_64_128, u, v, s)

      msg_phdr = %{alg: :aes_ccm_16_64_128}
      msg_uhdr = %{iv: <<222, 100, 52, 107, 249, 208, 239, 101, 73, 73, 196, 224>>}
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

      alg = COSE.algorithm(:aes_ccm_16_64_128)
      context = ContextKDF.build(:aes_ccm_16_64_128, %PartyInfo{nonce: <<1>>}, %PartyInfo{}, s)

      assert [^alg, [nil, <<1>>, nil], [nil, nil, nil], [128, %CBOR.Tag{}]] =
               ContextKDF.encode(context)
    end

    test "encrypt message", %{
      msg: msg,
      sender_key: sender_key,
      receiver_key: receiver_key,
      # recipient: recipient,
      context: context
    } do
      kek_bytes = Recipient.derive_kek(sender_key, receiver_key, context)
      assert byte_size(kek_bytes) == 16

      cek = %Keys.Symmetric{k: kek_bytes, alg: :aes_ccm_16_64_128}
      # kek = %Keys.Symmetric{k: kek_bytes, alg: :direct}

      Encrypt.encrypt(msg, cek, msg.uhdr.iv)
    end

    # test "encrypt", %{sender_key: sender_key, receiver_key: receiver_key, recipient: recipient, msg: msg} do
    #   enc_msg = Encrypt.encrypt(msg, sender_key, receiver_key)
    #   dec_msg Encrypt.decrypt(msg, sender_key, receiver_key)
    # end
  end
end
