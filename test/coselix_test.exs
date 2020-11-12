defmodule CoselixTest do
  use ExUnit.Case
  doctest Coselix

  test "generate okp keys" do
    assert Coselix.Keys.OKP.generate(:enc).kty == Coselix.key_type(:okp)
    assert Coselix.Keys.OKP.generate(:enc).crv == Coselix.curve(:x25519)
    assert Coselix.Keys.OKP.generate(:sig).crv == Coselix.curve(:ed25519)
  end

  describe "sign1 message" do
    setup do
        key = Coselix.Keys.OKP.generate(:sig)
        msg = Coselix.Messages.Sign1.build("content to sign")
        {:ok, %{key: key, msg: msg}}
    end

    test "sign", %{key: key, msg: msg} do
        msg = Coselix.Messages.Sign1.sign(msg, key)
        assert Coselix.Messages.Sign1.verify(msg, key)

        # alter signature
        <<_::binary-size(3)>> <> tmp = msg.signature
        altered_signature = "aaa" <> tmp
        altered_msg = Map.put(msg, :signature, altered_signature)
        refute Coselix.Messages.Sign1.verify(altered_msg, key)
    end

    test "encode", %{key: key, msg: msg} do
        msg = Coselix.Messages.Sign1.sign(msg, key)
        encoded_msg = Coselix.Messages.Sign1.encode(msg, key)
        decoded_msg = Coselix.Messages.Sign1.decode(encoded_msg, key)
        assert decoded_msg == msg
    end
  end
end
