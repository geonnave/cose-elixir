defmodule COSETest.CWT do
  use ExUnit.Case
  doctest COSE
  alias COSE.{Keys, CWT}

  describe "cbor web token" do
    setup do
      key = Keys.OKP.generate(:sig)

      d = Base.decode16!("8437C5D1CB4DE744B33B23A943644268A2CC0F11AF66953F74BAB8B395AFCC21")
      x = Base.decode16!("0D89C5C34501D85E9D23EDBFF932AA85B660100C3534D98F8A0722C992D8B324")
      key = Map.put(key, :d, d) |> Map.put(:x, x)

      claims = %{
        expiration: 1_615_898_871,
        issuer: "did:sw:SpUu2RxLDiz4TeupvSpTaB",
        subject: "did:sw:6v84ovgu4d9KPvPwHiBJWD"
      }

      {:ok, %{key: key, claims: claims}}
    end

    test "encode claims (convert to integer keys)", %{claims: claims} do
      assert %{4 => 1_615_898_871} = CWT.encode_claim_names(claims)

      claims = Map.put(claims, :custom_claim, "this claim is application-specific")
      assert %{:custom_claim => _value} = CWT.encode_claim_names(claims)

      custom_claims = %{custom_claim: 22}
      assert %{22 => _value} = CWT.encode_claim_names(claims, custom_claims)
    end

    test "decode claims (convert from integer keys)", %{claims: claims} do
      encoded = CWT.encode_claim_names(claims)

      assert %{:expiration => 1_615_898_871} = CWT.decode_claim_names(encoded)

      custom_claims = %{custom_claim: 22}
      claims = Map.put(claims, :custom_claim, "this claim is application-specific")

      encoded = CWT.encode_claim_names(claims, custom_claims)
      assert %{22 => _value} = CWT.decode_claim_names(encoded)
      assert %{:custom_claim => _value} = CWT.decode_claim_names(encoded, custom_claims)
    end

    test "encode token", %{key: key, claims: claims} do
      claims = Map.put(claims, :custom_claim, "this claim is application-specific")
      custom_claims = %{custom_claim: 22}

      token = CWT.sign_encode(claims, key, custom_claims)
      assert is_binary(token)
    end

    test "decode token", %{key: key, claims: claims} do
      token = CWT.sign_encode(claims, key)

      # remove `issued_at` since original claims do not have it
      retrived_claims = CWT.verify_decode(token, key) |> Map.delete(:issued_at)
      assert ^claims = retrived_claims
    end
  end
end
