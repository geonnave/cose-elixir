defmodule COSE.CWT do
  alias COSE.Messages.{Sign1}

  @spec_claims %{
    issuer: 1,
    subject: 2,
    audience: 3,
    expiration: 4,
    not_before: 5,
    issued_at: 6,
    token_id: 7
  }

  def setup_dates(claims) do
    one_year = 60 * 60 * 24 * 365
    claims = if claims[:expiration], do: claims, else: Map.put(claims, :expiration, one_year)
    Map.put(claims, :issued_at, DateTime.to_unix(DateTime.utc_now()))
  end

  def encode_claim_names(claims, custom_claims \\ %{}) do
    claims
    |> Enum.map(fn {name, value} ->
      key =
        case @spec_claims[name] do
          key when is_integer(key) ->
            key

          _ ->
            custom_claims[name] || name
        end

      {key, value}
    end)
    |> Enum.into(%{})
  end

  def sign_encode(claims, key, custom_claims \\ %{}) do
    claims
    |> setup_dates()
    |> encode_claim_names(custom_claims)
    |> CBOR.encode()
    |> Sign1.build(%{alg: :eddsa})
    |> Sign1.sign_encode(key)
  end

  def decode_claim_names(claims, custom_claims \\ %{}) do
    claims
    |> Enum.map(fn {key, value} ->
      name =
        case invert_map(@spec_claims)[key] do
          name when not is_nil(name) ->
            name

          _ ->
            invert_map(custom_claims)[key] || key
        end

      {name, value}
    end)
    |> Enum.into(%{})
  end

  def invert_map(map) do
    Map.new(map, fn {key, val} -> {val, key} end)
  end

  def verify_decode(token, key, custom_claims \\ %{}) do
    if verified_msg = Sign1.verify_decode(token, key) do
      {:ok, cbor_claims, ""} = CBOR.decode(verified_msg.payload.value)

      cbor_claims
      |> decode_claim_names(custom_claims)
    end
  end

  def peek_claims(token, custom_claims \\ %{}) do
    msg = Sign1.decode(token)
    {:ok, cbor_claims, ""} = CBOR.decode(msg.payload.value)

    cbor_claims
    |> decode_claim_names(custom_claims)
  end
end
