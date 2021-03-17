defmodule COSE.MixProject do
  use Mix.Project

  def project do
    [
      app: :cose,
      version: "0.1.0",
      elixir: "~> 1.11",
      start_permanent: Mix.env() == :prod,
      deps: deps()
    ]
  end

  def application do
    [
      extra_applications: [:logger, :crypto]
    ]
  end

  defp deps do
    [
      {:b58, git: "https://github.com/dwyl/base58.git"},
      {:cbor, "~> 1.0.0"},
      {:hkdf_erlang, "~> 0.1.1"}
    ]
  end
end
