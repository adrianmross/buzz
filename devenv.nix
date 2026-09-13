{ pkgs, lib, ... }:

# Nix alternative to the Hermit toolchain in bin/ (same pins: node 24, pnpm 11,
# rust from rust-toolchain.toml, cmake, just). `just`, `pnpm`, `cargo` and
# `pnpm tauri ...` (Tauri CLI comes from @tauri-apps/cli in desktop/) all work
# from this shell; the Docker services for the relay are still `just setup`.
{
  languages.javascript = {
    enable = true;
    package = pkgs.nodejs_24;
    pnpm = {
      enable = true;
      package = pkgs.pnpm_11.override { nodejs = pkgs.nodejs_24; };
    };
  };

  languages.rust = {
    enable = true;
    toolchainFile = ./rust-toolchain.toml;
  };

  packages = with pkgs; [
    git
    just
    jq
    curl
    cmake # audiopus_sys / sherpa-onnx build scripts
    pkg-config
  ] ++ lib.optionals stdenv.isDarwin [ libiconv ];
}
