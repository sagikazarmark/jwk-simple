{ pkgs, ... }:

{
  cachix.pull = [ "sagikazarmark-dev" ];

  dotenv.enable = true;

  env = {
    CC_wasm32_unknown_unknown = "${pkgs.llvmPackages.clang-unwrapped}/bin/clang";
  };

  packages = with pkgs; [
    cargo-release
    cargo-watch
    cargo-expand
    wasm-bindgen-cli
  ];

  languages.rust = {
    enable = true;
    channel = "stable";
    targets = [ "wasm32-unknown-unknown" ];
  };
}
