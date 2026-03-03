{
  pkgs,
  inputs,
  ...
}:

{
  cachix.pull = [ "sagikazarmark-dev" ];

  dotenv.enable = true;

  env = {
    CC_wasm32_unknown_unknown = "${pkgs.llvmPackages.clang-unwrapped}/bin/clang";
  };

  overlays = [
    (
      final: prev:
      let
        unstable = inputs.nixpkgsUnstable.legacyPackages.${prev.stdenv.hostPlatform.system};
      in
      {
        inherit (unstable)
          chromedriver
          geckodriver
          wasm-pack
          wasm-bindgen-cli_0_2_108
          ;
      }
    )
  ];

  packages = with pkgs; [
    cargo-release
    cargo-watch
    cargo-expand
    wasm-pack
    wasm-bindgen-cli_0_2_108
    # chromedriver
    geckodriver
  ];

  languages.rust = {
    enable = true;
    channel = "stable";
    targets = [ "wasm32-unknown-unknown" ];
  };
}
