{
  pkgs,
  lib,
  config,
  inputs,
  ...
}:

let
  # docs.rs documents on nightly with `--cfg docsrs`, which the crate turns into
  # `#![feature(doc_cfg)]`, and with every feature on both targets (see
  # `[package.metadata.docs.rs]`), a combination that compiles nowhere else.
  # Kept off PATH so stable stays the toolchain; `just docsrs-*` runs it through
  # `CARGO_NIGHTLY`. `nightly.latest` is whatever the rust-overlay input pins.
  rustNightly =
    let
      rustBin = inputs.rust-overlay.lib.mkRustBin { } pkgs.buildPackages;
    in
    rustBin.nightly.latest.minimal.override { targets = [ "wasm32-unknown-unknown" ]; };

  # cargo finds rustc and rustdoc on PATH rather than next to itself, so running
  # the nightly cargo by path alone would document with the stable rustdoc.
  cargoNightly = pkgs.writeShellScriptBin "cargo-nightly" ''
    export PATH="${rustNightly}/bin:$PATH"
    exec cargo "$@"
  '';

  # wasm-bindgen-cli must match the `wasm-bindgen` crate in Cargo.lock exactly, or
  # wasm-bindgen-test-runner refuses to run. nixpkgs keeps older releases under
  # attributes like `wasm-bindgen-cli_0_2_129`. Same lookup as the dioxus and
  # worker-build modules in devenv-extras; fails loudly when nixpkgs lacks the
  # version, which is the signal to update nixpkgs (or pin wasm-bindgen).
  wasmBindgenVersion =
    let
      lock = builtins.fromTOML (builtins.readFile ./Cargo.lock);
      package = lib.findFirst (p: p.name == "wasm-bindgen") null lock.package;
    in
    if package == null then throw "wasm-bindgen is not in Cargo.lock" else package.version;

  wasmBindgenCli =
    let
      attr = "wasm-bindgen-cli_${lib.replaceStrings [ "." ] [ "_" ] wasmBindgenVersion}";
    in
    if pkgs.wasm-bindgen-cli.version == wasmBindgenVersion then
      pkgs.wasm-bindgen-cli
    else
      pkgs.${attr} or (throw ''
        nixpkgs has no wasm-bindgen-cli ${wasmBindgenVersion} (neither `wasm-bindgen-cli` nor `${attr}`).
        Update the nixpkgs input, or pin `wasm-bindgen` in Cargo.toml to a version it has.
      '');

  # wasm-bindgen-test-runner finds geckodriver itself, but geckodriver looks for
  # Firefox in /Applications on macOS and on PATH on Linux. Point both at the Nix
  # ones, so the browser tests run the same Firefox everywhere.
  webdriverJson = pkgs.writeText "webdriver.json" (
    builtins.toJSON {
      "moz:firefoxOptions".binary = config.browsers.firefox.executable;
    }
  );
in
{
  cachix.pull = [ "sagikazarmark-dev" ];

  dagger = {
    enable = true;

    version = "v1.0.0-beta.20";
  };

  # Firefox and geckodriver for the headless browser tests (tests/web_crypto.rs).
  browsers.firefox.enable = true;

  env = {
    CC_wasm32_unknown_unknown = "${pkgs.llvmPackages.clang-unwrapped}/bin/clang";

    # The docs.rs reproduction (`just docsrs`).
    CARGO_NIGHTLY = lib.getExe cargoNightly;

    GECKODRIVER = lib.getExe' config.browsers.firefox.driver.package "geckodriver";
    WASM_BINDGEN_TEST_WEBDRIVER_JSON = toString webdriverJson;
    # Also the budget for the browser to start, which defaults to a minute; a
    # cold CI runner has exceeded that.
    WASM_BINDGEN_TEST_TIMEOUT = "120";
  };

  packages = with pkgs; [
    just

    cargo-audit
    cargo-release
    cargo-watch
    cargo-expand
    wasm-pack
    wasmBindgenCli
  ];

  languages.rust = {
    enable = true;
    channel = "stable";
    targets = [ "wasm32-unknown-unknown" ];
  };
}
