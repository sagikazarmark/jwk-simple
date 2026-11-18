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

  # worker-build is released with the `worker` crate, so it tracks `worker` in
  # Cargo.lock. nixpkgs lags behind (0.8.7 at the time of writing) and its build
  # fails anyway: zstd-sys needs libzstd, which the derivation does not provide.
  # Drop this once nixpkgs has a working worker-build at the right version.
  workerBuild = pkgs.worker-build.overrideAttrs (
    finalAttrs: old: {
      version = "0.9.0";
      src = pkgs.fetchFromGitHub {
        owner = "cloudflare";
        repo = "workers-rs";
        tag = "v${finalAttrs.version}";
        hash = "sha256-+M3vrg99XrNb116RydlC2OEQYfFIPIGUOiaA65bCTiA=";
      };
      cargoDeps = pkgs.rustPlatform.fetchCargoVendor {
        inherit (finalAttrs) pname version src;
        hash = "sha256-EbRwSrxRys2EcDfB88apmH5Rm0NUWLKtmGPS77fAhpI=";
      };
      buildInputs = old.buildInputs or [ ] ++ [ pkgs.zstd ];
    }
  );

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

  # Firefox and geckodriver for the headless browser tests (tests/web_crypto.rs).
  browsers.firefox.enable = true;

  worker-build = {
    enable = true;
    package = workerBuild;
  };

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
    cargo-hack
    cargo-release
    cargo-watch
    cargo-expand
    wasm-pack

    # wasm-bindgen-test-runner refuses to run unless wasm-bindgen-cli matches the
    # `wasm-bindgen` crate exactly. The worker-build module resolves it from
    # Cargo.lock (nixpkgs, including versioned attributes such as
    # `wasm-bindgen-cli_0_2_129`) but only uses it for builds, so put it on PATH.
    config.worker-build.wasm-bindgen.package
  ];

  languages.rust = {
    enable = true;
    channel = "stable";
    targets = [ "wasm32-unknown-unknown" ];
  };
}
