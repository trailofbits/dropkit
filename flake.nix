{
  description = "CLI tool for managing DigitalOcean droplets";

  inputs = {
    nixpkgs.url = "github:NixOS/nixpkgs/nixpkgs-unstable";
  };

  outputs =
    { self, nixpkgs }:
    let
      supportedSystems = [
        "x86_64-linux"
        "aarch64-linux"
        "x86_64-darwin"
        "aarch64-darwin"
      ];
      forAllSystems = f: nixpkgs.lib.genAttrs supportedSystems (system: f nixpkgs.legacyPackages.${system});
    in
    {
      packages = forAllSystems (pkgs: {
        default = pkgs.python3Packages.buildPythonApplication {
          pname = "dropkit";
          version = "0.1.0";
          pyproject = true;
          src = ./.;

          build-system = [ pkgs.python3Packages.hatchling ];

          # The custom hatch build hook runs `git rev-parse` which fails in
          # the Nix sandbox (no .git directory). Pre-create the version file
          # and strip the hook so hatchling doesn't try to run it.
          prePatch = ''
            echo "${self.shortRev or self.dirtyShortRev or "unknown"}" > dropkit/_version.txt
            substituteInPlace pyproject.toml \
              --replace-fail '[tool.hatch.build.hooks.custom]' ""
          '';

          dependencies = with pkgs.python3Packages; [
            typer
            rich
            requests
            pyyaml
            jinja2
            shellingham
            pydantic
          ];

          makeWrapperArgs = [
            "--prefix"
            "PATH"
            ":"
            (pkgs.lib.makeBinPath [ pkgs.tailscale ])
          ];

          # Tests require network access and a DigitalOcean API token
          doCheck = false;

          meta = {
            description = "CLI tool for managing DigitalOcean droplets";
            homepage = "https://github.com/trailofbits/dropkit";
            license = pkgs.lib.licenses.asl20;
            mainProgram = "dropkit";
          };
        };
      });

      devShells = forAllSystems (pkgs: {
        default = pkgs.mkShell {
          packages = [
            pkgs.uv
            pkgs.python311
            pkgs.shellcheck
            pkgs.tailscale
          ];
        };
      });
    };
}
